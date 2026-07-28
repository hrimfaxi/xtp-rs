#!/bin/sh

# 可由 procd 的：
# procd_set_param env DEBUG=0
# 覆盖。
DEBUG="${DEBUG:-1}"
DEBUG_LOG="${DEBUG_LOG:-/tmp/shadowquic-stats-report.debug.log}"
SOCKET="${SOCKET:-/tmp/xtp-rs-report.sock}"

FIFO="/tmp/shadowquic-stats-report.$$.fifo"
LOGREAD_PID=""
CLEANED=0
SEND_FAIL_COUNT=0

command -v socat >/dev/null || {
    logger -t xtp-stats-reporter "ERROR: socat not found, exiting"
    exit 1
}

monotime() {
    local uptime rest

    IFS=' ' read -r uptime rest < /proc/uptime
    printf '%s' "$uptime"
}

dbg() {
    [ "$DEBUG" = "1" ] || return 0

    printf '%s uptime=%s [shadowquic-stats-report] %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" \
        "$(monotime)" \
        "$*" >> "$DEBUG_LOG"
}

cleanup() {
    # 防止 EXIT trap、TERM trap 等多次调用 cleanup。
    [ "$CLEANED" = "1" ] && return 0
    CLEANED=1

    dbg "cleanup started: logread_pid=${LOGREAD_PID:-none}"

    if [ -n "$LOGREAD_PID" ]; then
        # logread 已退出时 kill 会失败，忽略即可。
        kill "$LOGREAD_PID" 2>/dev/null
        wait "$LOGREAD_PID" 2>/dev/null
        LOGREAD_PID=""
    fi

    rm -f "$FIFO"

    dbg "cleanup completed"
}

# 收到 procd 的 stop/restart 信号后退出。
# EXIT trap 负责统一执行 cleanup。
trap 'exit 0' INT TERM HUP
trap 'cleanup' EXIT

if [ "$DEBUG" = "1" ]; then
    : > "$DEBUG_LOG"
    dbg "script started: socket=$SOCKET fifo=$FIFO"
fi

get_instance_id() {
    local pid="$1"
    local cmdline_file="/proc/$pid/cmdline"
    local cmdline cfg_file instance

    if [ ! -r "$cmdline_file" ]; then
        dbg "PID=$pid: cannot read $cmdline_file"
        printf 'unknown-%s\n' "$pid"
        return 1
    fi

    # 仅供调试显示。/proc/PID/cmdline 实际以 NUL 分隔。
    cmdline=$(tr '\000' '|' < "$cmdline_file" 2>/dev/null)
    dbg "PID=$pid: cmdline=$cmdline"

    # 支持以下参数格式：
    #
    # shadowquic -c /etc/xray/shadowquic/niyaou.yaml
    # shadowquic -c=/etc/xray/shadowquic/niyaou.yaml
    # shadowquic --config /etc/xray/shadowquic/niyaou.yaml
    # shadowquic --config=/etc/xray/shadowquic/niyaou.yaml
    cfg_file=$(
        tr '\000' '\n' < "$cmdline_file" 2>/dev/null | awk '
            $0 == "-c" || $0 == "--config" {
                if (getline > 0) {
                    print
                    exit
                }
            }

            index($0, "-c=") == 1 {
                sub(/^-c=/, "")
                print
                exit
            }

            index($0, "--config=") == 1 {
                sub(/^--config=/, "")
                print
                exit
            }
        '
    )

    if [ -z "$cfg_file" ]; then
        dbg "PID=$pid: config argument not found; using unknown-$pid"
        printf 'unknown-%s\n' "$pid"
        return 1
    fi

    instance=$(basename "$cfg_file")
    instance=${instance%.*}

    if [ -z "$instance" ]; then
        dbg "PID=$pid: empty instance derived from cfg_file=$cfg_file"
        printf 'unknown-%s\n' "$pid"
        return 1
    fi

    dbg "PID=$pid: cfg_file=$cfg_file instance_id=$instance"
    printf '%s\n' "$instance"
    return 0
}

send_json() {
    local json="$1"
    local t_start t_end rc

    if [ ! -S "$SOCKET" ]; then
        dbg "ERROR: socket does not exist or is not a Unix socket: $SOCKET"
        return 1
    fi

    t_start=$(monotime)
    dbg "sending JSON via UNIX datagram: $json"

    if [ "$DEBUG" = "1" ]; then
        if printf '%s\n' "$json" | socat -u - UNIX-SENDTO:"$SOCKET" \
            2>>"$DEBUG_LOG"; then
            t_end=$(monotime)
            dbg "send success: started=$t_start ended=$t_end"
            SEND_FAIL_COUNT=0
            return 0
        fi
    else
        if printf '%s\n' "$json" | socat -u - UNIX-SENDTO:"$SOCKET" \
            2>/dev/null; then
            SEND_FAIL_COUNT=0
            return 0
        fi
    fi

    rc=$?
    t_end=$(monotime)
    dbg "ERROR: socat UNIX-SENDTO failed: rc=$rc started=$t_start ended=$t_end"
    SEND_FAIL_COUNT=$((SEND_FAIL_COUNT + 1))
    # 每连续失败 60 次报一次 syslog，避免静默假运行。
    if [ $((SEND_FAIL_COUNT % 60)) -eq 1 ]; then
        logger -t xtp-stats-reporter "WARNING: send failed $SEND_FAIL_COUNT times (socket=$SOCKET)"
    fi
    return "$rc"
}

# 必须避免原来的：
#
#   logread -f | while read ...
#
# 因为 restart 时管道创建的子 Shell 或 logread 可能遗留。
#
# 改为 FIFO：主 Shell 直接执行 while read；logread 是可记录 PID、
# 可在 cleanup 中明确终止的后台子进程。

rm -f "$FIFO"

if ! mkfifo "$FIFO"; then
    dbg "ERROR: cannot create FIFO: $FIFO"
    exit 1
fi

if [ "$DEBUG" = "1" ]; then
    logread -f -e 'shadowquic\[[0-9][0-9]*\].*(uplink|downlink) stats ' > "$FIFO" 2>>"$DEBUG_LOG" &
else
    logread -f -e 'shadowquic\[[0-9][0-9]*\].*(uplink|downlink) stats ' > "$FIFO" 2>/dev/null &
fi

LOGREAD_PID=$!
dbg "started logread: pid=$LOGREAD_PID"

# 打开 FIFO 的读端后，后台 logread 的写端也会完成打开。
while IFS= read -r line; do
    # 防御性措施：即使以后有人重新将 stderr 写回 syslog，
    # 也绝不处理本脚本自己的调试信息。
    case "$line" in
        *"[shadowquic-stats-report]"*)
            continue
            ;;
    esac

    # 必须是 shadowquic[PID]: 格式。
    case "$line" in
        *"shadowquic["*"]:"*)
            ;;
        *)
            continue
            ;;
    esac

    case "$line" in
        *"uplink stats "*|*"downlink stats "*)
            ;;
        *)
            continue
            ;;
    esac

    dbg "received valid shadowquic stats event"

    parsed_data=$(
        printf '%s\n' "$line" | awk '
        {
            pid = ""

            if (match($0, /shadowquic\[[0-9]+\]/)) {
                pid = substr($0, RSTART, RLENGTH)
                sub(/^shadowquic\[/, "", pid)
                sub(/\]$/, "", pid)
            }

            if (pid == "")
                exit

            if ($0 ~ /uplink stats /)
                link = "uplink"
            else if ($0 ~ /downlink stats /)
                link = "downlink"
            else
                exit

            rtt = ""
            if (match($0, /rtt=[0-9.]+ms/)) {
                # 去掉 rtt= 和 ms。
                rtt = substr($0, RSTART + 4, RLENGTH - 6)
            }

            loss = ""
            if (match($0, /packet_loss_rate=[0-9.]+%/)) {
                # packet_loss_rate= 为 17 字符，去掉末尾 %。
                loss = substr($0, RSTART + 17, RLENGTH - 18) / 100
            }

            mtu = ""
            if (match($0, /mtu=[0-9]+/)) {
                mtu = substr($0, RSTART + 4, RLENGTH - 4)
            }

            printf "%s|%s|%s|%s|%s\n", pid, rtt, loss, mtu, link
        }'
    )

    if [ -z "$parsed_data" ]; then
        dbg "ERROR: parsing failed; no parsed_data generated"
        continue
    fi

    IFS='|' read -r pid rtt loss_rate mtu link <<EOF
$parsed_data
EOF

    [ -n "$rtt" ] || rtt=0
    [ -n "$loss_rate" ] || loss_rate=0
    [ -n "$mtu" ] || mtu=0

    dbg "parsed: pid=$pid rtt=$rtt loss_rate=$loss_rate mtu=$mtu link=$link"

    instance_id=$(get_instance_id "$pid")
    instance_rc=$?

    dbg "instance lookup: pid=$pid instance_id=$instance_id rc=$instance_rc"

    json_string=$(
        printf '{"upstream_id":"%s","peer":"%s","rtt_ms":%.3f,"loss_rate":%.4f,"mtu":%d,"link":"%s"}' \
            "$instance_id" \
            "$pid" \
            "$rtt" \
            "$loss_rate" \
            "$mtu" \
            "$link"
    )

    if ! send_json "$json_string"; then
        dbg "ERROR: failed to report pid=$pid instance=$instance_id"
    fi
done < "$FIFO"

# 通常不会走到这里；若 logread 异常退出而 FIFO EOF，会正常退出。
dbg "logread stream ended"
exit 0
