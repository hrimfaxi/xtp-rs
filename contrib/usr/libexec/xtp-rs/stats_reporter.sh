#!/bin/sh

# 可由 procd 的：
# procd_set_param env DEBUG=0
# 覆盖。
DEBUG="${DEBUG:-0}"
DEBUG_LOG="${DEBUG_LOG:-/tmp/shadowquic-stats-report.debug.log}"
SOCKET="${SOCKET:-/tmp/xtp-rs-report.sock}"
REFRESH_INTERVAL="${REFRESH_INTERVAL:-30}"   # 刷新间隔（秒）
REFRESH_URL="${REFRESH_URL:-http://cp.cloudflare.com/generate_204}"   # 探测目标 URL

# REFRESH_INTERVAL 非数字、空或 0 时回退到默认值，
# 避免 sleep 立即失败造成无间隔高速循环。
case "$REFRESH_INTERVAL" in
    ''|*[!0-9]*|0)
        logger -t xtp-stats-reporter \
            "WARNING: invalid REFRESH_INTERVAL=$REFRESH_INTERVAL, using 30"
        REFRESH_INTERVAL=30
        ;;
esac

FIFO="/tmp/shadowquic-stats-report.$$.fifo"
LOGREAD_PID=""
REFRESH_PID=""
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

    dbg "cleanup started: logread_pid=${LOGREAD_PID:-none} refresh_pid=${REFRESH_PID:-none}"

    if [ -n "$LOGREAD_PID" ]; then
        # logread 已退出时 kill 会失败，忽略即可。
        kill "$LOGREAD_PID" 2>/dev/null
        wait "$LOGREAD_PID" 2>/dev/null
        LOGREAD_PID=""
    fi

    if [ -n "$REFRESH_PID" ]; then
        # 直接终止刷新循环本身。若其当前正在运行 curl（多实例并发探测
        # 时可能有多个在途 curl），curl 受 --max-time 2 限制；若正在
        # sleep，则 sleep 最多持续至本轮剩余刷新间隔。它们均不会进入
        # 下一次刷新循环。
        kill "$REFRESH_PID" 2>/dev/null
        wait "$REFRESH_PID" 2>/dev/null
        REFRESH_PID=""
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

# ---------- 提取配置文件路径（供刷新和 get_config_name 共用） ----------
get_config_path() {
    local pid="$1"
    local cmdline_file="/proc/$pid/cmdline"

    if [ ! -r "$cmdline_file" ]; then
        dbg "PID=$pid: cannot read $cmdline_file"
        return 1
    fi

    # 支持以下参数格式：
    #
    # shadowquic -c /etc/xray/shadowquic/niyaou.yaml
    # shadowquic -c=/etc/xray/shadowquic/niyaou.yaml
    # shadowquic --config /etc/xray/shadowquic/niyaou.yaml
    # shadowquic --config=/etc/xray/shadowquic/niyaou.yaml
    tr '\0' '\n' < "$cmdline_file" 2>/dev/null | awk '
        { a[NR] = $0 }

        END {
            # 有 "--" 时，仅解析其后的真实程序参数；
            # 无 "--" 时，从头解析。
            start = 1
            for (i = 1; i <= NR; i++) {
                if (a[i] == "--") {
                    start = i + 1
                    break
                }
            }

            for (i = start; i <= NR; i++) {
                file = ""

                # -c /path/config.yaml
                # --config /path/config.yaml
                if ((a[i] == "-c" || a[i] == "--config") && i < NR) {
                    file = a[i + 1]
                }
                # -c=/path/config.yaml
                else if (a[i] ~ /^-c=/) {
                    file = substr(a[i], 4)
                }
                # --config=/path/config.yaml
                else if (a[i] ~ /^--config=/) {
                    file = substr(a[i], 10)
                }

                # 只需非空且不以 "-" 开头即可
                if (file != "" && file !~ /^-/) {
                    print file
                    exit
                }
            }
        }
    '
}

# 从 /proc/PID/cmdline 提取配置文件名（去扩展名），作为 upstream_id 的基名。
# 多实例日志带 instance{n=N} 时由调用方追加 _N 后缀（如 combine_0）；
# 单实例/旧版日志无 instance 字段，直接使用基名（向后兼容）。
get_config_name() {
    local pid="$1"
    local cmdline_file="/proc/$pid/cmdline"
    local cmdline cfg_file cfg_name

    if [ ! -r "$cmdline_file" ]; then
        dbg "PID=$pid: cannot read $cmdline_file"
        printf 'unknown-%s\n' "$pid"
        return 1
    fi

    # 仅供调试显示。/proc/PID/cmdline 实际以 NUL 分隔。
    cmdline=$(tr '\000' '|' < "$cmdline_file" 2>/dev/null)
    dbg "PID=$pid: cmdline=$cmdline"

    # 复用 get_config_path 获取配置文件
    cfg_file=$(get_config_path "$pid")

    if [ -z "$cfg_file" ]; then
        dbg "PID=$pid: config argument not found; using unknown-$pid"
        printf 'unknown-%s\n' "$pid"
        return 1
    fi

    cfg_name=$(basename "$cfg_file")
    cfg_name=${cfg_name%.*}

    if [ -z "$cfg_name" ]; then
        dbg "PID=$pid: empty config name derived from cfg_file=$cfg_file"
        printf 'unknown-%s\n' "$pid"
        return 1
    fi

    dbg "PID=$pid: cfg_file=$cfg_file config_name=$cfg_name"
    printf '%s\n' "$cfg_name"
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

# ---------- 刷新功能 ----------
# 从配置提取所有 bind-addr，每行输出 "host port"。
# 多实例配置含多个 inbound（每个实例一个），需全部探测；
# 兼容顶层键与 YAML 列表项（"- bind-addr:"）两种写法，
# 支持引号、行尾注释、IPv6 方括号（如 [::1]:1080）。
parse_bind_addrs() {
    awk '
        /^[[:space:]]*-[[:space:]]*bind-addr:/ || /^[[:space:]]*bind-addr:/ {
            v = $0
            sub(/^[[:space:]]*(-[[:space:]]*)?bind-addr:[[:space:]]*/, "", v)
            sub(/[[:space:]]*#.*$/, "", v)
            gsub(/["'\''[:space:]]/, "", v)

            if (v ~ /^\[.*\]:[0-9]+$/) {
                sub(/^\[/, "", v)
                split(v, a, /]:/)
                print a[1], a[2]
                next
            }
            if (v ~ /^[^:]+:[0-9]+$/) {
                split(v, a, /:/)
                print a[1], a[2]
            }
        }
    ' "$1" 2>/dev/null
}

refresh_connections() {
    # host/port/proxy 在管道 while（子 shell）内赋值，正常 POSIX sh 下
    # 不会外泄；仍声明为 local，防止 lastpipe/未来重构时泄漏为全局。
    local pids pid config_path addrs host port proxy

    # [s]hadowquic 避免 pgrep 匹配到本脚本自身的命令行。
    # 不依赖配置文件后缀（.yaml/.yml/.conf 均可命中）。
    pids=$(pgrep -f '[s]hadowquic' 2>/dev/null)
    if [ -z "$pids" ]; then
        dbg "refresh: no shadowquic processes found"
        return 0
    fi

    for pid in $pids; do
        # 检查进程是否存在
        if ! kill -0 "$pid" 2>/dev/null; then
            continue
        fi

        config_path=$(get_config_path "$pid")
        if [ -z "$config_path" ] || [ ! -r "$config_path" ]; then
            dbg "refresh: PID=$pid config not readable: ${config_path:-none}"
            continue
        fi

        # 多实例配置有多个 bind-addr，全部探测。探测仅用于触发流量，
        # 让每个实例都向 syslog 输出 stats，无需 instance ↔ 端口映射。
        addrs=$(parse_bind_addrs "$config_path")
        if [ -z "$addrs" ]; then
            dbg "refresh: PID=$pid no valid bind-addr in $config_path"
            continue
        fi

        printf '%s\n' "$addrs" | while read -r host port; do
            [ -n "$host" ] || continue

            case "$port" in
                ''|*[!0-9]*)
                    dbg "refresh: PID=$pid invalid bind port: ${port:-missing}"
                    continue
                    ;;
            esac
            if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                dbg "refresh: PID=$pid bind port out of range: $port"
                continue
            fi

            # 通配监听地址不可直连，探测时回落到回环地址。
            case "$host" in
                0.0.0.0) host=127.0.0.1 ;;
                "::") host="::1" ;;
            esac

            # IPv6 主机在代理 URL 中需要加方括号。
            case "$host" in
                *:*) proxy="socks5h://[$host]:$port" ;;
                *) proxy="socks5h://$host:$port" ;;
            esac

            dbg "refresh: probing PID=$pid via $proxy"
            # 发送 HEAD 请求触发新连接，忽略输出，超时 2 秒。
            # --noproxy '' 强制不使用 NO_PROXY/no_proxy 规则，确保探测
            # 一定经过 SOCKS5（否则可能绕过 Shadowquic 直连，线报不刷新）。
            # -- 防止异常的 REFRESH_URL（如以 - 开头）被 curl 当作选项解析。
            # 并发探测：多实例配置有多个 bind-addr，串行时每个失败探测
            # 最多阻塞 2 秒，逐个累加会拉长整轮刷新周期；后台并行执行，
            # 失败日志由子 shell 写入，curl 受 --max-time 2 自行限时。
            (
                if ! curl --proxy "$proxy" \
                    --noproxy '' \
                    --connect-timeout 1 --max-time 2 \
                    --silent --output /dev/null \
                    --head \
                    -- "$REFRESH_URL" 2>/dev/null; then
                    dbg "refresh: probe failed: PID=$pid proxy=$proxy"
                fi
            ) &
        done
    done
}

# 后台刷新循环
refresh_loop() {
    while true; do
        refresh_connections
        sleep "$REFRESH_INTERVAL"
    done
}
# ----------------------------------

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
    logread -f -e 'shadowquic\[[0-9][0-9]*\].*\(uplink\|downlink\) stats ' > "$FIFO" 2>>"$DEBUG_LOG" &
else
    logread -f -e 'shadowquic\[[0-9][0-9]*\].*\(uplink\|downlink\) stats ' > "$FIFO" 2>/dev/null &
fi

LOGREAD_PID=$!
dbg "started logread: pid=$LOGREAD_PID"

# 启动刷新循环。refresh 依赖 curl 探测，缺失时不启动子进程。
if command -v curl >/dev/null 2>&1; then
    # 子 shell 内清除父进程的 trap，避免 worker 退出时误触发 cleanup，
    # 清理父进程持有的 logread/FIFO 等资源。
    (
        trap - 0 INT TERM HUP
        refresh_loop
    ) &
    REFRESH_PID=$!
    dbg "started refresh loop: pid=$REFRESH_PID interval=$REFRESH_INTERVAL url=$REFRESH_URL"
else
    dbg "refresh disabled: curl not found"
fi

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

            # 多实例日志带 instance{n=N}: 前缀，提取 N；
            # 单实例/旧版日志无此字段，inst 保持空。
            # 用 index/substr 而非 brace 正则，避免 busybox awk 兼容问题；
            # 数字后必须紧跟 "}" 才认定为实例序号，防止日志其他位置
            # 恰好出现 "instance{n=" 字样时误提取。
            inst = ""
            i = index($0, "instance{n=")
            if (i > 0) {
                rest = substr($0, i + length("instance{n="))
                if (match(rest, /^[0-9]+/) && substr(rest, RLENGTH + 1, 1) == "}")
                    inst = substr(rest, 1, RLENGTH)
            }

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

            printf "%s|%s|%s|%s|%s|%s\n", pid, rtt, loss, mtu, link, inst
        }'
    )

    if [ -z "$parsed_data" ]; then
        dbg "ERROR: parsing failed; no parsed_data generated"
        continue
    fi

    IFS='|' read -r pid rtt loss_rate mtu link inst_n <<EOF
$parsed_data
EOF

    [ -n "$rtt" ] || rtt=0
    [ -n "$loss_rate" ] || loss_rate=0
    [ -n "$mtu" ] || mtu=0

    dbg "parsed: pid=$pid rtt=$rtt loss_rate=$loss_rate mtu=$mtu link=$link instance=${inst_n:-none}"

    cfg_name=$(get_config_name "$pid")
    cfg_rc=$?

    dbg "config name lookup: pid=$pid cfg_name=$cfg_name rc=$cfg_rc"

    # 进程刚退出（cmdline 已消失）等场景拿不到配置名，拼出的
    # unknown-* id 在 xtp-rs 侧必然匹配不上，直接跳过本次上报。
    if [ "$cfg_rc" -ne 0 ] || [ -z "$cfg_name" ]; then
        dbg "skip report: no config name for pid=$pid"
        continue
    fi

    # upstream_id 推导：
    # - 多实例日志带 instance{n=N}：配置名_N（如 combine_0），
    #   与 xtp-rs 配置中该实例的 upstream id 对应。
    # - 单实例/旧版日志无 instance 字段：直接用配置名，向后兼容。
    if [ -n "$inst_n" ]; then
        upstream_id="${cfg_name}_${inst_n}"
    else
        upstream_id="$cfg_name"
    fi

    dbg "upstream_id=$upstream_id"

    json_string=$(
        printf '{"upstream_id":"%s","peer":"%s","rtt_ms":%.3f,"loss_rate":%.4f,"mtu":%d,"link":"%s"}' \
            "$upstream_id" \
            "$pid" \
            "$rtt" \
            "$loss_rate" \
            "$mtu" \
            "$link"
    )

    if ! send_json "$json_string"; then
        dbg "ERROR: failed to report pid=$pid upstream_id=$upstream_id"
    fi
done < "$FIFO"

# 通常不会走到这里；若 logread 异常退出而 FIFO EOF，会正常退出。
dbg "logread stream ended"
exit 0
