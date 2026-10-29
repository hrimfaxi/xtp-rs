#!/bin/sh

# 取数方式按进程自动选择，无需按 shadowquic 版本手工切换：
#
#   1. REST 模式：该进程的配置文件里有顶层 `restful-api:` 段，且它的
#      /api/v1/outbounds 能取到数据 —— 用 probe 端点喂流量、轮询连接采样；
#   2. 日志模式：其余情况（老二进制没有 restful-api、配置里没写这段、
#      或者 API 一时连不上）沿用原来的 logread 抓
#      "uplink/downlink connection stats"。
#
# 两种模式发给 xtp-rs 的报文格式完全一致，xtp-rs 侧无需任何改动。

# 可由 procd 的：
# procd_set_param env DEBUG=0
# 覆盖。
DEBUG="${DEBUG:-0}"
DEBUG_LOG="${DEBUG_LOG:-/tmp/shadowquic-stats-report.debug.log}"
SOCKET="${SOCKET:-/tmp/xtp-rs-report.sock}"
REFRESH_INTERVAL="${REFRESH_INTERVAL:-30}"   # 刷新间隔（秒）
REFRESH_URL="${REFRESH_URL:-http://cp.cloudflare.com/generate_204}"   # 探测目标 URL

# ---- REST 模式参数 ----
API_TIMEOUT="${API_TIMEOUT:-5}"                    # 单个 API 请求超时（秒）
PROBE_TIMEOUT_MS="${PROBE_TIMEOUT_MS:-3000}"       # probe 喂流量超时（毫秒）
# 采样超过该年龄就不上报，避免隧道空闲或 probe 失败时反复推同一份过期数据。
MAX_SAMPLE_AGE_MS="${MAX_SAMPLE_AGE_MS:-120000}"
# 本轮由 REST 取数的 pid 列表：日志路径据此跳过，避免同一份数据重复上报。
# 读侧可能随时 grep，写侧只用"追加"和"整文件原子替换"，绝不先截断。
# 三者在 main() 里落到 mktemp -d 建的私有目录中 —— /tmp 是可写的共享目录，
# 用可预测的 $$ 命名再直接 > 重定向，等于给本地用户一个符号链接攻击面。
REST_PIDS_FILE=""
JSON_FILE=""
FIFO=""
SEND_FAIL_FILE=""
STATE_DIR=""

# JSON 解析后端：优先 jq（自带 @json、表达式更完整），
# OpenWrt 上一般只有 libubox 的 jsonfilter。两者都没有时禁用 REST 模式。
JSON_BACKEND=""

LOGREAD_PID=""
REFRESH_PID=""
CLEANED=0

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
        # 直接终止刷新循环本身。若其当前正在运行 curl（多个 bind-addr
        # 并发探测时可能有多个在途 curl），curl 受 --max-time 2 限制；若正在
        # sleep，则 sleep 最多持续至本轮剩余刷新间隔。它们均不会进入
        # 下一次刷新循环。
        kill "$REFRESH_PID" 2>/dev/null
        wait "$REFRESH_PID" 2>/dev/null
        REFRESH_PID=""
    fi

    rm -f "$FIFO"
    rm -f "$REST_PIDS_FILE" "$REST_PIDS_FILE.tmp"
    rm -f "$JSON_FILE" "$SEND_FAIL_FILE"
    # 整个私有状态目录一起删（含 mktemp 建的目录本身）。
    if [ -n "$STATE_DIR" ]; then
        rm -rf "$STATE_DIR"
    fi

    dbg "cleanup completed"
}

# ---------- 提取配置文件路径（供刷新和 get_config_name 共用） ----------
get_config_path() {
    local pid="$1"
    local cmdline_file="/proc/$pid/cmdline"
    local cfg_file

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
    cfg_file=$(tr '\0' '\n' < "$cmdline_file" 2>/dev/null | awk '
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
    ')

    if [ -z "$cfg_file" ]; then
        dbg "PID=$pid: config argument not found"
        return 1
    fi

    # 相对路径是相对 shadowquic 自己的 cwd 解析的，不是本脚本的 cwd ——
    # procd 里常见 `-c tproxy_cn.yaml` 这种写法，直接 open 会失败。
    case "$cfg_file" in
        /*) ;;
        *) cfg_file="/proc/$pid/cwd/$cfg_file" ;;
    esac

    printf '%s\n' "$cfg_file"
    return 0
}

# 从 /proc/PID/cmdline 提取配置文件名（去扩展名），作为 upstream_id 的前缀。
# 用途是跨进程去重：不同 shadowquic 进程可能使用相同的出站 tag（旧式单端点
# 写法 outbound tag 甚至默认为 "outbound"），仅用 tag 会撞 id。
# 取不到时由调用方跳过本次上报。
get_config_name() {
    local pid="$1"
    local cmdline_file="/proc/$pid/cmdline"
    local cmdline cfg_file cfg_name

    if [ ! -r "$cmdline_file" ]; then
        dbg "PID=$pid: cannot read $cmdline_file"
        return 1
    fi

    # 仅供调试显示。/proc/PID/cmdline 实际以 NUL 分隔。
    cmdline=$(tr '\000' '|' < "$cmdline_file" 2>/dev/null)
    dbg "PID=$pid: cmdline=$cmdline"

    # 复用 get_config_path 获取配置文件
    cfg_file=$(get_config_path "$pid")

    if [ -z "$cfg_file" ]; then
        dbg "PID=$pid: config argument not found"
        return 1
    fi

    cfg_name=$(basename "$cfg_file")
    cfg_name=${cfg_name%.*}

    if [ -z "$cfg_name" ]; then
        dbg "PID=$pid: empty config name derived from cfg_file=$cfg_file"
        return 1
    fi

    dbg "PID=$pid: cfg_file=$cfg_file config_name=$cfg_name"
    printf '%s\n' "$cfg_name"
    return 0
}

# 非负整数校验（字节数、包数、毫秒数）。JSON 不允许前导 0，
# 这里也拒绝：`printf %d` 对 "010" 这类输入可能按八进制解析。
is_uint() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        0|[1-9]*) return 0 ;;
    esac
    return 1
}

# 有上限的非负整数：先按位数挡掉会溢出的长数字，再做 shell 算术比较。
# 直接 `[ "$v" -le "$max" ]` 遇到 40 位数字会报错，而在 if 条件里
# "报错"会被当成"不满足"，于是一个荒谬的大值反而通过了范围检查。
is_uint_range() {
    local v="$1" max="$2"

    is_uint "$v" || return 1
    [ ${#v} -le ${#max} ] || return 1
    [ "$v" -le "$max" ]
}

# 计数器与采样年龄的上限（18 位）。shadowquic 侧是 u64（最多 20 位），
# 真实计数远到不了 18 位，这里的作用是"拒绝不可信的离谱值"：
# - 超过 2^53（16 位）double 已不精确，loss_rate 只是近似；
# - 到 double 溢出量级（309 位以上）会算出 -nan，printf 直接把它拼进报文，
#   吐出一个非法 JSON；
# - 超长数字还会让 shell 算术溢出（`[ 大数 -gt N ]` 在 busybox 下报错，
#   而 if 条件里"报错"等于"不成立"）。
COUNTER_MAX="999999999999999999"

# rtt 校验：语法（接受 JSON 的整数、小数与科学计数法 —— jq 会把 1e-7 印成
# 1E-7，大写 E 与 +/- 都会出现，拒绝 "."、"1.2.3" 这类半成品）加范围。
# 上限取 10^7 ms（约 2.7 小时）：比这更大的"延迟"只可能是坏数据，
# 而 1e400 这种溢出量级的值在 awk 里是 inf、在 busybox printf 里是几百位
# 数字，都不该被当成真实延迟发出去。
# 值走 ENVIRON 而不是 -v：-v 会把长得像数字的字符串转成数字再回转，
# 字符串形态就不再是原样了。
is_valid_rtt() {
    case "$1" in
        ''|*[!0-9.eE+-]*) return 1 ;;
    esac

    STATS_NUM="$1" awk 'BEGIN {
        s = ENVIRON["STATS_NUM"]
        if (s !~ /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/)
            exit 1
        v = s + 0
        exit !(v >= 0 && v < 1e7)
    }'
}

# 采样年龄是否已经过期。用 awk 比较：shell 的 test 对大数会溢出，
# 溢出后条件为假，过期采样就会被当成新鲜的报上去。
is_age_stale() {
    STATS_AGE="$1" STATS_MAX="$2" awk 'BEGIN {
        exit !(ENVIRON["STATS_AGE"] + 0 > ENVIRON["STATS_MAX"] + 0)
    }'
}

# 把字符串转成可嵌进 JSON 字符串字面量的内容（不含两侧引号）。
# 只转义 JSON 强制要求转义的字符：反斜杠、双引号、0x00-0x1f 控制字符；
# 其余字节原样保留 —— 多字节 UTF-8 在 JSON 字符串里本来就合法，
# 因而不需要（也不应该）在这里做 \uXXXX 之类的解码/编码。
json_escape() {
    printf '%s' "$1" | awk '
        BEGIN {
            for (i = 1; i < 32; i++)
                ctl[sprintf("%c", i)] = sprintf("\\u%04x", i)
        }

        {
            if (NR > 1)
                printf "\\n"

            out = ""
            n = length($0)
            for (i = 1; i <= n; i++) {
                c = substr($0, i, 1)
                if (c == "\\")
                    out = out "\\\\"
                else if (c == "\"")
                    out = out "\\\""
                else if (c in ctl)
                    out = out ctl[c]
                else
                    out = out c
            }
            printf "%s", out
        }
    '
}

# 丢包率：lost/(sent+1)，四位小数。与日志模式的 packet_loss_rate 同口径。
# 注意：输入若不是普通整数（比如 40 位以上的计数），awk 会算出 inf/nan，
# 调用方必须先用 is_uint_range 挡住，并在用之前校验结果是不是十进制数。
loss_rate_from() {
    awk -v lost="$1" -v sent="$2" 'BEGIN { printf "%.4f", lost / (sent + 1) }'
}

# 构造上报报文。日志模式与 REST 模式共用，保证两条路径逐字节一致。
# 参数：upstream_id peer rtt loss_rate mtu link
build_report_json() {
    printf '{"upstream_id":"%s","peer":"%s","rtt_ms":%.3f,"loss_rate":%.4f,"mtu":%d,"link":"%s"}' \
        "$(json_escape "$1")" "$2" "$3" "$4" "$5" "$6"
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

    # 直接取管道的退出码：写成 if ... ; fi 时，条件不成立且没有 else
    # 分支会让整个 if 复合命令返回 0，真实失败码就被吞掉了。
    if [ "$DEBUG" = "1" ]; then
        printf '%s\n' "$json" | socat -u - UNIX-SENDTO:"$SOCKET" \
            2>>"$DEBUG_LOG"
    else
        printf '%s\n' "$json" | socat -u - UNIX-SENDTO:"$SOCKET" \
            2>/dev/null
    fi
    rc=$?

    t_end=$(monotime)

    if [ "$rc" -eq 0 ]; then
        dbg "send success: started=$t_start ended=$t_end"
        clear_send_failures
        return 0
    fi

    dbg "ERROR: socat UNIX-SENDTO failed: rc=$rc started=$t_start ended=$t_end"
    count_send_failure "$rc"
    return "$rc"
}

# 连续发送失败计数。落盘而不是放变量：上报都在管道的 while 子 shell 里执行，
# 进程内变量每轮都会重置，"连续失败 60 次报一次 syslog"永远不会触发。
#
# 计数方式是"每次失败往文件追加一个字节，用文件大小当计数"：日志路径与
# REST worker 会并发调用，读-加-写会丢更新，而 O_APPEND 的单字节写入不会。
# 并发下的告警时机仍可能差一两次（两个调用者读到相邻的大小），
# 所以这是一个近似计数，只用来"别让它静默失败"，不承担精确语义。
count_send_failure() {
    local rc="$1" n

    [ -n "$SEND_FAIL_FILE" ] || return 0

    printf 'x' >> "$SEND_FAIL_FILE" 2>/dev/null
    n=$(wc -c < "$SEND_FAIL_FILE" 2>/dev/null | tr -d ' ')
    case "$n" in
        ''|*[!0-9]*) return 0 ;;
    esac

    # 每连续失败 60 次报一次 syslog，避免静默假运行。
    if [ $((n % 60)) -eq 1 ]; then
        logger -t xtp-stats-reporter \
            "WARNING: send failed $n times (socket=$SOCKET, rc=$rc)"
    fi
    return 0
}

clear_send_failures() {
    [ -n "$SEND_FAIL_FILE" ] && rm -f "$SEND_FAIL_FILE" 2>/dev/null
    return 0
}

# ---------- JSON 解析后端 ----------
# 只保留两件事：挑后端、按点分路径取标量。JSON 本身交给 jq / jsonfilter，
# 脚本不再自己解析 —— 手写的解析器在转义、\uXXXX、字段顺序上极易出错。
detect_json_backend() {
    if command -v jq >/dev/null 2>&1; then
        JSON_BACKEND="jq"
    elif command -v jsonfilter >/dev/null 2>&1; then
        JSON_BACKEND="jsonfilter"
    else
        JSON_BACKEND=""
    fi
}

# json_get <file> <path>：取标量并原样打印（字符串为解码后的原文，数字为原文）。
# path 为点分形式且只用数组下标，如 outbounds[0].quality.sq_conn_stats.uplink.rtt；
# 两种后端的表达式都只是给同一段路径加前缀，语法差异仅此一处。
# 字段缺失、为 null、或 JSON 本身不合法时返回非零（jq 会把 null 打到 stdout，
# 所以调用方必须看返回码而不是输出）。
json_get() {
    local v

    case "$JSON_BACKEND" in
        jq)
            v=$(jq -er ".$2" "$1" 2>/dev/null) || return 1
            ;;
        jsonfilter)
            v=$(jsonfilter -i "$1" -e "@.$2" 2>/dev/null) || return 1
            ;;
        *)
            return 1
            ;;
    esac

    printf '%s\n' "$v"
    return 0
}

# 数组长度。不能拿 tag 的行数顶替：tag 缺失/为 null 时两个后端都会少输出
# 一行，末尾缺 tag 就会被静默忽略（全部缺 tag 时会误判成"成功但没有数据"，
# 于是永久挡住日志路径）。
#
# 两个后端都没有 length：jsonfilter 用 -t 逐个下标探存在性。
# 元素本身为 null 时 jsonfilter 会提前收手，所以下面还要和 tag 行数交叉校验。
json_array_len() {
    local file="$1" path="$2" idx

    case "$JSON_BACKEND" in
        jq)
            # 只数非 null 元素，与 jsonfilter 的探存在性口径对齐。
            jq -r ".$path | map(select(. != null)) | length" "$file" 2>/dev/null
            ;;
        jsonfilter)
            idx=0
            while jsonfilter -i "$file" -t "@.$path[$idx]" >/dev/null 2>&1; do
                idx=$((idx + 1))
            done
            printf '%s\n' "$idx"
            ;;
        *)
            return 1
            ;;
    esac
}

# 所有出站 tag，每行一个（数组顺序）。仅用于统计出站个数：
# 真正的取数按数组下标逐个取，避免顺序错位导致把 A 出站的数字挂到 B 的 id 上。
json_outbound_tags() {
    case "$JSON_BACKEND" in
        jq)
            jq -r '.outbounds[]? | .tag // empty' "$1" 2>/dev/null
            ;;
        jsonfilter)
            jsonfilter -i "$1" -e '@.outbounds[*].tag' 2>/dev/null
            ;;
        *)
            return 1
            ;;
    esac
}

# 响应是否是期望的结构：outbounds 为数组。非零表示这次响应不可用。
json_has_outbounds() {
    case "$JSON_BACKEND" in
        jq)
            jq -e '(.outbounds | type) == "array"' "$1" >/dev/null 2>&1
            ;;
        jsonfilter)
            # -t 打印匹配值的类型名：outbounds 必须是 array。
            # 直接取 @.outbounds 不行 —— 空对象 {} 也算"有该键"。
            jsonfilter -i "$1" -t '@.outbounds' 2>/dev/null | grep -qx 'array'
            ;;
        *)
            return 1
            ;;
    esac
}

# ---------- RESTful API 取数 ----------
# 从配置文件提取 restful-api 段的监听地址与 secret。
# 依次输出三行：host、port、secret（未配置 secret 时为空行）；没有该段则无输出。
parse_restful_api() {
    awk '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s)
            sub(/[[:space:]]+$/, "", s)
            return s
        }

        # 去掉 YAML 注释。只有行首或空白之后的 # 才是注释起始，
        # 引号内的 # 一律保留 —— 否则 secret: "abc#123" 会被截成 abc。
        # 引号内的转义/双写引号也要认（"a\" #b" 里的 # 仍在引号内），
        # 否则会把引号提前收掉，后面的 # 就被当成注释。
        function strip_comment(s,   i, n, c, q, out) {
            out = ""
            q = ""
            n = length(s)

            for (i = 1; i <= n; i++) {
                c = substr(s, i, 1)

                if (q != "") {
                    out = out c

                    # 双引号里的反斜杠：连下一个字符一起吞掉。
                    if (q == "\"" && c == "\\") {
                        i++
                        out = out substr(s, i, 1)
                        continue
                    }

                    # 单引号里的两个连续单引号是一个转义的单引号。
                    if (q == "\047" && c == "\047" && substr(s, i + 1, 1) == "\047") {
                        i++
                        out = out substr(s, i, 1)
                        continue
                    }

                    if (c == q)
                        q = ""
                    continue
                }

                if (c == "\"" || c == "\047") {
                    q = c
                    out = out c
                    continue
                }

                if (c == "#" && (i == 1 || substr(s, i - 1, 1) ~ /[[:space:]]/))
                    break

                out = out c
            }

            return out
        }

        # 去掉成对引号并处理转义：双引号里只认 \\ \" \/ \n \t \r，
        # 单引号里两个连续单引号表示一个单引号。裸标量原样返回（只 trim）。
        # 遇到别的转义（\u4e2d 之类）就置 bad_escape：YAML 会把它解码成
        # 另一个字符串，这里不装作等价，整段被判为不可解析。
        function unquote(s,   i, n, q, c, out) {
            s = trim(s)
            n = length(s)
            if (n < 2)
                return s

            q = substr(s, 1, 1)
            if ((q != "\"" && q != "\047") || substr(s, n, 1) != q)
                return s

            out = ""
            for (i = 2; i < n; i++) {
                c = substr(s, i, 1)

                if (q == "\047" && c == "\047" && substr(s, i + 1, 1) == "\047") {
                    out = out "\047"
                    i++
                    continue
                }

                if (q == "\"" && c == "\\") {
                    i++
                    c = substr(s, i, 1)
                    if (c == "n") out = out "\n"
                    else if (c == "t") out = out "\t"
                    else if (c == "r") out = out "\r"
                    else if (c == "\"") out = out "\""
                    else if (c == "\\") out = out "\\"
                    else if (c == "/") out = out "/"
                    else bad_escape = 1   # 不认识的转义：整段判为不可解析
                    continue
                }

                out = out c
            }

            return out
        }

        /^[[:space:]]*#/ { next }

        # 顶层 `restful-api:` 开始，遇到下一个顶层键结束。
        /^restful-api:/ { inside = 1; next }
        inside && /^[^[:space:]]/ { inside = 0 }

        inside && /^[[:space:]]*bind-addr:/ {
            v = strip_comment($0)
            sub(/^[[:space:]]*bind-addr:[[:space:]]*/, "", v)
            addr = unquote(v)
        }

        inside && /^[[:space:]]*secret:/ {
            v = trim(strip_comment($0))
            sub(/^secret:[[:space:]]*/, "", v)

            # 块标量（`secret: |`、`secret: >-` 之类）是跨行文本，这里只解析
            # 单行标量。直接把它当字面量 "|" 用，等于给 API 发一个必然错的
            # Bearer；宁可整段判定为不可解析，让该进程走日志模式。
            # 判定用去引号前的原始标量：`secret: "|"` 是合法的一字符 secret。
            if (v ~ /^[|>][-+0-9]*$/)
                unsupported = 1
            else {
                secret = unquote(v)
                # 控制字符（\n \r \t，可能来自转义）会破坏下面三行传递格式，
                # 也会搅乱 Authorization 头；这种值宁可不认。
                if (secret ~ /[[:cntrl:]]/)
                    unsupported = 1
            }
        }

        END {
            if (addr == "" || unsupported || bad_escape)
                exit

            # 支持 [::1]:9090 / 0.0.0.0:9090 / "127.0.0.1:9090" 等写法。
            # 主机字符集限定为字母数字与 . _ -（IPv6 方括号内是十六进制与冒号/点），
            # 端口最多 5 位：这两个值会被直接拼进 URL，放行 / ? # @ 空格 之类的
            # 字符等于让配置决定请求打到哪个端点。
            if (addr ~ /^\[[0-9A-Fa-f:.]*\]:[0-9]+$/) {
                sub(/^\[/, "", addr)
                split(addr, a, /]:/)
                host = a[1]
                port = a[2]
            } else if (addr ~ /^[A-Za-z0-9._-]+:[0-9]+$/) {
                split(addr, a, /:/)
                host = a[1]
                port = a[2]
            } else {
                exit
            }

            if (length(port) > 5)
                exit

            print host
            print port
            print secret
        }
    ' "$1" 2>/dev/null
}

# 把 parse_restful_api 的三行输出读进 REST_HOST / REST_PORT / REST_SECRET。
# 必须 IFS= read：默认 IFS 会去掉字段首尾空白，`secret: " abc "` 会被悄悄
# 改成 "abc"，认证随之失败（解析层保留了空格，别在这一步又剥一次）。
read_rest_fields() {
    REST_HOST=""
    REST_PORT=""
    REST_SECRET=""

    { IFS= read -r REST_HOST; IFS= read -r REST_PORT; IFS= read -r REST_SECRET; } <<EOF
$1
EOF
}

# 调用 API：rest_api <host> <port> <secret> <method> <path> [body]
# 成功时输出响应体，失败返回非零。
rest_api() {
    local host="$1" port="$2" secret="$3" method="$4" path="$5" body="$6"
    local url

    # 通配监听地址不可直连，改用回环（与日志模式的探测口径一致）。
    case "$host" in
        0.0.0.0|"") host=127.0.0.1 ;;
        "::") host="::1" ;;
    esac

    case "$host" in
        *:*) url="http://[$host]:$port$path" ;;
        *) url="http://$host:$port$path" ;;
    esac

    # --noproxy '*' 是本机管理 API 必须的：空值 '' 表示"没有任何例外主机"，
    # 等于强迫请求走代理 —— 若环境里配了 http_proxy，API 请求（连同一串
    # Bearer secret）会被送进代理，既失败又泄露凭据。
    set -- curl --silent --show-error --fail \
        --noproxy '*' \
        --max-time "$API_TIMEOUT" -X "$method" "$url"

    if [ -n "$secret" ]; then
        set -- "$@" -H "Authorization: Bearer $secret"
    fi

    if [ -n "$body" ]; then
        set -- "$@" -H "Content-Type: application/json" -d "$body"
    fi

    "$@" 2>/dev/null
}

# 从已落盘的 API 响应里取出本轮要上报的采样，每行一条：
#
#   <tag>\t<link>\t<rtt>\t<lost>\t<sent>\t<mtu>\t<sample_age_ms>
#
# 全部字段都已校验成合法数值、tag 不含控制字符，调用方可以直接拼 JSON。
# 返回非零表示响应结构与预期不一致（长度对不上、有出站取不出 tag），
# 本进程本轮放弃走 REST，让日志路径继续工作 —— 宁可少报一轮，
# 也不要把错位的数据报上去，或者把"无法解析的响应"当成"没有数据要报"。
rest_collect_samples() {
    local file="$1"
    local n n_tags idx base tag link p age rtt lost sent mtu identified

    n=$(json_array_len "$file" outbounds)
    case "$n" in
        ''|*[!0-9]*)
            dbg "rest: cannot read outbounds length"
            return 1
            ;;
    esac

    # 空数组当作响应不可用：这样的进程不可能有出站统计，把它的日志路径
    # 挡住只会让数据彻底消失。
    if [ "$n" -eq 0 ]; then
        dbg "rest: outbounds is empty"
        return 1
    fi

    # 交叉校验：tag 行数必须与数组长度一致，否则说明有出站缺 tag，
    # 下标与 tag 的对应关系就不成立了。
    n_tags=$(json_outbound_tags "$file" | wc -l | tr -d ' ')
    if [ "$n_tags" -ne "$n" ]; then
        dbg "rest: $n outbound(s) but $n_tags tag(s), payload shape unexpected"
        return 1
    fi

    dbg "rest: $file has $n outbound(s)"

    idx=0
    identified=0
    while [ "$idx" -lt "$n" ]; do
        base="outbounds[$idx]"
        idx=$((idx + 1))

        if ! tag=$(json_get "$file" "$base.tag") || [ -z "$tag" ]; then
            dbg "rest: outbound #$((idx - 1)) has no usable tag"
            continue
        fi

        # 控制字符会破坏行内字段分隔，这条出站本轮跳过（不影响其它出站）。
        case "$tag" in
            *[[:cntrl:]]*)
                dbg "rest: outbound #$((idx - 1)) tag contains control characters, skipped"
                continue
                ;;
        esac
        identified=$((identified + 1))

        # sample_age_ms 缺失或非数字时无法判断新鲜度：整条出站跳过，
        # 绝不当成 0（否则过期采样会被永远当成最新数据反复上报）。
        if ! age=$(json_get "$file" "$base.quality.sq_conn_stats.sample_age_ms"); then
            dbg "rest: tag=$tag has no sample_age_ms, skipped"
            continue
        fi
        if ! is_uint_range "$age" "$COUNTER_MAX"; then
            dbg "rest: tag=$tag has invalid sample_age_ms=$age, skipped"
            continue
        fi

        for link in uplink downlink; do
            p="$base.quality.sq_conn_stats.$link"

            if ! rtt=$(json_get "$file" "$p.rtt"); then
                continue
            fi
            if ! lost=$(json_get "$file" "$p.lost_packets"); then
                continue
            fi
            if ! sent=$(json_get "$file" "$p.sent_packets"); then
                continue
            fi
            if ! mtu=$(json_get "$file" "$p.current_mtu"); then
                continue
            fi

            # 逐字段校验，不拼起来一起看：某个字段是空串时，拼接结果仍可能
            # 通过"全是数字"的检查，随后被 printf 当成 0 报出去。
            if ! is_valid_rtt "$rtt"; then
                dbg "rest: tag=$tag link=$link invalid rtt=$rtt, skipped"
                continue
            fi
            if ! is_uint_range "$lost" "$COUNTER_MAX" ||
                ! is_uint_range "$sent" "$COUNTER_MAX"; then
                dbg "rest: tag=$tag link=$link invalid counters lost=$lost sent=$sent, skipped"
                continue
            fi
            # mtu 是 u16 量级，限定范围同时也挡住了会溢出 printf %d 的大数。
            if ! is_uint_range "$mtu" 65535; then
                dbg "rest: tag=$tag link=$link invalid mtu=$mtu, skipped"
                continue
            fi

            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$tag" "$link" "$rtt" "$lost" "$sent" "$mtu" "$age"
        done
    done

    if [ "$identified" -ne "$n" ]; then
        dbg "rest: only $identified/$n outbounds identified"
        return 1
    fi
    return 0
}

# 该 pid 本轮是否已经由 REST 取数（决定日志路径是否跳过它）。
is_rest_pid() {
    [ -s "$REST_PIDS_FILE" ] || return 1
    grep -qx "$1" "$REST_PIDS_FILE" 2>/dev/null
}

# probe 端点把 tag 放在 URL 路径里，只接受不会再被 URL 语义吃掉的字符；
# 其它字符（/ ? # 空格 等）本轮跳过 probe，不影响该出站的采样上报。
# "." 与 ".." 也要挡：curl 会按 URL 规则把它们当成路径段规范化掉，
# /api/v1/outbounds/../probe 会变成别的端点。
tag_url_safe() {
    case "$1" in
        ''|.|..|*[!A-Za-z0-9._~-]*) return 1 ;;
        *) return 0 ;;
    esac
}

# 逐个 shadowquic 进程尝试 REST 取数并上报。
# API 不可达、响应不合法、响应结构不符时都不写 $REST_PIDS_FILE，
# 日志路径下一轮自然接管。
refresh_rest() {
    local pids pid config_path rest host port secret cfg_name rest_now
    local samples tag link rtt lost sent mtu age upstream_id loss_rate

    rest_now=""

    if [ -n "$JSON_BACKEND" ]; then
        pids=$(pgrep -f '[s]hadowquic' 2>/dev/null)

        for pid in $pids; do
            kill -0 "$pid" 2>/dev/null || continue

            config_path=$(get_config_path "$pid")
            [ -n "$config_path" ] || continue
            [ -r "$config_path" ] || continue

            rest=$(parse_restful_api "$config_path")
            if [ -z "$rest" ]; then
                dbg "rest: PID=$pid no restful-api section, using logs"
                continue
            fi

            read_rest_fields "$rest"
            host="$REST_HOST"
            port="$REST_PORT"
            secret="$REST_SECRET"
            [ -n "$host" ] && [ -n "$port" ] || continue

            cfg_name=$(get_config_name "$pid")
            [ -n "$cfg_name" ] || continue

            # 先看 curl 自己的退出码，再看 JSON 是否完整可用：
            # 超时前收到的半截响应可以"非空但不可用"，只凭非空判断会把
            # 一次失败当成 API 可用，进而把日志路径永久挡住。
            if ! rest_api "$host" "$port" "$secret" GET /api/v1/outbounds \
                > "$JSON_FILE"; then
                dbg "rest: PID=$pid API request failed at $host:$port, using logs"
                continue
            fi

            if [ ! -s "$JSON_FILE" ] || ! json_has_outbounds "$JSON_FILE"; then
                dbg "rest: PID=$pid API returned unusable payload, using logs"
                continue
            fi

            # 取数成功后再切换归属：此处之前任何失败都不影响日志路径。
            samples=$(rest_collect_samples "$JSON_FILE")
            if [ $? -ne 0 ]; then
                dbg "rest: PID=$pid API payload has unexpected shape, using logs"
                continue
            fi

            # 归属切换必须早于 probe：probe 会经 outbound.handle 触发
            # print_stats 往 syslog 写一条，若此时 pid 还没进列表，
            # 日志路径会把这同一次采样再报一遍。
            printf '%s\n' "$pid" >> "$REST_PIDS_FILE"
            rest_now="$rest_now $pid"

            dbg "rest: PID=$pid API ok at $host:$port, ${samples:+reporting samples}"

            printf '%s\n' "$samples" | while IFS='	' read -r tag link rtt lost sent mtu age; do
                [ -n "$tag" ] || continue

                if is_age_stale "$age" "$MAX_SAMPLE_AGE_MS"; then
                    dbg "rest: skip stale sample tag=$tag link=$link age_ms=$age"
                    continue
                fi

                # 与日志路径的 packet_loss_rate 完全同口径：lost/(sent+1)。
                loss_rate=$(loss_rate_from "$lost" "$sent")
                # 兜底：上面已按位数挡住会算出 nan/inf 的输入，这里再确认
                # 结果本身是纯十进制数，免得把 "-nan" 之类拼进报文。
                case "$loss_rate" in
                    ''|*[!0-9.]*)
                        dbg "rest: tag=$tag link=$link invalid loss_rate=$loss_rate, skipped"
                        continue
                        ;;
                esac
                upstream_id="${cfg_name}_${tag}"

                json_string=$(build_report_json \
                    "$upstream_id" "$pid" "$rtt" "$loss_rate" "$mtu" "$link")
                if [ $? -ne 0 ] || [ -z "$json_string" ]; then
                    dbg "rest: ERROR cannot build report for $upstream_id"
                    continue
                fi

                dbg "rest: reporting $json_string"
                send_json "$json_string" ||
                    dbg "rest: ERROR failed to report $upstream_id"
            done

            # 再用 probe 端点喂一次流量，让 shadowquic 刷新连接采样（它会经
            # outbound.handle 打开会话并触发 print_stats），供下一轮读取。
            # 每个出站都探：采样正是靠 probe 刷新的，上面因过期或缺失被跳过
            # 上报的出站尤其需要，否则它永远刷新不出来。冷启动时没有任何
            # 采样，走的也是这条路。
            #
            # REFRESH_URL 走 JSON 转义，别让 URL 里的引号把报文搞坏。
            json_outbound_tags "$JSON_FILE" | sort -u | while read -r tag; do
                [ -n "$tag" ] || continue
                if ! tag_url_safe "$tag"; then
                    dbg "rest: skip probe for tag=$tag (not URL-path safe)"
                    continue
                fi
                rest_api "$host" "$port" "$secret" POST \
                    "/api/v1/outbounds/$tag/probe" \
                    "{\"url\":\"$(json_escape "$REFRESH_URL")\",\"timeout_ms\":$PROBE_TIMEOUT_MS}" \
                    >/dev/null ||
                    dbg "rest: probe failed tag=$tag (ignored)"
            done
        done
    fi

    # 本轮成功的 pid 已用追加方式写进列表（读侧立刻可见）；这里再原子替换成
    # 只含本轮 pid 的列表，清掉已经不再走 REST 的进程。必须先写临时文件再
    # mv：截断会让读侧看到"空列表"，那一瞬间的日志会被重复上报。
    : > "$REST_PIDS_FILE.tmp"
    for pid in $rest_now; do
        printf '%s\n' "$pid" >> "$REST_PIDS_FILE.tmp"
    done
    mv "$REST_PIDS_FILE.tmp" "$REST_PIDS_FILE"
}

# ---------- 刷新功能 ----------
# 从配置提取所有 bind-addr，每行输出 "host port"。
# 一份配置可含多个 inbound，需全部探测；
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

        # REST 已接管该进程时不再按 inbound 探测：数据来源换成 API 之后，
        # 喂流量由 outbound 级 probe 完成，重复探测纯属浪费。
        if is_rest_pid "$pid"; then
            dbg "refresh: PID=$pid served by REST, skip inbound probe"
            continue
        fi

        # 一份配置可有多个 inbound（多个 bind-addr），全部探测。探测
        # 仅用于触发流量，让每个 inbound 对应的出站都向 syslog 输出
        # stats；上报身份由日志里的 outbound tag 决定，无需端口映射。
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
            # 并发探测：一份配置可有多个 bind-addr，串行时每个失败探测
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
        # REST 列表由 refresh_rest 自己维护（追加 + 轮末原子替换），
        # 这里不能先清空：清空到重新写入之间，日志路径会把同一个
        # print_stats 再报一遍。
        refresh_rest
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

# 数值型环境变量的统一校验：非数字、空或 0 时回退到默认值，
# 避免 sleep / curl 直接失败造成无间隔高速循环。
num_or() {
    case "$1" in
        ''|*[!0-9]*|0) printf '%s' "$2" ;;
        *) printf '%s' "$1" ;;
    esac
}

main() {
    # REFRESH_INTERVAL 非法时额外发一条 syslog：这项配错会直接打满 CPU。
    case "$REFRESH_INTERVAL" in
        ''|*[!0-9]*|0)
            logger -t xtp-stats-reporter \
                "WARNING: invalid REFRESH_INTERVAL=$REFRESH_INTERVAL, using 30"
            REFRESH_INTERVAL=30
            ;;
    esac

    API_TIMEOUT=$(num_or "$API_TIMEOUT" 5)
    PROBE_TIMEOUT_MS=$(num_or "$PROBE_TIMEOUT_MS" 3000)
    MAX_SAMPLE_AGE_MS=$(num_or "$MAX_SAMPLE_AGE_MS" 120000)

    if ! command -v socat >/dev/null 2>&1; then
        logger -t xtp-stats-reporter "ERROR: socat not found, exiting"
        exit 1
    fi

    detect_json_backend
    if [ -z "$JSON_BACKEND" ]; then
        # 没有 jq 也没有 jsonfilter：REST 模式不可用，但日志模式照常工作。
        logger -t xtp-stats-reporter \
            "NOTICE: neither jq nor jsonfilter found, REST stats mode disabled (logs only)"
    fi
    dbg "json backend: ${JSON_BACKEND:-none}"

    trap 'exit 0' INT TERM HUP
    trap 'cleanup' EXIT

    # 状态文件（pid 列表、API 响应、FIFO）放进 0700 的私有目录。
    # /tmp 一般对本地用户可写，用可预测的名字再直接重定向等于把
    # "截断/覆写任意文件"的机会交出去；mktemp -d 建成 0700，抢占不了。
    STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/shadowquic-stats-report.XXXXXX") || {
        logger -t xtp-stats-reporter "ERROR: cannot create state dir under ${TMPDIR:-/tmp}, exiting"
        exit 1
    }
    REST_PIDS_FILE="$STATE_DIR/rest-pids"
    JSON_FILE="$STATE_DIR/outbounds.json"
    SEND_FAIL_FILE="$STATE_DIR/send-failures"
    FIFO="$STATE_DIR/stats.fifo"

    if [ "$DEBUG" = "1" ]; then
        : > "$DEBUG_LOG"
        dbg "script started: socket=$SOCKET state_dir=$STATE_DIR"
    fi

    if ! mkfifo "$FIFO"; then
        dbg "ERROR: cannot create FIFO: $FIFO"
        exit 1
    fi

    if [ "$DEBUG" = "1" ]; then
        logread -f -e 'shadowquic\[[0-9][0-9]*\].*\(uplink\|downlink\) connection stats ' > "$FIFO" 2>>"$DEBUG_LOG" &
    else
        logread -f -e 'shadowquic\[[0-9][0-9]*\].*\(uplink\|downlink\) connection stats ' > "$FIFO" 2>/dev/null &
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
        handle_log_line "$line"
    done < "$FIFO"

    # 通常不会走到这里；若 logread 异常退出而 FIFO EOF，会正常退出。
    dbg "logread stream ended"
    exit 0
}

# 日志模式：解析一行 syslog 并上报。
handle_log_line() {
    local line="$1" parsed_data pid rtt loss_rate mtu link outbound_tag
    local cfg_name cfg_rc upstream_id json_string

    # 防御性措施：即使以后有人重新将 stderr 写回 syslog，
    # 也绝不处理本脚本自己的调试信息。
    case "$line" in
        *"[shadowquic-stats-report]"*)
            return 0
            ;;
    esac

    # 必须是 shadowquic[PID]: 格式。
    case "$line" in
        *"shadowquic["*"]:"*)
            ;;
        *)
            return 0
            ;;
    esac

    case "$line" in
        *"uplink connection stats "*|*"downlink connection stats "*)
            ;;
        *)
            return 0
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

            if ($0 ~ /uplink connection stats /)
                link = "uplink"
            else if ($0 ~ /downlink connection stats /)
                link = "downlink"
            else
                exit

            # 新版日志带 tracing span 前缀，出站隧道由 outbound{tag=...}
            # 标识。该 tag 与配置名一起拼成上报的 upstream_id
            # （<配置名>_<tag>，见下方主循环），xtp-rs 侧 id 须完全一致。
            # 用 index/substr 而非 brace 正则，避免 busybox awk 兼容问题；
            # 必须遇到 "}" 才算完整 tag，防止日志其他位置恰好含
            # "outbound{tag=" 字样时误提取。
            otag = ""
            i = index($0, "outbound{tag=")
            if (i > 0) {
                rest = substr($0, i + length("outbound{tag="))
                j = index(rest, "}")
                if (j > 1)
                    otag = substr(rest, 1, j - 1)
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

            printf "%s|%s|%s|%s|%s|%s\n", pid, rtt, loss, mtu, link, otag
        }'
    )

    if [ -z "$parsed_data" ]; then
        dbg "ERROR: parsing failed; no parsed_data generated"
        return 0
    fi

    IFS='|' read -r pid rtt loss_rate mtu link outbound_tag <<EOF
$parsed_data
EOF

    # 该进程已由 REST 取数：日志和 API 出自同一个 print_stats，报两遍没有意义。
    if is_rest_pid "$pid"; then
        dbg "skip log-path report: pid=$pid served by REST"
        return 0
    fi

    [ -n "$rtt" ] || rtt=0
    [ -n "$loss_rate" ] || loss_rate=0
    [ -n "$mtu" ] || mtu=0

    dbg "parsed: pid=$pid rtt=$rtt loss_rate=$loss_rate mtu=$mtu link=$link outbound_tag=${outbound_tag:-none}"

    # 日志缺 outbound tag（格式异常）时无法与 xtp-rs upstream id 对应，
    # 直接跳过本次上报，避免无意义的上报。
    if [ -z "$outbound_tag" ]; then
        dbg "skip report: no outbound tag for pid=$pid"
        return 0
    fi

    cfg_name=$(get_config_name "$pid")
    cfg_rc=$?

    dbg "config name lookup: pid=$pid cfg_name=$cfg_name rc=$cfg_rc"

    # 进程刚退出（cmdline 已消失）等场景拿不到配置名，拼出的 id 在
    # xtp-rs 侧必然匹配不上，直接跳过本次上报。
    if [ "$cfg_rc" -ne 0 ] || [ -z "$cfg_name" ]; then
        dbg "skip report: no config name for pid=$pid"
        return 0
    fi

    # upstream_id = <配置名>_<出站 tag>：
    # - 配置名跨进程去重（不同 shadowquic 进程可能用相同出站 tag）；
    # - 出站 tag 区分同一进程内的多条出站隧道。
    upstream_id="${cfg_name}_${outbound_tag}"

    dbg "upstream_id=$upstream_id"

    # 发之前再确认一次归属：上面那次 is_rest_pid 检查之后、到这里之前，
    # 刷新循环可能刚好把这个进程切成 REST 取数。紧贴发送再查一次能把
    # "检查—发送"这个窗口压到最小；要彻底消除得靠按采样身份去重，
    # 而切换瞬间重复上报同一次采样对 xtp-rs 只是幂等更新。
    if is_rest_pid "$pid"; then
        dbg "skip log-path report (late check): pid=$pid served by REST"
        return 0
    fi

    json_string=$(build_report_json \
        "$upstream_id" "$pid" "$rtt" "$loss_rate" "$mtu" "$link")
    if [ $? -ne 0 ] || [ -z "$json_string" ]; then
        dbg "ERROR: cannot build report for pid=$pid upstream_id=$upstream_id"
        return 0
    fi

    if ! send_json "$json_string"; then
        dbg "ERROR: failed to report pid=$pid upstream_id=$upstream_id"
    fi

    return 0
}

# 被单测 source 时（STATS_REPORTER_TEST=1）只加载函数定义，不启动服务。
if [ "${STATS_REPORTER_TEST:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

main
