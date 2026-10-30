#!/bin/sh

# 只走 RESTful API 的性能上报 daemon（logread 模式已移除）。
#
# 数据来源只有 ShadowQUIC 的 REST API：
#
#   1. GET  /api/v1/outbounds              取各出站的上/下行连接采样；
#   2. POST /api/v1/outbounds/<tag>/probe   喂一次流量，让采样下轮可读。
#
# 因此每个 ShadowQUIC 进程的配置里都必须有顶层 `restful-api:` 段：没有这一段，
# 或者这一段解析不出来，一律报错退出 —— 这个版本没有日志回落路径，静默跳过
# 等于永远没有数据。退出后由 procd 重启，报错会持续出现在 syslog 里。
#
# 发给 xtp-rs 的报文格式与旧版一致，xtp-rs 侧无需任何改动。

# 可由 procd 的：
# procd_set_param env DEBUG=0
# 覆盖。
DEBUG="${DEBUG:-0}"
DEBUG_LOG="${DEBUG_LOG:-/tmp/shadowquic-stats-report.debug.log}"
SOCKET="${SOCKET:-/tmp/xtp-rs-report.sock}"
REFRESH_INTERVAL="${REFRESH_INTERVAL:-30}"   # 取数 / 喂流量周期（秒）
REFRESH_URL="${REFRESH_URL:-http://cp.cloudflare.com/generate_204}"   # 探测目标 URL

API_TIMEOUT="${API_TIMEOUT:-5}"                    # 单个 API 请求超时（秒）
PROBE_TIMEOUT_MS="${PROBE_TIMEOUT_MS:-3000}"       # probe 喂流量超时（毫秒）
# 采样超过该年龄就不上报，避免隧道空闲或 probe 失败时反复推同一份过期数据。
MAX_SAMPLE_AGE_MS="${MAX_SAMPLE_AGE_MS:-120000}"

# 三者在 main() 里落到 mktemp -d 建的私有目录中 —— /tmp 是可写的共享目录，
# 用可预测的 $$ 命名再直接 > 重定向，等于给本地用户一个符号链接攻击面。
JSON_FILE=""
SEND_FAIL_FILE=""
API_FAIL_FILE=""
STATE_DIR=""

# JSON 解析后端：优先 jq（自带 @json、表达式更完整），
# OpenWrt 上一般只有 libubox 的 jsonfilter。两者都没有时无法取数，
# 启动阶段直接报错退出。
JSON_BACKEND=""

SLEEP_PID=""
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

# 致命错误：写 syslog 后退出。配置不满足要求时用它，不做降级。
die() {
    logger -t xtp-stats-reporter "ERROR: $*"
    dbg "fatal: $*"
    exit 1
}

cleanup() {
    # 防止 EXIT trap、TERM trap 等多次调用 cleanup。
    [ "$CLEANED" = "1" ] && return 0
    CLEANED=1

    dbg "cleanup started: sleep_pid=${SLEEP_PID:-none}"

    # 周期等待中的后台 sleep 可能还在跑，退出时一并收掉。
    if [ -n "$SLEEP_PID" ]; then
        kill "$SLEEP_PID" 2>/dev/null
        wait "$SLEEP_PID" 2>/dev/null
        SLEEP_PID=""
    fi

    rm -f "$JSON_FILE" "$SEND_FAIL_FILE" "$API_FAIL_FILE"
    # 整个私有状态目录一起删（含 mktemp 建的目录本身）。
    if [ -n "$STATE_DIR" ]; then
        rm -rf "$STATE_DIR"
    fi

    dbg "cleanup completed"
}

# ---------- 进程识别与配置解析 ----------
# cmdline_is_shadowquic：从 stdin 读 cmdline 文本（NUL 或换行分隔，首行是
# argv[0]），判 argv[0] 的 basename 是否以 shadowquic 开头。
# pgrep -f 会把命令行里带 "shadowquic" 的无关进程一起命中（编辑器、tail、
# 包装脚本），而"配置里没有 restful-api 就退出"是致命判定，绝不能被
# `vim shadowquic.yaml` 之类的进程触发，所以这里再按 argv[0] 过一遍。
# 抽成纯函数是为了单测能直接喂造出来的 cmdline：换台机器往往找不到一个
# "改名之后还肯运行"的替身进程（例如 uutils 的 coreutils 会校验 argv[0]）。
cmdline_is_shadowquic() {
    local exe

    IFS= read -r exe || :

    case "${exe##*/}" in
        shadowquic*) return 0 ;;
    esac

    return 1
}

is_shadowquic_pid() {
    local cmdline="/proc/$1/cmdline"

    # 先判可读：否则重定向失败会在 stderr 上留下 "cannot open ..."，
    # 而 pid 不存在是轮询里的正常情况（进程刚退出）。
    [ -r "$cmdline" ] || return 1

    tr '\0' '\n' < "$cmdline" 2>/dev/null | cmdline_is_shadowquic
}

# 从 cmdline 文本（同上，首行 argv[0]）里挑出配置文件参数。取不到时无输出。
# 支持以下参数格式：
#
# shadowquic -c /etc/xray/shadowquic/niyaou.yaml
# shadowquic -c=/etc/xray/shadowquic/niyaou.yaml
# shadowquic --config /etc/xray/shadowquic/niyaou.yaml
# shadowquic --config=/etc/xray/shadowquic/niyaou.yaml
parse_config_arg() {
    awk '
        { a[NR] = $0 }

        END {
            # argv[0] 是程序路径，从 argv[1] 开始扫描。
            for (i = 2; i <= NR; i++) {

                # `--` 是选项结束符（clap 也是这个语义）：后面都是位置参数，
                # 不可能再有 -c / --config，继续扫只会把位置参数误认成配置。
                if (a[i] == "--")
                    break

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

# 从 /proc/PID/cmdline 提取配置文件路径。取不到时返回非零。
get_config_path() {
    local pid="$1"
    local cmdline_file="/proc/$pid/cmdline"
    local cfg_file

    if [ ! -r "$cmdline_file" ]; then
        dbg "PID=$pid: cannot read $cmdline_file"
        return 1
    fi

    cfg_file=$(tr '\0' '\n' < "$cmdline_file" 2>/dev/null | parse_config_arg)

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

# 丢包率：lost/(sent+1)，四位小数。与 ShadowQUIC 日志里的 packet_loss_rate 同口径。
# 注意：输入若不是普通整数（比如 40 位以上的计数），awk 会算出 inf/nan，
# 调用方必须先用 is_uint_range 挡住，并在用之前校验结果是不是十进制数。
loss_rate_from() {
    awk -v lost="$1" -v sent="$2" 'BEGIN { printf "%.4f", lost / (sent + 1) }'
}

# 构造上报报文。
# 参数：upstream_id peer rtt loss_rate mtu link
build_report_json() {
    printf '{"upstream_id":"%s","peer":"%s","rtt_ms":%.3f,"loss_rate":%.4f,"mtu":%d,"link":"%s"}' \
        "$(json_escape "$1")" "$2" "$3" "$4" "$5" "$6"
}

send_json() {
    local json="$1"
    local t_start t_end rc

    if [ ! -S "$SOCKET" ]; then
        # 最常见的一种故障（xtp-rs 没起来 / SOCKET 配错）也走失败计数：
        # 只写 debug 日志的话，DEBUG=0 时它会一直静默。
        dbg "ERROR: socket does not exist or is not a Unix socket: $SOCKET"
        count_send_failure 1
        return 1
    fi

    t_start=$(monotime)
    dbg "sending JSON via UNIX datagram: $json"

    # 这里的发送没有时间上界，别指望 socat 的选项补上：-t 是"一个方向 EOF
    # 后的关闭阶段等待"，-T 是传输循环内的无活动超时，都不是"整次发送的总
    # 超时"，也打断不了卡在 sendto 上的写。前台命令执行期间 TERM 只会被记下，
    # 收尾要等它自己返回（procd 的 term_timeout 到点会 SIGKILL，清理就跑不掉）。
    # 已知残留风险，未修。
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

# 连续失败计数。落盘而不是放变量：上报都在管道的 while 子 shell 里执行，
# 进程内变量每轮都会重置，"连续失败 60 次报一次 syslog"永远不会触发。
#
# 计数方式是"每次失败往文件追加一个字节，用文件大小当计数"：成功后清零
# 与失败写入可能交错，读-加-写会丢更新，而 O_APPEND 的单字节写入不会。
# 所以这是一个近似计数，只用来"别让它静默失败"，不承担精确语义。
count_failure() {
    local file="$1" msg="$2" n

    [ -n "$file" ] || return 0

    printf 'x' >> "$file" 2>/dev/null
    n=$(wc -c < "$file" 2>/dev/null | tr -d ' ')
    case "$n" in
        ''|*[!0-9]*) return 0 ;;
    esac

    # 首次失败立刻报一次（否则要等半个周期才知道坏了），之后每 60 次一条：
    # 判等用 (n % 60) -eq 1，命中的是第 1、61、121… 次。
    if [ $((n % 60)) -eq 1 ]; then
        logger -t xtp-stats-reporter \
            "WARNING: $msg (consecutive failures: $n)"
    fi
    return 0
}

count_send_failure() {
    count_failure "$SEND_FAIL_FILE" "send failed (socket=$SOCKET, rc=$1)"
}

count_api_failure() {
    count_failure "$API_FAIL_FILE" "API request failed ($1)"
}

clear_failures() {
    [ -n "$1" ] && rm -f "$1" 2>/dev/null
    return 0
}

clear_send_failures() {
    clear_failures "$SEND_FAIL_FILE"
}

clear_api_failures() {
    clear_failures "$API_FAIL_FILE"
}

# 清掉已经退出的实例的计数文件。按 pid 分文件之后，shadowquic 反复重启会在
# 状态目录里留下越来越多的小文件；pid 不在了就没有"连续失败"可言，直接删。
prune_stale_api_failures() {
    local f

    for f in "$STATE_DIR"/api-failures.*; do
        [ -e "$f" ] || continue
        kill -0 "${f##*.}" 2>/dev/null || rm -f "$f"
    done
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
# 一行，末尾缺 tag 就会被静默忽略（全部缺 tag 时会误判成"成功但没有数据"）。
#
# 两个后端都没有 length：jsonfilter 用 -t 逐个下标探存在性。
# 元素本身为 null 时 jsonfilter 会提前收手，所以调用方还要和 tag 行数交叉校验。
#
# 两个后端的算法并不等价，这里如实记下各自实现，别当成"口径已对齐"：
#   jq        — 数整个数组里非 null 元素的个数；
#   jsonfilter — 从下标 0 顺序探到第一个 null（或越界）为止，之后的元素不计。
# 因此同一份含 null 的响应可能得到不同的 n，调用方不能只靠 n 成立：
# tag 行数必须等于 n、遍历完 identified 必须等于 n，否则整轮放弃上报。
# 已知表现：首部 null（下标 0 取不到 tag）与中间的 null（identified 偏小）都会
# 报结构异常；尾部 null 不会被遍历到，等于被忽略 —— 它本身也没有采样可取。
# jsonfilter 遇到 null 时究竟停在哪，本机没有该后端，未实测。
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

# 所有出站 tag，每行一个（数组顺序）。用于统计出站个数与逐个 probe：
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
# 成功时输出三行：host、port、secret（未配置 secret 时为空行）。
#
# 注意这里不是 YAML 解析器，只认顶层 `restful-api:` 段里的单行 `bind-addr:` /
# `secret:` 两个键（块标量、不支持的转义一律判为不可解析）。段的边界只按"下一个
# 顶格行"切分，不校验缩进层级 —— 该段内部更深层的同名 `secret:` / `bind-addr:`
# 同样会被匹配，这是已知限制。
#
# 返回值区分两种不可用：
#   2 — 有 `restful-api:` 段，但这一段的写法解析不出来（含不支持的 secret
#       写法、地址不合法等）；
#   3 — 根本没有顶层 `restful-api:` 段。
# 两者都是致命错误，分开只为让 syslog 里的原因说得清楚。
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
        /^restful-api:/ { inside = 1; found = 1; next }
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
            # Bearer；宁可整段判定为不可解析。
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
            # 没有该段：与"有段但解析不出来"分开报，调用方据此给出不同提示。
            if (!found || addr == "" || unsupported || bad_escape)
                exit (found ? 2 : 3)

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
                exit 2
            }

            if (length(port) > 5)
                exit 2

            # 光看位数不够：127.0.0.1:99999 会通过上面的检查，之后每轮 curl
            # 都失败。端口必须落在可连接范围内（0 拿来当"动态端口"的话，脚本
            # 也无从得知实际端口，同样按不可解析处理）。
            if (port + 0 < 1 || port + 0 > 65535)
                exit 2

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

    # 通配监听地址不可直连，改用回环。
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
# 本轮放弃上报 —— 宁可少报一轮，也不要把错位的数据报上去，
# 或者把"无法解析的响应"当成"没有数据要报"。
rest_collect_samples() {
    local file="$1"
    local n n_tags idx base tag link p age rtt lost sent mtu identified

    n=$(json_array_len "$file" outbounds)
    case "$n" in
        ''|*[!0-9]*)
            dbg "api: cannot read outbounds length"
            return 1
            ;;
    esac

    # 空数组当作响应不可用：这样的进程不可能有出站统计。
    if [ "$n" -eq 0 ]; then
        dbg "api: outbounds is empty"
        return 1
    fi

    # 交叉校验：tag 行数必须与数组长度一致，否则说明有出站缺 tag，
    # 下标与 tag 的对应关系就不成立了。
    n_tags=$(json_outbound_tags "$file" | wc -l | tr -d ' ')
    if [ "$n_tags" -ne "$n" ]; then
        dbg "api: $n outbound(s) but $n_tags tag(s), payload shape unexpected"
        return 1
    fi

    dbg "api: $file has $n outbound(s)"

    idx=0
    identified=0
    while [ "$idx" -lt "$n" ]; do
        base="outbounds[$idx]"
        idx=$((idx + 1))

        if ! tag=$(json_get "$file" "$base.tag") || [ -z "$tag" ]; then
            dbg "api: outbound #$((idx - 1)) has no usable tag"
            continue
        fi

        # 控制字符会破坏行内字段分隔，这条出站本轮跳过（不影响其它出站）。
        case "$tag" in
            *[[:cntrl:]]*)
                dbg "api: outbound #$((idx - 1)) tag contains control characters, skipped"
                continue
                ;;
        esac
        identified=$((identified + 1))

        # sample_age_ms 缺失或非数字时无法判断新鲜度：整条出站跳过，
        # 绝不当成 0（否则过期采样会被永远当成最新数据反复上报）。
        if ! age=$(json_get "$file" "$base.quality.sq_conn_stats.sample_age_ms"); then
            dbg "api: tag=$tag has no sample_age_ms, skipped"
            continue
        fi
        if ! is_uint_range "$age" "$COUNTER_MAX"; then
            dbg "api: tag=$tag has invalid sample_age_ms=$age, skipped"
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
                dbg "api: tag=$tag link=$link invalid rtt=$rtt, skipped"
                continue
            fi
            if ! is_uint_range "$lost" "$COUNTER_MAX" ||
                ! is_uint_range "$sent" "$COUNTER_MAX"; then
                dbg "api: tag=$tag link=$link invalid counters lost=$lost sent=$sent, skipped"
                continue
            fi
            # mtu 是 u16 量级，限定范围同时也挡住了会溢出 printf %d 的大数。
            if ! is_uint_range "$mtu" 65535; then
                dbg "api: tag=$tag link=$link invalid mtu=$mtu, skipped"
                continue
            fi

            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$tag" "$link" "$rtt" "$lost" "$sent" "$mtu" "$age"
        done
    done

    if [ "$identified" -ne "$n" ]; then
        dbg "api: only $identified/$n outbounds identified"
        return 1
    fi
    return 0
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

# 轮询一轮：逐个 ShadowQUIC 进程取数、上报，并 probe 一次喂流量。
# 配置里没有（或解析不出）`restful-api:` 段时退出 —— 这个版本只走
# RESTful API，没有日志回落路径。
poll_outbounds() {
    local pids pid config_path rest rc host port secret cfg_name
    local samples tag link rtt lost sent mtu age upstream_id loss_rate json_string

    pids=$(pgrep -f '[s]hadowquic' 2>/dev/null)
    if [ -z "$pids" ]; then
        dbg "poll: no shadowquic process found"
        return 0
    fi

    for pid in $pids; do
        kill -0 "$pid" 2>/dev/null || continue
        is_shadowquic_pid "$pid" || continue

        # 失败计数按 pid 分文件：不同进程的连续失败数必须互不影响。共用一个
        # 文件时，A 一直失败、B 一直成功就会每轮"A 失败 → B 成功清零 → A 又
        # 是第一次失败"，节流彻底失效。
        API_FAIL_FILE="$STATE_DIR/api-failures.$pid"

        config_path=$(get_config_path "$pid")
        if [ -z "$config_path" ]; then
            # 进程可能刚退出，也可能不是用 -c/--config 启动的：取不到配置
            # 就没法确认 restful-api 是否开启。这两种都是非标准部署，
            # 记一条 syslog 便于排查，本轮跳过。
            logger -t xtp-stats-reporter \
                "WARNING: PID=$pid config path not found, skipped"
            continue
        fi
        if [ ! -r "$config_path" ]; then
            die "PID=$pid config not readable: $config_path"
        fi

        rest=$(parse_restful_api "$config_path")
        rc=$?
        case "$rc" in
            0) ;;
            3)
                die "PID=$pid ($config_path): no top-level 'restful-api:' section, this reporter only supports the RESTful API (no logread fallback)"
                ;;
            *)
                die "PID=$pid ($config_path): 'restful-api:' section cannot be parsed (unsupported secret form or invalid bind-addr)"
                ;;
        esac

        # rc=0 已保证三行都在且 host / port 合法，这里直接取用。
        read_rest_fields "$rest"
        host="$REST_HOST"
        port="$REST_PORT"
        secret="$REST_SECRET"

        # upstream_id = <配置名>_<出站 tag>：配置名（basename，同机唯一）区分
        # 进程，出站 tag 区分同一进程内的多条隧道。
        cfg_name=$(basename "$config_path")
        cfg_name=${cfg_name%.*}
        if [ -z "$cfg_name" ]; then
            logger -t xtp-stats-reporter \
                "WARNING: PID=$pid config name is empty: $config_path, skipped"
            continue
        fi

        # 先看 curl 自己的退出码，再看 JSON 是否完整可用：超时前收到的半截
        # 响应可以"非空但不可用"，只凭非空判断会把一次失败当成 API 可用。
        # 三种失败都走计数 + 节流 syslog：REST-only 之后没有日志回落路径，
        # 只剩 debug 日志的话，"服务活着但一直没有数据"会一直不报警。
        if ! rest_api "$host" "$port" "$secret" GET /api/v1/outbounds \
            > "$JSON_FILE"; then
            dbg "poll: PID=$pid API request failed at $host:$port, retry next round"
            count_api_failure "pid=$pid host=$host port=$port request failed"
            continue
        fi

        if [ ! -s "$JSON_FILE" ] || ! json_has_outbounds "$JSON_FILE"; then
            dbg "poll: PID=$pid API returned unusable payload, retry next round"
            count_api_failure "pid=$pid host=$host port=$port unusable payload"
            continue
        fi

        samples=$(rest_collect_samples "$JSON_FILE")
        if [ $? -ne 0 ]; then
            dbg "poll: PID=$pid API payload has unexpected shape, retry next round"
            count_api_failure "pid=$pid host=$host port=$port unexpected payload shape"
            continue
        fi

        clear_api_failures
        dbg "poll: PID=$pid API ok at $host:$port"

        printf '%s\n' "$samples" | while IFS='	' read -r tag link rtt lost sent mtu age; do
            [ -n "$tag" ] || continue

            if is_age_stale "$age" "$MAX_SAMPLE_AGE_MS"; then
                dbg "poll: skip stale sample tag=$tag link=$link age_ms=$age"
                continue
            fi

            loss_rate=$(loss_rate_from "$lost" "$sent")
            # 兜底：上面已按位数挡住会算出 nan/inf 的输入，这里再确认
            # 结果本身是纯十进制数，免得把 "-nan" 之类拼进报文。
            case "$loss_rate" in
                ''|*[!0-9.]*)
                    dbg "poll: tag=$tag link=$link invalid loss_rate=$loss_rate, skipped"
                    continue
                    ;;
            esac
            upstream_id="${cfg_name}_${tag}"

            json_string=$(build_report_json \
                "$upstream_id" "$pid" "$rtt" "$loss_rate" "$mtu" "$link")
            if [ $? -ne 0 ] || [ -z "$json_string" ]; then
                dbg "poll: ERROR cannot build report for $upstream_id"
                continue
            fi

            dbg "poll: reporting $json_string"
            send_json "$json_string" ||
                dbg "poll: ERROR failed to report $upstream_id"
        done

        # 再用 probe 端点喂一次流量，让 ShadowQUIC 刷新连接采样（它会经
        # outbound.handle 打开会话并触发 print_stats），供下一轮读取。
        # 每个出站都探：采样正是靠 probe 刷新的，上面因过期或缺失被跳过
        # 上报的出站尤其需要，否则它永远刷新不出来。冷启动时没有任何
        # 采样，走的也是这条路。
        #
        # REFRESH_URL 走 JSON 转义，别让 URL 里的引号把报文搞坏。
        json_outbound_tags "$JSON_FILE" | sort -u | while read -r tag; do
            [ -n "$tag" ] || continue
            if ! tag_url_safe "$tag"; then
                dbg "poll: skip probe for tag=$tag (not URL-path safe)"
                continue
            fi
            rest_api "$host" "$port" "$secret" POST \
                "/api/v1/outbounds/$tag/probe" \
                "{\"url\":\"$(json_escape "$REFRESH_URL")\",\"timeout_ms\":$PROBE_TIMEOUT_MS}" \
                >/dev/null ||
                dbg "poll: probe failed tag=$tag (ignored)"
        done
    done

    prune_stale_api_failures
}

# 数值型环境变量的统一校验：空、非数字、前导零、0 或超过上限时回退到默认值，
# 避免 sleep / curl 直接失败造成无间隔高速循环。
# 复用 is_uint_range 而不是自己写 case：`''|*[!0-9]*|0)` 会放过 "00"
# （sleep 00 就是零秒等待）和几十位的数字（sleep / curl 会直接报错）。
num_or() {
    local v="$1" fallback="$2" max="$3"

    if is_uint_range "$v" "$max" && [ "$v" -gt 0 ]; then
        printf '%s' "$v"
    else
        printf '%s' "$fallback"
    fi
}

main() {
    # 上限只为挡住"配错成天文数字"：无限大等于永不超时，
    # 0 等于无间隔循环。正常部署的值离这些上界很远。
    interval=$(num_or "$REFRESH_INTERVAL" 30 86400)
    if [ "$interval" != "$REFRESH_INTERVAL" ]; then
        # REFRESH_INTERVAL 配错会直接打满 CPU，这项多报一条 syslog。
        logger -t xtp-stats-reporter \
            "WARNING: invalid REFRESH_INTERVAL=$REFRESH_INTERVAL, using $interval"
    fi
    REFRESH_INTERVAL=$interval

    API_TIMEOUT=$(num_or "$API_TIMEOUT" 5 3600)
    PROBE_TIMEOUT_MS=$(num_or "$PROBE_TIMEOUT_MS" 3000 3600000)
    MAX_SAMPLE_AGE_MS=$(num_or "$MAX_SAMPLE_AGE_MS" 120000 86400000)

    # 只走 RESTful API，三件依赖缺一不可，缺了就别假装在跑。
    command -v socat >/dev/null 2>&1 ||
        die "socat not found"
    command -v curl >/dev/null 2>&1 ||
        die "curl not found (required by the RESTful API mode)"
    detect_json_backend
    [ -n "$JSON_BACKEND" ] ||
        die "neither jq nor jsonfilter found (required to parse API responses)"

    trap 'exit 0' INT TERM HUP
    trap 'cleanup' EXIT

    # 状态文件（API 响应、失败计数）放进 0700 的私有目录。
    # /tmp 一般对本地用户可写，用可预测的名字再直接重定向等于把
    # "截断/覆写任意文件"的机会交出去；mktemp -d 建成 0700，抢占不了。
    STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/shadowquic-stats-report.XXXXXX") ||
        die "cannot create state dir under ${TMPDIR:-/tmp}"
    JSON_FILE="$STATE_DIR/outbounds.json"
    SEND_FAIL_FILE="$STATE_DIR/send-failures"
    # API_FAIL_FILE 不在这里定：它按 pid 分文件（见 poll_outbounds）。

    if [ "$DEBUG" = "1" ]; then
        : > "$DEBUG_LOG"
        dbg "script started: socket=$SOCKET state_dir=$STATE_DIR interval=$REFRESH_INTERVAL url=$REFRESH_URL backend=$JSON_BACKEND"
    fi

    while :; do
        poll_outbounds

        # 后台 sleep + wait 而不是直接 sleep：直接 sleep 时 TERM 要等这一轮
        # 睡完（最长一个周期）才被处理，procd 的 term_timeout 一到就 SIGKILL，
        # 收尾清理就跑不掉了。wait 会被信号打断，trap 立刻生效。
        sleep "$REFRESH_INTERVAL" &
        SLEEP_PID=$!
        wait "$SLEEP_PID" 2>/dev/null
        SLEEP_PID=""
    done
}

# 被单测 source 时（STATS_REPORTER_TEST=1）只加载函数定义，不启动服务。
if [ "${STATS_REPORTER_TEST:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

main
