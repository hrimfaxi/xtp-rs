#!/bin/sh

# stats_reporter.sh 的纯函数单测：restful-api 配置解析、JSON 转义、
# JSON 取数（jq / jsonfilter 两种后端）、REST 采样收集的字段校验。
#
# 用法：
#   sh contrib/tests/stats-reporter-test.sh
#
# 当前机器装了哪个后端就跑哪个；两个都没有时跳过 JSON 相关用例
# （正式启动时缺后端是致命错误，脚本会直接退出）。

STATS_REPORTER_TEST=1
. "$(dirname "$0")/../usr/libexec/xtp-rs/stats_reporter.sh"

PASS=0
FAIL=0
TMPDIR_TEST=$(mktemp -d /tmp/stats-reporter-test.XXXXXX) || exit 1
trap 'rm -rf "$TMPDIR_TEST"' EXIT

ok() {
    PASS=$((PASS + 1))
    printf 'ok   %s\n' "$1"
}

ng() {
    FAIL=$((FAIL + 1))
    printf 'FAIL %s\n' "$1"
    [ -n "${2:-}" ] && printf '     %s\n' "$2"
}

check_eq() {
    if [ "$2" = "$3" ]; then
        ok "$1"
    else
        ng "$1" "expected [$2] got [$3]"
    fi
}

check_rc() { # <name> <expected-rc-nonzero|zero> <rc>
    case "$2" in
        zero) [ "$3" -eq 0 ] && ok "$1" || ng "$1" "expected rc=0 got rc=$3" ;;
        nonzero) [ "$3" -ne 0 ] && ok "$1" || ng "$1" "expected nonzero rc" ;;
    esac
}

# ---------- json_escape ----------
check_eq 'json_escape 转义双引号与反斜杠' 'a\"b\\c' "$(json_escape 'a"b\c')"
check_eq 'json_escape 转义制表符' 'x\u0009y' "$(json_escape "$(printf 'x\ty')")"
check_eq 'json_escape 转义换行' 'a\nb' "$(json_escape "$(printf 'a\nb')")"
check_eq 'json_escape 保留 UTF-8' '中文_' "$(json_escape '中文_')"
check_eq 'json_escape 空串' '' "$(json_escape '')"

# ---------- 发送失败计数 ----------
# 上报都在管道的 while 子 shell 里跑，计数必须落盘才能累计；这里用假的
# logger 断言阈值行为，避免污染本机 syslog。
logger() {
    LOGGER_CALLS=$((LOGGER_CALLS + 1))
}

SEND_FAIL_FILE="$TMPDIR_TEST/send-failures"
SOCKET="/tmp/nonexistent-test.sock"
LOGGER_CALLS=0

i=0
while [ $i -lt 60 ]; do
    count_send_failure 1
    i=$((i + 1))
done
check_eq 'count_send_failure 累计到 60' '60' \
    "$(wc -c < "$SEND_FAIL_FILE" | tr -d ' ')"
check_eq 'count_send_failure 只在 1 与 61 时报 syslog' '1' "$LOGGER_CALLS"

count_send_failure 1
check_eq 'count_send_failure 第 61 次再报一次' '2' "$LOGGER_CALLS"

clear_send_failures
check_eq 'clear_send_failures 清掉计数文件' 'missing' \
    "$([ -e "$SEND_FAIL_FILE" ] && echo present || echo missing)"
SEND_FAIL_FILE=""

# socket 不存在是最常见的故障（xtp-rs 没起来 / SOCKET 配错）：它必须计入失败
# 计数，否则 DEBUG=0 时这条路径一点声音都没有。
SEND_FAIL_FILE="$TMPDIR_TEST/send-failures-socket"
LOGGER_CALLS=0
send_json '{"upstream_id":"x"}' >/dev/null 2>&1
check_rc 'send_json: socket 不存在时返回非零' nonzero $?
check_eq 'send_json: socket 不存在时计入失败' '1' \
    "$(wc -c < "$SEND_FAIL_FILE" | tr -d ' ')"
check_eq 'send_json: 首次失败立刻报一条 syslog' '1' "$LOGGER_CALLS"
SEND_FAIL_FILE=""

# API 失败同理：REST-only 之后没有日志回落，“服务活着但一直没有数据”
# 只能靠这条节流 syslog 暴露。
API_FAIL_FILE="$TMPDIR_TEST/api-failures"
LOGGER_CALLS=0
i=0
while [ $i -lt 120 ]; do
    count_api_failure "pid=1 host=127.0.0.1 port=9090 request failed"
    i=$((i + 1))
done
check_eq 'count_api_failure 首次与第 61 次各报一条' '2' "$LOGGER_CALLS"
clear_api_failures
check_eq 'clear_api_failures 清掉计数文件' 'missing' \
    "$([ -e "$API_FAIL_FILE" ] && echo present || echo missing)"
API_FAIL_FILE=""

# 计数必须按实例隔离（脚本里按 pid 分文件）：A 一直失败、B 一直成功时，B 的清零
# 不能动 A 的计数，否则"A 首次失败即告警"会退化成每轮一条。
API_FAIL_FILE="$TMPDIR_TEST/api-failures.100"
LOGGER_CALLS=0
count_api_failure "pid=100 host=127.0.0.1 port=9090 request failed"
API_FAIL_FILE="$TMPDIR_TEST/api-failures.200"
clear_api_failures
check_eq 'clear_api_failures: B 的清零不动 A 的计数文件' 'present' \
    "$([ -e "$TMPDIR_TEST/api-failures.100" ] && echo present || echo missing)"
API_FAIL_FILE="$TMPDIR_TEST/api-failures.100"
count_api_failure "pid=100 host=127.0.0.1 port=9090 request failed"
check_eq 'count_api_failure: A 的第二次失败不重复告警' '1' "$LOGGER_CALLS"
API_FAIL_FILE=""

# 按 pid 分文件之后要能收走已退出实例的计数文件，否则进程反复重启会在状态
# 目录里越堆越多。
STATE_DIR="$TMPDIR_TEST/prune"
mkdir -p "$STATE_DIR"
: > "$STATE_DIR/api-failures.99999999"
: > "$STATE_DIR/api-failures.$$"
prune_stale_api_failures
check_eq 'prune_stale_api_failures: 删掉已退出 pid 的计数文件' 'missing' \
    "$([ -e "$STATE_DIR/api-failures.99999999" ] && echo present || echo missing)"
check_eq 'prune_stale_api_failures: 保留存活 pid 的计数文件' 'present' \
    "$([ -e "$STATE_DIR/api-failures.$$" ] && echo present || echo missing)"
STATE_DIR=""

# ---------- 丢包率 -> 报文 链路 ----------
check_eq 'loss_rate_from 正常值' '0.0150' "$(loss_rate_from 150 9999)"

# 计数到 double 溢出量级（309 位以上）时 awk 会算出 -nan，printf 会把它原样
# 拼进报文（非法 JSON）。取数阶段按位数拦掉就是这个原因。
long_counter=$(awk 'BEGIN { s = ""; for (i = 0; i < 400; i++) s = s "9"; print s }')
case "$(loss_rate_from "$long_counter" "$long_counter")" in
    *[!0-9.]*) ok 'loss_rate_from 溢出的计数不是十进制数（故取数阶段拦掉）' ;;
    *) ng 'loss_rate_from 溢出的计数不是十进制数（故取数阶段拦掉）' ;;
esac

# 但 40 位（≈1e40）在 double 里仍有限，不会算成 nan —— 位数上限的作用
# 是"拒绝不可信的离谱值"，不是修一个 40 位就会崩的 bug。
forty=$(awk 'BEGIN { s = ""; for (i = 0; i < 40; i++) s = s "9"; print s }')
check_eq 'loss_rate_from 40 位输入仍是十进制数' '1.0000' \
    "$(loss_rate_from "$forty" "$forty")"

# ---------- 上报报文 ----------
# 报文格式被 xtp-rs 逐字段解析，这里锁死格式。
check_eq 'build_report_json 报文格式' \
    '{"upstream_id":"tproxy_cn_sq-out","peer":"18520","rtt_ms":301.384,"loss_rate":0.0150,"mtu":1452,"link":"uplink"}' \
    "$(build_report_json 'tproxy_cn_sq-out' '18520' '301.383866' '0.0150' '1452' 'uplink')"

check_eq 'build_report_json 转义 id 里的引号' \
    '{"upstream_id":"cfg_we\"ird","peer":"1","rtt_ms":0.000,"loss_rate":0.0000,"mtu":0,"link":"downlink"}' \
    "$(build_report_json 'cfg_we"ird' '1' '0' '0' '0' 'downlink')"

# ---------- parse_restful_api ----------
# 输出三行：host / port / secret，用 | 拼起来方便断言。
read_rest() {
    parse_restful_api "$1" | awk '
        { a[NR] = $0 }
        END { if (NR > 0) printf "%s|%s|%s", a[1], a[2], a[3] }
    '
}

cat > "$TMPDIR_TEST/a.yaml" <<'EOF'
inbounds:
  - tag: tproxy-in
    bind-addr: "[::]:10810"

restful-api:
  tag: restful-api
  bind-addr: "127.0.0.1:9090"
  secret: "abc#123"        # 引号内的 # 不是注释

log-level: "info"
EOF
check_eq 'restful-api: secret 里的 # 不被当注释' \
    '127.0.0.1|9090|abc#123' "$(read_rest "$TMPDIR_TEST/a.yaml")"

cat > "$TMPDIR_TEST/b.yaml" <<'EOF'
inbounds:
  - tag: tproxy-in
    bind-addr: "0.0.0.0:10810"
EOF
check_eq 'restful-api: 无该段时无输出' '' "$(read_rest "$TMPDIR_TEST/b.yaml")"

cat > "$TMPDIR_TEST/c.yaml" <<'EOF'
restful-api:
  bind-addr: [::1]:9090
  secret: 'it''s a secret'
EOF
check_eq 'restful-api: 裸 IPv6 / 单引号转义' \
    "::1|9090|it's a secret" "$(read_rest "$TMPDIR_TEST/c.yaml")"

cat > "$TMPDIR_TEST/d.yaml" <<'EOF'
restful-api:
  bind-addr: 0.0.0.0:9091
  secret: abc#123
EOF
check_eq 'restful-api: 裸标量里的 # 保留' \
    '0.0.0.0|9091|abc#123' "$(read_rest "$TMPDIR_TEST/d.yaml")"

cat > "$TMPDIR_TEST/e.yaml" <<'EOF'
restful-api:
  bind-addr: "127.0.0.1:9092"
  # secret: "commented-out"
EOF
check_eq 'restful-api: 被注释的 secret 视为未配置' \
    '127.0.0.1|9092|' "$(read_rest "$TMPDIR_TEST/e.yaml")"

cat > "$TMPDIR_TEST/f.yaml" <<'EOF'
restful-api:
  bind-addr: "127.0.0.1:9093"
  secret: "a b  c"
EOF
check_eq 'restful-api: secret 里的空格保留' \
    '127.0.0.1|9093|a b  c' "$(read_rest "$TMPDIR_TEST/f.yaml")"

cat > "$TMPDIR_TEST/g.yaml" <<'EOF'
restful-api:
  bind-addr: "127.0.0.1:9094"
  secret: "with \"quote\" and \\ backslash"
EOF
check_eq 'restful-api: secret 里的转义序列' \
    '127.0.0.1|9094|with "quote" and \ backslash' "$(read_rest "$TMPDIR_TEST/g.yaml")"

cat > "$TMPDIR_TEST/h.yaml" <<'EOF'
restful-api:
  bind-addr: "127.0.0.1:9095"
  secret: "abc\" #def"
EOF
check_eq 'restful-api: 转义引号后面的 # 仍在引号内' \
    '127.0.0.1|9095|abc" #def' "$(read_rest "$TMPDIR_TEST/h.yaml")"

cat > "$TMPDIR_TEST/i.yaml" <<'EOF'
restful-api:
  bind-addr: "127.0.0.1:9096"
  secret: 'a'' #b'
EOF
check_eq 'restful-api: 单引号双写 + 引号内的 #' \
    "127.0.0.1|9096|a' #b" "$(read_rest "$TMPDIR_TEST/i.yaml")"

cat > "$TMPDIR_TEST/k.yaml" <<'YAML'
restful-api:
  bind-addr: "127.0.0.1:9098"
  secret: |
    multi-line-secret
YAML
check_eq 'restful-api: 块标量 secret 判为不可解析' '' "$(read_rest "$TMPDIR_TEST/k.yaml")"

cat > "$TMPDIR_TEST/l.yaml" <<'YAML'
restful-api:
  bind-addr: "127.0.0.1:9099"
  secret: "a\u4e2d"
YAML
# YAML 会把 \u4e2d 解码成"中"，脚本不做这种解码，也不装作等价：整段判为不可解析。
check_eq 'restful-api: 不支持的转义判为不可解析' '' "$(read_rest "$TMPDIR_TEST/l.yaml")"

cat > "$TMPDIR_TEST/m.yaml" <<'YAML'
restful-api:
  bind-addr: "127.0.0.1:9100"
  secret: "|"
YAML
check_eq 'restful-api: 引号内的 | 是合法 secret' \
    '127.0.0.1|9100||' "$(read_rest "$TMPDIR_TEST/m.yaml")"

cat > "$TMPDIR_TEST/n.yaml" <<'YAML'
restful-api:
  bind-addr: "127.0.0.1:9101"
  secret: " abc "
YAML
# 解析层要保住首尾空格；下面的 read 环节也必须用 IFS= 才不会再剥一次。
check_eq 'restful-api: secret 首尾空白保留' \
    '127.0.0.1|9101| abc ' "$(read_rest "$TMPDIR_TEST/n.yaml")"

# 解析 → 三行读取 → 交给 rest_api 的这条链路（read 用默认 IFS 会吃掉空白）。
read_rest_fields "$(parse_restful_api "$TMPDIR_TEST/n.yaml")"
check_eq 'read_rest_fields: host' '127.0.0.1' "$REST_HOST"
check_eq 'read_rest_fields: port' '9101' "$REST_PORT"
check_eq 'read_rest_fields: secret 首尾空白不被 read 剥掉' ' abc ' "$REST_SECRET"


cat > "$TMPDIR_TEST/o.yaml" <<'YAML'
restful-api:
  bind-addr: "127.0.0.1:9102"
  secret: "a\nb"
YAML
# \n 会破坏三行传递格式、也会搅乱 Authorization 头，判为不可解析。
check_eq 'restful-api: secret 含控制字符判为不可解析' '' "$(read_rest "$TMPDIR_TEST/o.yaml")"

cat > "$TMPDIR_TEST/p.yaml" <<'YAML'
restful-api:
  bind-addr: "evil/host:9090"
YAML
check_eq 'restful-api: 主机含 URL 分隔符时整段作废' '' "$(read_rest "$TMPDIR_TEST/p.yaml")"

cat > "$TMPDIR_TEST/q.yaml" <<'YAML'
restful-api:
  bind-addr: "127.0.0.1:123456"
YAML
check_eq 'restful-api: 端口位数超限时整段作废' '' "$(read_rest "$TMPDIR_TEST/q.yaml")"

cat > "$TMPDIR_TEST/r.yaml" <<'YAML'
restful-api:
  bind-addr: "127.0.0.1:99999"
YAML
# 位数没超（5 位），但超出端口范围：当作配置错误立即退出，而不是每轮 curl 失败。
check_eq 'restful-api: 端口超出 65535 时整段作废' '' "$(read_rest "$TMPDIR_TEST/r.yaml")"

cat > "$TMPDIR_TEST/s.yaml" <<'YAML'
restful-api:
  bind-addr: "127.0.0.1:0"
YAML
check_eq 'restful-api: 端口 0 判为不可解析' '' "$(read_rest "$TMPDIR_TEST/s.yaml")"

cat > "$TMPDIR_TEST/t.yaml" <<'YAML'
restful-api:
  bind-addr: "127.0.0.1:65535"
YAML
check_eq 'restful-api: 上界端口 65535 可用' '127.0.0.1|65535|' \
    "$(read_rest "$TMPDIR_TEST/t.yaml")"

cat > "$TMPDIR_TEST/j.yaml" <<'EOF'
restful-api:
  bind-addr: "127.0.0.1 : 9097"
EOF
check_eq 'restful-api: 地址含空白时整段作废' '' "$(read_rest "$TMPDIR_TEST/j.yaml")"

# 返回值把"没有该段"和"有该段但解析不出来"分开：只走 RESTful API 的版本
# 两者都会致命退出，但 syslog 里要能看出是哪种情况。
parse_restful_api "$TMPDIR_TEST/a.yaml" >/dev/null
check_eq 'parse_restful_api: 正常配置 rc=0' '0' "$?"
parse_restful_api "$TMPDIR_TEST/b.yaml" >/dev/null
check_eq 'parse_restful_api: 无该段 rc=3' '3' "$?"
parse_restful_api "$TMPDIR_TEST/k.yaml" >/dev/null
check_eq 'parse_restful_api: 块标量 secret rc=2' '2' "$?"
parse_restful_api "$TMPDIR_TEST/q.yaml" >/dev/null
check_eq 'parse_restful_api: 端口位数超限 rc=2' '2' "$?"
parse_restful_api "$TMPDIR_TEST/r.yaml" >/dev/null
check_eq 'parse_restful_api: 端口超出范围 rc=2' '2' "$?"

# ---------- 进程识别与命令行解析 ----------
# 这里以前靠 ln -s 出一个名叫 shadowquic 的 sleep 当替身进程。那条路不可移植：
# uutils 的 coreutils 会校验 argv[0] 与二进制名是否一致（改名即拒跑），
# OpenWrt 的 busybox 也会把未知 applet 名当错误，于是用例在正常环境里假失败。
# 改成直接喂 cmdline 文本 —— 顺带能覆盖 `vim shadowquic.yaml` 这类真实误判。
printf 'shadowquic\n-c\n/etc/x.yaml\n' | cmdline_is_shadowquic
check_rc 'cmdline_is_shadowquic: 裸程序名' zero $?
printf '/usr/bin/shadowquic\nrun\n' | cmdline_is_shadowquic
check_rc 'cmdline_is_shadowquic: 绝对路径' zero $?
printf '/usr/lib/shadowquic-rs\nrun\n' | cmdline_is_shadowquic
check_rc 'cmdline_is_shadowquic: 带后缀的程序名' zero $?
printf 'vim\nshadowquic.yaml\n' | cmdline_is_shadowquic
check_rc 'cmdline_is_shadowquic: 不误判命令行含 shadowquic 的编辑器' nonzero $?
printf 'tail\n-f\n/tmp/shadowquic.log\n' | cmdline_is_shadowquic
check_rc 'cmdline_is_shadowquic: 不误判 tail 日志' nonzero $?
printf '' | cmdline_is_shadowquic
check_rc 'cmdline_is_shadowquic: 空 cmdline' nonzero $?

if is_shadowquic_pid $$; then
    ng 'is_shadowquic_pid: 不接受 argv[0] 为 sh 的进程'
else
    ok 'is_shadowquic_pid: 不接受 argv[0] 为 sh 的进程'
fi

if is_shadowquic_pid 99999999; then
    ng 'is_shadowquic_pid: 不存在的 pid'
else
    ok 'is_shadowquic_pid: 不存在的 pid'
fi

# 配置文件参数：支持 -c / -c= / --config / --config=，且 `--` 是选项结束符。
cfgarg() {
    printf '%s\n' "$@" | parse_config_arg
}

check_eq 'parse_config_arg: -c 分离形式' '/etc/x.yaml' \
    "$(cfgarg shadowquic -c /etc/x.yaml)"
check_eq 'parse_config_arg: -c= 形式' '/etc/x.yaml' \
    "$(cfgarg shadowquic -c=/etc/x.yaml)"
check_eq 'parse_config_arg: --config 分离形式' '/etc/x.yaml' \
    "$(cfgarg shadowquic run --config /etc/x.yaml)"
check_eq 'parse_config_arg: --config= 形式' '/etc/x.yaml' \
    "$(cfgarg shadowquic --config=/etc/x.yaml)"

# 回归点：`shadowquic -c a.yaml --` 是合法写法，`--` 之前的 -c 必须照常生效
# （旧实现把 `--` 当成"只看它后面"，于是把真正的 -c 跳过了）。
check_eq 'parse_config_arg: -- 之前的 -c 仍有效' '/etc/x.yaml' \
    "$(cfgarg shadowquic -c /etc/x.yaml --)"
check_eq 'parse_config_arg: -- 之后不再解析' '/etc/x.yaml' \
    "$(cfgarg shadowquic -c /etc/x.yaml -- -c /etc/y.yaml)"
check_eq 'parse_config_arg: 只有 -- 之后的 -c 时取不到' '' \
    "$(cfgarg shadowquic -- -c /etc/y.yaml)"

check_eq 'parse_config_arg: 没有配置参数' '' "$(cfgarg shadowquic run)"
check_eq 'parse_config_arg: -c 后面跟的是另一个选项时不算配置' '' \
    "$(cfgarg shadowquic -c --dump)"

# ---------- 数值校验 ----------
for v in 0 5 1452 12345; do
    if is_uint "$v"; then ok "is_uint 接受 $v"; else ng "is_uint 接受 $v"; fi
done
for v in '' 007 -1 1.5 1e5 ' 5' 5x; do
    if is_uint "$v"; then ng "is_uint 拒绝 [$v]"; else ok "is_uint 拒绝 [$v]"; fi
done

for v in 0 1.5 301.383866 1e-06 1E-7 2.5E+2 0.0 9.9e6; do
    if is_valid_rtt "$v"; then ok "is_valid_rtt 接受 $v"; else ng "is_valid_rtt 接受 $v"; fi
done
for v in '' . 1.2.3 1e 1e+ e5 0x10 '1 2' NaN 5x -0.5 1e400 2e7; do
    if is_valid_rtt "$v"; then ng "is_valid_rtt 拒绝 [$v]"; else ok "is_valid_rtt 拒绝 [$v]"; fi
done

# 位数超限的整数不能"因为 shell 溢出反而通过"范围检查
if is_uint_range 1452 65535; then ok 'is_uint_range 接受 1452'; else ng 'is_uint_range 接受 1452'; fi
if is_uint_range 99999 65535; then ng 'is_uint_range 拒绝 99999'; else ok 'is_uint_range 拒绝 99999'; fi
if is_uint_range 99999999999999999999999999999999 65535; then
    ng 'is_uint_range 拒绝超长数字'
else
    ok 'is_uint_range 拒绝超长数字'
fi

# 过期判定走 awk：超长年龄不能因为 shell 溢出而被判成"新鲜"
if is_age_stale 130000 120000; then ok 'is_age_stale 判定过期'; else ng 'is_age_stale 判定过期'; fi
if is_age_stale 60000 120000; then ng 'is_age_stale 判定新鲜'; else ok 'is_age_stale 判定新鲜'; fi
if is_age_stale 99999999999999999999999999999999 120000; then
    ok 'is_age_stale 超长年龄判为过期'
else
    ng 'is_age_stale 超长年龄判为过期'
fi

# 环境数值：前导零（`sleep 00` 就是零秒等待）、0、超长数字都必须回退到默认值，
# 否则 REFRESH_INTERVAL=00 会变成无间隔循环。
check_eq 'num_or: 正常值' '30' "$(num_or 30 30 86400)"
check_eq 'num_or: 上界本身可用' '86400' "$(num_or 86400 30 86400)"
check_eq 'num_or: 空值回退' '30' "$(num_or '' 30 86400)"
check_eq 'num_or: 0 回退' '30' "$(num_or 0 30 86400)"
check_eq 'num_or: 前导零回退' '30' "$(num_or 00 30 86400)"
check_eq 'num_or: 非数字回退' '30' "$(num_or 3x 30 86400)"
check_eq 'num_or: 超上限回退' '30' "$(num_or 99999 30 86400)"
check_eq 'num_or: 四十位数字回退' '30' \
    "$(num_or 9999999999999999999999999999999999999999 30 86400)"

# ---------- JSON 取数 ----------
detect_json_backend

if [ -z "$JSON_BACKEND" ]; then
    printf 'skip JSON 用例：本机既无 jq 也无 jsonfilter\n'
else
    printf 'json backend: %s\n' "$JSON_BACKEND"

    # 与 shadowquic /api/v1/outbounds 实测响应同构：
    # 第一个出站没有连接采样（direct），第二个有上下行采样。
    cat > "$TMPDIR_TEST/ok.json" <<'EOF'
{"outbounds":[
 {"tag":"direct","quality":{"probe":{"status":"ok"},"sq_conn_stats":null}},
 {"tag":"sq-out","quality":{"sq_conn_stats":{
   "sample_age_ms":6365,
   "uplink":{"current_mtu":1452,"lost_packets":208,"rtt":302.10632599999997,"sent_packets":12737},
   "downlink":{"current_mtu":1452,"lost_packets":2165,"rtt":301.383866,"sent_packets":14680}}}}]}
EOF

    json_has_outbounds "$TMPDIR_TEST/ok.json"
    check_rc 'json_has_outbounds: 正常响应' zero $?

    check_eq 'json_get: 数组下标取 tag' 'sq-out' \
        "$(json_get "$TMPDIR_TEST/ok.json" 'outbounds[1].tag')"
    check_eq 'json_get: 取浮点数' '302.10632599999997' \
        "$(json_get "$TMPDIR_TEST/ok.json" 'outbounds[1].quality.sq_conn_stats.uplink.rtt')"

    json_get "$TMPDIR_TEST/ok.json" 'outbounds[0].quality.sq_conn_stats' >/dev/null
    check_rc 'json_get: null 视为缺失' nonzero $?

    json_get "$TMPDIR_TEST/ok.json" 'outbounds[9].tag' >/dev/null
    check_rc 'json_get: 越界下标视为缺失' nonzero $?

    printf '{"outbounds":[{"tag":"x"' > "$TMPDIR_TEST/truncated.json"
    json_has_outbounds "$TMPDIR_TEST/truncated.json"
    check_rc 'json_has_outbounds: 截断的响应' nonzero $?

    printf '{"error":"boom"}' > "$TMPDIR_TEST/noarr.json"
    json_has_outbounds "$TMPDIR_TEST/noarr.json"
    check_rc 'json_has_outbounds: 结构不符的响应' nonzero $?

    printf '{"outbounds":{}}' > "$TMPDIR_TEST/objarr.json"
    json_has_outbounds "$TMPDIR_TEST/objarr.json"
    check_rc 'json_has_outbounds: outbounds 不是数组' nonzero $?

    # 取数：只有 sq-out 有采样，上下行各一条。
    samples=$(rest_collect_samples "$TMPDIR_TEST/ok.json")
    check_rc 'rest_collect_samples: 正常响应' zero $?
    check_eq 'rest_collect_samples: 上下行各一条' '2' \
        "$(printf '%s\n' "$samples" | wc -l | tr -d ' ')"
    check_eq 'rest_collect_samples: 每条 7 个字段' '0' \
        "$(printf '%s\n' "$samples" | awk -F '\t' 'NF != 7 { bad++ } END { print bad + 0 }')"
    check_eq 'rest_collect_samples: 首条内容' 'sq-out	uplink	302.10632599999997	208	12737	1452	6365' \
        "$(printf '%s\n' "$samples" | head -1)"

    # 采样年龄缺失 / 非法时整条出站跳过，绝不当成 0。
    printf '{"outbounds":[{"tag":"x","quality":{"sq_conn_stats":{"uplink":{"current_mtu":1452,"lost_packets":1,"rtt":1.5,"sent_packets":2}}}}]}' \
        > "$TMPDIR_TEST/noage.json"
    check_eq 'rest_collect_samples: 缺 sample_age_ms 时不产出' '' \
        "$(rest_collect_samples "$TMPDIR_TEST/noage.json")"

    printf '{"outbounds":[{"tag":"x","quality":{"sq_conn_stats":{"sample_age_ms":"oops","uplink":{"current_mtu":1452,"lost_packets":1,"rtt":1.5,"sent_packets":2}}}}]}' \
        > "$TMPDIR_TEST/badage.json"
    check_eq 'rest_collect_samples: 非数字 sample_age_ms 时不产出' '' \
        "$(rest_collect_samples "$TMPDIR_TEST/badage.json")"

    # 计数器缺失时跳过该方向，不拿 0 冒充。
    printf '{"outbounds":[{"tag":"x","quality":{"sq_conn_stats":{"sample_age_ms":10,"uplink":{"current_mtu":1452,"rtt":1.5,"sent_packets":2}}}}]}' \
        > "$TMPDIR_TEST/nolost.json"
    check_eq 'rest_collect_samples: 缺计数器时不产出该方向' '' \
        "$(rest_collect_samples "$TMPDIR_TEST/nolost.json")"

    # 出站取不出 tag 时返回非零，调用方据此放弃本轮上报。
    printf '{"outbounds":[{"tag":null},{"tag":"y","quality":{"sq_conn_stats":null}}]}' \
        > "$TMPDIR_TEST/notag.json"
    rest_collect_samples "$TMPDIR_TEST/notag.json" >/dev/null
    check_rc 'rest_collect_samples: 出站缺 tag 时报结构异常' nonzero $?

    # tag 缺在末尾时同样要报异常：只按 tag 行数推导长度的话这里会被放过，
    # 出站被静默忽略。
    printf '{"outbounds":[{"tag":"a","quality":{"sq_conn_stats":null}},{"tag":null}]}' \
        > "$TMPDIR_TEST/tailnotag.json"
    rest_collect_samples "$TMPDIR_TEST/tailnotag.json" >/dev/null
    check_rc 'rest_collect_samples: 末尾缺 tag 时报结构异常' nonzero $?

    # 全部缺 tag：不能当成"成功但没有采样"，否则这一轮会被误判成正常。
    printf '{"outbounds":[{"quality":{}},{"quality":{}}]}' > "$TMPDIR_TEST/allnotag.json"
    rest_collect_samples "$TMPDIR_TEST/allnotag.json" >/dev/null
    check_rc 'rest_collect_samples: 全部缺 tag 时报结构异常' nonzero $?

    printf '{"outbounds":[]}' > "$TMPDIR_TEST/emptyarr.json"
    rest_collect_samples "$TMPDIR_TEST/emptyarr.json" >/dev/null
    check_rc 'rest_collect_samples: 空 outbounds 视为不可用' nonzero $?

    # 科学计数法的 rtt 是合法 JSON 数字，jq/jsonfilter 会原样输出（1E-7 这种
    # 大写形式也会出现），不能当成非法值丢掉。
    printf '{"outbounds":[{"tag":"x","quality":{"sq_conn_stats":{"sample_age_ms":10,"uplink":{"current_mtu":1452,"lost_packets":1,"rtt":1E-7,"sent_packets":2}}}}]}' \
        > "$TMPDIR_TEST/scinot.json"
    check_eq 'rest_collect_samples: 科学计数法 rtt 可用' 'uplink	1E-7' \
        "$(rest_collect_samples "$TMPDIR_TEST/scinot.json" | awk -F '\t' 'NF { print $2 "\t" $3 }')"

    # 半成品数字要丢掉。
    printf '{"outbounds":[{"tag":"x","quality":{"sq_conn_stats":{"sample_age_ms":10,"uplink":{"current_mtu":1452,"lost_packets":1,"rtt":"1.2.3","sent_packets":2}}}}]}' \
        > "$TMPDIR_TEST/badrtt.json"
    check_eq 'rest_collect_samples: 非法 rtt 不产出' '' \
        "$(rest_collect_samples "$TMPDIR_TEST/badrtt.json")"

    # 字段是空串时不能靠"拼接后全是数字"蒙过校验。
    printf '{"outbounds":[{"tag":"x","quality":{"sq_conn_stats":{"sample_age_ms":10,"uplink":{"current_mtu":1452,"lost_packets":"","rtt":1.5,"sent_packets":2}}}}]}' \
        > "$TMPDIR_TEST/emptyfield.json"
    check_eq 'rest_collect_samples: 空串计数器不产出' '' \
        "$(rest_collect_samples "$TMPDIR_TEST/emptyfield.json")"

    # 尾部 null 元素：两个后端都当作"元素不存在"，不报结构异常。这是有意
    # 接受的取舍（jsonfilter 无法区分 null 元素与越界），这里锁死行为。
    printf '{"outbounds":[{"tag":"a","quality":{}},null]}' > "$TMPDIR_TEST/tailnull.json"
    tailnull_out=$(rest_collect_samples "$TMPDIR_TEST/tailnull.json")
    tailnull_rc=$?
    check_rc 'rest_collect_samples: 尾部 null 不算结构异常' zero "$tailnull_rc"
    check_eq 'rest_collect_samples: 尾部 null 不产出采样' '' "$tailnull_out"

    # 超长计数器会让 loss_rate 算出 inf/nan，必须在取数阶段就挡掉。
    printf '{"outbounds":[{"tag":"x","quality":{"sq_conn_stats":{"sample_age_ms":10,"uplink":{"current_mtu":1452,"lost_packets":%s,"rtt":1.5,"sent_packets":2}}}}]}' \
        "$(printf '9%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40)" \
        > "$TMPDIR_TEST/hugelost.json"
    check_eq 'rest_collect_samples: 超长计数器不产出' '' \
        "$(rest_collect_samples "$TMPDIR_TEST/hugelost.json")"

    # 数字字符串形式：后端不会把它重新格式化，能直接验证位数限制本身。
    printf '{"outbounds":[{"tag":"x","quality":{"sq_conn_stats":{"sample_age_ms":10,"uplink":{"current_mtu":1452,"lost_packets":"%s","rtt":1.5,"sent_packets":2}}}}]}' \
        "$(printf '9%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20)" \
        > "$TMPDIR_TEST/hugeloststr.json"
    check_eq 'rest_collect_samples: 20 位计数器字符串不产出' '' \
        "$(rest_collect_samples "$TMPDIR_TEST/hugeloststr.json")"

    # 边界：18 位（上限）仍然可用，说明限制没有过紧。
    printf '{"outbounds":[{"tag":"x","quality":{"sq_conn_stats":{"sample_age_ms":10,"uplink":{"current_mtu":1452,"lost_packets":999999999999999999,"rtt":1.5,"sent_packets":999999999999999999}}}}]}' \
        > "$TMPDIR_TEST/maxcounter.json"
    check_eq 'rest_collect_samples: 18 位计数器仍可用' '1' \
        "$(rest_collect_samples "$TMPDIR_TEST/maxcounter.json" | wc -l | tr -d ' ')"

    # 超长 sample_age_ms 同理：先按位数挡掉，不进过期比较。
    printf '{"outbounds":[{"tag":"x","quality":{"sq_conn_stats":{"sample_age_ms":%s,"uplink":{"current_mtu":1452,"lost_packets":1,"rtt":1.5,"sent_packets":2}}}}]}' \
        "$(printf '9%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40)" \
        > "$TMPDIR_TEST/hugeage.json"
    check_eq 'rest_collect_samples: 超长 sample_age_ms 不产出' '' \
        "$(rest_collect_samples "$TMPDIR_TEST/hugeage.json")"

    # 长度推导本身（jq：整个数组里非 null 元素的个数；jsonfilter 的算法不同，
    # 见下面的独立段落）。
    check_eq 'json_array_len: 混合数组' '2' \
        "$(json_array_len "$TMPDIR_TEST/notag.json" outbounds)"
    check_eq 'json_array_len: 空数组' '0' \
        "$(json_array_len "$TMPDIR_TEST/emptyarr.json" outbounds)"

    # 只有采样、没有标签的出站在正常响应里不算异常。
    printf '{"outbounds":[{"tag":"a","quality":{}}]}' > "$TMPDIR_TEST/nostats.json"
    check_eq 'rest_collect_samples: 无采样的出站正常跳过' '0' \
        "$(rest_collect_samples "$TMPDIR_TEST/nostats.json" | wc -l | tr -d ' ')"
fi

# ---------- 真 jsonfilter 后端 ----------
# 上面那组跑的是本机选中的后端（装了 jq 就是 jq）。target 上跑的是 jsonfilter，
# 而它的 -t 类型输出、null 元素的停止点、数组下标语义都还没在本机验证过 ——
# 没装就明确 SKIP，绝不拿 jq 跑过的结果充当 jsonfilter 通过。
if ! command -v jsonfilter >/dev/null 2>&1; then
    printf 'SKIP jsonfilter 后端用例：本机没有 jsonfilter（jq 的结果不能替代）\n'
else
    saved_backend="$JSON_BACKEND"
    JSON_BACKEND=jsonfilter

    cat > "$TMPDIR_TEST/jf-ok.json" <<'EOF'
{"outbounds":[
 {"tag":"direct","quality":{"probe":{"status":"ok"},"sq_conn_stats":null}},
 {"tag":"sq-out","quality":{"sq_conn_stats":{
   "sample_age_ms":6365,
   "uplink":{"current_mtu":1452,"lost_packets":208,"rtt":302.10632599999997,"sent_packets":12737},
   "downlink":{"current_mtu":1452,"lost_packets":2165,"rtt":301.383866,"sent_packets":14680}}}}]}
EOF
    printf '{"outbounds":[]}' > "$TMPDIR_TEST/jf-empty.json"
    printf '{"outbounds":{}}' > "$TMPDIR_TEST/jf-objarr.json"
    printf '{"outbounds":[{"tag":"x"' > "$TMPDIR_TEST/jf-truncated.json"
    printf '{"outbounds":[null,{"tag":"a","quality":{"sq_conn_stats":null}}]}' \
        > "$TMPDIR_TEST/jf-headnull.json"
    printf '{"outbounds":[{"tag":"a","quality":{"sq_conn_stats":null}},null,{"tag":"b","quality":{"sq_conn_stats":null}}]}' \
        > "$TMPDIR_TEST/jf-midnull.json"
    printf '{"outbounds":[{"tag":"a","quality":{"sq_conn_stats":null}},null]}' \
        > "$TMPDIR_TEST/jf-tailnull.json"
    printf '{"outbounds":[{"tag":null},{"tag":"y","quality":{"sq_conn_stats":null}}]}' \
        > "$TMPDIR_TEST/jf-notag.json"

    json_has_outbounds "$TMPDIR_TEST/jf-ok.json"
    check_rc 'jsonfilter: 正常响应的 outbounds 是数组' zero $?
    json_has_outbounds "$TMPDIR_TEST/jf-objarr.json"
    check_rc 'jsonfilter: outbounds 为对象时判为不可用' nonzero $?
    json_has_outbounds "$TMPDIR_TEST/jf-truncated.json"
    check_rc 'jsonfilter: 截断的响应判为不可用' nonzero $?

    check_eq 'jsonfilter: 按下标取 tag' 'sq-out' \
        "$(json_get "$TMPDIR_TEST/jf-ok.json" 'outbounds[1].tag')"
    json_get "$TMPDIR_TEST/jf-ok.json" 'outbounds[9].tag' >/dev/null
    check_rc 'jsonfilter: 越界下标视为缺失' nonzero $?

    check_eq 'jsonfilter: 正常响应上下行各一条' '2' \
        "$(rest_collect_samples "$TMPDIR_TEST/jf-ok.json" | wc -l | tr -d ' ')"
    rest_collect_samples "$TMPDIR_TEST/jf-empty.json" >/dev/null
    check_rc 'jsonfilter: 空数组视为不可用' nonzero $?

    # null / 缺 tag 的四种形态：只断言安全不变式（绝不把 null 当出站、绝不产出
    # 采样），不断言 rc —— jsonfilter 停在哪一步还没在真机验证，把观测值打出来
    # 留痕，真机跑一次就能看清。
    for f in headnull midnull tailnull notag; do
        out=$(rest_collect_samples "$TMPDIR_TEST/jf-$f.json" 2>/dev/null)
        rc=$?
        n=$(json_array_len "$TMPDIR_TEST/jf-$f.json" outbounds)
        ntags=$(json_outbound_tags "$TMPDIR_TEST/jf-$f.json" | wc -l | tr -d ' ')
        check_eq "jsonfilter: $f 不产出采样" '' "$out"
        printf '     留痕 %-8s n=%s tags=%s rc=%s\n' "$f" "${n:-?}" "$ntags" "$rc"
    done

    JSON_BACKEND="$saved_backend"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
