#!/bin/sh
# vim: set sw=2 ts=2 et:

# XTP-RS 透明代理 —— 公共函数库
# 用法: . "$(dirname "$0")/common.sh"

# -------------------------------------------------------------------------
# 规避 alias 污染
# -------------------------------------------------------------------------
# OpenWrt 等系统常在 /etc/profile 中定义 alias ip='ip -c'。
# 当脚本被 source 执行时，alias 会污染当前 shell，导致 ip 输出带 ANSI
# 颜色码，进而使 grep 匹配失败。command 为 POSIX 内置命令，可绕过 alias
# 与函数，直接调用原始命令。
# -------------------------------------------------------------------------
ip_cmd()  { command ip "$@"; }
nft_cmd() { command nft "$@"; }

# 常量（如需调整透明代理参数，在此统一修改）
XTP_TABLE_ID=100
XTP_FWMARK=1
XTP_BYPASS_MARK=2
XTP_TABLE_NAME="xtp-rs"
XTP_TPROXY_PORT=10810

# -------------------------------------------------------------------------
# 配置值解析与校验辅助（setup 等脚本生成 nft 规则时复用）
# -------------------------------------------------------------------------

# 校验 IPv4 地址或 CIDR 网段：点分十进制 4 组八位组 + 可选 /0-32 前缀。
# 拒绝非法字符、越界值与前导零，杜绝任意内容注入 nft 规则。
# 仅应在已 set -f 的上下文中调用（见 normalize_ip_cidr_list）。
is_valid_ipv4_cidr() {
  _in="$1"
  # 字符白名单：仅数字、点、斜杠合法（空白、字母、符号一律拒绝）
  case "$_in" in
    *[!0-9./]*|'') return 1 ;;
  esac
  _addr="${_in%%/*}"
  _tail="${_in#*/}"
  # 不含 '/' 时 ${_in#*/} 原样返回（_tail == _in），视为无前缀；
  # 含多个 '/' 时 _tail 中仍有 '/'，非法
  case "$_tail" in
    */*) return 1 ;;
  esac
  [ -n "$_addr" ] || return 1
  # 恰好 3 个点：分词会吞掉连续/首尾点产生的空字段（如 1.2.3.4. /
  # .1.2.3.4 / 1..2.3.4 恰好也能分出 4 个合法数字），须先卡死点数
  [ "$(printf '%s' "$_addr" | tr -cd '.' | wc -c)" -eq 3 ] || return 1
  # 地址部分：恰好 4 个 0-255 的八位组，无前导零（"0" 合法，"01" 非法）
  _octets="$(printf '%s\n' "$_addr" | tr '.' ' ')"
  _n=0
  for _o in $_octets; do
    case "$_o" in
      *[!0-9]*|'') return 1 ;;
      [0-9]|[1-9][0-9]|[1-9][0-9][0-9]) ;;
      *) return 1 ;;
    esac
    [ "$_o" -le 255 ] || return 1
    _n=$((_n + 1))
  done
  [ "$_n" -eq 4 ] || return 1
  # 前缀部分（可选）：0-32
  if [ "$_tail" != "$_in" ]; then
    case "$_tail" in
      [0-9]|[12][0-9]|3[0-2]) ;;
      *) return 1 ;;
    esac
  fi
  return 0
}

# 归一化 IPv4 地址 / CIDR 列表：非法项告警并丢弃，去重后以空格分隔输出
normalize_ip_cidr_list() (
  # 在子 shell 中禁用 glob 并固定 IFS：防止用户输入的 '*' 等通配符在
  # for 展开时被替换成当前目录的文件名，且不污染调用方的 set -f / IFS 状态。
  set -f
  IFS=' '
  _raw="$1"
  [ -n "$_raw" ] || return 0
  # 空白、制表符、换行统一为空格；逗号、分号也是合法分隔符
  _raw="$(printf '%s\n' "$_raw" | tr ',;\t\r\n' '     ')"
  _out=""
  for _e in $_raw; do
    if ! is_valid_ipv4_cidr "$_e"; then
      echo "xtp-rs: warning: invalid IPv4 address/CIDR ignored: '$_e'" >&2
      continue
    fi
    # 去重（以冒号分隔暂存），保持首次出现的顺序
    case ":$_out:" in
      *":$_e:"*) continue ;;
    esac
    _out="$_out:$_e"
  done
  printf '%s\n' "${_out#:}" | tr ':' ' '
)

# 生成 nft set 元素串："      <item>," 每行一项（6 空格缩进）。
# 入参须为 normalize_* 归一化后的空格分隔列表。
set_elements_nft() {
  for _p in $1; do
    printf '      %s,\n' "$_p"
  done
}

# 生成源 IP 直连规则："    ip saddr <cidr> return" 每条一行（4 空格缩进）。
# 入参须为 normalize_ip_cidr_list 归一化后的空格分隔列表。
saddr_bypass_rules_nft() {
  for _s in $1; do
    printf '    ip saddr %s return\n' "$_s"
  done
}

# 归一化端口列表：非法/越界项告警并丢弃，去重后以空格分隔输出；
# 入参为空时使用默认列表 $_default。注意：入参非空但全部非法时返回
# 空串，须由调用方回退默认值（setup-xtp-rs.sh 已处理），本函数不单独
# 保证输出非空。
normalize_port_list() (
  # 在子 shell 中禁用 glob 并固定 IFS：防止用户输入的 '*' 等通配符被
  # 展开成当前目录的文件名（如 CWD 恰有名为 443 的文件时会被误当端口），
  # 且不污染调用方的 set -f / IFS 状态。
  set -f
  IFS=' '
  _raw="$1"
  _default="$2"
  [ -n "$_raw" ] || _raw="$_default"
  # 空白、制表符、换行统一为空格；逗号、分号也是合法分隔符
  _raw="$(printf '%s\n' "$_raw" | tr ',;\t\r\n' '     ')"
  _out=""
  for _p in $_raw; do
    case "$_p" in
      *[!0-9]*|'')
        echo "xtp-rs: warning: invalid port ignored: '$_p'" >&2
        continue
        ;;
    esac
    if [ "$_p" -lt 1 ] || [ "$_p" -gt 65535 ]; then
      echo "xtp-rs: warning: port out of range (1-65535) ignored: $_p" >&2
      continue
    fi
    # 去重（以冒号分隔暂存），保持首次出现的顺序
    case ":$_out:" in
      *":$_p:"*) continue ;;
    esac
    _out="$_out:$_p"
  done
  printf '%s\n' "${_out#:}" | tr ':' ' '
)

# -------------------------------------------------------------------------
# 存在性检查（用于幂等添加/删除）
# -------------------------------------------------------------------------

# $1: fwmark  $2: table id
has_ip_rule() {
  ip_cmd rule show 2>/dev/null | command grep -q "fwmark.*lookup ${2}"
}

has_ip6_rule() {
  ip_cmd -6 rule show 2>/dev/null | command grep -q "fwmark.*lookup ${2}"
}

# $1: table id
has_ip_route() {
  ip_cmd route show table "$1" 2>/dev/null | command grep -q "local default dev lo"
}

has_ip6_route() {
  ip_cmd -6 route show table "$1" 2>/dev/null | command grep -q "local default dev lo"
}

# $1: table name
has_nft_table() {
  nft_cmd list table inet "$1" >/dev/null 2>&1
}

# -------------------------------------------------------------------------
# 幂等操作封装
# -------------------------------------------------------------------------

add_ip_rule() {
  if ! has_ip_rule "$1" "$2"; then
    ip_cmd rule add fwmark "$1" table "$2"
  fi
}

del_ip_rule() {
  if has_ip_rule "$1" "$2"; then
    ip_cmd rule del fwmark "$1" table "$2"
  fi
}

add_ip_route() {
  if ! has_ip_route "$1"; then
    ip_cmd route add local default dev lo table "$1"
  fi
}

del_ip_route() {
  if has_ip_route "$1"; then
    ip_cmd route del local default dev lo table "$1"
  fi
}

add_ip6_rule() {
  if ! has_ip6_rule "$1" "$2"; then
    ip_cmd -6 rule add fwmark "$1" table "$2"
  fi
}

del_ip6_rule() {
  if has_ip6_rule "$1" "$2"; then
    ip_cmd -6 rule del fwmark "$1" table "$2"
  fi
}

add_ip6_route() {
  if ! has_ip6_route "$1"; then
    ip_cmd -6 route add local default dev lo table "$1"
  fi
}

del_ip6_route() {
  if has_ip6_route "$1"; then
    ip_cmd -6 route del local default dev lo table "$1"
  fi
}

# 加载 nft 规则（先删旧表，再从 stdin 读取新规则）
# 用法: load_nft_table "$XTP_TABLE_NAME" <<'EOF' ... EOF
load_nft_table() {
  local name="$1"
  if has_nft_table "$name"; then
    nft_cmd delete table inet "$name" 2>/dev/null || true
  fi
  nft_cmd -f -
}

del_nft_table() {
  if has_nft_table "$1"; then
    nft_cmd delete table inet "$1"
  fi
}
