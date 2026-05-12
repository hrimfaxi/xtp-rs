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
