#!/bin/sh
# vim: set sw=2 ts=2 et:

set -eu

# 加载同目录下的公共库
. "$(dirname "$0")/common.sh"

# -------------------------------------------------------------------------
# 卸载顺序与安装相反：先删 rule，再删 route，避免中间状态丢包
# -------------------------------------------------------------------------

# 1. 删除策略路由规则
del_ip_rule "$XTP_FWMARK" "$XTP_TABLE_ID"
del_ip6_rule "$XTP_FWMARK" "$XTP_TABLE_ID"

# 2. 删除路由表
del_ip_route "$XTP_TABLE_ID"
del_ip6_route "$XTP_TABLE_ID"

# 3. 删除 nftables 表
del_nft_table "$XTP_TABLE_NAME"
