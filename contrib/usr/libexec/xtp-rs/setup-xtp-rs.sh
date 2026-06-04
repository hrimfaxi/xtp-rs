#!/bin/sh
# vim: set sw=2 ts=2 et:

set -eu

# 加载同目录下的公共库
. "$(dirname "$0")/common.sh"

# -------------------------------------------------------------------------
# 0. 获取路由器本机 IPv4 地址
# -------------------------------------------------------------------------
# 自动收集当前系统上所有非回环、非链路本地的 IPv4 地址，并将其加入
# local_ip，避免发往路由器本机服务的流量再次进入透明代理路径。
# -------------------------------------------------------------------------
LOCAL_IPV4_ENTRIES="$(
  ip_cmd -4 -o addr show 2>/dev/null \
    | awk '
        {
          split($4, a, "/");
          ip = a[1];
          if (ip !~ /^127\./ && ip !~ /^169\.254\./) {
            print "      " ip ","
          }
        }
      ' \
    | sort -u
)"

# -------------------------------------------------------------------------
# 1. 路由表（必须先于 rule 添加）
# -------------------------------------------------------------------------
# TPROXY 要求内核认为目标地址是"本机"，因此需要在独立路由表中声明
# local default dev lo。若先加 rule 再加 route，中间状态会导致 fwmark=1
# 的包因查无路由而被丢弃。
# -------------------------------------------------------------------------
add_ip_route "$XTP_TABLE_ID"
add_ip6_route "$XTP_TABLE_ID"

# -------------------------------------------------------------------------
# 2. 策略路由规则（fwmark → 路由表）
# -------------------------------------------------------------------------
add_ip_rule "$XTP_FWMARK" "$XTP_TABLE_ID"
add_ip6_rule "$XTP_FWMARK" "$XTP_TABLE_ID"

# -------------------------------------------------------------------------
# 3. nftables 透明代理规则
# -------------------------------------------------------------------------
load_nft_table "$XTP_TABLE_NAME" <<NFTABLES
#
# XTP-RS 透明代理 (TPROXY) 核心原理
# ==================================
#
# 本 nftables 表配合 Linux TPROXY 内核机制，实现无需修改客户端的透明
# 流量劫持：将发往公网 TCP 80/443 的数据包重定向到本地 xtp-rs
# 监听端口（默认 10810），由 xtp-rs 代为建立真实连接。
#
# -------------------------------------------------------------------------
# 【为什么必须配置 ip rule + ip route local】
# -------------------------------------------------------------------------
# TPROXY 与 REDIRECT/NAT 不同：它不修改数据包的目的地址（DNAT），而是
# 在"路由决策后、本地交付前"将包截获给本地进程。这要求内核必须认为该
# 数据包是"发往本机"的，否则不会进入本地输入路径。
#
# 因此需要策略路由配合：
#   1. output / prerouting 链将待代理包标记 fwmark=1；
#   2. ip rule add fwmark 1 table 100 将所有 fwmark=1 的包导入路由表 100；
#   3. ip route add local default dev lo table 100 在表 100 中声明：
#      "无论目的 IP 是什么，都是本地地址"，于是内核将包交给 lo 接口；
#   4. 监听在 [::1]:10810 的 xtp-rs 通过 TPROXY 套接字接收原始包，
#      并可通过 getsockopt 获取原始目的地址，从而透明代理。
#
# 注意：必须先添加 route 再添加 rule。若 rule 存在而 route 不存在，
# 被标记的包会因查不到路由而被丢弃，可能导致系统网络异常。
#
# -------------------------------------------------------------------------
# 【fwmark 1 —— 待代理流量】
# -------------------------------------------------------------------------
# output 链（route hook）：
#   拦截本机进程发出的 tcp dport {80,443}，设置 fwmark=1。
#   随后该包命中 ip rule → 表 100 → local route → 被 TPROXY 截获到
#   127.0.0.1:10810 或 [::1]:10810。
#
# prerouting 链（filter hook）：
#   对于作为网关时转发的流量（或外部进入本机的流量），同样将 TCP
#   80/443 标记 fwmark=1 并 TPROXY 到本地端口。
#
# -------------------------------------------------------------------------
# 【fwmark 2 —— 已代理/绕过流量（防环路）】
# -------------------------------------------------------------------------
# xtp-rs 向外发起真实连接时，应在其出站 socket 上设置 SO_MARK=2
#（或通过 iptables/nftables 为 xtp-rs 进程出站流量统一标记）。
# output / prerouting 链中遇到 fwmark=2 直接 return，避免代理程序
# 发出的请求再次被自身拦截，形成无限代理环路。
#
# -------------------------------------------------------------------------
# 【divert 链 —— 短路径优化（可选）】
# -------------------------------------------------------------------------
# 已被 TPROXY 接管的连接，内核会为其关联一个 "transparent" 状态的
# socket。divert 链在 mangle 优先级提前检查：
#   socket transparent 1 meta mark set 1 accept
# 若匹配，说明该连接已在代理中，直接标记并放行，跳过后面复杂的规则
# 匹配，降低 CPU 开销。OpenWrt 需安装 kmod-nf-socket / kmod-nft-socket。
#
# -------------------------------------------------------------------------
# 【保留地址（reserved_ip / reserved_ip6）】
# -------------------------------------------------------------------------
# RFC1918 私有网段、链路本地地址、环回地址，以及用户指定的直连服务器
# IP，均不应进入代理，否则会导致内网服务不可达或流量绕远。
#
# 【192.168.0.0/16 与 fd00::/8 特殊处理】
# -------------------------------------------------------------------------
# 内网 TCP 全部直连（return）；内网 UDP 仅放行非 53 端口。
# 这样 UDP/53（DNS）仍可被代理/劫持，其余内网 UDP 直连。
#

table inet xtp-rs {
  set local_ip {
    type ipv4_addr;
    elements = {
${LOCAL_IPV4_ENTRIES}
    }
  }

  set reserved_ip {
    type ipv4_addr;
    flags interval;
    elements = {
      # ==============================================================
      # 1. 私有地址、保留地址、以及需要直连（不经过代理）的特定服务器 IP
      # ==============================================================
      10.0.0.0/8,
      100.64.0.0/10,
      127.0.0.0/8,
      169.254.0.0/16,
      172.16.0.0/12,
      192.0.0.0/24,
      224.0.0.0/4,
      240.0.0.0/4,
      # ==============================================================
      # 2. 路由器本机 LAN IP：避免发往本机服务的流量被透明代理再次截获，
      # 导致 xtp-rs 直连重发后形成环路或请求悬空。
      # 如路由器 LAN IP 不是 192.168.15.1，请按实际地址修改。
      # ==============================================================
      192.168.15.1/32,
      # ==============================================================
      # 3. 用户自定义：添加需要强制直连的外部服务器 IP 或 CIDR
      #    例如：你的上游 SOCKS5 服务器、内网网关、特定 API 服务器等。
      #    这些 IP 不会走 TPROXY 代理，也无需为它们设置 fwmark=2 绕过。
      #    注意：一行一个，末尾加逗号。
      #
      # 示例：
      # ==============================================================
      # 203.0.113.10/32,
      # 198.51.100.0/24,
    }
  }

  set reserved_ip6 {
    type ipv6_addr;
    flags interval;
    elements = {
      ::1/128,                 # Loopback
      fe80::/10,               # Link-Local
      fc00::/7,                # Unique Local Unicast (ULA)
    }
  }

  chain prerouting {
    type filter hook prerouting priority filter; policy accept;
    # 可选：根据源 IP 跳过代理（如内网管理段）
    # ip saddr 10.2.1.0/24 return
    ip daddr @local_ip return
    ip daddr @reserved_ip return
    meta l4proto tcp ip daddr 192.168.0.0/16 return
    ip daddr 192.168.0.0/16 udp dport != 53 return
    ip6 daddr @reserved_ip6 return
    meta l4proto tcp ip6 daddr fd00::/8 return
    ip6 daddr fd00::/8 udp dport != 53 return
    meta mark 2 return
    meta l4proto { tcp, } th dport { 80, 443, } meta mark set 1 tproxy ip to 127.0.0.1:10810 accept
    meta l4proto { tcp, } th dport { 80, 443, } meta mark set 1 tproxy ip6 to [::1]:10810 accept
    meta l4proto { udp, } th dport { 53, 443, } meta mark set 1 tproxy ip to 127.0.0.1:10810 accept
    meta l4proto { udp, } th dport { 53, 443, } meta mark set 1 tproxy ip6 to [::1]:10810 accept
  }

  chain output {
    type route hook output priority filter; policy accept;
    # 如需要使用uid xtp-rs来标记进程的包，解除以下注释
    # meta skuid xtp-rs counter return
    ip daddr @local_ip return
    ip daddr @reserved_ip return
    meta l4proto tcp ip daddr 192.168.0.0/16 return
    ip daddr 192.168.0.0/16 udp dport != 53 return
    ip6 daddr @reserved_ip6 return
    meta l4proto tcp ip6 daddr fd00::/8 return
    ip6 daddr fd00::/8 udp dport != 53 return
    meta mark 2 counter return
    meta l4proto { tcp, } th dport { 80, 443, } meta mark set 1 accept
    meta l4proto { udp, } th dport { 53, 443, } meta mark set 1 accept
  }

  # divert表用于避免已有连接的包二次通过TPROXY，理论上有一定的性能提升
  # openwrt: 需要kmod-nf-socket和kmod-nft-socket包支持
  chain divert {
    type filter hook prerouting priority mangle; policy accept;
    meta l4proto tcp socket transparent 1 meta mark set 1 accept
  }
}
NFTABLES
