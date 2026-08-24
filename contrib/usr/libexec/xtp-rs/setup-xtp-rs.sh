#!/bin/sh
# vim: set sw=2 ts=2 et:

set -eu

# 加载同目录下的公共库
. "$(dirname "$0")/common.sh"

# -------------------------------------------------------------------------
# 0. 获取代理入口接口名和本机 IPv4 地址
# -------------------------------------------------------------------------
# TPROXY 仅应在指定入口接口上拦截流量，避免非预期接口（如 WAN、VPN、
# Docker bridge）的流量被误截获。可通过环境变量 XTP_PROXY_INGRESS_IFACES
# 指定多个接口（空格分隔），未设置时自动从 uci 获取 network.lan.device，
# 最终 fallback 到自动检测第一个物理网络接口。
# -------------------------------------------------------------------------
XTP_PROXY_INGRESS_IFACES="${XTP_PROXY_INGRESS_IFACES:-}"
if [ -z "$XTP_PROXY_INGRESS_IFACES" ] && command -v uci >/dev/null 2>&1; then
  XTP_PROXY_INGRESS_IFACES="$(uci -q get network.lan.device || true)"
fi
# 自动检测：排除回环、VPN、Docker、虚拟网桥等非物理接口
if [ -z "$XTP_PROXY_INGRESS_IFACES" ]; then
  XTP_PROXY_INGRESS_IFACES="$(
    ip_cmd -o link show up 2>/dev/null \
      | awk '{print $2}' | sed 's/://' \
      | grep -vE '^(lo|docker|virbr|br-|veth|tun|tap|wg|tailscale)' \
      | head -1
  )"
fi
: "${XTP_PROXY_INGRESS_IFACES:=br-lan}"

# 关闭 glob 展开，防止变量中的通配符被误展开为文件名
set -f

# 校验接口名称合法性，生成 nft 集合格式："br-lan", "br-guest"
XTP_PROXY_INGRESS_IFACES_NFT=""
for _iface in $XTP_PROXY_INGRESS_IFACES; do
  case "$_iface" in
    *[![:alnum:]_.:-]*|'')
      echo "xtp-rs: invalid ingress interface name: $_iface" >&2
      exit 1
      ;;
  esac
  # 接口可能尚未创建（VPN、动态 bridge 等），仅警告不阻断
  if ! ip_cmd link show dev "$_iface" >/dev/null 2>&1; then
    echo "xtp-rs: warning: ingress interface not present yet: $_iface" >&2
  fi
  if [ -n "$XTP_PROXY_INGRESS_IFACES_NFT" ]; then
    XTP_PROXY_INGRESS_IFACES_NFT="${XTP_PROXY_INGRESS_IFACES_NFT}, "
  fi
  XTP_PROXY_INGRESS_IFACES_NFT="${XTP_PROXY_INGRESS_IFACES_NFT}\"${_iface}\""
done

set +f

# 自动收集当前系统上所有非回环、非链路本地的 IPv4 地址，并将其加入
# local_ip，避免发往路由器本机服务的流量再次进入透明代理路径。
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

# 定义外部文件路径
EXT_RESERVED_IP_FILE="${EXT_RESERVED_IP_FILE:-$(dirname "$0")/ext_reserved_ip}"

# 构建 reserved_ip 元素列表（静态 + 动态）
# ==============================================================
# 私有地址、保留地址、以及需要直连（不经过代理）的特定服务器 IP
# ==============================================================
RESERVED_IP_ELEMENTS="      10.0.0.0/8,
      100.64.0.0/10,
      127.0.0.0/8,
      169.254.0.0/16,
      172.16.0.0/12,
      192.0.0.0/24,
      224.0.0.0/4,
      240.0.0.0/4,"

if [ -f "$EXT_RESERVED_IP_FILE" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    # 去除首尾空白
    line="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    # 跳过空行和注释行
    case "$line" in
      ''|'#'*) continue ;;
    esac
    # 若行末没有逗号则添加
    [ "${line%,}" = "$line" ] && line="$line,"
    # 追加到列表，保持缩进（6个空格）
    RESERVED_IP_ELEMENTS="$RESERVED_IP_ELEMENTS
      $line"
  done < "$EXT_RESERVED_IP_FILE"
fi

# ----- 关键：移除所有完全空的行，确保 nftables 集合元素列表不含空行 -----
RESERVED_IP_ELEMENTS="$(echo "$RESERVED_IP_ELEMENTS" | grep -v '^[[:space:]]*$')"

# -------------------------------------------------------------------------
# 可选：中国大陆 IPv4 目的地址直连（不经过 TPROXY）
# -------------------------------------------------------------------------
# 开启 XTP_BYPASS_CHNROUTE=1 后，目的地址命中 china_ips 集合的流量在
# prerouting / output 中提前 return，保持正常转发路径：
#   - 国内流量不再被代理，延迟与 CPU 开销显著降低；
#   - 这些流重新走 FORWARD 路径，fw4 flowtable 软/硬 offload 得以生效。
#     （TPROXY 截走的流会被导入本机 input 路径，永远到不了 forward hook，
#      对这些流 nat offload 是无效的。）
# 列表由 update-chnroute.sh 下载生成（建议加入 cron 定期刷新），本脚本只
# 消费不下载，开机不依赖网络；文件缺失或损坏时仅警告并继续，不影响其余功能。
# 更新列表后需重跑本脚本（或重启 xtp-rs 服务）才会生效。
#
# 开关取值优先级：环境变量 XTP_BYPASS_CHNROUTE > uci 选项
# xtp-rs.main.bypass_chnroute（/etc/config/xtp-rs）> 默认关闭。
# -------------------------------------------------------------------------
XTP_BYPASS_CHNROUTE="${XTP_BYPASS_CHNROUTE:-}"
if [ -z "$XTP_BYPASS_CHNROUTE" ] && command -v uci >/dev/null 2>&1; then
  XTP_BYPASS_CHNROUTE="$(uci -q get xtp-rs.main.bypass_chnroute || true)"
fi
# 归一化布尔值（兼容 true/yes/on 等写法），防止 uci 侧填入意外值
case "$XTP_BYPASS_CHNROUTE" in
  1|true|yes|on) XTP_BYPASS_CHNROUTE=1 ;;
  *) XTP_BYPASS_CHNROUTE=0 ;;
esac
CHNROUTE_NFT_FILE="${XTP_CHNROUTE_FILE:-/etc/xtp-rs/chnroute.nft}"

CHNROUTE_INCLUDE=""
CHNROUTE_RETURN=""
if [ "$XTP_BYPASS_CHNROUTE" = "1" ]; then
  if [ -s "$CHNROUTE_NFT_FILE" ] && grep -q '^set china_ips' "$CHNROUTE_NFT_FILE"; then
    CHNROUTE_INCLUDE="include \"${CHNROUTE_NFT_FILE}\""
    CHNROUTE_RETURN="ip daddr @china_ips return"
  else
    echo "xtp-rs: warning: XTP_BYPASS_CHNROUTE=1 but $CHNROUTE_NFT_FILE is missing or invalid, bypass disabled; run update-chnroute.sh first" >&2
  fi
fi

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
# tproxy / socket 是 nft 表达式，分别由内核模块 nft_tproxy / nft_socket 提供；
# 缺模块时整张表加载失败。先尝试加载，失败则提示安装对应 kmod 包。
for _mod in nft_tproxy nft_socket; do
  [ -d "/sys/module/$_mod" ] || modprobe "$_mod" 2>/dev/null || true
  if [ ! -d "/sys/module/$_mod" ]; then
    echo "xtp-rs: kernel module $_mod not available, install kmod-nft-${_mod#nft_}" >&2
    exit 1
  fi
done

#cat <<NFTABLES
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
# prerouting 链（mangle hook）：
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
# 【divert —— 短路径优化（可选）】
# -------------------------------------------------------------------------
# 已被 TPROXY 接管的连接，内核会为其关联一个 "transparent" 状态的
# socket。prerouting 链中优先检查：
#   socket transparent 1 socket wildcard 0 meta mark set 1 accept
# 若匹配，说明该连接已在代理中，直接标记并放行，跳过后面复杂的规则
# 匹配，降低 CPU 开销。OpenWrt 需安装 kmod-nf-socket / kmod-nft-socket。
# socket wildcard 0 避免误匹配绑定 0.0.0.0/:: 的通配监听 socket。
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
${RESERVED_IP_ELEMENTS}
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

${CHNROUTE_INCLUDE}

  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;

    # xtp-rs 自身发起真实上游连接时设置 mark 2，防止再次进入 TPROXY。
    # 注意：不能在此 return mark 1；本机 output 链标记为 mark 1 的首包
    # 需要继续命中后面的 TPROXY 规则。
    # 放在最前面：mark 是整数比较，比 iifname 字符串匹配更快。
    meta mark 2 return

    # 仅代理明确配置的入口接口；未列入集合的 WAN、VPN、Docker 等接口均不进入 TPROXY。
    # 多接口示例：XTP_PROXY_INGRESS_IFACES="br-lan br-guest"
    # lo 必须放行：xtp-rs 出站到本地 SOCKS5（127.0.0.1:20808 等）的包经 output 链
    # 标记 mark 2 后走策略路由表 100 从 lo 回环，响应包从 lo 入站经过此 hook，
    # 若 lo 不在白名单中会被丢弃，导致 xtp-rs 无法连接本地 upstream。
    iifname != { ${XTP_PROXY_INGRESS_IFACES_NFT}, "lo" } return

    # 已被 transparent socket 接管的 TCP 连接：恢复策略路由 mark，不重复 TPROXY
    # openwrt: 需要 kmod-nf-socket 和 kmod-nft-socket 包支持
    meta l4proto tcp socket transparent 1 socket wildcard 0 meta mark set 1 accept

    # 可选：根据源 IP 跳过代理（如内网管理段）
    # ip saddr 10.2.1.0/24 return
    ip daddr @local_ip return
    ip daddr @reserved_ip return
    ${CHNROUTE_RETURN}
    meta l4proto tcp ip daddr 192.168.0.0/16 return
    ip daddr 192.168.0.0/16 udp dport != 53 return
    ip6 daddr @reserved_ip6 return
    meta l4proto tcp ip6 daddr fd00::/8 return
    ip6 daddr fd00::/8 udp dport != 53 return

    meta l4proto { tcp, } th dport { 80, 443, } meta mark set 1 tproxy ip to 127.0.0.1:10810 accept
    meta l4proto { tcp, } th dport { 80, 443, } meta mark set 1 tproxy ip6 to [::1]:10810 accept
    meta l4proto { udp, } th dport { 53, 443, } meta mark set 1 tproxy ip to 127.0.0.1:10810 accept
    meta l4proto { udp, } th dport { 53, 443, } meta mark set 1 tproxy ip6 to [::1]:10810 accept
  }

  chain output {
    type route hook output priority filter; policy accept;
    meta mark 2 counter return
    # 如需要使用uid xtp-rs来标记进程的包，解除以下注释
    # meta skuid xtp-rs counter return
    ip daddr @local_ip return
    ip daddr @reserved_ip return
    ${CHNROUTE_RETURN}
    meta l4proto tcp ip daddr 192.168.0.0/16 return
    ip daddr 192.168.0.0/16 udp dport != 53 return
    ip6 daddr @reserved_ip6 return
    meta l4proto tcp ip6 daddr fd00::/8 return
    ip6 daddr fd00::/8 udp dport != 53 return
    meta l4proto { tcp, } th dport { 80, 443, } meta mark set 1 accept
    meta l4proto { udp, } th dport { 53, 443, } meta mark set 1 accept
  }
}
NFTABLES
