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

# -------------------------------------------------------------------------
# 额外保留 IP（追加进 reserved_ip 集合，强制直连）
# -------------------------------------------------------------------------
# 在下方内置保留网段之外，允许用户追加自定义直连地址（如上游 VPN IP、
# 内网服务器、指定公网 IP），这些目的地址不进入 TPROXY。
# 取值优先级与 tcp_ports / udp_ports 相同：环境变量 XTP_EXT_RESERVED_IP >
# uci 选项 xtp-rs.main.ext_reserved_ip（/etc/config/xtp-rs）> 默认为空。
# 格式：空白、逗号或分号分隔的 IPv4 地址或 CIDR 网段（如 192.168.9.0/24）；
# UCI 侧也可用 list 语法逐条定义（uci get 会以空格连接各条目，处理方式
# 相同）。非法项忽略并告警。改动后需重跑本脚本（或重启服务）才会生效。
# -------------------------------------------------------------------------
XTP_EXT_RESERVED_IP="${XTP_EXT_RESERVED_IP:-}"
if [ -z "$XTP_EXT_RESERVED_IP" ] && command -v uci >/dev/null 2>&1; then
  XTP_EXT_RESERVED_IP="$(uci -q get xtp-rs.main.ext_reserved_ip || true)"
fi

# 归一化与校验辅助函数（is_valid_ipv4_cidr / normalize_ip_cidr_list /
# set_elements_nft / normalize_port_list）已移至 common.sh。

# 构建 reserved_ip 元素列表（内置保留网段 + 用户追加的 ext_reserved_ip）
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

EXT_RESERVED_IP_LIST="$(normalize_ip_cidr_list "$XTP_EXT_RESERVED_IP")"
if [ -n "$EXT_RESERVED_IP_LIST" ]; then
  RESERVED_IP_ELEMENTS="$RESERVED_IP_ELEMENTS
$(set_elements_nft "$EXT_RESERVED_IP_LIST")"
fi

# -------------------------------------------------------------------------
# 可选：源 IP 直连（根据源地址跳过 TPROXY，如内网管理段）
# -------------------------------------------------------------------------
# 在 prerouting / output 链中，源地址命中列表的流量提前 return，不进入
# TPROXY，保持正常转发路径（fw4 flowtable 软/硬 offload 得以生效）。
# 适用于整个网段不需要代理的场景（如管理网段、监控网段）。
# 取值优先级与 ext_reserved_ip 相同：环境变量 XTP_BYPASS_SADDR >
# uci 选项 xtp-rs.main.bypass_saddr（/etc/config/xtp-rs）> 默认为空。
# 格式与校验方式同 ext_reserved_ip：空白、逗号或分号分隔的 IPv4 地址或
# CIDR 网段（如 10.2.1.0/24）；UCI 侧也可用 list 语法逐条定义，uci get
# 会以空格连接各条目，处理方式相同。非法项忽略并告警。改动后需重跑本
# 脚本（或重启服务）才会生效。
# -------------------------------------------------------------------------
XTP_BYPASS_SADDR="${XTP_BYPASS_SADDR:-}"
if [ -z "$XTP_BYPASS_SADDR" ] && command -v uci >/dev/null 2>&1; then
  XTP_BYPASS_SADDR="$(uci -q get xtp-rs.main.bypass_saddr || true)"
fi

BYPASS_SADDR_LIST="$(normalize_ip_cidr_list "$XTP_BYPASS_SADDR")"

# 规则生成函数 saddr_bypass_rules_nft 见 common.sh（与 set_elements_nft 对称）。
BYPASS_SADDR_RULES=""
[ -z "$BYPASS_SADDR_LIST" ] || {
  BYPASS_SADDR_RULES="$(saddr_bypass_rules_nft "$BYPASS_SADDR_LIST")"
}

# -------------------------------------------------------------------------
# 可选：中国大陆 IP（IPv4 + IPv6）目的地址直连（不经过 TPROXY）
# -------------------------------------------------------------------------
# 开启 XTP_BYPASS_CHNROUTE=1 后，目的地址命中 china_ips（IPv4）/
# china_ip6s（IPv6）集合的流量在 prerouting / output 中提前 return，
# 保持正常转发路径：
#   - 国内流量不再被代理，延迟与 CPU 开销显著降低；
#   - 这些流重新走 FORWARD 路径，fw4 flowtable 软/硬 offload 得以生效。
#     （TPROXY 截走的流会被导入本机 input 路径，永远到不了 forward hook，
#      对这些流 nat offload 是无效的。）
# 列表由 update-chnroute.sh 下载生成（建议加入 cron 定期刷新），本脚本只
# 消费不下载，开机不依赖网络；文件缺失或损坏时仅警告并继续，不影响其余功能。
# 两个地址族相互独立：任一列表缺失只跳过对应规则。更新列表后需重跑本脚本
# （或重启 xtp-rs 服务）才会生效。
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
CHNROUTE6_NFT_FILE="${XTP_CHNROUTE6_FILE:-/etc/xtp-rs/chnroute6.nft}"

CHNROUTE_INCLUDE=""
CHNROUTE_RETURN=""
CHNROUTE6_INCLUDE=""
CHNROUTE6_RETURN=""
if [ "$XTP_BYPASS_CHNROUTE" = "1" ]; then
  if [ -s "$CHNROUTE_NFT_FILE" ] && grep -q '^set china_ips' "$CHNROUTE_NFT_FILE"; then
    CHNROUTE_INCLUDE="include \"${CHNROUTE_NFT_FILE}\""
    CHNROUTE_RETURN="ip daddr @china_ips counter return"
  else
    echo "xtp-rs: warning: XTP_BYPASS_CHNROUTE=1 but $CHNROUTE_NFT_FILE is missing or invalid, IPv4 bypass disabled; run update-chnroute.sh first" >&2
  fi
  if [ -s "$CHNROUTE6_NFT_FILE" ] && grep -q '^set china_ip6s' "$CHNROUTE6_NFT_FILE"; then
    CHNROUTE6_INCLUDE="include \"${CHNROUTE6_NFT_FILE}\""
    CHNROUTE6_RETURN="ip6 daddr @china_ip6s counter return"
  else
    echo "xtp-rs: warning: XTP_BYPASS_CHNROUTE=1 but $CHNROUTE6_NFT_FILE is missing or invalid, IPv6 bypass disabled; run update-chnroute.sh first" >&2
  fi
fi

# -------------------------------------------------------------------------
# 待代理端口配置（TCP / UDP 目的端口）
# -------------------------------------------------------------------------
# 默认拦截 TCP 80/443、UDP 53/443。端口列表可配置，取值优先级与
# bypass_chnroute 相同：环境变量 XTP_TCP_PORTS / XTP_UDP_PORTS >
# uci 选项 xtp-rs.main.tcp_ports / udp_ports（/etc/config/xtp-rs）>
# 内置默认值。未安装 uci 的系统自动使用环境变量或内置默认值。
# 列表为空白、逗号或分号分隔的端口号（1-65535）；非法项忽略并告警，
# 全部无效时回退默认值，保证生成的 nft 集合永不为空（归一化函数
# normalize_port_list 见 common.sh）。
# 改动后需重跑本脚本（或重启 xtp-rs 服务）才会生效。
# -------------------------------------------------------------------------
XTP_TCP_PORTS="${XTP_TCP_PORTS:-}"
if [ -z "$XTP_TCP_PORTS" ] && command -v uci >/dev/null 2>&1; then
  XTP_TCP_PORTS="$(uci -q get xtp-rs.main.tcp_ports || true)"
fi
XTP_UDP_PORTS="${XTP_UDP_PORTS:-}"
if [ -z "$XTP_UDP_PORTS" ] && command -v uci >/dev/null 2>&1; then
  XTP_UDP_PORTS="$(uci -q get xtp-rs.main.udp_ports || true)"
fi

XTP_TCP_PORT_LIST="$(normalize_port_list "$XTP_TCP_PORTS" "80 443")"
if [ -z "$XTP_TCP_PORT_LIST" ]; then
  echo "xtp-rs: warning: no valid TCP ports configured, falling back to defaults: 80 443" >&2
  XTP_TCP_PORT_LIST="80 443"
fi
XTP_UDP_PORT_LIST="$(normalize_port_list "$XTP_UDP_PORTS" "53 443")"
if [ -z "$XTP_UDP_PORT_LIST" ]; then
  echo "xtp-rs: warning: no valid UDP ports configured, falling back to defaults: 53 443" >&2
  XTP_UDP_PORT_LIST="53 443"
fi

TCP_PORT_ELEMENTS="$(set_elements_nft "$XTP_TCP_PORT_LIST")"
UDP_PORT_ELEMENTS="$(set_elements_nft "$XTP_UDP_PORT_LIST")"

# -------------------------------------------------------------------------
# 可选：按进程属主（uid）跳过代理（防环路的替代方案）
# -------------------------------------------------------------------------
# output 链中，属主为指定用户/uid 的本机出站流量提前 return，不进入
# TPROXY。适用于让 xtp-rs 以专用用户运行、出站 socket 未设置
# XTP_BYPASS_MARK（config.toml 的 fwmark）的场景，同样可避免代理流量
# 被再次劫持形成环路。
# 取值优先级：环境变量 XTP_BYPASS_SKUID > uci 选项
# xtp-rs.main.bypass_skuid（/etc/config/xtp-rs）> 默认为空（关闭）。
# 取值为数字 uid 或用户名：用户名在应用规则时通过 id -u 解析为数字
# uid，用户不存在时告警并忽略。改动后需重跑本脚本（或重启服务）才会
# 生效。
# -------------------------------------------------------------------------
XTP_BYPASS_SKUID="${XTP_BYPASS_SKUID:-}"
if [ -z "$XTP_BYPASS_SKUID" ] && command -v uci >/dev/null 2>&1; then
  XTP_BYPASS_SKUID="$(uci -q get xtp-rs.main.bypass_skuid || true)"
fi

# 校验数字 uid：仅数字且不超过 2147483647（兼容 32 位平台的算术运算）
is_valid_uid() {
  _u="$1"
  case "$_u" in
    *[!0-9]*|'') return 1 ;;
  esac
  [ "$_u" -le 2147483647 ] || return 1
  return 0
}

# 将 bypass_skuid 解析为数字 uid：纯数字直接使用；用户名经 id -u 解析，
# 解析失败（用户不存在等）时告警并忽略。规则中一律写数字 uid，避免
# nft 加载时因名称解析失败导致整表加载失败。
SKUID_BYPASS_RULE=""
if [ -n "$XTP_BYPASS_SKUID" ]; then
  _skuid=""
  case "$XTP_BYPASS_SKUID" in
    *[!0-9]*)
      # 含非数字字符：视为用户名，先过字符白名单再解析
      case "$XTP_BYPASS_SKUID" in
        -*|.*|*[![:alnum:]_.-]*)
          echo "xtp-rs: warning: invalid bypass_skuid ignored: '$XTP_BYPASS_SKUID'" >&2
          ;;
        *)
          if command -v id >/dev/null 2>&1; then
            _skuid="$(id -u "$XTP_BYPASS_SKUID" 2>/dev/null || true)"
          fi
          [ -n "$_skuid" ] || echo "xtp-rs: warning: bypass_skuid user not found, ignored: '$XTP_BYPASS_SKUID'" >&2
          ;;
      esac
      ;;
    *)
      # 纯数字：直接作为 uid
      if is_valid_uid "$XTP_BYPASS_SKUID"; then
        _skuid="$XTP_BYPASS_SKUID"
      else
        echo "xtp-rs: warning: invalid bypass_skuid ignored: '$XTP_BYPASS_SKUID'" >&2
      fi
      ;;
  esac

  # 归一化前导零（007 -> 7），不依赖 nft 对非十进制写法的解析行为
  while [ "$_skuid" != "0" ] && [ "${_skuid#0}" != "$_skuid" ]; do
    _skuid="${_skuid#0}"
  done
  # uid 0 会放行所有 root 进程的本机出站流量，效果上等于关闭本机出站代理
  if [ "$_skuid" = "0" ]; then
    echo "xtp-rs: warning: bypass_skuid=0 will bypass proxy for ALL root-owned local traffic" >&2
  fi

  [ -z "$_skuid" ] || SKUID_BYPASS_RULE="    meta skuid ${_skuid} counter return"
fi

# -------------------------------------------------------------------------
# 1. 路由表（必须先于 rule 添加）
# -------------------------------------------------------------------------
# TPROXY 要求内核认为目标地址是"本机"，因此需要在独立路由表中声明
# local default dev lo。若先加 rule 再加 route，中间状态会导致
# 待代理包（fwmark = XTP_FWMARK）因查无路由而被丢弃。
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
# 流量劫持：将发往公网 TCP 目标端口（默认 80/443，可经 uci 配置）的
# 数据包重定向到本地 xtp-rs 监听端口（默认 ${XTP_TPROXY_PORT}），由 xtp-rs 代为
# 建立真实连接。
#
# -------------------------------------------------------------------------
# 【为什么必须配置 ip rule + ip route local】
# -------------------------------------------------------------------------
# TPROXY 与 REDIRECT/NAT 不同：它不修改数据包的目的地址（DNAT），而是
# 在"路由决策后、本地交付前"将包截获给本地进程。这要求内核必须认为该
# 数据包是"发往本机"的，否则不会进入本地输入路径。
#
# 因此需要策略路由配合：
#   1. output / prerouting 链将待代理包标记 fwmark=${XTP_FWMARK}；
#   2. ip rule add fwmark ${XTP_FWMARK} table ${XTP_TABLE_ID} 将标记包导入路由表 ${XTP_TABLE_ID}；
#   3. ip route add local default dev lo table ${XTP_TABLE_ID} 在表 ${XTP_TABLE_ID} 中声明：
#      "无论目的 IP 是什么，都是本地地址"，于是内核将包交给 lo 接口；
#   4. 监听在 [::1]:${XTP_TPROXY_PORT} 的 xtp-rs 通过 TPROXY 套接字接收原始包，
#      并可通过 getsockopt 获取原始目的地址，从而透明代理。
#
# 注意：必须先添加 route 再添加 rule。若 rule 存在而 route 不存在，
# 被标记的包会因查不到路由而被丢弃，可能导致系统网络异常。
#
# -------------------------------------------------------------------------
# 【fwmark ${XTP_FWMARK} —— 待代理流量】
# -------------------------------------------------------------------------
# output 链（route hook）：
#   拦截本机进程发出的 tcp 目标端口（默认 {80,443}，uci 可配置），
#   设置 fwmark=${XTP_FWMARK}。
#   随后该包命中 ip rule → 表 ${XTP_TABLE_ID} → local route → 被 TPROXY 截获到
#   127.0.0.1:${XTP_TPROXY_PORT} 或 [::1]:${XTP_TPROXY_PORT}。
#
# prerouting 链（mangle hook）：
#   对于作为网关时转发的流量（或外部进入本机的流量），同样将 TCP
#   默认端口 {80,443} 与 UDP {53,443} 标记 fwmark=${XTP_FWMARK} 并 TPROXY。
#
# -------------------------------------------------------------------------
# 【fwmark ${XTP_BYPASS_MARK} —— 已代理/绕过流量（防环路）】
# -------------------------------------------------------------------------
# xtp-rs 向外发起真实连接时，应在其出站 socket 上设置 SO_MARK=${XTP_BYPASS_MARK}
#（config.toml 的 fwmark；或通过 iptables/nftables 为 xtp-rs 进程出站流量统一标记）。
# output / prerouting 链中遇到 fwmark=${XTP_BYPASS_MARK} 直接 return，避免代理程序
# 发出的请求再次被自身拦截，形成无限代理环路。
#
# -------------------------------------------------------------------------
# 【divert —— 短路径优化（可选）】
# -------------------------------------------------------------------------
# 已被 TPROXY 接管的连接，内核会为其关联一个 "transparent" 状态的
# socket。prerouting 链中优先检查：
#   socket transparent 1 socket wildcard 0 meta mark set ${XTP_FWMARK} accept
# 若匹配，说明该连接已在代理中，直接标记并放行，跳过后面复杂的规则
# 匹配，降低 CPU 开销。OpenWrt 需安装 kmod-nf-socket / kmod-nft-socket。
# socket wildcard 0 避免误匹配绑定 0.0.0.0/:: 的通配监听 socket。
#
# -------------------------------------------------------------------------
# 【保留地址（reserved_ip / reserved_ip6）】
# -------------------------------------------------------------------------
# RFC1918 私有网段、链路本地地址、环回地址，以及用户通过 uci 选项
# xtp-rs.main.ext_reserved_ip 追加的直连网段，均不应进入代理，否则会
# 导致内网服务不可达或流量绕远。
#
# 【192.168.0.0/16 与 fd00::/8 特殊处理】
# -------------------------------------------------------------------------
# 内网 TCP 全部直连（return）；内网 UDP 仅放行命中 xtp_udp_ports 集合的
# 端口（默认 53/443），其余直连。这样 UDP/53（DNS）等仍可被代理/劫持。
# 端口列表可由 uci xtp-rs.main.tcp_ports / udp_ports 自定义。
#

table inet ${XTP_TABLE_NAME} {
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

  # 待代理 TCP 目的端口（uci xtp-rs.main.tcp_ports，默认 80,443）
  set xtp_tcp_ports {
    type inet_service;
    elements = {
${TCP_PORT_ELEMENTS}
    }
  }

  # 待代理 UDP 目的端口（uci xtp-rs.main.udp_ports，默认 53,443）
  set xtp_udp_ports {
    type inet_service;
    elements = {
${UDP_PORT_ELEMENTS}
    }
  }

${CHNROUTE_INCLUDE}
${CHNROUTE6_INCLUDE}

  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;

    # xtp-rs 自身发起真实上游连接时设置 mark ${XTP_BYPASS_MARK}，防止再次进入 TPROXY。
    # 注意：不能在此 return mark ${XTP_FWMARK}；本机 output 链标记为
    # mark ${XTP_FWMARK} 的首包需要继续命中后面的 TPROXY 规则。
    # 放在最前面：mark 是整数比较，比 iifname 字符串匹配更快。
    meta mark ${XTP_BYPASS_MARK} return

    # 仅代理明确配置的入口接口；未列入集合的 WAN、VPN、Docker 等接口均不进入 TPROXY。
    # 多接口示例：XTP_PROXY_INGRESS_IFACES="br-lan br-guest"
    # lo 必须放行：xtp-rs 出站到本地 SOCKS5（127.0.0.1:20808 等）的包经 output 链
    # 标记 mark ${XTP_BYPASS_MARK} 后走策略路由表 ${XTP_TABLE_ID} 从 lo 回环，响应包从 lo 入站经过此 hook，
    # 若 lo 不在白名单中会被丢弃，导致 xtp-rs 无法连接本地 upstream。
    iifname != { ${XTP_PROXY_INGRESS_IFACES_NFT}, "lo" } return

    # 已被 transparent socket 接管的 TCP 连接：恢复策略路由 mark，不重复 TPROXY
    # openwrt: 需要 kmod-nf-socket 和 kmod-nft-socket 包支持
    meta l4proto tcp socket transparent 1 socket wildcard 0 meta mark set ${XTP_FWMARK} accept

    # 源 IP 直连：命中 uci xtp-rs.main.bypass_saddr 列表的流量提前 return（默认无规则）
${BYPASS_SADDR_RULES}
    ip daddr @local_ip return
    ip daddr @reserved_ip return
    ${CHNROUTE_RETURN}
    meta l4proto tcp ip daddr 192.168.0.0/16 return
    # 内网 UDP：命中 xtp_udp_ports 的端口继续落到下方 TPROXY 规则（DNS 等），
    # 其余内网 UDP 直连。通过跳转子链实现"不在集合中则直连"语义：
    #   - 子链 return 回到父链下一条规则，随即被 TPROXY；
    #   - 子链 accept 终结本表对本包的处理（verdict 上传给父链），
    #     与旧写法 udp dport != 53 return 等价的前提是本链 policy accept
    #     （prerouting / output 均如此，base chain 里的 return 会落到
    #     policy accept）；此写法不依赖集合负匹配（!= @set）这一较新的
    #     内核语法，兼容性更好。
    ip daddr 192.168.0.0/16 meta l4proto udp jump lan_udp_ports
    ip6 daddr @reserved_ip6 return
    ${CHNROUTE6_RETURN}
    meta l4proto tcp ip6 daddr fd00::/8 return
    ip6 daddr fd00::/8 meta l4proto udp jump lan_udp_ports

    meta l4proto tcp th dport @xtp_tcp_ports meta mark set ${XTP_FWMARK} tproxy ip to 127.0.0.1:${XTP_TPROXY_PORT} accept
    meta l4proto tcp th dport @xtp_tcp_ports meta mark set ${XTP_FWMARK} tproxy ip6 to [::1]:${XTP_TPROXY_PORT} accept
    meta l4proto udp th dport @xtp_udp_ports meta mark set ${XTP_FWMARK} tproxy ip to 127.0.0.1:${XTP_TPROXY_PORT} accept
    meta l4proto udp th dport @xtp_udp_ports meta mark set ${XTP_FWMARK} tproxy ip6 to [::1]:${XTP_TPROXY_PORT} accept
  }

  chain output {
    type route hook output priority filter; policy accept;
    meta mark ${XTP_BYPASS_MARK} counter return

    # 按进程属主（uid）跳过代理（uci xtp-rs.main.bypass_skuid，默认关闭）：
    # xtp-rs 以专用用户运行且未设置出站 fwmark 时的防环路方案。
${SKUID_BYPASS_RULE}

    # 源 IP 直连：命中 uci xtp-rs.main.bypass_saddr 列表的流量提前 return（默认无规则）
${BYPASS_SADDR_RULES}
    ip daddr @local_ip return
    ip daddr @reserved_ip return
    ${CHNROUTE_RETURN}
    meta l4proto tcp ip daddr 192.168.0.0/16 return
    # 同 prerouting：内网 UDP 命中 xtp_udp_ports 才进入代理，其余直连
    ip daddr 192.168.0.0/16 meta l4proto udp jump lan_udp_ports
    ip6 daddr @reserved_ip6 return
    ${CHNROUTE6_RETURN}
    meta l4proto tcp ip6 daddr fd00::/8 return
    ip6 daddr fd00::/8 meta l4proto udp jump lan_udp_ports
    meta l4proto tcp th dport @xtp_tcp_ports meta mark set ${XTP_FWMARK} accept
    meta l4proto udp th dport @xtp_udp_ports meta mark set ${XTP_FWMARK} accept
  }

  # 内网 UDP 端口判定子链（被 prerouting / output 共同调用）：
  #   - dport ∈ xtp_udp_ports（默认含 DNS 53）→ return 回父链，
  #     继续命中其后的 TPROXY / mark 规则；
  #   - 其余内网 UDP → accept 终结本表处理，保持直连
  #     （父链均 policy accept，与旧的 base-chain return 等价）。
  chain lan_udp_ports {
    udp dport @xtp_udp_ports counter return
    counter accept
  }
}
NFTABLES
