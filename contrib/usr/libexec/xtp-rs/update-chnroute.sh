#!/bin/sh
# vim: set sw=2 ts=2 et:

set -eu

# -------------------------------------------------------------------------
# XTP-RS 中国大陆 IP（IPv4 + IPv6）直连列表更新脚本
#
# 从上游下载 chnroute（IPv4 CIDR）与 chn_ip_v6（IPv6 起止地址对）列表，
# 生成 nftables set 片段写入：
#   /etc/xtp-rs/chnroute.nft   （set china_ips ，type ipv4_addr）
#   /etc/xtp-rs/chnroute6.nft  （set china_ip6s，type ipv6_addr）
#
# IPv6 上游格式为每行两列「起始地址 结束地址」（含两端、空格分隔），
# 并非 CIDR 写法；nftables 的 interval set 原生支持区间元素（a-b），
# 故校验后原样写入，由 auto-merge 合并相邻/重叠区间。
#
# 片段供 setup-xtp-rs.sh 在开启 XTP_BYPASS_CHNROUTE=1 时 include 进
# inet xtp-rs 表，使发往中国大陆的流量不进入 TPROXY、保持正常转发路径
# （fw4 flowtable 软/硬 offload 得以对其生效）。两个地址族相互独立，
# 任一下载/生成失败不影响另一个的更新。
#
# 本脚本只生成数据文件，不改动运行中的规则；生成后需重跑 setup-xtp-rs.sh
# （或重启 xtp-rs 服务）才会生效。
#
# 【建议加入 cron 定期更新】列表每月都会有变动，建议每周更新一至两次，
# 例如每周三、周日 04:30 各执行一次。注意本脚本只生成数据文件，必须串联
# 重跑 setup-xtp-rs.sh 才会应用到运行中的规则；&& 保证下载失败时不动现有规则：
#   30 4 * * 0,3 { /usr/libexec/xtp-rs/update-chnroute.sh && /usr/libexec/xtp-rs/setup-xtp-rs.sh; } >/dev/null 2>&1
# OpenWrt 上可直接将该行追加到 /etc/crontabs/root，
# 然后执行 /etc/init.d/cron restart 使其生效。
#
# 环境变量：
#   XTP_CHNROUTE_URL    IPv4 上游列表 URL。默认指向 GitHub raw，墙内无法直连：
#                       可临时开着代理手动执行，或换成任意镜像地址。
#   XTP_CHNROUTE_FILE   IPv4 输出路径（默认 /etc/xtp-rs/chnroute.nft）。
#                       若修改，需与 setup-xtp-rs.sh 侧的值保持一致。
#   XTP_CHNROUTE6_URL   IPv6 上游列表 URL（默认同仓库 chn_ip_v6.txt）。
#   XTP_CHNROUTE6_FILE  IPv6 输出路径（默认 /etc/xtp-rs/chnroute6.nft）。
#                       若修改，需与 setup-xtp-rs.sh 侧的值保持一致。
# -------------------------------------------------------------------------

CHNROUTE_URL="${XTP_CHNROUTE_URL:-https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chnroute.txt}"
CHNROUTE_FILE="${XTP_CHNROUTE_FILE:-/etc/xtp-rs/chnroute.nft}"
CHNROUTE6_URL="${XTP_CHNROUTE6_URL:-https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chn_ip_v6.txt}"
CHNROUTE6_FILE="${XTP_CHNROUTE6_FILE:-/etc/xtp-rs/chnroute6.nft}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xtp-chnroute.XXXXXX")"
# EXIT trap 同时清理目标目录中的半成品 tmp 文件：mv 因磁盘满等原因失败时
# ${...}.tmp.$$ 残留在 /etc/xtp-rs/，只清 TMP_DIR 回收不到它们；
# mv 成功后 rm -f 对已不存在的路径无副作用。
trap 'rm -rf "$TMP_DIR"; rm -f "${CHNROUTE_FILE}.tmp.$$" "${CHNROUTE6_FILE}.tmp.$$"' EXIT

fetch() {
  _url="$1"
  _out="$2"
  if command -v curl >/dev/null 2>&1; then
    # --max-time 兜底整个请求生命周期：--connect-timeout 只约束建连阶段，
    # 建连后传输挂起仍会长时间阻塞 cron
    curl -fsSL --retry 3 --connect-timeout 10 --max-time 60 -o "${_out}" "${_url}" || return 1
  elif command -v wget >/dev/null 2>&1; then
    # -T 统一覆盖 DNS/连接/读取空闲超时，busybox 与 GNU wget 均支持
    wget -q -T 10 -O "${_out}" "${_url}" || return 1
  else
    echo "[-] Neither curl nor wget found." >&2
    return 127
  fi
}

update_china_ips() {
  echo "[*] [IPv4] Downloading chnroute list ..."
  fetch "${CHNROUTE_URL}" "${TMP_DIR}/chnroute4.src" || return 1

  if [ ! -s "${TMP_DIR}/chnroute4.src" ]; then
    echo "[-] [IPv4] Downloaded chnroute is empty." >&2
    return 1
  fi

  echo "[*] [IPv4] Filtering valid IPv4 CIDR entries ..."
  # 仅保留合法 IPv4 CIDR（各字节 0-255、前缀 0-32），剔除注释与其他行
  grep -E '^[[:space:]]*(((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))(/(3[0-2]|[12][0-9]|[1-9]))?[[:space:]]*$' \
    "${TMP_DIR}/chnroute4.src" \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
    | sort -u \
    > "${TMP_DIR}/cidr4.txt"

  if [ ! -s "${TMP_DIR}/cidr4.txt" ]; then
    echo "[-] [IPv4] No valid IPv4 CIDR entries found." >&2
    return 1
  fi

  mkdir -p "$(dirname "${CHNROUTE_FILE}")" || return 1
  # 临时文件放在目标文件同目录：跨文件系统时 mv 才能保证原子替换
  {
    echo "set china_ips {"
    echo "  type ipv4_addr;"
    echo "  flags constant, interval;"
    # auto-merge 必须：上游列表存在重叠区间，没有它整表会因
    # "interval overlaps" 加载失败；同时可合并相邻网段减小内核集合体积
    echo "  auto-merge;"
    echo "  elements = {"
    awk 'BEGIN { first = 1 }
         {
           cidr = $0
           if (cidr !~ /\//) cidr = cidr "/32"
           if (first) { printf("      %s,", cidr); first = 0 }
           else printf("\n      %s,", cidr)
         }
         END { printf("\n") }' "${TMP_DIR}/cidr4.txt"
    echo "  }"
    echo "}"
  } > "${CHNROUTE_FILE}.tmp.$$"

  mv -f "${CHNROUTE_FILE}.tmp.$$" "${CHNROUTE_FILE}" || return 1

  echo "[+] [IPv4] $(wc -l < "${TMP_DIR}/cidr4.txt") entries installed to ${CHNROUTE_FILE}."
}

update_china_ip6s() {
  echo "[*] [IPv6] Downloading chn_ip_v6 list ..."
  fetch "${CHNROUTE6_URL}" "${TMP_DIR}/chnroute6.src" || return 1

  if [ ! -s "${TMP_DIR}/chnroute6.src" ]; then
    echo "[-] [IPv6] Downloaded list is empty." >&2
    return 1
  fi

  echo "[*] [IPv6] Validating start-end pairs ..."
  # 上游每行两列：「起始地址 结束地址」（含两端）。逐行校验两侧均为合法
  # IPv6 字面量、且 start <= end 后，原样输出为 nft 区间元素（start-end），
  # 不做区间->CIDR 换算；重叠/相邻区间交给 set 的 auto-merge 处理。
  # 方向必须校验：写反的区间能通过格式检查，但 nft include 是全有全无的，
  # 加载时会报 invalid interval 并炸掉整张 inet xtp-rs 表。
  awk '
    function ip6_ok(t) {
      return (t ~ /^(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|:((:[0-9A-Fa-f]{1,4}){1,7}|:))$/)
    }
    # 归一化 IPv6 字面量为定长可比较键：:: 展开为缺失的全零组（插在
    # 前后段之间）、每组左补零至 4 位、统一大写，得 32 位十六进制串。
    # 等长十六进制串的字典序与数值序一致，无需任何 128 位算术
    # （POSIX/busybox awk 没有 strtonum）。仅在 ip6_ok 通过后调用。
    function ip6_key(t,   pos, h, tl, nh, nt, miss, out, i, g, ah, at) {
      pos = index(t, "::")
      if (pos == 0) {
        nh = split(t, ah, ":"); nt = 0; miss = 0
      } else {
        h = substr(t, 1, pos - 1); tl = substr(t, pos + 2)
        nh = (h == "" ? 0 : split(h, ah, ":"))
        nt = (tl == "" ? 0 : split(tl, at, ":"))
        miss = 8 - nh - nt
      }
      out = ""
      for (i = 1; i <= nh; i++) { g = toupper(ah[i]); while (length(g) < 4) g = "0" g; out = out g }
      for (i = 1; i <= miss; i++) out = out "0000"
      for (i = 1; i <= nt; i++) { g = toupper(at[i]); while (length(g) < 4) g = "0" g; out = out g }
      return out
    }
    {
      line = $0
      sub(/^[ \t\r]+/, "", line); sub(/[ \t\r]+$/, "", line)
      if (line == "" || line ~ /^#/) next
      if (split(line, f, /[ \t]+/) != 2 || !ip6_ok(f[1]) || !ip6_ok(f[2])) {
        bad++
        next
      }
      if (ip6_key(f[1]) > ip6_key(f[2])) {
        bad++
        next
      }
      printf "      %s-%s,\n", f[1], f[2]
      cnt++
    }
    END {
      if (bad > 0) printf("[!] [IPv6] skipped %d invalid line(s).\n", bad) > "/dev/stderr"
      exit (cnt == 0 ? 1 : 0)
    }
  ' "${TMP_DIR}/chnroute6.src" > "${TMP_DIR}/ranges6.txt" || return 1

  mkdir -p "$(dirname "${CHNROUTE6_FILE}")" || return 1
  # 临时文件放在目标文件同目录：跨文件系统时 mv 才能保证原子替换
  {
    echo "set china_ip6s {"
    echo "  type ipv6_addr;"
    echo "  flags constant, interval;"
    # auto-merge：上游区间可能相邻或重叠，合并以通过加载并减小集合体积
    echo "  auto-merge;"
    echo "  elements = {"
    cat "${TMP_DIR}/ranges6.txt"
    echo "  }"
    echo "}"
  } > "${CHNROUTE6_FILE}.tmp.$$"

  mv -f "${CHNROUTE6_FILE}.tmp.$$" "${CHNROUTE6_FILE}" || return 1

  echo "[+] [IPv6] $(wc -l < "${TMP_DIR}/ranges6.txt") entries installed to ${CHNROUTE6_FILE}."
}

# 两个地址族独立更新：任一失败仅告警，不影响另一个；全部失败才退出非零，
# 使 cron 的 "&& setup" 链在完全无更新时不重建运行中的规则。
UPDATE_OK=0

if update_china_ips; then
  UPDATE_OK=1
else
  echo "[!] [IPv4] update failed, existing ${CHNROUTE_FILE} left untouched." >&2
fi

if update_china_ip6s; then
  UPDATE_OK=1
else
  echo "[!] [IPv6] update failed, existing ${CHNROUTE6_FILE} left untouched." >&2
fi

if [ "${UPDATE_OK}" -eq 0 ]; then
  echo "[-] All list updates failed." >&2
  exit 1
fi

echo "[i] Re-run setup-xtp-rs.sh (or restart the xtp-rs service) to apply."

# vim: set sw=2 ts=2 et:
