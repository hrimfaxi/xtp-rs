#!/bin/sh
# vim: set sw=2 ts=2 et:

set -eu

# -------------------------------------------------------------------------
# XTP-RS 中国大陆 IPv4 直连列表更新脚本
#
# 从上游下载 chnroute 列表，生成 nftables set 片段（set china_ips）写入
# /etc/xtp-rs/chnroute.nft，供 setup-xtp-rs.sh 在开启 XTP_BYPASS_CHNROUTE=1
# 时 include 进 inet xtp-rs 表，使发往中国大陆的流量不进入 TPROXY、保持
# 正常转发路径（fw4 flowtable 软/硬 offload 得以对其生效）。
#
# 本脚本只生成数据文件，不改动运行中的规则；生成后需重跑 setup-xtp-rs.sh
# （或重启 xtp-rs 服务）才会生效。
#
# 【建议加入 cron 定期更新】列表每月都会有变动，建议每周更新一至两次，
# 例如每周三、周日 04:30 各执行一次：
#   30 4 * * 0,3 /usr/libexec/xtp-rs/update-chnroute.sh >/dev/null 2>&1
# OpenWrt 上可直接将该行追加到 /etc/crontabs/root，
# 然后执行 /etc/init.d/cron restart 使其生效。
#
# 环境变量：
#   XTP_CHNROUTE_URL   上游列表 URL。默认指向 GitHub raw，墙内无法直连：
#                      可临时开着代理手动执行，或换成任意镜像地址。
#   XTP_CHNROUTE_FILE  输出路径（默认 /etc/xtp-rs/chnroute.nft）。
#                      若修改，需与 setup-xtp-rs.sh 侧的值保持一致。
# -------------------------------------------------------------------------

CHNROUTE_URL="${XTP_CHNROUTE_URL:-https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chnroute.txt}"
CHNROUTE_FILE="${XTP_CHNROUTE_FILE:-/etc/xtp-rs/chnroute.nft}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xtp-chnroute.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

TMP_CHNROUTE="${TMP_DIR}/chnroute.txt"
TMP_CIDR="${TMP_DIR}/cidr.txt"
# 临时文件放在目标文件同目录：跨文件系统时 mv 才能保证原子替换
TMP_OUT="${CHNROUTE_FILE}.tmp.$$"

echo "[*] Downloading chnroute list ..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --retry 3 --connect-timeout 10 -o "${TMP_CHNROUTE}" "${CHNROUTE_URL}"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "${TMP_CHNROUTE}" "${CHNROUTE_URL}"
else
  echo "[-] Neither curl nor wget found." >&2
  exit 1
fi

if [ ! -s "${TMP_CHNROUTE}" ]; then
  echo "[-] Downloaded chnroute is empty." >&2
  exit 1
fi

echo "[*] Filtering valid IPv4 CIDR entries ..."
# 仅保留合法 IPv4 CIDR（各字节 0-255、前缀 0-32），剔除注释与 IPv6 行
grep -E '^[[:space:]]*(((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))(/(3[0-2]|[12][0-9]|[1-9]))?[[:space:]]*$' \
  "${TMP_CHNROUTE}" \
  | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
  | sort -u \
  > "${TMP_CIDR}"

if [ ! -s "${TMP_CIDR}" ]; then
  echo "[-] No valid IPv4 CIDR entries found." >&2
  exit 1
fi

echo "[*] Generating nftables set snippet ..."
mkdir -p "$(dirname "${CHNROUTE_FILE}")"
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
         if (first) { printf("      %s", cidr); first = 0 }
         else printf(",\n      %s", cidr)
       }
       END { printf("\n") }' "${TMP_CIDR}"
  echo "  }"
  echo "}"
} > "${TMP_OUT}"

echo "[*] Installing to ${CHNROUTE_FILE} (atomic replace) ..."
mv -f "${TMP_OUT}" "${CHNROUTE_FILE}"

ENTRIES="$(wc -l < "${TMP_CIDR}")"
echo "[+] Done. ${ENTRIES} entries installed."
echo "[i] Re-run setup-xtp-rs.sh (or restart the xtp-rs service) to apply."

# vim: set sw=2 ts=2 et:
