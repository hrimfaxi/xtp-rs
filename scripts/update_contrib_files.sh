#!/bin/sh
set -e

CONTRIB_DIR="$(cd "$(dirname "$0")/.." && pwd)/contrib/etc/xtp-rs"

MMDB_PATH="$CONTRIB_DIR/Country-only-cn-private.mmdb"
MMDB_URL="https://raw.githubusercontent.com/kkkgo/Country-only-cn-private.mmdb/main/Country-only-cn-private.mmdb"
MMDB_SHA_URL="https://raw.githubusercontent.com/kkkgo/Country-only-cn-private.mmdb/main/Country-only-cn-private.mmdb.sha256sum"

GEOSITE_PATH="$CONTRIB_DIR/geosite.dat"
GEOSITE_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

LOCK="/tmp/update_xtp_contrib.lock"
UPDATED=0

# 下载辅助函数：检查退出码 + 文件非空
download() {
  _url="$1"
  _dst="$2"
  if ! wget -q -O "$_dst" "$_url"; then
    echo "[x] download failed: $_url"
    return 1
  fi
  if [ ! -s "$_dst" ]; then
    echo "[x] downloaded file is empty: $_url"
    return 1
  fi
}

# -----------------------
# 防并发锁
# -----------------------
if [ -f "$LOCK" ]; then
  echo "[x] another update running"
  exit 0
fi

touch "$LOCK"

# -----------------------
# trap 自动清理
# -----------------------
MMDB_TMP=""
MMDB_SHA_TMP=""
GEOSITE_TMP=""

cleanup() {
  rm -f "$LOCK"
  [ -n "$MMDB_TMP" ] && rm -f "$MMDB_TMP"
  [ -n "$MMDB_SHA_TMP" ] && rm -f "$MMDB_SHA_TMP"
  [ -n "$GEOSITE_TMP" ] && rm -f "$GEOSITE_TMP"
}

trap cleanup EXIT INT TERM

# =======================
# MMDB 更新逻辑（sha 校验）
# =======================
echo "[*] updating mmdb..."

MMDB_TMP="$(mktemp /tmp/mmdb.XXXXXX)"
MMDB_SHA_TMP="$(mktemp /tmp/mmdb-sha.XXXXXX)"

download "$MMDB_SHA_URL" "$MMDB_SHA_TMP"
REMOTE_SHA="$(awk '{print $1}' "$MMDB_SHA_TMP")"

if [ -f "$MMDB_PATH" ]; then
  LOCAL_SHA="$(sha256sum "$MMDB_PATH" | awk '{print $1}')"
else
  LOCAL_SHA=""
fi

if [ "$REMOTE_SHA" != "$LOCAL_SHA" ]; then
  echo "[!] mmdb changed"

  download "$MMDB_URL" "$MMDB_TMP"
  DOWNLOADED_SHA="$(sha256sum "$MMDB_TMP" | awk '{print $1}')"

  if [ "$DOWNLOADED_SHA" = "$REMOTE_SHA" ]; then
    mv "$MMDB_TMP" "$MMDB_PATH"
    chmod 644 "$MMDB_PATH"
    UPDATED=1
    MMDB_TMP=""
    echo "[+] mmdb updated"
  else
    echo "[x] mmdb sha mismatch"
    exit 1
  fi
else
  echo "[=] mmdb unchanged"
fi

rm -f "$MMDB_SHA_TMP"
MMDB_SHA_TMP=""

# =======================
# Geosite 更新逻辑（diff 判断）
# =======================
echo "[*] updating geosite..."

GEOSITE_TMP="$(mktemp /tmp/geosite.XXXXXX)"

download "$GEOSITE_URL" "$GEOSITE_TMP"

# 排除 GitHub 返回的错误页面（HTML）混入
if head -c 4 "$GEOSITE_TMP" | grep -q '<!DO'; then
  echo "[x] geosite download returned HTML (likely GitHub error page)"
  exit 1
fi

if [ -f "$GEOSITE_PATH" ]; then
  if cmp -s "$GEOSITE_TMP" "$GEOSITE_PATH"; then
    echo "[=] geosite unchanged"
  else
    mv "$GEOSITE_TMP" "$GEOSITE_PATH"
    chmod 644 "$GEOSITE_PATH"
    UPDATED=1
    GEOSITE_TMP=""
    echo "[+] geosite updated"
  fi
else
  mv "$GEOSITE_TMP" "$GEOSITE_PATH"
  chmod 644 "$GEOSITE_PATH"
  UPDATED=1
  GEOSITE_TMP=""
  echo "[+] geosite created"
fi

# -----------------------
# 结果
# -----------------------
if [ "$UPDATED" -eq 1 ]; then
  echo "[+] files updated, ready for release build"
else
  echo "[=] no changes"
fi

# vim: set sw=2 ts=2 et:
