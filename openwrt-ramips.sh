#!/bin/bash

set -euo pipefail

export PATH=$PATH:~/.cargo/bin

cross +nightly build \
  --target mipsel-unknown-linux-musl \
  -Z build-std=std,panic_abort \
  --release

BIN=target/mipsel-unknown-linux-musl/release/xtp-rs

# upx 压缩（需要本地安装 upx）
if command -v upx &>/dev/null; then
  upx -3 $BIN
  echo "UPX compression done"
else
  echo "upx not found, skipping compression"
fi

TARGET=${1:-zengl}
rsync -avrPzz $BIN $TARGET:/usr/bin/
ssh $TARGET service xtp-rs restart
