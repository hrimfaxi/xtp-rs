#!/bin/bash

export PATH=$PATH:~/.cargo/bin
cross +nightly build --target mipsel-unknown-linux-musl -Z build-std=std,panic_abort --release

BIN=target/mipsel-unknown-linux-musl/release/xtp-rs
# Strip 符号表（减小体积）
/home/hrimfaxi/temp/openwrt-sdk-25.12.2-ramips-mt7621_gcc-14.3.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-14.3.0_musl/bin/mipsel-openwrt-linux-musl-strip $BIN

# upx 压缩（需要本地安装 upx）
if command -v upx &>/dev/null; then
  upx -3 $BIN
  echo "UPX compression done"
else
  echo "upx not found, skipping compression"
fi

# 上传并重启
#rsync -avrPzz $BIN zdxlz:/usr/bin
#ssh zdxlz service xtp-rs restart
