#!/bin/bash

set -euo pipefail

export TOOLCHAIN=~/temp/openwrt-sdk-25.12.6-x86-64_gcc-14.3.0_musl.Linux-x86_64/staging_dir/toolchain-x86_64_gcc-14.3.0_musl/bin/
export PATH=$TOOLCHAIN:$PATH

export CC_X86_64_UNKNOWN_LINUX_MUSL=$TOOLCHAIN/x86_64-openwrt-linux-musl-gcc
export CXX_X86_64_UNKNOWN_LINUX_MUSL=$TOOLCHAIN/x86_64-openwrt-linux-musl-g++
export AR_X86_64_UNKNOWN_LINUX_MUSL=$TOOLCHAIN/x86_64-openwrt-linux-musl-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$TOOLCHAIN/x86_64-openwrt-linux-musl-gcc

cargo build --release --target x86_64-unknown-linux-musl

BIN=target/x86_64-unknown-linux-musl/release/xtp-rs

# Strip 符号表（减小体积）
x86_64-openwrt-linux-musl-strip $BIN

# upx 压缩（需要本地安装 upx）
if command -v upx &>/dev/null; then
  upx --lzma $BIN
  echo "UPX compression done"
else
  echo "upx not found, skipping compression"
fi

TARGET=${1:-n6000}
rsync -avrPzz $BIN $TARGET:/usr/bin/
ssh $TARGET service xtp-rs restart
