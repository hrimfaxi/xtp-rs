#!/bin/bash

TOOLCHAIN=~/temp/openwrt-sdk-25.12.2-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin
export PATH=$TOOLCHAIN:$PATH

export CC_aarch64_unknown_linux_musl=$TOOLCHAIN/aarch64-openwrt-linux-musl-gcc
export CXX_aarch64_unknown_linux_musl=$TOOLCHAIN/aarch64-openwrt-linux-musl-g++
export AR_aarch64_unknown_linux_musl=$TOOLCHAIN/aarch64-openwrt-linux-musl-ar
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$TOOLCHAIN/aarch64-openwrt-linux-musl-gcc

# 编译
cargo build --release --target aarch64-unknown-linux-musl

BIN=target/aarch64-unknown-linux-musl/release/xtp-rs

# Strip 符号表（减小体积）
aarch64-openwrt-linux-musl-strip $BIN

# upx 压缩（需要本地安装 upx）
if command -v upx &>/dev/null; then
  upx --lzma $BIN
  echo "UPX compression done"
else
  echo "upx not found, skipping compression"
fi

# 上传并重启
rsync -avrPzz $BIN root@10.0.1.1:/usr/bin
ssh root@10.0.1.1 service xtp-rs restart
