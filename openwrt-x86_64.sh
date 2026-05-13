#!/bin/bash

set -e

export TOOLCHAIN=/home/hrimfaxi/temp/openwrt-sdk-25.12.2-x86-64_gcc-14.3.0_musl.Linux-x86_64/staging_dir/toolchain-x86_64_gcc-14.3.0_musl/bin/
export PATH=$TOOLCHAIN:$PATH

export CC_X86_64_UNKNOWN_LINUX_MUSL=$TOOLCHAIN/x86_64-openwrt-linux-musl-gcc
export CXX_X86_64_UNKNOWN_LINUX_MUSL=$TOOLCHAIN/x86_64-openwrt-linux-musl-g++
export AR_X86_64_UNKNOWN_LINUX_MUSL=$TOOLCHAIN/x86_64-openwrt-linux-musl-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$TOOLCHAIN/x86_64-openwrt-linux-musl-gcc

cargo build --release --target x86_64-unknown-linux-musl
rsync -avrPzz target/x86_64-unknown-linux-musl/release/xtp-rs n6000:/usr/bin/
ssh n6000 service xtp-rs restart
