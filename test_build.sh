#!/bin/bash
set -euo pipefail

cargo build
cargo build --no-default-features

cargo build --no-default-features -F sniff-tls
cargo build --no-default-features -F sniff-quic
cargo build --no-default-features -F sniff-http
cargo build --no-default-features -F sniff-tls -F sniff-quic -F sniff-http
