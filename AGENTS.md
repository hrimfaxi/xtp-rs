# AGENTS.md

## 项目概述

单 crate Rust 二进制项目——基于 TPROXY 的透明代理，通过 SOCKS5 上游转发 TCP/UDP 流量，支持 GeoIP/geosite 智能分流。非 workspace，根目录只有一个 `Cargo.toml`。

## 构建与测试

```bash
cargo build                    # debug 构建（默认 features：全部 sniff + geosite）
cargo build --release          # 体积优化（opt-level "z", LTO, strip, panic=abort）
cargo test                     # 全部单元测试（tokio 运行时自动提供）
cargo clippy -- -D warnings    # lint
```

无 rustfmt.toml / clippy.toml，使用默认配置。

提交前必须运行 `cargo fmt` 格式化代码。

运行单个测试：
```bash
cargo test <test_name>
```

## Feature 说明

| Feature | 作用 |
|---------|------|
| `geosite` | geosite.dat 域名路由（`geosite-rs` + `prost`） |
| `sniff-tls` | 从 TLS ClientHello 提取 SNI |
| `sniff-http` | 从 HTTP 请求头提取 Host |
| `sniff-quic` | 解析 QUIC Initial 包的 SNI（引入 `aes`、`hkdf`、`sha2`、`aes-gcm`） |
| `sniff-tls-common` | TLS 公共代码，被 `sniff-quic` 和 `sniff-tls` 自动启用 |

默认启用全部。可禁用单个 sniff feature 以减小二进制体积。

## 架构

入口：`src/main.rs`——解析 CLI（`clap`）、加载 `config.toml`、构建 `AppState`、启动任务。

核心模块：
- `cli.rs` — `Config` 结构体（serde/toml）、校验逻辑、所有配置项。配置 schema 在此，不在文档。
- `state.rs` — `AppState` 持有运行时状态、路由表（IP trie、域名路由、geosite）、上游集合。热重载通过 `ArcSwap` 原子替换 `Arc<AppState>`。
- `tcp.rs` — TCP tproxy 接受循环，splice 零拷贝路径。
- `udp/` — UDP tproxy + 端口转发。每个 key 通过 `DashMap<UdpSessionKey, Mutex<()>>` 串行化。
- `sniff/` — 协议嗅探器，统一 `Sniffer` trait。每个嗅探器通过 `#[cfg(feature = "...")]` 条件编译。
- `upstream.rs` — 动态评分（`TCP_INFO` 吞吐量、QUIC 探针报告），加权随机选择。
- `socks5.rs` — SOCKS5 客户端，支持认证。
- `socket_factory.rs` — Socket 创建，处理 `SO_MARK`、`IP_TRANSPARENT`、`SO_REUSEADDR/PORT`。

## 交叉编译

目标：`mipsel-unknown-linux-musl`（OpenWrt 路由器）。见 `Cross.toml` 和 `.cargo/config.toml`。
```bash
cross build --release --target mipsel-unknown-linux-musl
```

## 运行环境要求

- Linux，需启用 TPROXY 内核支持（`NETFILTER_XT_TARGET_TPROXY`）。
- root 权限或 `CAP_NET_ADMIN` + `CAP_NET_RAW` + `CAP_NET_BIND_SERVICE`。
- 部署脚本在 `contrib/usr/libexec/xtp-rs/`，负责配置 nftables + 策略路由。
- 配置文件：`-c path/to/config.toml`（默认 `./config.toml`）。

## 信号

- `SIGHUP` — 热重载配置（原子替换，旧 generation 排空后停止）。
- `SIGUSR1` — 循环切换代理模式：smart → global → bypass → smart。

## 编码约定

- 代码注释使用中文，保持一致。
- Sniff 功能是双路径控制：`#[cfg(feature = "...")]` 控制编译，配置项（`sniff_tls_sni = true` 等）控制运行时激活。编译未开启 feature 但配置启用 = 启动时警告，不是编译错误。
- `fwmark = 2` 是出站 socket 的旁路标记；`fwmark = 1` 保留给 nftables 入站标记。混用会导致路由环路。
- UDP 使用 `BytesMut::split_to().freeze()` 零拷贝传递载荷给 spawn 的 task。
- `TaskGuard`（`util.rs`）管理 spawn task 的生命周期和优雅退出。

## 配置参考

完整配置模板：`contrib/etc/xtp-rs/config.toml`。配置结构体定义：`src/cli.rs`（`Config`）。
