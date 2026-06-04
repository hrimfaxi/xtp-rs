# xtp-rs

**xtp-rs** 是一个基于 **TPROXY** 的高性能透明代理 / 端口转发工具，可将所有入站 TCP/UDP 流量通过一个或多个 **SOCKS5** 上游服务器转发，并支持基于 IP 归属地（MaxMind GeoIP2）、geosite 域名列表、自定义 CIDR 以及本地地址的智能分流。  
同时提供动态上游评分、TLS/HTTP/QUIC 域名嗅探、热重载等功能。

---

## ✨ 特性

- 🔁 **透明代理 (TPROXY)**  
  支持 IPv4/IPv6 的 TCP 和 UDP 流量拦截与转发，无需修改客户端配置。

- 🧭 **智能路由**  
  根据目标 IP 的国家/地区（MaxMind MMDB）、geosite 域名分类、自定义 CIDR 列表、本地地址类型判断选择直连或走代理。  
  支持运行时通过 `SIGUSR1` 在 `smart` / `global` / `bypass` 模式间动态切换。

- 📡 **多 SOCKS5 上游**  
  支持配置多个上游 SOCKS5 服务器，并支持用户名/密码认证。

- 📈 **动态上游评分**  
  实时监控 TCP 吞吐量（通过 `TCP_INFO`），并接收 QUIC 探针（RTT/丢包率/MTU）报告，采用平方加权随机算法自动选择最优上游。

- 👃 **域名嗅探**  
  - **TLS SNI**：从 TLS ClientHello 中提取域名（用于 HTTPS）。  
  - **HTTP Host**：从 HTTP/1.x 请求头中提取域名（用于明文 HTTP）。  
  - **QUIC SNI**：从 QUIC Initial 包中解析域名（实验性，默认关闭）。  

  > 注意：上述嗅探功能在配置文件中默认均为 **关闭**，需手动设置 `sniff_tls_sni = true` 等开启。编译时均已包含相关代码（features 默认启用）。

- ⚙️ **端口转发**  
  将本地 TCP/UDP 端口强制通过 SOCKS5 转发到指定目标（可用于 DNS over SOCKS5、远程访问等）。

- 🔄 **热重载**  
  发送 `SIGHUP` 重新加载配置文件，无需重启进程。  
  发送 `SIGUSR1` 循环切换代理模式（smart → global → bypass → smart）。

- 🧹 **健康检查**  
  可选的主动健康检查（HTTP HEAD），结合被动性能监控，自动隔离故障上游。

- 📦 **一键部署脚本**  
  提供 `setup-xtp-rs.sh` / `unsetup-xtp-rs.sh` 脚本，快速配置 nftables + 策略路由，实现透明代理环境搭建。

---

## 📦 构建

### 依赖
- Rust 1.70+
- Linux 内核（需启用 `TPROXY`、`IP_TRANSPARENT`、`NF_SOCKET` 等选项）

### 编译

```bash
git clone https://github.com/hrimfaxi/xtp-rs.git
cd xtp-rs

# 默认启用所有 sniff 功能和 geosite 支持
cargo build --release

# 如需禁用某些 sniff 功能（例如不需要 QUIC sniff）以减小体积
cargo build --release --no-default-features --features "sniff-tls,sniff-http,geosite"
```

可选 Features：
| Feature | 说明 |
|---------|------|
| `sniff-tls` | TLS SNI 嗅探（默认启用） |
| `sniff-http` | HTTP Host 嗅探（默认启用） |
| `sniff-quic` | QUIC SNI 嗅探（默认禁用） |
| `geosite`   | geosite.dat 分流支持（默认启用） |

---

## 🚀 使用方法

### 1. 部署透明代理环境（使用提供的脚本）

项目 `contrib/usr/libexec/xtp-rs/` 目录下提供了三个辅助脚本：

- `common.sh` – 公共函数库，供其他脚本引用。
- `setup-xtp-rs.sh` – 一键配置 nftables 规则和策略路由（需 root 权限）。
- `unsetup-xtp-rs.sh` – 一键清理上述规则。

**执行步骤：**

```bash
cd contrib/usr/libexec/xtp-rs

# 配置透明代理环境（添加路由表、策略路由、nftables 规则）
sudo ./setup-xtp-rs.sh

# 启动 xtp-rs（需另开终端或后台运行）
sudo ../target/release/xtp-rs -c /etc/xtp-rs/config.toml

# 停止 xtp-rs 后清理环境
sudo ./unsetup-xtp-rs.sh
```

> **重要**：`setup-xtp-rs.sh` 脚本会自动配置：
> - 路由表 ID `100`，添加 `local default dev lo` 路由；
> - 策略规则：`fwmark 1` 查找路由表 `100`；
> - nftables 表 `inet xtp-rs`：
>   - 在 `prerouting` 链（处理转发的入站流量）和 `output` 链（处理本机发出的出站流量）中，匹配 TCP 80/443 以及 UDP 53/443，对这些需要代理的包**设置 `fwmark=1`**，使其走上述策略路由；
>   - 同时，xtp-rs 程序自身发出的出站连接会设置 `SO_MARK=2`（即 `XTP_BYPASS_MARK`），nftables 规则中遇到 `meta mark 2` 直接放行，从而避免代理流量被再次劫持形成环路。
>
> 如需修改默认端口或 fwmark，可编辑 `common.sh` 中的 `XTP_TPROXY_PORT`、`XTP_FWMARK`、`XTP_BYPASS_MARK` 变量。

### 2. 编写配置文件

默认配置文件路径为 **`config.toml`**（可通过 `-c` 参数指定）。  
以下是一个最小化配置示例：

```toml
# config.toml
listen = "[::]:10810"
mmdb_path = "/path/to/GeoLite2-Country.mmdb"

[[upstream]]
id = "your_socks5_server"
addr = "127.0.0.1:20808"

[[port_forward]]
bind = "127.0.0.1:5353"
remote = "8.8.8.8:53"
network = "udp"
```

完整的配置模板（包含所有可选项）见 [config.toml](./contrib/etc/xtp-rs/config.toml)（或根据源码 `src/cli.rs` 中的 `Config` 结构生成）。

### 3. 运行

```bash
sudo xtp-rs -c /etc/xtp-rs/config.toml
```

### 4. 信号控制

| 信号 | 行为 |
|------|------|
| `SIGHUP` | 热重载配置文件 |
| `SIGUSR1` | 循环切换代理模式（smart → global → bypass → smart） |
| `SIGTERM`/`SIGINT` | 优雅退出 |

---

## ⚙️ 配置说明

### 核心参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `listen` | string | `"[::]:10810"` | TPROXY 监听地址（与脚本中的端口需一致） |
| `udp` | bool | `true` | 是否启用 UDP 转发 |
| `fwmark` | u32 | `2` | **注意**：直连 / SOCKS5 出站 socket 使用的 fwmark。
必须与脚本中的 XTP_BYPASS_MARK（默认 2）保持一致，以确保 xtp-rs 自身发出的连接不会被透明代理再次劫持，从而避免环路。 |
| `mmdb_path` | string | 无 | GeoIP2 Country 数据库路径（留空禁用国家判定） |
| `direct_countries` | [string] | `["CN"]` | 直连的国家代码（ISO 3166-1 alpha-2） |
| `force_direct_ips` | [string] | `[]` | 强制直连的 IP/CIDR（优先级低于 force_socks5） |
| `force_socks5_ips` | [string] | `[]` | 强制走代理的 IP/CIDR（最高优先级） |
| `direct_local_ip` | bool | `true` | 回环/链路本地地址是否强制直连 |
| `sniff_tls_sni` | bool | `false` | 是否启用 TLS SNI 嗅探（仅非直连 TCP） |
| `sniff_http_host` | bool | `false` | 是否启用 HTTP Host 嗅探 |
| `sniff_quic_sni` | bool | `false` | 是否启用 QUIC SNI 嗅探（UDP） |
| `proxy_mode` | string | `"smart"` | 代理模式：`smart`/`global`/`bypass` |
| `geosite_path` | string | 无 | geosite.dat 文件路径（需编译 geosite feature） |
| `proxy_geosite_tags` | [string] | `[]` | 走代理的 geosite 分类（如 `gfw`） |
| `direct_geosite_tags` | [string] | `[]` | 走直连的 geosite 分类（如 `geolocation-cn`） |

> **重要**：  
> - XTP_FWMARK=1：用于标记入站需要代理的流量（由 nftables 规则设置）。
> - XTP_BYPASS_MARK=2：用于标记已代理/直连的出站流量（xtp-rs 程序设置）。
因此配置文件中的 fwmark 必须设为 2，不能为 1，否则代理程序自己的请求会被再次劫持。
> - 嗅探功能默认关闭，需要手动开启。编译时默认包含所有嗅探代码（除 QUIC 外），运行时开启不会带来额外性能损失（仅处理非直连流量的首包）。

### 上游配置

```toml
[[upstream]]
id = "server1"                 # 唯一标识
addr = "192.168.1.100:1080"   # SOCKS5 地址
```

- 至少配置一个 `upstream`。
- 可配置多个，系统会动态评分并加权随机选择。

### 端口转发

```toml
[[port_forward]]
name = "dns-via-socks5"       # 可选，仅用于日志
bind = "127.0.0.1:5353"       # 本地监听地址
remote = "8.8.8.8:53"         # 远端目标（必须是 IP:PORT）
network = "both"              # tcp / udp / both
```

---

## 📂 目录结构

```
xtp-rs/
├── scripts/
│   ├── common.sh               # 公共函数库
│   ├── setup-xtp-rs.sh         # 透明代理环境安装脚本
│   └── unsetup-xtp-rs.sh       # 清理脚本
├── src/
│   ├── cli.rs                  # 命令行和配置结构
│   ├── sniff/                  # 协议嗅探（tls, http, quic）
│   ├── socks5.rs               # SOCKS5 客户端实现
│   ├── tcp.rs                  # TCP 透明代理处理
│   ├── udp/                    # UDP 会话管理与转发
│   ├── upstream.rs             # 上游评分与选择
│   ├── state.rs                # 全局状态与生命周期
│   └── util.rs                 # 工具函数
├── Cargo.toml
└── README.md
```

---

## 🧪 测试

```bash
cargo test
```

部分测试需要 `tokio` 运行时环境（会自动处理）。

---

## 📄 许可

本项目使用 **GPL-3.0** 许可证。详见 [LICENSE](./LICENSE)。

---

## 🙏 致谢

- [tokio](https://tokio.rs/) – 异步运行时
- [maxminddb](https://github.com/oschwald/maxminddb-rust) – GeoIP2 解析
- [iptrie](https://crates.io/crates/iptrie) – IP 前缀匹配
- [geosite-rs](https://crates.io/crates/geosite-rs) – Geosite 解析

---

## ⚠️ 注意事项

1. **权限要求**  
   透明代理需要 root 权限（或 `CAP_NET_ADMIN`+`CAP_NET_RAW`）。

2. **splice 零拷贝**  
   若系统启用了 IP 转发（`net.ipv4.ip_forward=1`），使用 `splice` 可能导致性能下降，参见 [splice 与转发路径的注意事项](https://github.com/XTLS/Xray-core/discussions/59)。建议保持默认 `splice = false`。

3. **QUIC SNI 嗅探**  
   实验性功能，默认关闭。开启后会尝试解析 UDP 数据包的 QUIC Initial，可能增加 CPU 开销。

4. **配置文件路径**  
   默认读取当前工作目录下的 `config.toml`，可通过 `-c` 参数指定。脚本中未强制配置路径，请自行管理。

5. **热重载限制**  
   `SIGHUP` 重载时，端口转发监听地址若发生改变，旧地址上的监听 socket 会被关闭，新地址重新绑定。若新旧地址冲突可能导致短暂失败，建议设计时避免频繁变动。

---

**欢迎提交 Issue 和 PR！**
