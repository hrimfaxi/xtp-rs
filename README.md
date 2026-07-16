# xtp-rs

**xtp-rs** 是一个基于 **TPROXY** 的高性能透明代理 / 端口转发工具，可将所有入站 TCP/UDP 流量通过一个或多个 **SOCKS5** 上游服务器转发，并支持基于 IP 归属地（MaxMind GeoIP2）、geosite 域名列表、自定义 CIDR 以及本地地址的智能分流。
同时提供动态上游评分、TLS/HTTP/QUIC 域名嗅探、热重载等功能。

---

## ✨ 特性

- 🔁 **透明代理 (TPROXY)**
  支持 IPv4/IPv6 的 TCP 和 UDP 流量拦截与转发，无需修改客户端配置。

- 🧭 **智能路由**
  根据目标 IP 的国家/地区（MaxMind MMDB）、geosite 域名分类、自定义 CIDR 列表、本地地址类型判断选择直连或走代理。
  支持通过域名规则（`force_direct_domains` / `force_socks5_domains`）覆盖 geosite 和 IP 规则的路由决策。
  支持运行时通过 `SIGUSR1` 在 `smart` / `global` / `bypass` 模式间动态切换。

- 📡 **多 SOCKS5 上游**
  支持配置多个上游 SOCKS5 服务器，支持用户名/密码认证、分组路由和增益系数。

- 📈 **动态上游评分**
  实时监控 TCP 吞吐量（通过 `TCP_INFO`），并接收 QUIC 探针（RTT/丢包率/MTU）报告，采用平方加权随机算法自动选择最优上游。支持粘性切换容忍度避免频繁切换。

- 👃 **域名嗅探**
  - **TLS SNI**：从 TLS ClientHello 中提取域名（用于 HTTPS）。
  - **HTTP Host**：从 HTTP/1.x 请求头中提取域名（用于明文 HTTP）。
  - **QUIC SNI**：从 QUIC Initial 包中解析域名（默认启用）。

  > 注意：上述嗅探功能在配置文件中默认均为 **关闭**，需手动设置 `sniff_tls_sni = true` 等开启。编译时默认包含所有嗅探代码。

- ⚙️ **端口转发**
  将本地 TCP/UDP 端口强制通过 SOCKS5 转发到指定目标（可用于 DNS over SOCKS5、远程访问等）。

- 🔄 **热重载**
  发送 `SIGHUP` 重新加载配置文件，无需重启进程。
  发送 `SIGUSR1` 循环切换代理模式（smart → global → bypass → smart）。

- 🧹 **健康检查**
  可选的主动健康检查（HTTP HEAD），结合被动性能监控，自动隔离故障上游。

- 📦 **一键部署脚本**
  提供 `setup-xtp-rs.sh` / `unsetup-xtp-rs.sh` 脚本，快速配置 nftables + 策略路由，实现透明代理环境搭建。

- 🔀 **客户端路由**
  支持按客户端源 IP 分配不同 upstream 分组，实现精细化流量管理。

---

## 📦 构建

### 依赖
- Rust 1.70+（edition 2024）
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
| `sniff-quic` | QUIC SNI 嗅探（默认启用） |
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
sudo xtp-rs -c /etc/xtp-rs/config.toml

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
| `socks5_user` | string | 无 | SOCKS5 认证用户名（需与 `socks5_password` 同时配置） |
| `socks5_password` | string | 无 | SOCKS5 认证密码（需与 `socks5_user` 同时配置） |
| `mmdb_path` | string | 无 | GeoIP2 Country 数据库路径（留空禁用国家判定） |
| `direct_countries` | [string] | `["CN"]` | 直连的国家代码（ISO 3166-1 alpha-2） |
| `force_direct_ips` | [string] | `[]` | 强制直连的 IP/CIDR（优先级低于 force_socks5） |
| `force_socks5_ips` | [string] | `[]` | 强制走代理的 IP/CIDR（最高优先级） |
| `force_direct_ips_file` | string | 无 | 额外的强制直连 IP/CIDR 文件路径（每行一个） |
| `force_socks5_ips_file` | string | 无 | 额外的强制 SOCKS5 IP/CIDR 文件路径（每行一个） |
| `force_direct_domains` | [string] | `[]` | 强制直连的域名（优先级高于 geosite，低于 force_socks5_domains） |
| `force_socks5_domains` | [string] | `[]` | 强制走代理的域名（域名规则中优先级最高） |
| `direct_local_ip` | bool | `true` | 回环/链路本地地址是否强制直连 |
| `sniff_tls_sni` | bool | `false` | 是否启用 TLS SNI 嗅探（仅非直连 TCP） |
| `sniff_http_host` | bool | `false` | 是否启用 HTTP Host 嗅探 |
| `sniff_quic_sni` | bool | `false` | 是否启用 QUIC SNI 嗅探（UDP） |
| `proxy_mode` | string | `"smart"` | 代理模式：`smart`/`global`/`bypass` |
| `geosite_path` | string | 无 | geosite.dat 文件路径（需编译 geosite feature） |
| `proxy_geosite_tags` | [string] | `[]` | 走代理的 geosite 分类（如 `gfw`） |
| `direct_geosite_tags` | [string] | `[]` | 走直连的 geosite 分类（如 `geolocation-cn`） |
| `log_level` | string | 从环境变量读取，否则 `info` | 日志级别：`error`/`warn`/`info`/`debug`/`trace` |
| `udp_session_timeout_secs` | u64 | `60` | UDP 会话空闲超时时间（秒） |
| `connect_timeout_secs` | u64 | `20` | 上游连接超时时间（秒） |
| `splice` | bool | `false` | TCP 转发是否优先使用 splice 零拷贝 |
| `route_cache_ttl_secs` | u64 | `5` | 路由结果缓存 TTL（秒），0 禁用缓存 |
| `route_cache_max` | usize | `4096` | 路由结果缓存最大条目数 |

### 路由优先级

在 `smart` 模式下，路由决策按以下优先级从高到低执行（命中即返回）：

1. **域名强制规则** — `force_socks5_domains` → `force_direct_domains`
2. **geosite 域名分类** — `proxy_geosite_tags` → `direct_geosite_tags`
3. **路由缓存** — 缓存由 IP 规则和 GeoIP 得出的结果（域名规则不写缓存）
4. **IP 强制规则** — `force_socks5_ips` → `force_direct_ips`
5. **本地地址** — `direct_local_ip` 控制的回环/链路本地地址
6. **GeoIP 国家判定** — `direct_countries` 中的国家代码

域名规则支持两种格式：
- `.example.com` — 后缀匹配，匹配 example.com 及其所有子域名
- `example.com` — 精确匹配，仅匹配 example.com

> 示例：排除 PlayStation 流量不走代理
> ```toml
> force_direct_domains = [".playstation.com", ".sony.com", ".playstation.net"]
> ```

### 找路流程

以下是单条连接从接收到转发的完整路由决策流程。

#### TCP 连接

```
客户端 ──(TPROXY)──▶ xtp-rs ──▶ 目标地址
                         │
                    ① IP-only 初判
                    ② 是否需要嗅探域名？
                    ③ 条件嗅探 (TLS → HTTP)
                    ④ 最终直连/代理判定
                    ⑤ 选择上游并转发
```

1. **代理模式检查** — `proxy_mode` 为 `global` 时一律走代理，`bypass` 时一律直连，`smart` 进入后续规则匹配。

2. **IP-only 初判** — 仅凭目标 IP 查询路由规则（不涉及域名）：
   - `force_socks5_ips` 命中 → 走代理
   - `force_direct_ips` 命中 → 直连
   - 本地地址（回环/链路本地，`direct_local_ip` 控制）→ 直连
   - GeoIP 国家判定（`direct_countries`）→ 按结果决定
   - 均未命中 → 默认走代理

3. **判断是否需要域名嗅探** — 满足以下任一条件则需要：
   - 配置了域名强制规则（`force_direct_domains` 或 `force_socks5_domains` 非空）
   - 配置了 geosite 且处于 `smart` 模式
   - 配置了 `client_domain_routes` 且当前客户端 IP 匹配其中的 CIDR

4. **快速路径** — 若 IP 初判为直连 **且** 不需要嗅探，直接建立直连并转发，跳过后续步骤。

5. **条件嗅探** — 仅在需要时执行，按顺序尝试：
   - **TLS SNI**（`sniff_tls_sni`）— 解析 TLS ClientHello 提取 SNI
   - **HTTP Host**（`sniff_http_host`）— 解析 HTTP/1.x 请求头的 `Host` 字段
   - 任一嗅探成功即停止；全部失败则域名为空

6. **最终路由判定** — 若配置了 geosite 规则，用嗅探到的域名重新执行 `should_direct()`（域名规则优先级高于 IP 规则）；否则沿用 IP-only 结果。

7. **构建转发目标**：
   - 直连 → 直接连接原始目标 IP:Port
   - 走代理 + 嗅探成功 → SOCKS5 CONNECT 使用**域名**（让上游代理解析）
   - 走代理 + 嗅探失败 → SOCKS5 CONNECT 使用原始目标 IP

8. **上游选择**（仅走代理时）：
   - 查 `client_domain_routes`（客户端 IP + 域名 → 分组）
   - 查 `client_routes`（客户端 IP → 分组）
   - 未配置或未命中则使用 `"default"` 分组
   - 在分组内按动态评分做平方加权随机选择
   - 连接失败则尝试同组其他上游，全部失败则回退到 `"default"` 分组

9. **缓存** — 路由结果和上游选择写入缓存（`route_cache_ttl_secs` 控制 TTL），后续相同目标的连接直接复用。

#### UDP 数据包

```
客户端 ──(TPROXY)──▶ xtp-rs ──▶ 目标地址
                         │
                    ① 已有会话？→ 直接转发
                    ② 条件嗅探 QUIC SNI
                    ③ 创建/复用会话
                    ④ 转发数据包
```

1. **已有会话** — 若目标已有活跃的 UDP 会话，直接转发，不重新路由。

2. **条件嗅探**（QUIC SNI）— 仅在目标 IP 判定为**非直连**时执行：
   - `quic_sniff_forward_first = true`（默认）：首个数据包立即转发（不携带域名），同时后台启动嗅探；后续数据包使用嗅探到的域名。
   - `quic_sniff_forward_first = false`：缓存数据包直到嗅探完成。
   - 若 IP 判定为直连，跳过嗅探，直接转发。

3. **会话出站方式**：
   - 直连 → 本地 UDP socket 直接发送
   - 走代理 → SOCKS5 UDP ASSOCIATE

4. **上游选择** — 与 TCP 相同的分组查找 + 动态评分逻辑。

> **TCP 与 UDP 嗅探的关键差异**：TCP 嗅探结果会参与**直连/代理决策**（通过 geosite/域名规则）；UDP 嗅探结果仅影响**上游分组选择**，直连/代理判定始终基于 IP-only 结果。

### 上游动态评分参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `disable_upstream_score` | bool | `false` | 禁用上游动态评分（启用后完全随机选择） |
| `upstream_switch_tolerance` | u32 | `0` | 粘性切换容忍度（分），0 表示不启用粘性 |
| `quic_weight` | u32 | `70` | QUIC 探针在选路分数中的权重（0-100） |

### 健康检查参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `health_check_interval_secs` | u64 | `0` | 主动健康检查间隔（秒），0 表示禁用 |
| `health_check_timeout_secs` | u64 | `5` | 单次健康检查超时（秒） |
| `health_check_fail_threshold` | u32 | `2` | 连续失败次数阈值 |
| `health_check_url` | string | `"cp.cloudflare.com"` | 健康检查目标 URL |

### TLS 嗅探参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `tcp_peek_buffer_size` | usize | `32768` | TCP 首包 sniff 全局缓冲区上限（字节） |
| `tls_sniff_peek_len` | usize | `2048` | TLS sniff 首次 peek 长度（字节） |
| `tls_sniff_max_len` | usize | `32768` | TLS sniff 最大探测长度（字节） |
| `tls_sniff_max_retries` | usize | `5` | TLS sniff 最大重试次数 |
| `tls_sniff_wait_more_ms` | u64 | `100` | TLS sniff 等待更多数据时间（毫秒） |
| `tls_sniff_timeout_ms` | u64 | `1000` | TLS sniff 总超时时间（毫秒） |

### HTTP 嗅探参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `http_sniff_peek_len` | usize | `512` | HTTP sniff 首次 peek 长度（字节） |
| `http_sniff_max_len` | usize | `16384` | HTTP sniff 最大探测长度（字节） |
| `http_sniff_max_retries` | usize | `5` | HTTP sniff 最大重试次数 |
| `http_sniff_wait_more_ms` | u64 | `100` | HTTP sniff 等待更多数据时间（毫秒） |
| `http_sniff_timeout_ms` | u64 | `1000` | HTTP sniff 总超时时间（毫秒） |

> **重要**：
> - XTP_FWMARK=1：用于标记入站需要代理的流量（由 nftables 规则设置）。
> - XTP_BYPASS_MARK=2：用于标记已代理/直连的出站流量（xtp-rs 程序设置）。
因此配置文件中的 fwmark 必须设为 2，不能为 1，否则代理程序自己的请求会被再次劫持。
> - 嗅探功能默认关闭，需要手动开启。编译时默认包含所有嗅探代码，运行时开启不会带来额外性能损失（仅处理非直连流量的首包）。

### 上游配置

```toml
[[upstream]]
id = "server1"                 # 唯一标识
addr = "192.168.1.100:1080"   # SOCKS5 地址
# groups = ["default"]         # 所属分组，未设置则自动属于 ["default"]
# gain = 1.0                   # 乘数因子，用于放大或缩小该 upstream 的动态分数
```

- 至少配置一个 `upstream`。
- 可配置多个，系统会动态评分并加权随机选择。
- `gain` 必须大于 0，用于调整该 upstream 的选路权重。
- `groups` 用于配合 `client_routes` 实现分组路由。

### 客户端路由配置

```toml
# 按客户端源 IP 分配 upstream 分组
[client_routes]
"192.168.1.100" = "group_a"
"192.168.2.0/24" = "group_b"

# 按客户端源 IP + 域名模式分配 upstream 分组
# 支持两种域名匹配模式：
#   - ".example.com"：后缀匹配，匹配 example.com 及其所有子域名
#   - "example.com"：精确匹配，仅匹配 example.com
[client_domain_routes."192.168.1.100"]
".google.com" = "proxy_group"    # 后缀匹配
"example.com" = "direct_group"   # 精确匹配
```

- `client_routes`：按客户端源 IP 分配 upstream 分组，支持单 IP 和 CIDR。
- `client_domain_routes`：按客户端源 IP + 域名模式分配 upstream 分组，优先级高于 `client_routes`。
- 域名匹配按后缀长度降序优先匹配，确保最长匹配优先。

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
├── contrib/
│   ├── etc/
│   │   ├── capabilities/xtp-rs.json  # Linux capabilities 配置
│   │   ├── init.d/xtp-rs             # OpenWrt init 脚本
│   │   └── xtp-rs/
│   │       ├── config.toml            # 完整配置模板
│   │       └── Country-only-cn-private.mmdb  # GeoIP 数据库示例
│   └── usr/libexec/xtp-rs/
│       ├── common.sh                  # 公共函数库
│       ├── setup-xtp-rs.sh           # 透明代理环境安装脚本
│       └── unsetup-xtp-rs.sh         # 清理脚本
├── scripts/
│   └── test_socks5_udp.py            # UDP 测试脚本
├── src/
│   ├── cli.rs                         # 命令行和配置结构
│   ├── main.rs                        # 程序入口
│   ├── sniff/                         # 协议嗅探（tls, http, quic）
│   ├── socks5.rs                      # SOCKS5 客户端实现
│   ├── socket_factory.rs             # Socket 创建工厂
│   ├── tcp.rs                         # TCP 透明代理处理
│   ├── udp/                           # UDP 会话管理与转发
│   ├── upstream.rs                    # 上游评分与选择
│   ├── state.rs                       # 全局状态与生命周期
│   └── util.rs                        # 工具函数
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
- [geosite-rs](https://github.com/hrimfaxi/geosite-rs) – Geosite 解析
- [socket2](https://github.com/rust-lang/socket2) – 底层 socket 操作

---

## ⚠️ 注意事项

1. **权限要求**
   透明代理需要 root 权限（或 `CAP_NET_ADMIN`+`CAP_NET_RAW`+`CAP_NET_BIND_SERVICE`）。

2. **splice 零拷贝**
   若系统启用了 IP 转发（`net.ipv4.ip_forward=1`），使用 `splice` 可能导致性能下降，参见 [splice 与转发路径的注意事项](https://github.com/XTLS/Xray-core/discussions/59)。建议保持默认 `splice = false`。

3. **QUIC SNI 嗅探**
   默认启用，会尝试解析 UDP 数据包的 QUIC Initial，可能增加 CPU 开销。可在配置中关闭。

4. **配置文件路径**
   默认读取当前工作目录下的 `config.toml`，可通过 `-c` 参数指定。

5. **热重载限制**
   `SIGHUP` 重载时，端口转发监听地址若发生改变，旧地址上的监听 socket 会被关闭，新地址重新绑定。若新旧地址冲突可能导致短暂失败，建议设计时避免频繁变动。

6. **客户端路由**
   使用 `client_routes` 和 `client_domain_routes` 时，确保引用的 upstream 分组已在 `[[upstream]]` 中配置。未配置 `groups` 的 upstream 默认属于 `default` 组。

7. **OpenWrt 部署**
   使用 `contrib/etc/init.d/xtp-rs` 脚本可集成到 OpenWrt 的 procd 服务管理，支持ujail 沙箱和 capabilities 限制。

---

**欢迎提交 Issue 和 PR！**
