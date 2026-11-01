# OpenWrt 部署

> [← 返回 README](../README.md) · 相关：[配置参考](./配置.md) · [工作原理](./工作原理.md) · [通用 Linux 部署](./部署.md)

本文介绍 OpenWrt 下的部署与服务管理，命令默认在 root shell 中执行，使用 `uci`、`opkg`、`/etc/init.d`、`logread`、procd。
通用 Linux（Debian / Ubuntu / 软路由发行版等）的 systemd 部署请参阅 [通用 Linux 部署](./部署.md)，不要直接套用本文对应章节的命令。

---

## 一、安装方式

### 方式一：OpenWrt 软件包仓库

软件包 Makefile 仓库：[openwrt-xtp-rs](https://github.com/hrimfaxi/openwrt-xtp-rs)。按该仓库说明加入 feed 后：

```sh
opkg update
opkg install xtp-rs
```

### 方式二：预编译二进制

[GitHub Releases](https://github.com/hrimfaxi/xtp-rs/releases) 提供 x86_64 / i686 / aarch64 / armv7 / mips(el) / mips64 等多平台预编译二进制（glibc 与 musl 两种版本）。OpenWrt 请选用 **musl 静态版本**，放入 `/usr/bin/xtp-rs` 并 `chmod +x`。

### 方式三：自行交叉编译

见下节。

---

## 二、交叉编译

目标平台通常为 `mipsel-unknown-linux-musl`（MT7621 等）或 `aarch64-unknown-linux-musl`（Filogic 等）。项目根目录提供了一组基于 OpenWrt SDK toolchain 的脚本：

| 脚本 | 目标 |
|------|------|
| `openwrt-aarch64.sh` | `aarch64-unknown-linux-musl` |
| `openwrt-x86_64.sh` | `x86_64-unknown-linux-musl` |
| `openwrt-ramips.sh` | `mipsel-unknown-linux-musl`（需 `cross` + nightly，`-Z build-std`） |

使用前需先下载对应的 OpenWrt SDK，并修改脚本顶部的 `TOOLCHAIN` 路径指向 SDK 的 `staging_dir/toolchain-*/bin`。脚本会设置 `CC_/CXX_/AR_/CARGO_TARGET_*_LINKER` 环境变量后执行 `cargo build --release --target ...`，部分脚本还会 strip 与 upx 压缩。

也可直接使用 `cross`（见 `Cross.toml`）：

```sh
cross build --release --target mipsel-unknown-linux-musl
```

按需裁剪 feature 以减小体积（例如禁用 QUIC sniff）：

```sh
cargo build --release --target mipsel-unknown-linux-musl \
  --no-default-features --features "sniff-tls,sniff-http,geosite"
```

---

## 三、UCI 配置（`/etc/config/xtp-rs`）

透明代理的**环境参数**（拦截哪些端口、放行哪些地址）通过 UCI 配置，段名为 `xtp_rs 'main'`。默认模板见 [contrib/etc/config/xtp-rs](../contrib/etc/config/xtp-rs)，各项均有注释。

> [!NOTE]
> 这里配置的是 **nftables 拦截规则**，不是 xtp-rs 程序本身的配置。程序配置仍在 `/etc/xtp-rs/config.toml`（见 [配置参考](./配置.md)）。两者相互独立。

| UCI 选项 | 默认 | 说明 |
|----------|------|------|
| `bypass_chnroute` | `0` | 中国大陆 IP 目的地址直连（需先跑 `update-chnroute.sh`） |
| `ban_foreign_quic` | `0` | 拒绝发往境外地址的 QUIC（UDP/443），迫使回落到 TCP（需先跑 `update-chnroute.sh`） |
| `ban_foreign_quic_action` | `auto` | 上面开关的处置动作：`auto` / `reject` / `drop` |
| `tcp_ports` | `80 443` | 待代理 TCP 目的端口（空白 / 逗号 / 分号分隔，1-65535；`none` = 不代理 TCP） |
| `udp_ports` | `53 443` | 待代理 UDP 目的端口（同上；`none` = 不代理 UDP） |
| `ext_reserved_ip` | 空 | 额外强制直连的目的地址（上游 VPN IP、内网服务器、指定公网 IP） |
| `bypass_saddr` | 空 | 按源 IP 直连，跳过代理 |
| `bypass_skuid` | 空 | 按进程属主（用户名或 uid）直连，防环路替代方案 |

读写示例：

```sh
# 查看
uci get xtp-rs.main.bypass_chnroute

# 修改（单值）
uci set xtp-rs.main.bypass_chnroute='1'
uci set xtp-rs.main.ext_reserved_ip='10.8.0.1 192.168.9.0/24'
uci set xtp-rs.main.bypass_skuid='xtp-rs'

# 修改（列表语法逐条添加，脚本处理方式相同）
uci add_list xtp-rs.main.ext_reserved_ip='10.8.0.1'

# 提交并生效
uci commit xtp-rs
/etc/init.d/xtp-rs restart
```

改动 UCI 后**必须重启服务或重跑 `setup-xtp-rs.sh`** 才会写入 nftables。

### 中国大陆 IP 直连

```sh
# 1. 下载并生成列表（需能访问 GitHub，可用 XTP_CHNROUTE_URL / XTP_CHNROUTE6_URL 指定镜像）
/usr/libexec/xtp-rs/update-chnroute.sh

# 2. 开启开关
uci set xtp-rs.main.bypass_chnroute='1'
uci commit xtp-rs

# 3. 应用规则
/etc/init.d/xtp-rs restart

# 4. 建议加入 cron 定期刷新（只更新文件不重跑 setup 不生效）
#    30 4 * * 0,3 { /usr/libexec/xtp-rs/update-chnroute.sh && /usr/libexec/xtp-rs/setup-xtp-rs.sh; } >/dev/null 2>&1
#    追加到 /etc/crontabs/root 后执行：/etc/init.d/cron restart
```

列表文件位于 `/etc/xtp-rs/chnroute.nft`（IPv4）与 `/etc/xtp-rs/chnroute6.nft`（IPv6）；两个地址族独立，任一缺失只跳过对应规则。脚本只能识别“文件缺失 / 不是以 `set china_ips` 开头”这类问题；语法或类型损坏的文件要到 nft 加载阶段才会报错，此时 `setup-xtp-rs.sh` 会回滚到旧规则并报错（透明代理不会因此消失）。

### 关闭某个协议的代理（`none`）

把端口列表写成 `none`（或 `off`，大小写不敏感）就是「该协议完全不代理」：

```sh
uci set xtp-rs.main.udp_ports='none'    # 不代理任何 UDP（境外 DNS、内网 UDP 全部直连）
uci set xtp-rs.main.tcp_ports='none'    # 不代理任何 TCP
uci commit xtp-rs
/etc/init.d/xtp-rs restart
```

> [!IMPORTANT]
> **空值不等于 `none`**：把 `udp_ports` 设成空串 / 删掉该选项，脚本会回退到内置默认值（UDP 仍代理 `53 443`）。原因是未安装 uci 的系统在没设环境变量时也读不到值，若把空值当成"关闭"，那些系统会静默变成"什么都不代理"而服务看起来一切正常。

实现上，`none` 生成的 `xtp_tcp_ports` / `xtp_udp_ports` 集合**不带 `elements`**（nft 不接受空的 `elements = { }` 块），引用该集合的 `tproxy` / `mark` 规则因此永不命中；`lan_udp_ports` 子链也随之退化为"内网 UDP 全部直连"。

注意与 `ban_foreign_quic` 的配合：若 `tcp_ports` 不含 `443`（或为 `none`）而 `ban_foreign_quic=1`，被拦下的境外 QUIC 回落 TCP 时是**直连**而非走代理，`setup-xtp-rs.sh` 会在启动日志里给出告警。

### 禁止境外 QUIC

客户端（尤其浏览器）会优先用 QUIC（UDP/443）直连境外站点，这类流量要么绕过代理、要么在 UDP 不代理时直连出去。开启本选项后，目的地址不在中国大陆 IP 列表内的 UDP/443 被拦下，**支持快速回落的客户端**（Chrome / Firefox 等）会随即尝试 TCP/443，从而经代理访问：

```sh
# 1. 列表前置条件同 bypass_chnroute（已生成可跳过）
/usr/libexec/xtp-rs/update-chnroute.sh

# 2. 开启开关
uci set xtp-rs.main.ban_foreign_quic='1'
uci commit xtp-rs

# 3. 应用规则
/etc/init.d/xtp-rs restart
```

处置动作由 `ban_foreign_quic_action` 控制：

| 取值 | 行为 | 适用 |
|------|------|------|
| `auto`（默认） | 先按 `reject` 生成；整表加载失败时自动改用 `drop` 重试一次 | 通用，兼顾回落速度与旧内核 |
| `reject` | 强制回 ICMP / ICMPv6 `port-unreachable`，回落最快 | 内核 ≥ 5.9 |
| `drop` | 强制丢包，不发 ICMP，客户端要等 QUIC 握手超时 | 内核 < 5.9（OpenWrt 19.07 / 21.02 的 4.14 / 5.4） |

> [!IMPORTANT]
> **内核要求**：`reject` 用在 `prerouting` hook 需要 Linux ≥ 5.9（内核 `nft_reject_validate` 从 5.9 起才允许 `PRE_ROUTING`）。更早的内核上整张表会加载失败，这也是 `auto` 存在的原因 —— 它失败一次后自动降级为 `drop` 并告警。显式写 `reject` 则不做降级，失败即报错（`setup-xtp-rs.sh` 会回滚到旧规则，透明代理不会因此消失，但新规则不生效）。

其他行为要点：

- 规则位于 `TPROXY` 规则**之前**，因此即使 `udp_ports` 含 `443`，境外 QUIC 也会被拦下而不会进入代理。
- 匹配的是**所有** UDP/443，不只是 QUIC：其它跑在 443 上的 UDP 协议同样被拦；QUIC 跑在非 443 端口不覆盖。
- 国内 QUIC 命中 `china_ips` / `china_ip6s` 故不受影响。**注意“国内”取决于列表新鲜度**：列表里没有的国内 IP 会被当成境外而拦下（结果是回落 TCP，不是断网），所以列表要按 [中国大陆 IP 直连](#中国大陆-ip-直连) 的建议定期刷新。
- 对应地址族的列表缺失或损坏时只跳过该族规则并告警 —— 此时该族境外 QUIC 是**放行**而非拦截。
- 保留地址不影响：xtp-rs 自身出站（`fwmark` 等于旁路标记）与 `local_ip` 在更前面的规则里已 `return`，上游隧道不受影响。
- 排除项复用 `reserved_ip` / `reserved_ip6` 集合（保留网段 + `ext_reserved_ip`；`fc00::/7` 已覆盖 `fd00::/8`），并单独排除 `192.168.0.0/16`：内网 UDP 命中 `udp_ports`（默认含 443）时会从 `lan_udp_ports` 子链 `return` 回父链，而 `192.168/16` 刻意不在 `reserved_ip` 里（内网 UDP 命中代理端口时仍需可代理），不排除会把内网 QUIC 误拦。**内网服务若用公网地址访问**（split-horizon、服务直接绑在公网 IP 上），该地址要加进 `ext_reserved_ip`，否则会被当成境外。
- 影响范围限于 `XTP_PROXY_INGRESS_IFACES` 列出的入口接口（+ `lo`）出去的流量；从 WAN 进入、要转发给内网服务器的入站流量不经本规则（DNAT 在更早的 `dstnat` 优先级完成，目的地址已变成内网地址）。
- 已在 flowtable 快路径上的既有会话不再经过 netfilter，开启后可能要等旧流超时或被清掉才完全生效；排查时可 `conntrack -F` 或重启上游设备。
- 与 `bypass_chnroute` 共用同一份列表：两者任一开启都会 include 集合文件，`bypass_chnroute` 关掉不影响本选项。
- 只想让境外 QUIC 走 **TCP 代理**（不再代理 UDP/443）时，把 `443` 从 `udp_ports` 移除即可。

### 无 uci 时的回退

`setup-xtp-rs.sh` 的取值优先级为：**环境变量 > UCI 选项 > 内置默认**。因此即使临时没有 uci，也可用环境变量覆盖（变量名见 [通用 Linux 部署](./部署.md#42-环境变量无需-uci通用-linux-直接使用)）：

```sh
XTP_TCP_PORTS="80 443" XTP_BYPASS_CHNROUTE=1 /usr/libexec/xtp-rs/setup-xtp-rs.sh
```

---

## 四、procd 服务（`/etc/init.d/xtp-rs`）

`contrib/etc/init.d/xtp-rs` 提供 procd 服务脚本：

| 命令 | 作用 |
|------|------|
| `/etc/init.d/xtp-rs enable` | 开机自启 |
| `/etc/init.d/xtp-rs start` | 启动（先校验配置，再拉起进程并添加 nftables 规则） |
| `/etc/init.d/xtp-rs stop` | 先清理 nftables 规则，再停止进程 |
| `/etc/init.d/xtp-rs restart` | 重启并重新应用规则 |
| `/etc/init.d/xtp-rs reload` | 发送 `SIGHUP` 热重载配置 |

启动流程要点：

1. 先用 `xtp-rs --check -c /etc/xtp-rs/config.toml` 校验配置，失败则中止，避免带错配置反复 respawn；
2. `procd` 拉起主进程，配置 `respawn 3600 5 0`（1 小时内最多重启 5 次）与 `nofile=1048576`；
3. 若存在 `/sbin/ujail` 与 `/etc/capabilities/xtp-rs.json`，以 `nobody` 用户 + 只读 jail + capabilities 运行；
4. 最后调用 `setup-xtp-rs.sh` 写入透明代理规则。

> [!NOTE]
> `SIGHUP` 热重载只重载 `/etc/xtp-rs/config.toml`，**不会**重跑 nftables 规则；改 UCI 选项需 `restart`。

---

## 五、xtp-stats-reporter（ShadowQUIC 性能上报）

`xtp-stats-reporter` 是 **ShadowQUIC 专用**的性能上报 daemon：它采集 ShadowQUIC 的链路质量（RTT、丢包率、MTU），通过本地 Unix 数据报 socket（`/tmp/xtp-rs-report.sock`）以 JSON 上报给 xtp-rs，供上游动态评分使用。无需修改 ShadowQUIC。机制详见 [工作原理](./工作原理.md#五上游动态评分机制)。

### 5.1 取数方式（仅 RESTful API）

脚本只通过 ShadowQUIC 的 RESTful API 取数，不再抓 syslog（没有 `logread` 回落）：

| 条件 | 行为 |
|------|------|
| 该进程的配置文件里有顶层 `restful-api:` 段，且 `/api/v1/outbounds` 能取到数据 | 轮询 API 取连接采样，并用 `POST /api/v1/outbounds/{tag}/probe` 主动喂流量刷新采样 |
| 配置里没有 `restful-api:` 段，或这一段解析不出来 | **报错退出**（`ERROR:` 写 syslog，由 procd 重启，问题不修就一直报） |
| 段存在但 API 一时连不上 | 本轮跳过，下一轮重试；`DEBUG=1` 时记入 debug 日志 |

即：**这个版本没有降级路径**，配置不对时表现为"daemon 反复重启 + syslog 里有 ERROR"，而不是悄悄不上报数据。

要求的 ShadowQUIC 配置：

```yaml
restful-api:
  tag: restful-api
  bind-addr: "127.0.0.1:9090"   # 只给本机上报用，绑回环即可
  # secret: "choose-a-secret"   # 配了就必须带 Bearer，脚本会自动读取
```

ShadowQUIC 需以 `restful-api` feature 编译（默认开启），否则配置会被判为非法而启动失败。`upstream_id` 取 `<配置文件名>_<出站 tag>`：配置文件名跨进程去重，tag 来自 API 返回的出站 tag。

API 响应由 `jq` 或 `jsonfilter` 解析（脚本不再自己解析 JSON）：两者都没有时启动阶段直接报错退出。取数细节：

- 只有 `curl` 退出码为 0 **且**响应体是合法 JSON、`outbounds` 为数组时才认为本次响应可用；截断的响应、错误对象、半截数据一律按"本轮无数据"处理，避免"非空就当可用"；
- 结构与标签同样交叉校验：`outbounds` 为空、数组长度与 tag 数量不一致（有出站缺 tag）、某条出站取不出 tag，都按"响应不可用"处理并跳过本轮 —— 不做静默跳过，否则错位的数据会被报上去。例外是数组元素本身为 `null`：`jsonfilter` 无法把"元素是 null"和"下标越界"区分开，两个后端统一按"该元素不存在"处理；
- 只认 `argv[0]` 的 basename 以 `shadowquic` 开头的进程：`pgrep -f` 会把命令行里带 "shadowquic" 的无关进程（编辑器、`tail`）一起命中，"没有 `restful-api` 段就退出"是致命判定，不能被这类进程触发；
- API 请求带 `--noproxy '*'`：本机管理接口必须直连，否则环境里配了 `http_proxy` 时请求（连同 Bearer secret）会被送进代理；
- 出站的 `sample_age_ms` 缺失或非数字时**整条出站跳过**，不按 0 处理（否则过期采样会被当成最新数据反复上报）；过期判断用 `awk` 比较而不是 shell 的 `test` —— 超出整数范围的年龄会让 `test` 报错，而 `if` 里"报错"等于"不过期"；
- 计数器、`rtt`、`mtu` 逐字段校验，任一字段不可用就跳过该方向：整数字段拒绝前导 0（`printf %d` 会按八进制解析）与超长数字（`lost`/`sent`/`sample_age_ms` 限制在 18 位内、`mtu` 限定 `0..65535`），`rtt` 接受 JSON 科学计数法（`jq` 会印成 `1E-7`）但限定在 `0..10^7 ms`（约 2.7 小时）。位数上限是"拒绝不可信的离谱值"：`shadowquic` 侧是 u64（最多 20 位），真实计数远到不了 18 位，而计数到 double 溢出量级（309 位以上）时 `lost/(sent+1)` 会算出 `-nan` 并被 `printf` 原样拼进报文、得到非法 JSON；算出来的 `loss_rate` 若不是纯十进制数也不发；
- probe 端点的 tag 直接拼在 URL 路径里，只有 `[A-Za-z0-9._~-]` 的 tag 会被 probe（其它字符不再尝试，避免 URL 语义破坏请求），但不影响该出站的采样上报；
- `bind-addr` 只接受 `主机:端口` 且主机字符集限定为字母数字与 `.` `_` `-`（IPv6 方括号内为十六进制/冒号/点）、端口最多 5 位：这个值会被直接拼进 URL，放行 `/` `?` `#` `@` 等于让配置文件决定请求打到哪个端点；
- 配置文件参数是相对路径时（procd 里常见的 `-c tproxy_cn.yaml`），按 `/proc/<PID>/cwd/` 解析，不依赖上报脚本自己的工作目录；
- `restful-api` 段的 `secret` 支持双/单引号与行尾注释，引号内的 `#` 不会被当成注释（`secret: "abc#123"` 与 `secret: "a\" #b"` 都按字面处理）；只解析单行标量，双引号内只解码 `\\` `\"` `\/` `\n` `\t` `\r`，且解码后含控制字符的 secret 一律拒绝（会破坏 Authorization 头）。secret 的首尾空白按原样保留（`secret: " abc "` 就是带空格的 `abc`）。超出这个子集的写法一律判为"这一段不可解析"并**报错退出**，而不是发一个已知不等价的凭据：块标量（`secret: |`、`secret: >-`，按去引号前的形态判断，所以 `secret: "|"` 仍是合法的一字符 secret）和 `\uXXXX` 这类转义都属此类；
- API 响应与发送失败计数放在 `mktemp -d` 建的 0700 私有目录里，退出时整目录删除 —— 避免在可写的 `/tmp` 里用可预测文件名重定向（本地符号链接攻击面）；
- "连续发送失败"的计数是**近似值**：计数用"追加一个字节、读文件大小"实现，不会因为读-改-写而丢整次更新，但成功清零与失败写入可能交错，某次阈值告警可能被延迟或漏掉。它只用来避免静默失败，不承担精确语义。
- 周期等待用「后台 `sleep` + `wait`」而不是直接 `sleep`：直接 `sleep` 时收到 TERM 要等这一轮睡完（最长一个周期）才会被处理，procd 的 `term_timeout` 一到就 SIGKILL，收尾清理（删私有目录）就跑不掉了。

取数是按字段逐个调用后端的（一条出站一轮约 10 次），换来的是"字段缺失就跳过、绝不猜值"的逐字段校验。代价实测可忽略：aarch64 路由器上一次 `jsonfilter` 约 3ms，两出站满轮约 0.07 秒，对 30 秒周期不足 0.3%。

可调环境变量（写在 `/etc/init.d/xtp-stats-reporter` 的 `procd_set_param env` 里）：

| 变量 | 默认 | 说明 |
|------|------|------|
| `REFRESH_INTERVAL` | `30` | 取数 / 喂流量周期（秒） |
| `REFRESH_URL` | `http://cp.cloudflare.com/generate_204` | probe 目标，仅支持 `http://`，且需 2xx |
| `API_TIMEOUT` | `5` | 单个 API 请求超时（秒） |
| `PROBE_TIMEOUT_MS` | `3000` | probe 超时（毫秒） |
| `MAX_SAMPLE_AGE_MS` | `120000` | 采样年龄超过该值不再上报，避免隧道空闲时反复推过期数据 |

> [!NOTE]
> API 返回的 `sq_conn_stats` 只在**连接已建立且数据面刷新过采样**后才有值（ShadowQUIC 的 `print_stats` 在发起代理请求时触发、10 秒节流）。所以脚本每轮都会 probe 一次喂流量；若 probe 目标不可达且链路上本来没有流量，会因采样过期而不上报，评分随之按 `quic_stale_secs` 衰减。

### 5.2 安装、依赖与上报格式

安装：

```sh
cp contrib/etc/init.d/xtp-stats-reporter /etc/init.d/
cp contrib/usr/libexec/xtp-rs/stats_reporter.sh /usr/libexec/xtp-rs/
chmod +x /etc/init.d/xtp-stats-reporter /usr/libexec/xtp-rs/stats_reporter.sh

/etc/init.d/xtp-stats-reporter enable
/etc/init.d/xtp-stats-reporter start
```

依赖（缺任何一个都会启动即报错退出，错误写 syslog）：`socat`（`opkg install socat`）、`curl`（`opkg install curl`，轮询 API 与喂流量 probe 需要 —— OpenWrt 默认不带 curl，漏装会让 daemon 启动即退出）、`jq` 或 `jsonfilter`（OpenWrt 自带 libubox 的 `jsonfilter`，解析 API 响应）、`pgrep` / `awk`（busybox 自带）。不再依赖 `logread`。

脚本的纯函数（`restful-api` 配置解析、JSON 取数、报文构造）有单测，本机与路由器都能跑，装了哪个 JSON 后端就测哪个：

```sh
sh contrib/tests/stats-reporter-test.sh
```

上报 JSON 格式：

```json
{"upstream_id": "vultr_p20808", "peer": "1234", "rtt_ms": 152.300, "loss_rate": 0.3700, "mtu": 1280, "link": "downlink"}
```

| 字段 | 说明 |
|------|------|
| `upstream_id` | `<配置文件名>_<出站 tag>`：配置文件名跨进程去重，出站 tag 区分同进程内的多条隧道；需与 xtp-rs 侧该 upstream 的 `id` 完全一致 |
| `peer` | ShadowQUIC 进程 PID |
| `rtt_ms` | 链路 RTT（毫秒） |
| `loss_rate` | 丢包率（小数，0.37 = 37%） |
| `mtu` | 链路 MTU |
| `link` | 方向：`uplink` / `downlink` |

### 5.3 upstream_id 推导规则

`upstream_id` 推导规则：读取 `/proc/PID/cmdline`，取 `-c` / `-c=` / `--config` / `--config=` 参数对应配置文件的 basename 去扩展名作为前缀；再从日志 span 前缀 `inbound{tag=...}:outbound{tag=...}:` 取出 `outbound{tag=...}` 的 tag；拼成 `<配置名>_<tag>`。REST 模式没有日志 span，tag 直接取 API 返回的出站 tag，拼接规则相同。例如：

| 启动命令 | 日志 span 前缀 | `upstream_id` |
|----------|----------------|---------------|
| `shadowquic -c /etc/shadowquic/vultr.yaml`（outbound tag `p20808`） | `inbound{tag=20808}:outbound{tag=p20808}:` | `vultr_p20808` |
| `shadowquic -c /etc/shadowquic/vultr.yaml`（outbound tag `p20809`） | `inbound{tag=20809}:outbound{tag=p20809}:` | `vultr_p20809` |
| `shadowquic -c /etc/shadowquic/other.yaml`（outbound tag `p20808`） | `inbound{tag=...}:outbound{tag=p20808}:` | `other_p20808` |
| 找不到 `-c` 参数 / cmdline 不可读 / 日志无 `outbound{tag=...}` | — | 跳过该次上报（仅 debug 日志记录） |

xtp-rs 侧需把 upstream 的 `id` 配成完全一致的值。例如配置名 `vultr`、outbound tag `p20808`：

```toml
[[upstream]]
id = "vultr_p20808"
addr = "127.0.0.1:20808"
```

> [!NOTE]
> - `upstream_id` 用**配置文件名做前缀**是为跨进程去重：不同 shadowquic 进程可能复用同一出站 tag（旧式单端点 `outbound:` 写法 tag 甚至默认为 `outbound`），只取 tag 会撞在一起；
> - 出站 tag 区分同一进程内的多条隧道：一个 inbound 经路由（如 Lua `router`）可走多个 outbound，各出站会分别以自己的 tag 上报；
> - `upstream_id`（`<配置名>_<出站 tag>`）与 xtp-rs 的 upstream `id` 为精确相等匹配，改动 ShadowQUIC 配置里的 tag / 配置文件名后须同步修改 xtp-rs 侧 id；
> - 取数只走 RESTful API，不读 syslog：ShadowQUIC 配置里没有 `restful-api:` 段时 daemon 直接报错退出，不会退回日志解析；
> - 不使用 ShadowQUIC 时无需部署；xtp-rs 的 TCP 吞吐评分（基于 `TCP_INFO`）不依赖任何外部组件。

---

## 六、日志与排障

```sh
xtp-rs -T -c /etc/xtp-rs/config.toml    # 启动前自检 + 打印生效配置
logread -f | grep xtp-rs                 # 实时日志（procd 无 journalctl）
```

`log_level = "debug"` + `/etc/init.d/xtp-rs reload` 后，日志里能看到每条连接的客户端 / 目标、嗅探到的域名、命中的规则、被选中的组与上游、实时评分。

---

## 七、通用 Linux 与 OpenWrt 对照

| 用途 | 通用 Linux（[部署.md](./部署.md)） | OpenWrt（本文） |
|------|-----------------------------------|------------------|
| 提权 | `sudo` | root 终端（默认） |
| 包管理 | `apt` / `pacman` 等 | `opkg` |
| 环境参数 | 环境变量（`XTP_*`） | UCI `/etc/config/xtp-rs` + 环境变量回退 |
| 服务管理 | `systemctl` | `/etc/init.d/xtp-rs`（procd） |
| 沙箱 / 权限 | systemd `DynamicUser` + capabilities | ujail + capabilities |
| 日志 | `journalctl -u xtp-rs` | `logread` |
| 规则应用 | `setup-xtp-rs.sh`（systemd `ExecStartPost`） | `setup-xtp-rs.sh`（init.d `start_service`） |
