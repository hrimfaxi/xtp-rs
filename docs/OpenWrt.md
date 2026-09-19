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
| `tcp_ports` | `80 443` | 待代理 TCP 目的端口（空白 / 逗号 / 分号分隔，1-65535） |
| `udp_ports` | `53 443` | 待代理 UDP 目的端口 |
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

列表文件位于 `/etc/xtp-rs/chnroute.nft`（IPv4）与 `/etc/xtp-rs/chnroute6.nft`（IPv6）；两个地址族独立，任一缺失只跳过对应规则。

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

`xtp-stats-reporter` 是 **ShadowQUIC 专用**的性能上报 daemon：ShadowQUIC 把链路质量（RTT、丢包率、MTU）输出到 syslog，本 daemon 用 `logread` 实时捕获、解析后，通过本地 Unix 数据报 socket（`/tmp/xtp-rs-report.sock`）以 JSON 上报给 xtp-rs，供上游动态评分使用。无需修改 ShadowQUIC。机制详见 [工作原理](./工作原理.md#五上游动态评分机制)。

安装：

```sh
cp contrib/etc/init.d/xtp-stats-reporter /etc/init.d/
cp contrib/usr/libexec/xtp-rs/stats_reporter.sh /usr/libexec/xtp-rs/
chmod +x /etc/init.d/xtp-stats-reporter /usr/libexec/xtp-rs/stats_reporter.sh

/etc/init.d/xtp-stats-reporter enable
/etc/init.d/xtp-stats-reporter start
```

依赖：`socat`（`opkg install socat`）、`logread`（OpenWrt 自带）。

上报 JSON 格式：

```json
{"upstream_id": "bbr_tunnel", "peer": "1234", "rtt_ms": 152.300, "loss_rate": 0.3700, "mtu": 1280, "link": "downlink"}
```

| 字段 | 说明 |
|------|------|
| `upstream_id` | 由 ShadowQUIC `-c` / `--config` 参数推导的实例名（配置文件名去扩展名；多实例追加 `_N` 后缀） |
| `peer` | ShadowQUIC 进程 PID |
| `rtt_ms` | 链路 RTT（毫秒） |
| `loss_rate` | 丢包率（小数，0.37 = 37%） |
| `mtu` | 链路 MTU |
| `link` | 方向：`uplink` / `downlink` |

`upstream_id` 推导规则：读取 `/proc/PID/cmdline`，找到 `-c` / `-c=` / `--config` / `--config=` 参数对应路径，取 basename 去扩展名；若日志行带多实例前缀 `instance{n=N}:`，追加 `_N` 后缀。例如：

| 启动命令 | 日志 instance 字段 | `upstream_id` |
|----------|--------------------|---------------|
| `shadowquic -c /etc/shadowquic/bbr.yaml` | 无 | `bbr` |
| `shadowquic -c /etc/shadowquic/combine.yaml` | `instance{n=0}:` | `combine_0` |
| `shadowquic -c /etc/shadowquic/combine.yaml` | `instance{n=1}:` | `combine_1` |
| 找不到 `-c` 参数 / cmdline 不可读 | — | 跳过该次上报（仅 debug 日志记录） |

xtp-rs 侧需把 upstream 的 `id` 配成一致的值：单实例对应 `id = "bbr"`；多实例 `combine.yaml` 的第 N 个实例对应 `id = "combine_N"`。

> [!NOTE]
> - 单实例（旧版 fork，或新版只配一个实例）日志无 `instance{n=X}` 字段，`upstream_id` 保持配置名本身，与旧版部署兼容；
> - 实例序号 N 以 ShadowQUIC 实际日志为准，增删实例或调整顺序都会重排 N，需同步修改 xtp-rs 侧 id；
> - 仅解析匹配 `shadowquic[PID]:` 前缀 + `uplink stats` / `downlink stats` 关键字的日志，其他进程日志忽略；
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
