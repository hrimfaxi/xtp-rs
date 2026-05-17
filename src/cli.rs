use anyhow::{Result, anyhow};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

use crate::upstream::{Upstream, UpstreamSet};

#[derive(Parser)]
#[command(
    name = "xtp-rs",
    about = "tproxy / port forward -> SOCKS5, with IP country-based direct switch"
)]
pub struct Cli {
    /// 配置文件路径
    #[arg(short = 'c', long, default_value = "xtp-rs.toml")]
    pub config: String,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum PortForwardProto {
    /// 转发 TCP
    Tcp,
    /// 转发 UDP
    Udp,
    /// 同时转发 TCP 和 UDP
    Both,
}

#[derive(Deserialize, Clone)]
pub struct PortForward {
    /// 规则名称，仅用于日志输出。
    pub name: Option<String>,

    /// 本地监听地址。
    ///
    /// 示例：`"0.0.0.0:5353"`、`"[::]:5353"`。
    pub bind: String,

    /// 远端目标地址。
    ///
    /// 当前实现要求为可直接解析的 `SocketAddr`，
    /// 即 `IP:PORT` 形式，而不是域名。
    pub remote: String,

    /// 转发协议类型：`tcp` / `udp` / `both`。
    pub network: PortForwardProto,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamConfig {
    pub id: String,
    pub addr: SocketAddr,
}

#[derive(Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_listen")]
    /// 监听地址。
    ///
    /// 用于 TPROXY TCP/UDP 的监听端口，例如 `"[::]:10810"`。
    /// 若为 IPv6 unspecified（如 `[::]:10810`），通常会同时创建 IPv4 / IPv6 监听。
    pub listen: String,

    #[serde(default = "default_udp")]
    /// 是否启用 UDP 功能。
    ///
    /// - `true`：创建 TPROXY UDP socket，并启用 UDP 转发/代理相关逻辑
    /// - `false`：仅启用 TCP
    pub udp: bool,

    #[serde(default)]
    /// SOCKS5 用户名。
    ///
    /// 仅当同时配置了 `socks5_password` 时才会启用用户名/密码认证。
    pub socks5_user: Option<String>,

    #[serde(default)]
    /// SOCKS5 密码。
    ///
    /// 仅当同时配置了 `socks5_user` 时才会启用用户名/密码认证。
    pub socks5_password: Option<String>,

    #[serde(default = "default_fwmark")]
    /// 直连 / SOCKS5 出站 socket 使用的 fwmark。
    ///
    /// 用于配合策略路由、TPROXY 回包等网络规则。
    pub fwmark: u32,

    /// MaxMind GeoIP2 Country MMDB 文件路径。
    ///
    /// - `None` 或空字符串：禁用国家判定
    /// - 非空：启动时加载 MMDB，用于 `direct_countries` 判断
    pub mmdb_path: Option<String>,

    #[serde(default = "default_udp_session_timeout_secs")]
    /// UDP 会话空闲超时时间，单位秒。
    ///
    /// 超时后会清理：
    /// - UDP 会话状态
    /// - 用于伪造源地址回包的 fake UDP socket
    pub udp_session_timeout_secs: u64,

    #[serde(default = "default_splice")]
    /// TCP 转发时是否优先使用 splice/zero-copy。
    ///
    /// - `true`：优先调用 `tokio_splice::zero_copy_bidirectional`
    /// - `false`：回退到 `tokio::io::copy_bidirectional`
    pub splice: bool,

    #[serde(default = "default_sniff_tls_sni")]
    /// 是否对“非直连 TCP 连接”启用 TLS ClientHello SNI sniff。
    ///
    /// 若 sniff 成功，则当该连接走 SOCKS5 时，可按域名发起 CONNECT，
    /// 而不是按原始目标 IP 发起 CONNECT。
    ///
    /// 仅对 TCP 生效；对 UDP/QUIC/HTTP3 不生效。
    pub sniff_tls_sni: bool,

    #[serde(default = "default_sniff_http_host")]
    /// 是否对“非直连 TCP 连接”启用 HTTP/1.x Host 头 sniff。
    ///
    /// 通常在 TLS SNI sniff 未命中时，作为补充手段尝试从 HTTP 请求头中提取域名。
    ///
    /// 仅对明文 HTTP/1.0 / HTTP/1.1 生效；
    /// 不适用于 HTTPS、HTTP/2 帧层、HTTP/3/QUIC。
    pub sniff_http_host: bool,

    #[serde(default = "default_sniff_quic_sni")]
    /// 是否对 UDP/QUIC Initial Packet 启用 TLS ClientHello SNI sniff。
    ///
    /// 仅被动解析 QUIC Initial，不参与握手、不生成响应。
    /// 默认关闭，避免在路由器/嵌入式平台产生额外 CPU 开销。
    pub sniff_quic_sni: bool,

    #[serde(default = "default_tcp_peek_buffer_size")]
    /// TCP 首包 sniff 使用的全局 peek 缓冲区上限。
    ///
    /// 这个值是整个 TCP sniff 的“全局硬上限”：
    /// - 限制一次 peek 最多读取的字节数
    /// - 同时约束 TLS / HTTP sniff 的实际最大探测长度
    ///
    /// 因此即使 `tls_sniff_max_len` 或 `http_sniff_max_len` 配得更大，
    /// 实际仍不会超过 `tcp_peek_buffer_size`。
    ///
    /// 可理解为：
    /// - TLS 实际最大探测长度 = `min(tls_sniff_max_len, tcp_peek_buffer_size)`
    /// - HTTP 实际最大探测长度 = `min(http_sniff_max_len, tcp_peek_buffer_size)`
    pub tcp_peek_buffer_size: usize,

    #[serde(default = "default_tls_sniff_peek_len")]
    /// TLS sniff 的首次 peek 目标长度。
    ///
    /// 初次仅尝试读取这么多前缀数据；若不足以解析完整 ClientHello，
    /// 会在后续重试中逐步扩大。
    ///
    /// 该值通常应小于等于 `tls_sniff_max_len`。
    pub tls_sniff_peek_len: usize,

    #[serde(default = "default_tls_sniff_max_len")]
    /// TLS sniff 的协议级最大探测长度。
    ///
    /// 用于限制为解析 TLS ClientHello SNI 最多愿意探测多少字节。
    /// 这不是最终绝对上限；最终仍受 `tcp_peek_buffer_size` 约束。
    ///
    /// 实际生效值可理解为：
    /// `min(tls_sniff_max_len, tcp_peek_buffer_size)`
    ///
    /// 如果该值小于 `tcp_peek_buffer_size`，TLS sniff 会更早停止。
    pub tls_sniff_max_len: usize,

    #[serde(default = "default_tls_sniff_max_retries")]
    /// TLS sniff 在“前缀不足”时允许的最大重试次数。
    ///
    /// 每次重试通常会：
    /// - 扩大 peek 长度
    /// - 等待更多首包数据到达
    ///
    /// 重试次数越大，对分片 ClientHello 越宽容，但也会增加等待成本。
    pub tls_sniff_max_retries: usize,

    #[serde(default = "default_tls_sniff_wait_more_ms")]
    /// TLS sniff 每轮等待更多 peek 数据增长的最长时间，单位毫秒。
    ///
    /// 若在这段时间内没有拿到更多前缀数据，则停止 TLS sniff。
    pub tls_sniff_wait_more_ms: u64,

    #[serde(default = "default_tls_sniff_timeout_ms")]
    /// 单次 TLS sniff 的总超时时间，单位毫秒。
    ///
    /// 达到该超时后，无论是否还有潜在重试机会，都会放弃 TLS sniff。
    pub tls_sniff_timeout_ms: u64,

    #[serde(default = "default_http_sniff_peek_len")]
    /// HTTP sniff 的首次 peek 目标长度。
    ///
    /// 初次尝试读取请求行和部分请求头；若不足以拿到完整 HTTP 头，
    /// 会在后续重试中逐步扩大。
    ///
    /// 该值通常应小于等于 `http_sniff_max_len`。
    pub http_sniff_peek_len: usize,

    #[serde(default = "default_http_sniff_max_len")]
    /// HTTP sniff 的协议级最大探测长度。
    ///
    /// 用于限制为解析 HTTP/1.x Host 头最多愿意探测多少字节。
    /// 这不是最终绝对上限；最终仍受 `tcp_peek_buffer_size` 约束。
    ///
    /// 实际生效值可理解为：
    /// `min(http_sniff_max_len, tcp_peek_buffer_size)`
    ///
    /// 如果请求头在该长度内仍未完整结束（例如尚未读到 `\r\n\r\n`），
    /// 则放弃 HTTP sniff。
    pub http_sniff_max_len: usize,

    #[serde(default = "default_http_sniff_max_retries")]
    /// HTTP sniff 在“前缀不足”时允许的最大重试次数。
    ///
    /// 适用于 HTTP 请求行 / 请求头被拆包、第一次 peek 读不全的情况。
    pub http_sniff_max_retries: usize,

    #[serde(default = "default_http_sniff_wait_more_ms")]
    /// HTTP sniff 每轮等待更多 peek 数据增长的最长时间，单位毫秒。
    ///
    /// 若在这段时间内没有拿到更多请求头数据，则停止 HTTP sniff。
    pub http_sniff_wait_more_ms: u64,

    #[serde(default = "default_http_sniff_timeout_ms")]
    /// 单次 HTTP sniff 的总超时时间，单位毫秒。
    ///
    /// 达到该超时后，无论是否还有潜在重试机会，都会放弃 HTTP sniff。
    pub http_sniff_timeout_ms: u64,

    /// 日志级别。
    ///
    /// 若未配置，则优先尝试读取环境变量；再回退到默认 `info`。
    /// 常见值如：`"error"`、`"warn"`、`"info"`、`"debug"`、`"trace"`。
    pub log_level: Option<String>,

    #[serde(default = "default_direct_countries")]
    /// 需要直连的国家/地区代码列表。
    ///
    /// 仅在配置了 `mmdb_path` 时生效。
    /// 使用 ISO 3166-1 alpha-2 代码，例如：`["CN"]`。
    pub direct_countries: Vec<String>,

    #[serde(default)]
    /// 强制直连的 IP / CIDR 列表。
    ///
    /// 优先级低于 `force_socks5_ips`，高于 MMDB 国家判定。
    /// 支持：
    /// - 单个 IP，例如 `1.2.3.4`
    /// - CIDR，例如 `10.0.0.0/8`
    pub force_direct_ips: Vec<String>,

    #[serde(default)]
    /// 强制走 SOCKS5 的 IP / CIDR 列表。
    ///
    /// 这是最高优先级规则：
    /// 一旦命中，即使该 IP 同时也匹配 `force_direct_ips` 或 `direct_countries`，
    /// 仍然强制走 SOCKS5。
    pub force_socks5_ips: Vec<String>,

    #[serde(default)]
    /// 额外的强制直连 IP / CIDR 文件路径。
    ///
    /// 文件按行读取；每行一个 IP 或 CIDR。
    /// 读取后会追加到 `force_direct_ips`。
    pub force_direct_ips_file: Option<String>,

    #[serde(default)]
    /// 额外的强制 SOCKS5 IP / CIDR 文件路径。
    ///
    /// 文件按行读取；每行一个 IP 或 CIDR。
    /// 读取后会追加到 `force_socks5_ips`。
    pub force_socks5_ips_file: Option<String>,

    #[serde(default)]
    /// 端口转发规则列表。
    ///
    /// 这些规则独立于 TPROXY 监听：
    /// - TCP port-forward 始终通过 SOCKS5 转发到 `remote`
    /// - UDP port-forward 也会强制通过 SOCKS5 UDP ASSOCIATE 转发到 `remote`
    pub port_forward: Vec<PortForward>,

    #[serde(default = "default_direct_local_ip")]
    /// 是否将本地/回环/链路本地 IP 强制视为直连。
    ///
    /// - `true`（默认）：loopback、link-local、unspecified 等本地 IP 直接出站
    /// - `false`：本地 IP 也参与后续路由判定（MMDB / force_direct / force_socks5）
    pub direct_local_ip: bool,

    // 新字段：多 upstream
    pub upstream: Vec<UpstreamConfig>,

    #[serde(default = "default_disable_upstream_score")]
    /// 禁用 upstream 动态评分。
    /// - `false`（默认）：启用 TCP_INFO 监控 + 吞吐量评分 + 加权随机
    /// - `true`：完全随机选择 upstream，不做任何性能监控和分数更新
    pub disable_upstream_score: bool,

    #[serde(default = "default_upstream_switch_tolerance")]
    /// upstream 粘性切换容忍度，单位：分。
    ///
    /// - `0`（默认）：不启用粘性，每次 pick 都重新做平方加权随机
    /// - `>0`：仅当新 upstream 分数比当前高超过此值时才允许切换
    ///   例如 `100` 表示差距必须 >100 分才切，避免连接在 upstream 间乱跳
    pub upstream_switch_tolerance: u32,

    #[serde(default = "default_health_check_interval_secs")]
    /// 主动健康检查间隔，单位秒。
    ///
    /// - `0`（默认）：禁用主动探活，完全依赖 TCP_INFO 聚合和 shadowquic 探针
    /// - `>0`：定期通过 SOCKS5 对 `health_check_url` 发起 HTTP HEAD 探测
    pub health_check_interval_secs: u64,

    #[serde(default = "default_health_check_timeout_secs")]
    /// 单次健康检查超时时间，单位秒。
    pub health_check_timeout_secs: u64,

    #[serde(default = "default_health_check_fail_threshold")]
    /// 连续失败多少次后才判定 upstream 死亡并 penalize。
    pub health_check_fail_threshold: u32,

    #[serde(default = "default_health_check_url")]
    /// 健康检查的目标 URL，用于 HTTP HEAD 探测。
    ///
    /// 默认使用 Cloudflare 的探测端点。
    pub health_check_url: String,
}

pub fn default_listen() -> String {
    "[::]:10810".to_string()
}

pub fn default_udp() -> bool {
    true
}

pub fn default_direct_countries() -> Vec<String> {
    vec!["CN".to_string()]
}

pub fn default_fwmark() -> u32 {
    2
}

pub fn default_udp_session_timeout_secs() -> u64 {
    60
}

pub fn default_splice() -> bool {
    false
}

pub fn default_sniff_tls_sni() -> bool {
    false
}

pub fn default_sniff_http_host() -> bool {
    false
}

pub fn default_sniff_quic_sni() -> bool {
    false
}

pub fn default_tcp_peek_buffer_size() -> usize {
    32 * 1024
}

pub fn default_tls_sniff_peek_len() -> usize {
    2048
}

pub fn default_tls_sniff_max_len() -> usize {
    32 * 1024
}

pub fn default_tls_sniff_max_retries() -> usize {
    5
}

pub fn default_tls_sniff_wait_more_ms() -> u64 {
    100
}

pub fn default_tls_sniff_timeout_ms() -> u64 {
    1000
}

pub fn default_http_sniff_peek_len() -> usize {
    512
}

pub fn default_http_sniff_max_len() -> usize {
    16 * 1024
}

pub fn default_http_sniff_max_retries() -> usize {
    5
}

pub fn default_http_sniff_wait_more_ms() -> u64 {
    100
}

pub fn default_http_sniff_timeout_ms() -> u64 {
    1000
}

pub fn default_direct_local_ip() -> bool {
    true
}

pub fn default_disable_upstream_score() -> bool {
    false
}

pub fn default_upstream_switch_tolerance() -> u32 {
    0
}

pub fn default_health_check_interval_secs() -> u64 {
    0
}

pub fn default_health_check_timeout_secs() -> u64 {
    5
}

pub fn default_health_check_fail_threshold() -> u32 {
    2
}

pub fn default_health_check_url() -> String {
    "cp.cloudflare.com".to_string()
}

pub fn parse_listen_addr(listen: &str) -> Result<(IpAddr, u16)> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| anyhow!("invalid listen address '{listen}': {e}"))?;
    Ok((addr.ip(), addr.port()))
}

impl Config {
    pub fn build_upstream_set(&self) -> anyhow::Result<UpstreamSet> {
        if self.upstream.is_empty() {
            anyhow::bail!("upstream array must not be empty");
        }

        let mut ids = std::collections::HashSet::new();

        for u in &self.upstream {
            let trimmed = u.id.trim();
            if trimmed.is_empty() {
                anyhow::bail!("upstream id must not be empty");
            }
            if !ids.insert(trimmed) {
                anyhow::bail!("duplicate upstream id: {}", trimmed);
            }
        }

        let items = self
            .upstream
            .iter()
            .map(|u| Upstream::new(u.id.trim().to_string(), u.addr))
            .collect();

        Ok(UpstreamSet::new(items, self.upstream_switch_tolerance))
    }
}
