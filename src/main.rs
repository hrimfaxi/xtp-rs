use aes::Aes128;
use aes::cipher::{Block, BlockCipherEncrypt, KeyInit as AesKeyInit};
use aligned_vec::{AVec, RuntimeAlign};
use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use ipnet::IpNet;
use iptrie::{IpPrefix, Ipv4Prefix, Ipv4RTrieSet, Ipv6Prefix, Ipv6RTrieSet};
use maxminddb::Reader;
use maxminddb::geoip2::Country;
use nix::errno::Errno;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
use nix::sys::socket::{setsockopt, sockopt};
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::Interest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, Notify, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use aes_gcm::aead::{Aead, KeyInit as AeadKeyInit, Payload as AeadPayload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

const UDP_RECV_BUF_SIZE: usize = 65_536;
const UDP_BUF_ALIGN: usize = 4096;

#[derive(Parser)]
#[command(
    name = "xtp-rs",
    about = "tproxy / port forward -> SOCKS5, with IP country-based direct switch"
)]
struct Cli {
    /// 配置文件路径
    #[arg(short = 'c', long, default_value = "xtp-rs.toml")]
    config: String,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum PortForwardProto {
    /// 转发 TCP
    Tcp,
    /// 转发 UDP
    Udp,
    /// 同时转发 TCP 和 UDP
    Both,
}

#[derive(Deserialize, Clone)]
struct PortForward {
    /// 规则名称，仅用于日志输出。
    name: Option<String>,

    /// 本地监听地址。
    ///
    /// 示例：`"0.0.0.0:5353"`、`"[::]:5353"`。
    bind: String,

    /// 远端目标地址。
    ///
    /// 当前实现要求为可直接解析的 `SocketAddr`，
    /// 即 `IP:PORT` 形式，而不是域名。
    remote: String,

    /// 转发协议类型：`tcp` / `udp` / `both`。
    network: PortForwardProto,
}

#[derive(Deserialize, Clone)]
struct Config {
    #[serde(default = "default_listen")]
    /// 监听地址。
    ///
    /// 用于 TPROXY TCP/UDP 的监听端口，例如 `"[::]:10810"`。
    /// 若为 IPv6 unspecified（如 `[::]:10810`），通常会同时创建 IPv4 / IPv6 监听。
    listen: String,

    #[serde(default = "default_udp")]
    /// 是否启用 UDP 功能。
    ///
    /// - `true`：创建 TPROXY UDP socket，并启用 UDP 转发/代理相关逻辑
    /// - `false`：仅启用 TCP
    udp: bool,

    #[serde(default = "default_socks5_addr")]
    /// 上游 SOCKS5 代理地址。
    ///
    /// 仅用于“非直连”流量，或 `port_forward` 中强制走 SOCKS5 的场景。
    /// 格式示例：`"127.0.0.1:20808"`。
    socks5_addr: String,

    #[serde(default)]
    /// SOCKS5 用户名。
    ///
    /// 仅当同时配置了 `socks5_password` 时才会启用用户名/密码认证。
    socks5_user: Option<String>,

    #[serde(default)]
    /// SOCKS5 密码。
    ///
    /// 仅当同时配置了 `socks5_user` 时才会启用用户名/密码认证。
    socks5_password: Option<String>,

    #[serde(default = "default_fwmark")]
    /// 直连 / SOCKS5 出站 socket 使用的 fwmark。
    ///
    /// 用于配合策略路由、TPROXY 回包等网络规则。
    fwmark: u32,

    /// MaxMind GeoIP2 Country MMDB 文件路径。
    ///
    /// - `None` 或空字符串：禁用国家判定
    /// - 非空：启动时加载 MMDB，用于 `direct_countries` 判断
    mmdb_path: Option<String>,

    #[serde(default = "default_udp_session_timeout_secs")]
    /// UDP 会话空闲超时时间，单位秒。
    ///
    /// 超时后会清理：
    /// - UDP 会话状态
    /// - 用于伪造源地址回包的 fake UDP socket
    udp_session_timeout_secs: u64,

    #[serde(default = "default_splice")]
    /// TCP 转发时是否优先使用 splice/zero-copy。
    ///
    /// - `true`：优先调用 `tokio_splice::zero_copy_bidirectional`
    /// - `false`：回退到 `tokio::io::copy_bidirectional`
    splice: bool,

    #[serde(default = "default_sniff_tls_sni")]
    /// 是否对“非直连 TCP 连接”启用 TLS ClientHello SNI sniff。
    ///
    /// 若 sniff 成功，则当该连接走 SOCKS5 时，可按域名发起 CONNECT，
    /// 而不是按原始目标 IP 发起 CONNECT。
    ///
    /// 仅对 TCP 生效；对 UDP/QUIC/HTTP3 不生效。
    sniff_tls_sni: bool,

    #[serde(default = "default_sniff_http_host")]
    /// 是否对“非直连 TCP 连接”启用 HTTP/1.x Host 头 sniff。
    ///
    /// 通常在 TLS SNI sniff 未命中时，作为补充手段尝试从 HTTP 请求头中提取域名。
    ///
    /// 仅对明文 HTTP/1.0 / HTTP/1.1 生效；
    /// 不适用于 HTTPS、HTTP/2 帧层、HTTP/3/QUIC。
    sniff_http_host: bool,

    #[serde(default = "default_sniff_quic_sni")]
    /// 是否对 UDP/QUIC Initial Packet 启用 TLS ClientHello SNI sniff。
    ///
    /// 仅被动解析 QUIC Initial，不参与握手、不生成响应。
    /// 默认关闭，避免在路由器/嵌入式平台产生额外 CPU 开销。
    sniff_quic_sni: bool,

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
    tcp_peek_buffer_size: usize,

    #[serde(default = "default_tls_sniff_peek_len")]
    /// TLS sniff 的首次 peek 目标长度。
    ///
    /// 初次仅尝试读取这么多前缀数据；若不足以解析完整 ClientHello，
    /// 会在后续重试中逐步扩大。
    ///
    /// 该值通常应小于等于 `tls_sniff_max_len`。
    tls_sniff_peek_len: usize,

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
    tls_sniff_max_len: usize,

    #[serde(default = "default_tls_sniff_max_retries")]
    /// TLS sniff 在“前缀不足”时允许的最大重试次数。
    ///
    /// 每次重试通常会：
    /// - 扩大 peek 长度
    /// - 等待更多首包数据到达
    ///
    /// 重试次数越大，对分片 ClientHello 越宽容，但也会增加等待成本。
    tls_sniff_max_retries: usize,

    #[serde(default = "default_tls_sniff_wait_more_ms")]
    /// TLS sniff 每轮等待更多 peek 数据增长的最长时间，单位毫秒。
    ///
    /// 若在这段时间内没有拿到更多前缀数据，则停止 TLS sniff。
    tls_sniff_wait_more_ms: u64,

    #[serde(default = "default_tls_sniff_timeout_ms")]
    /// 单次 TLS sniff 的总超时时间，单位毫秒。
    ///
    /// 达到该超时后，无论是否还有潜在重试机会，都会放弃 TLS sniff。
    tls_sniff_timeout_ms: u64,

    #[serde(default = "default_http_sniff_peek_len")]
    /// HTTP sniff 的首次 peek 目标长度。
    ///
    /// 初次尝试读取请求行和部分请求头；若不足以拿到完整 HTTP 头，
    /// 会在后续重试中逐步扩大。
    ///
    /// 该值通常应小于等于 `http_sniff_max_len`。
    http_sniff_peek_len: usize,

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
    http_sniff_max_len: usize,

    #[serde(default = "default_http_sniff_max_retries")]
    /// HTTP sniff 在“前缀不足”时允许的最大重试次数。
    ///
    /// 适用于 HTTP 请求行 / 请求头被拆包、第一次 peek 读不全的情况。
    http_sniff_max_retries: usize,

    #[serde(default = "default_http_sniff_wait_more_ms")]
    /// HTTP sniff 每轮等待更多 peek 数据增长的最长时间，单位毫秒。
    ///
    /// 若在这段时间内没有拿到更多请求头数据，则停止 HTTP sniff。
    http_sniff_wait_more_ms: u64,

    #[serde(default = "default_http_sniff_timeout_ms")]
    /// 单次 HTTP sniff 的总超时时间，单位毫秒。
    ///
    /// 达到该超时后，无论是否还有潜在重试机会，都会放弃 HTTP sniff。
    http_sniff_timeout_ms: u64,

    /// 日志级别。
    ///
    /// 若未配置，则优先尝试读取环境变量；再回退到默认 `info`。
    /// 常见值如：`"error"`、`"warn"`、`"info"`、`"debug"`、`"trace"`。
    log_level: Option<String>,

    #[serde(default = "default_direct_countries")]
    /// 需要直连的国家/地区代码列表。
    ///
    /// 仅在配置了 `mmdb_path` 时生效。
    /// 使用 ISO 3166-1 alpha-2 代码，例如：`["CN"]`。
    direct_countries: Vec<String>,

    #[serde(default)]
    /// 强制直连的 IP / CIDR 列表。
    ///
    /// 优先级低于 `force_socks5_ips`，高于 MMDB 国家判定。
    /// 支持：
    /// - 单个 IP，例如 `1.2.3.4`
    /// - CIDR，例如 `10.0.0.0/8`
    force_direct_ips: Vec<String>,

    #[serde(default)]
    /// 强制走 SOCKS5 的 IP / CIDR 列表。
    ///
    /// 这是最高优先级规则：
    /// 一旦命中，即使该 IP 同时也匹配 `force_direct_ips` 或 `direct_countries`，
    /// 仍然强制走 SOCKS5。
    force_socks5_ips: Vec<String>,

    #[serde(default)]
    /// 额外的强制直连 IP / CIDR 文件路径。
    ///
    /// 文件按行读取；每行一个 IP 或 CIDR。
    /// 读取后会追加到 `force_direct_ips`。
    force_direct_ips_file: Option<String>,

    #[serde(default)]
    /// 额外的强制 SOCKS5 IP / CIDR 文件路径。
    ///
    /// 文件按行读取；每行一个 IP 或 CIDR。
    /// 读取后会追加到 `force_socks5_ips`。
    force_socks5_ips_file: Option<String>,

    #[serde(default)]
    /// 端口转发规则列表。
    ///
    /// 这些规则独立于 TPROXY 监听：
    /// - TCP port-forward 始终通过 SOCKS5 转发到 `remote`
    /// - UDP port-forward 也会强制通过 SOCKS5 UDP ASSOCIATE 转发到 `remote`
    port_forward: Vec<PortForward>,

    #[serde(default = "default_direct_local_ip")]
    /// 是否将本地/回环/链路本地 IP 强制视为直连。
    ///
    /// - `true`（默认）：loopback、link-local、unspecified 等本地 IP 直接出站
    /// - `false`：本地 IP 也参与后续路由判定（MMDB / force_direct / force_socks5）
    direct_local_ip: bool,
}

fn default_listen() -> String {
    "[::]:10810".to_string()
}

fn default_udp() -> bool {
    true
}

fn default_direct_countries() -> Vec<String> {
    vec!["CN".to_string()]
}

fn default_socks5_addr() -> String {
    "127.0.0.1:20808".to_string()
}

fn default_fwmark() -> u32 {
    2
}

fn default_udp_session_timeout_secs() -> u64 {
    60
}

fn default_splice() -> bool {
    false
}

fn default_sniff_tls_sni() -> bool {
    false
}

fn default_sniff_http_host() -> bool {
    false
}

fn default_sniff_quic_sni() -> bool {
    false
}

fn default_tcp_peek_buffer_size() -> usize {
    32 * 1024
}

fn default_tls_sniff_peek_len() -> usize {
    2048
}

fn default_tls_sniff_max_len() -> usize {
    32 * 1024
}

fn default_tls_sniff_max_retries() -> usize {
    5
}

fn default_tls_sniff_wait_more_ms() -> u64 {
    100
}

fn default_tls_sniff_timeout_ms() -> u64 {
    1000
}

fn default_http_sniff_peek_len() -> usize {
    512
}

fn default_http_sniff_max_len() -> usize {
    16 * 1024
}

fn default_http_sniff_max_retries() -> usize {
    5
}

fn default_http_sniff_wait_more_ms() -> u64 {
    100
}

fn default_http_sniff_timeout_ms() -> u64 {
    1000
}

fn default_direct_local_ip() -> bool {
    true
}

struct AppState {
    mmdb: Option<Arc<Reader<Vec<u8>>>>,
    config: Config,
    udp_runtime: Arc<UdpRuntime>,
    force_direct_v4: Ipv4RTrieSet,
    force_direct_v6: Ipv6RTrieSet,
    force_socks5_v4: Ipv4RTrieSet,
    force_socks5_v6: Ipv6RTrieSet,
    sniffers: Vec<Arc<dyn Sniffer>>,
    // UDP sniffer: QUIC Initial SNI.
    udp_sniffer: Option<Arc<UdpSniffer>>,
}

fn ipv4_trie_contains(trie: &Ipv4RTrieSet, ip: &Ipv4Addr) -> bool {
    trie.lookup(ip).len() != 0
}

fn ipv6_trie_contains(trie: &Ipv6RTrieSet, ip: &Ipv6Addr) -> bool {
    trie.lookup(ip).len() != 0
}

impl AppState {
    fn should_direct(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                // 先检查 SOCKS5 强制名单（优先级最高）
                if ipv4_trie_contains(&self.force_socks5_v4, &ipv4) {
                    return false;
                }
                if ipv4_trie_contains(&self.force_direct_v4, &ipv4) {
                    return true;
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6_trie_contains(&self.force_socks5_v6, &ipv6) {
                    return false;
                }
                if ipv6_trie_contains(&self.force_direct_v6, &ipv6) {
                    return true;
                }
            }
        }

        (self.config.direct_local_ip && is_must_direct_local_ip(ip))
            || self.is_direct_country_ip(ip)
    }

    fn is_direct_country_ip(&self, ip: IpAddr) -> bool {
        let mmdb = match self.mmdb.as_ref() {
            Some(reader) => reader,
            None => return false,
        };
        let lookup_result = match mmdb.lookup(ip) {
            Ok(r) => r,
            Err(_) => return false,
        };

        let country = match lookup_result.decode::<Country>() {
            Ok(Some(c)) => c,
            _ => return false,
        };

        country
            .country
            .iso_code
            .map(|code| {
                self.config
                    .direct_countries
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(code))
            })
            .unwrap_or(false)
    }

    fn socks5_credentials(&self) -> Option<(&str, &str)> {
        match (&self.config.socks5_user, &self.config.socks5_password) {
            (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum UdpSessionKind {
    Tproxy,
    PortForward { listen_addr: SocketAddr },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpSessionKey {
    kind: UdpSessionKind,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
}

#[derive(Clone)]
enum UdpReplyPath {
    Tproxy,
    PortForward { listen_sock: Arc<UdpSocket> },
}

#[derive(Debug, Clone, Copy)]
enum UdpRoutingMode {
    Auto,
    ForceSocks5,
}

#[derive(Clone)]
struct UdpSessionSpec {
    key: UdpSessionKey,
    routing: UdpRoutingMode,
    reply_path: UdpReplyPath,
    sniffed_host: Option<String>,
}

impl UdpSessionSpec {
    fn for_tproxy(client_addr: SocketAddr, orig_dst: SocketAddr) -> Self {
        Self {
            key: UdpSessionKey {
                kind: UdpSessionKind::Tproxy,
                client_addr,
                target_addr: orig_dst,
            },
            routing: UdpRoutingMode::Auto,
            reply_path: UdpReplyPath::Tproxy,
            sniffed_host: None,
        }
    }

    fn for_port_forward(
        listen_addr: SocketAddr,
        client_addr: SocketAddr,
        remote: SocketAddr,
        listen_sock: Arc<UdpSocket>,
    ) -> Self {
        Self {
            key: UdpSessionKey {
                kind: UdpSessionKind::PortForward { listen_addr },
                client_addr,
                target_addr: remote,
            },
            routing: UdpRoutingMode::ForceSocks5,
            reply_path: UdpReplyPath::PortForward { listen_sock },
            sniffed_host: None,
        }
    }
}

enum UdpSessionEntry {
    Creating(Arc<Notify>),
    Ready(Arc<UdpSession>),
}

struct UdpRuntime {
    sessions: Mutex<HashMap<UdpSessionKey, UdpSessionEntry>>,
    fake_udp: FakeUdpManager,
    timeout: Duration,
}

impl UdpRuntime {
    fn new(timeout: Duration) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            fake_udp: FakeUdpManager::new(),
            timeout,
        }
    }

    async fn get_or_create_udp_session(
        self: &Arc<Self>,
        state: Arc<AppState>,
        spec: UdpSessionSpec,
    ) -> Result<Arc<UdpSession>> {
        let key = spec.key;

        let creating_notify = loop {
            let mut sessions = self.sessions.lock().await;

            match sessions.get(&key) {
                Some(UdpSessionEntry::Ready(session)) => {
                    return Ok(session.clone());
                }
                Some(UdpSessionEntry::Creating(notify)) => {
                    let notify = notify.clone();
                    drop(sessions);

                    debug!(
                        "UDP session is being created, waiting: kind={:?}, client={}, target={}",
                        key.kind, key.client_addr, key.target_addr
                    );

                    notify.notified().await;
                    continue;
                }
                None => {
                    let notify = Arc::new(Notify::new());
                    sessions.insert(key, UdpSessionEntry::Creating(notify.clone()));
                    break notify;
                }
            }
        };

        let created = create_udp_session(state.clone(), spec.clone()).await;

        let mut sessions = self.sessions.lock().await;

        match created {
            Ok(session) => {
                sessions.insert(key, UdpSessionEntry::Ready(session.clone()));
                creating_notify.notify_waiters();

                info!(
                    "created UDP session: kind={:?}, client={}, target={}",
                    key.kind, key.client_addr, key.target_addr
                );

                Ok(session)
            }
            Err(e) => {
                sessions.remove(&key);
                creating_notify.notify_waiters();
                Err(e)
            }
        }
    }

    async fn cleanup_expired_sessions(&self) {
        let now = now_secs();
        let timeout_secs = self.timeout.as_secs();

        let snapshot: Vec<(UdpSessionKey, Arc<UdpSession>)> = {
            let sessions = self.sessions.lock().await;

            sessions
                .iter()
                .filter_map(|(key, entry)| match entry {
                    UdpSessionEntry::Ready(session) => Some((*key, session.clone())),
                    UdpSessionEntry::Creating(_) => None,
                })
                .collect()
        };

        let mut expired = Vec::new();

        for (key, session) in snapshot {
            let last_seen = session.last_seen_secs.load(Ordering::Relaxed);

            if now.saturating_sub(last_seen) >= timeout_secs {
                expired.push((key, session));
            }
        }

        if expired.is_empty() {
            return;
        }

        let mut sessions = self.sessions.lock().await;

        for (key, session) in expired {
            let should_remove = match sessions.get(&key) {
                Some(UdpSessionEntry::Ready(current)) => Arc::ptr_eq(current, &session),
                _ => false,
            };

            if should_remove {
                sessions.remove(&key);
                session.cancel.cancel();

                debug!(
                    "UDP session expired and cancelled: kind={:?}, client={}, target={}",
                    key.kind, key.client_addr, key.target_addr
                );
            }
        }
    }

    async fn get_ready_udp_session(&self, key: UdpSessionKey) -> Option<Arc<UdpSession>> {
        let sessions = self.sessions.lock().await;

        match sessions.get(&key) {
            Some(UdpSessionEntry::Ready(session)) => Some(session.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FakeUdpKey {
    src_addr: SocketAddr,
    fwmark: u32,
}

struct FakeUdpEntry {
    socket: Arc<UdpSocket>,
    last_used_secs: AtomicU64,
}

struct FakeUdpManager {
    sockets: Mutex<HashMap<FakeUdpKey, Arc<FakeUdpEntry>>>,
}

impl FakeUdpManager {
    fn new() -> Self {
        Self {
            sockets: Mutex::new(HashMap::new()),
        }
    }

    async fn get_or_create(&self, src_addr: SocketAddr, fwmark: u32) -> Result<Arc<UdpSocket>> {
        let key = FakeUdpKey { src_addr, fwmark };
        let now = now_secs();

        {
            let sockets = self.sockets.lock().await;

            if let Some(entry) = sockets.get(&key) {
                entry.last_used_secs.store(now, Ordering::Relaxed);
                return Ok(entry.socket.clone());
            }
        }

        let socket = Arc::new(create_fake_udp_socket(src_addr, fwmark)?);
        let entry = Arc::new(FakeUdpEntry {
            socket: socket.clone(),
            last_used_secs: AtomicU64::new(now),
        });

        let mut sockets = self.sockets.lock().await;

        if let Some(existing) = sockets.get(&key) {
            existing.last_used_secs.store(now, Ordering::Relaxed);
            return Ok(existing.socket.clone());
        }

        sockets.insert(key, entry);

        debug!(
            "created fake UDP socket: spoofed_src={}, fwmark={}",
            src_addr, fwmark
        );

        Ok(socket)
    }

    async fn send_to(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: &[u8],
        fwmark: u32,
    ) -> Result<usize> {
        let socket = self.get_or_create(src_addr, fwmark).await?;

        debug!(
            "fake UDP send: spoofed_src={}, dst={}, payload_len={}",
            src_addr,
            dst_addr,
            payload.len()
        );

        socket
            .send_to(payload, dst_addr)
            .await
            .context("fake UDP send_to failed")
    }

    async fn cleanup_expired(&self, timeout: Duration) {
        let now = now_secs();
        let timeout_secs = timeout.as_secs();

        let mut sockets = self.sockets.lock().await;

        sockets.retain(|key, entry| {
            let last = entry.last_used_secs.load(Ordering::Relaxed);
            let alive = now.saturating_sub(last) < timeout_secs;

            if !alive {
                debug!(
                    "fake UDP socket expired: spoofed_src={}, fwmark={}",
                    key.src_addr, key.fwmark
                );
            }

            alive
        });
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

struct UdpSession {
    spec: UdpSessionSpec,
    outbound: UdpOutbound,
    last_seen_secs: AtomicU64,
    cancel: CancellationToken,
}

enum UdpOutbound {
    Direct { socket: Arc<UdpSocket> },
    Socks5 { assoc: Socks5UdpAssoc },
}

impl UdpSession {
    fn key(&self) -> UdpSessionKey {
        self.spec.key
    }

    fn touch(&self) {
        self.last_seen_secs.store(now_secs(), Ordering::Relaxed);
    }

    async fn send_payload(&self, payload: &[u8]) -> Result<usize> {
        let key = self.key();

        match &self.outbound {
            UdpOutbound::Direct { socket } => {
                debug!(
                    "UDP direct send: kind={:?}, client={}, target={}, payload_len={}",
                    key.kind,
                    key.client_addr,
                    key.target_addr,
                    payload.len()
                );

                match socket.send(payload).await {
                    Ok(sent) => Ok(sent),
                    Err(e) if is_io_emsgsize(&e) => {
                        warn!(
                            "UDP datagram dropped due to EMSGSIZE: direction=client_to_direct, kind={:?}, client={}, target={}, payload_len={}, error={}",
                            key.kind,
                            key.client_addr,
                            key.target_addr,
                            payload.len(),
                            e
                        );

                        // 不杀 session，只丢当前 datagram。
                        Ok(0)
                    }
                    Err(e) => Err(e).context("direct UDP send failed"),
                }
            }
            UdpOutbound::Socks5 { assoc } => {
                let target = if let Some(host) = self.spec.sniffed_host.as_deref() {
                    Socks5UdpTarget::Domain {
                        host,
                        port: key.target_addr.port(),
                    }
                } else {
                    Socks5UdpTarget::Ip(key.target_addr)
                };

                let socks_target_log = match &target {
                    Socks5UdpTarget::Ip(addr) => format!("ip:{addr}"),
                    Socks5UdpTarget::Domain { host, port } => format!("domain:{host}:{port}"),
                };

                let pkt = build_socks5_udp_packet(target, payload);

                if pkt.is_empty() {
                    warn!(
                        "UDP SOCKS5 packet build failed: kind={:?}, client={}, target={}, sniffed_host={:?}",
                        key.kind, key.client_addr, key.target_addr, self.spec.sniffed_host
                    );

                    return Ok(0);
                }

                debug!(
                    "UDP SOCKS5 send: kind={:?}, client={}, original_target={}, socks_target={}, payload_len={}, pkt_len={}, relay={}",
                    key.kind,
                    key.client_addr,
                    key.target_addr,
                    socks_target_log,
                    payload.len(),
                    pkt.len(),
                    assoc.relay_addr
                );

                match assoc.udp_socket.send(&pkt).await {
                    Ok(sent) => Ok(sent),
                    Err(e) if is_io_emsgsize(&e) => {
                        warn!(
                            "UDP datagram dropped due to EMSGSIZE: direction=client_to_socks5, kind={:?}, client={}, target={}, payload_len={}, socks_pkt_len={}, relay={}, error={}",
                            key.kind,
                            key.client_addr,
                            key.target_addr,
                            payload.len(),
                            pkt.len(),
                            assoc.relay_addr,
                            e
                        );

                        // 不杀 session，只丢当前 datagram。
                        Ok(0)
                    }
                    Err(e) => Err(e).context("SOCKS5 UDP send failed"),
                }
            }
        }
    }

    async fn send_reply(
        &self,
        state: &AppState,
        direction: &'static str,
        remote_src: SocketAddr,
        payload: &[u8],
        relay_addr: Option<SocketAddr>,
    ) {
        let key = self.key();

        match &self.spec.reply_path {
            UdpReplyPath::Tproxy => {
                match state
                    .udp_runtime
                    .fake_udp
                    .send_to(remote_src, key.client_addr, payload, state.config.fwmark)
                    .await
                {
                    Ok(sent) => {
                        debug!(
                            "UDP response sent: direction={}, kind={:?}, spoofed_src={}, client={}, payload_len={}, sent={}",
                            direction,
                            key.kind,
                            remote_src,
                            key.client_addr,
                            payload.len(),
                            sent
                        );
                    }
                    Err(e) if is_anyhow_emsgsize(&e) => {
                        warn!(
                            "UDP datagram dropped due to EMSGSIZE: direction={}, kind={:?}, spoofed_src={}, client={}, payload_len={}, relay={:?}, error={:#}",
                            direction,
                            key.kind,
                            remote_src,
                            key.client_addr,
                            payload.len(),
                            relay_addr,
                            e
                        );
                    }
                    Err(e) => {
                        warn!(
                            "failed to send UDP response: direction={}, kind={:?}, spoofed_src={}, client={}, payload_len={}, relay={:?}, error={:#}",
                            direction,
                            key.kind,
                            remote_src,
                            key.client_addr,
                            payload.len(),
                            relay_addr,
                            e
                        );
                    }
                }
            }
            UdpReplyPath::PortForward { listen_sock } => {
                match listen_sock.send_to(payload, key.client_addr).await {
                    Ok(sent) => {
                        debug!(
                            "UDP response sent: direction={}, kind={:?}, remote_src={}, client={}, payload_len={}, sent={}",
                            direction,
                            key.kind,
                            remote_src,
                            key.client_addr,
                            payload.len(),
                            sent
                        );
                    }
                    Err(e) if is_io_emsgsize(&e) => {
                        warn!(
                            "UDP datagram dropped due to EMSGSIZE: direction={}, kind={:?}, remote_src={}, client={}, payload_len={}, relay={:?}, error={}",
                            direction,
                            key.kind,
                            remote_src,
                            key.client_addr,
                            payload.len(),
                            relay_addr,
                            e
                        );
                    }
                    Err(e) => {
                        warn!(
                            "failed to send UDP response: direction={}, kind={:?}, remote_src={}, client={}, payload_len={}, relay={:?}, error={:#}",
                            direction,
                            key.kind,
                            remote_src,
                            key.client_addr,
                            payload.len(),
                            relay_addr,
                            e
                        );
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct TProxyUdpPacketMeta {
    len: usize,
    client_addr: SocketAddr,
    orig_dst: SocketAddr,
}

struct TProxyUdpSocket {
    socket: Arc<UdpSocket>,
    fd: i32,
}

fn sockaddr_in_to_std(addr: libc::sockaddr_in) -> SocketAddr {
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    SocketAddr::new(IpAddr::V4(ip), port)
}

fn sockaddr_in6_to_std(addr: libc::sockaddr_in6) -> SocketAddr {
    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);
    SocketAddr::new(IpAddr::V6(ip), port)
}

impl TProxyUdpSocket {
    fn new(socket: UdpSocket) -> Self {
        let fd = socket.as_raw_fd();

        Self {
            socket: Arc::new(socket),
            fd,
        }
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> Result<TProxyUdpPacketMeta> {
        loop {
            self.socket.readable().await?;

            let result = self.socket.try_io(Interest::READABLE, || {
                let (len, client_addr, orig_dst) = Self::recv_udp_tproxy_packet_raw(self.fd, buf)?;

                let orig_dst = orig_dst.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("udp packet from {client_addr} missing original destination"),
                    )
                })?;

                Ok(TProxyUdpPacketMeta {
                    len,
                    client_addr,
                    orig_dst,
                })
            });

            match result {
                Ok(packet) => return Ok(packet),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn recv_udp_tproxy_packet_raw(
        fd: i32,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
        let mut iov = [IoSliceMut::new(buf)];

        // 为 ancillary data 分配空间
        let mut cmsgspace = nix::cmsg_space!([libc::sockaddr_in; 1], [libc::sockaddr_in6; 1]);

        let msg = recvmsg::<SockaddrStorage>(fd, &mut iov, Some(&mut cmsgspace), MsgFlags::empty())
            .map_err(errno_to_io)?;

        if msg.flags.contains(MsgFlags::MSG_CTRUNC) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "udp control message truncated",
            ));
        }

        let client_addr = msg
            .address
            .as_ref()
            .and_then(sockaddr_storage_to_std)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid peer sockaddr"))?;

        debug!(
            "udp recvmsg: n={}, client_addr={}, flags={:?}",
            msg.bytes, client_addr, msg.flags
        );

        let mut orig_dst = None;

        for cmsg in msg.cmsgs().map_err(errno_to_io)? {
            debug!("udp cmsg: {:?}", cmsg);

            match cmsg {
                ControlMessageOwned::Ipv4OrigDstAddr(addr) => {
                    orig_dst = Some(sockaddr_in_to_std(addr));
                    debug!("udp orig_dst(v4)={}", orig_dst.unwrap());
                    break;
                }

                ControlMessageOwned::Ipv6OrigDstAddr(addr) => {
                    orig_dst = Some(sockaddr_in6_to_std(addr));
                    debug!("udp orig_dst(v6)={}", orig_dst.unwrap());
                    break;
                }
                _ => {}
            }
        }

        Ok((msg.bytes, client_addr, orig_dst))
    }
}

fn sockaddr_storage_to_std(addr: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(v4) = addr.as_sockaddr_in() {
        let std_v4: std::net::SocketAddrV4 = (*v4).into();
        return Some(SocketAddr::V4(std_v4));
    }

    if let Some(v6) = addr.as_sockaddr_in6() {
        let std_v6: std::net::SocketAddrV6 = (*v6).into();
        return Some(SocketAddr::V6(std_v6));
    }

    None
}

fn errno_to_io(errno: Errno) -> io::Error {
    io::Error::from_raw_os_error(errno as i32)
}

#[derive(Debug)]
struct Socks5UdpAssoc {
    // SOCKS5 UDP ASSOCIATE 的 control TCP。
    // 必须持有到 UDP 会话结束，否则符合规范的服务端会释放 UDP relay。
    _control: TcpStream,
    relay_addr: SocketAddr,
    udp_socket: Arc<UdpSocket>,
}

enum Socks5Target<'a> {
    Ip(SocketAddr),
    Domain(&'a str, u16),
}

#[derive(Debug, Clone)]
enum TcpUpstreamTarget {
    Direct(SocketAddr),
    Socks5Ip(SocketAddr),
    Socks5Domain { host: String, port: u16 },
}

fn parse_listen_addr(listen: &str) -> Result<(IpAddr, u16)> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| anyhow!("invalid listen address '{listen}': {e}"))?;
    Ok((addr.ip(), addr.port()))
}

fn set_socket_reuse(socket: &Socket) -> Result<()> {
    socket
        .set_reuse_address(true)
        .context("SO_REUSEADDR failed")?;
    socket.set_reuse_port(true).context("SO_REUSEPORT failed")?;
    Ok(())
}

fn parse_ip_net_list(list: &[String]) -> Result<Vec<IpNet>> {
    list.iter()
        .map(|raw| {
            let s = raw.trim();

            if s.is_empty() {
                bail!("empty IP/CIDR entry");
            }

            if let Ok(net) = s.parse::<IpNet>() {
                return Ok(net);
            }

            let ip: IpAddr = s
                .parse()
                .with_context(|| format!("invalid IP/CIDR '{}'", raw))?;

            let prefix_len = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };

            IpNet::new(ip, prefix_len)
                .with_context(|| format!("failed to build host network from '{}'", raw))
        })
        .collect()
}

fn build_ip_tries(nets: &[IpNet]) -> Result<(Ipv4RTrieSet, Ipv6RTrieSet)> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    for net in nets {
        match net {
            IpNet::V4(v4net) => {
                let prefix = Ipv4Prefix::new(v4net.network(), v4net.prefix_len())
                    .context("failed to convert IPv4 network to prefix")?;
                v4.push(prefix);
            }
            IpNet::V6(v6net) => {
                let prefix = Ipv6Prefix::new(v6net.network(), v6net.prefix_len())
                    .context("failed to convert IPv6 network to prefix")?;
                v6.push(prefix);
            }
        }
    }

    Ok((Ipv4RTrieSet::from_iter(v4), Ipv6RTrieSet::from_iter(v6)))
}

async fn sniff_domain(
    client: &TcpStream,
    orig_dst: SocketAddr,
    sniffers: &[Arc<dyn Sniffer>],
    cfg: &SniffConfig,
) -> Option<String> {
    for sniffer in sniffers {
        if let Some(host) = sniff_with_engine(sniffer.as_ref(), client, orig_dst, cfg).await {
            return Some(host);
        }
    }
    None
}

fn build_sniffers(config: &Config) -> Vec<Arc<dyn Sniffer>> {
    let mut sniffers: Vec<Arc<dyn Sniffer>> = Vec::new();

    if config.sniff_tls_sni {
        sniffers.push(Arc::new(TlsSniffer::new(
            config.tls_sniff_peek_len,
            config.tls_sniff_max_len,
            config.tls_sniff_max_retries,
            config.tls_sniff_wait_more_ms,
            config.tls_sniff_timeout_ms,
        )));
    }

    if config.sniff_http_host {
        sniffers.push(Arc::new(HttpSniffer::new(
            config.http_sniff_peek_len,
            config.http_sniff_max_len,
            config.http_sniff_max_retries,
            config.http_sniff_wait_more_ms,
            config.http_sniff_timeout_ms,
        )));
    }

    sniffers
}

fn warn_if_splice_with_forwarding(splice_enabled: bool) {
    if !splice_enabled {
        return;
    }

    const PREFIX: &str = "/proc/sys/net/";

    let read_proc = |suffix: &str| -> bool {
        std::fs::read_to_string(format!("{}{}", PREFIX, suffix))
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .is_some_and(|n| n != 0)
    };

    let v4 = read_proc("ipv4/ip_forward");
    let v6 = read_proc("ipv6/conf/all/forwarding");

    if v4 || v6 {
        warn!(
            "splice=1 but ip_forward detected (ipv4={}, ipv6={}). \
             splice() may underperform on forwarding paths due to skb linearization. \
             Please see https://github.com/XTLS/Xray-core/discussions/59",
            v4, v6
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config_str = tokio::fs::read_to_string(&cli.config)
        .await
        .with_context(|| format!("failed to read config file {}", cli.config))?;

    let config: Config = toml::from_str(&config_str).context("invalid config")?;

    let env_filter = if let Some(ref level) = config.log_level {
        tracing_subscriber::EnvFilter::new(level)
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())
    };

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    debug!("xtp-rs started");

    warn_if_splice_with_forwarding(config.splice);

    let mmdb = match config.mmdb_path.as_deref() {
        Some("") | None => {
            info!("MMDB is disabled");
            None
        }
        Some(path) => {
            let data = tokio::fs::read(path)
                .await
                .with_context(|| format!("failed to read MMDB file {}", path))?;
            let reader = Reader::from_source(data).context("invalid MMDB data")?;
            info!("MMDB loaded from {}", path);
            Some(Arc::new(reader))
        }
    };

    let udp_runtime = Arc::new(UdpRuntime::new(Duration::from_secs(
        config.udp_session_timeout_secs,
    )));

    let (listen_ip, listen_port) =
        parse_listen_addr(&config.listen).context("invalid listen address")?;

    let mut direct_list = config.force_direct_ips.clone();
    if let Some(ref path) = config.force_direct_ips_file {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read force_direct_ips_file '{}'", path))?;
        direct_list.extend(
            content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.trim().to_string()),
        );
    }

    let mut socks5_list = config.force_socks5_ips.clone();
    if let Some(ref path) = config.force_socks5_ips_file {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read force_socks5_ips_file '{}'", path))?;
        socks5_list.extend(
            content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.trim().to_string()),
        );
    }

    let direct_nets =
        parse_ip_net_list(&direct_list).context("failed to parse force_direct_ips")?;
    info!("force_direct_ips: {} entries loaded", direct_nets.len());
    let socks5_nets =
        parse_ip_net_list(&socks5_list).context("failed to parse force_socks5_ips")?;
    info!("force_socks5_ips: {} entries loaded", socks5_nets.len());

    let (force_direct_v4, force_direct_v6) =
        build_ip_tries(&direct_nets).context("failed to build force_direct tries")?;
    let (force_socks5_v4, force_socks5_v6) =
        build_ip_tries(&socks5_nets).context("failed to build force_socks5 tries")?;

    let sniffers = build_sniffers(&config);
    let udp_sniffer = UdpSniffer::from_config(&config).map(Arc::new);

    let state = Arc::new(AppState {
        mmdb: mmdb.clone(),
        config,
        udp_runtime,
        force_direct_v4,
        force_direct_v6,
        force_socks5_v4,
        force_socks5_v6,
        sniffers,
        udp_sniffer,
    });

    let (tcp_v4, tcp_v6) = create_tproxy_tcp_listeners(listen_ip, listen_port)?;

    if let Some(l) = tcp_v4 {
        info!("TPROXY TCP (IPv4) on 0.0.0.0:{}", listen_port);
        let state = state.clone();
        tokio::spawn(async move { tcp_accept_loop(l, state).await });
    }

    if let Some(l) = tcp_v6 {
        info!("TPROXY TCP (IPv6) on [::]:{}", listen_port);
        let state = state.clone();
        tokio::spawn(async move { tcp_accept_loop(l, state).await });
    }

    let (udp_v4, udp_v6) = if state.config.udp {
        create_tproxy_udp_sockets(listen_ip, listen_port)?
    } else {
        (None, None)
    };

    if let Some(sock) = udp_v4 {
        info!("TPROXY UDP (IPv4) on 0.0.0.0:{}", listen_port);
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_udp_loop(state, sock).await {
                error!("IPv4 UDP loop exited with error: {:#}", e);
            }
        });
    }

    if let Some(sock) = udp_v6 {
        info!("TPROXY UDP (IPv6) on [::]:{}", listen_port);
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_udp_loop(state, sock).await {
                error!("IPv6 UDP loop exited with error: {:#}", e);
            }
        });
    }

    for pf in &state.config.port_forward {
        let bind_addr: SocketAddr = pf
            .bind
            .parse()
            .with_context(|| format!("invalid port-forward bind '{}'", pf.bind))?;
        let remote_addr: SocketAddr = pf
            .remote
            .parse()
            .with_context(|| format!("invalid port-forward remote '{}'", pf.remote))?;
        let state = state.clone();
        let name = pf.name.clone().unwrap_or_default();

        match pf.network {
            PortForwardProto::Tcp => {
                tokio::spawn(async move {
                    if let Err(e) = run_tcp_port_forward(bind_addr, remote_addr, state).await {
                        error!("port-forward TCP {name} error: {:#}", e);
                    }
                });
            }
            PortForwardProto::Udp => {
                tokio::spawn(async move {
                    if let Err(e) = run_udp_port_forward(bind_addr, remote_addr, state).await {
                        error!("port-forward UDP {name} error: {:#}", e);
                    }
                });
            }
            PortForwardProto::Both => {
                let name_tcp = name.clone();
                let name_udp = name.clone();
                let tcp_state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_tcp_port_forward(bind_addr, remote_addr, tcp_state).await {
                        error!("port-forward TCP(both) {name_tcp} error: {:#}", e);
                    }
                });
                tokio::spawn(async move {
                    if let Err(e) = run_udp_port_forward(bind_addr, remote_addr, state).await {
                        error!("port-forward UDP(both) {name_udp} error: {:#}", e);
                    }
                });
            }
        }
    }

    {
        let state = state.clone();
        tokio::spawn(async move {
            run_udp_gc_loop(state).await;
        });
    }

    tokio::signal::ctrl_c().await?;
    info!("shutting down");

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsSniffError {
    PeekEmpty,
    InsufficientPrefix,
    ProtocolNotMatched,
    TlsNoSni,
    ParseError,
    InvalidHostname,
    TooLargeClientHello,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpSniffError {
    PeekEmpty,
    InsufficientPrefix,
    ProtocolNotMatched,
    HttpNoHost,
    ParseError,
    InvalidHostname,
    TooLargeHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SniffError {
    PeekEmpty,
    ProtocolNotMatched,
    NoTarget,
    ParseError,
    InvalidHostname,
    TooLarge,
}

enum SniffAttempt {
    Matched(String),
    NeedMore,
    Abort(SniffError),
}

#[derive(Debug, Clone, Copy)]
pub struct SniffConfig {
    /// 全局 peek 硬上限。
    /// 所有嗅探器在增大 peek 缓冲区时，均不会超过此值。
    pub tcp_peek_buffer_size: usize,
}

trait Sniffer: Send + Sync {
    fn name(&self) -> &'static str;
    fn initial_peek_len(&self) -> usize;
    fn max_peek_len(&self) -> usize;
    fn max_retries(&self) -> usize;
    fn wait_more_duration(&self) -> Duration;
    fn timeout_duration(&self) -> Duration;
    fn classify(&self, buf: &[u8], max_len: usize) -> SniffAttempt;
    fn map_error_reason(&self, err: SniffError) -> &'static str;
}

struct TlsSniffer {
    peek_len: usize,
    max_len: usize,
    max_retries: usize,
    wait_more: Duration,
    timeout: Duration,
}

impl TlsSniffer {
    pub fn new(
        peek_len: usize,
        max_len: usize,
        max_retries: usize,
        wait_more_ms: u64,
        timeout_ms: u64,
    ) -> Self {
        Self {
            peek_len,
            max_len,
            max_retries,
            wait_more: Duration::from_millis(wait_more_ms.max(1)),
            timeout: Duration::from_millis(timeout_ms.max(1)),
        }
    }
}

impl Sniffer for TlsSniffer {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn initial_peek_len(&self) -> usize {
        self.peek_len
    }
    fn max_peek_len(&self) -> usize {
        self.max_len
    }
    fn max_retries(&self) -> usize {
        self.max_retries
    }
    fn wait_more_duration(&self) -> Duration {
        self.wait_more
    }
    fn timeout_duration(&self) -> Duration {
        self.timeout
    }

    fn classify(&self, buf: &[u8], max_len: usize) -> SniffAttempt {
        match sniff_tls_sni_from_prefix(buf, max_len) {
            Ok(host) => SniffAttempt::Matched(host),
            Err(TlsSniffError::InsufficientPrefix) => SniffAttempt::NeedMore,
            Err(TlsSniffError::PeekEmpty) => SniffAttempt::Abort(SniffError::PeekEmpty),
            Err(TlsSniffError::ProtocolNotMatched) => {
                SniffAttempt::Abort(SniffError::ProtocolNotMatched)
            }
            Err(TlsSniffError::TlsNoSni) => SniffAttempt::Abort(SniffError::NoTarget),
            Err(TlsSniffError::ParseError) => SniffAttempt::Abort(SniffError::ParseError),
            Err(TlsSniffError::InvalidHostname) => SniffAttempt::Abort(SniffError::InvalidHostname),
            Err(TlsSniffError::TooLargeClientHello) => SniffAttempt::Abort(SniffError::TooLarge),
        }
    }

    fn map_error_reason(&self, err: SniffError) -> &'static str {
        match err {
            SniffError::PeekEmpty => "peek_empty",
            SniffError::ProtocolNotMatched => "protocol_not_matched",
            SniffError::NoTarget => "tls_no_sni",
            SniffError::ParseError => "parse_error",
            SniffError::InvalidHostname => "invalid_hostname",
            SniffError::TooLarge => "client_hello_too_large",
        }
    }
}

fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn looks_like_http_1x_request_line(line: &str) -> bool {
    let mut parts = line.split(' ');

    let method = match parts.next() {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_uppercase()) => v,
        _ => return false,
    };

    let target = match parts.next() {
        Some(v) if !v.is_empty() => v,
        _ => return false,
    };

    let version = match parts.next() {
        Some(v) => v,
        None => return false,
    };

    if parts.next().is_some() {
        return false;
    }

    let _ = method;
    let _ = target;

    matches!(version, "HTTP/1.0" | "HTTP/1.1")
}

fn parse_http_host_header_value(value: &str) -> Result<String, HttpSniffError> {
    let value = value.trim();

    if value.is_empty() {
        return Err(HttpSniffError::ParseError);
    }

    if value.starts_with('[') {
        return Err(HttpSniffError::InvalidHostname);
    }

    let host = match value.rsplit_once(':') {
        Some((name, port))
            if !name.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            name
        }
        _ => value,
    };

    let host = host.trim().to_ascii_lowercase();

    if !is_valid_sni_hostname(&host) {
        return Err(HttpSniffError::InvalidHostname);
    }

    Ok(host)
}

fn sniff_http_host_from_prefix(
    buf: &[u8],
    max_header_size: usize,
) -> Result<String, HttpSniffError> {
    if buf.is_empty() {
        return Err(HttpSniffError::PeekEmpty);
    }

    let header_end = match find_http_header_end(buf) {
        Some(v) => v,
        None => {
            if buf.len() >= max_header_size {
                return Err(HttpSniffError::TooLargeHeader);
            }
            return Err(HttpSniffError::InsufficientPrefix);
        }
    };

    let header =
        std::str::from_utf8(&buf[..header_end]).map_err(|_| HttpSniffError::ProtocolNotMatched)?;

    let mut lines = header.split("\r\n");

    let request_line = lines.next().ok_or(HttpSniffError::ParseError)?;
    if !looks_like_http_1x_request_line(request_line) {
        return Err(HttpSniffError::ProtocolNotMatched);
    }

    for line in lines {
        if line.is_empty() {
            break;
        }

        let (name, value) = line.split_once(':').ok_or(HttpSniffError::ParseError)?;
        if name.eq_ignore_ascii_case("host") {
            return parse_http_host_header_value(value);
        }
    }

    Err(HttpSniffError::HttpNoHost)
}

struct HttpSniffer {
    peek_len: usize,
    max_len: usize,
    max_retries: usize,
    wait_more: Duration,
    timeout: Duration,
}

impl HttpSniffer {
    pub fn new(
        peek_len: usize,
        max_len: usize,
        max_retries: usize,
        wait_more_ms: u64,
        timeout_ms: u64,
    ) -> Self {
        Self {
            peek_len,
            max_len,
            max_retries,
            wait_more: Duration::from_millis(wait_more_ms.max(1)),
            timeout: Duration::from_millis(timeout_ms.max(1)),
        }
    }
}

impl Sniffer for HttpSniffer {
    fn name(&self) -> &'static str {
        "http"
    }

    fn initial_peek_len(&self) -> usize {
        self.peek_len
    }

    fn max_peek_len(&self) -> usize {
        self.max_len
    }

    fn max_retries(&self) -> usize {
        self.max_retries
    }

    fn wait_more_duration(&self) -> Duration {
        self.wait_more
    }

    fn timeout_duration(&self) -> Duration {
        self.timeout
    }

    fn classify(&self, buf: &[u8], max_len: usize) -> SniffAttempt {
        match sniff_http_host_from_prefix(buf, max_len) {
            Ok(host) => SniffAttempt::Matched(host),
            Err(HttpSniffError::InsufficientPrefix) => SniffAttempt::NeedMore,
            Err(HttpSniffError::PeekEmpty) => SniffAttempt::Abort(SniffError::PeekEmpty),
            Err(HttpSniffError::ProtocolNotMatched) => {
                SniffAttempt::Abort(SniffError::ProtocolNotMatched)
            }
            Err(HttpSniffError::HttpNoHost) => SniffAttempt::Abort(SniffError::NoTarget),
            Err(HttpSniffError::ParseError) => SniffAttempt::Abort(SniffError::ParseError),
            Err(HttpSniffError::InvalidHostname) => {
                SniffAttempt::Abort(SniffError::InvalidHostname)
            }
            Err(HttpSniffError::TooLargeHeader) => SniffAttempt::Abort(SniffError::TooLarge),
        }
    }

    fn map_error_reason(&self, err: SniffError) -> &'static str {
        match err {
            SniffError::PeekEmpty => "peek_empty",
            SniffError::ProtocolNotMatched => "protocol_not_matched",
            SniffError::NoTarget => "http_no_host",
            SniffError::ParseError => "parse_error",
            SniffError::InvalidHostname => "invalid_hostname",
            SniffError::TooLarge => "header_too_large",
        }
    }
}

async fn peek_client_prefix(stream: &TcpStream, max_len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; max_len];
    let n = stream.peek(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

async fn wait_for_more_peek_data(
    stream: &TcpStream,
    max_len: usize,
    last_len: usize,
    wait: Duration,
) -> Result<Option<Vec<u8>>> {
    let deadline = tokio::time::Instant::now() + wait;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(None);
        }

        let remain = deadline.saturating_duration_since(now);

        let buf = match tokio::time::timeout(remain, peek_client_prefix(stream, max_len)).await {
            Ok(r) => r?,
            Err(_) => return Ok(None),
        };

        if buf.len() > last_len {
            return Ok(Some(buf));
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(None);
        }

        let sleep_for = Duration::from_millis(5).min(deadline.saturating_duration_since(now));
        tokio::time::sleep(sleep_for).await;
    }
}

fn should_retry_sniff(
    engine_name: &str,
    attempt: usize,
    max_retries: usize,
    cur_len: usize,
    last_peek_len: usize,
    orig_dst: SocketAddr,
) -> bool {
    if attempt >= max_retries {
        debug!(
            "{} sniff stop: reason=max_retries_exceeded, dst={}, attempts={}, peek_len={}",
            engine_name,
            orig_dst,
            attempt + 1,
            cur_len
        );
        return false;
    }

    if cur_len == 0 {
        debug!(
            "{} sniff stop: reason=peek_empty, dst={}",
            engine_name, orig_dst
        );
        return false;
    }

    if cur_len <= last_peek_len {
        debug!(
            "{} sniff stop: reason=no_progress, dst={}, attempt={}, peek_len={}",
            engine_name, orig_dst, attempt, cur_len
        );
        return false;
    }

    true
}

async fn sniff_with_engine(
    engine: &dyn Sniffer,
    client: &TcpStream,
    orig_dst: SocketAddr,
    cfg: &SniffConfig,
) -> Option<String> {
    let timeout = engine.timeout_duration();
    let inner = async {
        let hard_cap = cfg.tcp_peek_buffer_size.max(1);
        let max_len = engine.max_peek_len().max(1).min(hard_cap);
        let mut peek_len = engine.initial_peek_len().max(1).min(max_len);
        let max_retries = engine.max_retries();
        let wait_more = engine.wait_more_duration();

        let mut attempt = 0usize;
        let mut last_peek_len = 0usize;

        loop {
            let buf = match peek_client_prefix(client, peek_len).await {
                Ok(buf) => buf,
                Err(e) => {
                    debug!(
                        "{} sniff failed: reason=peek_failed, dst={}, attempt={}, error={:#}",
                        engine.name(),
                        orig_dst,
                        attempt,
                        e
                    );
                    return None;
                }
            };

            let cur_len = buf.len();

            match engine.classify(&buf, peek_len) {
                SniffAttempt::Matched(host) => {
                    debug!(
                        "{} sniff success: dst={}, host={}, attempt={}, peek_len={}",
                        engine.name(),
                        orig_dst,
                        host,
                        attempt,
                        cur_len
                    );
                    return Some(host);
                }
                SniffAttempt::NeedMore => {
                    debug!(
                        "{} sniff retryable failure: reason=insufficient_prefix, dst={}, attempt={}, peek_len={}",
                        engine.name(),
                        orig_dst,
                        attempt,
                        cur_len
                    );

                    if !should_retry_sniff(
                        engine.name(),
                        attempt,
                        max_retries,
                        cur_len,
                        last_peek_len,
                        orig_dst,
                    ) {
                        return None;
                    }

                    last_peek_len = cur_len;

                    let next_len = (peek_len.saturating_mul(2)).min(max_len);
                    if next_len <= peek_len {
                        debug!(
                            "{} sniff stop: reason=max_peek_reached, dst={}, attempt={}, peek_len={}",
                            engine.name(),
                            orig_dst,
                            attempt,
                            cur_len
                        );
                        return None;
                    }

                    match wait_for_more_peek_data(client, next_len, last_peek_len, wait_more).await
                    {
                        Ok(Some(_)) => {
                            peek_len = next_len;
                            attempt += 1;
                            continue;
                        }
                        Ok(None) => {
                            debug!(
                                "{} sniff stop: reason=no_more_peek_growth, dst={}, attempt={}, peek_len={}",
                                engine.name(),
                                orig_dst,
                                attempt,
                                cur_len
                            );
                            return None;
                        }
                        Err(e) => {
                            debug!(
                                "{} sniff stop: reason=wait_more_failed, dst={}, attempt={}, error={:#}",
                                engine.name(),
                                orig_dst,
                                attempt,
                                e
                            );
                            return None;
                        }
                    }
                }
                SniffAttempt::Abort(err) => {
                    debug!(
                        "{} sniff failed: reason={}, dst={}, attempt={}, peek_len={}",
                        engine.name(),
                        engine.map_error_reason(err),
                        orig_dst,
                        attempt,
                        cur_len
                    );
                    return None;
                }
            }
        }
    };

    match tokio::time::timeout(timeout, inner).await {
        Ok(v) => v,
        Err(_) => {
            debug!(
                "{} sniff failed: reason=timeout, dst={}, timeout_ms={}",
                engine.name(),
                orig_dst,
                timeout.as_millis()
            );
            None
        }
    }
}

fn be_u16(b: &[u8]) -> Result<u16, TlsSniffError> {
    if b.len() < 2 {
        return Err(TlsSniffError::ParseError);
    }
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn be_u24(b: &[u8]) -> Result<usize, TlsSniffError> {
    if b.len() < 3 {
        return Err(TlsSniffError::ParseError);
    }
    Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize))
}

fn is_valid_sni_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.ends_with('.') {
        return false;
    }

    let mut has_alpha = false;

    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
        if label.chars().any(|c| c.is_ascii_alphabetic()) {
            has_alpha = true;
        }
    }

    has_alpha
}

fn parse_sni_from_client_hello_body(body: &[u8]) -> Result<String, TlsSniffError> {
    if body.len() < 2 + 32 + 1 {
        return Err(TlsSniffError::ParseError);
    }

    let mut off = 0usize;

    off += 2; // legacy_version
    off += 32; // random

    let session_id_len = *body.get(off).ok_or(TlsSniffError::ParseError)? as usize;
    off += 1;
    if off + session_id_len > body.len() {
        return Err(TlsSniffError::ParseError);
    }
    off += session_id_len;

    let cipher_suites_len =
        be_u16(body.get(off..off + 2).ok_or(TlsSniffError::ParseError)?)? as usize;
    off += 2;
    if cipher_suites_len == 0
        || !cipher_suites_len.is_multiple_of(2)
        || off + cipher_suites_len > body.len()
    {
        return Err(TlsSniffError::ParseError);
    }
    off += cipher_suites_len;

    let compression_methods_len = *body.get(off).ok_or(TlsSniffError::ParseError)? as usize;
    off += 1;
    if compression_methods_len == 0 || off + compression_methods_len > body.len() {
        return Err(TlsSniffError::ParseError);
    }
    off += compression_methods_len;

    if off == body.len() {
        return Err(TlsSniffError::TlsNoSni);
    }

    let extensions_len = be_u16(body.get(off..off + 2).ok_or(TlsSniffError::ParseError)?)? as usize;
    off += 2;
    if off + extensions_len > body.len() {
        return Err(TlsSniffError::ParseError);
    }

    let ext_end = off + extensions_len;
    while off + 4 <= ext_end {
        let ext_type = be_u16(&body[off..off + 2])?;
        let ext_len = be_u16(&body[off + 2..off + 4])? as usize;
        off += 4;

        if off + ext_len > ext_end {
            return Err(TlsSniffError::ParseError);
        }

        if ext_type == 0xfe0d {
            // encrypted_client_hello extension.
            // 被动 sniff 无法解密 ECH，按无目标处理，回退 IP 路由。
            return Err(TlsSniffError::TlsNoSni);
        }

        if ext_type == 0x0000 {
            let ext = &body[off..off + ext_len];
            if ext.len() < 2 {
                return Err(TlsSniffError::ParseError);
            }

            let list_len = be_u16(&ext[0..2])? as usize;
            if list_len + 2 != ext.len() {
                return Err(TlsSniffError::ParseError);
            }

            let mut p = 2usize;
            while p + 3 <= ext.len() {
                let name_type = ext[p];
                let name_len = be_u16(&ext[p + 1..p + 3])? as usize;
                p += 3;

                if p + name_len > ext.len() {
                    return Err(TlsSniffError::ParseError);
                }

                if name_type == 0 {
                    let host = std::str::from_utf8(&ext[p..p + name_len])
                        .map_err(|_| TlsSniffError::InvalidHostname)?
                        .to_ascii_lowercase();

                    if !is_valid_sni_hostname(&host) {
                        return Err(TlsSniffError::InvalidHostname);
                    }

                    return Ok(host);
                }

                p += name_len;
            }

            return Err(TlsSniffError::TlsNoSni);
        }

        off += ext_len;
    }

    if off != ext_end {
        return Err(TlsSniffError::ParseError);
    }

    Err(TlsSniffError::TlsNoSni)
}

fn sniff_tls_sni_from_prefix(
    buf: &[u8],
    max_client_hello_size: usize,
) -> Result<String, TlsSniffError> {
    if buf.is_empty() {
        return Err(TlsSniffError::PeekEmpty);
    }

    let mut off = 0usize;
    let mut handshake = Vec::with_capacity(buf.len().min(4096));
    let mut needed_total: Option<usize> = None;
    let mut saw_handshake_record = false;

    while off < buf.len() {
        if buf.len() - off < 5 {
            if off == 0 && !buf.is_empty() {
                if buf[0] != 0x16 {
                    return Err(TlsSniffError::ProtocolNotMatched);
                }

                if buf.len() >= 2 && buf[1] != 0x03 {
                    return Err(TlsSniffError::ProtocolNotMatched);
                }

                return Err(TlsSniffError::InsufficientPrefix);
            }

            return if saw_handshake_record {
                Err(TlsSniffError::InsufficientPrefix)
            } else {
                Err(TlsSniffError::ProtocolNotMatched)
            };
        }
        let content_type = buf[off];

        if content_type != 22 {
            return Err(TlsSniffError::ProtocolNotMatched);
        }

        let version_major = buf[off + 1];

        if version_major != 0x03 {
            return Err(TlsSniffError::ProtocolNotMatched);
        }

        let record_len = be_u16(&buf[off + 3..off + 5])? as usize;

        const MAX_TLS_RECORD_PAYLOAD: usize = 18 * 1024;
        if record_len == 0 || record_len > MAX_TLS_RECORD_PAYLOAD {
            return Err(TlsSniffError::ProtocolNotMatched);
        }

        let record_end = off + 5 + record_len;

        if record_end > buf.len() {
            return Err(TlsSniffError::InsufficientPrefix);
        }

        let payload = &buf[off + 5..record_end];

        saw_handshake_record = true;
        handshake.extend_from_slice(payload);

        if needed_total.is_none() && handshake.len() >= 4 {
            if handshake[0] != 0x01 {
                return Err(TlsSniffError::ProtocolNotMatched);
            }

            let hs_len = be_u24(&handshake[1..4])?;
            let total = 4 + hs_len;

            if total > max_client_hello_size {
                return Err(TlsSniffError::TooLargeClientHello);
            }

            needed_total = Some(total);
        }

        if let Some(total) = needed_total
            && handshake.len() >= total
        {
            let body = &handshake[4..total];
            return parse_sni_from_client_hello_body(body);
        }

        off = record_end;
    }

    if saw_handshake_record {
        Err(TlsSniffError::InsufficientPrefix)
    } else {
        Err(TlsSniffError::ProtocolNotMatched)
    }
}

fn decide_tcp_upstream_target(
    orig_dst: SocketAddr,
    direct: bool,
    sniffed_sni: Option<&str>,
) -> TcpUpstreamTarget {
    if direct {
        TcpUpstreamTarget::Direct(orig_dst)
    } else if let Some(host) = sniffed_sni {
        TcpUpstreamTarget::Socks5Domain {
            host: host.to_string(),
            port: orig_dst.port(),
        }
    } else {
        TcpUpstreamTarget::Socks5Ip(orig_dst)
    }
}

async fn connect_tcp_upstream(
    target: &TcpUpstreamTarget,
    socks5_addr: &str,
    fwmark: u32,
    creds: Option<(&str, &str)>,
) -> Result<TcpStream> {
    match target {
        TcpUpstreamTarget::Direct(addr) => {
            debug!("direct connect to {}", addr);
            direct_connect(*addr, fwmark).await
        }
        TcpUpstreamTarget::Socks5Ip(addr) => {
            debug!("proxy connect by ip: {}", addr);
            socks5_connect(Socks5Target::Ip(*addr), socks5_addr, fwmark, creds).await
        }
        TcpUpstreamTarget::Socks5Domain { host, port } => {
            debug!("proxy connect by hostname: host={}, port={}", host, port);

            socks5_connect(
                Socks5Target::Domain(host.as_str(), *port),
                socks5_addr,
                fwmark,
                creds,
            )
            .await
        }
    }
}

async fn handle_tcp_connection(
    mut client: TcpStream,
    orig_dst: SocketAddr,
    state: Arc<AppState>,
) -> Result<()> {
    let direct = state.should_direct(orig_dst.ip());

    let sniff_cfg = SniffConfig {
        tcp_peek_buffer_size: state.config.tcp_peek_buffer_size,
    };

    let sniffed_host = if direct {
        None
    } else {
        sniff_domain(&client, orig_dst, &state.sniffers, &sniff_cfg).await
    };

    let target = decide_tcp_upstream_target(orig_dst, direct, sniffed_host.as_deref());

    let mut upstream = connect_tcp_upstream(
        &target,
        &state.config.socks5_addr,
        state.config.fwmark,
        state.socks5_credentials(),
    )
    .await?;

    let (a, b) =
        splice_or_copy_bidirectional(state.config.splice, &mut client, &mut upstream).await?;

    debug!(
        "tcp finished, orig_dst={}, upstream_target={:?}, sniffed_host={:?}, client->upstream={} bytes, upstream->client={} bytes",
        orig_dst, target, sniffed_host, a, b
    );

    Ok(())
}

async fn direct_connect(orig_dst: SocketAddr, fwmark: u32) -> Result<TcpStream> {
    let domain = if orig_dst.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create socket for direct connect")?;

    socket.set_mark(fwmark)?;
    socket.set_nonblocking(true)?;

    match socket.connect(&orig_dst.into()) {
        Ok(_) => {}
        Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e).context("direct connect failed"),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;

    stream.writable().await?;

    if let Some(e) = stream.take_error()? {
        return Err(e).context("direct connect final handshake error");
    }

    Ok(stream)
}

fn enable_orig_dst_v4<F: std::os::fd::AsFd>(fd: &F) -> io::Result<()> {
    setsockopt(fd, sockopt::Ipv4OrigDstAddr, &true).map_err(errno_to_io)
}

fn enable_orig_dst_v6<F: std::os::fd::AsFd>(fd: &F) -> io::Result<()> {
    setsockopt(fd, sockopt::Ipv6OrigDstAddr, &true).map_err(errno_to_io)
}

fn tproxy_tcp_listener_for_ip(ip: IpAddr, port: u16) -> Result<TcpListener> {
    let sa = SocketAddr::new(ip, port);
    SocketFactory::new().bind_tcp_listener(
        sa,
        true,
        true,
        if sa.is_ipv6() { Some(true) } else { None },
        1024,
    )
}

fn create_tproxy_tcp_listeners(
    ip: IpAddr,
    port: u16,
) -> Result<(Option<TcpListener>, Option<TcpListener>)> {
    match ip {
        IpAddr::V4(_) => {
            let v4 = tproxy_tcp_listener_for_ip(ip, port)?;
            Ok((Some(v4), None))
        }
        IpAddr::V6(v6) if v6.is_unspecified() => {
            let v4 = tproxy_tcp_listener_for_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)?;
            let v6 = tproxy_tcp_listener_for_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)?;
            Ok((Some(v4), Some(v6)))
        }
        IpAddr::V6(_) => {
            let v6 = tproxy_tcp_listener_for_ip(ip, port)?;
            Ok((None, Some(v6)))
        }
    }
}

async fn tcp_accept_loop(listener: TcpListener, state: Arc<AppState>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    let orig_dst = match stream.local_addr() {
                        Ok(addr) => addr,
                        Err(e) => {
                            error!("failed to get local_addr: {:#}", e);
                            return;
                        }
                    };

                    info!("TCP connection: {} -> {}", peer_addr, orig_dst);

                    if let Err(e) = handle_tcp_connection(stream, orig_dst, state).await {
                        error!("tcp {} handling error: {:#}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("failed to accept TCP connection: {:#}", e);
            }
        }
    }
}

fn tproxy_udp_socket_for_ip(ip: IpAddr, port: u16) -> Result<UdpSocket> {
    let sa = SocketAddr::new(ip, port);
    SocketFactory::new().bind_tproxy_udp_socket(sa, if sa.is_ipv6() { Some(true) } else { None })
}

fn create_tproxy_udp_sockets(
    ip: IpAddr,
    port: u16,
) -> Result<(Option<UdpSocket>, Option<UdpSocket>)> {
    match ip {
        IpAddr::V4(_) => {
            let v4 = tproxy_udp_socket_for_ip(ip, port)?;
            Ok((Some(v4), None))
        }
        IpAddr::V6(v6) if v6.is_unspecified() => {
            let v4 = tproxy_udp_socket_for_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)?;
            let v6 = tproxy_udp_socket_for_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)?;
            Ok((Some(v4), Some(v6)))
        }
        IpAddr::V6(_) => {
            let v6 = tproxy_udp_socket_for_ip(ip, port)?;
            Ok((None, Some(v6)))
        }
    }
}

async fn socks5_auth(stream: &mut TcpStream, creds: Option<(&str, &str)>) -> Result<()> {
    if let Some((user, pass)) = creds {
        // 提议方法：0x00（无认证）和 0x02（用户名/密码）
        stream
            .write_all(&[0x05, 0x02, 0x00, 0x02])
            .await
            .context("failed to send SOCKS5 auth methods")?;

        let mut resp = [0u8; 2];
        stream
            .read_exact(&mut resp)
            .await
            .context("failed to read SOCKS5 method selection")?;

        if resp[0] != 0x05 {
            bail!("invalid SOCKS5 version in method selection");
        }

        match resp[1] {
            0x00 => bail!("SOCKS5 server chose no-auth, but username/password required"),
            0x02 => {
                // 执行用户名/密码子协商 (RFC 1929)
                let mut up_req = Vec::with_capacity(3 + user.len() + pass.len());
                up_req.push(0x01); // 子协商版本
                up_req.push(user.len() as u8);
                up_req.extend_from_slice(user.as_bytes());
                up_req.push(pass.len() as u8);
                up_req.extend_from_slice(pass.as_bytes());

                stream
                    .write_all(&up_req)
                    .await
                    .context("failed to send SOCKS5 username/password")?;

                let mut up_resp = [0u8; 2];
                stream
                    .read_exact(&mut up_resp)
                    .await
                    .context("failed to read SOCKS5 username/password reply")?;

                if up_resp[0] != 0x01 || up_resp[1] != 0x00 {
                    bail!("SOCKS5 username/password authentication failed");
                }
            }
            _ => bail!("unsupported SOCKS5 auth method chosen: {:#x}", resp[1]),
        }
    } else {
        // 无认证
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .context("failed to send SOCKS5 no-auth request")?;

        let mut buf = [0u8; 2];
        stream
            .read_exact(&mut buf)
            .await
            .context("failed to read SOCKS5 no-auth response")?;

        if buf != [0x05, 0x00] {
            bail!("SOCKS5 no-auth negotiation failed, got {:?}", buf);
        }
    }
    Ok(())
}

async fn socks5_connect(
    target: Socks5Target<'_>,
    socks5_addr: &str,
    fwmark: u32,
    creds: Option<(&str, &str)>,
) -> Result<TcpStream> {
    let proxy_addr: SocketAddr = socks5_addr
        .parse()
        .map_err(|e| anyhow!("invalid SOCKS5 address '{socks5_addr}': {e}"))?;

    let domain = if proxy_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create socket for SOCKS5 connect")?;

    socket.set_mark(fwmark)?;
    socket.set_nonblocking(true)?;

    match socket.connect(&proxy_addr.into()) {
        Ok(_) => {}
        Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e).context("SOCKS5 connect failed"),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let mut stream = TcpStream::from_std(std_stream)?;

    stream.writable().await?;

    if let Some(e) = stream.take_error()? {
        return Err(e).context("SOCKS5 connect handshake error");
    }

    socks5_auth(&mut stream, creds).await?;

    let mut req = vec![0x05, 0x01, 0x00];

    match target {
        Socks5Target::Ip(SocketAddr::V4(v4)) => {
            req.push(0x01);
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());

            debug!("SOCKS5 connect by IPv4: {}", SocketAddr::V4(v4));
        }
        Socks5Target::Ip(SocketAddr::V6(v6)) => {
            req.push(0x04);
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());

            debug!("SOCKS5 connect by IPv6: {}", SocketAddr::V6(v6));
        }
        Socks5Target::Domain(host, port) => {
            let host_bytes = host.as_bytes();
            if host_bytes.is_empty() || host_bytes.len() > 255 {
                bail!("invalid SOCKS5 domain length: {}", host_bytes.len());
            }

            req.push(0x03);
            req.push(host_bytes.len() as u8);
            req.extend_from_slice(host_bytes);
            req.extend_from_slice(&port.to_be_bytes());

            debug!("SOCKS5 connect by domain: {}:{}", host, port);
        }
    }

    stream
        .write_all(&req)
        .await
        .context("failed to send SOCKS5 connect request")?;

    let mut resp = [0u8; 4];
    stream
        .read_exact(&mut resp)
        .await
        .context("failed to read SOCKS5 connect response")?;

    if resp[1] != 0x00 {
        bail!("SOCKS5 connect failed, reply code {:#x}", resp[1]);
    }

    let skip_len = match resp[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        _ => bail!("invalid SOCKS5 address type in response: {:#x}", resp[3]),
    };

    let mut dummy = vec![0u8; skip_len];
    stream
        .read_exact(&mut dummy)
        .await
        .context("failed to skip SOCKS5 address in response")?;

    Ok(stream)
}

async fn socks5_udp_associate_for_client(
    socks5_addr: &str,
    fwmark: u32,
    creds: Option<(&str, &str)>,
) -> Result<Socks5UdpAssoc> {
    let proxy_addr: SocketAddr = socks5_addr
        .parse()
        .map_err(|e| anyhow!("invalid SOCKS5 address '{socks5_addr}': {e}"))?;

    let domain = if proxy_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let tcp_sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create TCP socket for UDP ASSOCIATE")?;

    tcp_sock.set_mark(fwmark)?;
    tcp_sock.set_nonblocking(true)?;

    match tcp_sock.connect(&proxy_addr.into()) {
        Ok(_) => {}
        Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e).context("SOCKS5 UDP ASSOCIATE connect failed"),
    }

    let std_stream: std::net::TcpStream = tcp_sock.into();
    let mut control = TcpStream::from_std(std_stream)?;

    control.writable().await?;

    if let Some(e) = control.take_error()? {
        return Err(e).context("SOCKS5 UDP ASSOCIATE handshake error");
    }

    socks5_auth(&mut control, creds).await?;

    let req = if proxy_addr.is_ipv4() {
        vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    } else {
        let mut v = vec![0x05, 0x03, 0x00, 0x04];
        v.extend_from_slice(&[0u8; 16]);
        v.extend_from_slice(&[0u8; 2]);
        v
    };

    debug!("SOCKS5 UDP ASSOCIATE req hex = {}", hex_encode(&req));

    control
        .write_all(&req)
        .await
        .context("failed to send SOCKS5 UDP ASSOCIATE request")?;

    let mut head = [0u8; 4];
    control
        .read_exact(&mut head)
        .await
        .context("failed to read SOCKS5 UDP ASSOCIATE reply header")?;

    if head[0] != 0x05 {
        bail!("invalid SOCKS5 version in UDP ASSOCIATE reply");
    }

    if head[1] != 0x00 {
        bail!("SOCKS5 UDP ASSOCIATE failed, reply code {:#x}", head[1]);
    }

    let relay_addr = match head[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            control.read_exact(&mut buf).await?;

            let mut full = Vec::from(head);
            full.extend_from_slice(&buf);

            debug!("SOCKS5 UDP ASSOCIATE resp hex = {}", hex_encode(&full));

            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);

            SocketAddr::new(IpAddr::V4(ip), port)
        }
        0x04 => {
            let mut buf = [0u8; 18];
            control.read_exact(&mut buf).await?;

            let mut full = Vec::from(head);
            full.extend_from_slice(&buf);

            debug!("SOCKS5 UDP ASSOCIATE resp hex = {}", hex_encode(&full));

            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[..16]);

            let port = u16::from_be_bytes([buf[16], buf[17]]);

            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
        }
        0x03 => {
            let mut l = [0u8; 1];
            control.read_exact(&mut l).await?;

            let len = l[0] as usize;
            let mut rest = vec![0u8; len + 2];

            control.read_exact(&mut rest).await?;

            let mut full = Vec::from(head);
            full.extend_from_slice(&l);
            full.extend_from_slice(&rest);

            debug!("SOCKS5 UDP ASSOCIATE resp hex = {}", hex_encode(&full));

            let host = std::str::from_utf8(&rest[..len])
                .context("invalid relay domain name in SOCKS5 UDP ASSOCIATE reply")?;

            let port = u16::from_be_bytes([rest[len], rest[len + 1]]);

            let mut iter = tokio::net::lookup_host((host, port))
                .await
                .context("failed to resolve relay domain")?;

            iter.next()
                .ok_or_else(|| anyhow!("failed to resolve relay domain to an IP address"))?
        }
        _ => bail!(
            "invalid address type in SOCKS5 UDP ASSOCIATE reply: {:#x}",
            head[3]
        ),
    };

    let udp_domain = if relay_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let udp_sock = Socket::new(udp_domain, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create UDP socket for ASSOCIATE")?;

    udp_sock.set_mark(fwmark)?;
    udp_sock.set_nonblocking(true)?;

    if relay_addr.is_ipv4() {
        udp_sock.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).into())?;
    } else {
        udp_sock.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).into())?;
    }

    debug!("connect to SOCKS5 UDP relay_addr: {:?}", relay_addr);

    udp_sock
        .connect(&relay_addr.into())
        .with_context(|| format!("failed to connect to SOCKS5 relay {relay_addr}"))?;

    let std_udp: std::net::UdpSocket = udp_sock.into();
    let udp_socket = Arc::new(UdpSocket::from_std(std_udp)?);

    debug!(
        "SOCKS5 UDP client session created: local={}, relay={}",
        udp_socket.local_addr()?,
        relay_addr
    );

    Ok(Socks5UdpAssoc {
        _control: control,
        relay_addr,
        udp_socket,
    })
}

fn create_direct_udp_socket(target_addr: SocketAddr, fwmark: u32) -> Result<Arc<UdpSocket>> {
    SocketFactory::new().connect_direct_udp(target_addr, fwmark)
}

fn create_fake_udp_socket(src_addr: SocketAddr, fwmark: u32) -> Result<UdpSocket> {
    // 核心：bind 到要伪装成的源地址。
    // 例如返回 DNS 响应时，这里可能是 8.8.8.8:53。
    let std_udp = SocketFactory::new().bind_udp_std(
        src_addr,
        true,
        true,
        if src_addr.is_ipv6() {
            Some(false)
        } else {
            None
        },
        Some(fwmark),
    )?;

    UdpSocket::from_std(std_udp).context("failed to convert fake UDP socket to tokio")
}

async fn create_udp_session(state: Arc<AppState>, spec: UdpSessionSpec) -> Result<Arc<UdpSession>> {
    let key = spec.key;

    let outbound = match spec.routing {
        UdpRoutingMode::Auto => {
            if state.should_direct(key.target_addr.ip()) {
                debug!(
                    "creating direct UDP session: kind={:?}, client={}, target={}",
                    key.kind, key.client_addr, key.target_addr
                );

                let socket = create_direct_udp_socket(key.target_addr, state.config.fwmark)?;

                debug!(
                    "direct UDP socket created: local={}, peer={}",
                    socket.local_addr()?,
                    socket.peer_addr()?
                );

                UdpOutbound::Direct { socket }
            } else {
                debug!(
                    "creating SOCKS5 UDP session: kind={:?}, client={}, target={}",
                    key.kind, key.client_addr, key.target_addr
                );

                let assoc = socks5_udp_associate_for_client(
                    &state.config.socks5_addr,
                    state.config.fwmark,
                    state.socks5_credentials(),
                )
                .await?;

                debug!(
                    "SOCKS5 UDP session created: kind={:?}, client={}, target={}, relay={}, local={}",
                    key.kind,
                    key.client_addr,
                    key.target_addr,
                    assoc.relay_addr,
                    assoc.udp_socket.local_addr()?
                );

                UdpOutbound::Socks5 { assoc }
            }
        }
        UdpRoutingMode::ForceSocks5 => {
            debug!(
                "creating forced SOCKS5 UDP session: kind={:?}, client={}, target={}",
                key.kind, key.client_addr, key.target_addr
            );

            let assoc = socks5_udp_associate_for_client(
                &state.config.socks5_addr,
                state.config.fwmark,
                state.socks5_credentials(),
            )
            .await?;

            debug!(
                "forced SOCKS5 UDP session created: kind={:?}, client={}, target={}, relay={}, local={}",
                key.kind,
                key.client_addr,
                key.target_addr,
                assoc.relay_addr,
                assoc.udp_socket.local_addr()?
            );

            UdpOutbound::Socks5 { assoc }
        }
    };

    let session = Arc::new(UdpSession {
        spec,
        outbound,
        last_seen_secs: AtomicU64::new(now_secs()),
        cancel: CancellationToken::new(),
    });

    let (ready_tx, ready_rx) = oneshot::channel();

    {
        let session = session.clone();
        let state = state.clone();

        tokio::spawn(async move {
            if let Err(e) = run_udp_session_recv_loop(session, state, ready_tx).await {
                warn!("UDP session recv loop exited with error: {:#}", e);
            }
        });
    }

    // 防止首包发送早于 recv loop 初始化。
    ready_rx
        .await
        .map_err(|_| anyhow!("UDP session recv loop exited before ready"))?;

    Ok(session)
}

async fn run_udp_loop(state: Arc<AppState>, tproxy_udp: UdpSocket) -> Result<()> {
    let tproxy_udp = TProxyUdpSocket::new(tproxy_udp);
    let mut buf = new_aligned_udp_buf();

    let mut pending_sniff: HashMap<UdpSessionKey, PendingUdpSniff> = HashMap::new();
    let mut last_pending_reap_secs = now_secs();

    loop {
        let packet = match tproxy_udp.recv_packet(&mut buf).await {
            Ok(packet) => packet,
            Err(e) => {
                warn!("failed to receive TPROXY UDP packet: {:#}", e);
                continue;
            }
        };

        let now = now_secs();
        if now.saturating_sub(last_pending_reap_secs) >= UDP_SNIFF_REAP_INTERVAL_SECS {
            last_pending_reap_secs = now;
            reap_pending_udp_sniff(state.clone(), &mut pending_sniff).await;
        }

        if packet.len == 0 {
            continue;
        }

        let payload = &buf[..packet.len];

        let spec = UdpSessionSpec::for_tproxy(packet.client_addr, packet.orig_dst);

        handle_udp_client_payload(state.clone(), &mut pending_sniff, spec, payload).await;
    }
}

async fn run_udp_session_recv_loop(
    session: Arc<UdpSession>,
    state: Arc<AppState>,
    ready_tx: oneshot::Sender<()>,
) -> Result<()> {
    let key = session.key();

    debug!(
        "UDP session recv loop starting: kind={:?}, client={}, target={}",
        key.kind, key.client_addr, key.target_addr
    );

    match &session.outbound {
        UdpOutbound::Direct { socket } => {
            run_direct_udp_recv_loop(session.clone(), state, socket.clone(), ready_tx).await
        }
        UdpOutbound::Socks5 { assoc } => {
            run_socks5_udp_recv_loop(
                session.clone(),
                state,
                assoc.udp_socket.clone(),
                assoc.relay_addr,
                ready_tx,
            )
            .await
        }
    }
}

async fn run_direct_udp_recv_loop(
    session: Arc<UdpSession>,
    state: Arc<AppState>,
    socket: Arc<UdpSocket>,
    ready_tx: oneshot::Sender<()>,
) -> Result<()> {
    let key = session.key();
    let mut buf = new_aligned_udp_buf();

    debug!(
        "direct UDP recv loop started: kind={:?}, client={}, target={}, local={}, peer={}",
        key.kind,
        key.client_addr,
        key.target_addr,
        socket.local_addr()?,
        socket.peer_addr()?
    );

    let _ = ready_tx.send(());

    loop {
        tokio::select! {
            _ = session.cancel.cancelled() => {
                debug!(
                    "direct UDP recv loop cancelled: kind={:?}, client={}, target={}",
                    key.kind,
                    key.client_addr,
                    key.target_addr
                );
                return Ok(());
            }

            r = socket.recv(&mut buf) => {
                let n = match connected_udp_recv_result(
                    r,
                    "direct",
                    key,
                    None,
                )? {
                    Some(n) => n,
                    None => continue,
                };

                session.touch();

                let payload = &buf[..n];

                debug!(
                    "direct UDP response: kind={:?}, target={}, client={}, payload_len={}",
                    key.kind,
                    key.target_addr,
                    key.client_addr,
                    payload.len()
                );

                session
                    .send_reply(
                        &state,
                        "direct_to_client",
                        key.target_addr,
                        payload,
                        None,
                    )
                    .await;
            }
        }
    }
}

async fn run_socks5_udp_recv_loop(
    session: Arc<UdpSession>,
    state: Arc<AppState>,
    relay_sock: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    ready_tx: oneshot::Sender<()>,
) -> Result<()> {
    let key = session.key();
    let mut buf = new_aligned_udp_buf();

    debug!(
        "SOCKS5 UDP recv loop started: kind={:?}, client={}, target={}, relay={}, local={}",
        key.kind,
        key.client_addr,
        key.target_addr,
        relay_addr,
        relay_sock.local_addr()?
    );

    let _ = ready_tx.send(());

    loop {
        tokio::select! {
            _ = session.cancel.cancelled() => {
                debug!(
                    "SOCKS5 UDP recv loop cancelled: kind={:?}, client={}, target={}",
                    key.kind,
                    key.client_addr,
                    key.target_addr
                );
                return Ok(());
            }

            r = relay_sock.recv(&mut buf) => {
                let n = match connected_udp_recv_result(
                    r,
                    "socks5",
                    key,
                    Some(relay_addr),
                )? {
                    Some(n) => n,
                    None => continue,
                };

                session.touch();

                trace!(
                    "SOCKS5 UDP raw recv: kind={:?}, client={}, target={}, relay={}, local={}, packet_len={}, head={}",
                    key.kind,
                    key.client_addr,
                    key.target_addr,
                    relay_addr,
                    relay_sock.local_addr().unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
                    n,
                    hex_encode(&buf[..n.min(80)])
                );

                let (remote_src, payload) = match parse_socks5_udp_packet_with_fallback_src(&buf[..n], key.target_addr) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(
                            "invalid SOCKS5 UDP packet: kind={:?}, client={}, target={}, relay={}, packet_len={}, error={:#}",
                            key.kind,
                            key.client_addr,
                            key.target_addr,
                            relay_addr,
                            n,
                            e
                        );
                        continue;
                    }
                };

                let client_visible_src = match &session.spec.reply_path {
                    UdpReplyPath::Tproxy => {
                        // TPROXY 必须让客户端看到“原始目标地址”作为回包源。
                        //
                        // 特别是 SOCKS5 UDP 使用 domain ATYP 时，relay 可能解析到不同 IP；
                        // 如果把 relay 回包头里的 remote_src 直接伪造成源地址，
                        // QUIC 客户端会认为 peer 地址不匹配而丢包。
                        key.target_addr
                    }
                    UdpReplyPath::PortForward { .. } => {
                        // port-forward 是客户端发给本地监听 socket，
                        // 回包源地址由本地 listen_sock 决定；这里仅用于日志。
                        remote_src
                    }
                };

                debug!(
                    "SOCKS5 UDP response: kind={:?}, relay_remote_src={}, client_visible_src={}, client={}, payload_len={}",
                    key.kind,
                    remote_src,
                    client_visible_src,
                    key.client_addr,
                    payload.len()
                );

                session
                    .send_reply(
                        &state,
                        "socks5_to_client",
                        client_visible_src,
                        payload,
                        Some(relay_addr),
                    )
                    .await;
            }
        }
    }
}

async fn run_udp_gc_loop(state: Arc<AppState>) {
    let interval = Duration::from_secs(10);

    loop {
        tokio::time::sleep(interval).await;

        state.udp_runtime.cleanup_expired_sessions().await;

        state
            .udp_runtime
            .fake_udp
            .cleanup_expired(state.udp_runtime.timeout)
            .await;
    }
}

async fn run_tcp_port_forward(
    listen_addr: SocketAddr,
    remote: SocketAddr,
    state: Arc<AppState>,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind port-forward TCP {listen_addr} failed"))?;

    info!(
        "port-forward TCP: listening on {}, forwarding to {} via SOCKS5",
        listen_addr, remote
    );

    loop {
        let (mut client, peer_addr) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            info!("port-forward TCP: {} -> {} via SOCKS5", peer_addr, remote);

            let target = TcpUpstreamTarget::Socks5Ip(remote);

            let mut upstream = match connect_tcp_upstream(
                &target,
                &state.config.socks5_addr,
                state.config.fwmark,
                state.socks5_credentials(),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "port-forward TCP upstream connect failed: remote={}, target={:?}, error={:#}",
                        remote, target, e
                    );
                    return;
                }
            };

            if let Err(e) =
                splice_or_copy_bidirectional(state.config.splice, &mut client, &mut upstream).await
            {
                error!("port-forward TCP relay error: {:#}", e);
            }
        });
    }
}

async fn run_udp_port_forward(
    listen_addr: SocketAddr,
    remote: SocketAddr,
    state: Arc<AppState>,
) -> Result<()> {
    let listen_sock = SocketFactory::new().bind_port_forward_udp_listener(listen_addr)?;

    info!(
        "port-forward UDP: listening on {}, forwarding to {} via SOCKS5",
        listen_addr, remote
    );

    let mut buf = new_aligned_udp_buf();
    let mut pending_sniff: HashMap<UdpSessionKey, PendingUdpSniff> = HashMap::new();
    let mut last_pending_reap_secs = now_secs();

    loop {
        let (n, client_addr) = listen_sock.recv_from(&mut buf).await?;

        let now = now_secs();
        if now.saturating_sub(last_pending_reap_secs) >= UDP_SNIFF_REAP_INTERVAL_SECS {
            last_pending_reap_secs = now;
            reap_pending_udp_sniff(state.clone(), &mut pending_sniff).await;
        }

        if n == 0 {
            continue;
        }

        let payload = &buf[..n];

        let spec =
            UdpSessionSpec::for_port_forward(listen_addr, client_addr, remote, listen_sock.clone());

        handle_udp_client_payload(state.clone(), &mut pending_sniff, spec, payload).await;
    }
}

enum Socks5UdpTarget<'a> {
    Ip(SocketAddr),
    Domain { host: &'a str, port: u16 },
}

fn build_socks5_udp_packet(target: Socks5UdpTarget<'_>, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 1 + 255 + 2 + payload.len());

    out.extend_from_slice(&[0x00, 0x00, 0x00]);

    match target {
        Socks5UdpTarget::Ip(SocketAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        Socks5UdpTarget::Ip(SocketAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
        Socks5UdpTarget::Domain { host, port } => {
            let host = host.as_bytes();

            // 调用方已校验 hostname，这里只做 SOCKS5 协议长度保护。
            if host.is_empty() || host.len() > 255 {
                out.clear();
                return out;
            }

            out.push(0x03);
            out.push(host.len() as u8);
            out.extend_from_slice(host);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }

    out.extend_from_slice(payload);

    out
}

fn parse_socks5_udp_packet_with_fallback_src(
    pkt: &[u8],
    fallback_src: SocketAddr,
) -> Result<(SocketAddr, &[u8])> {
    if pkt.len() < 4 {
        bail!("SOCKS5 UDP packet too short");
    }

    if pkt[0] != 0x00 || pkt[1] != 0x00 {
        bail!("invalid SOCKS5 UDP reserved fields");
    }

    if pkt[2] != 0x00 {
        bail!("fragmented SOCKS5 UDP not supported");
    }

    let atyp = pkt[3];
    let mut off = 4;

    let src = match atyp {
        0x01 => {
            if pkt.len() < off + 4 + 2 {
                bail!("short IPv4 SOCKS5 UDP packet");
            }

            let ip = Ipv4Addr::new(pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]);
            off += 4;

            let port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            off += 2;

            SocketAddr::new(IpAddr::V4(ip), port)
        }
        0x04 => {
            if pkt.len() < off + 16 + 2 {
                bail!("short IPv6 SOCKS5 UDP packet");
            }

            let mut ip = [0u8; 16];
            ip.copy_from_slice(&pkt[off..off + 16]);
            off += 16;

            let port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            off += 2;

            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
        }
        0x03 => {
            if pkt.len() < off + 1 {
                bail!("short domain SOCKS5 UDP packet");
            }

            let name_len = pkt[off] as usize;
            off += 1;

            if pkt.len() < off + name_len + 2 {
                bail!("short domain SOCKS5 UDP packet address");
            }

            // 不需要解析 domain 内容；TPROXY 场景回客户端必须使用原始目标地址。
            // port 也不可信，直接使用 fallback_src 更符合透明代理语义。
            off += name_len;

            let _port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            off += 2;

            fallback_src
        }
        _ => bail!("invalid SOCKS5 UDP address type: {:#x}", atyp),
    };

    Ok((src, &pkt[off..]))
}

fn is_must_direct_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_must_direct_local_ipv4(ip),
        IpAddr::V6(ip) => is_must_direct_local_ipv6(ip),
    }
}

fn is_must_direct_local_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_unspecified()
}

fn is_must_direct_local_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_unicast_link_local()
}

fn is_io_emsgsize(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::EMSGSIZE)
}

fn is_anyhow_emsgsize(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(is_io_emsgsize)
            .unwrap_or(false)
    })
}

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::new();

    for (i, b) in data.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }

        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }

    s
}

fn connected_udp_recv_result(
    r: std::io::Result<usize>,
    direction: &'static str,
    key: UdpSessionKey,
    relay_addr: Option<SocketAddr>,
) -> Result<Option<usize>> {
    match r {
        Ok(0) => Ok(None),
        Ok(n) => Ok(Some(n)),
        Err(e) if is_io_emsgsize(&e) => {
            warn!(
                "UDP recv got EMSGSIZE, ignored: direction={}, kind={:?}, client={}, target={}, relay={:?}, error={}",
                direction, key.kind, key.client_addr, key.target_addr, relay_addr, e
            );

            Ok(None)
        }
        Err(e) => Err(e).with_context(|| format!("{direction} UDP recv failed")),
    }
}

fn new_aligned_udp_buf() -> AVec<u8, RuntimeAlign> {
    let mut buf = AVec::<u8, RuntimeAlign>::with_capacity(UDP_BUF_ALIGN, UDP_RECV_BUF_SIZE);
    buf.resize(UDP_RECV_BUF_SIZE, 0);
    buf
}

async fn splice_or_copy_bidirectional(
    splice: bool,
    client: &mut TcpStream,
    upstream: &mut TcpStream,
) -> Result<(u64, u64)> {
    if splice {
        tokio_splice::zero_copy_bidirectional(client, upstream)
            .await
            .map_err(|e| anyhow!("splice error: {}", e))
    } else {
        tokio::io::copy_bidirectional(client, upstream)
            .await
            .map_err(Into::into)
    }
}

fn unspecified_addr_for(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

struct SocketFactory;

impl SocketFactory {
    fn new() -> Self {
        Self
    }

    fn domain_for(addr: SocketAddr) -> Domain {
        if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        }
    }

    fn udp_socket(&self, addr: SocketAddr) -> Result<Socket> {
        Socket::new(Self::domain_for(addr), Type::DGRAM, Some(Protocol::UDP))
            .context("failed to create UDP socket")
    }

    fn tcp_socket(&self, addr: SocketAddr) -> Result<Socket> {
        Socket::new(Self::domain_for(addr), Type::STREAM, Some(Protocol::TCP))
            .context("failed to create TCP socket")
    }

    fn enable_orig_dst(&self, socket: &Socket, addr: SocketAddr) -> Result<()> {
        if addr.is_ipv4() {
            enable_orig_dst_v4(socket).context("failed to set IP_RECVORIGDSTADDR")?;
        } else {
            enable_orig_dst_v6(socket).context("failed to set IPV6_RECVORIGDSTADDR")?;
        }

        Ok(())
    }

    fn apply_socket_options(
        &self,
        socket: &Socket,
        addr: SocketAddr,
        reuse_addr: bool,
        transparent: bool,
        only_v6: Option<bool>,
        mark: Option<u32>,
    ) -> Result<()> {
        if transparent {
            if addr.is_ipv4() {
                socket.set_ip_transparent_v4(true)?;
            } else {
                socket.set_ip_transparent_v6(true)?;
            }
        }

        if let Some(v) = only_v6
            && addr.is_ipv6()
        {
            socket.set_only_v6(v)?;
        }

        if reuse_addr {
            set_socket_reuse(socket)?;
        }

        if let Some(fwmark) = mark {
            socket.set_mark(fwmark)?;
        }

        Ok(())
    }

    fn bind_udp_std(
        &self,
        addr: SocketAddr,
        reuse_addr: bool,
        transparent: bool,
        only_v6: Option<bool>,
        mark: Option<u32>,
    ) -> Result<std::net::UdpSocket> {
        let socket = self.udp_socket(addr)?;
        self.apply_socket_options(&socket, addr, reuse_addr, transparent, only_v6, mark)?;
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        Ok(socket.into())
    }

    fn bind_tcp_listener(
        &self,
        addr: SocketAddr,
        reuse_addr: bool,
        transparent: bool,
        only_v6: Option<bool>,
        backlog: i32,
    ) -> Result<TcpListener> {
        let socket = self.tcp_socket(addr)?;
        self.apply_socket_options(&socket, addr, reuse_addr, transparent, only_v6, None)?;
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        socket.listen(backlog)?;
        TcpListener::from_std(socket.into()).context("failed to convert to tokio TCP listener")
    }

    fn bind_tproxy_udp_socket(&self, addr: SocketAddr, only_v6: Option<bool>) -> Result<UdpSocket> {
        let socket = self.udp_socket(addr)?;
        self.apply_socket_options(&socket, addr, true, true, only_v6, None)?;
        self.enable_orig_dst(&socket, addr)?;
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        UdpSocket::from_std(socket.into()).context("failed to convert to tokio UDP socket")
    }

    fn connect_direct_udp(&self, target_addr: SocketAddr, fwmark: u32) -> Result<Arc<UdpSocket>> {
        let bind_addr = unspecified_addr_for(target_addr);
        let socket = self.udp_socket(bind_addr)?;
        self.apply_socket_options(&socket, bind_addr, false, false, None, Some(fwmark))?;
        socket.set_nonblocking(true)?;
        socket.bind(&bind_addr.into())?;
        socket
            .connect(&target_addr.into())
            .with_context(|| format!("failed to connect direct UDP socket to {target_addr}"))?;

        let std_udp: std::net::UdpSocket = socket.into();
        Ok(Arc::new(UdpSocket::from_std(std_udp)?))
    }

    fn bind_port_forward_udp_listener(&self, addr: SocketAddr) -> Result<Arc<UdpSocket>> {
        let socket = self.udp_socket(addr)?;
        self.apply_socket_options(&socket, addr, true, false, None, None)?;
        socket.set_nonblocking(true)?;
        socket
            .bind(&addr.into())
            .with_context(|| format!("bind port-forward UDP to {addr}"))?;
        Ok(Arc::new(UdpSocket::from_std(socket.into())?))
    }
}

const QUIC_SNI_INPUT_CAP: usize = 16 * 1024;
const QUIC_CRYPTO_REASSEMBLY_CAP: usize = 32 * 1024;

const QUIC_VERSION_V1: u32 = 0x0000_0001;
const QUIC_VERSION_DRAFT29: u32 = 0xff00_001d;

const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

const QUIC_DRAFT29_INITIAL_SALT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpSniffError {
    ProtocolNotMatched,
    InsufficientPrefix,
    NoTarget,
    ParseError,
    InvalidHostname,
    TooLarge,
}

impl From<TlsSniffError> for UdpSniffError {
    fn from(err: TlsSniffError) -> Self {
        match err {
            TlsSniffError::PeekEmpty => UdpSniffError::InsufficientPrefix,
            TlsSniffError::InsufficientPrefix => UdpSniffError::InsufficientPrefix,
            TlsSniffError::ProtocolNotMatched => UdpSniffError::ProtocolNotMatched,
            TlsSniffError::TlsNoSni => UdpSniffError::NoTarget,
            TlsSniffError::ParseError => UdpSniffError::ParseError,
            TlsSniffError::InvalidHostname => UdpSniffError::InvalidHostname,
            TlsSniffError::TooLargeClientHello => UdpSniffError::TooLarge,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpSniffProtocol {
    QuicSni,
}

#[derive(Debug)]
enum UdpSniffOutcome {
    Matched {
        protocol: UdpSniffProtocol,
        host: String,
    },
    NotMatched,
    NeedMore {
        protocol: UdpSniffProtocol,
    },
    Failed {
        protocol: UdpSniffProtocol,
        error: UdpSniffError,
    },
}

struct UdpSniffer {
    quic_sni: bool,
}

impl UdpSniffer {
    fn from_config(config: &Config) -> Option<Self> {
        if config.sniff_quic_sni {
            Some(Self { quic_sni: true })
        } else {
            None
        }
    }

    fn protocol_name(protocol: UdpSniffProtocol) -> &'static str {
        match protocol {
            UdpSniffProtocol::QuicSni => "quic_sni",
        }
    }

    fn error_reason(error: UdpSniffError) -> &'static str {
        match error {
            UdpSniffError::ProtocolNotMatched => "protocol_not_matched",
            UdpSniffError::InsufficientPrefix => "insufficient_prefix",
            UdpSniffError::NoTarget => "no_target",
            UdpSniffError::ParseError => "parse_error",
            UdpSniffError::InvalidHostname => "invalid_hostname",
            UdpSniffError::TooLarge => "too_large",
        }
    }

    fn new_session(&self) -> UdpSnifferSession {
        UdpSnifferSession {
            quic_sni: self.quic_sni,
            quic_crypto: QuicCryptoReassembly::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct QuicInitialKeys {
    hp_key: [u8; 16],
    key: [u8; 16],
    iv: [u8; 12],
}

fn quic_initial_salt(version: u32) -> Option<&'static [u8; 20]> {
    match version {
        QUIC_VERSION_V1 => Some(&QUIC_V1_INITIAL_SALT),
        QUIC_VERSION_DRAFT29 => Some(&QUIC_DRAFT29_INITIAL_SALT),
        _ => None,
    }
}

fn hkdf_expand_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    out: &mut [u8],
) -> Result<(), UdpSniffError> {
    let hk = Hkdf::<Sha256>::from_prk(secret).map_err(|_| UdpSniffError::ParseError)?;

    let full_label = {
        let mut v = Vec::with_capacity("tls13 ".len() + label.len());
        v.extend_from_slice(b"tls13 ");
        v.extend_from_slice(label.as_bytes());
        v
    };

    if full_label.len() > u8::MAX as usize || context.len() > u8::MAX as usize {
        return Err(UdpSniffError::ParseError);
    }

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    hk.expand(&info, out).map_err(|_| UdpSniffError::ParseError)
}

fn hkdf_expand_label_from_hkdf(
    hk: &Hkdf<Sha256>,
    label: &str,
    context: &[u8],
    out: &mut [u8],
) -> Result<(), UdpSniffError> {
    let full_label = {
        let mut v = Vec::with_capacity("tls13 ".len() + label.len());
        v.extend_from_slice(b"tls13 ");
        v.extend_from_slice(label.as_bytes());
        v
    };

    if full_label.len() > u8::MAX as usize || context.len() > u8::MAX as usize {
        return Err(UdpSniffError::ParseError);
    }

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    hk.expand(&info, out).map_err(|_| UdpSniffError::ParseError)
}

fn derive_quic_initial_keys(version: u32, dcid: &[u8]) -> Result<QuicInitialKeys, UdpSniffError> {
    let salt = quic_initial_salt(version).ok_or(UdpSniffError::ProtocolNotMatched)?;

    let (_, initial_hk) = Hkdf::<Sha256>::extract(Some(salt), dcid);

    let mut initial_secret = [0u8; 32];
    hkdf_expand_label_from_hkdf(&initial_hk, "client in", &[], &mut initial_secret)?;

    let mut hp_key = [0u8; 16];
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];

    hkdf_expand_label(&initial_secret, "quic hp", &[], &mut hp_key)?;
    hkdf_expand_label(&initial_secret, "quic key", &[], &mut key)?;
    hkdf_expand_label(&initial_secret, "quic iv", &[], &mut iv)?;

    Ok(QuicInitialKeys { hp_key, key, iv })
}

fn quic_read_u32(buf: &[u8], off: usize) -> Result<u32, UdpSniffError> {
    if off + 4 > buf.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    Ok(u32::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

fn quic_varint_len(first: u8) -> usize {
    match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    }
}

fn quic_read_varint(buf: &[u8], off: &mut usize) -> Result<u64, UdpSniffError> {
    let first = *buf.get(*off).ok_or(UdpSniffError::InsufficientPrefix)?;

    let len = quic_varint_len(first);

    if *off + len > buf.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let mut value = (first & 0x3f) as u64;

    for b in &buf[*off + 1..*off + len] {
        value = (value << 8) | (*b as u64);
    }

    *off += len;

    Ok(value)
}

struct QuicCryptoReassembly {
    buf: Vec<u8>,
    present: Vec<bool>,
    contiguous_len: usize,
}

impl QuicCryptoReassembly {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            present: Vec::new(),
            contiguous_len: 0,
        }
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), UdpSniffError> {
        let end = offset
            .checked_add(data.len())
            .ok_or(UdpSniffError::TooLarge)?;

        if end > QUIC_CRYPTO_REASSEMBLY_CAP {
            return Err(UdpSniffError::TooLarge);
        }

        if self.buf.len() < end {
            self.buf.resize(end, 0);
            self.present.resize(end, false);
        }

        self.buf[offset..end].copy_from_slice(data);

        for p in &mut self.present[offset..end] {
            *p = true;
        }

        while self.contiguous_len < self.present.len() && self.present[self.contiguous_len] {
            self.contiguous_len += 1;
        }

        Ok(())
    }

    fn contiguous(&self) -> &[u8] {
        &self.buf[..self.contiguous_len]
    }
}

fn quic_build_nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn = packet_number.to_be_bytes();

    for i in 0..8 {
        nonce[12 - 8 + i] ^= pn[i];
    }

    nonce
}

fn quic_parse_tls_client_hello_from_crypto(crypto: &[u8]) -> Result<String, UdpSniffError> {
    if crypto.len() < 4 {
        trace!(
            "QUIC crypto insufficient: contiguous_len={}, need handshake header",
            crypto.len()
        );
        return Err(UdpSniffError::InsufficientPrefix);
    }

    if crypto[0] != 0x01 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    let hs_len = be_u24(&crypto[1..4]).map_err(|_| UdpSniffError::ParseError)?;
    let total = 4usize.checked_add(hs_len).ok_or(UdpSniffError::TooLarge)?;

    trace!(
        "QUIC crypto ClientHello progress: contiguous_len={}, needed_total={}",
        crypto.len(),
        total
    );

    if total > QUIC_CRYPTO_REASSEMBLY_CAP {
        return Err(UdpSniffError::TooLarge);
    }

    if crypto.len() < total {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let body = &crypto[4..total];

    parse_sni_from_client_hello_body(body).map_err(Into::into)
}

fn quic_remove_header_protection_and_decrypt(
    packet: &[u8],
    packet_start: usize,
    pn_offset: usize,
    packet_end: usize,
    keys: &QuicInitialKeys,
) -> Result<Vec<u8>, UdpSniffError> {
    if pn_offset + 4 + 16 > packet.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    if packet_end > packet.len() || packet_end <= pn_offset {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let sample = &packet[pn_offset + 4..pn_offset + 4 + 16];

    let hp_cipher = Aes128::new_from_slice(&keys.hp_key).map_err(|_| UdpSniffError::ParseError)?;

    let mut block = Block::<Aes128>::default();
    block.copy_from_slice(sample);

    hp_cipher.encrypt_block(&mut block);

    let mask: &[u8] = block.as_ref();

    let first_unprotected = packet[packet_start] ^ (mask[0] & 0x0f);
    let pn_len = ((first_unprotected & 0x03) + 1) as usize;

    if pn_len == 0 || pn_len > 4 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    if pn_offset + pn_len > packet_end {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let mut pn_bytes = [0u8; 4];

    for i in 0..pn_len {
        pn_bytes[4 - pn_len + i] = packet[pn_offset + i] ^ mask[1 + i];
    }

    let packet_number = u32::from_be_bytes(pn_bytes) as u64;

    let mut header = Vec::with_capacity(pn_offset - packet_start + pn_len);
    header.extend_from_slice(&packet[packet_start..pn_offset]);
    header[0] = first_unprotected;

    for i in 0..pn_len {
        header.push(packet[pn_offset + i] ^ mask[1 + i]);
    }

    let ciphertext = &packet[pn_offset + pn_len..packet_end];

    if ciphertext.len() < 16 {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let nonce = quic_build_nonce(&keys.iv, packet_number);

    let aead = Aes128Gcm::new_from_slice(&keys.key).map_err(|_| UdpSniffError::ParseError)?;

    aead.decrypt(
        Nonce::from_slice(&nonce),
        AeadPayload {
            msg: ciphertext,
            aad: &header,
        },
    )
    .map_err(|_| UdpSniffError::ProtocolNotMatched)
}

fn quic_skip_ack_frame(
    frame_type: u64,
    frames: &[u8],
    off: &mut usize,
) -> Result<(), UdpSniffError> {
    let _largest_acknowledged = quic_read_varint(frames, off)?;
    let _ack_delay = quic_read_varint(frames, off)?;
    let ack_range_count = quic_read_varint(frames, off)?;
    let _first_ack_range = quic_read_varint(frames, off)?;

    for _ in 0..ack_range_count {
        let _gap = quic_read_varint(frames, off)?;
        let _ack_range_length = quic_read_varint(frames, off)?;
    }

    if frame_type == 0x03 {
        let _ect0 = quic_read_varint(frames, off)?;
        let _ect1 = quic_read_varint(frames, off)?;
        let _ce = quic_read_varint(frames, off)?;
    }

    Ok(())
}

fn quic_skip_connection_close_frame(frames: &[u8], off: &mut usize) -> Result<(), UdpSniffError> {
    let _error_code = quic_read_varint(frames, off)?;
    let _frame_type = quic_read_varint(frames, off)?;
    let reason_len = quic_read_varint(frames, off)? as usize;

    if *off + reason_len > frames.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    *off += reason_len;

    Ok(())
}

fn quic_parse_initial_frames(
    frames: &[u8],
    crypto: &mut QuicCryptoReassembly,
) -> Result<(), UdpSniffError> {
    let mut off = 0usize;

    while off < frames.len() {
        let frame_type = quic_read_varint(frames, &mut off)?;

        match frame_type {
            0x00 => {
                // PADDING
            }
            0x01 => {
                // PING
            }
            0x02 | 0x03 => {
                quic_skip_ack_frame(frame_type, frames, &mut off)?;
            }
            0x06 => {
                let crypto_offset = quic_read_varint(frames, &mut off)? as usize;
                let crypto_len = quic_read_varint(frames, &mut off)? as usize;

                if off + crypto_len > frames.len() {
                    return Err(UdpSniffError::InsufficientPrefix);
                }

                crypto.write(crypto_offset, &frames[off..off + crypto_len])?;
                off += crypto_len;
            }
            0x1c => {
                quic_skip_connection_close_frame(frames, &mut off)?;
            }
            _ => {
                return Err(UdpSniffError::ProtocolNotMatched);
            }
        }
    }

    Ok(())
}

fn quic_parse_one_initial_packet(
    datagram: &[u8],
    packet_start: usize,
    crypto: &mut QuicCryptoReassembly,
) -> Result<usize, UdpSniffError> {
    if packet_start >= datagram.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let first = datagram[packet_start];

    if first & 0x80 == 0 || first & 0x40 == 0 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    // Long Header packet type. For QUIC v1:
    // 00 = Initial, 01 = 0-RTT, 10 = Handshake, 11 = Retry.
    let packet_type = (first & 0x30) >> 4;
    if packet_type != 0 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    let mut off = packet_start + 1;

    let version = quic_read_u32(datagram, off)?;
    off += 4;

    if quic_initial_salt(version).is_none() {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    let dcid_len = *datagram.get(off).ok_or(UdpSniffError::InsufficientPrefix)? as usize;
    off += 1;

    if dcid_len > 20 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    if off + dcid_len > datagram.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let dcid = &datagram[off..off + dcid_len];
    off += dcid_len;

    let scid_len = *datagram.get(off).ok_or(UdpSniffError::InsufficientPrefix)? as usize;
    off += 1;

    if scid_len > 20 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    if off + scid_len > datagram.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    off += scid_len;

    // Initial token field.
    let token_len = quic_read_varint(datagram, &mut off)? as usize;

    if off + token_len > datagram.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    off += token_len;

    // Length includes packet number and protected payload.
    let protected_len = quic_read_varint(datagram, &mut off)? as usize;

    if protected_len == 0 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    let pn_offset = off;

    let packet_end = pn_offset
        .checked_add(protected_len)
        .ok_or(UdpSniffError::TooLarge)?;

    if packet_end > datagram.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let keys = derive_quic_initial_keys(version, dcid)?;

    let plaintext = quic_remove_header_protection_and_decrypt(
        datagram,
        packet_start,
        pn_offset,
        packet_end,
        &keys,
    )?;

    quic_parse_initial_frames(&plaintext, crypto)?;

    Ok(packet_end)
}

fn sniff_quic_sni_from_datagram_with_reassembly(
    datagram: &[u8],
    crypto: &mut QuicCryptoReassembly,
) -> Result<String, UdpSniffError> {
    if datagram.is_empty() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let datagram = &datagram[..datagram.len().min(QUIC_SNI_INPUT_CAP)];

    let first = datagram[0];

    if first & 0x80 == 0 || first & 0x40 == 0 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    let mut off = 0usize;
    let mut saw_initial = false;

    while off < datagram.len() {
        match quic_parse_one_initial_packet(datagram, off, crypto) {
            Ok(next_off) => {
                saw_initial = true;
                off = next_off;

                match quic_parse_tls_client_hello_from_crypto(crypto.contiguous()) {
                    Ok(host) => return Ok(host),
                    Err(UdpSniffError::InsufficientPrefix) => {
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(UdpSniffError::ProtocolNotMatched) if saw_initial => {
                // Coalesced datagram 后面可能跟非 Initial 包。
                break;
            }
            Err(e) => return Err(e),
        }
    }

    if saw_initial {
        Err(UdpSniffError::InsufficientPrefix)
    } else {
        Err(UdpSniffError::ProtocolNotMatched)
    }
}

struct UdpSnifferSession {
    quic_sni: bool,
    quic_crypto: QuicCryptoReassembly,
}

impl UdpSnifferSession {
    fn feed(&mut self, payload: &[u8]) -> UdpSniffOutcome {
        if self.quic_sni {
            return match sniff_quic_sni_from_datagram_with_reassembly(
                payload,
                &mut self.quic_crypto,
            ) {
                Ok(host) => UdpSniffOutcome::Matched {
                    protocol: UdpSniffProtocol::QuicSni,
                    host,
                },
                Err(UdpSniffError::ProtocolNotMatched) => UdpSniffOutcome::NotMatched,
                Err(UdpSniffError::InsufficientPrefix) => UdpSniffOutcome::NeedMore {
                    protocol: UdpSniffProtocol::QuicSni,
                },
                Err(error) => UdpSniffOutcome::Failed {
                    protocol: UdpSniffProtocol::QuicSni,
                    error,
                },
            };
        }

        UdpSniffOutcome::NotMatched
    }
}

const UDP_SNIFF_TIMEOUT_SECS: u64 = 5;
const UDP_SNIFF_MAX_CACHED_DATAGRAMS: usize = 8;
const UDP_SNIFF_MAX_CACHED_BYTES: usize = 64 * 1024;

struct PendingUdpSniff {
    started_secs: u64,
    spec: UdpSessionSpec,
    sniffer: UdpSnifferSession,
    datagrams: Vec<Vec<u8>>,
    cached_bytes: usize,
}

impl PendingUdpSniff {
    fn new(spec: UdpSessionSpec, sniffer: UdpSnifferSession, first_payload: &[u8]) -> Self {
        Self {
            started_secs: now_secs(),
            spec,
            sniffer,
            datagrams: vec![first_payload.to_vec()],
            cached_bytes: first_payload.len(),
        }
    }

    fn push_datagram(&mut self, payload: &[u8]) -> bool {
        let next_bytes = self.cached_bytes.saturating_add(payload.len());

        if self.datagrams.len() >= UDP_SNIFF_MAX_CACHED_DATAGRAMS {
            return false;
        }

        if next_bytes > UDP_SNIFF_MAX_CACHED_BYTES {
            return false;
        }

        self.datagrams.push(payload.to_vec());
        self.cached_bytes = next_bytes;

        true
    }

    fn expired(&self) -> bool {
        now_secs().saturating_sub(self.started_secs) >= UDP_SNIFF_TIMEOUT_SECS
    }
}

async fn forward_udp_payload(state: Arc<AppState>, spec: UdpSessionSpec, payload: &[u8]) {
    let key = spec.key;

    let session = match state
        .udp_runtime
        .get_or_create_udp_session(state.clone(), spec)
        .await
    {
        Ok(session) => session,
        Err(e) => {
            warn!(
                "failed to get/create UDP session: kind={:?}, client={}, target={}, error={:#}",
                key.kind, key.client_addr, key.target_addr, e
            );
            return;
        }
    };

    session.touch();

    match session.send_payload(payload).await {
        Ok(sent) => {
            if sent == 0 {
                debug!(
                    "UDP packet dropped before forwarding: kind={:?}, client={}, target={}, payload_len={}, sent=0",
                    key.kind,
                    key.client_addr,
                    key.target_addr,
                    payload.len()
                );
            } else {
                debug!(
                    "UDP packet forwarded: kind={:?}, client={}, target={}, payload_len={}, sent={}",
                    key.kind,
                    key.client_addr,
                    key.target_addr,
                    payload.len(),
                    sent
                );
            }
        }
        Err(e) => {
            warn!(
                "failed to forward UDP packet: kind={:?}, client={}, target={}, error={:#}",
                key.kind, key.client_addr, key.target_addr, e
            );
        }
    }
}

async fn flush_pending_udp_sniff(state: Arc<AppState>, pending: PendingUdpSniff) {
    let spec = pending.spec;

    for payload in pending.datagrams {
        forward_udp_payload(state.clone(), spec.clone(), &payload).await;
    }
}

async fn forward_udp_payload_to_session(session: Arc<UdpSession>, payload: &[u8]) {
    let key = session.key();

    session.touch();

    match session.send_payload(payload).await {
        Ok(sent) => {
            if sent == 0 {
                debug!(
                    "UDP packet dropped before forwarding: kind={:?}, client={}, target={}, payload_len={}, sent=0",
                    key.kind,
                    key.client_addr,
                    key.target_addr,
                    payload.len()
                );
            } else {
                debug!(
                    "UDP packet forwarded: kind={:?}, client={}, target={}, payload_len={}, sent={}",
                    key.kind,
                    key.client_addr,
                    key.target_addr,
                    payload.len(),
                    sent
                );
            }
        }
        Err(e) => {
            warn!(
                "failed to forward UDP packet: kind={:?}, client={}, target={}, error={:#}",
                key.kind, key.client_addr, key.target_addr, e
            );
        }
    }
}

async fn handle_udp_client_payload(
    state: Arc<AppState>,
    pending_sniff: &mut HashMap<UdpSessionKey, PendingUdpSniff>,
    spec: UdpSessionSpec,
    payload: &[u8],
) {
    let key = spec.key;

    if let Some(session) = state.udp_runtime.get_ready_udp_session(key).await {
        pending_sniff.remove(&key);

        debug!(
            "UDP existing session hit, skip sniff: kind={:?}, client={}, target={}, payload_len={}",
            key.kind,
            key.client_addr,
            key.target_addr,
            payload.len()
        );

        forward_udp_payload_to_session(session, payload).await;
        return;
    }

    // 已有 pending：继续跨 datagram 重组。
    if let Some(mut pending) = pending_sniff.remove(&key) {
        if pending.expired() {
            debug!(
                "UDP sniff pending expired: kind={:?}, client={}, target={}",
                key.kind, key.client_addr, key.target_addr
            );

            flush_pending_udp_sniff(state.clone(), pending).await;
            forward_udp_payload(state, spec, payload).await;
            return;
        }

        if !pending.push_datagram(payload) {
            debug!(
                "UDP sniff pending too large: kind={:?}, client={}, target={}",
                key.kind, key.client_addr, key.target_addr
            );

            flush_pending_udp_sniff(state.clone(), pending).await;
            forward_udp_payload(state, spec, payload).await;
            return;
        }

        match pending.sniffer.feed(payload) {
            UdpSniffOutcome::Matched { protocol, host } => {
                debug!(
                    "UDP sniff success after reassembly: protocol={}, kind={:?}, client={}, target={}, host={}",
                    UdpSniffer::protocol_name(protocol),
                    key.kind,
                    key.client_addr,
                    key.target_addr,
                    host
                );

                pending.spec.sniffed_host = Some(host);
                flush_pending_udp_sniff(state, pending).await;
            }
            UdpSniffOutcome::NeedMore { protocol } => {
                debug!(
                    "UDP sniff still need more: protocol={}, kind={:?}, client={}, target={}, payload_len={}",
                    UdpSniffer::protocol_name(protocol),
                    key.kind,
                    key.client_addr,
                    key.target_addr,
                    payload.len()
                );

                pending_sniff.insert(key, pending);
                enforce_pending_udp_sniff_capacity(pending_sniff);
            }
            UdpSniffOutcome::NotMatched => {
                debug!(
                    "UDP sniff pending not matched: kind={:?}, client={}, target={}",
                    key.kind, key.client_addr, key.target_addr
                );

                flush_pending_udp_sniff(state, pending).await;
            }
            UdpSniffOutcome::Failed { protocol, error } => {
                debug!(
                    "UDP sniff pending failed: protocol={}, reason={}, kind={:?}, client={}, target={}",
                    UdpSniffer::protocol_name(protocol),
                    UdpSniffer::error_reason(error),
                    key.kind,
                    key.client_addr,
                    key.target_addr
                );

                flush_pending_udp_sniff(state, pending).await;
            }
        }

        return;
    }

    // 没有 pending：首包尝试 sniff。
    if let Some(sniffer) = state.udp_sniffer.as_deref() {
        let target_ip_direct = matches!(spec.routing, UdpRoutingMode::Auto)
            && state.should_direct(spec.key.target_addr.ip());

        if !target_ip_direct {
            let mut sniff_session = sniffer.new_session();

            match sniff_session.feed(payload) {
                UdpSniffOutcome::Matched { protocol, host } => {
                    let mut spec = spec;

                    debug!(
                        "UDP sniff success: protocol={}, kind={:?}, client={}, target={}, host={}",
                        UdpSniffer::protocol_name(protocol),
                        key.kind,
                        key.client_addr,
                        key.target_addr,
                        host
                    );

                    spec.sniffed_host = Some(host);
                    forward_udp_payload(state, spec, payload).await;
                    return;
                }
                UdpSniffOutcome::NeedMore { protocol } => {
                    debug!(
                        "UDP sniff need more, pending created: protocol={}, kind={:?}, client={}, target={}, payload_len={}",
                        UdpSniffer::protocol_name(protocol),
                        key.kind,
                        key.client_addr,
                        key.target_addr,
                        payload.len()
                    );

                    let pending = PendingUdpSniff::new(spec, sniff_session, payload);
                    pending_sniff.insert(key, pending);
                    enforce_pending_udp_sniff_capacity(pending_sniff);
                    return;
                }
                UdpSniffOutcome::NotMatched => {
                    debug!(
                        "UDP sniff not matched: kind={:?}, client={}, target={}",
                        key.kind, key.client_addr, key.target_addr
                    );
                }
                UdpSniffOutcome::Failed { protocol, error } => {
                    debug!(
                        "UDP sniff failed: protocol={}, reason={}, kind={:?}, client={}, target={}",
                        UdpSniffer::protocol_name(protocol),
                        UdpSniffer::error_reason(error),
                        key.kind,
                        key.client_addr,
                        key.target_addr
                    );
                }
            }
        }
    }

    // 未启用 sniff / 直连 / 非 QUIC / sniff 失败，正常转发。
    forward_udp_payload(state, spec, payload).await;
}

const UDP_SNIFF_MAX_PENDING_SESSIONS: usize = 4096;
const UDP_SNIFF_REAP_INTERVAL_SECS: u64 = 1;

async fn reap_pending_udp_sniff(
    state: Arc<AppState>,
    pending_sniff: &mut HashMap<UdpSessionKey, PendingUdpSniff>,
) {
    let now = now_secs();

    let expired_keys: Vec<UdpSessionKey> = pending_sniff
        .iter()
        .filter_map(|(key, pending)| {
            if now.saturating_sub(pending.started_secs) >= UDP_SNIFF_TIMEOUT_SECS {
                Some(*key)
            } else {
                None
            }
        })
        .collect();

    for key in expired_keys {
        if let Some(pending) = pending_sniff.remove(&key) {
            debug!(
                "UDP sniff pending expired by reap: kind={:?}, client={}, target={}, cached_datagrams={}, cached_bytes={}",
                key.kind,
                key.client_addr,
                key.target_addr,
                pending.datagrams.len(),
                pending.cached_bytes
            );

            flush_pending_udp_sniff(state.clone(), pending).await;
        }
    }

    while pending_sniff.len() > UDP_SNIFF_MAX_PENDING_SESSIONS {
        let oldest_key = pending_sniff
            .iter()
            .min_by_key(|(_, pending)| pending.started_secs)
            .map(|(key, _)| *key);

        let Some(oldest_key) = oldest_key else {
            break;
        };

        if let Some(pending) = pending_sniff.remove(&oldest_key) {
            warn!(
                "UDP sniff pending overflow, dropping oldest: kind={:?}, client={}, target={}, cached_datagrams={}, cached_bytes={}, pending_len={}",
                oldest_key.kind,
                oldest_key.client_addr,
                oldest_key.target_addr,
                pending.datagrams.len(),
                pending.cached_bytes,
                pending_sniff.len()
            );

            // 超限时建议 drop，不 flush，避免攻击流量制造大量 UDP sessions。
            drop(pending);
        }
    }
}

fn enforce_pending_udp_sniff_capacity(
    pending_sniff: &mut HashMap<UdpSessionKey, PendingUdpSniff>,
) {
    while pending_sniff.len() > UDP_SNIFF_MAX_PENDING_SESSIONS {
        let oldest_key = pending_sniff
            .iter()
            .min_by_key(|(_, pending)| pending.started_secs)
            .map(|(key, _)| *key);

        let Some(oldest_key) = oldest_key else {
            break;
        };

        if let Some(pending) = pending_sniff.remove(&oldest_key) {
            warn!(
                "UDP sniff pending overflow, dropping oldest immediately: kind={:?}, client={}, target={}, cached_datagrams={}, cached_bytes={}, pending_len={}",
                oldest_key.kind,
                oldest_key.client_addr,
                oldest_key.target_addr,
                pending.datagrams.len(),
                pending.cached_bytes,
                pending_sniff.len()
            );

            drop(pending);
        }
    }
}
