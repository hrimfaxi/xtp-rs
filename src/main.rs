use aligned_vec::{AVec, RuntimeAlign};
use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
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
use tracing::{debug, error, info, warn};

const UDP_RECV_BUF_SIZE: usize = 65_536;
const UDP_BUF_ALIGN: usize = 4096;

#[derive(Parser)]
#[command(name = "xtp-rs", about = "XTP-RS - Transparent TCP/UDP proxy splitter")]
struct Cli {
    /// 配置文件路径
    #[arg(short = 'c', long, default_value = "xtp-rs.toml")]
    config: String,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum PortForwardProto {
    Tcp,
    Udp,
    Both,
}

#[derive(Deserialize, Clone)]
struct PortForward {
    name: Option<String>,
    bind: String,
    remote: String,
    proto: PortForwardProto,
}

#[derive(Deserialize, Clone)]
struct Config {
    #[serde(default = "default_listen")]
    listen: String,

    #[serde(default = "default_udp")]
    udp: bool,

    #[serde(default = "default_socks5_addr")]
    socks5_addr: String,

    #[serde(default)]
    socks5_user: Option<String>,

    #[serde(default)]
    socks5_password: Option<String>,

    #[serde(default = "default_fwmark")]
    fwmark: u32,

    #[serde(default = "default_mmdb_path")]
    mmdb_path: String,

    #[serde(default = "default_udp_session_timeout_secs")]
    udp_session_timeout_secs: u64,

    log_level: Option<String>,

    #[serde(default)]
    port_forward: Vec<PortForward>,
}

fn default_listen() -> String {
    "[::]:10810".to_string()
}

fn default_udp() -> bool {
    true
}

fn default_socks5_addr() -> String {
    "127.0.0.1:20808".to_string()
}

fn default_fwmark() -> u32 {
    2
}

fn default_mmdb_path() -> String {
    "Country-only-cn-private.mmdb".to_string()
}

fn default_udp_session_timeout_secs() -> u64 {
    60
}

struct AppState {
    mmdb: Arc<Reader<Vec<u8>>>,
    config: Config,
    udp_runtime: Arc<UdpRuntime>,
}

impl AppState {
    fn should_direct(&self, ip: IpAddr) -> bool {
        is_must_direct_local_ip(ip) || self.is_china_ip(ip)
    }

    fn is_china_ip(&self, ip: IpAddr) -> bool {
        let result = match self.mmdb.lookup(ip) {
            Ok(r) => r,
            Err(_) => return false,
        };

        let country = match result.decode::<Country>() {
            Ok(Some(c)) => c,
            _ => return false,
        };

        country
            .country
            .iso_code
            .map(|code| code == "CN")
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
                let pkt = build_socks5_udp_packet(key.target_addr, payload);

                debug!(
                    "UDP SOCKS5 send: kind={:?}, client={}, target={}, payload_len={}, pkt_len={}, relay={}",
                    key.kind,
                    key.client_addr,
                    key.target_addr,
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

    let mmdb_data = tokio::fs::read(&config.mmdb_path)
        .await
        .with_context(|| format!("failed to read MMDB file {}", config.mmdb_path))?;
    let mmdb = Reader::from_source(mmdb_data).context("invalid MMDB data")?;

    info!("MMDB loaded from {}", config.mmdb_path);

    let udp_runtime = Arc::new(UdpRuntime::new(Duration::from_secs(
        config.udp_session_timeout_secs,
    )));

    let (listen_ip, listen_port) =
        parse_listen_addr(&config.listen).context("invalid listen address")?;

    let state = Arc::new(AppState {
        mmdb: Arc::new(mmdb),
        config,
        udp_runtime,
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

        match pf.proto {
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

async fn handle_tcp_connection(
    mut client: TcpStream,
    orig_dst: SocketAddr,
    state: Arc<AppState>,
) -> Result<()> {
    let direct = state.should_direct(orig_dst.ip());

    let mut upstream = if direct {
        debug!("direct connect to {}", orig_dst);
        direct_connect(orig_dst, state.config.fwmark).await?
    } else {
        debug!("proxy connect to {}", orig_dst);
        socks5_connect(
            orig_dst,
            &state.config.socks5_addr,
            state.config.fwmark,
            state.socks5_credentials(),
        )
        .await?
    };

    let (a, b) = tokio_splice::zero_copy_bidirectional(&mut client, &mut upstream).await?;

    debug!(
        "tcp finished, client->upstream={} bytes, upstream->client={} bytes",
        a, b
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
    orig_dst: SocketAddr,
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

    match orig_dst {
        SocketAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.ip().octets());
        }
    }

    req.extend_from_slice(&orig_dst.port().to_be_bytes());

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

    loop {
        let packet = match tproxy_udp.recv_packet(&mut buf).await {
            Ok(packet) => packet,
            Err(e) => {
                warn!("failed to receive TPROXY UDP packet: {:#}", e);
                continue;
            }
        };

        if packet.len == 0 {
            continue;
        }

        let payload = &buf[..packet.len];

        let spec = UdpSessionSpec::for_tproxy(packet.client_addr, packet.orig_dst);

        let session = match state
            .udp_runtime
            .get_or_create_udp_session(state.clone(), spec)
            .await
        {
            Ok(session) => session,
            Err(e) => {
                warn!(
                    "failed to get/create UDP session: kind={:?}, client={}, target={}, error={:#}",
                    UdpSessionKind::Tproxy,
                    packet.client_addr,
                    packet.orig_dst,
                    e
                );
                continue;
            }
        };

        session.touch();

        match session.send_payload(payload).await {
            Ok(sent) => {
                if sent == 0 {
                    debug!(
                        "UDP packet dropped before forwarding: kind={:?}, client={}, target={}, payload_len={}, sent=0",
                        UdpSessionKind::Tproxy,
                        packet.client_addr,
                        packet.orig_dst,
                        payload.len()
                    );
                } else {
                    debug!(
                        "UDP packet forwarded: kind={:?}, client={}, target={}, payload_len={}, sent={}",
                        UdpSessionKind::Tproxy,
                        packet.client_addr,
                        packet.orig_dst,
                        payload.len(),
                        sent
                    );
                }
            }
            Err(e) => {
                warn!(
                    "failed to forward UDP packet: kind={:?}, client={}, target={}, error={:#}",
                    UdpSessionKind::Tproxy,
                    packet.client_addr,
                    packet.orig_dst,
                    e
                );
            }
        }
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

                let (remote_src, payload) = match parse_socks5_udp_packet(&buf[..n]) {
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

                debug!(
                    "SOCKS5 UDP response: kind={:?}, remote_src={}, client={}, payload_len={}",
                    key.kind,
                    remote_src,
                    key.client_addr,
                    payload.len()
                );

                session
                    .send_reply(
                        &state,
                        "socks5_to_client",
                        remote_src,
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

            let mut upstream = match socks5_connect(
                remote,
                &state.config.socks5_addr,
                state.config.fwmark,
                state.socks5_credentials(),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    error!("port-forward TCP SOCKS5 connect to {remote}: {:#}", e);
                    return;
                }
            };

            if let Err(e) = tokio_splice::zero_copy_bidirectional(&mut client, &mut upstream).await
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

    loop {
        let (n, client_addr) = listen_sock.recv_from(&mut buf).await?;
        if n == 0 {
            continue;
        }

        let payload = &buf[..n];

        let spec =
            UdpSessionSpec::for_port_forward(listen_addr, client_addr, remote, listen_sock.clone());

        let session = match state
            .udp_runtime
            .get_or_create_udp_session(state.clone(), spec)
            .await
        {
            Ok(session) => session,
            Err(e) => {
                warn!(
                    "failed to get/create UDP port-forward session: client={}, remote={}, error={:#}",
                    client_addr, remote, e
                );
                continue;
            }
        };

        session.touch();

        if let Err(e) = session.send_payload(payload).await {
            warn!(
                "port-forward UDP send error: client={}, remote={}, error={:#}",
                client_addr, remote, e
            );
        }
    }
}

fn build_socks5_udp_packet(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 1 + 18 + payload.len());

    out.extend_from_slice(&[0x00, 0x00, 0x00]);

    match dst {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    out.extend_from_slice(payload);

    out
}

fn parse_socks5_udp_packet(pkt: &[u8]) -> Result<(SocketAddr, &[u8])> {
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

    let dst = match atyp {
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
            bail!("domain name in SOCKS5 UDP response not supported");
        }
        _ => bail!("invalid SOCKS5 UDP address type: {:#x}", atyp),
    };

    Ok((dst, &pkt[off..]))
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
            .map(|ioe| is_io_emsgsize(ioe))
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
    let mut buf = AVec::<u8, RuntimeAlign>::with_capacity(UDP_BUF_ALIGN.into(), UDP_RECV_BUF_SIZE);
    buf.resize(UDP_RECV_BUF_SIZE, 0);
    buf
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

        if let Some(v) = only_v6 {
            if addr.is_ipv6() {
                socket.set_only_v6(v)?;
            }
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
