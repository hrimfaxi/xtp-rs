use clap::Parser;
use maxminddb::Reader;
use maxminddb::geoip2::Country;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, Notify, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

#[derive(Parser)]
#[command(name = "xtp-rs", about = "XTP-RS - Transparent TCP/UDP proxy splitter")]
struct Cli {
    /// 配置文件路径
    #[arg(short = 'c', long, default_value = "xtp-rs.toml")]
    config: String,
}

#[derive(Deserialize, Clone)]
struct Config {
    #[serde(default = "default_listen_addr")]
    listen_addr: String,

    #[serde(default = "default_listen_port")]
    listen_port: u16,

    #[serde(default = "default_udp_listen_port")]
    udp_listen_port: u16,

    #[serde(default = "default_socks5_addr")]
    socks5_addr: String,

    #[serde(default = "default_fwmark")]
    fwmark: u32,

    #[serde(default = "default_mmdb_path")]
    mmdb_path: String,

    #[serde(default = "default_udp_session_timeout_secs")]
    udp_session_timeout_secs: u64,

    log_level: Option<String>,
}

fn default_listen_addr() -> String {
    "::".to_string()
}

fn default_listen_port() -> u16 {
    10810
}

fn default_udp_listen_port() -> u16 {
    10810
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpSessionKey {
    client_addr: SocketAddr,
    orig_dst: SocketAddr,
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
        key: UdpSessionKey,
    ) -> io::Result<Arc<UdpSession>> {
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
                        "UDP session is being created, waiting: client={}, orig_dst={}",
                        key.client_addr, key.orig_dst
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

        let created = create_udp_session(state.clone(), key).await;

        let mut sessions = self.sessions.lock().await;

        match created {
            Ok(session) => {
                sessions.insert(key, UdpSessionEntry::Ready(session.clone()));
                creating_notify.notify_waiters();

                info!(
                    "created UDP session: client={}, orig_dst={}",
                    key.client_addr, key.orig_dst
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
        let now = Instant::now();
        let timeout = self.timeout;

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
            let last_seen = *session.last_seen.lock().await;

            if now.duration_since(last_seen) >= timeout {
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
                    "UDP session expired and cancelled: client={}, orig_dst={}",
                    key.client_addr, key.orig_dst
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
    last_used: Instant,
}

struct FakeUdpManager {
    sockets: Mutex<HashMap<FakeUdpKey, FakeUdpEntry>>,
}

impl FakeUdpManager {
    fn new() -> Self {
        Self {
            sockets: Mutex::new(HashMap::new()),
        }
    }

    async fn get_or_create(&self, src_addr: SocketAddr, fwmark: u32) -> io::Result<Arc<UdpSocket>> {
        let key = FakeUdpKey { src_addr, fwmark };
        let now = Instant::now();

        {
            let mut sockets = self.sockets.lock().await;
            if let Some(entry) = sockets.get_mut(&key) {
                entry.last_used = now;
                return Ok(entry.socket.clone());
            }
        }

        let socket = Arc::new(create_fake_udp_socket(src_addr, fwmark)?);

        {
            let mut sockets = self.sockets.lock().await;

            if let Some(entry) = sockets.get_mut(&key) {
                entry.last_used = now;
                return Ok(entry.socket.clone());
            }

            sockets.insert(
                key,
                FakeUdpEntry {
                    socket: socket.clone(),
                    last_used: now,
                },
            );
        }

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
    ) -> io::Result<usize> {
        let socket = self.get_or_create(src_addr, fwmark).await?;

        debug!(
            "fake UDP send: spoofed_src={}, dst={}, payload_len={}",
            src_addr,
            dst_addr,
            payload.len()
        );

        socket.send_to(payload, dst_addr).await
    }

    async fn cleanup_expired(&self, timeout: Duration) {
        let now = Instant::now();
        let mut sockets = self.sockets.lock().await;

        sockets.retain(|key, entry| {
            let alive = now.duration_since(entry.last_used) < timeout;

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

struct UdpSession {
    key: UdpSessionKey,
    outbound: UdpOutbound,
    last_seen: Mutex<Instant>,
    cancel: CancellationToken,
}

enum UdpOutbound {
    Direct { socket: Arc<UdpSocket> },
    Socks5 { assoc: Socks5UdpAssoc },
}

impl UdpSession {
    async fn touch(&self) {
        *self.last_seen.lock().await = Instant::now();
    }

    async fn send_payload(&self, payload: &[u8]) -> io::Result<usize> {
        match &self.outbound {
            UdpOutbound::Direct { socket } => socket.send(payload).await,
            UdpOutbound::Socks5 { assoc } => {
                let pkt = build_socks5_udp_packet(self.key.orig_dst, payload);

                debug!(
                    "UDP SOCKS5 send: client={}, orig_dst={}, payload_len={}, pkt_len={}, relay={}",
                    self.key.client_addr,
                    self.key.orig_dst,
                    payload.len(),
                    pkt.len(),
                    assoc.relay_addr
                );

                assoc.udp_socket.send(&pkt).await
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

impl TProxyUdpSocket {
    fn new(socket: UdpSocket) -> Self {
        let fd = socket.as_raw_fd();

        Self {
            socket: Arc::new(socket),
            fd,
        }
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<TProxyUdpPacketMeta> {
        loop {
            self.socket.readable().await?;

            let result = self.socket.try_io(Interest::READABLE, || {
                let (len, client_addr, orig_dst) = Self::recv_udp_tproxy_packet_raw(self.fd, buf)?;

                let orig_dst = orig_dst.ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidData,
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
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn recv_udp_tproxy_packet_raw(
        fd: i32,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
        // `cmsghdr` / ancillary data 要求按机器字长对齐。
        // 普通 `[u8; N]` 的 alignment 只有 1，严格来说不适合作为 `msg_control`。
        #[repr(C, align(8))]
        struct CmsgAlignedBuffer([u8; 512]);

        unsafe {
            let mut name: libc::sockaddr_storage = zeroed();

            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut _,
                iov_len: buf.len(),
            };

            let mut cmsg_buf = CmsgAlignedBuffer([0u8; 512]);

            let mut msg: libc::msghdr = zeroed();

            msg.msg_name = &mut name as *mut _ as *mut _;
            msg.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
            msg.msg_iov = &mut iov as *mut _;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.0.as_mut_ptr() as *mut _;
            msg.msg_controllen = cmsg_buf.0.len();

            let n = libc::recvmsg(fd, &mut msg, 0);

            if n < 0 {
                return Err(io::Error::last_os_error());
            }

            if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "udp control message truncated",
                ));
            }

            let client_addr = sockaddr_to_socketaddr(&name, msg.msg_namelen)
                .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid peer sockaddr"))?;

            debug!(
                "udp recvmsg: n={}, client_addr={}, msg_controllen={}",
                n, client_addr, msg.msg_controllen
            );

            let mut orig_dst = None;

            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);

            while !cmsg.is_null() {
                let level = (*cmsg).cmsg_level;
                let ty = (*cmsg).cmsg_type;
                let len = (*cmsg).cmsg_len;

                debug!("udp cmsg: level={}, type={}, len={}", level, ty, len);

                if level == libc::SOL_IP && ty == libc::IP_ORIGDSTADDR {
                    let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                    let sa = *data;

                    let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                    let port = u16::from_be(sa.sin_port);

                    orig_dst = Some(SocketAddr::new(IpAddr::V4(ip), port));

                    debug!("udp orig_dst(v4)={}", orig_dst.unwrap());

                    break;
                }

                #[cfg(target_os = "linux")]
                {
                    if level == libc::SOL_IPV6 && ty == libc::IPV6_ORIGDSTADDR {
                        let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
                        let sa6 = *data;

                        let ip = Ipv6Addr::from(sa6.sin6_addr.s6_addr);
                        let port = u16::from_be(sa6.sin6_port);

                        orig_dst = Some(SocketAddr::new(IpAddr::V6(ip), port));

                        debug!("udp orig_dst(v6)={}", orig_dst.unwrap());

                        break;
                    }
                }

                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }

            Ok((n as usize, client_addr, orig_dst))
        }
    }
}

#[derive(Debug)]
struct Socks5UdpAssoc {
    // SOCKS5 UDP ASSOCIATE 的 control TCP。
    // 必须持有到 UDP 会话结束，否则符合规范的服务端会释放 UDP relay。
    _control: TcpStream,
    relay_addr: SocketAddr,
    udp_socket: Arc<UdpSocket>,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let config_str = tokio::fs::read_to_string(&cli.config)
        .await
        .map_err(|e| io::Error::other(format!("failed to read config: {e}")))?;

    let config: Config = toml::from_str(&config_str)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("invalid config: {e}")))?;

    let env_filter = if let Some(ref level) = config.log_level {
        tracing_subscriber::EnvFilter::new(level)
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())
    };

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    debug!("xtp-rs started");

    let mmdb_data = tokio::fs::read(&config.mmdb_path).await?;
    let mmdb = Reader::from_source(mmdb_data)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("invalid MMDB: {e}")))?;

    info!("MMDB loaded from {}", config.mmdb_path);

    let udp_runtime = Arc::new(UdpRuntime::new(Duration::from_secs(
        config.udp_session_timeout_secs,
    )));

    let state = Arc::new(AppState {
        mmdb: Arc::new(mmdb),
        config,
        udp_runtime,
    });

    let tcp_listener = tproxy_tcp_listener(&state.config.listen_addr, state.config.listen_port)?;

    info!(
        "TPROXY TCP listening on {}:{}",
        state.config.listen_addr, state.config.listen_port
    );

    let udp_sock = tproxy_udp_socket(&state.config.listen_addr, state.config.udp_listen_port)?;

    info!(
        "TPROXY UDP listening on {}:{}",
        state.config.listen_addr, state.config.udp_listen_port
    );

    {
        let state = state.clone();
        tokio::spawn(async move {
            run_udp_gc_loop(state).await;
        });
    }

    {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_udp_loop(state, udp_sock).await {
                error!("udp loop error: {}", e);
            }
        });
    }

    loop {
        let (stream, peer_addr) = tcp_listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            let orig_dst = match stream.local_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    error!("failed to get local_addr: {}", e);
                    return;
                }
            };

            info!("TCP connection: {} -> {}", peer_addr, orig_dst);

            if let Err(e) = handle_tcp_connection(stream, orig_dst, state).await {
                error!("tcp {} handling error: {}", peer_addr, e);
            }
        });
    }
}

async fn handle_tcp_connection(
    mut client: TcpStream,
    orig_dst: SocketAddr,
    state: Arc<AppState>,
) -> io::Result<()> {
    let direct = state.should_direct(orig_dst.ip());

    let mut upstream = if direct {
        debug!("direct connect to {}", orig_dst);
        direct_connect(orig_dst, state.config.fwmark).await?
    } else {
        debug!("proxy connect to {}", orig_dst);
        socks5_connect(orig_dst, &state.config.socks5_addr, state.config.fwmark).await?
    };

    let (a, b) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;

    debug!(
        "tcp finished, client->upstream={} bytes, upstream->client={} bytes",
        a, b
    );

    Ok(())
}

async fn direct_connect(orig_dst: SocketAddr, fwmark: u32) -> io::Result<TcpStream> {
    let domain = if orig_dst.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_mark(fwmark)?;
    socket.set_nonblocking(true)?;

    match socket.connect(&orig_dst.into()) {
        Ok(_) => {}
        Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;

    stream.writable().await?;

    if let Some(e) = stream.take_error()? {
        return Err(e);
    }

    Ok(stream)
}

fn tproxy_tcp_listener(addr: &str, port: u16) -> io::Result<TcpListener> {
    let ip: IpAddr = addr
        .parse()
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;

    let sa = SocketAddr::new(ip, port);

    let domain = if sa.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    if sa.is_ipv4() {
        socket.set_ip_transparent_v4(true)?;
    } else {
        socket.set_ip_transparent_v6(true)?;
        socket.set_only_v6(false)?;

        let one: libc::c_int = 1;

        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_IPV6,
                libc::IPV6_RECVORIGDSTADDR,
                &one as *const _ as *const _,
                size_of::<libc::c_int>() as _,
            )
        };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&sa.into())?;
    socket.listen(1024)?;

    TcpListener::from_std(socket.into())
}

fn tproxy_udp_socket(addr: &str, port: u16) -> io::Result<UdpSocket> {
    let ip: IpAddr = addr
        .parse()
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;

    let sa = SocketAddr::new(ip, port);

    let domain = if sa.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    if sa.is_ipv4() {
        socket.set_ip_transparent_v4(true)?;

        let one: libc::c_int = 1;

        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_IP,
                libc::IP_RECVORIGDSTADDR,
                &one as *const _ as *const _,
                size_of::<libc::c_int>() as _,
            )
        };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    } else {
        socket.set_ip_transparent_v6(true)?;
        socket.set_only_v6(false)?;

        let one: libc::c_int = 1;

        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_IPV6,
                libc::IPV6_RECVORIGDSTADDR,
                &one as *const _ as *const _,
                size_of::<libc::c_int>() as _,
            )
        };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&sa.into())?;

    let std_sock: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_sock)
}

async fn socks5_connect(
    orig_dst: SocketAddr,
    socks5_addr: &str,
    fwmark: u32,
) -> io::Result<TcpStream> {
    let proxy_addr: SocketAddr = socks5_addr
        .parse()
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;

    let domain = if proxy_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_mark(fwmark)?;
    socket.set_nonblocking(true)?;

    match socket.connect(&proxy_addr.into()) {
        Ok(_) => {}
        Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let mut stream = TcpStream::from_std(std_stream)?;

    stream.writable().await?;

    if let Some(e) = stream.take_error()? {
        return Err(e);
    }

    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    if buf != [0x05, 0x00] {
        return Err(io::Error::new(
            ErrorKind::ConnectionRefused,
            "SOCKS5 auth negotiation failed",
        ));
    }

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

    stream.write_all(&req).await?;

    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp).await?;

    if resp[1] != 0x00 {
        return Err(io::Error::new(
            ErrorKind::ConnectionRefused,
            format!("SOCKS5 connect failed, rep={:#x}", resp[1]),
        ));
    }

    let skip_len = match resp[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid SOCKS5 atyp in response",
            ));
        }
    };

    let mut dummy = vec![0u8; skip_len];
    stream.read_exact(&mut dummy).await?;

    Ok(stream)
}

async fn socks5_udp_associate_for_client(
    socks5_addr: &str,
    fwmark: u32,
) -> io::Result<Socks5UdpAssoc> {
    let proxy_addr: SocketAddr = socks5_addr
        .parse()
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;

    let domain = if proxy_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let tcp_sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    tcp_sock.set_mark(fwmark)?;
    tcp_sock.set_nonblocking(true)?;

    match tcp_sock.connect(&proxy_addr.into()) {
        Ok(_) => {}
        Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }

    let std_stream: std::net::TcpStream = tcp_sock.into();
    let mut control = TcpStream::from_std(std_stream)?;

    control.writable().await?;

    if let Some(e) = control.take_error()? {
        return Err(e);
    }

    let auth_req = [0x05, 0x01, 0x00];

    debug!("SOCKS5 UDP auth req hex = {}", hex_encode(&auth_req));

    control.write_all(&auth_req).await?;

    let mut meth = [0u8; 2];
    control.read_exact(&mut meth).await?;

    debug!("SOCKS5 UDP auth resp hex = {}", hex_encode(&meth));

    if meth != [0x05, 0x00] {
        return Err(io::Error::new(
            ErrorKind::ConnectionRefused,
            "SOCKS5 auth negotiation failed for UDP ASSOCIATE",
        ));
    }

    let req = if proxy_addr.is_ipv4() {
        vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    } else {
        let mut v = vec![0x05, 0x03, 0x00, 0x04];
        v.extend_from_slice(&[0u8; 16]);
        v.extend_from_slice(&[0u8; 2]);
        v
    };

    debug!("SOCKS5 UDP ASSOCIATE req hex = {}", hex_encode(&req));

    control.write_all(&req).await?;

    let mut head = [0u8; 4];
    control.read_exact(&mut head).await?;

    if head[0] != 0x05 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid SOCKS5 version in UDP ASSOCIATE reply",
        ));
    }

    if head[1] != 0x00 {
        return Err(io::Error::new(
            ErrorKind::ConnectionRefused,
            format!("SOCKS5 UDP ASSOCIATE failed, rep={:#x}", head[1]),
        ));
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
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid relay domain utf8"))?;

            let port = u16::from_be_bytes([rest[len], rest[len + 1]]);

            let mut iter = tokio::net::lookup_host((host, port)).await?;

            iter.next().ok_or_else(|| {
                io::Error::new(
                    ErrorKind::AddrNotAvailable,
                    "failed to resolve relay domain",
                )
            })?
        }
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid SOCKS5 UDP ASSOCIATE atyp",
            ));
        }
    };

    let udp_domain = if relay_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let udp_sock = Socket::new(udp_domain, Type::DGRAM, Some(Protocol::UDP))?;

    udp_sock.set_mark(fwmark)?;
    udp_sock.set_nonblocking(true)?;

    if relay_addr.is_ipv4() {
        udp_sock.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).into())?;
    } else {
        udp_sock.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).into())?;
    }

    debug!("connect to SOCKS5 UDP relay_addr: {:?}", relay_addr);

    udp_sock.connect(&relay_addr.into())?;

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

fn create_direct_udp_socket(orig_dst: SocketAddr, fwmark: u32) -> io::Result<Arc<UdpSocket>> {
    let domain = if orig_dst.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_mark(fwmark)?;
    socket.set_nonblocking(true)?;

    if orig_dst.is_ipv4() {
        socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).into())?;
    } else {
        socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).into())?;
    }

    socket.connect(&orig_dst.into())?;

    let std_udp: std::net::UdpSocket = socket.into();

    Ok(Arc::new(UdpSocket::from_std(std_udp)?))
}

fn create_fake_udp_socket(src_addr: SocketAddr, fwmark: u32) -> io::Result<UdpSocket> {
    let domain = if src_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    if src_addr.is_ipv4() {
        socket.set_ip_transparent_v4(true)?;
    } else {
        socket.set_ip_transparent_v6(true)?;
        socket.set_only_v6(false)?;
    }

    socket.set_mark(fwmark)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    // 核心：bind 到要伪装成的源地址。
    // 例如返回 DNS 响应时，这里可能是 8.8.8.8:53。
    socket.bind(&src_addr.into())?;

    let std_udp: std::net::UdpSocket = socket.into();

    UdpSocket::from_std(std_udp)
}

async fn create_udp_session(
    state: Arc<AppState>,
    key: UdpSessionKey,
) -> io::Result<Arc<UdpSession>> {
    let direct = state.should_direct(key.orig_dst.ip());

    let outbound = if direct {
        debug!(
            "creating direct UDP session: client={}, orig_dst={}",
            key.client_addr, key.orig_dst
        );

        let socket = create_direct_udp_socket(key.orig_dst, state.config.fwmark)?;

        debug!(
            "direct UDP socket created: local={}, peer={}",
            socket.local_addr()?,
            socket.peer_addr()?
        );

        UdpOutbound::Direct { socket }
    } else {
        debug!(
            "creating SOCKS5 UDP session: client={}, orig_dst={}",
            key.client_addr, key.orig_dst
        );

        let assoc =
            socks5_udp_associate_for_client(&state.config.socks5_addr, state.config.fwmark).await?;

        debug!(
            "SOCKS5 UDP session created: client={}, orig_dst={}, relay={}, local={}",
            key.client_addr,
            key.orig_dst,
            assoc.relay_addr,
            assoc.udp_socket.local_addr()?
        );

        UdpOutbound::Socks5 { assoc }
    };

    let session = Arc::new(UdpSession {
        key,
        outbound,
        last_seen: Mutex::new(Instant::now()),
        cancel: CancellationToken::new(),
    });

    let (ready_tx, ready_rx) = oneshot::channel();

    {
        let session = session.clone();
        let state = state.clone();

        tokio::spawn(async move {
            if let Err(e) = run_udp_session_recv_loop(session, state, ready_tx).await {
                warn!("UDP session recv loop exited with error: {}", e);
            }
        });
    }

    // 防止首包发送早于 recv loop 初始化。
    ready_rx.await.map_err(|_| {
        io::Error::new(
            ErrorKind::BrokenPipe,
            "UDP session recv loop exited before ready",
        )
    })?;

    Ok(session)
}

async fn run_udp_loop(state: Arc<AppState>, tproxy_udp: UdpSocket) -> io::Result<()> {
    let tproxy_udp = TProxyUdpSocket::new(tproxy_udp);
    let mut buf = vec![0u8; 65535];

    loop {
        let packet = match tproxy_udp.recv_packet(&mut buf).await {
            Ok(packet) => packet,
            Err(e) => {
                warn!("failed to receive TPROXY UDP packet: {}", e);
                continue;
            }
        };

        if packet.len == 0 {
            continue;
        }

        let payload = &buf[..packet.len];

        let key = UdpSessionKey {
            client_addr: packet.client_addr,
            orig_dst: packet.orig_dst,
        };

        let session = match state
            .udp_runtime
            .get_or_create_udp_session(state.clone(), key)
            .await
        {
            Ok(session) => session,
            Err(e) => {
                warn!(
                    "failed to get/create UDP session: client={}, orig_dst={}, error={}",
                    packet.client_addr, packet.orig_dst, e
                );
                continue;
            }
        };

        session.touch().await;

        match session.send_payload(payload).await {
            Ok(sent) => {
                debug!(
                    "UDP packet forwarded: client={}, orig_dst={}, payload_len={}, sent={}",
                    packet.client_addr,
                    packet.orig_dst,
                    payload.len(),
                    sent
                );
            }
            Err(e) => {
                warn!(
                    "failed to forward UDP packet: client={}, orig_dst={}, error={}",
                    packet.client_addr, packet.orig_dst, e
                );
            }
        }
    }
}

async fn run_udp_session_recv_loop(
    session: Arc<UdpSession>,
    state: Arc<AppState>,
    ready_tx: oneshot::Sender<()>,
) -> io::Result<()> {
    let key = session.key;

    debug!(
        "UDP session recv loop starting: client={}, orig_dst={}",
        key.client_addr, key.orig_dst
    );

    // socket 已经创建/connect 完毕。
    // 通知 run_udp_loop 可以发首包。
    let _ = ready_tx.send(());

    match &session.outbound {
        UdpOutbound::Direct { socket } => {
            run_direct_udp_recv_loop(session.clone(), state, socket.clone()).await
        }
        UdpOutbound::Socks5 { assoc } => {
            run_socks5_udp_recv_loop(
                session.clone(),
                state,
                assoc.udp_socket.clone(),
                assoc.relay_addr,
            )
            .await
        }
    }
}

async fn run_direct_udp_recv_loop(
    session: Arc<UdpSession>,
    state: Arc<AppState>,
    socket: Arc<UdpSocket>,
) -> io::Result<()> {
    let key = session.key;
    let mut buf = vec![0u8; 65535];

    debug!(
        "direct UDP recv loop started: client={}, orig_dst={}, local={}, peer={}",
        key.client_addr,
        key.orig_dst,
        socket.local_addr()?,
        socket.peer_addr()?
    );

    loop {
        tokio::select! {
            _ = session.cancel.cancelled() => {
                debug!(
                    "direct UDP recv loop cancelled: client={}, orig_dst={}",
                    key.client_addr,
                    key.orig_dst
                );
                return Ok(());
            }

            r = socket.recv(&mut buf) => {
                let n = r?;

                if n == 0 {
                    continue;
                }

                session.touch().await;

                let payload = &buf[..n];

                debug!(
                    "direct UDP response: orig_dst={}, client={}, payload_len={}",
                    key.orig_dst,
                    key.client_addr,
                    payload.len()
                );

                match state.udp_runtime.fake_udp
                    .send_to(
                        key.orig_dst,
                        key.client_addr,
                        payload,
                        state.config.fwmark,
                    )
                    .await
                {
                    Ok(sent) => {
                        debug!(
                            "direct UDP response sent: spoofed_src={}, client={}, bytes={}",
                            key.orig_dst,
                            key.client_addr,
                            sent
                        );
                    }
                    Err(e) => {
                        warn!(
                            "failed to send direct UDP response: spoofed_src={}, client={}, error={}",
                            key.orig_dst,
                            key.client_addr,
                            e
                        );
                    }
                }
            }
        }
    }
}

async fn run_socks5_udp_recv_loop(
    session: Arc<UdpSession>,
    state: Arc<AppState>,
    relay_sock: Arc<UdpSocket>,
    relay_addr: SocketAddr,
) -> io::Result<()> {
    let key = session.key;
    let mut buf = vec![0u8; 65535];

    debug!(
        "SOCKS5 UDP recv loop started: client={}, orig_dst={}, relay={}, local={}",
        key.client_addr,
        key.orig_dst,
        relay_addr,
        relay_sock.local_addr()?
    );

    loop {
        tokio::select! {
            _ = session.cancel.cancelled() => {
                debug!(
                    "SOCKS5 UDP recv loop cancelled: client={}, orig_dst={}",
                    key.client_addr,
                    key.orig_dst
                );
                return Ok(());
            }

            r = relay_sock.recv(&mut buf) => {
                let n = r?;

                if n == 0 {
                    continue;
                }

                session.touch().await;

                let (remote_src, payload) = match parse_socks5_udp_packet(&buf[..n]) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(
                            "invalid SOCKS5 UDP packet: client={}, orig_dst={}, relay={}, error={}",
                            key.client_addr,
                            key.orig_dst,
                            relay_addr,
                            e
                        );
                        continue;
                    }
                };

                debug!(
                    "SOCKS5 UDP response: remote_src={}, client={}, payload_len={}",
                    remote_src,
                    key.client_addr,
                    payload.len()
                );

                match state.udp_runtime.fake_udp
                    .send_to(
                        remote_src,
                        key.client_addr,
                        payload,
                        state.config.fwmark,
                    )
                    .await
                {
                    Ok(sent) => {
                        debug!(
                            "SOCKS5 UDP response sent: spoofed_src={}, client={}, bytes={}",
                            remote_src,
                            key.client_addr,
                            sent
                        );
                    }
                    Err(e) => {
                        warn!(
                            "failed to send SOCKS5 UDP response: spoofed_src={}, client={}, error={}",
                            remote_src,
                            key.client_addr,
                            e
                        );
                    }
                }
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

fn parse_socks5_udp_packet(pkt: &[u8]) -> io::Result<(SocketAddr, &[u8])> {
    if pkt.len() < 4 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "short socks5 udp packet",
        ));
    }

    if pkt[0] != 0x00 || pkt[1] != 0x00 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid socks5 udp rsv",
        ));
    }

    if pkt[2] != 0x00 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "fragmented socks5 udp not supported",
        ));
    }

    let atyp = pkt[3];
    let mut off = 4;

    let dst = match atyp {
        0x01 => {
            if pkt.len() < off + 4 + 2 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "short ipv4 socks5 udp packet",
                ));
            }

            let ip = Ipv4Addr::new(pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]);
            off += 4;

            let port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            off += 2;

            SocketAddr::new(IpAddr::V4(ip), port)
        }
        0x04 => {
            if pkt.len() < off + 16 + 2 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "short ipv6 socks5 udp packet",
                ));
            }

            let mut ip = [0u8; 16];
            ip.copy_from_slice(&pkt[off..off + 16]);
            off += 16;

            let port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            off += 2;

            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
        }
        0x03 => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "domain atyp in socks5 udp response not supported",
            ));
        }
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid socks5 udp atyp",
            ));
        }
    };

    Ok((dst, &pkt[off..]))
}

fn sockaddr_to_socketaddr(
    ss: &libc::sockaddr_storage,
    _len: libc::socklen_t,
) -> Option<SocketAddr> {
    unsafe {
        match ss.ss_family as i32 {
            libc::AF_INET => {
                let sa = &*(ss as *const _ as *const libc::sockaddr_in);

                let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr).to_be_bytes());
                let port = u16::from_be(sa.sin_port);

                Some(SocketAddr::new(IpAddr::V4(ip), port))
            }
            libc::AF_INET6 => {
                let sa = &*(ss as *const _ as *const libc::sockaddr_in6);

                let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
                let port = u16::from_be(sa.sin6_port);

                Some(SocketAddr::new(IpAddr::V6(ip), port))
            }
            _ => None,
        }
    }
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
