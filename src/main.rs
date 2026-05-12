use clap::Parser;
use maxminddb::geoip2::Country;
use maxminddb::Reader;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

#[derive(Parser)]
#[command(name = "xtp-rs", about = "XTP-RS - Transparent TCP proxy splitter")]
struct Cli {
    /// 配置文件路径
    #[arg(short = 'c', long, default_value = "xtp-rs.toml")]
    config: String,
}

#[derive(Deserialize)]
struct Config {
    #[serde(default = "default_listen_addr")]
    listen_addr: String,
    #[serde(default = "default_listen_port")]
    listen_port: u16,
    #[serde(default = "default_socks5_addr")]
    socks5_addr: String,
    #[serde(default = "default_fwmark")]
    fwmark: u32,
    #[serde(default = "default_mmdb_path")]
    mmdb_path: String,
    log_level: Option<String>,
}

fn default_listen_addr() -> String {
    "::".to_string()
}

fn default_listen_port() -> u16 {
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

struct AppState {
    mmdb: Arc<Reader<Vec<u8>>>,
    config: Config,
}

impl AppState {
    fn should_direct(&self, ip: IpAddr) -> bool {
        is_must_direct_local_ip(ip) || self.is_china_ip(ip)
    }

    fn is_china_ip(&self, ip: IpAddr) -> bool {
        let country = match self.mmdb.lookup::<Country<'_>>(ip) {
            Ok(country) => country,
            Err(_) => return false,
        };

        country
            .country
            .and_then(|c| c.iso_code)
            .map(|code| code == "CN")
            .unwrap_or(false)
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let config_str = tokio::fs::read_to_string(&cli.config)
        .await
        .map_err(|e| io::Error::new(ErrorKind::Other, format!("failed to read config: {e}")))?;

    let config: Config = toml::from_str(&config_str)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("invalid config: {e}")))?;

    let env_filter = if let Some(ref level) = config.log_level {
        tracing_subscriber::EnvFilter::new(level)
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info".into())
    };
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    debug!("xtp-rs started");

    let mmdb_data = tokio::fs::read(&config.mmdb_path).await?;
    let mmdb = Reader::from_source(mmdb_data)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("invalid MMDB: {e}")))?;

    let state = Arc::new(AppState {
        mmdb: Arc::new(mmdb),
        config,
    });

    info!("MMDB loaded from {}", state.config.mmdb_path);

    let listener = tproxy_tcp_listener(&state.config.listen_addr, state.config.listen_port)?;
    info!(
        "TPROXY TCP listening on {}:{}",
        state.config.listen_addr, state.config.listen_port
    );

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            // 在 TPROXY 中，local_addr() 就是原始目标地址 (orig_dst)
            let orig_dst = match stream.local_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    error!("failed to get local_addr: {}", e);
                    return;
                }
            };

            info!("Connection: {} -> {}", peer_addr, orig_dst);

            if let Err(e) = handle_connection(stream, orig_dst, state).await {
                error!("{} handling error: {}", peer_addr, e);
            }
        });
    }
}

async fn handle_connection(
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

    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok((from_client, from_upstream)) => {
            debug!(
                "proxy finished, client->upstream={} bytes, upstream->client={} bytes",
                from_client, from_upstream
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
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

    // 关键：开启透明代理
    if sa.is_ipv4() {
        socket.set_ip_transparent_v4(true)?;
    } else {
        socket.set_ip_transparent_v6(true)?;
        socket.set_only_v6(false)?;
        // 告诉内核为 IPv6 传递原始目的地信息
        let _ = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_IPV6,
                libc::IPV6_RECVORIGDSTADDR,
                &1 as *const libc::c_int as *const _,
                std::mem::size_of::<libc::c_int>() as _,
            )
        };
    }

    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&sa.into())?;
    socket.listen(1024)?;

    TcpListener::from_std(socket.into())
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

    // 2. 关键修复：先 connect，再转换
    // 对于已经设置了 mark 的 socket，我们需要直接调用底层 connect
    match socket.connect(&proxy_addr.into()) {
        Ok(_) => {}
        Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let mut stream = TcpStream::from_std(std_stream)?;

    // 等待连接成功
    stream.writable().await?;
    if let Some(e) = stream.take_error()? {
        return Err(e);
    }

    // 3. SOCKS5 握手 (保持不变)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf != [0x05, 0x00] {
        return Err(io::Error::new(
            ErrorKind::ConnectionRefused,
            "SOCKS5 auth negotiation failed",
        ));
    }

    // SOCKS5 connect request
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
