use anyhow::{Context, Result, anyhow, bail};
use ipnet::IpNet;
use iptrie::{Ipv4Prefix, Ipv4RTrieSet, Ipv6Prefix, Ipv6RTrieSet};
use nix::errno::Errno;
use nix::sys::socket::{setsockopt, sockopt};
use portable_atomic::AtomicU64;
use socket2::Socket;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_util::bytes::BytesMut;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::activity_stream::{Activity, ActivityGuard, half_close_watchdog};

pub const UDP_RECV_BUF_SIZE: usize = 65_536;

/// 创建可复用的 UDP 接收缓冲区。
///
/// 预留双倍容量，目的是降低 `split_to(n).freeze()` 之后、下一轮 `resize()` 时
/// 触发重新分配（或 CoW 复制）的频率。注意：这并不能“保证”永不复制——因为切出
/// 的 `Bytes` 可能仍引用原内存块，当剩余尾部空间不足以容纳 `UDP_RECV_BUF_SIZE`
/// 时，`BytesMut` 会分配新内存并把当前数据复制过去。
pub fn new_udp_buf() -> BytesMut {
    let mut buf = BytesMut::with_capacity(UDP_RECV_BUF_SIZE * 2);
    buf.resize(UDP_RECV_BUF_SIZE, 0);
    buf
}

/// 每次 recv 前调用：把长度重置为 `UDP_RECV_BUF_SIZE`。
///
/// 由于 `new_udp_buf()` 已预分配双倍容量，前若干轮通常有足够尾部空间而不触发
/// `realloc`；但当 `split_to` 累计偏移导致尾部空间不足，或仍有外部 `Bytes`
/// 引用旧内存时，`resize` 可能会分配新内存并复制剩余数据。这种偶尔的复制对
/// 常规 UDP 小包场景开销很小。
#[inline]
pub fn reset_udp_buf(buf: &mut BytesMut) {
    buf.resize(UDP_RECV_BUF_SIZE, 0);
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs()
}

pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data.iter() {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

pub fn is_io_emsgsize(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::EMSGSIZE)
}

pub fn is_anyhow_emsgsize(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(is_io_emsgsize)
            .unwrap_or(false)
    })
}

/// 把配置里的秒数转成看门狗宽限期。
///
/// `0` 表示禁用，返回 `None`。不能把 `0` 直接转成 `Some(Duration::ZERO)`：
/// 那会让看门狗在第一次半关闭的瞬间就触发，把每个正常结束的会话都当成泄漏回收。
pub fn half_close_grace(secs: u64) -> Option<Duration> {
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// `tcp_relay_half_close_timeout_total`：半关闭看门狗触发次数。
///
/// xtp-rs 没有 metrics 框架，`/tmp/xtp-rs-report.sock` 是只收不发的上报入口，
/// 因此计数器以进程内原子量暴露，由调用方在触发时打 WARN 日志，便于长期监控
/// 泄漏速率。用 `portable_atomic` 是因为 32 位 MIPS 没有原生 64 位原子。
static TCP_RELAY_HALF_CLOSE_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// `tcp_relay_copy_error_total`：`copy_bidirectional` 返回错误次数（不含看门狗路径）。
static TCP_RELAY_COPY_ERRORS: AtomicU64 = AtomicU64::new(0);

pub fn tcp_relay_half_close_timeouts() -> u64 {
    TCP_RELAY_HALF_CLOSE_TIMEOUTS.load(Ordering::Relaxed)
}

pub fn tcp_relay_copy_errors() -> u64 {
    TCP_RELAY_COPY_ERRORS.load(Ordering::Relaxed)
}

/// TCP relay 的结束方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEnd {
    /// 两个方向都读到 EOF，正常结束。
    Finished { sent: u64, recv: u64 },
    /// 一方已半关闭、另一方静默超过宽限期，看门狗主动回收。
    ///
    /// 此时两侧 socket 已被设为 `SO_LINGER=0`，调用方 drop 它们即可发出 RST。
    HalfCloseTimeout { silent_secs: u64 },
}

/// 对已建立的 TCP 连接做双向转发，并按需启用半关闭静默看门狗。
///
/// `client` 是下游连接，`upstream` 是出站连接（直连目标或 SOCKS5 代理）。
///
/// 三条路径：
/// - `splice = true`：zero-copy，**不做看门狗**。数据由内核在 fd 之间搬运，不经过
///   `poll_read`/`poll_write`，看门狗依赖的 `ActivityGuard` 观测不到字节流动，
///   且 `tokio_splice::Stream` 只对具体的 `TcpStream`/`UnixStream` 实现，包一层
///   guard 就不再满足约束。用户显式开启的优化不被静默改掉，代价是该路径无保护。
/// - `grace = None`（配置 `half_close_timeout = 0`）：纯 `copy_bidirectional`，
///   与改造前逐字一致，用于回滚验证。
/// - `grace = Some(_)`：两侧套 `ActivityGuard` 并与 `half_close_watchdog` 赛跑。
///   看门狗在第一次半关闭之前不会触发，因此“双方都未半关闭的空闲长连接”
///   （交互式登录等）永不被误杀。
///
/// 只有看门狗胜出这一条路径会发 RST。普通 `copy_bidirectional` 错误（`Some(Err)`）
/// 与 `grace = None` 走法一致，不做任何额外处理：错误本身已经意味着这条连接不可用，
/// 而对端未必有问题（例如只是我方出站 write 失败），此处强制 RST 会连带打死可能还
/// 健康的一侧，并让 `half_close_timeout > 0` 悄悄改变普通错误路径的语义。
pub async fn relay_tcp_streams(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    splice: bool,
    grace: Option<Duration>,
) -> Result<RelayEnd> {
    if splice {
        let (sent, recv) = tokio_splice::zero_copy_bidirectional(client, upstream)
            .await
            .map_err(|e| anyhow!("splice error: {}", e))?;
        return Ok(RelayEnd::Finished { sent, recv });
    }

    let Some(grace) = grace else {
        return match tokio::io::copy_bidirectional(client, upstream).await {
            Ok((sent, recv)) => Ok(RelayEnd::Finished { sent, recv }),
            Err(e) => {
                count_copy_error();
                Err(e.into())
            }
        };
    };

    let activity = Activity::new();

    // 两块 guard 可变借用 client/upstream，`copy` 又借用两块 guard。
    // 用块把它们的生命周期收窄：块结束时 future 先于 guard drop，guard 再先于
    // 对外层引用的借用结束，之后才能拿回 client/upstream 去设 SO_LINGER。
    let outcome = {
        let mut left = ActivityGuard::new(&mut *client, activity.clone());
        let mut right = ActivityGuard::new(&mut *upstream, activity.clone());
        let copy = tokio::io::copy_bidirectional(&mut left, &mut right);
        tokio::pin!(copy);

        tokio::select! {
            // biased：正常跑完优先于看门狗。默认的随机公平选择会在“最后一个 EOF
            // 刚到达”与“看门狗恰好到期”同时可轮询时有一半概率选到看门狗，把一个
            // 本该正常 FIN 结束的会话按泄漏回收掉。语义是“超过宽限期仍未结束才
            // 回收”，所以必须让已完成的那一侧先赢。
            biased;
            res = &mut copy => Some(res),
            _ = half_close_watchdog(&activity, grace) => None,
        }
    };

    match outcome {
        Some(Ok((sent, recv))) => Ok(RelayEnd::Finished { sent, recv }),
        Some(Err(e)) => {
            count_copy_error();
            Err(e.into())
        }
        None => {
            TCP_RELAY_HALF_CLOSE_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            let silent_secs = activity.quiet_since_half_close().unwrap_or(grace).as_secs();
            abort_with_rst(client, upstream);
            Ok(RelayEnd::HalfCloseTimeout { silent_secs })
        }
    }
}

fn count_copy_error() {
    TCP_RELAY_COPY_ERRORS.fetch_add(1, Ordering::Relaxed);
}

/// 放弃会话：对两侧 socket 设 `SO_LINGER=0`，由调用方随后的 drop 发出 RST。
///
/// 只在看门狗判定“半关闭后已静默超时”时使用。普通 drop 只发 FIN，此时对端本
/// 就在半关闭后不读不收，FIN 无人 ACK，连接会继续挂在 FIN-WAIT-2 上——回收就
/// 没意义了。
fn abort_with_rst(client: &mut TcpStream, upstream: &mut TcpStream) {
    set_linger_zero(client);
    set_linger_zero(upstream);
}

/// 把 socket 的 `SO_LINGER` 设为 0，使 `close()` 丢弃发送缓冲并直接发 RST。
///
/// 失败不致命：退化为普通 FIN，只是对端若不 ACK 会多挂一段。
fn set_linger_zero(stream: &TcpStream) {
    if let Err(e) = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO)) {
        debug!(
            error = format!("{:#}", e),
            "SO_LINGER=0 failed, closing will fall back to FIN"
        );
    }
}

pub async fn warn_if_splice_with_forwarding(splice_enabled: bool) {
    if !splice_enabled {
        return;
    }
    const PREFIX: &str = "/proc/sys/net/";
    async fn read_proc(suffix: &str) -> bool {
        match tokio::fs::read_to_string(format!("{}{}", PREFIX, suffix)).await {
            Ok(s) => s.trim().parse::<i32>().map(|n| n != 0).unwrap_or(false),
            Err(_) => false,
        }
    }
    let (v4, v6) = tokio::join!(
        read_proc("ipv4/ip_forward"),
        read_proc("ipv6/conf/all/forwarding")
    );
    if v4 || v6 {
        warn!(
            ipv4 = v4,
            ipv6 = v6,
            "splice=1 but ip_forward detected; splice() may underperform on forwarding paths due to skb linearization. \
            Please see https://github.com/XTLS/Xray-core/discussions/59"
        );
    }
}

pub fn parse_ip_net_list(list: &[String]) -> Result<Vec<IpNet>> {
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

pub fn build_ip_tries(nets: &[IpNet]) -> Result<(Ipv4RTrieSet, Ipv6RTrieSet)> {
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

pub fn set_socket_reuse(socket: &Socket) -> Result<()> {
    socket
        .set_reuse_address(true)
        .context("SO_REUSEADDR failed")?;
    socket.set_reuse_port(true).context("SO_REUSEPORT failed")?;
    Ok(())
}

pub fn enable_orig_dst_v4<F: AsFd>(fd: &F) -> io::Result<()> {
    setsockopt(fd, sockopt::Ipv4OrigDstAddr, &true).map_err(errno_to_io)
}

pub fn enable_orig_dst_v6<F: AsFd>(fd: &F) -> io::Result<()> {
    setsockopt(fd, sockopt::Ipv6OrigDstAddr, &true).map_err(errno_to_io)
}

pub fn errno_to_io(errno: Errno) -> io::Error {
    io::Error::from_raw_os_error(errno as i32)
}

pub fn sockaddr_storage_to_std(addr: &nix::sys::socket::SockaddrStorage) -> Option<SocketAddr> {
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

pub fn sockaddr_in_to_std(addr: libc::sockaddr_in) -> SocketAddr {
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    SocketAddr::new(IpAddr::V4(ip), port)
}

pub fn sockaddr_in6_to_std(addr: libc::sockaddr_in6) -> SocketAddr {
    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);
    SocketAddr::new(IpAddr::V6(ip), port)
}

pub fn unspecified_addr_for(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TcpInfoExt {
    pub tcpi_state: u8,
    pub tcpi_ca_state: u8,
    pub tcpi_retransmits: u8,
    pub tcpi_probes: u8,
    pub tcpi_backoff: u8,
    pub tcpi_options: u8,
    pub tcpi_snd_rcv_wscale: u8, // 对应内核位域：snd_wscale + rcv_wscale
    pub tcpi_delivery_rate_app_limited: u8, // 对应内核位域/填充
    pub tcpi_rto: u32,
    pub tcpi_ato: u32,
    pub tcpi_snd_mss: u32,
    pub tcpi_rcv_mss: u32,

    pub tcpi_unacked: u32,
    pub tcpi_sacked: u32,
    pub tcpi_lost: u32,
    pub tcpi_retrans: u32,
    pub tcpi_fackets: u32,

    pub tcpi_last_data_sent: u32,
    pub tcpi_last_ack_sent: u32,
    pub tcpi_last_data_recv: u32,
    pub tcpi_last_ack_recv: u32,

    pub tcpi_pmtu: u32,
    pub tcpi_rcv_ssthresh: u32,
    pub tcpi_rtt: u32,
    pub tcpi_rttvar: u32,
    pub tcpi_snd_ssthresh: u32,
    pub tcpi_snd_cwnd: u32,
    pub tcpi_advmss: u32,
    pub tcpi_reordering: u32,

    pub tcpi_rcv_rtt: u32,
    pub tcpi_rcv_space: u32,
    pub tcpi_total_retrans: u32,

    pub tcpi_pacing_rate: u64,
    pub tcpi_max_pacing_rate: u64,

    /// 本机发送并已被对端 ACK 的 payload 字节数
    pub tcpi_bytes_acked: u64,

    /// 本机从对端收到的 payload 字节数
    pub tcpi_bytes_received: u64,
}

pub fn get_tcp_info_ext_raw(fd: std::os::fd::RawFd) -> Option<TcpInfoExt> {
    let mut info: TcpInfoExt = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<TcpInfoExt>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        return None;
    }

    // 如果内核返回的 tcp_info 长度不够，说明没有填到 bytes_received。
    if len < std::mem::size_of::<TcpInfoExt>() as libc::socklen_t {
        return None;
    }

    Some(info)
}

pub struct TaskGuard {
    cancel: CancellationToken,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl TaskGuard {
    pub fn new() -> Self {
        Self {
            cancel: CancellationToken::new(),
            handles: Mutex::new(Vec::new()),
        }
    }

    pub fn child_token(&self) -> CancellationToken {
        self.cancel.child_token()
    }

    /// 同步 spawn，guard 不跨 await，完全安全
    pub fn spawn<F>(&self, build: impl FnOnce(CancellationToken) -> F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let token = self.child_token();
        let mut handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        // 自动清理已结束任务，避免动态 spawn 场景下无限增长
        handles.retain(|h| !h.is_finished());
        handles.push(tokio::spawn(build(token)));
    }

    /// 1) 发 cancel；2) 把 handles 拿出来；3) 带超时等它们结束。返回是否在超时前全部完成
    pub async fn shutdown(&self, timeout: Duration) -> bool {
        self.cancel.cancel();

        let handles: Vec<_> = {
            let mut h = self.handles.lock().unwrap_or_else(|e| e.into_inner());
            h.drain(..).collect()
        };

        let deadline = tokio::time::Instant::now() + timeout;
        let mut ok = true;

        for mut handle in handles {
            let now = tokio::time::Instant::now();

            if now >= deadline {
                handle.abort();
                let _ = handle.await;
                ok = false;
                continue;
            }

            match tokio::time::timeout_at(deadline, &mut handle).await {
                Ok(Ok(())) => {
                    // 正常退出
                }
                Ok(Err(e)) => {
                    warn!(error = format!("{:#}", e), "task exited with JoinError");
                }
                Err(_) => {
                    handle.abort();
                    let _ = handle.await;
                    ok = false;
                }
            }
        }

        ok
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub fn canonical_domain(domain: &str) -> String {
    domain
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// 域名后缀匹配。
///
/// 匹配：
/// - `example.com` == `example.com`
/// - `www.example.com` ends with `.example.com`
///
/// 不匹配：
/// - `badexample.com` 不应匹配 `example.com`
pub fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let d_norm = canonical_domain(domain);
    let s_norm = canonical_domain(suffix);

    let d_len = d_norm.len();
    let s_len = s_norm.len();

    // 2. 长度边界短路
    if d_len < s_len {
        return false;
    }

    // 3. 规范化后完全相等 (例如 domain: "google.com", suffix: "google.com")
    if d_len == s_len {
        return d_norm == s_norm;
    }

    // 4. 处理子域名后缀匹配 (例如 domain: "www.google.com", suffix: "google.com")
    if d_norm.ends_with(&s_norm) {
        let prev_char_idx = d_len - s_len - 1;
        if let Some(c) = d_norm.as_bytes().get(prev_char_idx) {
            return *c == b'.';
        }
    }

    false
}

pub fn parse_ip_or_cidr(s: &str) -> Result<IpNet> {
    if let Ok(net) = s.parse::<IpNet>() {
        Ok(net)
    } else {
        let ip: IpAddr = s
            .parse()
            .with_context(|| format!("invalid IP/CIDR '{}'", s))?;
        Ok(IpNet::from(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iptrie::IpPrefix;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ---- parse_ip_net_list ----
    #[test]
    fn parse_ip_and_cidr() {
        let list = vec!["1.2.3.4".to_string(), "10.0.0.0/8".to_string()];
        let nets = parse_ip_net_list(&list).unwrap();
        assert_eq!(nets.len(), 2);
    }

    #[test]
    fn parse_empty_string_error() {
        let list = vec!["".to_string()];
        assert!(parse_ip_net_list(&list).is_err());
    }

    #[test]
    fn parse_invalid() {
        let list = vec!["not_an_ip".to_string()];
        assert!(parse_ip_net_list(&list).is_err());
    }

    // ---- build_ip_tries ----
    #[test]
    fn build_and_lookup_v4() {
        let net: IpNet = "192.168.1.0/24".parse().unwrap();
        let (v4, _) = build_ip_tries(&[net]).unwrap();
        assert!(
            v4.lookup(&"192.168.1.55".parse::<Ipv4Addr>().unwrap())
                .len()
                > 0
        );
        assert!(v4.lookup(&"192.168.2.1".parse::<Ipv4Addr>().unwrap()).len() == 0);
    }

    #[test]
    fn build_and_lookup_v6() {
        let net: IpNet = "2001:db8::/32".parse().unwrap();
        let (_, v6) = build_ip_tries(&[net]).unwrap();
        let hit: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let miss: Ipv6Addr = "2001:db9::1".parse().unwrap();
        assert!(v6.lookup(&hit).len() > 0);
        assert!(v6.lookup(&miss).len() == 0);
    }

    // ---- hex_encode ----
    #[test]
    fn hex_encode_works() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(hex_encode(&[]), "");
    }

    // ---- unspecified_addr_for ----
    #[test]
    fn unspecified_v4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80);
        let unspec = unspecified_addr_for(addr);
        assert_eq!(
            unspec,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        );
    }

    #[test]
    fn unspecified_v6() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)), 443);
        let unspec = unspecified_addr_for(addr);
        assert_eq!(
            unspec,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        );
    }

    // ---- is_io_emsgsize ----
    #[test]
    fn detects_emsgsize() {
        let e = std::io::Error::from_raw_os_error(libc::EMSGSIZE);
        assert!(is_io_emsgsize(&e));
    }

    #[test]
    fn non_emsgsize() {
        let e = std::io::Error::from_raw_os_error(libc::EINVAL);
        assert!(!is_io_emsgsize(&e));
    }

    // ---- now_secs ----
    #[test]
    fn now_secs_is_monotonic() {
        let t1 = now_secs();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = now_secs();
        assert!(t2 >= t1);
    }

    // ---- half_close_grace ----
    #[test]
    fn half_close_grace_zero_disables_the_watchdog() {
        // 0 必须是 None：Some(Duration::ZERO) 会让看门狗在第一个半关闭瞬间触发。
        assert_eq!(half_close_grace(0), None);
    }

    #[test]
    fn half_close_grace_positive_is_that_many_seconds() {
        assert_eq!(half_close_grace(1), Some(Duration::from_secs(1)));
        assert_eq!(half_close_grace(600), Some(Duration::from_secs(600)));
    }

    #[test]
    fn test_domain_matches_suffix() {
        // 1. 完全相等的情况
        assert!(domain_matches_suffix("google.com", "google.com"));
        assert!(
            domain_matches_suffix("Google.Com", "google.com"),
            "应该忽略大小写"
        );

        // 2. 标准子域名匹配
        assert!(domain_matches_suffix("www.google.com", "google.com"));
        assert!(domain_matches_suffix("mail.www.google.com", "google.com"));
        assert!(domain_matches_suffix("a.b.c.d.google.com", "google.com"));

        // 3. 相似但【不应该】匹配的情况（经典边界漏洞）
        assert!(
            !domain_matches_suffix("notgoogle.com", "google.com"),
            "防止字符串部分包含的伪匹配"
        );
        assert!(!domain_matches_suffix("fakegoogle.com", "google.com"));
        assert!(
            !domain_matches_suffix("google.com.cn", "google.com"),
            "后缀不同不应匹配"
        );
        assert!(
            !domain_matches_suffix("com", "google.com"),
            "长度不够不应匹配"
        );

        // 4. 各种恶心的 FQDN 尾部点（Trailing Dot）情况
        // 因为入口进来了 canonical_domain，所以这些行为必须表现一致且安全
        assert!(domain_matches_suffix("google.com.", "google.com"));
        assert!(domain_matches_suffix("google.com", "google.com."));
        assert!(domain_matches_suffix("google.com.", "google.com."));
        assert!(domain_matches_suffix("www.google.com.", "google.com"));
        assert!(domain_matches_suffix("www.google.com", "google.com."));
        assert!(domain_matches_suffix("www.google.com.", "google.com."));

        // 5. 空字符或非法边界防御
        assert!(!domain_matches_suffix("", "google.com"));
        assert!(!domain_matches_suffix("google.com", ""));
        assert!(domain_matches_suffix("", ""));
    }

    // ========== canonical_domain ==========

    #[test]
    fn test_canonical_domain_lowercase() {
        assert_eq!(canonical_domain("Example.COM"), "example.com");
    }

    #[test]
    fn test_canonical_domain_leading_dot() {
        assert_eq!(canonical_domain(".example.com"), "example.com");
    }

    #[test]
    fn test_canonical_domain_trailing_dot() {
        assert_eq!(canonical_domain("example.com."), "example.com");
    }

    #[test]
    fn test_canonical_domain_both_dots_and_case() {
        assert_eq!(canonical_domain(".Example.COM."), "example.com");
    }

    #[test]
    fn test_canonical_domain_empty() {
        assert_eq!(canonical_domain(""), "");
    }

    #[test]
    fn test_canonical_domain_only_dot() {
        assert_eq!(canonical_domain("."), "");
    }

    // ========== domain_matches_suffix ==========

    #[test]
    fn test_domain_matches_suffix_exact() {
        assert!(domain_matches_suffix("google.com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_case_insensitive() {
        assert!(domain_matches_suffix("Google.Com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_single_subdomain() {
        assert!(domain_matches_suffix("www.google.com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_deep_subdomain() {
        assert!(domain_matches_suffix("a.b.c.google.com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_not_a_subdomain_1() {
        assert!(!domain_matches_suffix("notgoogle.com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_not_a_subdomain_2() {
        assert!(!domain_matches_suffix("fakegoogle.com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_longer_tld() {
        assert!(!domain_matches_suffix("google.com.cn", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_shorter_domain() {
        assert!(!domain_matches_suffix("com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_trailing_dot_domain() {
        assert!(domain_matches_suffix("google.com.", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_trailing_dot_suffix() {
        assert!(domain_matches_suffix("google.com", "google.com."));
    }

    #[test]
    fn test_domain_matches_suffix_both_trailing_dots() {
        assert!(domain_matches_suffix("www.google.com.", "google.com."));
    }

    #[test]
    fn test_domain_matches_suffix_empty_domain() {
        assert!(!domain_matches_suffix("", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_empty_suffix() {
        assert!(!domain_matches_suffix("google.com", ""));
    }

    #[test]
    fn test_domain_matches_suffix_both_empty() {
        // 与当前实现保持一致：空字符串视为相等
        assert!(domain_matches_suffix("", ""));
    }

    #[test]
    fn parse_ip_or_cidr_accepts_plain_ip() {
        let net = parse_ip_or_cidr("192.168.1.10").unwrap();
        assert_eq!(net, "192.168.1.10/32".parse::<IpNet>().unwrap());

        let net6 = parse_ip_or_cidr("2001:db8::1").unwrap();
        assert_eq!(net6, "2001:db8::1/128".parse::<IpNet>().unwrap());
    }
}
