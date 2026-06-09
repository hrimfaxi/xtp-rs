use aligned_vec::{AVec, RuntimeAlign};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use iptrie::{Ipv4Prefix, Ipv4RTrieSet, Ipv6Prefix, Ipv6RTrieSet};
use nix::errno::Errno;
use nix::sys::socket::{setsockopt, sockopt};
use socket2::Socket;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::Mutex;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub const UDP_RECV_BUF_SIZE: usize = 65_536;
pub const UDP_BUF_ALIGN: usize = 4096;

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

pub fn new_aligned_udp_buf() -> AVec<u8, RuntimeAlign> {
    let mut buf = AVec::<u8, RuntimeAlign>::with_capacity(UDP_BUF_ALIGN, UDP_RECV_BUF_SIZE);
    buf.resize(UDP_RECV_BUF_SIZE, 0);
    buf
}

pub async fn splice_or_copy_bidirectional<A, B>(
    splice: bool,
    client: &mut A,
    upstream: &mut B,
) -> Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + tokio_splice::Stream,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + tokio_splice::Stream,
{
    if splice {
        tokio_splice::zero_copy_bidirectional(client, upstream)
            .await
            .map_err(|e| anyhow::anyhow!("splice error: {}", e))
    } else {
        tokio::io::copy_bidirectional(client, upstream)
            .await
            .map_err(Into::into)
    }
}

pub fn warn_if_splice_with_forwarding(splice_enabled: bool) {
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
        let mut handles = self.handles.lock().expect("bad taskguard lock");
        // 自动清理已结束任务，避免动态 spawn 场景下无限增长
        handles.retain(|h| !h.is_finished());
        handles.push(tokio::spawn(build(token)));
    }

    /// 1) 发 cancel；2) 把 handles 拿出来；3) 带超时等它们结束。返回是否在超时前全部完成
    pub async fn shutdown(&self, timeout: Duration) -> bool {
        self.cancel.cancel();

        let handles: Vec<_> = {
            let mut h = self.handles.lock().expect("bad taskguard lock");
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
