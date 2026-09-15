use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};

use crate::sniff::{SniffConfig, sniff_domain};
use crate::socket_factory::SocketFactory;
use crate::socks5::{Socks5Target, socks5_connect};
use crate::state::AppState;
use crate::upstream::Upstream;
use crate::util::{
    RelayEnd, half_close_grace, relay_tcp_streams, tcp_relay_copy_errors,
    tcp_relay_half_close_timeouts,
};

#[derive(Debug)]
pub enum TcpUpstreamTarget {
    Direct(SocketAddr),
    Socks5Ip(SocketAddr),
    Socks5Domain { host: String, port: u16 },
}

/// 在指定分组内尝试连接 SOCKS5，失败自动在同组内换 upstream，全组失败后 fallback 到 default 分组
async fn try_connect_socks5_group(
    target: &TcpUpstreamTarget,
    state: &Arc<AppState>,
    mut group: &str,
    exclude: Option<&str>,
) -> Result<(TcpStream, Arc<Upstream>)> {
    let mut failed: HashSet<String> = HashSet::new();
    if let Some(id) = exclude {
        failed.insert(id.to_string());
    }

    loop {
        let up = if failed.is_empty() {
            state.upstreams.pick_from_group(group)
        } else {
            state
                .upstreams
                .pick_excluding_many_from_group(group, &failed)
        };

        let up = match up {
            Some(u) => u,
            None => {
                if group == "default" {
                    bail!("all upstreams in default group failed");
                } else {
                    warn!(
                        "all upstreams in group '{}' failed, fallback to default",
                        group
                    );
                    group = "default";
                    failed.clear();
                    continue;
                }
            }
        };

        match connect_tcp_upstream(
            target,
            up.addr,
            state.config.fwmark,
            state.socks5_credentials(),
            std::time::Duration::from_secs(state.config.connect_timeout_secs),
        )
        .await
        {
            Ok(s) => return Ok((s, up)),
            Err(e) => {
                warn!(
                    upstream_id = %up.id,
                    error = format!("{:#}", e),
                    "upstream connect failed"
                );
                if !state.config.disable_upstream_score {
                    up.penalize();
                }
                failed.insert(up.id.clone());
            }
        }
    }
}

pub fn decide_tcp_upstream_target(
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

pub async fn connect_tcp_upstream(
    target: &TcpUpstreamTarget,
    socks5_addr: SocketAddr,
    fwmark: u32,
    creds: Option<(&str, &str)>,
    timeout: std::time::Duration,
) -> Result<TcpStream> {
    match target {
        TcpUpstreamTarget::Direct(addr) => {
            debug!(addr = %addr, "direct connect");
            tokio::time::timeout(timeout, direct_connect(*addr, fwmark))
                .await
                .map_err(|_| anyhow!("direct connect timeout"))?
        }
        TcpUpstreamTarget::Socks5Ip(addr) => {
            debug!(addr = %addr, "proxy connect by ip");
            tokio::time::timeout(
                timeout,
                socks5_connect(Socks5Target::Ip(*addr), socks5_addr, fwmark, creds),
            )
            .await
            .map_err(|_| anyhow!("SOCKS5 connect timeout"))?
        }
        TcpUpstreamTarget::Socks5Domain { host, port } => {
            debug!(host = %host, port = port, "proxy connect by hostname");
            tokio::time::timeout(
                timeout,
                socks5_connect(
                    Socks5Target::Domain(host.as_str(), *port),
                    socks5_addr,
                    fwmark,
                    creds,
                ),
            )
            .await
            .map_err(|_| anyhow!("SOCKS5 connect timeout"))?
        }
    }
}

pub async fn direct_connect(orig_dst: SocketAddr, fwmark: u32) -> Result<TcpStream> {
    debug!(dst = %orig_dst, "direct connect");
    SocketFactory::new()
        .connect_tcp_stream(orig_dst, fwmark)
        .await
        .with_context(|| format!("direct connect to {orig_dst} failed"))
}

async fn relay_tcp(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    splice: bool,
    half_close_timeout: Option<Duration>,
    target: SocketAddr,
    up: Option<&Upstream>,
    start: Instant,
) -> Result<()> {
    let relay_result = relay_tcp_streams(client, upstream, splice, half_close_timeout).await;
    let duration = start.elapsed();

    match relay_result {
        Ok(RelayEnd::Finished { sent, recv }) => {
            if let Some(up) = up {
                debug!(
                    target = %target,
                    upstream_id = %up.id,
                    score = up.score(),
                    sent = sent,
                    recv = recv,
                    duration_ms = duration.as_millis(),
                    "TCP finished"
                );
            } else {
                debug!(
                    target = %target,
                    duration_ms = duration.as_millis(),
                    sent = sent,
                    recv = recv,
                    "TCP direct finished"
                );
            }
            Ok(())
        }
        Ok(RelayEnd::HalfCloseTimeout { silent_secs }) => {
            // 每次触发一条，不做采样：这条日志同时是“泄漏是否仍在发生”的唯一现场证据，
            // 采样会掩盖泄漏速率。带上累计值，运维可直接从日志算出回收速率。
            let total = tcp_relay_half_close_timeouts();
            if let Some(up) = up {
                warn!(
                    target = %target,
                    upstream_id = %up.id,
                    silent_secs = silent_secs,
                    duration_ms = duration.as_millis(),
                    total = total,
                    "TCP relay half-closed and silent, session reclaimed with RST"
                );
            } else {
                warn!(
                    target = %target,
                    silent_secs = silent_secs,
                    duration_ms = duration.as_millis(),
                    total = total,
                    "TCP direct relay half-closed and silent, session reclaimed with RST"
                );
            }
            Ok(())
        }
        Err(e) => {
            let copy_errors_total = tcp_relay_copy_errors();
            if let Some(up) = up {
                error!(
                    target = %target,
                    upstream_id = %up.id,
                    score = up.score(),
                    copy_errors_total = copy_errors_total,
                    error = format!("{:#}", e),
                    "TCP relay error"
                );
            } else {
                error!(
                    target = %target,
                    copy_errors_total = copy_errors_total,
                    error = format!("{:#}", e),
                    "TCP direct relay error"
                );
            }
            Err(e)
        }
    }
}

async fn pick_and_connect(
    target: &TcpUpstreamTarget,
    state: &Arc<AppState>,
    client_addr: &SocketAddr,
    orig_dst: SocketAddr,
    domain: Option<&str>,
    exclude: Option<&str>,
) -> Result<(TcpStream, Arc<Upstream>)> {
    trace!(
        client = %client_addr,
        orig_dst = %orig_dst,
        domain = ?domain,
        "tcp upstream select"
    );

    let group = state.lookup_upstream_group(client_addr.ip(), orig_dst.ip(), domain);

    trace!(
        client = %client_addr,
        group = %group,
        "tcp selected group"
    );

    let (s, up) = try_connect_socks5_group(target, state, group, exclude).await?;
    debug!(
        upstream_id = %up.id,
        upstream_addr = %up.addr,
        score = up.score(),
        target = %orig_dst,
        "selected upstream"
    );
    Ok((s, up))
}

pub async fn handle_tcp_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    orig_dst: SocketAddr,
    state: Arc<AppState>,
) -> Result<()> {
    let sniff_cfg = SniffConfig {
        tcp_peek_buffer_size: state.config.tcp_peek_buffer_size,
    };

    // 1. 先基于 IP 判断直连（不 sniff）
    let direct_by_ip = state.should_direct(orig_dst.ip(), None);

    // 2. 判断是否需要 sniff 域名
    let need_sniff_for_geosite = state.need_geosite_sniff();
    let need_sniff_for_upstream = state.need_upstream_domain_sniff(client_addr.ip());

    // 1a. 仅当确定不需要 sniff 时，才走 fast-path 直连
    if direct_by_ip && !need_sniff_for_geosite && !need_sniff_for_upstream {
        let target = decide_tcp_upstream_target(orig_dst, true, None);
        if let TcpUpstreamTarget::Direct(target_addr) = target {
            let timeout = std::time::Duration::from_secs(state.config.connect_timeout_secs);
            let mut upstream =
                tokio::time::timeout(timeout, direct_connect(target_addr, state.config.fwmark))
                    .await
                    .map_err(|_| anyhow!("direct connect timeout"))??;
            return relay_tcp(
                &mut client,
                &mut upstream,
                state.config.splice,
                half_close_grace(state.config.half_close_timeout),
                orig_dst,
                None,
                Instant::now(),
            )
            .await;
        }
    }

    // 只有以下情况才 sniff：
    // - geosite 需要域名辅助决策（无论直连还是代理）
    // - 或：IP 判断为代理，且 client_domain_routes 需要域名选 upstream
    let domain: Option<String> =
        if need_sniff_for_geosite || (!direct_by_ip && need_sniff_for_upstream) {
            sniff_domain(&client, orig_dst, &state.sniffers, &sniff_cfg).await
        } else {
            None
        };

    // 3. 最终直连判断（使用域名，如果有 geosite）
    let direct = if need_sniff_for_geosite {
        state.should_direct(orig_dst.ip(), domain.as_deref())
    } else {
        direct_by_ip
    };

    let target = decide_tcp_upstream_target(orig_dst, direct, domain.as_deref());

    // 4. 代理路径上选 upstream 分组
    let (mut upstream, up) = match target {
        TcpUpstreamTarget::Direct(target_addr) => {
            let timeout = std::time::Duration::from_secs(state.config.connect_timeout_secs);
            let s = tokio::time::timeout(timeout, direct_connect(target_addr, state.config.fwmark))
                .await
                .map_err(|_| anyhow!("direct connect timeout"))??;
            (s, None)
        }
        _ => {
            let target_ip = orig_dst.ip();
            // 尝试 upstream 缓存
            if let Some(cached_up) =
                state.get_cached_upstream(client_addr.ip(), target_ip, domain.as_deref())
            {
                match connect_tcp_upstream(
                    &target,
                    cached_up.addr,
                    state.config.fwmark,
                    state.socks5_credentials(),
                    std::time::Duration::from_secs(state.config.connect_timeout_secs),
                )
                .await
                {
                    Ok(s) => {
                        debug!(
                            upstream_id = %cached_up.id,
                            upstream_addr = %cached_up.addr,
                            score = cached_up.score(),
                            target = %orig_dst,
                            "cached upstream"
                        );
                        (s, Some(cached_up))
                    }
                    Err(e) => {
                        warn!(
                            upstream_id = %cached_up.id,
                            error = format!("{:#}", e),
                            "cached upstream connect failed, falling back to pick"
                        );
                        state.remove_cached_upstream(
                            client_addr.ip(),
                            target_ip,
                            domain.as_deref(),
                        );
                        if !state.config.disable_upstream_score {
                            cached_up.penalize();
                        }
                        let (s, up) = pick_and_connect(
                            &target,
                            &state,
                            &client_addr,
                            orig_dst,
                            domain.as_deref(),
                            Some(&cached_up.id),
                        )
                        .await?;
                        (s, Some(up))
                    }
                }
            } else {
                let (s, up) = pick_and_connect(
                    &target,
                    &state,
                    &client_addr,
                    orig_dst,
                    domain.as_deref(),
                    None,
                )
                .await?;
                (s, Some(up))
            }
        }
    };

    // 缓存 upstream 选择
    if let Some(ref up) = up {
        state.cache_upstream(client_addr.ip(), orig_dst.ip(), domain.as_deref(), up);
    }

    let relay_start = Instant::now();
    if let Some(ref up) = up {
        let token = up.track(upstream.as_raw_fd());
        let result = relay_tcp(
            &mut client,
            &mut upstream,
            state.config.splice,
            half_close_grace(state.config.half_close_timeout),
            orig_dst,
            Some(up),
            relay_start,
        )
        .await;
        drop(token);
        result
    } else {
        relay_tcp(
            &mut client,
            &mut upstream,
            state.config.splice,
            half_close_grace(state.config.half_close_timeout),
            orig_dst,
            None,
            relay_start,
        )
        .await
    }
}

pub async fn run_tcp_port_forward(
    listener: TcpListener,
    remote: SocketAddr,
    state: Arc<AppState>,
    cancel: CancellationToken,
) -> Result<()> {
    info!(
        "port-forward TCP: listening on {}, forwarding to {} via SOCKS5",
        listener.local_addr()?,
        remote
    );

    let listen_addr = listener.local_addr()?;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!(
                    listen_addr = %listen_addr,
                    remote = %remote,
                    "port-forward TCP shutting down"
                );
                break;
            }
            res = listener.accept() => {
                let (mut client, peer_addr) = res
                    .with_context(|| format!("accept on port-forward {}", listen_addr))?;
                let state_for_task = state.clone();
                state.tcp_handlers.spawn(|cancel| async move {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {
                            debug!(peer = %peer_addr, remote = %remote, "port-forward TCP handler cancelled");
                        }
                        _ = async {
                            let state = state_for_task;
                            debug!(peer = %peer_addr, remote = %remote, "port-forward TCP via SOCKS5");

                            let target = TcpUpstreamTarget::Socks5Ip(remote);
                            let (mut upstream, up) = match try_connect_socks5_group(&target, &state, "default", None).await {
                                Ok((s, up)) => {
                                    debug!(
                                        upstream_id = %up.id,
                                        upstream_addr = %up.addr,
                                        score = up.score(),
                                        remote = %remote,
                                        "selected upstream for port-forward"
                                    );
                                    (s, up)
                                }
                                Err(e) => {
                                    error!(
                                        remote = %remote,
                                        error = format!("{:#}", e),
                                        "port-forward upstream connect failed"
                                    );
                                    return;
                                }
                            };

                            let start = Instant::now();
                            let _token = up.track(upstream.as_raw_fd());
                            let relay_result = relay_tcp_streams(
                                &mut client,
                                &mut upstream,
                                state.config.splice,
                                half_close_grace(state.config.half_close_timeout),
                            ).await;
                            let duration = start.elapsed();

                            match relay_result {
                                Ok(RelayEnd::Finished { sent, recv }) => {
                                    info!(
                                        remote = %remote,
                                        peer = %peer_addr,
                                        upstream_id = %up.id,
                                        score = up.score(),
                                        sent = sent,
                                        recv = recv,
                                        duration_ms = duration.as_millis(),
                                        "TCP port-forward finished"
                                    );
                                }
                                Ok(RelayEnd::HalfCloseTimeout { silent_secs }) => {
                                    warn!(
                                        remote = %remote,
                                        peer = %peer_addr,
                                        upstream_id = %up.id,
                                        silent_secs = silent_secs,
                                        duration_ms = duration.as_millis(),
                                        total = tcp_relay_half_close_timeouts(),
                                        "port-forward TCP half-closed and silent, session reclaimed with RST"
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        remote = %remote,
                                        upstream_id = %up.id,
                                        score = up.score(),
                                        copy_errors_total = tcp_relay_copy_errors(),
                                        error = format!("{:#}", e),
                                        "port-forward TCP relay error"
                                    );
                                }
                            }
                        } => {}
                    }
                });
            }
        }
    }

    Ok(())
}

pub async fn tcp_accept_loop(
    listener: TcpListener,
    state: Arc<AppState>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("TCP accept loop shutting down");
                break;
            }
            // accept 分支放到后面
            res = listener.accept() => {
                match res {
                    Ok((stream, peer_addr)) => {
                        let state_for_task = state.clone();
                        state.tcp_handlers.spawn(|cancel| async move {
                            tokio::select! {
                                biased;
                                _ = cancel.cancelled() => {
                                    debug!(peer = %peer_addr, "TCP handler cancelled");
                                }
                                _ = async {
                                    let state = state_for_task;
                                    let orig_dst = match stream.local_addr() {
                                        Ok(addr) => addr,
                                        Err(e) => {
                                            error!(error = format!("{:#}", e), "failed to get local_addr");
                                            return;
                                        }
                                    };

                                    debug!(peer = %peer_addr, orig_dst = %orig_dst, "TCP connection");
                                    if let Err(e) = handle_tcp_connection(stream, peer_addr, orig_dst, state).await {
                                            error!(peer = %peer_addr, error = format!("{:#}", e), "tcp handling error");
                                    }
                                } => {}
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = format!("{:#}", e), "failed to accept TCP connection");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_direct() {
        let dst = "8.8.8.8:443".parse().unwrap();
        let target = decide_tcp_upstream_target(dst, true, None);
        assert!(matches!(target, TcpUpstreamTarget::Direct(a) if a == dst));
    }

    #[test]
    fn decide_socks5_ip() {
        let dst = "8.8.8.8:443".parse().unwrap();
        let target = decide_tcp_upstream_target(dst, false, None);
        assert!(matches!(target, TcpUpstreamTarget::Socks5Ip(a) if a == dst));
    }

    #[test]
    fn decide_socks5_domain() {
        let dst = "8.8.8.8:443".parse().unwrap();
        let target = decide_tcp_upstream_target(dst, false, Some("example.com"));
        match target {
            TcpUpstreamTarget::Socks5Domain { host, port } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("expected Socks5Domain"),
        }
    }

    #[test]
    fn decide_socks5_domain_keeps_orig_port() {
        let dst = "1.2.3.4:8080".parse().unwrap();
        let target = decide_tcp_upstream_target(dst, false, Some("foo.bar"));
        match target {
            TcpUpstreamTarget::Socks5Domain { host, port } => {
                assert_eq!(host, "foo.bar");
                assert_eq!(port, 8080);
            }
            _ => panic!("expected Socks5Domain"),
        }
    }

    // ===== 半关闭静默超时：真实 loopback socket 集成测试 =====
    //
    // 不依赖 TPROXY/root：直接用两个已建立的 `TcpStream` 调用 `relay_tcp_streams`，
    // 与 `handle_tcp_connection` 的调用方式完全一致。上游由测试端自己扮演——它连到
    // `back`，relay 侧 accept 出来的就是出站 socket。
    //
    // 计数器是进程级静态量，用一把异步锁把涉及计数的用例串起来，避免互相干扰。

    static RELAY_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const REQUEST: &[u8] = b"GET / HTTP/1.0\r\n\r\n";
    const RESPONSE: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nhello";

    struct RelayFixture {
        /// 下游客户端连这里（模拟 TPROXY 接受到的连接）。
        front: SocketAddr,
        /// 模拟最终目标：测试端连这里，relay 侧 accept 后即为出站 socket。
        back: SocketAddr,
        /// relay 任务的结束方式。
        task: tokio::task::JoinHandle<Result<RelayEnd>>,
    }

    async fn spawn_relay(grace: Option<Duration>) -> RelayFixture {
        let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let back_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = front_listener.local_addr().unwrap();
        let back = back_listener.local_addr().unwrap();

        let task = tokio::spawn(async move {
            let (mut client, _) = front_listener.accept().await?;
            let (mut upstream, _) = back_listener.accept().await?;
            relay_tcp_streams(&mut client, &mut upstream, false, grace).await
        });

        RelayFixture { front, back, task }
    }

    /// 上游读一个请求、只关写半边、读半边保持打开且此后完全静默。
    ///
    /// 这是任务书里的泄漏场景：`copy_bidirectional` 需要一个方向 EOF 才可能返回，
    /// 而这个上游永远不关读半边，于是 relay 永久挂起。
    #[tokio::test]
    async fn half_closed_and_silent_session_is_reclaimed_after_the_grace() {
        let _guard = RELAY_TEST_LOCK.lock().await;
        const GRACE_SECS: u64 = 1;

        let before = tcp_relay_half_close_timeouts();
        let fixture = spawn_relay(Some(Duration::from_secs(GRACE_SECS))).await;

        let mut client = TcpStream::connect(fixture.front).await.unwrap();
        let mut peer = TcpStream::connect(fixture.back).await.unwrap();

        client.write_all(REQUEST).await.unwrap();
        let mut got = vec![0u8; REQUEST.len()];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(got, REQUEST, "relay 应把请求转发给上游");
        peer.shutdown().await.unwrap();

        // 上游的半关闭被 relay 传递到下游：b→a 方向结束，看门狗就此上膛。
        let mut buf = [0u8; 16];
        assert_eq!(
            client.read(&mut buf).await.unwrap(),
            0,
            "上游的半关闭必须被 relay 传递到下游"
        );

        let ended = tokio::time::timeout(Duration::from_secs(GRACE_SECS + 5), fixture.task)
            .await
            .expect("relay 未在宽限期内回收半关闭且静默的会话")
            .expect("relay 任务 panic");

        match ended {
            Ok(RelayEnd::HalfCloseTimeout { silent_secs }) => assert!(
                silent_secs >= GRACE_SECS,
                "静默时长 {silent_secs}s 不应小于宽限期 {GRACE_SECS}s"
            ),
            other => panic!("期望 HalfCloseTimeout，实际 {other:?}"),
        }

        assert!(
            tcp_relay_half_close_timeouts() > before,
            "tcp_relay_half_close_timeout_total 应增长"
        );

        // 关键性质是“对端没有观察到正常 EOF”。SO_LINGER=0 的 drop 发 RST，读到 Ok(0)
        // 则说明只发了 FIN，仍会留下 FIN-WAIT-2 隐患。注意 read 返回错误本身只证明
        // “不是干净 EOF”，严格说不能反推错误一定由 abortive close 造成；要坐实 RST
        // 需要具体 errno，因此在唯一受支持的平台上再补一条更强的断言。
        let err = peer
            .read(&mut buf)
            .await
            .expect_err("看门狗回收后上游不应观察到正常 EOF");
        // xtp-rs 只支持 Linux（TPROXY），因此在受支持平台上再断言具体 errno，把「确实发了
        // RST」坐实。用 #[cfg] 而不是 cfg!：平台条件在语法层面即清晰，非 Linux 平台既不
        // 编译也不维护这条 Linux 特定断言。
        #[cfg(target_os = "linux")]
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        #[cfg(not(target_os = "linux"))]
        drop(err);
    }

    /// `half_close_timeout = 0` 必须完全保留改造前行为：什么都不回收。
    #[tokio::test]
    async fn a_disabled_timeout_leaves_a_half_closed_session_alone() {
        let _guard = RELAY_TEST_LOCK.lock().await;
        const WATCH_FOR_SECS: u64 = 3;

        let before = tcp_relay_half_close_timeouts();
        let mut fixture = spawn_relay(None).await;

        let mut client = TcpStream::connect(fixture.front).await.unwrap();
        let mut peer = TcpStream::connect(fixture.back).await.unwrap();

        client.write_all(REQUEST).await.unwrap();
        let mut got = vec![0u8; REQUEST.len()];
        peer.read_exact(&mut got).await.unwrap();
        peer.shutdown().await.unwrap();

        let mut buf = [0u8; 16];
        assert_eq!(client.read(&mut buf).await.unwrap(), 0);

        // 与上面的用例只差 grace，但这里观察窗口内不得有任何东西结束会话。
        let ended =
            tokio::time::timeout(Duration::from_secs(WATCH_FOR_SECS), &mut fixture.task).await;
        assert!(
            ended.is_err(),
            "half_close_timeout = 0 时不应回收半关闭会话，但会话被结束了"
        );
        assert_eq!(
            tcp_relay_half_close_timeouts(),
            before,
            "禁用看门狗时计数器不得增长"
        );

        fixture.task.abort();
    }

    /// 正常双向关闭（两边都走到 EOF）路径不受影响，且不触发看门狗计数器。
    ///
    /// 宽限期给足 30s，远长于本用例在 loopback 上跑完所需的时间：如果看门狗是唯一
    /// 能结束它的东西，15s 的外层超时会先失败。
    #[tokio::test]
    async fn a_normal_both_sided_close_is_untouched_by_the_watchdog() {
        let _guard = RELAY_TEST_LOCK.lock().await;

        let before = tcp_relay_half_close_timeouts();
        let fixture = spawn_relay(Some(Duration::from_secs(30))).await;

        let mut client = TcpStream::connect(fixture.front).await.unwrap();
        let mut peer = TcpStream::connect(fixture.back).await.unwrap();

        client.write_all(REQUEST).await.unwrap();
        client.shutdown().await.unwrap();

        let mut got = vec![0u8; REQUEST.len()];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(got, REQUEST);

        // 下游半关闭被传递：上游读到 EOF。
        let mut buf = [0u8; 1];
        assert_eq!(peer.read(&mut buf).await.unwrap(), 0);
        peer.write_all(RESPONSE).await.unwrap();
        peer.shutdown().await.unwrap();

        let mut got = vec![0u8; RESPONSE.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, RESPONSE);
        // 正常路径用 FIN：下游读到的是干净 EOF，而不是 RST。
        assert_eq!(client.read(&mut buf).await.unwrap(), 0);

        let ended = tokio::time::timeout(Duration::from_secs(15), fixture.task)
            .await
            .expect("正常双向关闭应在看门狗之前结束")
            .expect("relay 任务 panic");

        match ended {
            Ok(RelayEnd::Finished { sent, recv }) => {
                assert_eq!(sent as usize, REQUEST.len());
                assert_eq!(recv as usize, RESPONSE.len());
            }
            other => panic!("期望 Finished，实际 {other:?}"),
        }
        assert_eq!(
            tcp_relay_half_close_timeouts(),
            before,
            "正常双向关闭不得触发看门狗计数器"
        );
    }

    /// 并发压测：128 个半关闭且静默的会话必须全部被回收，且每个只计一次。
    ///
    /// 对应任务书 6.3 的压测要求，但不需要 root/TPROXY、也不依赖 `ss` 手工观测：
    /// 看门狗只要漏掉任何一个会话，对应的 relay 任务就不会结束，整体超时即失败。
    /// 每个会话占 4 个 fd（下游、relay 侧下游、relay 侧出站、上游），128 会话约 512 个。
    #[tokio::test]
    async fn concurrent_half_closed_sessions_are_all_reclaimed() {
        let _guard = RELAY_TEST_LOCK.lock().await;
        const SESSIONS: usize = 128;
        // 有 barrier 保证 128 个计时起点一致（见下），宽限期无需为建连阶段放大，
        // 留 2 倍余量仅为极端负载下的时间缓冲。
        const GRACE_SECS: u64 = 2;
        let grace = Some(Duration::from_secs(GRACE_SECS));

        // 所有上游在半关闭之前先在此集合，把「half-close 发起阶段」同步化，消除建连
        // 耗时对宽限期的污染：否则先建好的会话会在“还在建后面 100 多个连接”的这段时间
        // 里先跑满宽限期，慢机器上会让随后对这些 client 的 EOF 读变成 ECONNRESET
        // （连接已被 RST 回收），测试非确定性失败，也会让“看门狗是否漏杀”的结论被建连
        // 耗时污染。
        //
        // 注意这并不等于“计时起点完全一致”：watchdog 的真正上膛时刻取决于各 relay 观察
        // 到 EOF 并完成对应方向 poll_shutdown 的时机，仍受 TCP 与 Tokio 调度影响，只是
        // 差异远小于宽限期。若该差异导致误判，应放大 grace，故这里仍留了余量。
        let barrier = Arc::new(tokio::sync::Barrier::new(SESSIONS + 1));

        let before = tcp_relay_half_close_timeouts();

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let back = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let back_addr = back.local_addr().unwrap();

        // 上游：读一个请求后只关写半边，读半边保持打开且静默，然后统计连接是否被中止。
        let peers_barrier = Arc::clone(&barrier);
        let peers = tokio::spawn(async move {
            let mut handles = Vec::with_capacity(SESSIONS);
            for _ in 0..SESSIONS {
                let (mut peer, _) = back.accept().await.unwrap();
                let barrier = Arc::clone(&peers_barrier);
                handles.push(tokio::spawn(async move {
                    let mut buf = vec![0u8; REQUEST.len()];
                    peer.read_exact(&mut buf).await.unwrap();
                    barrier.wait().await;
                    peer.shutdown().await.unwrap();
                    let mut b = [0u8; 1];
                    // 关键性质：不是干净 EOF——Ok(0) 说明只发了 FIN，那仍会留下
                    // FIN-WAIT-2 隐患。读返回错误说明对端未观察到正常 EOF（Linux 上
                    // 表现为 ECONNRESET）。
                    peer.read(&mut b).await.is_err()
                }));
            }
            let mut aborted = 0;
            for h in handles {
                if h.await.unwrap() {
                    aborted += 1;
                }
            }
            aborted
        });

        // relay：每个会话一个任务，走的是与生产路径完全相同的函数。
        let relays = tokio::spawn(async move {
            let mut handles = Vec::with_capacity(SESSIONS);
            for _ in 0..SESSIONS {
                let (mut client, _) = front.accept().await.unwrap();
                let mut upstream = TcpStream::connect(back_addr).await.unwrap();
                handles.push(tokio::spawn(async move {
                    relay_tcp_streams(&mut client, &mut upstream, false, grace).await
                }));
            }
            let mut ends = Vec::with_capacity(SESSIONS);
            for h in handles {
                ends.push(h.await.unwrap());
            }
            ends
        });

        // 下游客户端：全部建立并发出请求，此后保持打开且静默。
        let mut clients = Vec::with_capacity(SESSIONS);
        for _ in 0..SESSIONS {
            let mut c = TcpStream::connect(front_addr).await.unwrap();
            c.write_all(REQUEST).await.unwrap();
            clients.push(c);
        }

        // 128 个请求都已送达上游，放行半关闭，此后只剩“静默”这一个变量。
        barrier.wait().await;

        // 半关闭必须被传递到每个下游。
        for c in clients.iter_mut() {
            let mut b = [0u8; 16];
            assert_eq!(
                c.read(&mut b).await.unwrap(),
                0,
                "上游的半关闭必须被传递到下游"
            );
        }

        let ends = tokio::time::timeout(Duration::from_secs(GRACE_SECS + 20), relays)
            .await
            .expect("并非所有半关闭静默会话都被回收：有会话仍挂起，即泄漏")
            .expect("relay 任务 panic");

        assert_eq!(ends.len(), SESSIONS);
        for end in &ends {
            assert!(
                matches!(end, Ok(RelayEnd::HalfCloseTimeout { .. })),
                "期望全部为 HalfCloseTimeout，实际出现 {end:?}"
            );
        }

        assert_eq!(
            tcp_relay_half_close_timeouts() - before,
            SESSIONS as u64,
            "每个会话应恰好计一次：既不漏计，也不重复计"
        );

        let aborted = tokio::time::timeout(Duration::from_secs(10), peers)
            .await
            .expect("上游未能全部观察到连接被回收")
            .expect("上游任务 panic");
        assert_eq!(
            aborted, SESSIONS,
            "每个会话都应观察到连接被中止（RST），而不是干净的 FIN"
        );
    }

    /// 半关闭后仍在推进的会话**不得**被回收；停止推进后才回收。
    ///
    /// 这是“绝不误杀”这一核心要求在真实 socket 调度下的验证：`activity_stream`
    /// 的单测只证明 `Activity` 的 touch 逻辑本身，这里证明
    /// `ActivityGuard` + `copy_bidirectional` + 看门狗三者组合起来确实按设计工作
    /// ——即半关闭之后真的存在一条“持续有进展就不会被回收”的路径。
    #[tokio::test]
    async fn a_half_closed_session_with_ongoing_progress_is_not_reclaimed() {
        let _guard = RELAY_TEST_LOCK.lock().await;
        const GRACE_SECS: u64 = 1;
        const GAP_MS: u64 = 300;
        const ACTIVE_ROUNDS: usize = 11;
        // 把「测试参数声明的时间关系」交给编译器检查，避免参数与覆盖说明再次脱节：
        // 1) 每轮**计划**间隔严格小于宽限期，否则某一轮自身就会跑满计时；
        // 2) 活跃阶段**计划**总时长真的跨越 3 个以上宽限期，否则不能声称覆盖多个周期。
        // 注意两者只保证名义关系，不保证运行时墙钟间隔：测试机被严重抢占、sleep 醒来后
        // task 延迟调度时，实际间隔仍可能超过 grace。
        const _: () = assert!(GAP_MS < GRACE_SECS * 1000);
        const _: () = assert!(ACTIVE_ROUNDS as u64 * GAP_MS > 3 * GRACE_SECS * 1000);

        let before = tcp_relay_half_close_timeouts();
        let mut fixture = spawn_relay(Some(Duration::from_secs(GRACE_SECS))).await;

        let mut client = TcpStream::connect(fixture.front).await.unwrap();
        let mut peer = TcpStream::connect(fixture.back).await.unwrap();

        // 由**下游**先半关闭，这样存活方向是 上游→下游，可以继续送数据。
        client.write_all(REQUEST).await.unwrap();
        let mut got = vec![0u8; REQUEST.len()];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(got, REQUEST);
        client.shutdown().await.unwrap();

        // 上游读到 EOF（下游半关闭被 relay 传递），看门狗从这一刻开始计时。
        let mut buf = [0u8; 1];
        assert_eq!(peer.read(&mut buf).await.unwrap(), 0);

        // 活跃阶段：每隔 GAP_MS 送一小块。每一轮的**计划**间隔都严格小于宽限期（由上面的
        // const assert 强制），因此每一轮 relay progress 都应重置倒计时；累计跨越 3 个以上
        // 宽限期仍未被回收，才足以证明「有进展就不误杀」。
        //
        // 本用例验证的是**聚合**性质，不是逐次事件的敏感性：单个 touch 缺失时，相邻进展
        // 间隔仍小于 grace，累计静默不会达到上限，用例不会失败。因此它能覆盖「机制整体
        // 失效」（例如 Activity::touch 变成空操作——已用变异测试确认会失败），但覆盖不到
        // 「偶发丢掉一次重置」。要覆盖后者需要注入式的假时钟，不适合真实 socket 用例。
        for round in 0..ACTIVE_ROUNDS {
            tokio::time::sleep(Duration::from_millis(GAP_MS)).await;
            peer.write_all(b"x").await.unwrap();
            let mut one = [0u8; 1];
            client.read_exact(&mut one).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(1), &mut fixture.task)
                    .await
                    .is_err(),
                "第 {round} 轮仍在活跃传输，会话不得被回收（误杀）"
            );
        }

        // 停止推进：上游保持打开且静默，看门狗应在宽限期内回收。
        let ended = tokio::time::timeout(Duration::from_secs(GRACE_SECS + 5), fixture.task)
            .await
            .expect("停止推进后应在宽限期内被回收")
            .expect("relay 任务 panic");
        assert!(
            matches!(ended, Ok(RelayEnd::HalfCloseTimeout { .. })),
            "期望 HalfCloseTimeout，实际 {ended:?}"
        );
        assert_eq!(
            tcp_relay_half_close_timeouts() - before,
            1,
            "只应在停止推进后回收一次"
        );
    }
}
