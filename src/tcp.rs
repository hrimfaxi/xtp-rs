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
            state.config.tcp_nodelay,
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
    tcp_nodelay: bool,
) -> Result<TcpStream> {
    match target {
        TcpUpstreamTarget::Direct(addr) => {
            debug!(addr = %addr, "direct connect");
            tokio::time::timeout(timeout, direct_connect(*addr, fwmark, tcp_nodelay))
                .await
                .map_err(|_| anyhow!("direct connect timeout"))?
        }
        TcpUpstreamTarget::Socks5Ip(addr) => {
            debug!(addr = %addr, "proxy connect by ip");
            tokio::time::timeout(
                timeout,
                socks5_connect(
                    Socks5Target::Ip(*addr),
                    socks5_addr,
                    fwmark,
                    creds,
                    tcp_nodelay,
                ),
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
                    tcp_nodelay,
                ),
            )
            .await
            .map_err(|_| anyhow!("SOCKS5 connect timeout"))?
        }
    }
}

pub async fn direct_connect(
    orig_dst: SocketAddr,
    fwmark: u32,
    tcp_nodelay: bool,
) -> Result<TcpStream> {
    debug!(dst = %orig_dst, "direct connect");
    SocketFactory::new()
        .connect_tcp_stream(orig_dst, fwmark, tcp_nodelay)
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
        Ok(RelayEnd::HalfCloseTimeout { grace_secs }) => {
            // 每次触发一条，不做采样：这条日志同时是“泄漏是否仍在发生”的唯一现场证据，
            // 采样会掩盖泄漏速率。带上累计值，运维可直接从日志算出回收速率。
            let total = tcp_relay_half_close_timeouts();
            if let Some(up) = up {
                warn!(
                    target = %target,
                    upstream_id = %up.id,
                    grace_secs = grace_secs,
                    duration_ms = duration.as_millis(),
                    total = total,
                    "TCP relay half-closed and silent, session reclaimed with RST"
                );
            } else {
                warn!(
                    target = %target,
                    grace_secs = grace_secs,
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
            let mut upstream = tokio::time::timeout(
                timeout,
                direct_connect(target_addr, state.config.fwmark, state.config.tcp_nodelay),
            )
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
            let s = tokio::time::timeout(
                timeout,
                direct_connect(target_addr, state.config.fwmark, state.config.tcp_nodelay),
            )
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
                    state.config.tcp_nodelay,
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
                // 回程方向（上游 -> 客户端）；accept 循环里丢弃错误：为一个
                // socket 选项拒绝连接（或打断整个循环）比付这段延迟更糟。
                if state.config.tcp_nodelay {
                    let _ = client.set_nodelay(true);
                }
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
                                Ok(RelayEnd::HalfCloseTimeout { grace_secs }) => {
                                    warn!(
                                        remote = %remote,
                                        peer = %peer_addr,
                                        upstream_id = %up.id,
                                        grace_secs = grace_secs,
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
                        // 回程方向（上游 -> 客户端）；accept 循环里丢弃错误，理由同上。
                        if state.config.tcp_nodelay {
                            let _ = stream.set_nodelay(true);
                        }
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
    // 计时语义已由 `src/relay.rs` 的 duplex + 暂停时钟单测确定性地覆盖，这里只留
    // 必须用真 socket 才能验证的两条性质：
    // 1. 回收时确实发出 RST（`SO_LINGER=0` 只对真实 fd 有意义）；
    // 2. 正常双向关闭仍走 FIN，不会被误判成泄漏回收。
    //
    // 不依赖 TPROXY/root：直接用两个已建立的 `TcpStream` 调用 `relay_tcp_streams`，
    // 与 `handle_tcp_connection` 的调用方式完全一致。上游由测试端自己扮演——它连到
    // `back`，relay 侧 accept 出来的就是出站 socket。

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

    /// 上游读一个请求、只关写半边、读半边保持打开且此后完全静默：`copy_bidirectional`
    /// 需要一个方向 EOF 才可能返回，而这个上游永远不关读半边，于是 relay 永久挂起。
    ///
    /// 关键断言是「对端没有观察到正常 EOF」——读到 `Ok(0)` 说明只发了 FIN，连接仍会
    /// 挂在 FIN-WAIT-2 上，回收就没意义了。
    #[tokio::test]
    async fn half_closed_and_silent_session_is_reclaimed_with_rst() {
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

        // 上游的半关闭被 relay 传递到下游：b→a 方向结束，计时就此上膛。
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
            Ok(RelayEnd::HalfCloseTimeout { grace_secs }) => assert_eq!(
                grace_secs, GRACE_SECS,
                "返回值就是配置的宽限期本身，不是实测静默时长"
            ),
            other => panic!("期望 HalfCloseTimeout，实际 {other:?}"),
        }

        // 计数器是进程级共享量，并行跑的其他用例也可能计入，因此只断言单调增长。
        assert!(
            tcp_relay_half_close_timeouts() > before,
            "tcp_relay_half_close_timeout_total 应增长"
        );

        // 读到错误只证明「不是干净 EOF」，要坐实「确实发了 RST」需要具体 errno。
        // xtp-rs 只支持 Linux（TPROXY），因此在受支持平台上再补一条更强的断言；
        // 用 #[cfg] 而不是 cfg!：非 Linux 平台既不编译也不维护这条断言。
        let err = peer
            .read(&mut buf)
            .await
            .expect_err("超时回收后上游不应观察到正常 EOF");
        #[cfg(target_os = "linux")]
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        #[cfg(not(target_os = "linux"))]
        drop(err);
    }

    /// 正常双向关闭（两边都走到 EOF）仍然是干净的 FIN，且不被算作泄漏回收。
    ///
    /// 宽限期给足 30s，远长于本用例在 loopback 上跑完所需的时间：如果超时是唯一能
    /// 结束它的东西，15s 的外层超时会先失败。
    #[tokio::test]
    async fn a_normal_both_sided_close_ends_with_fin() {
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
            .expect("正常双向关闭应在超时之前结束")
            .expect("relay 任务 panic");

        // 返回 Finished 本身就等价于「本次会话未走超时路径、未计入泄漏计数器」：
        // 两者在 relay_tcp_streams 里是同一个分支。
        match ended {
            Ok(RelayEnd::Finished { sent, recv }) => {
                assert_eq!(sent as usize, REQUEST.len());
                assert_eq!(recv as usize, RESPONSE.len());
            }
            other => panic!("期望 Finished，实际 {other:?}"),
        }
    }
}
