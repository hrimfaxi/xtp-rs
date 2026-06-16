use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
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
use crate::util::splice_or_copy_bidirectional;

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
) -> Result<(TcpStream, Arc<Upstream>)> {
    let mut failed: HashSet<String> = HashSet::new();

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
                .map_err(|_| anyhow::anyhow!("direct connect timeout"))?
        }
        TcpUpstreamTarget::Socks5Ip(addr) => {
            debug!(addr = %addr, "proxy connect by ip");
            tokio::time::timeout(
                timeout,
                socks5_connect(Socks5Target::Ip(*addr), socks5_addr, fwmark, creds),
            )
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS5 connect timeout"))?
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
            .map_err(|_| anyhow::anyhow!("SOCKS5 connect timeout"))?
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
    target: SocketAddr,
    up: Option<&Upstream>,
    start: Instant,
) -> Result<()> {
    let splice_result = splice_or_copy_bidirectional(splice, client, upstream).await;
    let duration = start.elapsed();

    match splice_result {
        Ok((sent, recv)) => {
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
        Err(e) => {
            if let Some(up) = up {
                error!(
                    target = %target,
                    upstream_id = %up.id,
                    score = up.score(),
                    error = format!("{:#}", e),
                    "TCP relay error"
                );
            } else {
                error!(
                    target = %target,
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
) -> Result<(TcpStream, Arc<Upstream>)> {
    trace!(
        client = %client_addr,
        orig_dst = %orig_dst,
        domain = ?domain,
        "tcp upstream select"
    );

    let group = if let Some(domain_str) = domain {
        let domain_group = state
            .runtime
            .client_domain_routes
            .lookup(client_addr.ip())
            .and_then(|t| t.lookup(domain_str));
        trace!(
            client_ip = %client_addr.ip(),
            domain = %domain_str,
            domain_result = %domain_group.unwrap_or("None"),
            "tcp client_domain_routes lookup"
        );

        let ip_group = state.runtime.client_routes.lookup(client_addr.ip());
        trace!(
            client_ip = %client_addr.ip(),
            ip_result = %ip_group.map(|s| s.as_str()).unwrap_or("None"),
            "tcp client_routes lookup"
        );

        domain_group
            .or_else(|| ip_group.map(|s| s.as_str()))
            .unwrap_or("default")
    } else {
        let ip_group = state.runtime.client_routes.lookup(client_addr.ip());
        trace!(
            client_ip = %client_addr.ip(),
            ip_result = %ip_group.map(|s| s.as_str()).unwrap_or("None"),
            "tcp client_routes lookup (no domain)"
        );

        ip_group.map_or("default", |s| s.as_str())
    };

    trace!(
        client = %client_addr,
        group = %group,
        "tcp selected group"
    );

    let (s, up) = try_connect_socks5_group(target, state, group).await?;
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
                    .map_err(|_| anyhow::anyhow!("direct connect timeout"))??;
            return relay_tcp(
                &mut client,
                &mut upstream,
                state.config.splice,
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
                .map_err(|_| anyhow::anyhow!("direct connect timeout"))??;
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
                        )
                        .await?;
                        (s, Some(up))
                    }
                }
            } else {
                let (s, up) =
                    pick_and_connect(&target, &state, &client_addr, orig_dst, domain.as_deref())
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
        let token = up.track(upstream.as_raw_fd()).await;
        let result = relay_tcp(
            &mut client,
            &mut upstream,
            state.config.splice,
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
                            let (mut upstream, up) = match try_connect_socks5_group(&target, &state, "default").await {
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
                            let _token = up.track(upstream.as_raw_fd()).await;
                            let splice_result = splice_or_copy_bidirectional(
                                state.config.splice,
                                &mut client,
                                &mut upstream,
                            ).await;
                            let duration = start.elapsed();

                            match splice_result {
                                Ok((sent, recv)) => {
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
                                Err(e) => {
                                    error!(
                                        remote = %remote,
                                        upstream_id = %up.id,
                                        score = up.score(),
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
}
