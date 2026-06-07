use anyhow::{Context, Result, bail};
use socket2::{Domain, Protocol, Socket, Type};
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
        )
        .await
        {
            Ok(s) => return Ok((s, up)),
            Err(_) => {
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

pub async fn direct_connect(orig_dst: SocketAddr, fwmark: u32) -> Result<TcpStream> {
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

pub async fn handle_tcp_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    orig_dst: SocketAddr,
    state: Arc<AppState>,
) -> Result<()> {
    let sniff_cfg = SniffConfig {
        tcp_peek_buffer_size: state.config.tcp_peek_buffer_size,
    };

    let domain: Option<String> = if state.need_domain_sniff() {
        sniff_domain(&client, orig_dst, &state.sniffers, &sniff_cfg).await
    } else {
        None
    };

    // 分流判断
    let direct = state.should_direct(orig_dst.ip(), domain.as_deref());
    let target = decide_tcp_upstream_target(orig_dst, direct, domain.as_deref());

    // 分流：直连不碰 upstream，不评分
    let (mut upstream, up) = match target {
        TcpUpstreamTarget::Direct(target) => {
            let s = direct_connect(target, state.config.fwmark).await?;
            (s, None)
        }
        _ => {
            let group = if let Some(ref domain_str) = domain {
                state
                    .runtime
                    .client_domain_routes
                    .lookup(client_addr.ip())
                    .and_then(|t| t.lookup(domain_str))
                    .or_else(|| {
                        state
                            .runtime
                            .client_routes
                            .lookup(client_addr.ip())
                            .map(|s| s.as_str())
                    })
                    .unwrap_or("default")
            } else {
                state
                    .runtime
                    .client_routes
                    .lookup(client_addr.ip())
                    .map_or("default", |s| s.as_str())
            };
            let (s, up) = try_connect_socks5_group(&target, &state, group).await?;
            debug!(
                "selected upstream {} at {} (score={:.0}) for {}",
                up.id,
                up.addr,
                up.score(),
                orig_dst
            );
            (s, Some(up))
        }
    };

    let start = Instant::now();
    let _token = up.as_ref().map(|up| up.track(upstream.as_raw_fd()));
    let splice_result =
        splice_or_copy_bidirectional(state.config.splice, &mut client, &mut upstream).await;
    let duration = start.elapsed();

    match splice_result {
        Ok((sent, recv)) => {
            // 只有 SOCKS5 路径才更新分数
            if let Some(ref up) = up {
                info!(
                    "TCP finished: orig_dst={}, upstream={}, score={:.0}, sent={}, recv={}, duration_ms={}",
                    orig_dst,
                    up.id,
                    up.score(),
                    sent,
                    recv,
                    duration.as_millis(),
                );
            } else {
                info!(
                    "TCP direct finished: orig_dst={}, duration_ms={}, sent={}, recv={}",
                    orig_dst,
                    duration.as_millis(),
                    sent,
                    recv,
                );
            }
            Ok(())
        }
        Err(e) => {
            if let Some(ref up) = up {
                error!(
                    "TCP relay error: orig_dst={}, upstream={}, score={:.0}, error={:#}",
                    orig_dst,
                    up.id,
                    up.score(),
                    e
                );
            } else {
                error!(
                    "TCP direct relay error: orig_dst={}, error={:#}",
                    orig_dst, e
                );
            }
            Err(e)
        }
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
                info!("port-forward TCP {} -> {} shutting down", listen_addr, remote);
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
                            debug!("port-forward TCP {} -> {} handler cancelled", peer_addr, remote);
                        }
                        _ = async {
                            let state = state_for_task;
                            info!("port-forward TCP: {} -> {} via SOCKS5", peer_addr, remote);

                            let target = TcpUpstreamTarget::Socks5Ip(remote);
                            let (mut upstream, up) = match try_connect_socks5_group(&target, &state, "default").await {
                                Ok((s, up)) => {
                                    debug!(
                                        "selected upstream {} at {} (score={:.0}) for port-forward {}",
                                        up.id, up.addr, up.score(), remote
                                    );
                                    (s, up)
                                }
                                Err(e) => {
                                    error!(
                                        "port-forward upstream connect failed: remote={}, error={:#}",
                                        remote, e
                                    );
                                    return;
                                }
                            };

                            let start = Instant::now();
                            let _token = up.track(upstream.as_raw_fd());
                            let splice_result = splice_or_copy_bidirectional(
                                state.config.splice,
                                &mut client,
                                &mut upstream,
                            ).await;
                            let duration = start.elapsed();

                            match splice_result {
                                Ok((sent, recv)) => {
                                    info!(
                                        "TCP port-forward finished: remote={}, peer={}, upstream={}, score={:.0}, sent={}, recv={}, duration_ms={}",
                                        remote, peer_addr, up.id, up.score(), sent, recv, duration.as_millis(),
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        "port-forward TCP relay error: remote={}, upstream={}, score={:.0}, error={:#}",
                                        remote, up.id, up.score(), e
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
                                    debug!("TCP handler {} cancelled", peer_addr);
                                }
                                _ = async {
                                    let state = state_for_task;
                                    let orig_dst = match stream.local_addr() {
                                        Ok(addr) => addr,
                                        Err(e) => {
                                            error!("failed to get local_addr: {:#}", e);
                                            return;
                                        }
                                    };

                                    info!("TCP connection: {} -> {}", peer_addr, orig_dst);
                                    if let Err(e) = handle_tcp_connection(stream, peer_addr, orig_dst, state).await {
                                        error!("tcp {} handling error: {:#}", peer_addr, e);
                                    }
                                } => {}
                            }
                        });
                    }
                    Err(e) => {
                        error!("failed to accept TCP connection: {:#}", e);
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
