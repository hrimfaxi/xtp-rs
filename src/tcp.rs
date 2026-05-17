use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
#[allow(unused_imports)]
use tracing::{debug, error, info, trace};

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

/// 尝试连 SOCKS5，失败时惩罚当前 upstream 并自动换一个
async fn try_connect_socks5(
    target: &TcpUpstreamTarget,
    state: &Arc<AppState>,
) -> Result<(TcpStream, Arc<Upstream>)> {
    let up = state.upstreams.pick();
    match connect_tcp_upstream(
        target,
        up.addr,
        state.config.fwmark,
        state.socks5_credentials(),
    )
    .await
    {
        Ok(s) => Ok((s, up)),
        Err(e) => {
            // 第一个 upstream 建连失败，惩罚它
            if !state.config.disable_upstream_score {
                up.penalize();
            }

            // 排除被惩罚的这个，选另一个
            match state.upstreams.pick_excluding(&up.id) {
                Some(up2) => {
                    match connect_tcp_upstream(
                        target,
                        up2.addr,
                        state.config.fwmark,
                        state.socks5_credentials(),
                    )
                    .await
                    {
                        Ok(s) => Ok((s, up2)),
                        Err(e2) => Err(e2), // 第二个也失败，不再惩罚
                    }
                }
                None => Err(e), // 没别的可选了
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

    // 分流：直连不碰 upstream，不评分
    let (mut upstream, up) = match target {
        TcpUpstreamTarget::Direct(target) => {
            let s = direct_connect(target, state.config.fwmark).await?;
            (s, None)
        }
        _ => {
            let (s, up) = try_connect_socks5(&target, &state).await?;
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
    let _token = if let Some(ref up) = up {
        Some(up.track(upstream.as_raw_fd()))
    } else {
        None
    };
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
            let (mut upstream, up) = match try_connect_socks5(&target, &state).await {
                Ok((s, up)) => {
                    debug!(
                        "selected upstream {} at {} (score={:.0}) for port-forward {}",
                        up.id,
                        up.addr,
                        up.score(),
                        remote
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
            let splice_result =
                splice_or_copy_bidirectional(state.config.splice, &mut client, &mut upstream).await;
            let duration = start.elapsed();

            match splice_result {
                Ok((sent, recv)) => {
                    info!(
                        "TCP port-forward finished: remote={}, peer={}, upstream={}, score={:.0}, sent={}, recv={}, duration_ms={}",
                        remote,
                        peer_addr,
                        up.id,
                        up.score(),
                        sent,
                        recv,
                        duration.as_millis(),
                    );
                }
                Err(e) => {
                    error!(
                        "port-forward TCP relay error: remote={}, upstream={}, score={:.0}, error={:#}",
                        remote,
                        up.id,
                        up.score(),
                        e
                    );
                }
            }
        });
    }
}

pub async fn tcp_accept_loop(listener: TcpListener, state: Arc<AppState>) {
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
