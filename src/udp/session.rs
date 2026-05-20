use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

use crate::socks5::{Socks5UdpAssoc, Socks5UdpTarget, build_socks5_udp_packet};
use crate::util::{is_io_emsgsize, now_secs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum UdpSessionKind {
    Tproxy,
    PortForward { listen_addr: SocketAddr },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct UdpSessionKey {
    pub(crate) kind: UdpSessionKind,
    pub(crate) client_addr: SocketAddr,
    pub(crate) target_addr: SocketAddr,
}

#[derive(Clone)]
pub(crate) enum UdpReplyPath {
    Tproxy,
    PortForward { listen_sock: Arc<UdpSocket> },
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum UdpRoutingMode {
    Auto,
    ForceSocks5,
}

#[derive(Clone)]
pub(crate) struct UdpSessionSpec {
    pub(crate) key: UdpSessionKey,
    pub(crate) routing: UdpRoutingMode,
    pub(crate) reply_path: UdpReplyPath,
    pub(crate) sniffed_host: Option<String>,
}

impl UdpSessionSpec {
    pub(crate) fn for_tproxy(client_addr: SocketAddr, orig_dst: SocketAddr) -> Self {
        Self {
            key: UdpSessionKey {
                kind: UdpSessionKind::Tproxy,
                client_addr,
                target_addr: orig_dst,
            },
            routing: UdpRoutingMode::Auto,
            reply_path: UdpReplyPath::Tproxy,
            sniffed_host: None,
        }
    }

    pub(crate) fn for_port_forward(
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
            sniffed_host: None,
        }
    }
}

pub(crate) enum UdpSessionEntry {
    Creating(Arc<tokio::sync::Notify>),
    Ready(Arc<UdpSession>),
}

pub(crate) struct UdpSession {
    pub(crate) spec: UdpSessionSpec,
    pub(crate) outbound: UdpOutbound,
    pub(crate) last_seen_secs: AtomicU64,
    pub(crate) cancel: CancellationToken,

    // NOTE: 自引用环风险。
    // recv_task 持有本 session 的 recv loop JoinHandle，
    // 而 recv loop task 内部又持有 Arc<UdpSession>。
    // 正常路径下 task 收到 cancel 后迅速退出，future drop 打破环。
    // 若 task 异常卡住（如 I/O 死锁），session 可能无法释放。
    // 当前可接受；未来若出现泄漏，应将 handle 移到 UdpRuntime 统一管理。
    pub(crate) recv_task: Mutex<Option<JoinHandle<()>>>,
}

pub(crate) enum UdpOutbound {
    Direct { socket: Arc<UdpSocket> },
    Socks5 { assoc: Socks5UdpAssoc },
}

impl UdpSession {
    pub(crate) fn key(&self) -> UdpSessionKey {
        self.spec.key
    }

    pub(crate) fn touch(&self) {
        self.last_seen_secs.store(now_secs(), Ordering::Relaxed);
    }

    pub(crate) async fn send_payload(&self, payload: &[u8]) -> Result<usize> {
        let key = self.key();

        match &self.outbound {
            UdpOutbound::Direct { socket } => {
                trace!(
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
                        Ok(0)
                    }
                    Err(e) => Err(e).context("direct UDP send failed"),
                }
            }
            UdpOutbound::Socks5 { assoc } => {
                let target = if let Some(host) = self.spec.sniffed_host.as_deref() {
                    Socks5UdpTarget::Domain {
                        host,
                        port: key.target_addr.port(),
                    }
                } else {
                    Socks5UdpTarget::Ip(key.target_addr)
                };

                let socks_target_log = match &target {
                    Socks5UdpTarget::Ip(addr) => format!("ip:{addr}"),
                    Socks5UdpTarget::Domain { host, port } => format!("domain:{host}:{port}"),
                };

                let pkt = match build_socks5_udp_packet(target, payload) {
                    Ok(pkt) => pkt,
                    Err(e) => {
                        warn!(
                            "UDP SOCKS5 packet build failed: kind={:?}, client={}, target={}, sniffed_host={:?}, error={:#}",
                            key.kind, key.client_addr, key.target_addr, self.spec.sniffed_host, e
                        );
                        return Ok(0);
                    }
                };

                trace!(
                    "UDP SOCKS5 send: kind={:?}, client={}, original_target={}, socks_target={}, payload_len={}, pkt_len={}, relay={}",
                    key.kind,
                    key.client_addr,
                    key.target_addr,
                    socks_target_log,
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
                        Ok(0)
                    }
                    Err(e) => Err(e).context("SOCKS5 UDP send failed"),
                }
            }
        }
    }
}
