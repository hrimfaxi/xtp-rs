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
        if self.cancel.is_cancelled() {
            anyhow::bail!("UDP session cancelled");
        }

        let key = self.key();

        match &self.outbound {
            UdpOutbound::Direct { socket } => {
                trace!(
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    payload_len = payload.len(),
                    "UDP direct send"
                );

                match socket.send(payload).await {
                    Ok(sent) => Ok(sent),
                    Err(e) if is_io_emsgsize(&e) => {
                        warn!(
                            kind = ?key.kind,
                            client = %key.client_addr,
                            target = %key.target_addr,
                            payload_len = payload.len(),
                            error = format!("{:#}", e),
                            "UDP datagram dropped due to EMSGSIZE"
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
                            kind = ?key.kind,
                            client = %key.client_addr,
                            target = %key.target_addr,
                            sniffed_host = ?self.spec.sniffed_host,
                            error = format!("{:#}", e),
                            "UDP SOCKS5 packet build failed"
                        );
                        return Ok(0);
                    }
                };

                trace!(
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    socks_target = %socks_target_log,
                    payload_len = payload.len(),
                    pkt_len = pkt.len(),
                    relay = %assoc.relay_addr,
                    "UDP SOCKS5 send"
                );

                match assoc.udp_socket.send(&pkt).await {
                    Ok(sent) => Ok(sent),
                    Err(e) if is_io_emsgsize(&e) => {
                        warn!(
                            kind = ?key.kind,
                            client = %key.client_addr,
                            target = %key.target_addr,
                            payload_len = payload.len(),
                            pkt_len = pkt.len(),
                            relay = %assoc.relay_addr,
                            error = format!("{:#}", e),
                            "UDP datagram dropped due to EMSGSIZE: direction=client_to_socks5"
                        );
                        Ok(0)
                    }
                    Err(e) => Err(e).context("SOCKS5 UDP send failed"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn for_tproxy_sets_correct_fields() {
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 12345);
        let orig_dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let spec = UdpSessionSpec::for_tproxy(client, orig_dst);
        assert_eq!(spec.key.client_addr, client);
        assert_eq!(spec.key.target_addr, orig_dst);
        assert!(matches!(spec.key.kind, UdpSessionKind::Tproxy));
        assert!(matches!(spec.routing, UdpRoutingMode::Auto));
        assert!(matches!(spec.reply_path, UdpReplyPath::Tproxy));
        assert!(spec.sniffed_host.is_none());
    }

    #[tokio::test]
    async fn for_port_forward_sets_correct_fields() {
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let listen = "127.0.0.1:5353".parse().unwrap();
        let client = "127.0.0.1:12345".parse().unwrap();
        let remote = "8.8.8.8:53".parse().unwrap();

        let spec = UdpSessionSpec::for_port_forward(listen, client, remote, sock);

        assert_eq!(spec.key.client_addr, client);
        assert_eq!(spec.key.target_addr, remote);
        assert!(matches!(
                spec.key.kind,
                UdpSessionKind::PortForward { listen_addr } if listen_addr == listen
        ));
        assert!(matches!(spec.routing, UdpRoutingMode::ForceSocks5));
        assert!(matches!(spec.reply_path, UdpReplyPath::PortForward { .. }));
    }
}
