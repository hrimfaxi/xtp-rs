use anyhow::Result;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::io::Interest;
use tokio::net::UdpSocket;

use crate::util::{errno_to_io, sockaddr_in_to_std, sockaddr_in6_to_std, sockaddr_storage_to_std};

pub(crate) struct TProxyUdpSocket {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) fd: i32,
}

impl TProxyUdpSocket {
    pub(crate) fn new(socket: UdpSocket) -> Self {
        let fd = socket.as_raw_fd();
        Self {
            socket: Arc::new(socket),
            fd,
        }
    }

    pub(crate) async fn recv_packet(&self, buf: &mut [u8]) -> Result<TProxyUdpPacketMeta> {
        loop {
            self.socket.readable().await?;

            let result = self.socket.try_io(Interest::READABLE, || {
                let (len, client_addr, orig_dst) = Self::recv_udp_tproxy_packet_raw(self.fd, buf)?;

                let orig_dst = orig_dst.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("udp packet from {client_addr} missing original destination"),
                    )
                })?;

                Ok(TProxyUdpPacketMeta {
                    len,
                    client_addr,
                    orig_dst,
                })
            });

            match result {
                Ok(packet) => return Ok(packet),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn recv_udp_tproxy_packet_raw(
        fd: i32,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
        let mut iov = [IoSliceMut::new(buf)];
        let mut cmsgspace = nix::cmsg_space!([libc::sockaddr_in; 1], [libc::sockaddr_in6; 1]);

        let msg = recvmsg::<SockaddrStorage>(fd, &mut iov, Some(&mut cmsgspace), MsgFlags::empty())
            .map_err(errno_to_io)?;

        if msg.flags.contains(MsgFlags::MSG_CTRUNC) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "udp control message truncated",
            ));
        }

        let client_addr = msg
            .address
            .as_ref()
            .and_then(sockaddr_storage_to_std)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid peer sockaddr"))?;

        let mut orig_dst = None;
        for cmsg in msg.cmsgs().map_err(errno_to_io)? {
            match cmsg {
                ControlMessageOwned::Ipv4OrigDstAddr(addr) => {
                    orig_dst = Some(sockaddr_in_to_std(addr));
                    break;
                }
                ControlMessageOwned::Ipv6OrigDstAddr(addr) => {
                    orig_dst = Some(sockaddr_in6_to_std(addr));
                    break;
                }
                _ => {}
            }
        }

        Ok((msg.bytes, client_addr, orig_dst))
    }
}

#[derive(Debug)]
pub(crate) struct TProxyUdpPacketMeta {
    pub(crate) len: usize,
    pub(crate) client_addr: SocketAddr,
    pub(crate) orig_dst: SocketAddr,
}
