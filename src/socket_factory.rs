use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::util::{enable_orig_dst_v4, enable_orig_dst_v6, set_socket_reuse, unspecified_addr_for};

pub struct SocketFactory;

impl SocketFactory {
    pub fn new() -> Self {
        Self
    }

    pub fn domain_for(addr: SocketAddr) -> Domain {
        if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        }
    }

    pub fn udp_socket(&self, addr: SocketAddr) -> Result<Socket> {
        Socket::new(Self::domain_for(addr), Type::DGRAM, Some(Protocol::UDP))
            .context("failed to create UDP socket")
    }

    pub fn tcp_socket(&self, addr: SocketAddr) -> Result<Socket> {
        Socket::new(Self::domain_for(addr), Type::STREAM, Some(Protocol::TCP))
            .context("failed to create TCP socket")
    }

    pub fn enable_orig_dst(&self, socket: &Socket, addr: SocketAddr) -> Result<()> {
        if addr.is_ipv4() {
            enable_orig_dst_v4(socket).context("failed to set IP_RECVORIGDSTADDR")?;
        } else {
            enable_orig_dst_v6(socket).context("failed to set IPV6_RECVORIGDSTADDR")?;
        }

        Ok(())
    }

    pub fn apply_socket_options(
        &self,
        socket: &Socket,
        addr: SocketAddr,
        reuse_addr: bool,
        transparent: bool,
        only_v6: Option<bool>,
        mark: Option<u32>,
    ) -> Result<()> {
        if transparent {
            if addr.is_ipv4() {
                socket.set_ip_transparent_v4(true)?;
            } else {
                socket.set_ip_transparent_v6(true)?;
            }
        }

        if let Some(v) = only_v6
            && addr.is_ipv6()
        {
            socket.set_only_v6(v)?;
        }

        if reuse_addr {
            set_socket_reuse(socket)?;
        }

        if let Some(fwmark) = mark {
            socket.set_mark(fwmark)?;
        }

        Ok(())
    }

    pub fn bind_udp_std(
        &self,
        addr: SocketAddr,
        reuse_addr: bool,
        transparent: bool,
        only_v6: Option<bool>,
        mark: Option<u32>,
    ) -> Result<std::net::UdpSocket> {
        let socket = self.udp_socket(addr)?;
        self.apply_socket_options(&socket, addr, reuse_addr, transparent, only_v6, mark)?;
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        Ok(socket.into())
    }

    pub fn bind_tcp_listener(
        &self,
        addr: SocketAddr,
        reuse_addr: bool,
        transparent: bool,
        only_v6: Option<bool>,
        backlog: i32,
    ) -> Result<TcpListener> {
        let socket = self.tcp_socket(addr)?;
        self.apply_socket_options(&socket, addr, reuse_addr, transparent, only_v6, None)?;
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        socket.listen(backlog)?;
        TcpListener::from_std(socket.into()).context("failed to convert to tokio TCP listener")
    }

    pub fn bind_tproxy_udp_socket(
        &self,
        addr: SocketAddr,
        only_v6: Option<bool>,
    ) -> Result<UdpSocket> {
        let socket = self.udp_socket(addr)?;
        self.apply_socket_options(&socket, addr, true, true, only_v6, None)?;
        self.enable_orig_dst(&socket, addr)?;
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        UdpSocket::from_std(socket.into()).context("failed to convert to tokio UDP socket")
    }

    pub fn connect_direct_udp(
        &self,
        target_addr: SocketAddr,
        fwmark: u32,
    ) -> Result<Arc<UdpSocket>> {
        let bind_addr = unspecified_addr_for(target_addr);
        let socket = self.udp_socket(bind_addr)?;
        self.apply_socket_options(&socket, bind_addr, false, false, None, Some(fwmark))?;
        socket.set_nonblocking(true)?;
        socket.bind(&bind_addr.into())?;
        socket
            .connect(&target_addr.into())
            .with_context(|| format!("failed to connect direct UDP socket to {target_addr}"))?;

        let std_udp: std::net::UdpSocket = socket.into();
        Ok(Arc::new(UdpSocket::from_std(std_udp)?))
    }

    pub fn bind_port_forward_udp_listener(&self, addr: SocketAddr) -> Result<Arc<UdpSocket>> {
        let socket = self.udp_socket(addr)?;
        self.apply_socket_options(&socket, addr, true, false, None, None)?;
        socket.set_nonblocking(true)?;
        socket
            .bind(&addr.into())
            .with_context(|| format!("bind port-forward UDP to {addr}"))?;
        Ok(Arc::new(UdpSocket::from_std(socket.into())?))
    }

    /// 创建带 fwmark 的异步 TCP 连接
    pub async fn connect_tcp_stream(&self, addr: SocketAddr, fwmark: u32) -> Result<TcpStream> {
        let socket = self
            .tcp_socket(addr)
            .with_context(|| format!("failed to create TCP socket for {addr}"))?;
        self.apply_socket_options(&socket, addr, false, false, None, Some(fwmark))
            .with_context(|| format!("failed to apply socket options for {addr}"))?;
        socket
            .set_nonblocking(true)
            .with_context(|| format!("failed to set nonblocking for {addr}"))?;
        match socket.connect(&addr.into()) {
            Ok(()) => {}
            Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e).with_context(|| format!("tcp connect to {addr} failed")),
        }
        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)
            .with_context(|| format!("failed to convert to tokio TcpStream for {addr}"))?;
        stream
            .writable()
            .await
            .with_context(|| format!("tcp connect to {addr}: waiting for writable timed out"))?;
        if let Some(e) = stream
            .take_error()
            .with_context(|| format!("failed to query SO_ERROR for {addr}"))?
        {
            return Err(e).with_context(|| format!("tcp connect to {addr} failed after writable"));
        }
        Ok(stream)
    }
}

pub fn create_direct_udp_socket(target_addr: SocketAddr, fwmark: u32) -> Result<Arc<UdpSocket>> {
    SocketFactory::new().connect_direct_udp(target_addr, fwmark)
}

pub fn create_fake_udp_socket(src_addr: SocketAddr, fwmark: u32) -> Result<UdpSocket> {
    let std_udp = SocketFactory::new().bind_udp_std(
        src_addr,
        true,
        true,
        if src_addr.is_ipv6() {
            Some(false)
        } else {
            None
        },
        Some(fwmark),
    )?;
    UdpSocket::from_std(std_udp).context("failed to convert fake UDP socket to tokio")
}

pub fn tproxy_tcp_listener_for_ip(ip: IpAddr, port: u16) -> Result<TcpListener> {
    let sa = SocketAddr::new(ip, port);
    SocketFactory::new().bind_tcp_listener(
        sa,
        true,
        true,
        if sa.is_ipv6() { Some(true) } else { None },
        1024,
    )
}

pub fn create_tproxy_tcp_listeners(
    ip: IpAddr,
    port: u16,
) -> Result<(Option<TcpListener>, Option<TcpListener>)> {
    match ip {
        IpAddr::V4(_) => {
            let v4 = tproxy_tcp_listener_for_ip(ip, port)?;
            Ok((Some(v4), None))
        }
        IpAddr::V6(v6) if v6.is_unspecified() => {
            let v4 = tproxy_tcp_listener_for_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)?;
            let v6 = tproxy_tcp_listener_for_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)?;
            Ok((Some(v4), Some(v6)))
        }
        IpAddr::V6(_) => {
            let v6 = tproxy_tcp_listener_for_ip(ip, port)?;
            Ok((None, Some(v6)))
        }
    }
}

pub fn tproxy_udp_socket_for_ip(ip: IpAddr, port: u16) -> Result<UdpSocket> {
    let sa = SocketAddr::new(ip, port);
    SocketFactory::new().bind_tproxy_udp_socket(sa, if sa.is_ipv6() { Some(true) } else { None })
}

pub fn create_tproxy_udp_sockets(
    ip: IpAddr,
    port: u16,
) -> Result<(Option<UdpSocket>, Option<UdpSocket>)> {
    match ip {
        IpAddr::V4(_) => {
            let v4 = tproxy_udp_socket_for_ip(ip, port)?;
            Ok((Some(v4), None))
        }
        IpAddr::V6(v6) if v6.is_unspecified() => {
            let v4 = tproxy_udp_socket_for_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)?;
            let v6 = tproxy_udp_socket_for_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)?;
            Ok((Some(v4), Some(v6)))
        }
        IpAddr::V6(_) => {
            let v6 = tproxy_udp_socket_for_ip(ip, port)?;
            Ok((None, Some(v6)))
        }
    }
}
