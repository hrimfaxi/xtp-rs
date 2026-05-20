use anyhow::{Context, Result, anyhow, bail};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::trace;

use crate::util::hex_encode;

#[derive(Debug)]
pub struct Socks5UdpAssoc {
    pub(crate) _control: TcpStream,
    pub(crate) relay_addr: SocketAddr,
    pub(crate) udp_socket: Arc<UdpSocket>,
}

pub enum Socks5Target<'a> {
    Ip(SocketAddr),
    Domain(&'a str, u16),
}

pub enum Socks5UdpTarget<'a> {
    Ip(SocketAddr),
    Domain { host: &'a str, port: u16 },
}

pub fn build_socks5_udp_packet(target: Socks5UdpTarget<'_>, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(3 + 1 + 255 + 2 + payload.len());

    out.extend_from_slice(&[0x00, 0x00, 0x00]);

    match target {
        Socks5UdpTarget::Ip(SocketAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        Socks5UdpTarget::Ip(SocketAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
        Socks5UdpTarget::Domain { host, port } => {
            let host_bytes = host.as_bytes();

            if host_bytes.is_empty() || host_bytes.len() > 255 {
                bail!("invalid SOCKS5 UDP domain length: {}", host_bytes.len());
            }

            out.push(0x03);
            out.push(host_bytes.len() as u8);
            out.extend_from_slice(host_bytes);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }

    out.extend_from_slice(payload);

    Ok(out)
}

pub fn parse_socks5_udp_packet_with_fallback_src(
    pkt: &[u8],
    fallback_src: SocketAddr,
) -> Result<(SocketAddr, &[u8])> {
    if pkt.len() < 4 {
        bail!("SOCKS5 UDP packet too short");
    }

    if pkt[0] != 0x00 || pkt[1] != 0x00 {
        bail!("invalid SOCKS5 UDP reserved fields");
    }

    if pkt[2] != 0x00 {
        bail!("fragmented SOCKS5 UDP not supported");
    }

    let atyp = pkt[3];
    let mut off = 4;

    let src = match atyp {
        0x01 => {
            if pkt.len() < off + 4 + 2 {
                bail!("short IPv4 SOCKS5 UDP packet");
            }

            let ip = Ipv4Addr::new(pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]);
            off += 4;

            let port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            off += 2;

            SocketAddr::new(IpAddr::V4(ip), port)
        }
        0x04 => {
            if pkt.len() < off + 16 + 2 {
                bail!("short IPv6 SOCKS5 UDP packet");
            }

            let mut ip = [0u8; 16];
            ip.copy_from_slice(&pkt[off..off + 16]);
            off += 16;

            let port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            off += 2;

            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
        }
        0x03 => {
            if pkt.len() < off + 1 {
                bail!("short domain SOCKS5 UDP packet");
            }

            let name_len = pkt[off] as usize;
            off += 1;

            if pkt.len() < off + name_len + 2 {
                bail!("short domain SOCKS5 UDP packet address");
            }

            off += name_len;

            let _port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            off += 2;

            fallback_src
        }
        _ => bail!("invalid SOCKS5 UDP address type: {:#x}", atyp),
    };

    Ok((src, &pkt[off..]))
}

pub async fn socks5_auth(stream: &mut TcpStream, creds: Option<(&str, &str)>) -> Result<()> {
    if let Some((user, pass)) = creds {
        if user.is_empty() || user.len() > 255 || pass.is_empty() || pass.len() > 255 {
            bail!("invalid SOCKS5 username/password length");
        }

        stream
            .write_all(&[0x05, 0x02, 0x00, 0x02])
            .await
            .context("failed to send SOCKS5 auth methods")?;

        let mut resp = [0u8; 2];
        stream
            .read_exact(&mut resp)
            .await
            .context("failed to read SOCKS5 method selection")?;

        if resp[0] != 0x05 {
            bail!("invalid SOCKS5 version in method selection");
        }

        match resp[1] {
            0x00 => bail!("SOCKS5 server chose no-auth, but username/password required"),
            0x02 => {
                let mut up_req = Vec::with_capacity(3 + user.len() + pass.len());
                up_req.push(0x01);
                up_req.push(user.len() as u8);
                up_req.extend_from_slice(user.as_bytes());
                up_req.push(pass.len() as u8);
                up_req.extend_from_slice(pass.as_bytes());

                stream
                    .write_all(&up_req)
                    .await
                    .context("failed to send SOCKS5 username/password")?;

                let mut up_resp = [0u8; 2];
                stream
                    .read_exact(&mut up_resp)
                    .await
                    .context("failed to read SOCKS5 username/password reply")?;

                if up_resp[0] != 0x01 || up_resp[1] != 0x00 {
                    bail!("SOCKS5 username/password authentication failed");
                }
            }
            _ => bail!("unsupported SOCKS5 auth method chosen: {:#x}", resp[1]),
        }
    } else {
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .context("failed to send SOCKS5 no-auth request")?;

        let mut buf = [0u8; 2];
        stream
            .read_exact(&mut buf)
            .await
            .context("failed to read SOCKS5 no-auth response")?;

        if buf != [0x05, 0x00] {
            bail!("SOCKS5 no-auth negotiation failed, got {:?}", buf);
        }
    }
    Ok(())
}

pub async fn socks5_connect(
    target: Socks5Target<'_>,
    socks5_addr: SocketAddr,
    fwmark: u32,
    creds: Option<(&str, &str)>,
) -> Result<TcpStream> {
    let domain = if socks5_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create socket for SOCKS5 connect")?;

    socket.set_mark(fwmark)?;
    socket.set_nonblocking(true)?;

    match socket.connect(&socks5_addr.into()) {
        Ok(_) => {}
        Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e).context("SOCKS5 connect failed"),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let mut stream = TcpStream::from_std(std_stream)?;

    stream.writable().await?;

    if let Some(e) = stream.take_error()? {
        return Err(e).context("SOCKS5 connect handshake error");
    }

    socks5_auth(&mut stream, creds).await?;

    let mut req = vec![0x05, 0x01, 0x00];

    match target {
        Socks5Target::Ip(SocketAddr::V4(v4)) => {
            req.push(0x01);
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
            trace!("SOCKS5 connect by IPv4: {}", SocketAddr::V4(v4));
        }
        Socks5Target::Ip(SocketAddr::V6(v6)) => {
            req.push(0x04);
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
            trace!("SOCKS5 connect by IPv6: {}", SocketAddr::V6(v6));
        }
        Socks5Target::Domain(host, port) => {
            let host_bytes = host.as_bytes();
            if host_bytes.is_empty() || host_bytes.len() > 255 {
                bail!("invalid SOCKS5 domain length: {}", host_bytes.len());
            }

            req.push(0x03);
            req.push(host_bytes.len() as u8);
            req.extend_from_slice(host_bytes);
            req.extend_from_slice(&port.to_be_bytes());
            trace!("SOCKS5 connect by domain: {}:{}", host, port);
        }
    }

    stream
        .write_all(&req)
        .await
        .context("failed to send SOCKS5 connect request")?;

    let mut resp = [0u8; 4];
    stream
        .read_exact(&mut resp)
        .await
        .context("failed to read SOCKS5 connect response")?;

    if resp[0] != 0x05 {
        bail!("invalid SOCKS5 version in connect response: {:#x}", resp[0]);
    }

    if resp[1] != 0x00 {
        bail!("SOCKS5 connect failed, reply code {:#x}", resp[1]);
    }

    if resp[2] != 0x00 {
        bail!(
            "invalid SOCKS5 reserved field in connect response: {:#x}",
            resp[2]
        );
    }

    let skip_len = match resp[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        _ => bail!("invalid SOCKS5 address type in response: {:#x}", resp[3]),
    };

    let mut dummy = vec![0u8; skip_len];
    stream
        .read_exact(&mut dummy)
        .await
        .context("failed to skip SOCKS5 address in response")?;

    Ok(stream)
}

pub async fn socks5_udp_associate_for_client(
    socks5_addr: SocketAddr,
    fwmark: u32,
    creds: Option<(&str, &str)>,
) -> Result<Socks5UdpAssoc> {
    let domain = if socks5_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let tcp_sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create TCP socket for UDP ASSOCIATE")?;

    tcp_sock.set_mark(fwmark)?;
    tcp_sock.set_nonblocking(true)?;

    match tcp_sock.connect(&socks5_addr.into()) {
        Ok(_) => {}
        Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e).context("SOCKS5 UDP ASSOCIATE connect failed"),
    }

    let std_stream: std::net::TcpStream = tcp_sock.into();
    let mut control = TcpStream::from_std(std_stream)?;

    control.writable().await?;

    if let Some(e) = control.take_error()? {
        return Err(e).context("SOCKS5 UDP ASSOCIATE handshake error");
    }

    socks5_auth(&mut control, creds).await?;

    let req = if socks5_addr.is_ipv4() {
        vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    } else {
        let mut v = vec![0x05, 0x03, 0x00, 0x04];
        v.extend_from_slice(&[0u8; 16]);
        v.extend_from_slice(&[0u8; 2]);
        v
    };

    if tracing::enabled!(tracing::Level::TRACE) {
        trace!("SOCKS5 UDP ASSOCIATE req hex = {}", hex_encode(&req));
    }
    control
        .write_all(&req)
        .await
        .context("failed to send SOCKS5 UDP ASSOCIATE request")?;

    let mut head = [0u8; 4];
    control
        .read_exact(&mut head)
        .await
        .context("failed to read SOCKS5 UDP ASSOCIATE reply header")?;

    if head[0] != 0x05 {
        bail!("invalid SOCKS5 version in UDP ASSOCIATE reply");
    }

    if head[1] != 0x00 {
        bail!("SOCKS5 UDP ASSOCIATE failed, reply code {:#x}", head[1]);
    }

    if head[2] != 0x00 {
        bail!(
            "invalid SOCKS5 reserved field in UDP ASSOCIATE reply: {:#x}",
            head[2]
        );
    }

    let trace_resp = |body: &[u8]| {
        if tracing::enabled!(tracing::Level::TRACE) {
            let mut full = Vec::with_capacity(head.len() + body.len());
            full.extend_from_slice(&head);
            full.extend_from_slice(body);
            trace!("SOCKS5 UDP ASSOCIATE resp hex = {}", hex_encode(&full));
        }
    };

    let relay_addr = match head[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            control.read_exact(&mut buf).await?;
            trace_resp(&buf);
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            SocketAddr::new(IpAddr::V4(ip), port)
        }
        0x04 => {
            let mut buf = [0u8; 18];
            control.read_exact(&mut buf).await?;
            trace_resp(&buf);
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
        }
        0x03 => {
            let mut l = [0u8; 1];
            control.read_exact(&mut l).await?;
            let len = l[0] as usize;
            let mut rest = vec![0u8; len + 2];
            control.read_exact(&mut rest).await?;
            if tracing::enabled!(tracing::Level::TRACE) {
                let mut body = Vec::with_capacity(1 + rest.len());
                body.extend_from_slice(&l);
                body.extend_from_slice(&rest);
                trace_resp(&body);
            }
            let host = std::str::from_utf8(&rest[..len])
                .context("invalid relay domain name in SOCKS5 UDP ASSOCIATE reply")?;
            let port = u16::from_be_bytes([rest[len], rest[len + 1]]);

            let mut iter = tokio::net::lookup_host((host, port))
                .await
                .context("failed to resolve relay domain")?;

            iter.next()
                .ok_or_else(|| anyhow!("failed to resolve relay domain to an IP address"))?
        }
        _ => bail!(
            "invalid address type in SOCKS5 UDP ASSOCIATE reply: {:#x}",
            head[3]
        ),
    };

    // SOCKS5 服务器返回 0.0.0.0 / [::] 时，应 fallback 到 socks5 server 本身的地址
    let relay_addr = if relay_addr.ip().is_unspecified() {
        SocketAddr::new(socks5_addr.ip(), relay_addr.port())
    } else {
        relay_addr
    };

    let udp_domain = if relay_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let udp_sock = Socket::new(udp_domain, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create UDP socket for ASSOCIATE")?;

    udp_sock.set_mark(fwmark)?;
    udp_sock.set_nonblocking(true)?;

    if relay_addr.is_ipv4() {
        udp_sock.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).into())?;
    } else {
        udp_sock.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).into())?;
    }

    udp_sock
        .connect(&relay_addr.into())
        .with_context(|| format!("failed to connect to SOCKS5 relay {relay_addr}"))?;

    let std_udp: std::net::UdpSocket = udp_sock.into();
    let udp_socket = Arc::new(UdpSocket::from_std(std_udp)?);

    Ok(Socks5UdpAssoc {
        _control: control,
        relay_addr,
        udp_socket,
    })
}
