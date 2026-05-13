#!/usr/bin/env python3
import socket
import struct
import sys
import random

from hexdump import hexdump


SOCKS5_ADDR = ("127.0.0.1", 10808)
DNS_SERVER = ("8.8.8.8", 53)
TIMEOUT = 5.0


def build_dns_query(name: str, qtype: int = 1) -> bytes:
    # 一个最小 DNS 查询包
    # qtype: 1=A, 28=AAAA
    txid = random.randint(0, 0xFFFF)
    flags = 0x0100  # recursion desired
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)

    qname = b""
    for part in name.split("."):
        qname += bytes([len(part)])
        qname += part.encode("ascii")
    qname += b"\x00"

    question = qname + struct.pack("!HH", qtype, 1)  # QCLASS=IN
    return header + question


def parse_socks5_reply_addr(sock: socket.socket, atyp: int):
    if atyp == 0x01:  # IPv4
        data = recv_exact(sock, 4 + 2)
        host = socket.inet_ntoa(data[:4])
        port = struct.unpack("!H", data[4:6])[0]
        return host, port
    elif atyp == 0x04:  # IPv6
        data = recv_exact(sock, 16 + 2)
        host = socket.inet_ntop(socket.AF_INET6, data[:16])
        port = struct.unpack("!H", data[16:18])[0]
        return host, port
    elif atyp == 0x03:  # domain
        l = recv_exact(sock, 1)[0]
        data = recv_exact(sock, l + 2)
        host = data[:l].decode("utf-8", errors="replace")
        port = struct.unpack("!H", data[l:l+2])[0]
        return host, port
    else:
        raise RuntimeError(f"invalid atyp in socks5 reply: {atyp:#x}")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        out += chunk
    return out


def udp_associate():
    tcp = socket.create_connection(SOCKS5_ADDR, timeout=TIMEOUT)

    # method negotiation: no auth
    tcp.sendall(b"\x05\x01\x00")
    resp = recv_exact(tcp, 2)
    if resp != b"\x05\x00":
        raise RuntimeError(f"method negotiation failed: {resp!r}")

    # UDP ASSOCIATE to 0.0.0.0:0
    req = b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
    tcp.sendall(req)

    head = recv_exact(tcp, 4)
    ver, rep, rsv, atyp = head
    if ver != 0x05:
        raise RuntimeError(f"bad version: {ver:#x}")
    if rep != 0x00:
        raise RuntimeError(f"UDP ASSOCIATE failed, REP={rep:#x}")

    relay_host, relay_port = parse_socks5_reply_addr(tcp, atyp)
    print(f"[+] UDP relay = {relay_host}:{relay_port}")

    return tcp, (relay_host, relay_port)


def build_socks5_udp_packet(dst_host: str, dst_port: int, payload: bytes) -> bytes:
    # RSV(2)=0x0000, FRAG(1)=0, then ATYP/DST.ADDR/DST.PORT/DATA
    if ":" in dst_host:
        atyp = 0x04
        addr = socket.inet_pton(socket.AF_INET6, dst_host)
    else:
        atyp = 0x01
        addr = socket.inet_aton(dst_host)

    return b"\x00\x00\x00" + bytes([atyp]) + addr + struct.pack("!H", dst_port) + payload


def parse_socks5_udp_packet(data: bytes):
    if len(data) < 4:
        raise RuntimeError("short UDP packet")
    if data[0:2] != b"\x00\x00":
        raise RuntimeError("bad RSV")
    frag = data[2]
    if frag != 0:
        raise RuntimeError(f"FRAG not supported: {frag}")
    atyp = data[3]
    off = 4

    if atyp == 0x01:
        if len(data) < off + 4 + 2:
            raise RuntimeError("short IPv4 UDP packet")
        host = socket.inet_ntoa(data[off:off+4])
        off += 4
        port = struct.unpack("!H", data[off:off+2])[0]
        off += 2
    elif atyp == 0x04:
        if len(data) < off + 16 + 2:
            raise RuntimeError("short IPv6 UDP packet")
        host = socket.inet_ntop(socket.AF_INET6, data[off:off+16])
        off += 16
        port = struct.unpack("!H", data[off:off+2])[0]
        off += 2
    elif atyp == 0x03:
        if len(data) < off + 1:
            raise RuntimeError("short DOMAIN UDP packet")
        l = data[off]
        off += 1
        if len(data) < off + l + 2:
            raise RuntimeError("short DOMAIN UDP packet body")
        host = data[off:off+l].decode("utf-8", errors="replace")
        off += l
        port = struct.unpack("!H", data[off:off+2])[0]
        off += 2
    else:
        raise RuntimeError(f"invalid ATYP: {atyp:#x}")

    return host, port, data[off:]


def main():
    qname = "google.com"
    qtype = 1
    if len(sys.argv) >= 2:
        qname = sys.argv[1]
    if len(sys.argv) >= 3 and sys.argv[2].upper() == "AAAA":
        qtype = 28

    print(f"[*] query {qname} type={'AAAA' if qtype == 28 else 'A'} via SOCKS5 UDP ASSOCIATE")

    tcp, relay = udp_associate()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(TIMEOUT)

    dns_query = build_dns_query(qname, qtype=qtype)
    pkt = build_socks5_udp_packet(DNS_SERVER[0], DNS_SERVER[1], dns_query)

    print ("PKT: ")
    hexdump(pkt)

    print(f"[*] send UDP packet to relay {relay[0]}:{relay[1]}")
    udp.sendto(pkt, relay)

    data, addr = udp.recvfrom(65535)
    print(f"[+] got UDP response from relay peer {addr[0]}:{addr[1]}, {len(data)} bytes")

    dst_host, dst_port, payload = parse_socks5_udp_packet(data)
    print(f"[+] socks udp header dst = {dst_host}:{dst_port}, payload={len(payload)} bytes")

    if len(payload) >= 2:
        txid = struct.unpack("!H", payload[:2])[0]
        print(f"[+] DNS payload txid = {txid:#06x}")

    print("[+] SOCKS5 UDP ASSOCIATE seems working")

    tcp.close()
    udp.close()


if __name__ == "__main__":
    main()
