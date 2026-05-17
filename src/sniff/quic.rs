use aes::Aes128;
use aes::cipher::{Block, BlockCipherEncrypt, KeyInit as AesKeyInit};
use aes_gcm::aead::{Aead, KeyInit as AeadKeyInit, Payload as AeadPayload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use tracing::trace;

use crate::sniff::tls_common::TlsSniffError;
use crate::sniff::tls_common::{be_u24, parse_sni_from_client_hello_body};
use crate::sniff::udp::{
    UdpSniffError, UdpSniffOutcome, UdpSniffProtocol, UdpSnifferEngine, UdpSnifferSessionEngine,
};

const QUIC_SNI_INPUT_CAP: usize = 16 * 1024;
const QUIC_CRYPTO_REASSEMBLY_CAP: usize = 32 * 1024;

const QUIC_VERSION_V1: u32 = 0x0000_0001;
const QUIC_VERSION_DRAFT29: u32 = 0xff00_001d;

const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

const QUIC_DRAFT29_INITIAL_SALT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];

#[derive(Debug, Clone)]
struct QuicInitialKeys {
    hp_key: [u8; 16],
    key: [u8; 16],
    iv: [u8; 12],
}

fn quic_initial_salt(version: u32) -> Option<&'static [u8; 20]> {
    match version {
        QUIC_VERSION_V1 => Some(&QUIC_V1_INITIAL_SALT),
        QUIC_VERSION_DRAFT29 => Some(&QUIC_DRAFT29_INITIAL_SALT),
        _ => None,
    }
}

fn hkdf_expand_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    out: &mut [u8],
) -> Result<(), UdpSniffError> {
    let hk = Hkdf::<Sha256>::from_prk(secret).map_err(|_| UdpSniffError::ParseError)?;

    let full_label = {
        let mut v = Vec::with_capacity("tls13 ".len() + label.len());
        v.extend_from_slice(b"tls13 ");
        v.extend_from_slice(label.as_bytes());
        v
    };

    if full_label.len() > u8::MAX as usize || context.len() > u8::MAX as usize {
        return Err(UdpSniffError::ParseError);
    }

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    hk.expand(&info, out).map_err(|_| UdpSniffError::ParseError)
}

fn hkdf_expand_label_from_hkdf(
    hk: &Hkdf<Sha256>,
    label: &str,
    context: &[u8],
    out: &mut [u8],
) -> Result<(), UdpSniffError> {
    let full_label = {
        let mut v = Vec::with_capacity("tls13 ".len() + label.len());
        v.extend_from_slice(b"tls13 ");
        v.extend_from_slice(label.as_bytes());
        v
    };

    if full_label.len() > u8::MAX as usize || context.len() > u8::MAX as usize {
        return Err(UdpSniffError::ParseError);
    }

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    hk.expand(&info, out).map_err(|_| UdpSniffError::ParseError)
}

fn derive_quic_initial_keys(version: u32, dcid: &[u8]) -> Result<QuicInitialKeys, UdpSniffError> {
    let salt = quic_initial_salt(version).ok_or(UdpSniffError::ProtocolNotMatched)?;
    let (_, initial_hk) = Hkdf::<Sha256>::extract(Some(salt), dcid);

    let mut initial_secret = [0u8; 32];
    hkdf_expand_label_from_hkdf(&initial_hk, "client in", &[], &mut initial_secret)?;

    let mut hp_key = [0u8; 16];
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];

    hkdf_expand_label(&initial_secret, "quic hp", &[], &mut hp_key)?;
    hkdf_expand_label(&initial_secret, "quic key", &[], &mut key)?;
    hkdf_expand_label(&initial_secret, "quic iv", &[], &mut iv)?;

    Ok(QuicInitialKeys { hp_key, key, iv })
}

fn quic_read_u32(buf: &[u8], off: usize) -> Result<u32, UdpSniffError> {
    if off + 4 > buf.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }
    Ok(u32::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

fn quic_varint_len(first: u8) -> usize {
    match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    }
}

fn quic_read_varint(buf: &[u8], off: &mut usize) -> Result<u64, UdpSniffError> {
    let first = *buf.get(*off).ok_or(UdpSniffError::InsufficientPrefix)?;
    let len = quic_varint_len(first);
    if *off + len > buf.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }
    let mut value = (first & 0x3f) as u64;
    for b in &buf[*off + 1..*off + len] {
        value = (value << 8) | (*b as u64);
    }
    *off += len;
    Ok(value)
}

pub struct QuicCryptoReassembly {
    buf: Vec<u8>,
    present: Vec<bool>,
    contiguous_len: usize,
}

impl QuicCryptoReassembly {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            present: Vec::new(),
            contiguous_len: 0,
        }
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), UdpSniffError> {
        let end = offset
            .checked_add(data.len())
            .ok_or(UdpSniffError::TooLarge)?;
        if end > QUIC_CRYPTO_REASSEMBLY_CAP {
            return Err(UdpSniffError::TooLarge);
        }
        if self.buf.len() < end {
            self.buf.resize(end, 0);
            self.present.resize(end, false);
        }
        self.buf[offset..end].copy_from_slice(data);
        for p in &mut self.present[offset..end] {
            *p = true;
        }
        while self.contiguous_len < self.present.len() && self.present[self.contiguous_len] {
            self.contiguous_len += 1;
        }
        Ok(())
    }

    fn contiguous(&self) -> &[u8] {
        &self.buf[..self.contiguous_len]
    }
}

fn quic_build_nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn = packet_number.to_be_bytes();
    for i in 0..8 {
        nonce[12 - 8 + i] ^= pn[i];
    }
    nonce
}

fn quic_parse_tls_client_hello_from_crypto(crypto: &[u8]) -> Result<String, UdpSniffError> {
    if crypto.len() < 4 {
        trace!(
            "QUIC crypto insufficient: contiguous_len={}, need handshake header",
            crypto.len()
        );
        return Err(UdpSniffError::InsufficientPrefix);
    }
    if crypto[0] != 0x01 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }
    let hs_len = be_u24(&crypto[1..4]).map_err(|_| UdpSniffError::ParseError)?;
    let total = 4usize.checked_add(hs_len).ok_or(UdpSniffError::TooLarge)?;
    trace!(
        "QUIC crypto ClientHello progress: contiguous_len={}, needed_total={}",
        crypto.len(),
        total
    );
    if total > QUIC_CRYPTO_REASSEMBLY_CAP {
        return Err(UdpSniffError::TooLarge);
    }
    if crypto.len() < total {
        return Err(UdpSniffError::InsufficientPrefix);
    }
    let body = &crypto[4..total];
    parse_sni_from_client_hello_body(body).map_err(Into::into)
}

fn quic_remove_header_protection_and_decrypt(
    packet: &[u8],
    packet_start: usize,
    pn_offset: usize,
    packet_end: usize,
    keys: &QuicInitialKeys,
) -> Result<Vec<u8>, UdpSniffError> {
    if pn_offset + 4 + 16 > packet.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }
    if packet_end > packet.len() || packet_end <= pn_offset {
        return Err(UdpSniffError::InsufficientPrefix);
    }
    let sample = &packet[pn_offset + 4..pn_offset + 4 + 16];
    let hp_cipher = Aes128::new_from_slice(&keys.hp_key).map_err(|_| UdpSniffError::ParseError)?;
    let mut block = Block::<Aes128>::default();
    block.copy_from_slice(sample);
    hp_cipher.encrypt_block(&mut block);
    let mask: &[u8] = block.as_ref();
    let first_unprotected = packet[packet_start] ^ (mask[0] & 0x0f);
    let pn_len = ((first_unprotected & 0x03) + 1) as usize;
    if pn_len == 0 || pn_len > 4 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }
    if pn_offset + pn_len > packet_end {
        return Err(UdpSniffError::InsufficientPrefix);
    }
    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        pn_bytes[4 - pn_len + i] = packet[pn_offset + i] ^ mask[1 + i];
    }
    let packet_number = u32::from_be_bytes(pn_bytes) as u64;
    let mut header = Vec::with_capacity(pn_offset - packet_start + pn_len);
    header.extend_from_slice(&packet[packet_start..pn_offset]);
    header[0] = first_unprotected;
    for i in 0..pn_len {
        header.push(packet[pn_offset + i] ^ mask[1 + i]);
    }
    let ciphertext = &packet[pn_offset + pn_len..packet_end];
    if ciphertext.len() < 16 {
        return Err(UdpSniffError::InsufficientPrefix);
    }
    let nonce = quic_build_nonce(&keys.iv, packet_number);
    let aead = Aes128Gcm::new_from_slice(&keys.key).map_err(|_| UdpSniffError::ParseError)?;
    aead.decrypt(
        Nonce::from_slice(&nonce),
        AeadPayload {
            msg: ciphertext,
            aad: &header,
        },
    )
    .map_err(|_| UdpSniffError::ProtocolNotMatched)
}

fn quic_skip_ack_frame(
    frame_type: u64,
    frames: &[u8],
    off: &mut usize,
) -> Result<(), UdpSniffError> {
    let _largest_acknowledged = quic_read_varint(frames, off)?;
    let _ack_delay = quic_read_varint(frames, off)?;
    let ack_range_count = quic_read_varint(frames, off)?;
    let _first_ack_range = quic_read_varint(frames, off)?;

    for _ in 0..ack_range_count {
        let _gap = quic_read_varint(frames, off)?;
        let _ack_range_length = quic_read_varint(frames, off)?;
    }

    if frame_type == 0x03 {
        let _ect0 = quic_read_varint(frames, off)?;
        let _ect1 = quic_read_varint(frames, off)?;
        let _ce = quic_read_varint(frames, off)?;
    }

    Ok(())
}

fn quic_skip_connection_close_frame(frames: &[u8], off: &mut usize) -> Result<(), UdpSniffError> {
    let _error_code = quic_read_varint(frames, off)?;
    let _frame_type = quic_read_varint(frames, off)?;
    let reason_len = quic_read_varint(frames, off)? as usize;

    if *off + reason_len > frames.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    *off += reason_len;

    Ok(())
}

fn quic_parse_initial_frames(
    frames: &[u8],
    crypto: &mut QuicCryptoReassembly,
) -> Result<(), UdpSniffError> {
    let mut off = 0usize;

    while off < frames.len() {
        let frame_type = quic_read_varint(frames, &mut off)?;

        match frame_type {
            0x00 => {}
            0x01 => {}
            0x02 | 0x03 => {
                quic_skip_ack_frame(frame_type, frames, &mut off)?;
            }
            0x06 => {
                let crypto_offset = quic_read_varint(frames, &mut off)? as usize;
                let crypto_len = quic_read_varint(frames, &mut off)? as usize;

                if off + crypto_len > frames.len() {
                    return Err(UdpSniffError::InsufficientPrefix);
                }

                crypto.write(crypto_offset, &frames[off..off + crypto_len])?;
                off += crypto_len;
            }
            0x1c => {
                quic_skip_connection_close_frame(frames, &mut off)?;
            }
            _ => {
                return Err(UdpSniffError::ProtocolNotMatched);
            }
        }
    }

    Ok(())
}

fn quic_parse_one_initial_packet(
    datagram: &[u8],
    packet_start: usize,
    crypto: &mut QuicCryptoReassembly,
) -> Result<usize, UdpSniffError> {
    if packet_start >= datagram.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let first = datagram[packet_start];

    if first & 0x80 == 0 || first & 0x40 == 0 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    let packet_type = (first & 0x30) >> 4;
    if packet_type != 0 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    let mut off = packet_start + 1;

    let version = quic_read_u32(datagram, off)?;
    off += 4;

    if quic_initial_salt(version).is_none() {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    let dcid_len = *datagram.get(off).ok_or(UdpSniffError::InsufficientPrefix)? as usize;
    off += 1;

    if dcid_len > 20 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    if off + dcid_len > datagram.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let dcid = &datagram[off..off + dcid_len];
    off += dcid_len;

    let scid_len = *datagram.get(off).ok_or(UdpSniffError::InsufficientPrefix)? as usize;
    off += 1;

    if scid_len > 20 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    if off + scid_len > datagram.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    off += scid_len;

    let token_len = quic_read_varint(datagram, &mut off)? as usize;

    if off + token_len > datagram.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    off += token_len;

    let protected_len = quic_read_varint(datagram, &mut off)? as usize;

    if protected_len == 0 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    let pn_offset = off;

    let packet_end = pn_offset
        .checked_add(protected_len)
        .ok_or(UdpSniffError::TooLarge)?;

    if packet_end > datagram.len() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let keys = derive_quic_initial_keys(version, dcid)?;

    let plaintext = quic_remove_header_protection_and_decrypt(
        datagram,
        packet_start,
        pn_offset,
        packet_end,
        &keys,
    )?;

    quic_parse_initial_frames(&plaintext, crypto)?;

    Ok(packet_end)
}

pub fn sniff_quic_sni_from_datagram_with_reassembly(
    datagram: &[u8],
    crypto: &mut QuicCryptoReassembly,
) -> Result<String, UdpSniffError> {
    if datagram.is_empty() {
        return Err(UdpSniffError::InsufficientPrefix);
    }

    let datagram = &datagram[..datagram.len().min(QUIC_SNI_INPUT_CAP)];

    let first = datagram[0];

    if first & 0x80 == 0 || first & 0x40 == 0 {
        return Err(UdpSniffError::ProtocolNotMatched);
    }

    let mut off = 0usize;
    let mut saw_initial = false;

    while off < datagram.len() {
        match quic_parse_one_initial_packet(datagram, off, crypto) {
            Ok(next_off) => {
                saw_initial = true;
                off = next_off;

                match quic_parse_tls_client_hello_from_crypto(crypto.contiguous()) {
                    Ok(host) => return Ok(host),
                    Err(UdpSniffError::InsufficientPrefix) => {
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(UdpSniffError::ProtocolNotMatched) if saw_initial => {
                break;
            }
            Err(e) => return Err(e),
        }
    }

    if saw_initial {
        Err(UdpSniffError::InsufficientPrefix)
    } else {
        Err(UdpSniffError::ProtocolNotMatched)
    }
}

pub struct QuicSniUdpSniffer;

impl UdpSnifferEngine for QuicSniUdpSniffer {
    fn name(&self) -> &'static str {
        "quic_sni"
    }

    fn new_session(&self) -> Box<dyn UdpSnifferSessionEngine> {
        Box::new(QuicSniUdpSnifferSession::new())
    }
}

pub struct QuicSniUdpSnifferSession {
    quic_crypto: QuicCryptoReassembly,
}

impl QuicSniUdpSnifferSession {
    pub fn new() -> Self {
        Self {
            quic_crypto: QuicCryptoReassembly::new(),
        }
    }
}

impl UdpSnifferSessionEngine for QuicSniUdpSnifferSession {
    fn feed(&mut self, payload: &[u8]) -> UdpSniffOutcome {
        match sniff_quic_sni_from_datagram_with_reassembly(payload, &mut self.quic_crypto) {
            Ok(host) => UdpSniffOutcome::Matched {
                protocol: UdpSniffProtocol::QuicSni,
                host,
            },
            Err(UdpSniffError::ProtocolNotMatched) => UdpSniffOutcome::NotMatched,
            Err(UdpSniffError::InsufficientPrefix) => UdpSniffOutcome::NeedMore {
                protocol: UdpSniffProtocol::QuicSni,
            },
            Err(error) => UdpSniffOutcome::Failed {
                protocol: UdpSniffProtocol::QuicSni,
                error,
            },
        }
    }
}

impl From<TlsSniffError> for UdpSniffError {
    fn from(err: TlsSniffError) -> Self {
        match err {
            TlsSniffError::PeekEmpty => UdpSniffError::InsufficientPrefix,
            TlsSniffError::InsufficientPrefix => UdpSniffError::InsufficientPrefix,
            TlsSniffError::ProtocolNotMatched => UdpSniffError::ProtocolNotMatched,
            TlsSniffError::TlsNoSni => UdpSniffError::NoTarget,
            TlsSniffError::ParseError => UdpSniffError::ParseError,
            TlsSniffError::InvalidHostname => UdpSniffError::InvalidHostname,
            TlsSniffError::TooLargeClientHello => UdpSniffError::TooLarge,
        }
    }
}
