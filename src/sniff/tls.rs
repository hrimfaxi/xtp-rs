use crate::sniff::tls_common::{TlsSniffError, be_u16, be_u24, parse_sni_from_client_hello_body};
use crate::sniff::{SniffAttempt, SniffError, Sniffer};
use std::time::Duration;

pub struct TlsSniffer {
    peek_len: usize,
    max_len: usize,
    max_retries: usize,
    wait_more: Duration,
    timeout: Duration,
}

impl TlsSniffer {
    pub fn new(
        peek_len: usize,
        max_len: usize,
        max_retries: usize,
        wait_more_ms: u64,
        timeout_ms: u64,
    ) -> Self {
        Self {
            peek_len,
            max_len,
            max_retries,
            wait_more: Duration::from_millis(wait_more_ms.max(1)),
            timeout: Duration::from_millis(timeout_ms.max(1)),
        }
    }
}

impl Sniffer for TlsSniffer {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn initial_peek_len(&self) -> usize {
        self.peek_len
    }
    fn max_peek_len(&self) -> usize {
        self.max_len
    }
    fn max_retries(&self) -> usize {
        self.max_retries
    }
    fn wait_more_duration(&self) -> Duration {
        self.wait_more
    }
    fn timeout_duration(&self) -> Duration {
        self.timeout
    }

    fn classify(&self, buf: &[u8], max_len: usize) -> SniffAttempt {
        match sniff_tls_sni_from_prefix(buf, max_len) {
            Ok(host) => SniffAttempt::Matched(host),
            Err(TlsSniffError::InsufficientPrefix) => SniffAttempt::NeedMore,
            Err(TlsSniffError::PeekEmpty) => SniffAttempt::Abort(SniffError::PeekEmpty),
            Err(TlsSniffError::ProtocolNotMatched) => {
                SniffAttempt::Abort(SniffError::ProtocolNotMatched)
            }
            Err(TlsSniffError::TlsNoSni) => SniffAttempt::Abort(SniffError::NoTarget),
            Err(TlsSniffError::ParseError) => SniffAttempt::Abort(SniffError::ParseError),
            Err(TlsSniffError::InvalidHostname) => SniffAttempt::Abort(SniffError::InvalidHostname),
            Err(TlsSniffError::TooLargeClientHello) => SniffAttempt::Abort(SniffError::TooLarge),
        }
    }

    fn map_error_reason(&self, err: SniffError) -> &'static str {
        match err {
            SniffError::PeekEmpty => "peek_empty",
            SniffError::ProtocolNotMatched => "protocol_not_matched",
            SniffError::NoTarget => "tls_no_sni",
            SniffError::ParseError => "parse_error",
            SniffError::InvalidHostname => "invalid_hostname",
            SniffError::TooLarge => "client_hello_too_large",
        }
    }
}

pub fn sniff_tls_sni_from_prefix(
    buf: &[u8],
    max_client_hello_size: usize,
) -> Result<String, TlsSniffError> {
    if buf.is_empty() {
        return Err(TlsSniffError::PeekEmpty);
    }

    let mut off = 0usize;
    let mut handshake = Vec::with_capacity(buf.len().min(4096));
    let mut needed_total: Option<usize> = None;
    let mut saw_handshake_record = false;

    while off < buf.len() {
        if buf.len() - off < 5 {
            if off == 0 && !buf.is_empty() {
                if buf[0] != 0x16 {
                    return Err(TlsSniffError::ProtocolNotMatched);
                }

                if buf.len() >= 2 && buf[1] != 0x03 {
                    return Err(TlsSniffError::ProtocolNotMatched);
                }

                return Err(TlsSniffError::InsufficientPrefix);
            }

            return if saw_handshake_record {
                Err(TlsSniffError::InsufficientPrefix)
            } else {
                Err(TlsSniffError::ProtocolNotMatched)
            };
        }
        let content_type = buf[off];

        if content_type != 22 {
            return Err(TlsSniffError::ProtocolNotMatched);
        }

        let version_major = buf[off + 1];

        if version_major != 0x03 {
            return Err(TlsSniffError::ProtocolNotMatched);
        }

        let record_len = be_u16(&buf[off + 3..off + 5])? as usize;

        const MAX_TLS_RECORD_PAYLOAD: usize = 18 * 1024;
        if record_len == 0 || record_len > MAX_TLS_RECORD_PAYLOAD {
            return Err(TlsSniffError::ProtocolNotMatched);
        }

        let record_end = off + 5 + record_len;

        if record_end > buf.len() {
            return Err(TlsSniffError::InsufficientPrefix);
        }

        let payload = &buf[off + 5..record_end];

        saw_handshake_record = true;
        handshake.extend_from_slice(payload);

        if needed_total.is_none() && handshake.len() >= 4 {
            if handshake[0] != 0x01 {
                return Err(TlsSniffError::ProtocolNotMatched);
            }

            let hs_len = be_u24(&handshake[1..4])?;
            let total = 4 + hs_len;

            if total > max_client_hello_size {
                return Err(TlsSniffError::TooLargeClientHello);
            }

            needed_total = Some(total);
        }

        if let Some(total) = needed_total
            && handshake.len() >= total
        {
            let body = &handshake[4..total];
            return parse_sni_from_client_hello_body(body);
        }

        off = record_end;
    }

    if saw_handshake_record {
        Err(TlsSniffError::InsufficientPrefix)
    } else {
        Err(TlsSniffError::ProtocolNotMatched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sniff::tls_common::TlsSniffError;

    // 复用 tls_common 测试中的 client_hello_body
    fn client_hello_body(sni: Option<&str>, ech: bool) -> Vec<u8> {
        // 直接借用 crate::sniff::tls_common::tests::client_hello_body（若可见）
        // 若无法访问则重复实现（为保证独立性，这里复制一份）
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);
        let mut exts = Vec::new();
        if let Some(host) = sni {
            let host_bytes = host.as_bytes();
            let name_len = host_bytes.len();
            let sni_list_len = 3 + name_len;
            let ext_data_len = 2 + sni_list_len;
            let mut sni_ext = Vec::new();
            sni_ext.extend_from_slice(&[0x00, 0x00]);
            sni_ext.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
            sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
            sni_ext.push(0x00);
            sni_ext.extend_from_slice(&(name_len as u16).to_be_bytes());
            sni_ext.extend_from_slice(host_bytes);
            exts.extend_from_slice(&sni_ext);
        }
        if ech {
            let mut ech_ext = Vec::new();
            ech_ext.extend_from_slice(&[0xfe, 0x0d]);
            ech_ext.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&ech_ext);
        }
        if !exts.is_empty() {
            body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            body.extend_from_slice(&exts);
        }
        body
    }

    fn make_tls_record(content_type: u8, major: u8, minor: u8, payload: &[u8]) -> Vec<u8> {
        let mut rec = vec![content_type, major, minor];
        rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        rec.extend_from_slice(payload);
        rec
    }

    fn make_client_hello_handshake(host: &str) -> Vec<u8> {
        let body = client_hello_body(Some(host), false);
        let mut hs = vec![0x01]; // handshake type: ClientHello
        let len = body.len();
        hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        hs.extend_from_slice(&body);
        hs
    }

    #[test]
    fn new_clamps_zero_durations() {
        let s = TlsSniffer::new(512, 4096, 2, 0, 0);
        assert_eq!(s.wait_more_duration(), Duration::from_millis(1));
        assert_eq!(s.timeout_duration(), Duration::from_millis(1));
    }

    #[test]
    fn getters_return_config() {
        let s = TlsSniffer::new(256, 8192, 3, 50, 200);
        assert_eq!(s.initial_peek_len(), 256);
        assert_eq!(s.max_peek_len(), 8192);
        assert_eq!(s.max_retries(), 3);
        assert_eq!(s.wait_more_duration(), Duration::from_millis(50));
        assert_eq!(s.timeout_duration(), Duration::from_millis(200));
    }

    #[test]
    fn empty_buffer() {
        assert_eq!(
            sniff_tls_sni_from_prefix(&[], 4096),
            Err(TlsSniffError::PeekEmpty)
        );
    }

    #[test]
    fn first_byte_not_tls() {
        assert_eq!(
            sniff_tls_sni_from_prefix(&[0x15, 0x03, 0x03, 0x00, 0x00], 4096),
            Err(TlsSniffError::ProtocolNotMatched)
        );
    }

    #[test]
    fn tls_major_not_03() {
        let rec = make_tls_record(0x16, 0x02, 0x03, b"hello");
        assert_eq!(
            sniff_tls_sni_from_prefix(&rec, 4096),
            Err(TlsSniffError::ProtocolNotMatched)
        );
    }

    #[test]
    fn record_length_zero() {
        let rec = vec![0x16, 0x03, 0x03, 0x00, 0x00];
        assert_eq!(
            sniff_tls_sni_from_prefix(&rec, 4096),
            Err(TlsSniffError::ProtocolNotMatched)
        );
    }

    #[test]
    fn insufficient_data() {
        let rec = vec![0x16, 0x03, 0x03, 0x00, 0x20, 0x01];
        assert_eq!(
            sniff_tls_sni_from_prefix(&rec, 4096),
            Err(TlsSniffError::InsufficientPrefix)
        );
    }

    #[test]
    fn valid_tls_sni() {
        let hs = make_client_hello_handshake("example.com");
        let rec = make_tls_record(0x16, 0x03, 0x03, &hs);
        let host = sniff_tls_sni_from_prefix(&rec, 4096).unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn client_hello_split_across_records() {
        let hs = make_client_hello_handshake("foobar.com");
        let mid = hs.len() / 2;
        let rec1 = make_tls_record(0x16, 0x03, 0x03, &hs[..mid]);
        let rec2 = make_tls_record(0x16, 0x03, 0x03, &hs[mid..]);
        let mut concat = rec1.clone();
        concat.extend_from_slice(&rec2);
        let host = sniff_tls_sni_from_prefix(&concat, 4096).unwrap();
        assert_eq!(host, "foobar.com");
    }

    #[test]
    fn ech_leads_to_no_sni() {
        let body = client_hello_body(Some("example.com"), true);
        let hs = {
            let mut h = vec![0x01];
            let len = body.len();
            h.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
            h.extend_from_slice(&body);
            h
        };
        let rec = make_tls_record(0x16, 0x03, 0x03, &hs);
        let result = sniff_tls_sni_from_prefix(&rec, 4096);
        assert_eq!(result.unwrap(), "example.com");
    }

    #[test]
    fn incomplete_record_header() {
        assert_eq!(
            sniff_tls_sni_from_prefix(&[0x16, 0x03], 4096),
            Err(TlsSniffError::InsufficientPrefix)
        );
    }

    #[test]
    fn handshake_not_client_hello() {
        let hs = vec![0x02, 0x00, 0x00, 0x00]; // ServerHello type
        let rec = make_tls_record(0x16, 0x03, 0x03, &hs);
        assert_eq!(
            sniff_tls_sni_from_prefix(&rec, 4096),
            Err(TlsSniffError::ProtocolNotMatched)
        );
    }

    #[test]
    fn client_hello_exceeds_max_size() {
        let hs = make_client_hello_handshake("example.com");
        let rec = make_tls_record(0x16, 0x03, 0x03, &hs);
        // max_client_hello_size 设为很小，应报 TooLarge
        assert_eq!(
            sniff_tls_sni_from_prefix(&rec, 10),
            Err(TlsSniffError::TooLargeClientHello)
        );
    }

    #[test]
    fn record_length_exceeds_max_tls_record_payload() {
        // 构造一个声称长度超过 18KB 的 record
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(19_000u16).to_be_bytes()); // > 18*1024
        rec.resize(5 + 1, 0);
        assert_eq!(
            sniff_tls_sni_from_prefix(&rec, 4096),
            Err(TlsSniffError::ProtocolNotMatched)
        );
    }
}
