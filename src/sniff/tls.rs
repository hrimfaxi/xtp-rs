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
