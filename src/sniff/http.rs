use crate::sniff::{SniffAttempt, SniffError, Sniffer, is_valid_sni_hostname};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpSniffError {
    PeekEmpty,
    InsufficientPrefix,
    ProtocolNotMatched,
    HttpNoHost,
    ParseError,
    InvalidHostname,
    TooLargeHeader,
}

pub struct HttpSniffer {
    peek_len: usize,
    max_len: usize,
    max_retries: usize,
    wait_more: Duration,
    timeout: Duration,
}

impl HttpSniffer {
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

impl Sniffer for HttpSniffer {
    fn name(&self) -> &'static str {
        "http"
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
        match sniff_http_host_from_prefix(buf, max_len) {
            Ok(host) => SniffAttempt::Matched(host),
            Err(HttpSniffError::InsufficientPrefix) => SniffAttempt::NeedMore,
            Err(HttpSniffError::PeekEmpty) => SniffAttempt::Abort(SniffError::PeekEmpty),
            Err(HttpSniffError::ProtocolNotMatched) => {
                SniffAttempt::Abort(SniffError::ProtocolNotMatched)
            }
            Err(HttpSniffError::HttpNoHost) => SniffAttempt::Abort(SniffError::NoTarget),
            Err(HttpSniffError::ParseError) => SniffAttempt::Abort(SniffError::ParseError),
            Err(HttpSniffError::InvalidHostname) => {
                SniffAttempt::Abort(SniffError::InvalidHostname)
            }
            Err(HttpSniffError::TooLargeHeader) => SniffAttempt::Abort(SniffError::TooLarge),
        }
    }

    fn map_error_reason(&self, err: SniffError) -> &'static str {
        match err {
            SniffError::PeekEmpty => "peek_empty",
            SniffError::ProtocolNotMatched => "protocol_not_matched",
            SniffError::NoTarget => "http_no_host",
            SniffError::ParseError => "parse_error",
            SniffError::InvalidHostname => "invalid_hostname",
            SniffError::TooLarge => "header_too_large",
        }
    }
}

fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn looks_like_http_1x_request_line(line: &str) -> bool {
    let mut parts = line.split(' ');

    let method = match parts.next() {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_uppercase()) => v,
        _ => return false,
    };

    let target = match parts.next() {
        Some(v) if !v.is_empty() => v,
        _ => return false,
    };

    let version = match parts.next() {
        Some(v) => v,
        None => return false,
    };

    if parts.next().is_some() {
        return false;
    }

    let _ = method;
    let _ = target;

    matches!(version, "HTTP/1.0" | "HTTP/1.1")
}

fn parse_http_host_header_value(value: &str) -> Result<String, HttpSniffError> {
    let value = value.trim();

    if value.is_empty() {
        return Err(HttpSniffError::ParseError);
    }

    if value.starts_with('[') {
        return Err(HttpSniffError::InvalidHostname);
    }

    let host = match value.rsplit_once(':') {
        Some((name, port))
            if !name.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            name
        }
        _ => value,
    };

    let host = host.trim().to_ascii_lowercase();

    if !is_valid_sni_hostname(&host) {
        return Err(HttpSniffError::InvalidHostname);
    }

    Ok(host)
}

fn definitely_not_http_1x_prefix(buf: &[u8]) -> bool {
    // 如果已经看到第一行 \r\n，立即校验 request line 格式
    let Some(line_end) = buf.windows(2).position(|w| w == b"\r\n") else {
        return false; // 还没看到完整 request line，不能判断
    };

    let line = match std::str::from_utf8(&buf[..line_end]) {
        Ok(v) => v,
        Err(_) => return true,
    };

    if !looks_like_http_1x_request_line(line) {
        return true;
    }

    false
}

pub fn sniff_http_host_from_prefix(
    buf: &[u8],
    max_header_size: usize,
) -> Result<String, HttpSniffError> {
    if buf.is_empty() {
        return Err(HttpSniffError::PeekEmpty);
    }

    // 轻量协议判定：HTTP/1.x 请求行必须以大写字母开头
    if !buf[0].is_ascii_uppercase() {
        return Err(HttpSniffError::ProtocolNotMatched);
    }

    if definitely_not_http_1x_prefix(buf) {
        return Err(HttpSniffError::ProtocolNotMatched);
    }

    let header_end = match find_http_header_end(buf) {
        Some(v) => v,
        None => {
            if buf.len() >= max_header_size {
                return Err(HttpSniffError::TooLargeHeader);
            }
            return Err(HttpSniffError::InsufficientPrefix);
        }
    };

    let header =
        std::str::from_utf8(&buf[..header_end]).map_err(|_| HttpSniffError::ProtocolNotMatched)?;

    let mut lines = header.split("\r\n");

    let request_line = lines.next().ok_or(HttpSniffError::ParseError)?;
    if !looks_like_http_1x_request_line(request_line) {
        return Err(HttpSniffError::ProtocolNotMatched);
    }

    for line in lines {
        if line.is_empty() {
            break;
        }

        let (name, value) = line.split_once(':').ok_or(HttpSniffError::ParseError)?;
        if name.eq_ignore_ascii_case("host") {
            return parse_http_host_header_value(value);
        }
    }

    Err(HttpSniffError::HttpNoHost)
}
