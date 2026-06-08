#[cfg(feature = "sniff-tls-common")]
pub mod tls_common;
pub mod udp;

#[cfg(feature = "sniff-tls")]
pub mod tls;

#[cfg(feature = "sniff-http")]
pub mod http;

#[cfg(feature = "sniff-quic")]
pub mod quic;

use crate::cli::Config;
use crate::sniff::udp::UdpSnifferEngine;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
#[allow(unused_imports)]
use tracing::{debug, warn};

pub trait Sniffer: Send + Sync {
    fn name(&self) -> &'static str;
    fn initial_peek_len(&self) -> usize;
    fn max_peek_len(&self) -> usize;
    fn max_retries(&self) -> usize;
    fn wait_more_duration(&self) -> Duration;
    fn timeout_duration(&self) -> Duration;
    fn classify(&self, buf: &[u8], max_len: usize) -> SniffAttempt;
    fn map_error_reason(&self, err: SniffError) -> &'static str;
}

#[allow(dead_code)]
pub enum SniffAttempt {
    Matched(String),
    NeedMore,
    Abort(SniffError),
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffError {
    PeekEmpty,
    ProtocolNotMatched,
    NoTarget,
    ParseError,
    InvalidHostname,
    TooLarge,
}

#[derive(Debug, Clone, Copy)]
pub struct SniffConfig {
    pub tcp_peek_buffer_size: usize,
}

pub async fn peek_client_prefix(stream: &TcpStream, max_len: usize) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0u8; max_len];
    let n = stream.peek(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

pub async fn wait_for_more_peek_data(
    stream: &TcpStream,
    max_len: usize,
    last_len: usize,
    wait: Duration,
) -> anyhow::Result<Option<Vec<u8>>> {
    let deadline = tokio::time::Instant::now() + wait;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(None);
        }

        let remain = deadline.saturating_duration_since(now);

        let buf = match tokio::time::timeout(remain, peek_client_prefix(stream, max_len)).await {
            Ok(r) => r?,
            Err(_) => return Ok(None),
        };

        if buf.len() > last_len {
            return Ok(Some(buf));
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(None);
        }

        let sleep_for = Duration::from_millis(5).min(deadline.saturating_duration_since(now));
        tokio::time::sleep(sleep_for).await;
    }
}

pub fn should_retry_sniff(
    engine_name: &str,
    attempt: usize,
    max_retries: usize,
    cur_len: usize,
    last_peek_len: usize,
    orig_dst: SocketAddr,
) -> bool {
    if attempt >= max_retries {
        debug!(
            engine = engine_name,
            dst = %orig_dst,
            attempts = attempt + 1,
            peek_len = cur_len,
            "sniff stop: max_retries_exceeded"
        );
        return false;
    }

    if cur_len == 0 {
        debug!(engine = engine_name, dst = %orig_dst, "sniff stop: peek_empty");
        return false;
    }

    if cur_len <= last_peek_len {
        debug!(
            engine = engine_name,
            dst = %orig_dst,
            attempt = attempt,
            peek_len = cur_len,
            "sniff stop: no_progress"
        );
        return false;
    }

    true
}

pub async fn sniff_with_engine(
    engine: &dyn Sniffer,
    client: &TcpStream,
    orig_dst: SocketAddr,
    cfg: &SniffConfig,
) -> Option<String> {
    let timeout = engine.timeout_duration();
    let inner = async {
        let hard_cap = cfg.tcp_peek_buffer_size.max(1);
        let max_len = engine.max_peek_len().max(1).min(hard_cap);
        let mut peek_len = engine.initial_peek_len().max(1).min(max_len);
        let max_retries = engine.max_retries();
        let wait_more = engine.wait_more_duration();

        let mut attempt = 0usize;
        let mut last_peek_len = 0usize;

        loop {
            let buf = match peek_client_prefix(client, peek_len).await {
                Ok(buf) => buf,
                Err(e) => {
                    debug!(
                        engine = engine.name(),
                        dst = %orig_dst,
                        attempt = attempt,
                        error = format!("{:#}", e),
                        "sniff failed: peek_failed"
                    );
                    return None;
                }
            };

            let cur_len = buf.len();

            match engine.classify(&buf, max_len) {
                SniffAttempt::Matched(host) => {
                    debug!(
                        engine = engine.name(),
                        dst = %orig_dst,
                        host = %host,
                        attempt = attempt,
                        peek_len = cur_len,
                        "sniff success"
                    );
                    return Some(host);
                }
                SniffAttempt::NeedMore => {
                    debug!(
                        engine = engine.name(),
                        dst = %orig_dst,
                        attempt = attempt,
                        peek_len = cur_len,
                        "sniff retryable failure: insufficient_prefix"
                    );

                    if !should_retry_sniff(
                        engine.name(),
                        attempt,
                        max_retries,
                        cur_len,
                        last_peek_len,
                        orig_dst,
                    ) {
                        return None;
                    }

                    last_peek_len = cur_len;

                    let next_len = (peek_len.saturating_mul(2)).min(max_len);
                    if next_len <= peek_len {
                        debug!(
                            engine = engine.name(),
                            dst = %orig_dst,
                            attempt = attempt,
                            peek_len = cur_len,
                            "sniff stop: max_peek_reached"
                        );
                        return None;
                    }

                    match wait_for_more_peek_data(client, next_len, last_peek_len, wait_more).await
                    {
                        Ok(Some(_)) => {
                            peek_len = next_len;
                            attempt += 1;
                            continue;
                        }
                        Ok(None) => {
                            debug!(
                                engine = engine.name(),
                                dst = %orig_dst,
                                attempt = attempt,
                                peek_len = cur_len,
                                "sniff stop: no_more_peek_growth"
                            );
                            return None;
                        }
                        Err(e) => {
                            debug!(
                                engine = engine.name(),
                                dst = %orig_dst,
                                attempt = attempt,
                                error = format!("{:#}", e),
                                "sniff stop: wait_more_failed"
                            );
                            return None;
                        }
                    }
                }
                SniffAttempt::Abort(err) => {
                    debug!(
                        engine = engine.name(),
                        reason = engine.map_error_reason(err),
                        dst = %orig_dst,
                        attempt = attempt,
                        peek_len = cur_len,
                        "sniff failed",
                    );
                    return None;
                }
            }
        }
    };

    match tokio::time::timeout(timeout, inner).await {
        Ok(v) => v,
        Err(_) => {
            debug!(
                engine = engine.name(),
                dst = %orig_dst,
                timeout_ms = timeout.as_millis(),
                "sniff failed: timeout"
            );
            None
        }
    }
}

pub async fn sniff_domain(
    client: &TcpStream,
    orig_dst: SocketAddr,
    sniffers: &[Arc<dyn Sniffer>],
    cfg: &SniffConfig,
) -> Option<String> {
    for sniffer in sniffers {
        if let Some(host) = sniff_with_engine(sniffer.as_ref(), client, orig_dst, cfg).await {
            return Some(host);
        }
    }
    None
}

pub fn build_sniffers(config: &Config) -> Vec<Arc<dyn Sniffer>> {
    #[allow(unused_mut)]
    let mut sniffers: Vec<Arc<dyn Sniffer>> = Vec::new();
    #[cfg(feature = "sniff-tls")]
    if config.sniff_tls_sni {
        use crate::sniff::tls::TlsSniffer;
        sniffers.push(Arc::new(TlsSniffer::new(
            config.tls_sniff_peek_len,
            config.tls_sniff_max_len,
            config.tls_sniff_max_retries,
            config.tls_sniff_wait_more_ms,
            config.tls_sniff_timeout_ms,
        )));
    }
    #[cfg(not(feature = "sniff-tls"))]
    if config.sniff_tls_sni {
        _ = config.tls_sniff_peek_len;
        _ = config.tls_sniff_max_len;
        _ = config.tls_sniff_max_retries;
        _ = config.tls_sniff_wait_more_ms;
        _ = config.tls_sniff_timeout_ms;
        warn!(
            "config sniff_tls_sni=true but binary compiled without sniff-tls feature; \
             TLS SNI sniffing disabled"
        );
    }
    #[cfg(feature = "sniff-http")]
    if config.sniff_http_host {
        use crate::sniff::http::HttpSniffer;
        sniffers.push(Arc::new(HttpSniffer::new(
            config.http_sniff_peek_len,
            config.http_sniff_max_len,
            config.http_sniff_max_retries,
            config.http_sniff_wait_more_ms,
            config.http_sniff_timeout_ms,
        )));
    }
    #[cfg(not(feature = "sniff-http"))]
    if config.sniff_http_host {
        _ = config.http_sniff_peek_len;
        _ = config.http_sniff_max_len;
        _ = config.http_sniff_max_retries;
        _ = config.http_sniff_wait_more_ms;
        _ = config.http_sniff_timeout_ms;
        warn!(
            "config sniff_http_host=true but binary compiled without sniff-http feature; \
             HTTP Host sniffing disabled"
        );
    }
    sniffers
}

pub fn build_udp_sniffers(config: &Config) -> Vec<Arc<dyn UdpSnifferEngine>> {
    #[cfg(feature = "sniff-quic")]
    {
        use crate::sniff::quic::QuicSniUdpSniffer;
        let mut sniffers: Vec<Arc<dyn UdpSnifferEngine>> = Vec::new();
        if config.sniff_quic_sni {
            sniffers.push(Arc::new(QuicSniUdpSniffer));
        }
        sniffers
    }
    #[cfg(not(feature = "sniff-quic"))]
    {
        if config.sniff_quic_sni {
            warn!(
                "config sniff_quic_sni=true but binary compiled without sniff-quic feature; \
                 QUIC SNI sniffing disabled"
            );
        }
        Vec::new()
    }
}

#[allow(dead_code)]
pub fn is_valid_sni_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.ends_with('.') {
        return false;
    }

    let mut has_alpha = false;

    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
        if label.chars().any(|c| c.is_ascii_alphabetic()) {
            has_alpha = true;
        }
    }

    has_alpha
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ------ is_valid_sni_hostname ------
    #[test]
    fn valid_hostname() {
        assert!(is_valid_sni_hostname("example.com"));
        assert!(is_valid_sni_hostname("EXAMPLE.com"));
        assert!(is_valid_sni_hostname("a-b.example"));
        assert!(is_valid_sni_hostname("localhost"));
    }

    #[test]
    fn empty_or_too_long_hostname() {
        assert!(!is_valid_sni_hostname(""));
        let long = "a".repeat(254);
        assert!(!is_valid_sni_hostname(&long));
    }

    #[test]
    fn leading_or_trailing_dot() {
        assert!(!is_valid_sni_hostname(".example.com"));
        assert!(!is_valid_sni_hostname("example.com."));
    }

    #[test]
    fn double_dot() {
        assert!(!is_valid_sni_hostname("example..com"));
    }

    #[test]
    fn label_start_or_end_with_dash() {
        assert!(!is_valid_sni_hostname("-example.com"));
        assert!(!is_valid_sni_hostname("example-.com"));
    }

    #[test]
    fn non_ascii_or_underscore() {
        assert!(!is_valid_sni_hostname("exa_mple.com"));
        assert!(!is_valid_sni_hostname("例子.com"));
    }

    #[test]
    fn pure_ipv4_form() {
        assert!(!is_valid_sni_hostname("127.0.0.1"));
        assert!(!is_valid_sni_hostname("192.168.1.1"));
    }

    #[test]
    fn label_too_long() {
        let label = "a".repeat(64);
        let host = format!("{}.com", label);
        assert!(!is_valid_sni_hostname(&host));
    }

    // ------ should_retry_sniff ------
    #[test]
    fn retry_when_attempt_below_max_and_data_grew() {
        let orig = "127.0.0.1:1234".parse().unwrap();
        // attempt < max_retries, cur_len > last_peek_len => true
        assert!(should_retry_sniff("test", 0, 3, 100, 50, orig));
        // attempt >= max_retries => false
        assert!(!should_retry_sniff("test", 3, 3, 100, 50, orig));
        // cur_len == 0 => false
        assert!(!should_retry_sniff("test", 0, 3, 0, 0, orig));
        // cur_len <= last_peek_len => false
        assert!(!should_retry_sniff("test", 0, 3, 50, 100, orig));
    }

    // peek 测试可用本地 TcpListener + TcpStream（需 tokio runtime）
    #[tokio::test]
    async fn peek_does_not_consume() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        client.write_all(b"hello").await.unwrap();

        let peeked = peek_client_prefix(&server, 10).await.unwrap();
        assert_eq!(peeked, b"hello");

        let mut buf = [0u8; 5];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn wait_for_more_peek_data_sees_growth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        // 先发送 5 字节
        server.writable().await.unwrap();
        server.try_write(b"hello").unwrap();

        let peeked = peek_client_prefix(&client, 10).await.unwrap();
        assert_eq!(peeked.len(), 5);

        // 再发送更多
        server.try_write(b" world").unwrap();

        let more = wait_for_more_peek_data(&client, 100, 5, Duration::from_secs(1))
            .await
            .unwrap()
            .unwrap();
        assert!(more.len() > 5);
        assert_eq!(&more[..11], b"hello world");
    }

    #[tokio::test]
    async fn wait_for_more_peek_data_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (_server, _) = listener.accept().await.unwrap();

        let result = wait_for_more_peek_data(&client, 100, 0, Duration::from_millis(10)).await;
        // 超时应返回 Ok(None)
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }
}
