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
            "{} sniff stop: reason=max_retries_exceeded, dst={}, attempts={}, peek_len={}",
            engine_name,
            orig_dst,
            attempt + 1,
            cur_len
        );
        return false;
    }

    if cur_len == 0 {
        debug!(
            "{} sniff stop: reason=peek_empty, dst={}",
            engine_name, orig_dst
        );
        return false;
    }

    if cur_len <= last_peek_len {
        debug!(
            "{} sniff stop: reason=no_progress, dst={}, attempt={}, peek_len={}",
            engine_name, orig_dst, attempt, cur_len
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
                        "{} sniff failed: reason=peek_failed, dst={}, attempt={}, error={:#}",
                        engine.name(),
                        orig_dst,
                        attempt,
                        e
                    );
                    return None;
                }
            };

            let cur_len = buf.len();

            match engine.classify(&buf, max_len) {
                SniffAttempt::Matched(host) => {
                    debug!(
                        "{} sniff success: dst={}, host={}, attempt={}, peek_len={}",
                        engine.name(),
                        orig_dst,
                        host,
                        attempt,
                        cur_len
                    );
                    return Some(host);
                }
                SniffAttempt::NeedMore => {
                    debug!(
                        "{} sniff retryable failure: reason=insufficient_prefix, dst={}, attempt={}, peek_len={}",
                        engine.name(),
                        orig_dst,
                        attempt,
                        cur_len
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
                            "{} sniff stop: reason=max_peek_reached, dst={}, attempt={}, peek_len={}",
                            engine.name(),
                            orig_dst,
                            attempt,
                            cur_len
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
                                "{} sniff stop: reason=no_more_peek_growth, dst={}, attempt={}, peek_len={}",
                                engine.name(),
                                orig_dst,
                                attempt,
                                cur_len
                            );
                            return None;
                        }
                        Err(e) => {
                            debug!(
                                "{} sniff stop: reason=wait_more_failed, dst={}, attempt={}, error={:#}",
                                engine.name(),
                                orig_dst,
                                attempt,
                                e
                            );
                            return None;
                        }
                    }
                }
                SniffAttempt::Abort(err) => {
                    debug!(
                        "{} sniff failed: reason={}, dst={}, attempt={}, peek_len={}",
                        engine.name(),
                        engine.map_error_reason(err),
                        orig_dst,
                        attempt,
                        cur_len
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
                "{} sniff failed: reason=timeout, dst={}, timeout_ms={}",
                engine.name(),
                orig_dst,
                timeout.as_millis()
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
