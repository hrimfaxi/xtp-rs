use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio_util::bytes::Bytes;
use tracing::{debug, trace, warn};

// 共享的 UDP sniff 状态表：每个 UdpSessionKey 对应一个正在 sniff 中的会话。
// 由于多个 UDP packet task 可能并发访问，需要用 Arc<Mutex> 保护。
pub(crate) type PendingSniffMap = Arc<tokio::sync::Mutex<HashMap<UdpSessionKey, PendingUdpSniff>>>;

use crate::sniff::udp::{
    UdpSniffOutcome, UdpSnifferSessionEngine, udp_sniff_error_reason, udp_sniff_protocol_name,
};
use crate::state::AppState;
use crate::udp::session::{UdpRoutingMode, UdpSession, UdpSessionKey, UdpSessionSpec};

pub(crate) struct PendingReplayBuffer {
    datagrams: Vec<Bytes>,
    cached_bytes: usize,
}

impl PendingReplayBuffer {
    // 接受 &[u8]，内部复制为 Bytes
    pub(crate) fn new(first_payload: &[u8]) -> Self {
        Self {
            datagrams: vec![Bytes::copy_from_slice(first_payload)],
            cached_bytes: first_payload.len(),
        }
    }

    // 接受 &[u8]，内部复制为 Bytes
    pub(crate) fn push_datagram(&mut self, payload: &[u8]) -> bool {
        let next_bytes = self.cached_bytes.saturating_add(payload.len());
        if self.datagrams.len() >= UDP_SNIFF_MAX_CACHED_DATAGRAMS
            || next_bytes > UDP_SNIFF_MAX_CACHED_BYTES
        {
            return false;
        }
        self.datagrams.push(Bytes::copy_from_slice(payload));
        self.cached_bytes = next_bytes;
        true
    }

    pub(crate) fn into_datagrams(self) -> Vec<Bytes> {
        self.datagrams
    }

    pub(crate) fn datagram_count(&self) -> usize {
        self.datagrams.len()
    }

    pub(crate) fn cached_bytes(&self) -> usize {
        self.cached_bytes
    }
}

pub(crate) struct PendingUdpSniff {
    pub(crate) started_secs: u64,
    pub(crate) spec: UdpSessionSpec,
    pub(crate) sniffer: Box<dyn UdpSnifferSessionEngine>,
    pub(crate) replay: PendingReplayBuffer,
}

impl PendingUdpSniff {
    pub(crate) fn new(
        spec: UdpSessionSpec,
        sniffer: Box<dyn UdpSnifferSessionEngine>,
        first_payload: &[u8],
    ) -> Self {
        use crate::util::now_secs;
        Self {
            started_secs: now_secs(),
            spec,
            sniffer,
            replay: PendingReplayBuffer::new(first_payload),
        }
    }

    pub(crate) fn push_datagram(&mut self, payload: &[u8]) -> bool {
        self.replay.push_datagram(payload)
    }

    pub(crate) fn expired(&self) -> bool {
        use crate::util::now_secs;
        now_secs().saturating_sub(self.started_secs) >= UDP_SNIFF_TIMEOUT_SECS
    }

    pub(crate) fn datagram_count(&self) -> usize {
        self.replay.datagram_count()
    }

    pub(crate) fn cached_bytes(&self) -> usize {
        self.replay.cached_bytes()
    }
}

pub(crate) const UDP_SNIFF_TIMEOUT_SECS: u64 = 5;
pub(crate) const UDP_SNIFF_MAX_CACHED_DATAGRAMS: usize = 8;
pub(crate) const UDP_SNIFF_MAX_CACHED_BYTES: usize = 64 * 1024;
pub(crate) const UDP_SNIFF_MAX_PENDING_SESSIONS: usize = 4096;
pub(crate) const UDP_SNIFF_REAP_INTERVAL_SECS: u64 = 1;

pub(crate) async fn forward_udp_payload(
    state: Arc<AppState>,
    spec: UdpSessionSpec,
    payload: &[u8],
) {
    let key = spec.key;

    let session = match state
        .runtime
        .udp
        .get_or_create_udp_session(state.clone(), spec)
        .await
    {
        Ok(session) => session,
        Err(e) => {
            warn!(
                kind = ?key.kind,
                client = %key.client_addr,
                target = %key.target_addr,
                error = format!("{:#}", e),
                "failed to get/create UDP session"
            );
            return;
        }
    };

    session.touch();

    match session.send_payload(payload).await {
        Ok(sent) => {
            trace!(
                kind = ?key.kind,
                client = %key.client_addr,
                target = %key.target_addr,
                payload_len = payload.len(),
                sent = sent,
                "UDP packet forwarded"
            );
        }
        Err(e) => {
            warn!(
                kind = ?key.kind,
                client = %key.client_addr,
                target = %key.target_addr,
                error = format!("{:#}", e),
                "failed to forward UDP packet"
            );
        }
    }
}

pub(crate) async fn forward_udp_payload_to_session(session: Arc<UdpSession>, payload: &[u8]) {
    let key = session.key();

    session.touch();

    match session.send_payload(payload).await {
        Ok(sent) => {
            trace!(
                kind = ?key.kind,
                client = %key.client_addr,
                target = %key.target_addr,
                payload_len = payload.len(),
                sent = sent,
                "UDP packet forwarded (session)"
            );
        }
        Err(e) => {
            warn!(
                kind = ?key.kind,
                client = %key.client_addr,
                target = %key.target_addr,
                error = format!("{:#}", e),
                "failed to forward UDP packet (session)"
            );
        }
    }
}

pub(crate) async fn flush_pending_udp_sniff(state: Arc<AppState>, pending: PendingUdpSniff) {
    let datagrams = pending.replay.into_datagrams();
    let spec = pending.spec;
    for payload in datagrams {
        forward_udp_payload(state.clone(), spec.clone(), &payload).await;
    }
}

pub(crate) async fn handle_udp_client_payload(
    state: Arc<AppState>,
    pending_sniff: PendingSniffMap,
    spec: UdpSessionSpec,
    payload: &[u8],
) {
    if state.runtime.udp.closed.load(Ordering::SeqCst) {
        return;
    }
    let key = spec.key;

    if let Some(session) = state.runtime.udp.get_ready_udp_session(key).await {
        pending_sniff.lock().await.remove(&key);

        trace!(
            kind = ?key.kind,
            client = %key.client_addr,
            target = %key.target_addr,
            payload_len = payload.len(),
            "UDP existing session hit, skip sniff"
        );

        forward_udp_payload_to_session(session, payload).await;
        return;
    }

    if handle_pending_udp_sniff(state.clone(), pending_sniff.clone(), spec.clone(), payload).await {
        return;
    }

    if handle_new_udp_sniff(state.clone(), pending_sniff.clone(), spec.clone(), payload).await {
        return;
    }

    forward_udp_payload(state, spec, payload).await;
}

// 处理该 key 已有的 pending sniff。
// 如果 pending 已过期或太大，flush 后转发当前包；
// 如果 sniff 成功，flush 并标记 host；
// 如果还需要数据，把 pending 塞回 map 继续等。
pub(crate) async fn handle_pending_udp_sniff(
    state: Arc<AppState>,
    pending_sniff: PendingSniffMap,
    spec: UdpSessionSpec,
    payload: &[u8],
) -> bool {
    let key = spec.key;

    let Some(mut pending) = pending_sniff.lock().await.remove(&key) else {
        return false;
    };

    if pending.expired() {
        debug!(
            kind = ?key.kind,
            client = %key.client_addr,
            target = %key.target_addr,
            "UDP sniff pending expired"
        );

        flush_pending_udp_sniff(state.clone(), pending).await;
        forward_udp_payload(state, spec, payload).await;
        return true;
    }

    if !pending.push_datagram(payload) {
        debug!(
            kind = ?key.kind,
            client = %key.client_addr,
            target = %key.target_addr,
            "UDP sniff pending too large"
        );

        flush_pending_udp_sniff(state.clone(), pending).await;
        forward_udp_payload(state, spec, payload).await;
        return true;
    }

    match pending.sniffer.feed(payload) {
        UdpSniffOutcome::Matched { protocol, host } => {
            debug!(
                protocol = udp_sniff_protocol_name(protocol),
                kind = ?key.kind,
                client = %key.client_addr,
                target = %key.target_addr,
                host = %host,
                "UDP sniff success after reassembly"
            );

            pending.spec.sniffed_host = Some(host);
            flush_pending_udp_sniff(state, pending).await;
        }
        UdpSniffOutcome::NeedMore { protocol } => {
            debug!(
                protocol = udp_sniff_protocol_name(protocol),
                kind = ?key.kind,
                client = %key.client_addr,
                target = %key.target_addr,
                payload_len = payload.len(),
                "UDP sniff still need more",
            );

            {
                let mut guard = pending_sniff.lock().await;
                guard.insert(key, pending);
            }
            enforce_pending_udp_sniff_capacity(pending_sniff).await;
        }
        UdpSniffOutcome::NotMatched => {
            debug!(
                kind = ?key.kind,
                client = %key.client_addr,
                target = %key.target_addr,
                "UDP sniff pending not matched"
            );

            flush_pending_udp_sniff(state, pending).await;
        }
        UdpSniffOutcome::Failed { protocol, error } => {
            debug!(
                protocol = udp_sniff_protocol_name(protocol),
                reason = udp_sniff_error_reason(error),
                kind = ?key.kind,
                client = %key.client_addr,
                target = %key.target_addr,
                "UDP sniff pending failed"
            );

            flush_pending_udp_sniff(state, pending).await;
        }
    }

    true
}

pub(crate) async fn handle_new_udp_sniff(
    state: Arc<AppState>,
    pending_sniff: PendingSniffMap,
    spec: UdpSessionSpec,
    payload: &[u8],
) -> bool {
    let key = spec.key;

    if state.udp_sniffers.is_empty() {
        return false;
    }

    let target_ip_direct = matches!(spec.routing, UdpRoutingMode::Auto)
        && state.should_direct(spec.key.target_addr.ip(), None);

    if target_ip_direct {
        return false;
    }

    for sniffer in &state.udp_sniffers {
        let mut sniff_session = sniffer.new_session();

        match sniff_session.feed(payload) {
            UdpSniffOutcome::Matched { protocol, host } => {
                let mut spec = spec;

                debug!(
                    sniffer = sniffer.name(),
                    protocol = udp_sniff_protocol_name(protocol),
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    host = %host,
                    "UDP sniff success"
                );

                spec.sniffed_host = Some(host);
                forward_udp_payload(state, spec, payload).await;
                return true;
            }
            UdpSniffOutcome::NeedMore { protocol } => {
                debug!(
                    sniffer = sniffer.name(),
                    protocol = udp_sniff_protocol_name(protocol),
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    payload_len = payload.len(),
                    "UDP sniff need more, pending created"
                );

                let pending = PendingUdpSniff::new(spec, sniff_session, payload);
                {
                    let mut guard = pending_sniff.lock().await;
                    guard.insert(key, pending);
                }
                enforce_pending_udp_sniff_capacity(pending_sniff).await;
                return true;
            }
            UdpSniffOutcome::NotMatched => {
                debug!(
                    sniffer = sniffer.name(),
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    "UDP sniff not matched"
                );
                continue;
            }
            UdpSniffOutcome::Failed { protocol, error } => {
                debug!(
                    sniffer = sniffer.name(),
                    protocol = udp_sniff_protocol_name(protocol),
                    reason = udp_sniff_error_reason(error),
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    "UDP sniff failed"
                );
                continue;
            }
        }
    }

    false
}

// 清理过期的 pending sniff：把超时的 pending flush 掉，并释放资源。
// 由主循环每秒调用一次。
pub(crate) async fn reap_pending_udp_sniff(state: Arc<AppState>, pending_sniff: PendingSniffMap) {
    use crate::util::now_secs;
    let now = now_secs();

    // 先收集过期 keys（只读锁，快速）
    let expired_keys: Vec<UdpSessionKey> = {
        let guard = pending_sniff.lock().await;
        guard
            .iter()
            .filter_map(|(key, pending)| {
                if now.saturating_sub(pending.started_secs) >= UDP_SNIFF_TIMEOUT_SECS {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect()
    };

    // 批量 remove：一次写锁把 expired 全拿出来，再逐个 flush
    let expired_pendings: Vec<PendingUdpSniff> = {
        let mut guard = pending_sniff.lock().await;
        expired_keys
            .into_iter()
            .filter_map(|key| guard.remove(&key))
            .collect()
    };

    for pending in expired_pendings {
        debug!(
            kind = ?pending.spec.key.kind,
            client = %pending.spec.key.client_addr,
            target = %pending.spec.key.target_addr,
            cached_datagrams = pending.datagram_count(),
            cached_bytes = pending.cached_bytes(),
            "UDP sniff pending expired by reap"
        );
        flush_pending_udp_sniff(state.clone(), pending).await;
    }

    enforce_pending_udp_sniff_capacity(pending_sniff).await;
}

pub(crate) async fn enforce_pending_udp_sniff_capacity(pending_sniff: PendingSniffMap) {
    loop {
        let mut guard = pending_sniff.lock().await;
        if guard.len() <= UDP_SNIFF_MAX_PENDING_SESSIONS {
            break;
        }
        let oldest_key = guard
            .iter()
            .min_by_key(|(_, pending)| pending.started_secs)
            .map(|(key, _)| *key);

        let Some(oldest_key) = oldest_key else {
            break;
        };

        if let Some(pending) = guard.remove(&oldest_key) {
            warn!(
                kind = ?oldest_key.kind,
                client = %oldest_key.client_addr,
                target = %oldest_key.target_addr,
                cached_datagrams = pending.datagram_count(),
                cached_bytes = pending.cached_bytes(),
                pending_len = guard.len(),
                "UDP sniff pending overflow, dropping oldest immediately"
            );

            drop(pending);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sniff::udp::{UdpSniffOutcome, UdpSniffProtocol, UdpSnifferSessionEngine};
    use std::collections::HashMap;

    struct DummySniffer;
    impl UdpSnifferSessionEngine for DummySniffer {
        fn feed(&mut self, _payload: &[u8]) -> UdpSniffOutcome {
            UdpSniffOutcome::NeedMore {
                protocol: UdpSniffProtocol::QuicSni,
            }
        }
    }

    // ---- PendingReplayBuffer ----
    #[test]
    fn replay_buffer_starts_with_one_datagram() {
        let buf = PendingReplayBuffer::new(b"hello");
        assert_eq!(buf.datagram_count(), 1);
        assert_eq!(buf.cached_bytes(), 5);
    }

    #[test]
    fn push_within_limits() {
        let mut buf = PendingReplayBuffer::new(b"a");
        assert!(buf.push_datagram(b"b"));
        assert_eq!(buf.datagram_count(), 2);
    }

    #[test]
    fn push_exceeds_count() {
        let mut buf = PendingReplayBuffer::new(b"a");
        for _ in 0..UDP_SNIFF_MAX_CACHED_DATAGRAMS - 1 {
            assert!(buf.push_datagram(b"x"));
        }
        assert!(!buf.push_datagram(b"overflow"));
    }

    #[test]
    fn push_exceeds_bytes() {
        let big = vec![0u8; UDP_SNIFF_MAX_CACHED_BYTES];
        let mut buf = PendingReplayBuffer::new(&big[..]);
        assert!(!buf.push_datagram(b"x"));
    }

    #[test]
    fn into_datagrams_preserves_order() {
        let mut buf = PendingReplayBuffer::new(b"first");
        buf.push_datagram(b"second");
        let datagrams = buf.into_datagrams();
        assert_eq!(datagrams, vec![b"first".to_vec(), b"second".to_vec()]);
    }

    // ---- PendingUdpSniff ----
    #[test]
    fn pending_sniff_expired() {
        let spec = UdpSessionSpec::for_tproxy(
            "127.0.0.1:1000".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        );
        let sniffer = Box::new(DummySniffer);
        let mut pending = PendingUdpSniff::new(spec, sniffer, b"data");
        // 将 started_secs 设为很久以前，使其过期
        pending.started_secs = 0;
        assert!(pending.expired());
    }

    #[test]
    fn pending_sniff_not_expired() {
        let spec = UdpSessionSpec::for_tproxy(
            "127.0.0.1:1000".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        );
        let sniffer = Box::new(DummySniffer);
        let pending = PendingUdpSniff::new(spec, sniffer, b"data");
        // 刚创建应未过期
        assert!(!pending.expired());
    }

    // ---- enforce_pending_udp_sniff_capacity ----
    #[tokio::test]
    async fn enforce_removes_oldest_when_over_capacity() {
        let map = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let total = UDP_SNIFF_MAX_PENDING_SESSIONS + 2;
        for i in 0..total {
            let spec = UdpSessionSpec::for_tproxy(
                format!("127.0.0.1:{}", 1000 + i).parse().unwrap(),
                "10.0.0.1:443".parse().unwrap(),
            );
            let sniffer = Box::new(DummySniffer);
            let mut pending = PendingUdpSniff::new(spec, sniffer, b"x");
            pending.started_secs = i as u64;
            map.lock().await.insert(pending.spec.key, pending);
        }
        enforce_pending_udp_sniff_capacity(map.clone()).await;
        let guard = map.lock().await;
        assert!(guard.len() <= UDP_SNIFF_MAX_PENDING_SESSIONS);
        let oldest_key = UdpSessionSpec::for_tproxy(
            "127.0.0.1:1000".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        )
        .key;
        assert!(!guard.contains_key(&oldest_key));
    }
}
