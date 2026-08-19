//! UDP 嗅探的 pending 状态管理。
//!
//! QUIC 等 UDP 协议的首个数据包可能不足以提取域名（SNI），需要等待更多包。
//! 本模块维护一个 `PendingSniffMap`：当嗅探返回 `NeedMore` 时创建 pending 条目，
//! 后续到达的包继续喂给 sniffer，直到成功匹配、超时或容量溢出。
//!
//! 嗅探期间收到的包缓存在 `PendingReplayBuffer` 中，嗅探完成后一次性 flush
//! （带或不带 sniffed_host）到真正的 UDP session。
//!
//! 仿效 xray-core 的 full 模式：
//! - 每个 pending 有一个可配置的预算窗口（默认 200ms，对应 xray 的 cacheDeadline），
//!   窗口内持续累积 QUIC Initial 包以拼出 SNI；提前凑齐即立即放行。
//! - "再试 N 次仍然无果"也放弃（对应 xray 的 totalAttempt>=2）：`NotMatched`
//!   （协议未命中 / 非 QUIC）会计入次数，达到 `UDP_SNIFF_NO_CLUE_LIMIT` 即按 IP 转发。
//!
//! 关键常量：
//! - pending 超时默认 200ms（可由 `quic_sniff_pending_timeout_ms` 配置）
//! - 每会话最多缓存 8 包 / 64KB
//! - 全局上限 4096 个 pending，溢出时淘汰最老条目
//! - recv 循环在收包间隙顺带执行周期清理（无独立定时器臂，仅 full 模式按 100ms
//!   档位）；活跃流主要靠下一个数据包到达时的惰性过期判断保证 200ms 时效，
//!   静默流最坏要等一次 reap + 下一收包才被 flush（机会式收紧，非严格周期）

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio_util::bytes::Bytes;
use tracing::{debug, trace, warn};

// 共享的 UDP sniff 状态表：每个 UdpSessionKey 对应一个正在 sniff 中的会话。
// 使用 DashMap 替代 tokio::sync::Mutex<HashMap> 以减少锁竞争。
pub(crate) type PendingSniffMap = Arc<DashMap<UdpSessionKey, PendingUdpSniff>>;

use crate::cli::QuicSniffMode;
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
    pub(crate) deadline: Instant,
    pub(crate) no_clue_attempts: usize,
    pub(crate) spec: UdpSessionSpec,
    pub(crate) sniffer: Box<dyn UdpSnifferSessionEngine>,
    pub(crate) replay: PendingReplayBuffer,
}

impl PendingUdpSniff {
    pub(crate) fn new(
        spec: UdpSessionSpec,
        sniffer: Box<dyn UdpSnifferSessionEngine>,
        first_payload: &[u8],
        pending_timeout: Duration,
    ) -> Self {
        Self {
            deadline: Instant::now() + pending_timeout,
            no_clue_attempts: 0,
            spec,
            sniffer,
            replay: PendingReplayBuffer::new(first_payload),
        }
    }

    pub(crate) fn push_datagram(&mut self, payload: &[u8]) -> bool {
        self.replay.push_datagram(payload)
    }

    pub(crate) fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// 记录一次"无进展 / 协议未命中"（对应 xray-core 的 `totalAttempt`，
    /// `ErrNoClue` 计数、`ErrProtoNeedMoreData` 不计数）。
    /// 返回 true 表示已达到放弃阈值，应停止 pending 按 IP 转发。
    pub(crate) fn record_no_clue(&mut self) -> bool {
        self.no_clue_attempts += 1;
        self.no_clue_attempts >= UDP_SNIFF_NO_CLUE_LIMIT
    }

    pub(crate) fn datagram_count(&self) -> usize {
        self.replay.datagram_count()
    }

    pub(crate) fn cached_bytes(&self) -> usize {
        self.replay.cached_bytes()
    }
}

pub(crate) const UDP_SNIFF_NO_CLUE_LIMIT: usize = 2;
pub(crate) const UDP_SNIFF_MAX_CACHED_DATAGRAMS: usize = 8;
pub(crate) const UDP_SNIFF_MAX_CACHED_BYTES: usize = 64 * 1024;
pub(crate) const UDP_SNIFF_MAX_PENDING_SESSIONS: usize = 4096;
/// full 模式下 pending 的 reap 周期：配合 200ms 预算，静默-重组流最坏约一个周期兜底。
pub(crate) const UDP_SNIFF_REAP_INTERVAL: Duration = Duration::from_millis(100);
/// 未产出 pending（none/besteffort）时回落秒级清理 idle key_lock，
/// 避免在 MIPS 等低配场景为收紧 QUIC 超时支付额外周期开销。
pub(crate) const UDP_SNIFF_REAP_IDLE_INTERVAL: Duration = Duration::from_secs(1);

async fn send_udp_payload(session: &UdpSession, payload: &[u8]) {
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

    send_udp_payload(&session, payload).await;
}

pub(crate) async fn forward_udp_payload_to_session(session: Arc<UdpSession>, payload: &[u8]) {
    send_udp_payload(&session, payload).await;
}

pub(crate) async fn flush_pending_udp_sniff(state: Arc<AppState>, pending: PendingUdpSniff) {
    let datagrams = pending.replay.into_datagrams();
    let spec = pending.spec;

    // 注意：不更新已有 session 的 sniffed_host。
    // 首包已按 IP 路由建立 session 并发送了首个 SOCKS5 包（target=IP），
    // 如果中途改成域名 target，SOCKS5 relay 可能把域名解析到不同 IP，
    // 导致 QUIC 客户端跟不同服务器通信，握手失败。
    // 整条连接保持首包建立时的 target 语义（IP）一致性。

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
        pending_sniff.remove(&key);
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

    let Some(mut pending) = pending_sniff.remove(&key).map(|e| e.1) else {
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

            pending_sniff.insert(key, pending);
            enforce_pending_udp_sniff_capacity(pending_sniff).await;
        }
        UdpSniffOutcome::NotMatched => {
            // 对应 xray-core 的 ErrNoClue：不把它当"必定不是 QUIC"立即中止，
            // 而是计入 totalAttempt，达到阈值（默认 2 次）才放弃。
            // 允许预算窗口内偶发的非 Initial / 无关数据包。
            if pending.record_no_clue() {
                debug!(
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    no_clue_attempts = pending.no_clue_attempts,
                    "UDP sniff pending given up: too many no_clue"
                );
                flush_pending_udp_sniff(state, pending).await;
            } else {
                debug!(
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    no_clue_attempts = pending.no_clue_attempts,
                    "UDP sniff pending no_clue, waiting for more"
                );
                pending_sniff.insert(key, pending);
                enforce_pending_udp_sniff_capacity(pending_sniff).await;
            }
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
                match state.config.quic_sniff_mode {
                    QuicSniffMode::Full => {
                        debug!(
                            sniffer = sniffer.name(),
                            protocol = udp_sniff_protocol_name(protocol),
                            kind = ?key.kind,
                            client = %key.client_addr,
                            target = %key.target_addr,
                            payload_len = payload.len(),
                            "UDP sniff need more, pending created (full mode)"
                        );

                        // full 模式：缓存首包到 pending，等 sniff 完成后带 sniffed_host 一起转发。
                        // 在 ~quic_sniff_pending_timeout_ms 预算窗口内凑够能提取 SNI 的多个包才放行，
                        // 牺牲至多约一个 pending 窗口的时延换取识别率（仿效 xray-core full 模式）。
                        let pending_timeout =
                            Duration::from_millis(state.config.quic_sniff_pending_timeout_ms);
                        let pending =
                            PendingUdpSniff::new(spec, sniff_session, payload, pending_timeout);
                        pending_sniff.insert(key, pending);
                        enforce_pending_udp_sniff_capacity(pending_sniff).await;
                        return true;
                    }
                    QuicSniffMode::BestEffort | QuicSniffMode::None => {
                        // best-effort：只对首个数据包尝试提取 SNI。
                        // 首包不足即放弃，不再创建 pending、不再对后续包重试，直接按 IP 转发。
                        debug!(
                            sniffer = sniffer.name(),
                            protocol = udp_sniff_protocol_name(protocol),
                            mode = ?state.config.quic_sniff_mode,
                            kind = ?key.kind,
                            client = %key.client_addr,
                            target = %key.target_addr,
                            "UDP sniff best-effort: SNI not found in first packet, \
                             giving up (no further reassembly), forwarding by IP"
                        );

                        forward_udp_payload(state, spec, payload).await;
                        return true;
                    }
                }
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
// 由 maybe_reap_pending_udp_sniff 在收包间隙顺带调用（full 模式 100ms 周期）；
// 对活跃流主要依赖 next-packet 到达时的惰性过期判断。
pub(crate) async fn reap_pending_udp_sniff(state: Arc<AppState>, pending_sniff: PendingSniffMap) {
    // 收集过期 keys
    let expired_keys: Vec<UdpSessionKey> = pending_sniff
        .iter()
        .filter_map(|entry| {
            if entry.value().expired() {
                Some(*entry.key())
            } else {
                None
            }
        })
        .collect();

    // 批量 remove 并 flush
    for key in expired_keys {
        if let Some((_, pending)) = pending_sniff.remove(&key) {
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
    }

    enforce_pending_udp_sniff_capacity(pending_sniff).await;
}

pub(crate) async fn enforce_pending_udp_sniff_capacity(pending_sniff: PendingSniffMap) {
    while pending_sniff.len() > UDP_SNIFF_MAX_PENDING_SESSIONS {
        // deadline 与创建时间同序（超时窗口全局一致），故取最小 deadline 即最老条目；
        // 若未来允许每条 pending 不同超时，语义会变为"最早过期"，届时需改写。
        let oldest_key = pending_sniff
            .iter()
            .min_by_key(|entry| entry.value().deadline)
            .map(|entry| *entry.key());

        let Some(oldest_key) = oldest_key else {
            break;
        };

        if let Some((_, pending)) = pending_sniff.remove(&oldest_key) {
            warn!(
                kind = ?oldest_key.kind,
                client = %oldest_key.client_addr,
                target = ?oldest_key.target_addr,
                cached_datagrams = pending.datagram_count(),
                cached_bytes = pending.cached_bytes(),
                pending_len = pending_sniff.len(),
                "UDP sniff pending overflow, dropping oldest immediately"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sniff::udp::{UdpSniffOutcome, UdpSniffProtocol, UdpSnifferSessionEngine};

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
    fn mk_pending(spec: UdpSessionSpec, payload: &[u8]) -> PendingUdpSniff {
        PendingUdpSniff::new(
            spec,
            Box::new(DummySniffer),
            payload,
            Duration::from_secs(5),
        )
    }

    #[test]
    fn pending_sniff_expired() {
        let spec = UdpSessionSpec::for_tproxy(
            "127.0.0.1:1000".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        );
        let mut pending = mk_pending(spec, b"data");
        // 将 deadline 设为很久以前，使其过期
        pending.deadline = Instant::now() - Duration::from_secs(1);
        assert!(pending.expired());
    }

    #[test]
    fn pending_sniff_not_expired() {
        let spec = UdpSessionSpec::for_tproxy(
            "127.0.0.1:1000".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        );
        let pending = mk_pending(spec, b"data");
        // 刚创建应未过期
        assert!(!pending.expired());
    }

    #[test]
    fn no_clue_requires_two_attempts() {
        let spec = UdpSessionSpec::for_tproxy(
            "127.0.0.1:1000".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        );
        let mut pending = mk_pending(spec, b"data");
        // 第一次 no-clue 未达阈值
        assert!(!pending.record_no_clue());
        // 第二次达到阈值，应放弃
        assert!(pending.record_no_clue());
    }

    // ---- enforce_pending_udp_sniff_capacity ----
    #[tokio::test]
    async fn enforce_removes_oldest_when_over_capacity() {
        let map = Arc::new(DashMap::new());
        let total = UDP_SNIFF_MAX_PENDING_SESSIONS + 2;
        for i in 0..total {
            let spec = UdpSessionSpec::for_tproxy(
                format!("127.0.0.1:{}", 1000 + i).parse().unwrap(),
                "10.0.0.1:443".parse().unwrap(),
            );
            let mut pending = mk_pending(spec, b"x");
            pending.deadline = Instant::now() + Duration::from_secs(i as u64);
            map.insert(pending.spec.key, pending);
        }
        enforce_pending_udp_sniff_capacity(map.clone()).await;
        assert!(map.len() <= UDP_SNIFF_MAX_PENDING_SESSIONS);
        let oldest_key = UdpSessionSpec::for_tproxy(
            "127.0.0.1:1000".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        )
        .key;
        assert!(!map.contains_key(&oldest_key));
    }

    // ---- sniffed_host 传播 ----
    #[test]
    fn pending_sniff_created_with_none_host() {
        let spec = UdpSessionSpec::for_tproxy(
            "127.0.0.1:1000".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        );
        let pending = mk_pending(spec, b"data");
        assert!(pending.spec.sniffed_host.is_none());
    }

    #[test]
    fn pending_sniff_host_set_on_match() {
        let spec = UdpSessionSpec::for_tproxy(
            "127.0.0.1:1000".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        );
        let mut pending = mk_pending(spec, b"data");

        // 模拟 sniff 成功后设置 host（与 handle_pending_udp_sniff 的 Matched 路径一致）
        pending.spec.sniffed_host = Some("example.com".to_string());
        assert_eq!(pending.spec.sniffed_host.as_deref(), Some("example.com"));
    }

    #[test]
    fn pending_sniff_host_none_on_expire() {
        let spec = UdpSessionSpec::for_tproxy(
            "127.0.0.1:1000".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        );
        let mut pending = mk_pending(spec, b"data");
        pending.deadline = Instant::now() - Duration::from_secs(1);

        // 过期时 host 仍为 None — flush 路径不带 host 创建 session
        assert!(pending.expired());
        assert!(pending.spec.sniffed_host.is_none());
    }

    // ---- capacity enforcement 留下较新项 ----
    #[tokio::test]
    async fn enforce_keeps_newer_items() {
        let map: PendingSniffMap = Arc::new(DashMap::new());
        let total = UDP_SNIFF_MAX_PENDING_SESSIONS + 3;
        for i in 0..total {
            let spec = UdpSessionSpec::for_tproxy(
                format!("127.0.0.1:{}", 2000 + i).parse().unwrap(),
                "10.0.0.1:443".parse().unwrap(),
            );
            let mut pending = mk_pending(spec, b"x");
            pending.deadline = Instant::now() + Duration::from_secs(i as u64); // 0 最老, total-1 最新
            map.insert(pending.spec.key, pending);
        }

        enforce_pending_udp_sniff_capacity(map.clone()).await;

        // 应保留较新的项
        let newest_spec = UdpSessionSpec::for_tproxy(
            format!("127.0.0.1:{}", 2000 + total - 1).parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        );
        assert!(
            map.contains_key(&newest_spec.key),
            "newest item should remain"
        );

        // 最老的几项应被淘汰
        let oldest_spec = UdpSessionSpec::for_tproxy(
            "127.0.0.1:2000".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        );
        assert!(
            !map.contains_key(&oldest_spec.key),
            "oldest item should be evicted"
        );
    }

    // NOTE: 同 key 并发安全性由 run_udp_loop / run_udp_port_forward 中的
    // key_locks 保证；handle_udp_client_payload 在 key_lock 保护下串行执行，
    // 因此 DashMap 的 remove-mutate-insert 模式不会与同 key 并发更新交错。
}
