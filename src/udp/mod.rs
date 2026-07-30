mod fake;
mod pending;
mod session;
mod tproxy;

use anyhow::{Context, Result, anyhow};
use dashmap::DashMap;
use portable_atomic::AtomicU64;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, oneshot};
use tokio_util::bytes::Bytes;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

pub(crate) use pending::UDP_SNIFF_REAP_INTERVAL_SECS;
pub(crate) use session::{
    UdpOutbound, UdpReplyPath, UdpRoutingMode, UdpSession, UdpSessionEntry, UdpSessionKey,
    UdpSessionSpec,
};

use crate::socket_factory::create_direct_udp_socket;
use crate::socks5::{Socks5UdpAssoc, socks5_udp_associate_for_client};
use crate::state::AppState;
use crate::udp::fake::FakeUdpManager;
use crate::udp::pending::{PendingSniffMap, handle_udp_client_payload, reap_pending_udp_sniff};
use crate::udp::tproxy::TProxyUdpSocket;
use crate::util::{
    hex_encode, is_anyhow_emsgsize, is_io_emsgsize, new_udp_buf, now_secs, reset_udp_buf,
};

// 每个 UdpSessionKey 的串行锁：空 Mutex 只用于互斥，不存数据。
type UdpKeyLock = Arc<tokio::sync::Mutex<()>>;

// 当前 UDP loop 的 key_lock 表。DashMap 分片锁，减少高并发下的竞争。
type UdpKeyLocks = Arc<DashMap<UdpSessionKey, UdpKeyLock>>;

pub struct UdpRuntime {
    sessions: Mutex<HashMap<UdpSessionKey, UdpSessionEntry>>,
    fake_udp: FakeUdpManager,
    timeout: Duration,
    closed: AtomicBool,
}

impl UdpRuntime {
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            fake_udp: FakeUdpManager::new(),
            timeout,
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) async fn get_or_create_udp_session(
        self: &Arc<Self>,
        state: Arc<AppState>,
        spec: UdpSessionSpec,
    ) -> Result<Arc<UdpSession>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(anyhow!("UDP runtime is shutting down"));
        }
        let key = spec.key;

        let creating_notify = loop {
            let mut sessions = self.sessions.lock().await;
            if self.closed.load(Ordering::SeqCst) {
                return Err(anyhow!("UDP runtime is shutting down"));
            }

            match sessions.get(&key) {
                Some(UdpSessionEntry::Ready(session)) => {
                    trace!(
                        session_id = session.session_id,
                        kind = ?key.kind,
                        client = %key.client_addr,
                        target = %key.target_addr,
                        "UDP session reuse"
                    );
                    return Ok(session.clone());
                }
                Some(UdpSessionEntry::Creating(notify)) => {
                    let notify = notify.clone();
                    let notified = notify.notified();
                    drop(sessions);

                    debug!(
                        kind = ?key.kind,
                        client = %key.client_addr,
                        target = %key.target_addr,
                        "UDP session is being created, waiting"
                    );

                    notified.await;
                    continue;
                }
                None => {
                    let notify = Arc::new(tokio::sync::Notify::new());
                    sessions.insert(key, UdpSessionEntry::Creating(notify.clone()));
                    break notify;
                }
            }
        };

        let created = match tokio::spawn(create_udp_session(state.clone(), spec.clone())).await {
            Ok(result) => result,
            Err(join_err) => {
                let mut sessions = self.sessions.lock().await;
                sessions.remove(&key);
                drop(sessions);
                creating_notify.notify_waiters();
                if join_err.is_panic() {
                    return Err(anyhow!("UDP session creation panicked"));
                }
                return Err(anyhow!("UDP session creation task failed: {join_err}"));
            }
        };

        let mut sessions = self.sessions.lock().await;

        if self.closed.load(Ordering::SeqCst) {
            sessions.remove(&key);
            creating_notify.notify_waiters();

            let session_to_abort = match created {
                Ok(session) => {
                    session.cancel.cancel();
                    Some(session)
                }
                Err(_) => None,
            };

            drop(sessions); // 先放锁

            if let Some(session) = session_to_abort
                && let Some(h) = session.recv_task.lock().await.take()
            {
                h.abort();
            }

            return Err(anyhow!("UDP runtime is shutting down"));
        }

        match created {
            Ok(session) => {
                if session.cancel.is_cancelled() {
                    sessions.remove(&key);
                    creating_notify.notify_waiters();
                    return Err(anyhow!("UDP session recv loop exited before registration"));
                }
                sessions.insert(key, UdpSessionEntry::Ready(session.clone()));
                creating_notify.notify_waiters();

                debug!(
                    session_id = session.session_id,
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    "created UDP session"
                );

                Ok(session)
            }
            Err(e) => {
                sessions.remove(&key);
                creating_notify.notify_waiters();
                Err(e)
            }
        }
    }

    pub(crate) async fn cleanup_expired_sessions(&self) {
        let now = now_secs();
        let timeout_secs = self.timeout.as_secs();

        let snapshot: Vec<(UdpSessionKey, Arc<UdpSession>)> = {
            let sessions = self.sessions.lock().await;

            sessions
                .iter()
                .filter_map(|(key, entry)| match entry {
                    UdpSessionEntry::Ready(session) => Some((*key, session.clone())),
                    UdpSessionEntry::Creating(_) => None,
                })
                .collect()
        };

        let mut expired = Vec::with_capacity(snapshot.len());

        for (key, session) in snapshot {
            let last_seen = session
                .last_seen_secs
                .load(std::sync::atomic::Ordering::Relaxed);

            if now.saturating_sub(last_seen) >= timeout_secs {
                expired.push((key, session));
            }
        }

        if expired.is_empty() {
            return;
        }

        let mut expired_sessions = Vec::with_capacity(expired.len());
        let mut sessions = self.sessions.lock().await;

        for (key, session) in expired {
            let should_remove = match sessions.get(&key) {
                Some(UdpSessionEntry::Ready(current)) if Arc::ptr_eq(current, &session) => {
                    let last_seen = current.last_seen_secs.load(Ordering::Relaxed);
                    now.saturating_sub(last_seen) >= timeout_secs
                }
                _ => false,
            };

            if should_remove {
                debug!(
                    session_id = session.session_id,
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    "UDP session expired and cancelled"
                );
                sessions.remove(&key);
                session.cancel.cancel();
                expired_sessions.push(session);
            }
        }

        drop(sessions);

        for session in expired_sessions {
            if let Some(h) = session.recv_task.lock().await.take() {
                h.abort();
            }
        }
    }

    pub(crate) async fn get_ready_udp_session(
        &self,
        key: UdpSessionKey,
    ) -> Option<Arc<UdpSession>> {
        let sessions = self.sessions.lock().await;

        match sessions.get(&key) {
            Some(UdpSessionEntry::Ready(session)) => Some(session.clone()),
            _ => None,
        }
    }

    pub async fn shutdown(&self, timeout: Duration) -> bool {
        self.closed.store(true, Ordering::SeqCst);
        let mut sessions = self.sessions.lock().await;
        let mut ready_sessions = Vec::with_capacity(sessions.len());
        for entry in sessions.values() {
            match entry {
                UdpSessionEntry::Ready(session) => {
                    session.cancel.cancel();
                    ready_sessions.push(Arc::clone(session));
                }
                UdpSessionEntry::Creating(notify) => notify.notify_waiters(),
            }
        }
        sessions.clear();
        drop(sessions);

        // sessions 锁已释放，再拿每个 session 的 recv_task 锁
        let mut handles = Vec::with_capacity(ready_sessions.len());
        for session in ready_sessions {
            if let Some(h) = session.recv_task.lock().await.take() {
                handles.push(h);
            }
        }

        let deadline = tokio::time::Instant::now() + timeout;
        let mut ok = true;
        for mut h in handles {
            match tokio::time::timeout_at(deadline, &mut h).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    warn!(error = format!("{:#}", e), "UDP session recv task exited");
                }
                Err(_) => {
                    warn!(?timeout, "UDP session recv task did not exit, aborting");
                    h.abort();
                    let _ = h.await;
                    ok = false;
                }
            }
        }

        self.fake_udp.close().await;
        ok
    }
}

impl UdpSession {
    pub(crate) async fn send_reply(
        &self,
        state: &AppState,
        direction: &'static str,
        remote_src: SocketAddr,
        payload: &[u8],
        relay_addr: Option<SocketAddr>,
    ) {
        let key = self.key();

        match &self.spec.reply_path {
            UdpReplyPath::Tproxy => {
                match state
                    .runtime
                    .udp
                    .fake_udp
                    .send_to(remote_src, key.client_addr, payload, state.config.fwmark)
                    .await
                {
                    Ok(sent) => {
                        trace!(
                            direction = direction,
                            kind = ?key.kind,
                            spoofed_src = %remote_src,
                            client = %key.client_addr,
                            payload_len = payload.len(),
                            sent = sent,
                            "UDP response sent"
                        );
                    }
                    Err(e) if is_anyhow_emsgsize(&e) => {
                        warn!(
                            direction = direction,
                            kind = ?key.kind,
                            spoofed_src = %remote_src,
                            client = %key.client_addr,
                            payload_len = payload.len(),
                            relay = ?relay_addr,
                            error = format!("{:#}", e),
                            "UDP datagram dropped due to EMSGSIZE"
                        );
                    }
                    Err(e) => {
                        warn!(
                            direction = direction,
                            kind = ?key.kind,
                            spoofed_src = %remote_src,
                            client = %key.client_addr,
                            payload_len = payload.len(),
                            relay = ?relay_addr,
                            error = format!("{:#}", e),
                            "failed to send UDP response",
                        );
                    }
                }
            }
            UdpReplyPath::PortForward { listen_sock } => {
                match listen_sock.send_to(payload, key.client_addr).await {
                    Ok(sent) => {
                        trace!(
                            direction = direction,
                            kind = ?key.kind,
                            remote_src = %remote_src,
                            client = %key.client_addr,
                            payload_len = payload.len(),
                            sent = sent,
                            "UDP response sent"
                        );
                    }
                    Err(e) if is_io_emsgsize(&e) => {
                        warn!(
                            direction = direction,
                            kind = ?key.kind,
                            remote_src = %remote_src,
                            client = %key.client_addr,
                            payload_len = payload.len(),
                            relay = ?relay_addr,
                            error = format!("{:#}", e),
                            "UDP datagram dropped due to EMSGSIZE"
                        );
                    }
                    Err(e) => {
                        warn!(
                            direction = direction,
                            kind = ?key.kind,
                            remote_src = %remote_src,
                            client = %key.client_addr,
                            payload_len = payload.len(),
                            relay = ?relay_addr,
                            error = format!("{:#}", e),
                            "failed to send UDP response"
                        );
                    }
                }
            }
        }
    }
}

async fn connect_socks5_udp(state: &AppState, spec: &UdpSessionSpec) -> Result<Socks5UdpAssoc> {
    let key = spec.key;
    let group = state.lookup_upstream_group(key.client_addr.ip(), spec.sniffed_host.as_deref());
    let up = state
        .upstreams
        .pick_from_group(group)
        .or_else(|| state.upstreams.pick())
        .ok_or_else(|| anyhow!("no upstream available for group '{}'", group))?;
    debug!(
        upstream_id = %up.id,
        upstream_addr = %up.addr,
        score = up.score(),
        kind = ?key.kind,
        client = %key.client_addr,
        target = %key.target_addr,
        sniffed_host = ?spec.sniffed_host,
        "selected upstream for UDP"
    );

    let assoc = tokio::time::timeout(
        std::time::Duration::from_secs(state.config.connect_timeout_secs),
        socks5_udp_associate_for_client(up.addr, state.config.fwmark, state.socks5_credentials()),
    )
    .await
    .map_err(|_| anyhow!("SOCKS5 UDP ASSOCIATE timeout"))??;
    Ok(assoc)
}

async fn create_udp_session(state: Arc<AppState>, spec: UdpSessionSpec) -> Result<Arc<UdpSession>> {
    let key = spec.key;
    let outbound = match spec.routing {
        UdpRoutingMode::Auto => {
            if state.should_direct(key.target_addr.ip(), spec.sniffed_host.as_deref()) {
                debug!(
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    sniffed_host = ?spec.sniffed_host,
                    "UDP session direct"
                );
                let socket = create_direct_udp_socket(key.target_addr, state.config.fwmark)?;
                UdpOutbound::Direct { socket }
            } else {
                let assoc = connect_socks5_udp(&state, &spec).await?;
                UdpOutbound::Socks5 { assoc }
            }
        }
        UdpRoutingMode::ForceSocks5 => {
            let assoc = connect_socks5_udp(&state, &spec).await?;
            UdpOutbound::Socks5 { assoc }
        }
    };

    let session_id = crate::udp::session::UDP_SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let outbound_desc = match &outbound {
        UdpOutbound::Direct { .. } => "direct",
        UdpOutbound::Socks5 { .. } => "socks5",
    };
    debug!(
        session_id = session_id,
        kind = ?spec.key.kind,
        client = %spec.key.client_addr,
        target = %spec.key.target_addr,
        sniffed_host = ?spec.sniffed_host,
        outbound = outbound_desc,
        "UDP session creating"
    );

    let session = Arc::new(UdpSession {
        session_id,
        spec,
        outbound,
        last_seen_secs: AtomicU64::new(now_secs()),
        cancel: tokio_util::sync::CancellationToken::new(),
        recv_task: Mutex::new(None),
    });

    let (ready_tx, ready_rx) = oneshot::channel();

    let recv_handle = {
        let session = session.clone();
        let state = state.clone();

        tokio::spawn(async move {
            let result = run_udp_session_recv_loop(session.clone(), state.clone(), ready_tx).await;
            session.cancel.cancel();
            let mut map = state.runtime.udp.sessions.lock().await;
            let should_remove = matches!(
                map.get(&key),
                Some(UdpSessionEntry::Ready(current)) if Arc::ptr_eq(current, &session)
            );
            if should_remove {
                map.remove(&key);
            }
            drop(map);
            if let Err(e) = result {
                warn!(error = format!("{:#}", e), "UDP session recv loop exited");
            }
        })
    };

    {
        let mut guard = session.recv_task.lock().await;
        *guard = Some(recv_handle);
    }

    ready_rx
        .await
        .map_err(|_| anyhow!("UDP session recv loop exited before ready"))?;

    Ok(session)
}

async fn run_udp_session_recv_loop(
    session: Arc<UdpSession>,
    state: Arc<AppState>,
    ready_tx: oneshot::Sender<()>,
) -> Result<()> {
    let key = session.key();

    debug!(
        kind = ?key.kind,
        client = %key.client_addr,
        target = %key.target_addr,
        "UDP session recv loop starting"
    );

    match &session.outbound {
        UdpOutbound::Direct { socket } => {
            run_direct_udp_recv_loop(session.clone(), state, socket.clone(), ready_tx).await
        }
        UdpOutbound::Socks5 { assoc } => {
            run_socks5_udp_recv_loop(
                session.clone(),
                state,
                assoc.udp_socket.clone(),
                assoc.relay_addr,
                ready_tx,
            )
            .await
        }
    }
}

async fn run_direct_udp_recv_loop(
    session: Arc<UdpSession>,
    state: Arc<AppState>,
    socket: Arc<UdpSocket>,
    ready_tx: oneshot::Sender<()>,
) -> Result<()> {
    let key = session.key();
    let mut buf = new_udp_buf();
    let _ = ready_tx.send(());

    let idle_timeout_secs = state.config.udp_session_idle_timeout_secs;
    let idle_deadline = make_idle_deadline(idle_timeout_secs);
    tokio::pin!(idle_deadline);

    loop {
        reset_udp_buf(&mut buf);
        tokio::select! {
            biased;
            _ = session.cancel.cancelled() => {
                debug!(
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    "direct UDP recv loop cancelled"
                );
                return Ok(());
            }
            _ = &mut idle_deadline, if idle_timeout_secs > 0 => {
                warn!(
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    timeout_secs = idle_timeout_secs,
                    "direct UDP session idle timeout, cancelling"
                );
                return Ok(());
            }
            r = socket.recv(&mut buf) => {
                let n = match connected_udp_recv_result(
                    r,
                    "direct",
                    key,
                    None,
                )? {
                    Some(n) => n,
                    None => continue,
                };

                session.touch();
                reset_idle_deadline(idle_deadline.as_mut(), idle_timeout_secs);

                let payload = &buf[..n];

                session
                    .send_reply(
                        &state,
                        "direct_to_client",
                        key.target_addr,
                        payload,
                        None,
                    )
                    .await;
            }
        }
    }
}

async fn run_socks5_udp_recv_loop(
    session: Arc<UdpSession>,
    state: Arc<AppState>,
    relay_sock: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    ready_tx: oneshot::Sender<()>,
) -> Result<()> {
    let key = session.key();
    let mut buf = new_udp_buf();
    let relay_local = relay_sock.local_addr().ok();

    let _ = ready_tx.send(());

    // 空闲超时：每次收到回包后重置。如果在指定时间内没收到任何回包，
    // 说明 SOCKS5 UDP relay 可能失效，主动取消 session 以便客户端快速重试。
    let idle_timeout_secs = state.config.udp_session_idle_timeout_secs;
    let idle_deadline = make_idle_deadline(idle_timeout_secs);
    tokio::pin!(idle_deadline);
    let mut recv_count: u64 = 0;
    let mut inject_ok_count: u64 = 0;

    loop {
        reset_udp_buf(&mut buf);
        tokio::select! {
            biased;
            _ = session.cancel.cancelled() => {
                debug!(
                    session_id = session.session_id,
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    recv_count = recv_count,
                    inject_count = inject_ok_count,
                    "SOCKS5 UDP recv loop cancelled"
                );
                return Ok(());
            }

            _ = &mut idle_deadline, if idle_timeout_secs > 0 => {
                warn!(
                    session_id = session.session_id,
                    kind = ?key.kind,
                    client = %key.client_addr,
                    target = %key.target_addr,
                    relay = %relay_addr,
                    timeout_secs = idle_timeout_secs,
                    "SOCKS5 UDP session idle timeout, cancelling"
                );
                return Ok(());
            }

            r = relay_sock.recv(&mut buf) => {
                let n = match connected_udp_recv_result(
                    r,
                    "socks5",
                    key,
                    Some(relay_addr),
                )? {
                    Some(n) => n,
                    None => continue,
                };

                session.touch();
                recv_count += 1;
                reset_idle_deadline(idle_deadline.as_mut(), idle_timeout_secs);
                if recv_count == 1 {
                    debug!(
                        session_id = session.session_id,
                        kind = ?key.kind,
                        client = %key.client_addr,
                        target = %key.target_addr,
                        relay = %relay_addr,
                        "SOCKS5 UDP session first response received"
                    );
                }

                if tracing::enabled!(tracing::Level::TRACE) {
                    trace!(
                        kind = ?key.kind,
                        client = %key.client_addr,
                        target = %key.target_addr,
                        relay = %relay_addr,
                        local = ?relay_local,
                        packet_len = n,
                        head = %hex_encode(&buf[..n.min(80)]),
                        "SOCKS5 UDP raw recv"
                    );
                }

                let (remote_src, payload) = match crate::socks5::parse_socks5_udp_packet_with_fallback_src(&buf[..n], key.target_addr) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(
                            kind = ?key.kind,
                            client = %key.client_addr,
                            target = %key.target_addr,
                            relay = %relay_addr,
                            packet_len = n,
                            error = format!("{:#}", e),
                            "invalid SOCKS5 UDP packet"
                        );
                        continue;
                    }
                };

                let client_visible_src = match &session.spec.reply_path {
                    UdpReplyPath::Tproxy => {
                        // TPROXY 必须让客户端看到“原始目标地址”作为回包源。
                        // 特别是 SOCKS5 UDP 使用 domain ATYP 时，relay 可能解析到不同 IP；
                        // 如果把 relay 回包头里的 remote_src 直接伪造成源地址，
                        // QUIC 客户端会认为 peer 地址不匹配而丢包。
                        key.target_addr
                    }
                    UdpReplyPath::PortForward { .. } => {
                        // port-forward 是客户端发给本地监听 socket，
                        // 回包源地址由本地 listen_sock 决定；这里仅用于日志。
                        remote_src
                    }
                };

                session
                    .send_reply(
                        &state,
                        "socks5_to_client",
                        client_visible_src,
                        payload,
                        Some(relay_addr),
                    )
                    .await;
                inject_ok_count += 1;
            }
        }
    }
}

pub async fn run_udp_gc_loop(state: Arc<AppState>, cancel: CancellationToken) {
    let interval = Duration::from_secs(10);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("UDP GC loop shutting down");
                break;
            }
            _ = tokio::time::sleep(interval) => {},
        }

        state.runtime.udp.cleanup_expired_sessions().await;
        state
            .runtime
            .udp
            .fake_udp
            .cleanup_expired(state.runtime.udp.timeout)
            .await;
    }
}

// 获取指定 UdpSessionKey 的串行锁。
// 如果该 key 之前没有锁，就新建一个插入全局表并返回；
// 如果已有，直接返回已有的。这样同一个 key 的所有 UDP 包
// 共享同一把 Mutex，自然串行。
fn get_udp_key_lock(key_locks: &UdpKeyLocks, key: UdpSessionKey) -> UdpKeyLock {
    key_locks
        .entry(key)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

// 清理 key_lock 表中已经空闲的锁。
// Arc::strong_count(lock) == 1 表示只有 map 自己持有这把锁，
// 没有任何活跃或排队的 packet task 在使用它，可以安全删除。
fn reap_idle_udp_key_locks(key_locks: &UdpKeyLocks) {
    // strong_count == 1 表示只有 map 持有，没有活跃 task 在等待或使用
    key_locks.retain(|_, lock| Arc::strong_count(lock) > 1);
}

pub async fn run_udp_loop(
    state: Arc<AppState>,
    tproxy_udp: UdpSocket,
    cancel: CancellationToken,
) -> Result<()> {
    let tproxy_udp = TProxyUdpSocket::new(tproxy_udp);
    let mut buf = new_udp_buf();

    // UDP 包并发上限：每包 spawn 一个 task，超限丢弃
    const UDP_PACKET_TASK_LIMIT: usize = 4096;
    // 防 task 风暴
    let packet_sem = Arc::new(tokio::sync::Semaphore::new(UDP_PACKET_TASK_LIMIT));

    // 防同 key 并发
    let key_locks: UdpKeyLocks = Arc::new(DashMap::new());
    // 共享 sniff 状态
    let pending_sniff = Arc::new(DashMap::new());
    let mut last_pending_reap_secs = now_secs();

    loop {
        reset_udp_buf(&mut buf);
        let packet = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("UDP tproxy loop shutting down");
                break;
            }
            res = tproxy_udp.recv_packet(&mut buf) => {
                match res {
                    Ok(packet) => packet,
                    Err(e) => {
                        warn!(error = format!("{:#}", e), "failed to receive TPROXY UDP packet");
                        continue;
                    }
                }
            }
        };

        let now = now_secs();
        if now.saturating_sub(last_pending_reap_secs) >= UDP_SNIFF_REAP_INTERVAL_SECS {
            last_pending_reap_secs = now;
            reap_pending_udp_sniff(state.clone(), pending_sniff.clone()).await;
            // 顺带清理无 task 使用的 idle key_lock，防内存泄漏
            reap_idle_udp_key_locks(&key_locks);
        }

        if packet.len == 0 {
            continue;
        }

        // 零拷贝：从 BytesMut 切出已填充的前 n 字节，冻结为不可变的 Bytes。
        // 底层数据不复制，仅做引用计数拆分；split 后 buf 指向剩余尾部。
        let payload = buf.split_to(packet.len).freeze();
        let spec = UdpSessionSpec::for_tproxy(packet.client_addr, packet.orig_dst);

        spawn_udp_packet_handler(
            state.clone(),
            packet_sem.clone(),
            key_locks.clone(),
            pending_sniff.clone(),
            spec,
            payload,
        )
        .await;
    }

    Ok(())
}

pub async fn run_udp_port_forward(
    listen_sock: Arc<UdpSocket>,
    listen_addr: SocketAddr,
    remote: SocketAddr,
    state: Arc<AppState>,
    cancel: CancellationToken,
) -> Result<()> {
    info!(
        "port-forward UDP: listening on {}, forwarding to {} via SOCKS5",
        listen_addr, remote
    );

    let mut buf = new_udp_buf();
    const UDP_PACKET_TASK_LIMIT: usize = 4096;
    let packet_sem = Arc::new(tokio::sync::Semaphore::new(UDP_PACKET_TASK_LIMIT));
    let key_locks: UdpKeyLocks = Arc::new(DashMap::new());
    let pending_sniff = Arc::new(DashMap::new());
    let mut last_pending_reap_secs = now_secs();

    loop {
        reset_udp_buf(&mut buf);
        let (n, client_addr) = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!(
                    listen_addr = %listen_addr,
                    remote = %remote,
                    "port-forward UDP shutting down"
                );
                break;
            }
            res = listen_sock.recv_from(&mut buf) => {
                res?
            }
        };

        let now = now_secs();

        if now.saturating_sub(last_pending_reap_secs) >= UDP_SNIFF_REAP_INTERVAL_SECS {
            last_pending_reap_secs = now;
            reap_pending_udp_sniff(state.clone(), pending_sniff.clone()).await;
            reap_idle_udp_key_locks(&key_locks);
        }

        if n == 0 {
            continue;
        }

        let payload = buf.split_to(n).freeze();
        let spec =
            UdpSessionSpec::for_port_forward(listen_addr, client_addr, remote, listen_sock.clone());

        spawn_udp_packet_handler(
            state.clone(),
            packet_sem.clone(),
            key_locks.clone(),
            pending_sniff.clone(),
            spec,
            payload,
        )
        .await;
    }

    Ok(())
}

// 将单个 UDP 包丢进后台 task 处理。
// 流程：先抢全局并发许可 → 再拿该 key 的串行锁 → 最后 spawn。
// 如果 Semaphore 已满，直接丢弃报文并打 debug 日志。
async fn spawn_udp_packet_handler(
    state: Arc<AppState>,
    packet_sem: Arc<tokio::sync::Semaphore>,
    key_locks: UdpKeyLocks,
    pending_sniff: PendingSniffMap,
    spec: UdpSessionSpec,
    payload: Bytes,
) {
    // 1. 抢当前 UDP loop 的并发许可。失败说明该 loop 已有 4096 个 task 在跑，直接丢包。
    let Ok(permit) = packet_sem.try_acquire_owned() else {
        debug!(
            kind = ?spec.key.kind,
            client = %spec.key.client_addr,
            target = %spec.key.target_addr,
            "UDP packet worker overloaded, dropping packet"
        );
        return;
    };

    // 2. 获取该 key 的串行锁。没有就新建，有就复用。
    let key_lock = get_udp_key_lock(&key_locks, spec.key);

    // 3.  spawn 后台 task。_permit 和 _key_guard 随 task 结束自动释放。
    // 直接使用 payload，无需拷贝；内部函数如果期望 &[u8]，传 &payload
    tokio::spawn(async move {
        let _permit = permit;
        let _key_guard = key_lock.lock().await;
        handle_udp_client_payload(state, pending_sniff, spec, &payload).await;
    });
}

/// 创建空闲超时 deadline。
/// idle_timeout_secs == 0 时返回远未来 deadline；调用方必须通过 select! guard 禁用该分支。
fn make_idle_deadline(idle_timeout_secs: u64) -> tokio::time::Sleep {
    if idle_timeout_secs > 0 {
        tokio::time::sleep(Duration::from_secs(idle_timeout_secs))
    } else {
        tokio::time::sleep(Duration::from_secs(30 * 365 * 24 * 3600))
    }
}

/// 重置空闲超时 deadline。idle_timeout_secs == 0 时不做任何操作。
/// 使用 checked_add 防止超大配置值导致 Instant 溢出。
fn reset_idle_deadline(deadline: std::pin::Pin<&mut tokio::time::Sleep>, idle_timeout_secs: u64) {
    if idle_timeout_secs > 0 {
        let now = tokio::time::Instant::now();
        let next = now
            .checked_add(Duration::from_secs(idle_timeout_secs))
            .unwrap_or(now + Duration::from_secs(30 * 365 * 24 * 3600));
        deadline.reset(next);
    }
}

fn connected_udp_recv_result(
    r: std::io::Result<usize>,
    direction: &'static str,
    key: UdpSessionKey,
    relay_addr: Option<SocketAddr>,
) -> Result<Option<usize>> {
    match r {
        Ok(0) => Ok(None),
        Ok(n) => Ok(Some(n)),
        Err(e) if is_io_emsgsize(&e) => {
            warn!(
                direction = %direction,
                kind = ?key.kind,
                client = %key.client_addr,
                target = %key.target_addr,
                relay = ?relay_addr,
                error = format!("{:#}", e),
                "UDP recv got EMSGSIZE, ignored"
            );

            Ok(None)
        }
        Err(e) => Err(e).with_context(|| format!("{direction} UDP recv failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use session::UdpSessionKind;

    #[test]
    fn same_key_returns_same_lock() {
        let key_locks: UdpKeyLocks = Arc::new(DashMap::new());
        let key = UdpSessionKey {
            kind: UdpSessionKind::Tproxy,
            client_addr: "127.0.0.1:1000".parse().unwrap(),
            target_addr: "10.0.0.1:53".parse().unwrap(),
        };

        let l1 = get_udp_key_lock(&key_locks, key);
        let l2 = get_udp_key_lock(&key_locks, key);

        assert!(Arc::ptr_eq(&l1, &l2));
    }

    #[test]
    fn different_keys_return_different_locks() {
        let key_locks: UdpKeyLocks = Arc::new(DashMap::new());
        let key_a = UdpSessionKey {
            kind: UdpSessionKind::Tproxy,
            client_addr: "127.0.0.1:1000".parse().unwrap(),
            target_addr: "10.0.0.1:53".parse().unwrap(),
        };
        let key_b = UdpSessionKey {
            kind: UdpSessionKind::Tproxy,
            client_addr: "127.0.0.1:2000".parse().unwrap(),
            target_addr: "10.0.0.1:53".parse().unwrap(),
        };

        let l1 = get_udp_key_lock(&key_locks, key_a);
        let l2 = get_udp_key_lock(&key_locks, key_b);

        assert!(!Arc::ptr_eq(&l1, &l2));
    }

    #[test]
    fn reap_keeps_referenced_lock() {
        let key_locks: UdpKeyLocks = Arc::new(DashMap::new());
        let key = UdpSessionKey {
            kind: UdpSessionKind::Tproxy,
            client_addr: "127.0.0.1:1000".parse().unwrap(),
            target_addr: "10.0.0.1:53".parse().unwrap(),
        };

        let lock = get_udp_key_lock(&key_locks, key);
        reap_idle_udp_key_locks(&key_locks);

        // 外部仍持有 lock 的 Arc，strong_count > 1，不应被 reap
        assert!(key_locks.contains_key(&key));
        assert!(Arc::ptr_eq(&lock, &get_udp_key_lock(&key_locks, key)));
    }

    #[test]
    fn reap_removes_idle_lock() {
        let key_locks: UdpKeyLocks = Arc::new(DashMap::new());
        let key = UdpSessionKey {
            kind: UdpSessionKind::Tproxy,
            client_addr: "127.0.0.1:1000".parse().unwrap(),
            target_addr: "10.0.0.1:53".parse().unwrap(),
        };

        // 创建 lock 后立刻 drop，只剩 map 自身持有
        drop(get_udp_key_lock(&key_locks, key));
        assert!(key_locks.contains_key(&key));

        reap_idle_udp_key_locks(&key_locks);

        // strong_count == 1 的空闲 lock 应被清除
        assert!(!key_locks.contains_key(&key));
    }
}
