mod fake;
mod pending;
mod session;
mod tproxy;

use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

pub(crate) use pending::UDP_SNIFF_REAP_INTERVAL_SECS;
pub(crate) use session::{
    UdpOutbound, UdpReplyPath, UdpRoutingMode, UdpSession, UdpSessionEntry, UdpSessionKey,
    UdpSessionSpec,
};

use crate::socket_factory::create_direct_udp_socket;
use crate::socks5::socks5_udp_associate_for_client;
use crate::state::AppState;
use crate::udp::fake::FakeUdpManager;
use crate::udp::pending::{PendingUdpSniff, handle_udp_client_payload, reap_pending_udp_sniff};
use crate::udp::tproxy::TProxyUdpSocket;
use crate::util::{hex_encode, is_anyhow_emsgsize, is_io_emsgsize, new_aligned_udp_buf, now_secs};

pub struct UdpRuntime {
    sessions: Mutex<std::collections::HashMap<UdpSessionKey, UdpSessionEntry>>,
    fake_udp: FakeUdpManager,
    timeout: Duration,
    closed: AtomicBool,
}

impl UdpRuntime {
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: Mutex::new(std::collections::HashMap::new()),
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
                    return Ok(session.clone());
                }
                Some(UdpSessionEntry::Creating(notify)) => {
                    let notify = notify.clone();
                    drop(sessions);

                    debug!(
                        "UDP session is being created, waiting: kind={:?}, client={}, target={}",
                        key.kind, key.client_addr, key.target_addr
                    );

                    notify.notified().await;
                    continue;
                }
                None => {
                    let notify = Arc::new(tokio::sync::Notify::new());
                    sessions.insert(key, UdpSessionEntry::Creating(notify.clone()));
                    break notify;
                }
            }
        };

        let created = create_udp_session(state.clone(), spec.clone()).await;

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
                sessions.insert(key, UdpSessionEntry::Ready(session.clone()));
                creating_notify.notify_waiters();

                info!(
                    "created UDP session: kind={:?}, client={}, target={}",
                    key.kind, key.client_addr, key.target_addr
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

        let mut expired = Vec::new();

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

        let mut expired_sessions = Vec::new();
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
                sessions.remove(&key);
                session.cancel.cancel();
                expired_sessions.push(session);

                debug!(
                    "UDP session expired and cancelled: kind={:?}, client={}, target={}",
                    key.kind, key.client_addr, key.target_addr
                );
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
        let mut ready_sessions = Vec::new();
        for (_, entry) in sessions.iter() {
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
        let mut handles = Vec::new();
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
                    warn!("UDP session recv task exited with JoinError: {}", e);
                }
                Err(_) => {
                    warn!(
                        "UDP session recv task did not exit within {:?}, aborting",
                        timeout
                    );
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
                    .udp_runtime
                    .fake_udp
                    .send_to(remote_src, key.client_addr, payload, state.config.fwmark)
                    .await
                {
                    Ok(sent) => {
                        trace!(
                            "UDP response sent: direction={}, kind={:?}, spoofed_src={}, client={}, payload_len={}, sent={}",
                            direction,
                            key.kind,
                            remote_src,
                            key.client_addr,
                            payload.len(),
                            sent
                        );
                    }
                    Err(e) if is_anyhow_emsgsize(&e) => {
                        warn!(
                            "UDP datagram dropped due to EMSGSIZE: direction={}, kind={:?}, spoofed_src={}, client={}, payload_len={}, relay={:?}, error={:#}",
                            direction,
                            key.kind,
                            remote_src,
                            key.client_addr,
                            payload.len(),
                            relay_addr,
                            e
                        );
                    }
                    Err(e) => {
                        warn!(
                            "failed to send UDP response: direction={}, kind={:?}, spoofed_src={}, client={}, payload_len={}, relay={:?}, error={:#}",
                            direction,
                            key.kind,
                            remote_src,
                            key.client_addr,
                            payload.len(),
                            relay_addr,
                            e
                        );
                    }
                }
            }
            UdpReplyPath::PortForward { listen_sock } => {
                match listen_sock.send_to(payload, key.client_addr).await {
                    Ok(sent) => {
                        trace!(
                            "UDP response sent: direction={}, kind={:?}, remote_src={}, client={}, payload_len={}, sent={}",
                            direction,
                            key.kind,
                            remote_src,
                            key.client_addr,
                            payload.len(),
                            sent
                        );
                    }
                    Err(e) if is_io_emsgsize(&e) => {
                        warn!(
                            "UDP datagram dropped due to EMSGSIZE: direction={}, kind={:?}, remote_src={}, client={}, payload_len={}, relay={:?}, error={}",
                            direction,
                            key.kind,
                            remote_src,
                            key.client_addr,
                            payload.len(),
                            relay_addr,
                            e
                        );
                    }
                    Err(e) => {
                        warn!(
                            "failed to send UDP response: direction={}, kind={:?}, remote_src={}, client={}, payload_len={}, relay={:?}, error={:#}",
                            direction,
                            key.kind,
                            remote_src,
                            key.client_addr,
                            payload.len(),
                            relay_addr,
                            e
                        );
                    }
                }
            }
        }
    }
}

async fn create_udp_session(state: Arc<AppState>, spec: UdpSessionSpec) -> Result<Arc<UdpSession>> {
    let key = spec.key;
    let outbound = match spec.routing {
        UdpRoutingMode::Auto => {
            if state.should_direct(key.target_addr.ip()) {
                let socket = create_direct_udp_socket(key.target_addr, state.config.fwmark)?;
                UdpOutbound::Direct { socket }
            } else {
                let up = state.upstreams.pick();
                debug!(
                    "selected upstream {} at {} (score={:.0}) for UDP {:?}",
                    up.id,
                    up.addr,
                    up.score(),
                    key
                );

                let assoc = socks5_udp_associate_for_client(
                    up.addr,
                    state.config.fwmark,
                    state.socks5_credentials(),
                )
                .await?;
                UdpOutbound::Socks5 { assoc }
            }
        }
        UdpRoutingMode::ForceSocks5 => {
            let up = state.upstreams.pick();
            debug!(
                "selected upstream {} at {} (score={:.0}) for UDP {:?}",
                up.id,
                up.addr,
                up.score(),
                key
            );

            let assoc = socks5_udp_associate_for_client(
                up.addr,
                state.config.fwmark,
                state.socks5_credentials(),
            )
            .await?;
            UdpOutbound::Socks5 { assoc }
        }
    };

    let session = Arc::new(UdpSession {
        spec,
        outbound,
        last_seen_secs: std::sync::atomic::AtomicU64::new(now_secs()),
        cancel: tokio_util::sync::CancellationToken::new(),
        recv_task: Mutex::new(None),
    });

    let (ready_tx, ready_rx) = oneshot::channel();

    let recv_handle = {
        let session = session.clone();
        let state = state.clone();

        tokio::spawn(async move {
            if let Err(e) = run_udp_session_recv_loop(session, state, ready_tx).await {
                warn!("UDP session recv loop exited with error: {:#}", e);
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
        "UDP session recv loop starting: kind={:?}, client={}, target={}",
        key.kind, key.client_addr, key.target_addr
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
    let mut buf = new_aligned_udp_buf();

    let _ = ready_tx.send(());

    loop {
        tokio::select! {
            biased;
            _ = session.cancel.cancelled() => {
                debug!(
                    "direct UDP recv loop cancelled: kind={:?}, client={}, target={}",
                    key.kind,
                    key.client_addr,
                    key.target_addr
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
    let mut buf = new_aligned_udp_buf();
    let relay_local = relay_sock.local_addr().ok();

    let _ = ready_tx.send(());

    loop {
        tokio::select! {
            biased;
            _ = session.cancel.cancelled() => {
                debug!(
                    "SOCKS5 UDP recv loop cancelled: kind={:?}, client={}, target={}",
                    key.kind,
                    key.client_addr,
                    key.target_addr
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

                if tracing::enabled!(tracing::Level::TRACE) {
                    trace!(
                        "SOCKS5 UDP raw recv: kind={:?}, client={}, target={}, relay={}, local={:?}, packet_len={}, head={}",
                        key.kind,
                        key.client_addr,
                        key.target_addr,
                        relay_addr,
                        relay_local,
                        n,
                        hex_encode(&buf[..n.min(80)])
                    );
                }

                let (remote_src, payload) = match crate::socks5::parse_socks5_udp_packet_with_fallback_src(&buf[..n], key.target_addr) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(
                            "invalid SOCKS5 UDP packet: kind={:?}, client={}, target={}, relay={}, packet_len={}, error={:#}",
                            key.kind,
                            key.client_addr,
                            key.target_addr,
                            relay_addr,
                            n,
                            e
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

        state.udp_runtime.cleanup_expired_sessions().await;
        state
            .udp_runtime
            .fake_udp
            .cleanup_expired(state.udp_runtime.timeout)
            .await;
    }
}

pub async fn run_udp_loop(
    state: Arc<AppState>,
    tproxy_udp: UdpSocket,
    cancel: CancellationToken,
) -> Result<()> {
    let tproxy_udp = TProxyUdpSocket::new(tproxy_udp);
    let mut buf = new_aligned_udp_buf();

    let mut pending_sniff: std::collections::HashMap<UdpSessionKey, PendingUdpSniff> =
        std::collections::HashMap::new();
    let mut last_pending_reap_secs = now_secs();

    loop {
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
                        warn!("failed to receive TPROXY UDP packet: {:#}", e);
                        continue;
                    }
                }
            }
        };

        let now = now_secs();
        if now.saturating_sub(last_pending_reap_secs) >= UDP_SNIFF_REAP_INTERVAL_SECS {
            last_pending_reap_secs = now;
            reap_pending_udp_sniff(state.clone(), &mut pending_sniff).await;
        }

        if packet.len == 0 {
            continue;
        }

        let payload = &buf[..packet.len];

        let spec = UdpSessionSpec::for_tproxy(packet.client_addr, packet.orig_dst);

        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("UDP tproxy loop shutting down during packet handling");
                break;
            }
            _ = handle_udp_client_payload(state.clone(), &mut pending_sniff, spec, payload) => {}
        }
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

    let mut buf = new_aligned_udp_buf();
    let mut pending_sniff: std::collections::HashMap<UdpSessionKey, PendingUdpSniff> =
        std::collections::HashMap::new();
    let mut last_pending_reap_secs = now_secs();

    loop {
        let (n, client_addr) = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("port-forward UDP {} -> {} shutting down", listen_addr, remote);
                break;
            }
            res = listen_sock.recv_from(&mut buf) => {
                res?
            }
        };

        let now = now_secs();

        if now.saturating_sub(last_pending_reap_secs) >= UDP_SNIFF_REAP_INTERVAL_SECS {
            last_pending_reap_secs = now;
            reap_pending_udp_sniff(state.clone(), &mut pending_sniff).await;
        }

        if n == 0 {
            continue;
        }

        let payload = &buf[..n];

        let spec =
            UdpSessionSpec::for_port_forward(listen_addr, client_addr, remote, listen_sock.clone());

        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!(
                    "port-forward UDP {} -> {} shutting down during packet handling",
                    listen_addr,
                    remote
                );
                break;
            }
            _ = handle_udp_client_payload(state.clone(), &mut pending_sniff, spec, payload) => {}
        }
    }

    Ok(())
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
                "UDP recv got EMSGSIZE, ignored: direction={}, kind={:?}, client={}, target={}, relay={:?}, error={}",
                direction, key.kind, key.client_addr, key.target_addr, relay_addr, e
            );

            Ok(None)
        }
        Err(e) => Err(e).with_context(|| format!("{direction} UDP recv failed")),
    }
}
