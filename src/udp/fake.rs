use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, trace};

use crate::socket_factory::create_fake_udp_socket;
use crate::util::now_secs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FakeUdpKey {
    pub(crate) src_addr: SocketAddr,
    pub(crate) fwmark: u32,
}

pub(crate) struct FakeUdpEntry {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) last_used_secs: AtomicU64,
}

pub(crate) struct FakeUdpManager {
    sockets: Mutex<HashMap<FakeUdpKey, Arc<FakeUdpEntry>>>,
    closed: AtomicBool,
}

impl FakeUdpManager {
    pub(crate) fn new() -> Self {
        Self {
            sockets: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) async fn get_or_create(
        &self,
        src_addr: SocketAddr,
        fwmark: u32,
    ) -> Result<Arc<UdpSocket>> {
        if self.closed.load(Ordering::SeqCst) {
            bail!("fake UDP manager is closed");
        }

        let key = FakeUdpKey { src_addr, fwmark };
        let now = now_secs();

        {
            let sockets = self.sockets.lock().await;

            if self.closed.load(Ordering::SeqCst) {
                bail!("fake UDP manager is closed");
            }

            if let Some(entry) = sockets.get(&key) {
                entry.last_used_secs.store(now, Ordering::Relaxed);
                return Ok(entry.socket.clone());
            }
        }

        let socket = Arc::new(create_fake_udp_socket(src_addr, fwmark)?);
        let entry = Arc::new(FakeUdpEntry {
            socket: socket.clone(),
            last_used_secs: AtomicU64::new(now),
        });

        let mut sockets = self.sockets.lock().await;

        if self.closed.load(Ordering::SeqCst) {
            bail!("fake UDP manager is closed");
        }

        if let Some(existing) = sockets.get(&key) {
            existing.last_used_secs.store(now, Ordering::Relaxed);
            return Ok(existing.socket.clone());
        }

        sockets.insert(key, entry);

        debug!(spoofed_src = %src_addr, fwmark = fwmark, "created fake UDP socket");

        Ok(socket)
    }

    pub(crate) async fn send_to(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: &[u8],
        fwmark: u32,
    ) -> Result<usize> {
        let socket = self.get_or_create(src_addr, fwmark).await?;

        trace!(
            spoofed_src = %src_addr,
            dst = %dst_addr,
            payload_len = payload.len(),
            "fake UDP send"
        );

        socket
            .send_to(payload, dst_addr)
            .await
            .context("fake UDP send_to failed")
    }

    pub(crate) async fn cleanup_expired(&self, timeout: Duration) {
        let now = now_secs();
        let timeout_secs = timeout.as_secs();

        let mut sockets = self.sockets.lock().await;

        sockets.retain(|key, entry| {
            let last = entry.last_used_secs.load(Ordering::Relaxed);
            let alive = now.saturating_sub(last) < timeout_secs;

            if !alive {
                debug!(
                    spoofed_src = %key.src_addr,
                    fwmark = key.fwmark,
                    "fake UDP socket expired"
                );
            }

            alive
        });
    }

    pub(crate) async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let mut sockets = self.sockets.lock().await;
        sockets.clear();
    }
}
