use anyhow::{Context, Result, bail};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
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
    sockets: DashMap<FakeUdpKey, Arc<FakeUdpEntry>>,
    closed: AtomicBool,
}

impl FakeUdpManager {
    pub(crate) fn new() -> Self {
        Self {
            sockets: DashMap::new(),
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

        // 快速路径：已存在，直接返回
        if let Some(entry) = self.sockets.get(&key) {
            entry.last_used_secs.store(now, Ordering::Relaxed);
            return Ok(entry.socket.clone());
        }

        // 慢路径：创建 socket（锁外，不阻塞其他 key）
        let socket = Arc::new(create_fake_udp_socket(src_addr, fwmark)?);
        let entry = Arc::new(FakeUdpEntry {
            socket: socket.clone(),
            last_used_secs: AtomicU64::new(now),
        });

        // 创建 socket 期间可能已经 close，再检查一次
        if self.closed.load(Ordering::SeqCst) {
            bail!("fake UDP manager is closed");
        }

        // entry().or_insert() 分片级原子：同 key 只有一个 task 插入成功，
        // 其他 task 拿到已有 entry。多余 socket 随 drop 自动关闭。
        let existing = self.sockets.entry(key).or_insert(entry);
        existing.last_used_secs.store(now, Ordering::Relaxed);

        debug!(spoofed_src = %src_addr, fwmark = fwmark, "created fake UDP socket");

        Ok(existing.socket.clone())
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

        self.sockets.retain(|key, entry| {
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
        self.sockets.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket as StdUdpSocket;

    // 绑一个真实的 localhost socket（不设 SO_MARK），用于测试 DashMap 逻辑
    fn dummy_socket() -> Arc<UdpSocket> {
        let std = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        std.set_nonblocking(true).unwrap();
        Arc::new(UdpSocket::from_std(std).unwrap())
    }

    fn insert_entry(mgr: &FakeUdpManager, src_addr: SocketAddr, fwmark: u32) {
        let key = FakeUdpKey { src_addr, fwmark };
        let entry = Arc::new(FakeUdpEntry {
            socket: dummy_socket(),
            last_used_secs: AtomicU64::new(now_secs()),
        });
        mgr.sockets.insert(key, entry);
    }

    #[tokio::test]
    async fn same_key_returns_same_socket() {
        let mgr = FakeUdpManager::new();
        let addr = "127.0.0.1:10000".parse().unwrap();

        insert_entry(&mgr, addr, 0);
        let s1 = mgr.sockets.get(&FakeUdpKey { src_addr: addr, fwmark: 0 }).unwrap().socket.clone();
        let s2 = mgr.sockets.get(&FakeUdpKey { src_addr: addr, fwmark: 0 }).unwrap().socket.clone();

        assert!(Arc::ptr_eq(&s1, &s2));
    }

    #[tokio::test]
    async fn different_keys_return_different_sockets() {
        let mgr = FakeUdpManager::new();
        let a1 = "127.0.0.1:10001".parse().unwrap();
        let a2 = "127.0.0.1:10002".parse().unwrap();

        insert_entry(&mgr, a1, 0);
        insert_entry(&mgr, a2, 0);

        let s1 = mgr.sockets.get(&FakeUdpKey { src_addr: a1, fwmark: 0 }).unwrap().socket.clone();
        let s2 = mgr.sockets.get(&FakeUdpKey { src_addr: a2, fwmark: 0 }).unwrap().socket.clone();

        assert!(!Arc::ptr_eq(&s1, &s2));
    }

    #[tokio::test]
    async fn entry_or_insert_reuses_existing() {
        let mgr = FakeUdpManager::new();
        let key = FakeUdpKey {
            src_addr: "127.0.0.1:10003".parse().unwrap(),
            fwmark: 0,
        };

        let e1 = Arc::new(FakeUdpEntry {
            socket: dummy_socket(),
            last_used_secs: AtomicU64::new(now_secs()),
        });
        let e2 = Arc::new(FakeUdpEntry {
            socket: dummy_socket(),
            last_used_secs: AtomicU64::new(now_secs()),
        });

        let socket1 = mgr.sockets.entry(key).or_insert(e1).socket.clone();
        let socket2 = mgr.sockets.entry(key).or_insert(e2).socket.clone();

        // 第二个 or_insert 应复用已有的 entry
        assert!(Arc::ptr_eq(&socket1, &socket2));
    }

    #[tokio::test]
    async fn cleanup_keeps_fresh_entries() {
        let mgr = FakeUdpManager::new();
        let addr = "127.0.0.1:10004".parse().unwrap();

        insert_entry(&mgr, addr, 0);
        let socket = mgr.sockets.get(&FakeUdpKey { src_addr: addr, fwmark: 0 }).unwrap().socket.clone();

        // 同步版 retain：timeout 600s，刚插入的 entry 不会被清理
        let now = now_secs();
        let timeout_secs = 600u64;
        mgr.sockets.retain(|_, entry| {
            let last = entry.last_used_secs.load(Ordering::Relaxed);
            now.saturating_sub(last) < timeout_secs
        });

        let s2 = mgr.sockets.get(&FakeUdpKey { src_addr: addr, fwmark: 0 }).unwrap().socket.clone();
        assert!(Arc::ptr_eq(&socket, &s2));
    }

    #[tokio::test]
    async fn cleanup_removes_expired_entries() {
        let mgr = FakeUdpManager::new();
        let addr = "127.0.0.1:10005".parse().unwrap();
        let key = FakeUdpKey { src_addr: addr, fwmark: 0 };

        insert_entry(&mgr, addr, 0);
        let old_socket = mgr.sockets.get(&key).unwrap().socket.clone();

        // 把 last_used_secs 改到很久以前，模拟过期
        mgr.sockets.get(&key).unwrap().last_used_secs.store(1, Ordering::Relaxed);

        let now = now_secs();
        let timeout_secs = 10u64;
        mgr.sockets.retain(|_, entry| {
            let last = entry.last_used_secs.load(Ordering::Relaxed);
            now.saturating_sub(last) < timeout_secs
        });

        // 过期 entry 已被清除
        assert!(!mgr.sockets.contains_key(&key));

        // 重新插入，不应与旧 socket 相同
        insert_entry(&mgr, addr, 0);
        let new_socket = mgr.sockets.get(&key).unwrap().socket.clone();
        assert!(!Arc::ptr_eq(&old_socket, &new_socket));
    }

    #[tokio::test]
    async fn close_clears_all() {
        let mgr = FakeUdpManager::new();
        let addr = "127.0.0.1:10006".parse().unwrap();

        insert_entry(&mgr, addr, 0);
        assert_eq!(mgr.sockets.len(), 1);

        mgr.close().await;

        assert!(mgr.closed.load(Ordering::SeqCst));
        assert!(mgr.sockets.is_empty());
    }

    #[tokio::test]
    async fn close_sets_closed_flag() {
        let mgr = FakeUdpManager::new();
        assert!(!mgr.closed.load(Ordering::SeqCst));

        mgr.close().await;

        assert!(mgr.closed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn get_or_create_fails_after_close() {
        let mgr = FakeUdpManager::new();
        let addr = "127.0.0.1:10007".parse().unwrap();

        mgr.close().await;

        let result = mgr.get_or_create(addr, 0).await;
        assert!(result.is_err());
    }
}
