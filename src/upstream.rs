use arc_swap::ArcSwap;
use serde::Deserialize;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, Weak};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixDatagram;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::socks5::{Socks5Target, socks5_connect};
use crate::state::AppState;
use crate::util::{get_tcp_info_ext_raw, now_secs};

#[derive(Debug)]
pub struct Upstream {
    pub id: String,
    pub addr: SocketAddr,

    registry: Mutex<Vec<(Weak<()>, std::os::fd::RawFd)>>,

    tcp_score: AtomicU32,

    last_total_recv: AtomicU64,
    last_total_sent: AtomicU64,
    last_check_secs: AtomicU64,
    tcp_info_initialized: AtomicBool,
    health_failures: AtomicU32, // 连续失败次数

    quic_uplink_score: AtomicU32,
    quic_downlink_score: AtomicU32,
    quic_uplink_last_update_secs: AtomicU64,
    quic_downlink_last_update_secs: AtomicU64,
    quic_weight: AtomicU32, // 0-100，默认 70
}

impl Upstream {
    pub fn new(id: impl Into<String>, addr: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            id: id.into(),
            registry: Mutex::new(Vec::new()),
            addr,
            tcp_score: AtomicU32::new(500),
            quic_uplink_score: AtomicU32::new(500),
            quic_downlink_score: AtomicU32::new(500),
            quic_uplink_last_update_secs: AtomicU64::new(0),
            quic_downlink_last_update_secs: AtomicU64::new(0),
            last_total_recv: AtomicU64::new(0),
            last_total_sent: AtomicU64::new(0),
            last_check_secs: AtomicU64::new(0),
            tcp_info_initialized: AtomicBool::new(false),
            health_failures: AtomicU32::new(0),
            quic_weight: AtomicU32::new(70),
        })
    }

    pub fn set_quic_weight(&self, w: u32) {
        self.quic_weight.store(w.clamp(0, 100), Ordering::Relaxed);
    }

    pub fn track(&self, fd: std::os::fd::RawFd) -> Arc<()> {
        let token = Arc::new(());
        let weak = Arc::downgrade(&token);
        self.registry
            .lock()
            .expect("bad register lock")
            .push((weak, fd));
        token
    }

    pub async fn run_score_task(self: Arc<Self>, cancel: CancellationToken) {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {},
            }
            let (recv, sent, alive) = {
                let mut reg = self.registry.lock().expect("bad registry lock");
                reg.retain(|(w, _)| w.strong_count() > 0);
                let mut r = 0u64;
                let mut s = 0u64;
                let mut n = 0usize;
                for (_, fd) in reg.iter() {
                    if let Some(info) = get_tcp_info_ext_raw(*fd) {
                        r += info.tcpi_bytes_received;
                        s += info.tcpi_bytes_acked;
                        n += 1;
                    }
                }
                (r, s, n)
            };

            if alive == 0 {
                continue;
            }

            let now = now_secs();
            let prev_recv = self.last_total_recv.swap(recv, Ordering::Relaxed);
            let prev_sent = self.last_total_sent.swap(sent, Ordering::Relaxed);
            let prev_secs = self.last_check_secs.swap(now, Ordering::Relaxed);

            if !self.tcp_info_initialized.swap(true, Ordering::Relaxed) {
                continue;
            }

            let delta_recv = recv.saturating_sub(prev_recv);
            let delta_sent = sent.saturating_sub(prev_sent);
            let delta_bytes = delta_recv + delta_sent;
            let delta_secs = now.saturating_sub(prev_secs).max(1);

            if let Some(raw) = calc_throughput_score(delta_bytes, Duration::from_secs(delta_secs)) {
                let old = self.tcp_score.load(Ordering::Relaxed);
                // 50/50，历史与新数据同等权重
                let blended = (old * 5 + raw * 5) / 10;
                let speed_mibps = delta_bytes as f64 / 1024.0 / 1024.0 / delta_secs as f64;

                self.tcp_score.store(blended, Ordering::Relaxed);
                debug!(
                    "upstream aggregate score: id={}, alive={}, delta_mb={:.2}, speed={:.2}MiB/s, score={}",
                    self.id,
                    alive,
                    delta_bytes as f64 / 1024.0 / 1024.0,
                    speed_mibps,
                    blended,
                );
            }
        }
    }

    pub fn score(&self) -> u32 {
        let tcp = self.tcp_score.load(Ordering::Relaxed);
        let uplink = self.quic_uplink_score.load(Ordering::Relaxed);
        let downlink = self.quic_downlink_score.load(Ordering::Relaxed);

        let uplink_valid = self.quic_uplink_last_update_secs.load(Ordering::Relaxed) != 0;
        let downlink_valid = self.quic_downlink_last_update_secs.load(Ordering::Relaxed) != 0;

        let quic = match (uplink_valid, downlink_valid) {
            (true, true) => (uplink + downlink) / 2,
            (true, false) => uplink,
            (false, true) => downlink,
            (false, false) => 500,
        };

        let tcp_valid = tcp != 500;
        let quic_valid = uplink_valid || downlink_valid;
        let qw = self.quic_weight.load(Ordering::Relaxed);
        let tw = 100 - qw;

        match (tcp_valid, quic_valid) {
            (true, true) => (tcp * tw + quic * qw) / 100,
            (false, true) => quic,
            (true, false) => tcp,
            (false, false) => 500,
        }
    }

    /// 更新上行 QUIC 分数（冷却 5 秒）
    pub fn update_uplink_score(&self, raw: Option<u32>) {
        self.update_link_score(
            raw,
            &self.quic_uplink_score,
            &self.quic_uplink_last_update_secs,
        );
    }

    /// 更新下行 QUIC 分数（冷却 5 秒）
    pub fn update_downlink_score(&self, raw: Option<u32>) {
        self.update_link_score(
            raw,
            &self.quic_downlink_score,
            &self.quic_downlink_last_update_secs,
        );
    }

    fn update_link_score(&self, raw: Option<u32>, score: &AtomicU32, last_update: &AtomicU64) {
        let Some(raw) = raw else { return };
        let raw = raw.clamp(0, 1000);

        let now = now_secs();
        let last = last_update.load(Ordering::Relaxed);
        if now.saturating_sub(last) < 5 {
            return;
        }

        if last_update
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            let old = score.load(Ordering::Relaxed);
            let blended = (old * 3 + raw * 7) / 10;
            score.store(blended, Ordering::Relaxed);
        }
    }

    pub fn penalize(&self) {
        self.tcp_score.store(100, Ordering::Relaxed);
        self.quic_uplink_score.store(100, Ordering::Relaxed);
        self.quic_downlink_score.store(100, Ordering::Relaxed);
        let now = now_secs();
        self.quic_uplink_last_update_secs
            .store(now, Ordering::Relaxed);
        self.quic_downlink_last_update_secs
            .store(now, Ordering::Relaxed);
    }
}

pub struct UpstreamSet {
    items: Vec<Arc<Upstream>>,
    single: Option<Arc<Upstream>>,
    current: Mutex<Option<String>>,
    tolerance: u32,
}

impl UpstreamSet {
    pub fn new(items: Vec<Arc<Upstream>>, tolerance: u32, quic_weight: u32) -> Self {
        assert!(!items.is_empty());
        let single = if items.len() == 1 {
            Some(Arc::clone(&items[0]))
        } else {
            None
        };

        for up in &items {
            up.set_quic_weight(quic_weight);
        }

        Self {
            items,
            single,
            current: Mutex::new(None),
            tolerance,
        }
    }

    pub fn pick(&self) -> Arc<Upstream> {
        if let Some(ref up) = self.single {
            debug!("pick: single upstream={}, score={}", up.id, up.score());
            return Arc::clone(up);
        }

        // 没有排除规则，直接对全量 items 做平方加权随机
        self.pick_weighted(&self.items, None)
            .expect("UpstreamSet::items is non-empty by construction")
    }

    /// 排除指定 id 后加权随机选。
    /// 只剩一个或没有时返回 None。
    pub fn pick_excluding(&self, exclude_id: &str) -> Option<Arc<Upstream>> {
        // 单上游场景直接 None，没别的可选
        if self.single.is_some() {
            return None;
        }

        let candidates: Vec<_> = self
            .items
            .iter()
            .filter(|u| u.id != exclude_id)
            .cloned()
            .collect();

        if candidates.is_empty() {
            return None;
        }

        self.pick_weighted(&candidates, Some(exclude_id))
    }

    /// 公共的平方加权随机选择逻辑，带 tolerance 切换门槛。
    /// `exclude_ctx` 仅用于 debug 日志区分调用来源。
    fn pick_weighted(
        &self,
        items: &[Arc<Upstream>],
        exclude_ctx: Option<&str>,
    ) -> Option<Arc<Upstream>> {
        if items.is_empty() {
            return None;
        }

        // 1. 候选里的最高分
        let best = items.iter().max_by_key(|u| u.score())?;
        let best_score = best.score();

        // 2. 检查 sticky：仅当 tolerance > 0 时启用
        if self.tolerance > 0 {
            let sticky = {
                let guard = self.current.lock().expect("bad current lock");
                guard
                    .as_ref()
                    .and_then(|id| items.iter().find(|u| u.id == *id).cloned())
            };

            if let Some(ref cur) = sticky {
                let cur_score = cur.score();
                if best.id != cur.id && best_score > cur_score + self.tolerance {
                    debug!(
                        "pick: switch upstream {} (score={}) -> {} (score={}), tolerance={}",
                        cur.id, cur_score, best.id, best_score, self.tolerance
                    );
                    // 继续往下走，重新选
                } else {
                    debug!(
                        "pick: sticky upstream={}, score={}, best={} (score={}), tolerance={}",
                        cur.id, cur_score, best.id, best_score, self.tolerance
                    );
                    return Some(Arc::clone(cur));
                }
            }
        }

        // 3. 重新选：平方加权随机
        let mut score_details = Vec::with_capacity(items.len());
        let weights: Vec<u64> = items
            .iter()
            .map(|u| {
                let s = u.score();
                score_details.push(format!("{}={}", u.id, s));
                (s as u64) * (s as u64) // 平方加权：高分优势放大
            })
            .collect();
        let total: u64 = weights.iter().sum();

        if let Some(id) = exclude_ctx {
            debug!(
                "pick: {} upstreams, total_weight={}, [{}], excluding={}",
                items.len(),
                total,
                score_details.join(", "),
                id,
            );
        } else {
            debug!(
                "pick: {} upstreams, total_weight={}, [{}]",
                items.len(),
                total,
                score_details.join(", "),
            );
        }

        let chosen = if total == 0 {
            let idx = fastrand::usize(..items.len());
            debug!("pick: total=0, random pick upstream={}", items[idx].id);
            Arc::clone(&items[idx])
        } else {
            let mut r = fastrand::u64(..total);
            let pick_r = r;
            let mut picked = None;
            for (i, w) in weights.iter().enumerate() {
                if r < *w {
                    debug!(
                        "pick: weighted pick upstream={}, raw_score={}, weight={}, r={}/{}",
                        items[i].id,
                        items[i].score(),
                        w,
                        pick_r,
                        total
                    );
                    picked = Some(Arc::clone(&items[i]));
                    break;
                }
                r -= w;
            }
            picked.unwrap_or_else(|| {
                debug!("pick: fallback to first upstream={}", items[0].id);
                Arc::clone(&items[0])
            })
        };

        // 4. 更新 current
        *self.current.lock().expect("bad current lock") = Some(chosen.id.clone());
        Some(chosen)
    }

    pub fn find_by_id(&self, id: &str) -> Option<Arc<Upstream>> {
        self.items.iter().find(|u| u.id == id).cloned()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<Upstream>> + '_ {
        self.items.iter()
    }
}

/// 基于吞吐量的质量分（连接结束时用）。
pub fn calc_throughput_score(total_bytes: u64, duration: Duration) -> Option<u32> {
    // 2 秒内少于 16KB 视为 idle/保活噪声，不更新分数
    if total_bytes < 1024 * 16 {
        return None;
    }

    let secs = duration.as_secs_f64();
    if secs <= 0.0 {
        return None;
    }

    let bps = total_bytes as f64 / secs;
    let mib_per_sec = bps / 1024.0 / 1024.0;

    let score = if mib_per_sec >= 50.0 {
        1000
    } else if mib_per_sec >= 10.0 {
        800 + ((mib_per_sec - 10.0) / 40.0 * 200.0) as u32
    } else if mib_per_sec >= 5.0 {
        600 + ((mib_per_sec - 5.0) / 5.0 * 200.0) as u32
    } else if mib_per_sec >= 1.0 {
        300 + ((mib_per_sec - 1.0) / 4.0 * 300.0) as u32
    } else if mib_per_sec >= 0.1 {
        100 + ((mib_per_sec - 0.1) / 0.9 * 200.0) as u32
    } else {
        (mib_per_sec / 0.1 * 100.0) as u32
    };
    Some(score.clamp(0, 1000))
}

#[derive(Debug, Deserialize)]
pub struct ShadowQuicReport {
    pub upstream_id: String,
    pub peer: String,
    pub rtt_ms: f64,
    pub loss_rate: f64,
    pub mtu: u16,
    #[serde(default)] // 兼容没有 link 的旧报告
    pub link: Option<String>,
}

pub async fn run_upstream_stats_listener(
    state_swap: Arc<ArcSwap<AppState>>,
    cancel: CancellationToken,
) {
    const PATH: &str = "/tmp/xtp-rs-report.sock";

    // 启动时清理可能存在的旧文件（仅进程启动时执行一次）
    let _ = tokio::fs::remove_file(PATH).await;

    let sock = match UnixDatagram::bind(PATH) {
        Ok(s) => s,
        Err(e) => {
            error!("stats listener bind failed at {}: {}", PATH, e);
            return;
        }
    };

    #[cfg(target_os = "linux")]
    if let Err(e) = std::fs::set_permissions(PATH, std::fs::Permissions::from_mode(0o777)) {
        error!("stats listener chmod failed: {}", e);
        // chmod 失败但 socket 已创建，清理掉避免残留
        let _ = tokio::fs::remove_file(PATH).await;
        return;
    }

    info!("upstream stats listener bound to {}", PATH);

    let mut buf = vec![0u8; 2048];

    loop {
        tokio::select! {
           biased;
           _ = cancel.cancelled() => {
               info!("upstream stats listener shutting down");
               break;
           }
           res = sock.recv_from(&mut buf) => {
               match res {
                   Ok((n, _)) => {
                       let rep: ShadowQuicReport = match serde_json::from_slice(&buf[..n]) {
                           Ok(r) => r,
                           Err(e) => {
                               trace!("upstream stats JSON parse failed: {}", e);
                               continue;
                           }
                       };

                       trace!(
                           "upstream stats: id={} peer={}, rtt={}ms loss={:.2}% mtu={} link={:?}",
                           rep.upstream_id,
                           rep.peer,
                           rep.rtt_ms,
                           rep.loss_rate * 100.0,
                           rep.mtu,
                           rep.link,
                       );

                       let state = state_swap.load();

                       if state.config.disable_upstream_score {
                           trace!("upstream score disabled, ignoring stats report");
                           continue;
                       }

                        if let Some(up) = state.upstreams.find_by_id(&rep.upstream_id) {
                            let score = calc_quic_score(rep.rtt_ms, rep.loss_rate, rep.mtu);
                            match rep.link.as_deref() {
                                Some("downlink") => up.update_downlink_score(score),
                                _ => up.update_uplink_score(score), // 默认按上行处理（兼容旧报告）
                            }
                        }
                   }
                   Err(e) => {
                       error!("stats recv error: {}", e);
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => {
                                info!("upstream stats listener shutting down");
                                break;
                            }
                            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                        }
                   }
                }
            }
        }
    }

    let _ = tokio::fs::remove_file(PATH).await;
    info!("upstream stats listener exited, socket removed");
}

fn calc_quic_score(rtt_ms: f64, loss_rate: f64, mtu: u16) -> Option<u32> {
    if !rtt_ms.is_finite() || rtt_ms < 0.0 || !loss_rate.is_finite() || loss_rate < 0.0 {
        return None;
    }

    let base = 1000u32;

    let loss_penalty = match (loss_rate * 100.0) as u32 {
        0 => 0,
        1..=2 => 60,
        3..=5 => 200,
        6..=10 => 500,
        11..=20 => 750,
        _ => 900,
    };

    let rtt_penalty = match rtt_ms as u32 {
        0..=80 => 0,
        81..=150 => 40,
        151..=250 => 100,
        251..=400 => 180,
        _ => 300,
    };

    let mtu_penalty = match mtu {
        1400..=u16::MAX => 0,
        1300..=1399 => 60,
        1280..=1299 => 120,
        1200..=1279 => 250,
        _ => 450,
    };

    Some(
        base.saturating_sub(loss_penalty)
            .saturating_sub(rtt_penalty)
            .saturating_sub(mtu_penalty)
            .max(50),
    )
}

async fn check_upstream_health(
    up: &Upstream,
    fwmark: u32,
    creds: Option<(&str, &str)>,
    check_url: &str,
    timeout_secs: u64,
) -> bool {
    let target = Socks5Target::Domain(check_url, 80);

    let Ok(Ok(mut stream)) = timeout(
        Duration::from_secs(timeout_secs),
        socks5_connect(target, up.addr, fwmark, creds),
    )
    .await
    else {
        return false;
    };

    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        check_url
    );

    if stream.write_all(req.as_bytes()).await.is_err() {
        return false;
    }

    let mut buf = [0u8; 1024];
    let n = match timeout(Duration::from_secs(timeout_secs), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return false,
    };

    n >= 8 && buf[..n].windows(8).any(|w| w == b"HTTP/1.1")
}

pub async fn run_health_check_task(state: Arc<AppState>, cancel: CancellationToken) {
    let interval_secs = state.config.health_check_interval_secs;
    info!("health check task started, interval={}s", interval_secs);
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("health check task shutting down");
                break;
            }
            _ = interval.tick() => {},
        }

        let c = &state.config;
        let (timeout_secs, fail_threshold, check_url, fwmark, creds) = (
            c.health_check_timeout_secs,
            c.health_check_fail_threshold,
            c.health_check_url.clone(),
            c.fwmark,
            state
                .socks5_credentials()
                .map(|(u, p)| (u.to_string(), p.to_string())),
        );

        // 逐个检查，每检查一个前都先看 cancel 是否已触发
        'upstreams: for up in state.upstreams.iter() {
            let alive = tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    info!("health check task shutting down");
                    break 'upstreams;
                }
                r = check_upstream_health(
                    up,
                    fwmark,
                    creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
                    &check_url,
                    timeout_secs,
                ) => r,
            };

            if alive {
                let failures = up.health_failures.swap(0, Ordering::Relaxed);
                if failures > 0 {
                    debug!(
                        "upstream {} health check ok (recovered from {} failures)",
                        up.id, failures
                    );
                } else {
                    debug!("upstream {} health check ok", up.id);
                }
                if failures >= fail_threshold {
                    up.tcp_score.store(300, Ordering::Relaxed);
                    info!("upstream {} health recovered, score reset to 300", up.id);
                }
            } else {
                let f = up.health_failures.fetch_add(1, Ordering::Relaxed) + 1;
                if f == fail_threshold {
                    up.penalize();
                    warn!(
                        "upstream {} health check dead, penalized ({}/{})",
                        up.id, f, fail_threshold
                    );
                } else if f > fail_threshold {
                    debug!(
                        "upstream {} health check still dead ({}/{})",
                        up.id, f, fail_threshold
                    );
                } else {
                    debug!(
                        "upstream {} health check failed ({}/{})",
                        up.id, f, fail_threshold
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- calc_throughput_score ----------
    #[test]
    fn score_none_on_low_bytes() {
        assert_eq!(calc_throughput_score(1000, Duration::from_secs(2)), None);
    }

    #[test]
    fn score_none_on_zero_duration() {
        assert_eq!(calc_throughput_score(100_000, Duration::ZERO), None);
    }

    #[test]
    fn score_around_1000_for_50mib() {
        let bytes = 50 * 1024 * 1024;
        let dur = Duration::from_secs(1);
        let score = calc_throughput_score(bytes, dur).unwrap();
        assert!(score >= 1000); // 50 MiB/s -> max
    }

    #[test]
    fn score_around_800_for_10mib() {
        let bytes = 10 * 1024 * 1024;
        let dur = Duration::from_secs(1);
        let score = calc_throughput_score(bytes, dur).unwrap();
        assert!((800..1000).contains(&score));
    }

    #[test]
    fn score_never_exceeds_1000() {
        let bytes = 500 * 1024 * 1024;
        let dur = Duration::from_secs(1);
        let score = calc_throughput_score(bytes, dur).unwrap();
        assert_eq!(score, 1000);
    }

    // ---------- calc_quic_score ----------
    #[test]
    fn quic_score_rejects_nan() {
        assert_eq!(calc_quic_score(f64::NAN, 0.0, 1450), None);
    }

    #[test]
    fn quic_score_perfect() {
        let score = calc_quic_score(10.0, 0.0, 1450).unwrap();
        assert_eq!(score, 1000);
    }

    #[test]
    fn quic_score_high_loss_penalty() {
        let score = calc_quic_score(50.0, 0.15, 1450).unwrap();
        assert!(score < 500, "high loss should reduce score significantly");
    }

    #[test]
    fn quic_score_low_mtu_penalty() {
        let score = calc_quic_score(10.0, 0.0, 800).unwrap();
        assert!(score < 600);
    }

    #[test]
    fn quic_score_minimum_50() {
        let score = calc_quic_score(999.0, 0.5, 500).unwrap();
        assert_eq!(score, 50); // worst case clamped
    }

    // ---------- Upstream::score ----------
    fn make_upstream(id: &str) -> Arc<Upstream> {
        Upstream::new(id, "127.0.0.1:1080".parse().unwrap())
    }

    /// 直接设置 QUIC 分数并标记为已更新（绕过 3:7 平滑混合）
    fn set_quic_uplink(up: &Upstream, score: u32) {
        up.quic_uplink_score.store(score, Ordering::Relaxed);
        up.quic_uplink_last_update_secs.store(1, Ordering::Relaxed);
    }

    fn set_quic_downlink(up: &Upstream, score: u32) {
        up.quic_downlink_score.store(score, Ordering::Relaxed);
        up.quic_downlink_last_update_secs
            .store(1, Ordering::Relaxed);
    }

    #[test]
    fn score_initial_500() {
        let up = make_upstream("a");
        assert_eq!(up.score(), 500);
    }

    #[test]
    fn score_uses_downlink_when_uplink_missing() {
        let up = make_upstream("c");
        up.tcp_score.store(600, Ordering::Relaxed);
        set_quic_downlink(&up, 700);
        // uplink never updated => invalid, quic = downlink = 700
        let expected = (600 * 30 + 700 * 70) / 100; // 670
        assert_eq!(up.score(), expected);
    }

    #[test]
    fn score_averages_both_links() {
        let up = make_upstream("d");
        up.tcp_score.store(600, Ordering::Relaxed);
        set_quic_uplink(&up, 800);
        set_quic_downlink(&up, 600);
        let expected = (600 * 30 + 700 * 70) / 100; // 670
        assert_eq!(up.score(), expected);
    }

    #[test]
    fn penalize_sets_all_to_100() {
        let up = make_upstream("e");
        up.penalize();
        assert_eq!(up.tcp_score.load(Ordering::Relaxed), 100);
        assert_eq!(up.quic_uplink_score.load(Ordering::Relaxed), 100);
        assert_eq!(up.quic_downlink_score.load(Ordering::Relaxed), 100);
    }

    // ---------- UpstreamSet ----------
    fn upstream(id: &str) -> Arc<Upstream> {
        Upstream::new(id, "127.0.0.1:1080".parse().unwrap())
    }

    fn upstream_set(ids: &[&str], tolerance: u32) -> UpstreamSet {
        let items: Vec<_> = ids.iter().map(|id| upstream(id)).collect();
        UpstreamSet::new(items, tolerance, 70)
    }

    #[test]
    fn single_upstream_always_picked() {
        let set = upstream_set(&["a"], 0);
        let picked = set.pick();
        assert_eq!(picked.id, "a");
    }

    #[test]
    fn pick_excluding_single_returns_none() {
        let set = upstream_set(&["a"], 0);
        assert!(set.pick_excluding("a").is_none());
    }

    #[test]
    fn pick_excluding_removes_matching() {
        let set = upstream_set(&["a", "b"], 0);
        let picked = set.pick_excluding("a").unwrap();
        assert_eq!(picked.id, "b");
    }

    #[test]
    fn tolerance_sticky_when_best_not_exceeding() {
        let set = upstream_set(&["a", "b"], 50);
        for u in set.iter() {
            u.tcp_score.store(500, Ordering::Relaxed);
            set_quic_uplink(u, 500);
        }
        // sticky to "a"
        {
            let mut cur = set.current.lock().unwrap();
            *cur = Some("a".to_string());
        }
        let picked = set.pick();
        assert_eq!(picked.id, "a", "should stick because scores equal");
    }

    #[test]
    fn tolerance_switches_when_best_exceeds() {
        fastrand::seed(42); // 固定随机种子，避免偶然选中低分 upstream
        let set = upstream_set(&["a", "b"], 100);
        // sticky to "a"
        {
            let mut cur = set.current.lock().unwrap();
            *cur = Some("a".to_string());
        }
        // "a" at 500
        for u in set.iter() {
            u.tcp_score.store(500, Ordering::Relaxed);
            set_quic_uplink(u, 500);
        }
        // "b" quic=700 => score=(500*3+700*7)/10=640, diff=140 > 100
        let up_b = set.find_by_id("b").unwrap();
        set_quic_uplink(&up_b, 700);
        let picked = set.pick();
        assert_eq!(picked.id, "b");
    }

    #[test]
    fn score_blends_tcp_and_quic() {
        let up = make_upstream("b");
        up.tcp_score.store(600, Ordering::Relaxed);
        set_quic_uplink(&up, 800);
        // 默认 qw=70, tw=30
        let expected = (600 * 30 + 800 * 70) / 100; // 740
        assert_eq!(up.score(), expected);
    }

    #[test]
    fn score_respects_custom_quic_weight() {
        let up = make_upstream("f");
        up.set_quic_weight(50); // 5:5
        up.tcp_score.store(600, Ordering::Relaxed);
        set_quic_uplink(&up, 800);
        let expected = (600 * 50 + 800 * 50) / 100; // 700
        assert_eq!(up.score(), expected);
    }
}
