use anyhow::{Result, bail};
use arc_swap::ArcSwap;
use portable_atomic::AtomicU64;
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, Weak};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixDatagram;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::socks5::{Socks5Target, socks5_connect};
use crate::state::AppState;
use crate::util::{get_tcp_info_ext_raw, now_secs};

/// TCP 分数默认值（未通过流量更新前使用）
/// 略高于惩罚分(100)，避免卡住连接保持高分，同时给新 upstream 一个较低起点
const DEFAULT_SCORE: u32 = 150;

#[derive(Debug)]
pub struct Upstream {
    pub id: String,
    pub addr: SocketAddr,
    pub groups: Vec<String>,
    pub gain: f64,

    registry: std::sync::Mutex<Vec<(Weak<()>, std::os::fd::RawFd)>>,

    tcp_score: AtomicU32,
    tcp_score_initialized: AtomicBool,

    last_total_recv: AtomicU64,
    last_total_sent: AtomicU64,
    last_check_secs: AtomicU64,
    tcp_info_initialized: AtomicBool,
    health_failures: AtomicU32, // 连续失败次数

    quic_uplink_score: AtomicU32,
    quic_downlink_score: AtomicU32,
    quic_uplink_last_update_secs: AtomicU64,
    quic_downlink_last_update_secs: AtomicU64,
    quic_weight: AtomicU32, // 0-100，默认 40
}

impl Upstream {
    pub fn new(
        id: impl Into<String>,
        addr: SocketAddr,
        groups: Vec<String>,
        gain: f64,
    ) -> Arc<Self> {
        Arc::new(Self {
            id: id.into(),
            registry: std::sync::Mutex::new(Vec::new()),
            addr,
            groups,
            gain,
            tcp_score: AtomicU32::new(DEFAULT_SCORE),
            tcp_score_initialized: AtomicBool::new(false),
            quic_uplink_score: AtomicU32::new(DEFAULT_SCORE),
            quic_downlink_score: AtomicU32::new(DEFAULT_SCORE),
            quic_uplink_last_update_secs: AtomicU64::new(0),
            quic_downlink_last_update_secs: AtomicU64::new(0),
            last_total_recv: AtomicU64::new(0),
            last_total_sent: AtomicU64::new(0),
            last_check_secs: AtomicU64::new(0),
            tcp_info_initialized: AtomicBool::new(false),
            health_failures: AtomicU32::new(0),
            quic_weight: AtomicU32::new(40),
        })
    }

    pub fn set_quic_weight(&self, w: u32) {
        self.quic_weight.store(w.clamp(0, 100), Ordering::Relaxed);
    }

    fn lock_registry(&self) -> std::sync::MutexGuard<'_, Vec<(Weak<()>, std::os::fd::RawFd)>> {
        self.registry.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn track(&self, fd: std::os::fd::RawFd) -> Arc<()> {
        let token = Arc::new(());
        let weak = Arc::downgrade(&token);
        self.lock_registry().push((weak, fd));
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
            // 1. 锁内：清理失效条目并收集快照
            let entries: Vec<_> = {
                let mut reg = self.lock_registry();
                let mut entries = Vec::with_capacity(reg.len());
                reg.retain(|(weak, fd)| {
                    if let Some(token) = weak.upgrade() {
                        entries.push((token, *fd));
                        true
                    } else {
                        false
                    }
                });
                entries
            };

            // 2. 锁外：对快照中的 fd 做 getsockopt（best-effort，fd 可能已被复用）
            let (recv, sent, alive) = {
                let mut r = 0u64;
                let mut s = 0u64;
                let mut n = 0usize;
                for (_token, fd) in &entries {
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
                let speed_mbps = 8.0 * delta_bytes as f64 / 1_000_000.0 / delta_secs as f64;
                let speed_str = format!("{:.2}", speed_mbps);

                self.tcp_score.store(blended, Ordering::Relaxed);
                self.tcp_score_initialized.store(true, Ordering::Relaxed);
                let delta_mb = format!("{:.2}", delta_bytes as f64 / 1024.0 / 1024.0);
                debug!(
                    id = %self.id,
                    alive = alive,
                    delta_mb = %delta_mb,
                    speed_mbps = %speed_str,
                    score = blended,
                    "upstream aggregate score"
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
            (false, false) => DEFAULT_SCORE,
        };

        // tcp_score_initialized 为 false 说明从未通过 TCP 流量更新过，视为无效
        let tcp_valid = self.tcp_score_initialized.load(Ordering::Relaxed);
        let quic_valid = uplink_valid || downlink_valid;
        let qw = self.quic_weight.load(Ordering::Relaxed);
        let tw = 100 - qw;

        match (tcp_valid, quic_valid) {
            (true, true) => (tcp * tw + quic * qw) / 100,
            (false, true) => quic,
            (true, false) => tcp,
            (false, false) => DEFAULT_SCORE,
        }
    }

    /// 有效分数 = 原始动态分数 × gain，用于选路权重和 tolerance 比较。
    pub fn effective_score(&self) -> u64 {
        let raw = self.score() as f64;
        let eff = raw * self.gain;
        let clamped = eff.clamp(1.0, 10_000_000.0) as u64;
        if eff > 10_000_000.0 {
            warn!(
                id = %self.id,
                raw_score = self.score(),
                gain = self.gain,
                effective_score = clamped,
                "effective score clamped to upper bound"
            );
        }
        clamped
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
        self.tcp_score_initialized.store(true, Ordering::Relaxed);
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
    groups: HashMap<String, Vec<Arc<Upstream>>>,
    all_items: Vec<Arc<Upstream>>,
    current: Mutex<HashMap<String, Option<String>>>,
    tolerance: u32,
}

impl UpstreamSet {
    pub fn new(items: Vec<Arc<Upstream>>, tolerance: u32, quic_weight: u32) -> Result<Self> {
        if items.is_empty() {
            bail!("UpstreamSet cannot be created with empty items");
        }

        let mut groups: HashMap<String, Vec<Arc<Upstream>>> = HashMap::new();
        for up in &items {
            for group in &up.groups {
                groups
                    .entry(group.clone())
                    .or_default()
                    .push(Arc::clone(up));
            }
        }

        for up in &items {
            up.set_quic_weight(quic_weight);
        }

        Ok(Self {
            groups,
            all_items: items,
            current: Mutex::new(HashMap::new()),
            tolerance,
        })
    }

    pub fn pick(&self) -> Option<Arc<Upstream>> {
        self.pick_from_group("default")
    }

    pub fn pick_from_group(&self, group: &str) -> Option<Arc<Upstream>> {
        let items = self.groups.get(group)?;
        self.pick_weighted(items, group, None)
    }

    pub fn pick_excluding_many_from_group(
        &self,
        group: &str,
        exclude: &HashSet<String>,
    ) -> Option<Arc<Upstream>> {
        let items = self.groups.get(group)?;
        let candidates: Vec<_> = items
            .iter()
            .filter(|u| !exclude.contains(&u.id))
            .cloned()
            .collect();
        if candidates.is_empty() {
            return None;
        }
        self.pick_weighted(&candidates, group, None)
    }

    /// 公共的平方加权随机选择逻辑，带 tolerance 切换门槛。
    /// `exclude_ctx` 仅用于 debug 日志区分调用来源。
    fn pick_weighted(
        &self,
        items: &[Arc<Upstream>],
        group: &str,
        exclude_ctx: Option<&str>,
    ) -> Option<Arc<Upstream>> {
        match items.len() {
            0 => {
                debug!(
                    group = %group,
                    exclude_ctx = ?exclude_ctx,
                    "pick: no upstream available"
                );
                return None;
            }
            1 => {
                let up = &items[0];
                debug!(
                    group = %group,
                    exclude_ctx = ?exclude_ctx,
                    upstream_id = %up.id,
                    score = up.score(),
                    "pick: single upstream"
                );
                return Some(Arc::clone(up));
            }
            _ => {}
        }

        // 1. 候选里的最高有效分数
        let best = items.iter().max_by_key(|u| u.effective_score())?;
        let best_eff = best.effective_score();

        // 2. 检查 sticky：仅当 tolerance > 0 时启用
        if self.tolerance > 0 {
            let sticky = {
                let guard = self.current.lock().unwrap_or_else(|e| e.into_inner());
                guard
                    .get(group)
                    .and_then(|id| id.as_ref())
                    .and_then(|id| items.iter().find(|u| u.id == *id).cloned())
            };

            if let Some(ref cur) = sticky {
                let cur_eff = cur.effective_score();
                if best.id != cur.id && best_eff > cur_eff + self.tolerance as u64 {
                    debug!(
                        group = %group,
                        exclude_ctx = ?exclude_ctx,
                        from_upstream_id = %cur.id,
                        from_score = cur_eff,
                        to_upstream_id = %best.id,
                        to_score = best_eff,
                        tolerance = self.tolerance,
                        "pick: switch upstream"
                    );
                    // 继续往下走，重新选
                } else {
                    debug!(
                        group = %group,
                        exclude_ctx = ?exclude_ctx,
                        upstream_id = %cur.id,
                        score = cur_eff,
                        best_upstream_id = %best.id,
                        best_score = best_eff,
                        tolerance = self.tolerance,
                        "pick: keep sticky upstream"
                    );
                    return Some(Arc::clone(cur));
                }
            }
        }

        // 3. 重新选：平方加权随机
        let weights: Vec<u64> = items
            .iter()
            .map(|u| {
                let s = u.effective_score();
                s * s // 平方加权：高分优势放大
            })
            .collect();

        let total_weight: u64 = weights.iter().sum();

        if tracing::enabled!(tracing::Level::DEBUG) {
            let candidate_scores: Vec<(&str, u64)> = items
                .iter()
                .map(|u| (u.id.as_str(), u.effective_score()))
                .collect();
            debug!(
                group = %group,
                exclude_ctx = ?exclude_ctx,
                upstream_count = items.len(),
                best_upstream_id = %best.id,
                best_score = best_eff,
                total_weight = total_weight,
                candidate_scores = ?candidate_scores,
                "pick: candidate set"
            );
        }

        let chosen = if total_weight == 0 {
            let idx = fastrand::usize(..items.len());
            let chosen = Arc::clone(&items[idx]);
            debug!(
                group = %group,
                exclude_ctx = ?exclude_ctx,
                upstream_id = %chosen.id,
                score = chosen.effective_score(),
                index = idx,
                "pick: random pick upstream"
            );
            chosen
        } else {
            let mut r = fastrand::u64(..total_weight);
            let pick_r = r;
            let mut picked = None;

            for (i, w) in weights.iter().enumerate() {
                if r < *w {
                    let chosen = Arc::clone(&items[i]);
                    debug!(
                        group = %group,
                        exclude_ctx = ?exclude_ctx,
                        upstream_id = %chosen.id,
                        score = chosen.effective_score(),
                        weight = *w,
                        rand = pick_r,
                        total_weight = total_weight,
                        "pick: weighted pick upstream"
                    );
                    picked = Some(chosen);
                    break;
                }
                r -= *w;
            }

            picked.unwrap_or_else(|| {
                let chosen = Arc::clone(&items[0]);
                debug!(
                    group = %group,
                    exclude_ctx = ?exclude_ctx,
                    upstream_id = %chosen.id,
                    score = chosen.effective_score(),
                    "pick: fallback to first upstream"
                );
                chosen
            })
        };

        // 4. 更新 current
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(group.to_string(), Some(chosen.id.clone()));

        Some(chosen)
    }

    pub fn find_by_id(&self, id: &str) -> Option<Arc<Upstream>> {
        self.all_items.iter().find(|u| u.id == id).cloned()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<Upstream>> + '_ {
        self.all_items.iter()
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
            error!(path = %PATH, error = format!("{:#}", e), "stats listener bind failed");
            return;
        }
    };

    #[cfg(target_os = "linux")]
    if let Err(e) = std::fs::set_permissions(PATH, std::fs::Permissions::from_mode(0o777)) {
        error!(error = format!("{:#}", e), "stats listener chmod failed");
        // chmod 失败但 socket 已创建，清理掉避免残留
        let _ = tokio::fs::remove_file(PATH).await;
        return;
    }

    info!(path = %PATH, "upstream stats listener bound");

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
                                error!(error = format!("{:#}", e), "upstream stats JSON parse failed");
                               continue;
                           }
                       };

                        let loss_percent_cents = (rep.loss_rate * 100.0).round() as i32;

                        debug!(
                            upstream_id = %rep.upstream_id,
                            peer = %rep.peer,
                            rtt_ms = rep.rtt_ms,
                            loss_percent = loss_percent_cents,
                            mtu = rep.mtu,
                            link = %rep.link.as_deref().unwrap_or("none"),
                            "upstream stats report"
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
                        error!(
                            path = %PATH, error = format!("{:#}", e), "stats recv error"
                        );
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

    let loss_penalty = match (loss_rate * 100.0).round() as u32 {
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
    info!(interval_secs = interval_secs, "health check task started");
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
                        id = %up.id,
                        failures = failures,
                        "upstream health check ok (recovered)"
                    );
                } else {
                    debug!(id = %up.id, "upstream health check ok");
                }
                if failures >= fail_threshold {
                    up.tcp_score.store(300, Ordering::Relaxed);
                    up.tcp_score_initialized.store(true, Ordering::Relaxed);
                    info!(id = %up.id, "upstream health recovered, score reset to 300");
                }
            } else {
                let f = up.health_failures.fetch_add(1, Ordering::Relaxed) + 1;
                if f == fail_threshold {
                    up.penalize();
                    warn!(
                        id = %up.id,
                        failures = f,
                        threshold = fail_threshold,
                        "upstream health check dead, penalized"
                    );
                } else if f > fail_threshold {
                    debug!(
                        id = %up.id,
                        failures = f,
                        threshold = fail_threshold,
                        "upstream health check still dead"
                    );
                } else {
                    debug!(
                        id = %up.id,
                        failures = f,
                        threshold = fail_threshold,
                        "upstream health check failed"
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
        Upstream::new(
            id,
            "127.0.0.1:1080".parse().unwrap(),
            vec!["default".to_string()],
            1.0,
        )
    }

    /// 直接设置 TCP 分数并标记为已初始化（绕过 run_score_task）
    fn set_tcp_score(up: &Upstream, score: u32) {
        up.tcp_score.store(score, Ordering::Relaxed);
        up.tcp_score_initialized.store(true, Ordering::Relaxed);
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
    fn score_initial() {
        let up = make_upstream("a");
        assert_eq!(up.score(), DEFAULT_SCORE);
    }

    #[test]
    fn score_uses_downlink_when_uplink_missing() {
        let up = make_upstream("c");
        set_tcp_score(&up, 600);
        set_quic_downlink(&up, 700);
        // uplink never updated => invalid, quic = downlink = 700
        let expected = (600 * 60 + 700 * 40) / 100; // 640
        assert_eq!(up.score(), expected);
    }

    #[test]
    fn score_averages_both_links() {
        let up = make_upstream("d");
        set_tcp_score(&up, 600);
        set_quic_uplink(&up, 800);
        set_quic_downlink(&up, 600);
        let expected = (600 * 60 + 700 * 40) / 100; // 640
        assert_eq!(up.score(), expected);
    }

    #[test]
    fn penalize_sets_all_to_100() {
        let up = make_upstream("e");
        up.penalize();
        assert_eq!(up.tcp_score.load(Ordering::Relaxed), 100);
        assert!(up.tcp_score_initialized.load(Ordering::Relaxed));
        assert_eq!(up.quic_uplink_score.load(Ordering::Relaxed), 100);
        assert_eq!(up.quic_downlink_score.load(Ordering::Relaxed), 100);
    }

    // ---------- UpstreamSet ----------
    fn upstream(id: &str) -> Arc<Upstream> {
        Upstream::new(
            id,
            "127.0.0.1:1080".parse().unwrap(),
            vec!["default".to_string()],
            1.0,
        )
    }

    fn upstream_set(ids: &[&str], tolerance: u32) -> UpstreamSet {
        let items: Vec<_> = ids.iter().map(|id| upstream(id)).collect();
        UpstreamSet::new(items, tolerance, 40).unwrap()
    }

    #[test]
    fn single_upstream_always_picked() {
        let set = upstream_set(&["a"], 0);
        let picked = set.pick().unwrap();
        assert_eq!(picked.id, "a");
    }

    #[test]
    fn pick_excluding_many_single_returns_none() {
        let set = upstream_set(&["a"], 0);
        let mut excluded = HashSet::new();
        excluded.insert("a".to_string());
        assert!(
            set.pick_excluding_many_from_group("default", &excluded)
                .is_none()
        );
    }

    #[test]
    fn pick_excluding_many_removes_matching() {
        let set = upstream_set(&["a", "b"], 0);
        let mut excluded = HashSet::new();
        excluded.insert("a".to_string());
        let picked = set
            .pick_excluding_many_from_group("default", &excluded)
            .unwrap();
        assert_eq!(picked.id, "b");
    }

    #[test]
    fn pick_excluding_many_excludes_all() {
        let set = upstream_set(&["a", "b", "c"], 0);
        let mut excluded = HashSet::new();
        excluded.insert("a".to_string());
        excluded.insert("b".to_string());
        excluded.insert("c".to_string());
        assert!(
            set.pick_excluding_many_from_group("default", &excluded)
                .is_none()
        );
    }

    #[test]
    fn tolerance_sticky_when_best_not_exceeding() {
        let set = upstream_set(&["a", "b"], 50);
        for u in set.iter() {
            set_tcp_score(u, 500);
            set_quic_uplink(u, 500);
        }
        // sticky to "a"
        {
            let mut cur = set.current.lock().unwrap();
            cur.insert("default".to_string(), Some("a".to_string()));
        }
        let picked = set.pick().unwrap();
        assert_eq!(picked.id, "a", "should stick because scores equal");
    }

    #[test]
    fn tolerance_switches_when_best_exceeds() {
        fastrand::seed(42); // 固定随机种子，避免偶然选中低分 upstream
        let set = upstream_set(&["a", "b"], 100);
        // sticky to "a"
        {
            let mut cur = set.current.lock().unwrap();
            cur.insert("default".to_string(), Some("a".to_string()));
        }
        // "a" at 500
        for u in set.iter() {
            set_tcp_score(u, 500);
            set_quic_uplink(u, 500);
        }
        // "b" quic=850 => score=(500*60+850*40)/100=640, diff=140 > 100
        let up_b = set.find_by_id("b").unwrap();
        set_quic_uplink(&up_b, 850);
        let picked = set.pick().unwrap();
        assert_eq!(picked.id, "b");
    }

    #[test]
    fn score_blends_tcp_and_quic() {
        let up = make_upstream("b");
        set_tcp_score(&up, 600);
        set_quic_uplink(&up, 800);
        // 默认 qw=40, tw=60
        let expected = (600 * 60 + 800 * 40) / 100; // 680
        assert_eq!(up.score(), expected);
    }

    #[test]
    fn score_respects_custom_quic_weight() {
        let up = make_upstream("f");
        up.set_quic_weight(50); // 5:5
        set_tcp_score(&up, 600);
        set_quic_uplink(&up, 800);
        let expected = (600 * 50 + 800 * 50) / 100; // 700
        assert_eq!(up.score(), expected);
    }

    fn upstream_with_groups(id: &str, groups: Vec<String>) -> Arc<Upstream> {
        Upstream::new(id, "127.0.0.1:1080".parse().unwrap(), groups, 1.0)
    }

    #[test]
    fn pick_from_group_nonexistent_returns_none() {
        let set = upstream_set(&["a", "b"], 0);
        assert!(set.pick_from_group("nonexistent").is_none());
    }

    #[test]
    fn pick_from_group_sticky_isolated() {
        let items = vec![
            upstream_with_groups("a", vec!["default".to_string(), "office".to_string()]),
            upstream_with_groups("b", vec!["default".to_string()]),
            upstream_with_groups("c", vec!["office".to_string()]),
            upstream_with_groups("d", vec!["office".to_string()]),
        ];
        let set = UpstreamSet::new(items, 50, 40).unwrap();

        // sticky default -> a, office -> c
        {
            let mut cur = set.current.lock().unwrap();
            cur.insert("default".to_string(), Some("a".to_string()));
            cur.insert("office".to_string(), Some("c".to_string()));
        }

        let picked_default = set.pick_from_group("default").unwrap();
        assert_eq!(picked_default.id, "a");

        let picked_office = set.pick_from_group("office").unwrap();
        assert_eq!(picked_office.id, "c");
    }

    // ---------- effective_score ----------

    #[test]
    fn effective_score_default_gain() {
        let up = make_upstream("a");
        set_tcp_score(&up, 500);
        // gain=1.0, effective = 500 * 1.0 = 500
        assert_eq!(up.effective_score(), 500);
    }

    #[test]
    fn effective_score_with_gain_2x() {
        let up = Upstream::new(
            "b",
            "127.0.0.1:1080".parse().unwrap(),
            vec!["default".to_string()],
            2.0,
        );
        set_tcp_score(&up, 500);
        assert_eq!(up.effective_score(), 1000);
    }

    #[test]
    fn effective_score_with_gain_half() {
        let up = Upstream::new(
            "c",
            "127.0.0.1:1080".parse().unwrap(),
            vec!["default".to_string()],
            0.5,
        );
        set_tcp_score(&up, 1000);
        assert_eq!(up.effective_score(), 500);
    }

    #[test]
    fn effective_score_clamped_lower_bound() {
        let up = Upstream::new(
            "d",
            "127.0.0.1:1080".parse().unwrap(),
            vec!["default".to_string()],
            0.001,
        );
        set_tcp_score(&up, 1);
        // 1 * 0.001 = 0.001, clamped to 1
        assert_eq!(up.effective_score(), 1);
    }

    #[test]
    fn effective_score_clamped_upper_bound() {
        let up = Upstream::new(
            "e",
            "127.0.0.1:1080".parse().unwrap(),
            vec!["default".to_string()],
            100_000.0,
        );
        set_tcp_score(&up, 1000);
        // 1000 * 100000 = 100_000_000, clamped to 10_000_000
        assert_eq!(up.effective_score(), 10_000_000);
    }

    #[test]
    fn effective_score_raw_score_unchanged() {
        let up = Upstream::new(
            "f",
            "127.0.0.1:1080".parse().unwrap(),
            vec!["default".to_string()],
            3.0,
        );
        set_tcp_score(&up, 500);
        assert_eq!(up.effective_score(), 1500);
        // raw score unchanged
        assert_eq!(up.score(), 500);
    }

    // ---------- gain selection influence ----------

    #[test]
    fn gain_affects_weighted_selection() {
        fastrand::seed(42);
        let items = vec![
            Upstream::new(
                "high",
                "127.0.0.1:1080".parse().unwrap(),
                vec!["default".to_string()],
                2.0,
            ),
            Upstream::new(
                "low",
                "127.0.0.1:1080".parse().unwrap(),
                vec!["default".to_string()],
                0.5,
            ),
        ];
        // same raw score
        for u in &items {
            set_tcp_score(u, 500);
        }
        let set = UpstreamSet::new(items, 0, 40).unwrap();

        // effective: high=1000, low=250
        // weight: high=1000000, low=62500, ratio ~16:1
        let mut high_count = 0u32;
        let mut low_count = 0u32;
        for _ in 0..1000 {
            let picked = set.pick().unwrap();
            if picked.id == "high" {
                high_count += 1;
            } else {
                low_count += 1;
            }
        }
        // high should be picked much more often than low
        assert!(
            high_count > low_count * 5,
            "high gain should be picked much more often: high={}, low={}",
            high_count,
            low_count
        );
    }

    #[test]
    fn gain_affects_tolerance_comparison() {
        fastrand::seed(42);
        let items = vec![
            Upstream::new(
                "a",
                "127.0.0.1:1080".parse().unwrap(),
                vec!["default".to_string()],
                1.0,
            ),
            Upstream::new(
                "b",
                "127.0.0.1:1080".parse().unwrap(),
                vec!["default".to_string()],
                1.0,
            ),
        ];
        for u in &items {
            set_tcp_score(u, 500);
            set_quic_uplink(u, 500);
        }
        let set = UpstreamSet::new(items, 50, 40).unwrap();

        // sticky to "a"
        {
            let mut cur = set.current.lock().unwrap();
            cur.insert("default".to_string(), Some("a".to_string()));
        }

        // Set "b" gain=3.0 so effective=1500, "a" gain=1.0 effective=500
        // diff=1000 > tolerance=50, should switch
        let items2 = vec![
            Upstream::new(
                "a",
                "127.0.0.1:1080".parse().unwrap(),
                vec!["default".to_string()],
                1.0,
            ),
            Upstream::new(
                "b",
                "127.0.0.1:1080".parse().unwrap(),
                vec!["default".to_string()],
                3.0,
            ),
        ];
        for u in &items2 {
            set_tcp_score(u, 500);
            set_quic_uplink(u, 500);
        }
        let set2 = UpstreamSet::new(items2, 50, 40).unwrap();
        {
            let mut cur = set2.current.lock().unwrap();
            cur.insert("default".to_string(), Some("a".to_string()));
        }
        // a effective=500, b effective=1500, diff=1000 > 50
        let picked = set2.pick().unwrap();
        assert_eq!(picked.id, "b", "should switch due to higher gain");
    }
}
