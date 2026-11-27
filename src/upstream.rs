use anyhow::{Result, bail};
use arc_swap::ArcSwap;
use portable_atomic::AtomicU64;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, Weak};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixDatagram;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::socks5::{Socks5Target, socks5_connect};
use crate::state::AppState;
use crate::util::{get_tcp_info_ext_raw, now_secs};

/// 新 upstream 和惩罚后的 upstream 使用的基础分数。
/// 用于避免历史高分在异常或连接卡住后长期保留。
const DEFAULT_SCORE: u32 = 75;

/// QUIC 探针分数过期阈值默认值（秒）。实际值由配置决定，通过 UpstreamSet 统一设置。
const DEFAULT_QUIC_STALE_SECS: u64 = 180;

/// 最低分数，避免分数归零导致 upstream 被"饿死"无法被选中更新。
const MINIMAL_SCORE: u32 = 10;

/// 只有探针分、没有吞吐样本时的分数上限（组内没有任何实测样本时的默认值）。
/// 探针只测 RTT/丢包/MTU，与吞吐相关性弱；不设上限会让一条从未跑过数据的
/// 链路凭探针分拿到最高权重，把新连接全部吸走，而它自己永远拿不到吞吐样本。
const UNMEASURED_SCORE_CAP: u32 = 500;

/// 无吞吐证据链路的上限下限。组内唯一的实测链路本身很差时（比如只有 18 分），
/// 按 1/3 算出来的上限会把其他链路压得没有流量、也就永远测不出来，
/// 因此不低于这个值，保证探索空间。
const MIN_UNMEASURED_SCORE_CAP: u32 = 100;

// 不变式：(false, false) 分支返回 DEFAULT_SCORE，而 (false, true) 至少是
// MIN_UNMEASURED_SCORE_CAP。若前者反超后者，"既没吞吐又没探针"的链路会排在
// "只有探针、但被 cap 限幅"的链路前面，语义就倒挂了。
const _: () = assert!(DEFAULT_SCORE < MIN_UNMEASURED_SCORE_CAP);

/// 计入"活跃连接"的最小本窗口下行增量。空闲 keep-alive 和偶发心跳不计入速率
/// 分母 —— 否则挂着一堆长连接的链路会被稀释得看不出真实带宽。
const ACTIVE_CONN_MIN_BYTES: u64 = 1024 * 4;

/// MiB/s → Mbps 的换算系数（1 MiB/s = 8.388608 Mbps，十进制 Mbps）。
const MIB_TO_MBPS: f64 = 8.0 * 1024.0 * 1024.0 / 1_000_000.0;

/// FdSample.last_recv 的"尚未建立基线"哨兵值。
/// 不能用 0：新连接第一次采样时可能还没收到任何字节（握手/TTFB 阶段），
/// 若把 0 既当"未初始化"又当合法基线，下个窗口收到的突发会被永久跳过。
const UNINIT_RECV: u64 = u64::MAX;

/// pick 时对未初始化（无任何测量样本）upstream 的探索概率。
/// 保证新链路能分到流量产生吞吐/探针样本，打破"无样本→无分数→无流量"的饥饿循环。
const PICK_EXPLORE_RATIO: f32 = 0.05;

/// penalize() 之后把链路从候选池里压下去的时间（秒）。
///
/// 依赖分数的策略本来就会因为分数被打回 DEFAULT_SCORE 而少选它，但 random / rr /
/// lru / least_conn 完全不看分数，必须有一个独立的"刚失败过"标记才能体现 penalize。
/// 只要有别的候选存在就不选它；冷却结束自动回池，避免一次瞬时失败把好链路永久踢掉。
const PENALIZE_COOLDOWN_SECS: u64 = 60;

/// 每累计这么多次连接断开，就回收一次 registry 里失效的条目。
///
/// 采样任务每 2 秒清理一次，但 `disable_upstream_score = true` 时它不跑，
/// 那时只能靠连接断开路径兜底。按"断开次数"而不是"registry 长度"触发，
/// 是为了让清理成本摊薄——按长度触发的话，活跃长连接数一旦超过阈值，
/// 每次建连都要做一次 O(N) 扫描却一条都回收不掉。
const REGISTRY_PRUNE_EVERY: u32 = 256;

/// 组内选路策略。
///
/// 所有策略都跑同一套前置过滤：候选池先剔除"刚被 penalize"的链路（除非池里只剩它们），
/// 差别只在剩下的候选里怎么挑。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamStrategy {
    /// 粘性容忍度 + 平方加权随机 + 未测量链路探索（默认，即历史行为）。
    #[default]
    Weighted,
    /// 组内均匀随机，完全忽略分数。
    Random,
    /// 选最久未被选中过的链路（按 pick 序号，不是时间戳，不受时钟分辨率影响）。
    Lru,
    /// 选当前活跃连接数最少的链路。
    LeastConn,
    /// 组内严格轮询。
    Rr,
    /// 只取有效分最高的链路；同分时随机打破（否则同分链路里只有一条能拿流量）。
    Best,
}

/// 策略表里的保留键：既是内置兜底分组的名字，也是未覆盖分组的默认策略。
pub const DEFAULT_STRATEGY_KEY: &str = "default";

impl UpstreamStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Weighted => "weighted",
            Self::Random => "random",
            Self::Lru => "lru",
            Self::LeastConn => "least_conn",
            Self::Rr => "rr",
            Self::Best => "best",
        }
    }
}

impl fmt::Display for UpstreamStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 单个被追踪连接的采样基线：记录上次读到的累计下行字节。
/// 放在 registry 里以 Arc 共享，采样快照可以在锁外无锁回写，不必再抢 registry 的锁。
#[derive(Debug)]
struct FdSample {
    fd: std::os::fd::RawFd,
    last_recv: AtomicU64,
}

/// 一条被追踪连接的凭据。持有期间该 upstream 的活跃连接数计入这一条，
/// drop 时自动减一，并按累计断开次数顺带清理 registry。
pub struct ConnToken {
    up: Arc<Upstream>,
    /// 保住 registry 中对应 `Weak` 的存活期，采样任务据此判断连接是否还在。
    _alive: Arc<()>,
}

impl Drop for ConnToken {
    fn drop(&mut self) {
        self.up.active_conns.fetch_sub(1, Ordering::Relaxed);
        let dead = self.up.dead_since_prune.fetch_add(1, Ordering::Relaxed) + 1;
        if dead >= REGISTRY_PRUNE_EVERY {
            self.up.dead_since_prune.store(0, Ordering::Relaxed);
            self.up
                .lock_registry()
                .retain(|(weak, _)| weak.strong_count() > 0);
        }
    }
}

#[derive(Debug)]
pub struct Upstream {
    pub id: String,
    pub addr: SocketAddr,
    pub groups: Vec<String>,
    pub gain: f64,

    registry: std::sync::Mutex<Vec<(Weak<()>, Arc<FdSample>)>>,

    tcp_score: AtomicU32,
    tcp_score_initialized: AtomicBool,

    last_check_secs: AtomicU64,
    health_failures: AtomicU32, // 连续失败次数

    /// 最近一次被选中的序号（由 UpstreamSet 单调递增分配），0 表示从未被选中。LRU 策略使用。
    last_picked_seq: AtomicU64,
    /// 冷却截止时间（秒）：业务建连失败来源。
    penalized_until_secs: AtomicU64,
    /// 健康检查是否判定这条链路死亡。与业务冷却分开记账，且没有 TTL：
    /// 只有健康检查自己探测成功才会清除。用截止时间的话，探测延迟（串行检查
    /// 多条链路时，同一条链路的实际检查周期远大于配置间隔）会在冷却到期与下一次
    /// 检查结果之间留出空窗，把流量重新引到已知不可用的链路上。
    health_dead: AtomicBool,
    /// 当前活跃连接数：track() 时加一，ConnToken drop 时减一。
    active_conns: AtomicUsize,
    /// 自上次 registry 清理以来断开的连接数，见 [`REGISTRY_PRUNE_EVERY`]。
    dead_since_prune: AtomicU32,

    quic_uplink_score: AtomicU32,
    quic_downlink_score: AtomicU32,
    quic_uplink_last_update_secs: AtomicU64,
    quic_downlink_last_update_secs: AtomicU64,
    quic_weight: AtomicU32,     // 0-100，默认 40
    quic_stale_secs: AtomicU64, // 过期阈值（秒），由 UpstreamSet 统一设置
    /// 仅有探针分时的分数上限，由 run_relative_score_task 按组动态写入
    unmeasured_cap: AtomicU32,

    // 相对归一化评分（enable_relative_scoring 开启时使用）
    throughput_rate_mibs: AtomicU64, // 最近实测吞吐速率（MiB/s，存 f64 bits，EMA）
    throughput_updated_secs: AtomicU64, // 吞吐速率最后更新时间（秒）
    probe_quality: AtomicU64,        // 连续探针质量（0~1，存 f64 bits）
    probe_quality_updated_secs: AtomicU64, // 探针质量最后更新时间（秒）
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
            last_check_secs: AtomicU64::new(0),
            health_failures: AtomicU32::new(0),
            last_picked_seq: AtomicU64::new(0),
            penalized_until_secs: AtomicU64::new(0),
            health_dead: AtomicBool::new(false),
            active_conns: AtomicUsize::new(0),
            dead_since_prune: AtomicU32::new(0),
            quic_weight: AtomicU32::new(40),
            quic_stale_secs: AtomicU64::new(DEFAULT_QUIC_STALE_SECS),
            unmeasured_cap: AtomicU32::new(UNMEASURED_SCORE_CAP),
            throughput_rate_mibs: AtomicU64::new(0),
            throughput_updated_secs: AtomicU64::new(0),
            probe_quality: AtomicU64::new(0),
            probe_quality_updated_secs: AtomicU64::new(0),
        })
    }

    pub fn set_quic_weight(&self, w: u32) {
        self.quic_weight.store(w.clamp(0, 100), Ordering::Relaxed);
    }

    pub fn set_quic_stale_secs(&self, secs: u64) {
        self.quic_stale_secs.store(secs.max(1), Ordering::Relaxed);
    }

    /// QUIC 探针分数的过期阈值（秒）
    pub fn quic_stale_secs(&self) -> u64 {
        self.quic_stale_secs.load(Ordering::Relaxed)
    }

    fn lock_registry(&self) -> std::sync::MutexGuard<'_, Vec<(Weak<()>, Arc<FdSample>)>> {
        self.registry.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 登记一条连接：active_conns 加一，并把 fd 交给采样任务。
    /// 返回的 token 必须持有到连接结束，drop 时自动减一。
    #[must_use = "丢弃 token 会立刻把连接记为已结束，least_conn 会低估负载"]
    pub fn track(self: &Arc<Self>, fd: std::os::fd::RawFd) -> ConnToken {
        let alive = Arc::new(());
        let weak = Arc::downgrade(&alive);
        self.lock_registry().push((
            weak,
            Arc::new(FdSample {
                fd,
                last_recv: AtomicU64::new(UNINIT_RECV),
            }),
        ));
        self.active_conns.fetch_add(1, Ordering::Relaxed);
        ConnToken {
            up: Arc::clone(self),
            _alive: alive,
        }
    }

    pub async fn run_score_task(self: Arc<Self>, relative_mode: bool, cancel: CancellationToken) {
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
                reg.retain(|(weak, sample)| {
                    if let Some(token) = weak.upgrade() {
                        entries.push((token, Arc::clone(sample)));
                        true
                    } else {
                        false
                    }
                });
                entries
            };

            // 2. 锁外：对快照中的 fd 做 getsockopt（best-effort，fd 可能已被复用）。
            //    按 fd 自己算本窗口增量：只有真在传数据的连接才进速率分母。
            //    这样既能排除大量空闲 keep-alive 的稀释，也不会像聚合总量那样
            //    "被选得越多分越高"。
            // 只统计下行字节。上行方向在这个 socket 上是 loopback：tcpi_bytes_acked
            // 反映的是本机 SOCKS5 进程多快把数据抽进自己的发送缓冲（受 shadowquic
            // 的 send-window 支配），与远端上行带宽无关。
            let (sum_d, sum_sq, active, alive) = {
                let mut sum_d = 0u128;
                let mut sum_sq = 0u128;
                let mut active = 0usize;
                let mut alive = 0usize;
                for (_token, sample) in &entries {
                    let Some(info) = get_tcp_info_ext_raw(sample.fd) else {
                        continue;
                    };
                    alive += 1;
                    let cur = info.tcpi_bytes_received;
                    let prev = sample.last_recv.swap(cur, Ordering::Relaxed);
                    // 首次采样只建立基线，本轮不产生增量
                    if prev == UNINIT_RECV {
                        continue;
                    }
                    let delta = cur.saturating_sub(prev);
                    if delta >= ACTIVE_CONN_MIN_BYTES {
                        active += 1;
                        sum_d += delta as u128;
                        sum_sq += (delta as u128) * (delta as u128);
                    }
                }
                (sum_d, sum_sq, active, alive)
            };

            if alive == 0 {
                continue;
            }

            let now = now_secs();
            let prev_secs = self.last_check_secs.swap(now, Ordering::Relaxed);
            let delta_secs = now.saturating_sub(prev_secs).max(1);

            // 没有连接在本窗口真正传数据：本轮无样本，保留上一次实测值。
            if active == 0 || sum_d < 1024 * 16 {
                continue;
            }

            // 字节加权的下行速率：等价于"每条连接的速率，按它搬了多少字节加权"。
            // 结果接近高流量流的速率，既不被大量小请求拉低，也不随并发数放大。
            let mib_per_sec = byte_weighted_mib_per_sec(sum_d, sum_sq, delta_secs);
            // 绝对模式用的"代表性连接本窗口字节数"，单连接时等于该连接自身总量
            let weighted_bytes = (sum_sq / sum_d).min(u64::MAX as u128) as u64;
            let speed_mbps = mib_per_sec * MIB_TO_MBPS;
            let delta_mib = format!("{:.2}", sum_d as f64 / 1024.0 / 1024.0);

            if relative_mode {
                // 相对模式：只记录实测速率（MiB/s 的 EMA），不直接写 tcp_score。
                // tcp_score 由 run_relative_score_task 统一做组内归一化后写入。
                let old_rate = load_f64(&self.throughput_rate_mibs);
                let last = self.throughput_updated_secs.load(Ordering::Relaxed);
                let new_rate =
                    blend_rate_mibs(old_rate, last, now, self.quic_stale_secs(), mib_per_sec);
                store_f64(&self.throughput_rate_mibs, new_rate);
                self.throughput_updated_secs.store(now, Ordering::Relaxed);
                debug!(
                    id = %self.id,
                    alive = alive,
                    active = active,
                    delta_mib = %delta_mib,
                    speed_mbps = speed_mbps,
                    rate_mbps = new_rate * MIB_TO_MBPS,
                    "upstream per-active-conn rate (relative mode)"
                );
            } else if let Some(raw) =
                calc_throughput_score(weighted_bytes, Duration::from_secs(delta_secs))
            {
                let old = self.tcp_score.load(Ordering::Relaxed);
                // 50/50，历史与新数据同等权重
                let blended = (old * 5 + raw * 5) / 10;

                self.tcp_score.store(blended, Ordering::Relaxed);
                self.tcp_score_initialized.store(true, Ordering::Relaxed);
                debug!(
                    id = %self.id,
                    alive = alive,
                    active = active,
                    delta_mib = %delta_mib,
                    speed_mbps = speed_mbps,
                    score = blended,
                    "upstream per-active-conn score"
                );
            }
        }
    }

    pub fn score(&self) -> u32 {
        self.score_at(now_secs())
    }

    /// 有效分数 = 原始动态分数 × gain，用于选路权重和 tolerance 比较。
    pub fn effective_score(&self) -> u64 {
        self.effective_score_at(now_secs())
    }

    /// 使用指定时间计算有效分数
    pub fn effective_score_at(&self, now: u64) -> u64 {
        let raw_score = self.score_at(now);
        let eff = raw_score as f64 * self.gain;
        let clamped = eff.clamp(1.0, 10_000_000.0) as u64;
        if eff > 10_000_000.0 {
            debug!(
                id = %self.id,
                raw_score,
                gain = self.gain,
                effective_score = clamped,
                "effective score clamped to upper bound"
            );
        }
        clamped
    }

    /// 使用指定时间计算综合分数
    fn score_at(&self, now: u64) -> u32 {
        let tcp = self.tcp_score.load(Ordering::Relaxed);
        let quic = self.quic_score_effective_at(now);

        let tcp_valid = self.tcp_score_initialized.load(Ordering::Relaxed);
        // 注意：quic_valid 判定与 quic_score_effective_at 内的 decay 逻辑存在隐含契约——
        // decay 仅在 last_update_secs == 0 时返回 None，stale 仍返回 Some(MINIMAL_SCORE)。
        // 若修改 decay 让超期也返回 None，此处需同步调整。
        let quic_valid = self.quic_uplink_last_update_secs.load(Ordering::Relaxed) > 0
            || self.quic_downlink_last_update_secs.load(Ordering::Relaxed) > 0;
        let qw = self.quic_weight.load(Ordering::Relaxed);
        let tw = 100 - qw;

        match (tcp_valid, quic_valid) {
            (true, true) => (tcp * tw + quic * qw) / 100,
            // 只有探针分：限幅，避免零吞吐证据的链路凭探针分垄断选路。
            // 上限按组动态计算，见 unmeasured_cap_for()。
            (false, true) => quic.min(self.unmeasured_cap.load(Ordering::Relaxed)),
            (true, false) => tcp,
            (false, false) => DEFAULT_SCORE,
        }
    }

    /// 获取 QUIC 有效分数（应用衰减后的值），使用指定时间
    fn quic_score_effective_at(&self, now: u64) -> u32 {
        let stale_secs = self.quic_stale_secs.load(Ordering::Relaxed);
        let decay = |score: u32, last_update_secs: u64| -> Option<u32> {
            if last_update_secs == 0 {
                return None;
            }
            let elapsed = now.saturating_sub(last_update_secs);
            if elapsed >= stale_secs {
                return Some(MINIMAL_SCORE);
            }
            let factor = (stale_secs - elapsed) as f64 / stale_secs as f64;
            let decayed = (score as f64 * factor) as u32;
            Some(decayed.max(MINIMAL_SCORE))
        };

        let uplink = decay(
            self.quic_uplink_score.load(Ordering::Relaxed),
            self.quic_uplink_last_update_secs.load(Ordering::Relaxed),
        );
        let downlink = decay(
            self.quic_downlink_score.load(Ordering::Relaxed),
            self.quic_downlink_last_update_secs.load(Ordering::Relaxed),
        );

        match (uplink, downlink) {
            (Some(u), Some(d)) => (u + d) / 2,
            (Some(u), None) => u,
            (None, Some(d)) => d,
            (None, None) => DEFAULT_SCORE,
        }
    }

    /// 获取 TCP 分数（原始值，未经衰减）
    pub fn tcp_score_raw(&self) -> u32 {
        self.tcp_score.load(Ordering::Relaxed)
    }

    /// 获取上行 QUIC 分数（原始值，未经衰减）
    pub fn quic_uplink_score_raw(&self) -> u32 {
        self.quic_uplink_score.load(Ordering::Relaxed)
    }

    /// 获取下行 QUIC 分数（原始值，未经衰减）
    pub fn quic_downlink_score_raw(&self) -> u32 {
        self.quic_downlink_score.load(Ordering::Relaxed)
    }

    /// 获取上行 QUIC 最后更新时间（秒）
    pub fn quic_uplink_last_update_secs(&self) -> u64 {
        self.quic_uplink_last_update_secs.load(Ordering::Relaxed)
    }

    /// 获取下行 QUIC 最后更新时间（秒）
    pub fn quic_downlink_last_update_secs(&self) -> u64 {
        self.quic_downlink_last_update_secs.load(Ordering::Relaxed)
    }

    /// TCP 分数是否已初始化（有过流量更新）
    pub fn tcp_score_initialized(&self) -> bool {
        self.tcp_score_initialized.load(Ordering::Relaxed)
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

    /// 记录探针连续质量（0~1），并刷新对应方向的最后更新时间。
    /// 相对评分模式下由 run_relative_score_task 消费，替代绝对分段评分。
    pub fn set_probe_quality(&self, q: f64, link: Option<&str>) {
        store_f64(&self.probe_quality, q);
        let now = now_secs();
        match link {
            Some("downlink") => {
                self.quic_downlink_last_update_secs
                    .store(now, Ordering::Relaxed);
            }
            _ => {
                self.quic_uplink_last_update_secs
                    .store(now, Ordering::Relaxed);
            }
        }
        self.probe_quality_updated_secs
            .store(now, Ordering::Relaxed);
    }

    /// 业务建连失败后的惩罚：分数打回基础分，并进入冷却期。
    pub fn penalize(&self) {
        self.reset_scores();
        let now = now_secs();
        self.penalized_until_secs
            .store(now + PENALIZE_COOLDOWN_SECS, Ordering::Relaxed);
    }

    /// 健康检查判定死亡：分数打回基础分，并置上"判死"标记。
    ///
    /// 这个标记没有 TTL，只由 [`Self::clear_health_penalty`]（健康检查探测成功）
    /// 清除。组内只剩被判死的链路时，选路会回退到完整候选池，不会整组不可用。
    pub fn penalize_by_health(&self) {
        self.reset_scores();
        self.health_dead.store(true, Ordering::Relaxed);
    }

    fn reset_scores(&self) {
        self.tcp_score.store(DEFAULT_SCORE, Ordering::Relaxed);
        self.tcp_score_initialized.store(true, Ordering::Relaxed);
        self.quic_uplink_score
            .store(DEFAULT_SCORE, Ordering::Relaxed);
        self.quic_downlink_score
            .store(DEFAULT_SCORE, Ordering::Relaxed);
        let now = now_secs();
        self.quic_uplink_last_update_secs
            .store(now, Ordering::Relaxed);
        self.quic_downlink_last_update_secs
            .store(now, Ordering::Relaxed);
    }

    /// 链路是否应当避让（忽略分数的策略靠它实现"优先剔除失败链路"）：
    /// 业务建连失败的冷却期内，或健康检查判定死亡。
    pub fn is_penalized_at(&self, now: u64) -> bool {
        self.penalized_until_secs.load(Ordering::Relaxed) > now
            || self.health_dead.load(Ordering::Relaxed)
    }

    /// 健康检查探测成功：解除判死状态。业务建连失败的冷却不受影响。
    pub fn clear_health_penalty(&self) {
        self.health_dead.store(false, Ordering::Relaxed);
    }

    pub fn last_picked_seq(&self) -> u64 {
        self.last_picked_seq.load(Ordering::Relaxed)
    }

    fn mark_picked(&self, seq: u64) {
        // 并发下"分配序号"和"提交序号"不是原子的：先领到较小序号的任务可能后提交，
        // 用 store 会把刚写进去的更大序号改小，让这条链路显得比实际更久没用。
        // fetch_max 只增不减，保证记录值与真实最近使用顺序一致。
        self.last_picked_seq.fetch_max(seq, Ordering::Relaxed);
    }

    /// 当前活跃连接数。读写都是原子操作，不抢 registry 的锁。
    pub fn active_conns(&self) -> usize {
        self.active_conns.load(Ordering::Relaxed)
    }
}

/// 时间桶，覆盖 [start_secs, start_secs + bucket_secs) 时间段。
/// 时钟回拨时事件会归入当前最新桶，因此该桶的时间范围是统计近似值。
struct PickStatsBucket {
    start_secs: u64,
    counts: Vec<u64>,
}

/// 内部状态，由单个 Mutex 保护。
struct PickStatsInner {
    buckets: VecDeque<PickStatsBucket>,
    totals: Vec<u64>,
}

/// 选中统计：固定时间桶 + upstream 索引计数。
///
/// - 内存：O(桶数 × upstream 数)，与 pick 频率无关
/// - record_by_id()：按 id 查索引后整数加一，常规路径零分配（仅新桶时分配固定大小计数数组）
/// - counts()：O(k)，k = upstream 数
const PICK_STATS_BUCKET_SECS: u64 = 10;

struct PickStats {
    window_secs: u64,
    bucket_secs: u64,
    /// upstream id → 索引映射，record_by_id() 使用。
    indexes: HashMap<String, usize>,
    /// index → upstream id，仅日志打印时使用。
    upstream_ids: Vec<String>,
    inner: Mutex<PickStatsInner>,
    last_log_secs: AtomicU64,
}

impl PickStats {
    fn new(window_secs: u64, upstream_ids: Vec<String>) -> Self {
        let n = upstream_ids.len();
        let indexes = upstream_ids
            .iter()
            .enumerate()
            .map(|(i, id)| (id.clone(), i))
            .collect();
        let bucket_secs = PICK_STATS_BUCKET_SECS.min(window_secs).max(1);
        Self {
            window_secs,
            bucket_secs,
            indexes,
            upstream_ids,
            inner: Mutex::new(PickStatsInner {
                buckets: VecDeque::new(),
                totals: vec![0; n],
            }),
            last_log_secs: AtomicU64::new(0),
        }
    }

    /// 按 upstream id 记录一次选中，返回是否成功（未知 id 返回 false）。
    fn record_by_id(&self, upstream_id: &str) -> bool {
        let Some(&idx) = self.indexes.get(upstream_id) else {
            debug_assert!(
                false,
                "picked upstream missing from pick stats index: {upstream_id}"
            );
            return false;
        };
        self.record_at(now_secs(), idx);
        true
    }

    fn record_at(&self, now: u64, upstream_index: usize) {
        let bucket_start = now / self.bucket_secs * self.bucket_secs;
        let cutoff = now.saturating_sub(self.window_secs);
        let n = self.upstream_ids.len();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // 淘汰窗口外的旧桶
        while inner
            .buckets
            .front()
            .is_some_and(|b| b.start_secs.saturating_add(self.bucket_secs) <= cutoff)
        {
            let expired = inner.buckets.pop_front().expect("checked above");
            for (total, &cnt) in inner.totals.iter_mut().zip(&expired.counts) {
                debug_assert!(*total >= cnt, "pick stats total must cover expired bucket");
                *total = total.saturating_sub(cnt);
            }
        }

        // 找到或创建当前桶；时钟回拨时归入最新桶
        let use_existing = inner
            .buckets
            .back()
            .is_some_and(|b| b.start_secs > bucket_start);
        if !use_existing
            && inner
                .buckets
                .back()
                .is_none_or(|b| b.start_secs != bucket_start)
        {
            inner.buckets.push_back(PickStatsBucket {
                start_secs: bucket_start,
                counts: vec![0; n],
            });
        }

        let bucket = inner.buckets.back_mut().expect("just ensured bucket");
        bucket.counts[upstream_index] += 1;
        inner.totals[upstream_index] += 1;
    }

    /// 返回窗口内各 upstream 的选中次数，按次数降序。O(k) 复杂度。
    fn counts(&self) -> Vec<(String, u64)> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut counts: Vec<_> = self
            .upstream_ids
            .iter()
            .zip(&inner.totals)
            .filter_map(|(id, &c)| (c > 0).then_some((id.clone(), c)))
            .collect();
        counts.sort_by_key(|b| std::cmp::Reverse(b.1));
        counts
    }

    /// 距上次日志超过 60 秒时打印统计。
    fn maybe_log(&self) {
        let now = now_secs();
        let last = self.last_log_secs.load(Ordering::Relaxed);
        // 时钟回拨时重置节流基准，避免日志被长时间抑制
        if now < last {
            let _ = self.last_log_secs.compare_exchange(
                last,
                now,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            return;
        }
        if now - last < 60 {
            return;
        }
        if self
            .last_log_secs
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let counts = self.counts();
        if counts.is_empty() {
            return;
        }
        let total: u64 = counts.iter().map(|(_, c)| *c).sum();
        let parts: Vec<String> = counts.iter().map(|(id, c)| format!("{id}: {c}")).collect();
        info!(
            window_secs = self.window_secs,
            bucket_secs = self.bucket_secs,
            total_picks = total,
            upstreams = %parts.join(", "),
            "pick stats"
        );
    }
}

pub struct UpstreamSet {
    groups: HashMap<String, Vec<Arc<Upstream>>>,
    all_items: Vec<Arc<Upstream>>,
    current: Mutex<HashMap<String, Option<String>>>,
    tolerance: u32,
    pick_stats: Option<PickStats>,
    /// 分组 → 策略覆盖。保留键 `default` 兼作全局默认策略。
    group_strategies: HashMap<String, UpstreamStrategy>,
    /// 每个分组的轮询游标（rr 策略）。
    rr_cursor: Mutex<HashMap<String, usize>>,
    /// 全局单调递增的选中序号，lru 策略据此判断"最久未使用"。
    pick_seq: AtomicU64,
}

impl UpstreamSet {
    pub fn new(
        items: Vec<Arc<Upstream>>,
        tolerance: u32,
        quic_weight: u32,
        quic_stale_secs: u64,
        pick_stats_window_secs: u32,
    ) -> Result<Self> {
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
            up.set_quic_stale_secs(quic_stale_secs);
        }

        let pick_stats = (pick_stats_window_secs > 0).then(|| {
            let ids: Vec<String> = items.iter().map(|u| u.id.clone()).collect();
            PickStats::new(pick_stats_window_secs as u64, ids)
        });

        Ok(Self {
            groups,
            all_items: items,
            current: Mutex::new(HashMap::new()),
            tolerance,
            pick_stats,
            group_strategies: HashMap::new(),
            rr_cursor: Mutex::new(HashMap::new()),
            pick_seq: AtomicU64::new(0),
        })
    }

    /// 配置选路策略表。保留键 `default` 兼作全局默认策略，其余键按分组覆盖。
    pub fn with_group_strategies(
        mut self,
        group_strategies: HashMap<String, UpstreamStrategy>,
    ) -> Self {
        self.group_strategies = group_strategies;
        if !self.group_strategies.is_empty() {
            info!(
                default_strategy = %self.strategy_for(DEFAULT_STRATEGY_KEY),
                group_strategies = ?self.group_strategies,
                "upstream selection strategy configured"
            );
        }
        self
    }

    /// 某个分组实际生效的策略：本组覆盖 → `default` 键 → 内置 `weighted`。
    pub fn strategy_for(&self, group: &str) -> UpstreamStrategy {
        self.group_strategies
            .get(group)
            .or_else(|| self.group_strategies.get(DEFAULT_STRATEGY_KEY))
            .copied()
            .unwrap_or_default()
    }

    pub fn pick(&self) -> Option<Arc<Upstream>> {
        self.pick_from_group("default")
    }

    pub fn pick_from_group(&self, group: &str) -> Option<Arc<Upstream>> {
        let items = self.groups.get(group)?;
        self.pick_in_group(items, group, None)
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
        self.pick_in_group(&candidates, group, None)
    }

    /// 组内选路入口：先按 penalize 冷却过滤候选，再按该分组的策略分派。
    ///
    /// 过滤只做一次、对全部策略生效：依赖分数的策略本来就会因为分数被打回
    /// DEFAULT_SCORE 而少选失败链路，但忽略分数的策略同样需要"刚失败过就先别用"。
    /// 组内只剩被 penalize 的链路时不做过滤，避免整组不可用。
    /// `exclude_ctx` 仅用于 debug 日志区分调用来源。
    fn pick_in_group(
        &self,
        items: &[Arc<Upstream>],
        group: &str,
        exclude_ctx: Option<&str>,
    ) -> Option<Arc<Upstream>> {
        if items.is_empty() {
            debug!(
                group = %group,
                exclude_ctx = ?exclude_ctx,
                "pick: no upstream available"
            );
            return None;
        }

        let strategy = self.strategy_for(group);
        let now = now_secs();

        // 每个候选只读一次冷却状态：先数一遍再过滤一遍会让两次读取之间被别的任务
        // 改掉的链路漏进第二次过滤，得到一个空候选池（随后随机取 0 下标会 panic）。
        let mut penalized = 0usize;
        let mut healthy: Vec<Arc<Upstream>> = Vec::with_capacity(items.len());
        for up in items {
            if up.is_penalized_at(now) {
                penalized += 1;
            } else {
                healthy.push(Arc::clone(up));
            }
        }

        let chosen = if penalized > 0 && !healthy.is_empty() {
            debug!(
                group = %group,
                exclude_ctx = ?exclude_ctx,
                penalty_skipped = penalized,
                "pick: skip penalized upstreams"
            );
            self.pick_by_strategy(&healthy, group, exclude_ctx, strategy)
        } else {
            // 没有冷却链路，或全组都在冷却：用完整候选池，避免整组不可用
            self.pick_by_strategy(items, group, exclude_ctx, strategy)
        };

        self.commit_pick(group, &chosen);
        Some(chosen)
    }

    fn pick_by_strategy(
        &self,
        items: &[Arc<Upstream>],
        group: &str,
        exclude_ctx: Option<&str>,
        strategy: UpstreamStrategy,
    ) -> Arc<Upstream> {
        debug_assert!(!items.is_empty());

        if items.len() == 1 {
            let up = &items[0];
            debug!(
                group = %group,
                exclude_ctx = ?exclude_ctx,
                upstream_id = %up.id,
                score = up.score(),
                strategy = %strategy,
                "pick: single upstream"
            );
            return Arc::clone(up);
        }

        match strategy {
            UpstreamStrategy::Weighted => self.pick_score_based(items, group, exclude_ctx, true),
            UpstreamStrategy::Best => self.pick_score_based(items, group, exclude_ctx, false),
            UpstreamStrategy::Random => self.pick_uniform(items, group, exclude_ctx),
            UpstreamStrategy::Lru => self.pick_lru(items, group, exclude_ctx),
            UpstreamStrategy::LeastConn => self.pick_least_conn(items, group, exclude_ctx),
            UpstreamStrategy::Rr => self.pick_round_robin(items, group, exclude_ctx),
        }
    }

    /// 基于有效分数的选择：`weighted_draw = false` 时退化成"只取最高分"。
    /// 两种模式都保留未测量链路探索与 tolerance 粘性。
    fn pick_score_based(
        &self,
        items: &[Arc<Upstream>],
        group: &str,
        exclude_ctx: Option<&str>,
        weighted_draw: bool,
    ) -> Arc<Upstream> {
        // 0. 探索：存在尚无任何测量样本（未初始化）的 upstream 时，以固定概率从中均匀选取。
        //    这一步刻意排在粘性检查之前：粘性会把流量固定在当前链路上，新链路若排在
        //    粘性之后，就永远等不到产生样本的机会。
        //    探针报告与吞吐样本都依赖流量产生，若不探索，新链路会陷入
        //    "无样本→无分数→无流量"的死锁；penalize() 会把失败链路标记为已初始化，
        //    因此探索不会持续浪费流量在坏链路上。
        let uninit: Vec<&Arc<Upstream>> = items
            .iter()
            .filter(|u| !u.tcp_score_initialized())
            .collect();
        if !uninit.is_empty() && fastrand::f32() < PICK_EXPLORE_RATIO {
            let idx = fastrand::usize(..uninit.len());
            let chosen = Arc::clone(uninit[idx]);
            debug!(
                group = %group,
                exclude_ctx = ?exclude_ctx,
                upstream_id = %chosen.id,
                "pick: explore uninitialized upstream"
            );
            return chosen;
        }

        // 1. 候选里的最高有效分数
        let Some(best) = items.iter().max_by_key(|u| u.effective_score()) else {
            return Arc::clone(&items[0]);
        };
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
                    return Arc::clone(cur);
                }
            }
        }

        if !weighted_draw {
            // 同分时随机打破。max_by_key 在并列时恒定返回同一个元素，直接用它会在
            // 同分链路之间制造"永远只有它拿流量"；全部分数相同（例如关闭评分）时，
            // 随机打破等价于组内均匀随机。
            let top: Vec<&Arc<Upstream>> = items
                .iter()
                .filter(|u| u.effective_score() == best_eff)
                .collect();
            // effective_score() 读的是原子变量：算出 best_eff 之后、过滤之前，
            // 这条链路可能刚被 score_task 或 penalize 改了分数，此时 top 会为空，
            // 直接对 0 取随机下标会 panic。空集回退到快照里的 best。
            let chosen = match top.len() {
                0 => Arc::clone(best),
                1 => Arc::clone(top[0]),
                n => Arc::clone(top[fastrand::usize(..n)]),
            };
            debug!(
                group = %group,
                exclude_ctx = ?exclude_ctx,
                upstream_id = %chosen.id,
                score = best_eff,
                tied = top.len(),
                "pick: best-score pick upstream"
            );
            return chosen;
        }

        // 3. 重新选：平方加权随机。分数只读一次组成快照，抽签与日志都用它。
        let scores: Vec<u64> = items.iter().map(|u| u.effective_score()).collect();
        let total_weight = squared_weight_total(&scores);

        if tracing::enabled!(tracing::Level::DEBUG) {
            let candidate_scores: Vec<(&str, u64)> = items
                .iter()
                .zip(scores.iter())
                .map(|(u, s)| (u.id.as_str(), *s))
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

        if total_weight == 0 {
            let idx = fastrand::usize(..items.len());
            let chosen = Arc::clone(&items[idx]);
            debug!(
                group = %group,
                exclude_ctx = ?exclude_ctx,
                upstream_id = %chosen.id,
                score = scores[idx],
                index = idx,
                "pick: random pick upstream"
            );
            return chosen;
        }

        let pick_r = fastrand::u64(..total_weight);
        let Some(idx) = draw_index_by_squared_score(&scores, pick_r) else {
            let chosen = Arc::clone(&items[0]);
            debug!(
                group = %group,
                exclude_ctx = ?exclude_ctx,
                upstream_id = %chosen.id,
                score = scores[0],
                "pick: fallback to first upstream"
            );
            return chosen;
        };

        let chosen = Arc::clone(&items[idx]);
        debug!(
            group = %group,
            exclude_ctx = ?exclude_ctx,
            upstream_id = %chosen.id,
            score = scores[idx],
            weight = squared_weight(scores[idx]),
            rand = pick_r,
            total_weight = total_weight,
            "pick: weighted pick upstream"
        );
        chosen
    }

    /// 组内均匀随机，不看分数。
    fn pick_uniform(
        &self,
        items: &[Arc<Upstream>],
        group: &str,
        exclude_ctx: Option<&str>,
    ) -> Arc<Upstream> {
        let idx = fastrand::usize(..items.len());
        let chosen = Arc::clone(&items[idx]);
        debug!(
            group = %group,
            exclude_ctx = ?exclude_ctx,
            upstream_id = %chosen.id,
            index = idx,
            "pick: uniform random pick upstream"
        );
        chosen
    }

    /// 组内严格轮询：游标按分组独立推进。
    fn pick_round_robin(
        &self,
        items: &[Arc<Upstream>],
        group: &str,
        exclude_ctx: Option<&str>,
    ) -> Arc<Upstream> {
        let mut cursor = self.rr_cursor.lock().unwrap_or_else(|e| e.into_inner());
        let pos = cursor.get(group).copied().unwrap_or(0);
        let idx = pos % items.len();
        let chosen = Arc::clone(&items[idx]);
        // 候选集长度会随 penalize 过滤变化，游标只保证"每次前进一格"
        cursor.insert(group.to_string(), pos.wrapping_add(1));
        debug!(
            group = %group,
            exclude_ctx = ?exclude_ctx,
            upstream_id = %chosen.id,
            index = idx,
            "pick: round-robin pick upstream"
        );
        chosen
    }

    /// 选最久没有被选中过的链路（pick 序号最小），并列时随机打破。
    /// 从未被选过的链路序号为 0，因此天然优先——新链路能立刻拿到流量。
    fn pick_lru(
        &self,
        items: &[Arc<Upstream>],
        group: &str,
        exclude_ctx: Option<&str>,
    ) -> Arc<Upstream> {
        let seqs: Vec<u64> = items.iter().map(|u| u.last_picked_seq()).collect();
        let min_seq = seqs.iter().copied().min().unwrap_or(0);
        let ties: Vec<usize> = (0..items.len()).filter(|i| seqs[*i] == min_seq).collect();
        let idx = if ties.len() == 1 {
            ties[0]
        } else {
            ties[fastrand::usize(..ties.len())]
        };
        let chosen = Arc::clone(&items[idx]);
        debug!(
            group = %group,
            exclude_ctx = ?exclude_ctx,
            upstream_id = %chosen.id,
            last_picked_seq = min_seq,
            "pick: lru pick upstream"
        );
        chosen
    }

    /// 选当前活跃连接数最少的链路，并列时随机打破。
    fn pick_least_conn(
        &self,
        items: &[Arc<Upstream>],
        group: &str,
        exclude_ctx: Option<&str>,
    ) -> Arc<Upstream> {
        let conns: Vec<usize> = items.iter().map(|u| u.active_conns()).collect();
        let min_conns = conns.iter().copied().min().unwrap_or(0);
        let ties: Vec<usize> = (0..items.len())
            .filter(|i| conns[*i] == min_conns)
            .collect();
        let idx = if ties.len() == 1 {
            ties[0]
        } else {
            ties[fastrand::usize(..ties.len())]
        };
        let chosen = Arc::clone(&items[idx]);
        debug!(
            group = %group,
            exclude_ctx = ?exclude_ctx,
            upstream_id = %chosen.id,
            active_conns = min_conns,
            "pick: least-conn pick upstream"
        );
        chosen
    }

    /// 选路成功后统一更新粘性状态、LRU 序号与选中统计。
    fn commit_pick(&self, group: &str, chosen: &Arc<Upstream>) {
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(group.to_string(), Some(chosen.id.clone()));
        let seq = self.pick_seq.fetch_add(1, Ordering::Relaxed) + 1;
        chosen.mark_picked(seq);
        self.record_pick_stats(chosen);
    }

    fn record_pick_stats(&self, chosen: &Arc<Upstream>) {
        if let Some(ref stats) = self.pick_stats
            && stats.record_by_id(&chosen.id)
        {
            stats.maybe_log();
        }
    }

    pub fn find_by_id(&self, id: &str) -> Option<Arc<Upstream>> {
        self.all_items.iter().find(|u| u.id == id).cloned()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<Upstream>> + '_ {
        self.all_items.iter()
    }
}

/// 单个候选的抽签权重：有效分的平方（高分优势放大）。
fn squared_weight(score: u64) -> u64 {
    score.saturating_mul(score)
}

fn squared_weight_total(scores: &[u64]) -> u64 {
    scores.iter().map(|s| squared_weight(*s)).sum()
}

/// 平方加权抽签：给定各候选的有效分与一个随机数，返回命中的下标。
///
/// 抽签单独成纯函数是为了能确定性地钉住"权重是平方、不是线性"这个口径：
/// 统计测试只能验证大致比例，而线性权重（gain 3:1 时 75%）与平方权重（90%）
/// 在宽区间里都会通过。
fn draw_index_by_squared_score(scores: &[u64], rand: u64) -> Option<usize> {
    let total = squared_weight_total(scores);
    if total == 0 {
        return None;
    }
    let mut r = rand % total;
    for (i, score) in scores.iter().enumerate() {
        let w = squared_weight(*score);
        if r < w {
            return Some(i);
        }
        r -= w;
    }
    None
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
                            if state.config.enable_relative_scoring {
                                if let Some(q) = probe_quality(rep.rtt_ms, rep.loss_rate, rep.mtu) {
                                    up.set_probe_quality(q, rep.link.as_deref());
                                }
                            } else {
                                let score = calc_quic_score(rep.rtt_ms, rep.loss_rate, rep.mtu);
                                match rep.link.as_deref() {
                                    Some("downlink") => up.update_downlink_score(score),
                                    _ => up.update_uplink_score(score), // 默认按上行处理（兼容旧报告）
                                }
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

/// 连续探针质量函数（0~1，无绝对阈值分段），用于相对归一化评分。
/// 各分量随 RTT/丢包/MTU 变差而单调下降，无人工分段点，天然适配任意网络环境。
fn probe_quality(rtt_ms: f64, loss_rate: f64, mtu: u16) -> Option<f64> {
    if !rtt_ms.is_finite()
        || rtt_ms < 0.0
        || !loss_rate.is_finite()
        || !(0.0..=1.0).contains(&loss_rate)
    {
        return None;
    }
    let rtt_q = 1.0 / (1.0 + rtt_ms / 50.0);
    let loss_q = (-loss_rate * 10.0).exp();
    let mtu_q = (mtu.min(1400) as f64) / 1400.0;
    Some((rtt_q * loss_q * mtu_q).clamp(0.0, 1.0))
}

/// 相对归一化映射：value 相对 max 映射到 0~1000。
fn relative_score(value: f64, max: f64) -> u32 {
    if max <= 0.0 || value <= 0.0 {
        return 0;
    }
    (value / max * 1000.0).clamp(0.0, 1000.0) as u32
}

/// 字节加权的平均下行速率（MiB/s）：`Σd² / (dt · Σd)`。
///
/// 等价于"每连接速率按它搬的字节数加权"，所以结果由高流量流主导：
/// 一条大流不会因为旁边挂着一堆小请求而被拉低；空闲连接（d=0）权重为零，
/// 也不像聚合总量那样随并发连接数放大。单连接时退化为它自己的速率。
fn byte_weighted_mib_per_sec(sum_d: u128, sum_sq: u128, secs: u64) -> f64 {
    if sum_d == 0 {
        return 0.0;
    }
    let bytes_per_sec = sum_sq as f64 / sum_d as f64 / secs.max(1) as f64;
    bytes_per_sec / 1024.0 / 1024.0
}

/// 有实测样本时向相对分缓慢跟随（1/8 步长），避免单轮抖动把分数打飞。
/// 加 4 做四舍五入：截断会让 rel 比 old 高不到 8 时永远卡住不动。
fn blend_rate_sample(old: u32, rel: u32) -> u32 {
    (old * 7 + rel + 4) / 8
}

/// 速率 EMA：样本新鲜时 50/50 混合；首次或已过期时直接覆盖。
/// 过期后仍按 50/50 混合会让几小时前的旧速率把重启后的第一个样本拉偏一半。
fn blend_rate_mibs(old: f64, last_update: u64, now: u64, stale_secs: u64, cur: f64) -> f64 {
    let stale = last_update == 0 || now.saturating_sub(last_update) >= stale_secs;
    if stale || old <= 0.0 {
        cur
    } else {
        old * 0.5 + cur * 0.5
    }
}

/// 根据本轮是否有吞吐样本决定新的 tcp 分。
/// 返回 None 表示"本轮没有新证据"，调用方应保留旧值 —— 绝不能当成 0 分，
/// 否则空闲链路会在几十秒内被折半衰减到地板，再也回不来。
fn next_tcp_score(old: u32, initialized: bool, rel: Option<u32>) -> Option<u32> {
    let rel = rel?;
    Some(if initialized {
        blend_rate_sample(old, rel)
    } else {
        rel
    })
}

/// 无吞吐证据链路的分数上限：不超过同组最佳实测分的 1/3。
///
/// 平方加权下 `c = best/3` 意味着实测最佳链路大约能拿到 2/3 的权重，
/// 其余分给无证据链路作为探索空间。组内完全没有实测样本时退回默认上限，
/// 让尚未测量的链路彼此公平竞争。
fn unmeasured_cap_for(best_measured: Option<u32>) -> u32 {
    match best_measured {
        Some(best) => (best / 3).clamp(MIN_UNMEASURED_SCORE_CAP, UNMEASURED_SCORE_CAP),
        None => UNMEASURED_SCORE_CAP,
    }
}

/// 组内 max 的 EMA，跨轮次持久，避免瞬时抖动。
fn update_group_max_ema(map: &mut HashMap<String, f64>, group: &str, cur: f64) {
    if cur <= 0.0 {
        return;
    }
    let e = map.entry(group.to_string()).or_insert(0.0);
    *e = if *e == 0.0 { cur } else { *e * 0.9 + cur * 0.1 };
}

/// upstream 所属各组相对分的平均。
/// pick 是按 group 取候选池的，所以归一化必须按组做：全局 max 会把弱组整组压扁。
/// 多组链路在各自的池子里面对不同 max，取平均以在强组不被高估、弱组不被低估。
fn avg_relative_over_groups<F>(groups: &[String], mut score_of: F) -> Option<u32>
where
    F: FnMut(&str) -> Option<u32>,
{
    let mut sum = 0u64;
    let mut n = 0u64;
    for g in groups {
        if let Some(v) = score_of(g) {
            sum += v as u64;
            n += 1;
        }
    }
    (n > 0).then(|| (sum / n) as u32)
}

/// 将 f64 以 bits 形式存入 AtomicU64。
fn store_f64(a: &AtomicU64, v: f64) {
    a.store(v.to_bits(), Ordering::Relaxed);
}

/// 从 AtomicU64 读回 f64（以 bits 形式存储）。
fn load_f64(a: &AtomicU64) -> f64 {
    f64::from_bits(a.load(Ordering::Relaxed))
}

async fn check_upstream_health(
    up: &Upstream,
    fwmark: u32,
    creds: Option<(&str, &str)>,
    check_url: &str,
    timeout_secs: u64,
    tcp_nodelay: bool,
) -> bool {
    let target = Socks5Target::Domain(check_url, 80);

    let Ok(Ok(mut stream)) = timeout(
        Duration::from_secs(timeout_secs),
        socks5_connect(target, up.addr, fwmark, creds, tcp_nodelay),
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
                    c.tcp_nodelay,
                ) => r,
            };

            if alive {
                let failures = up.health_failures.swap(0, Ordering::Relaxed);
                // 只解除健康检查自己设置的冷却：业务建连失败设置的冷却由它自己的
                // TTL 过期。端口能握手不代表那条链路已经可用，别替它解除。
                up.clear_health_penalty();
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
                if f >= fail_threshold {
                    // 判死状态是粘住的，只会被成功探测清除，所以每轮重置分数即可。
                    // 首次跨阈值告警，之后只记 debug。
                    up.penalize_by_health();
                    if f == fail_threshold {
                        warn!(
                            id = %up.id,
                            failures = f,
                            threshold = fail_threshold,
                            "upstream health check dead, penalized"
                        );
                    } else {
                        debug!(
                            id = %up.id,
                            failures = f,
                            threshold = fail_threshold,
                            "upstream health check still dead"
                        );
                    }
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

/// 相对归一化评分任务：跨链路把实测吞吐速率与探针质量映射到相对分（0~1000）。
/// 仅在 enable_relative_scoring 开启时运行，替代绝对分段评分的 tcp/quic 分写入。
pub async fn run_relative_score_task(state: Arc<AppState>, cancel: CancellationToken) {
    let interval_secs = state.config.relative_rescore_interval_secs.max(1);
    let stale_secs = state.config.quic_stale_secs;
    info!(interval_secs, "relative score task started");
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // 每组 max 的 EMA，跨周期持久，避免瞬时抖动。
    // 归一化必须按组做：pick 是按 group 取候选池的，全局 max 会把弱组整组压扁。
    let mut max_rate_ema: HashMap<String, f64> = HashMap::new();
    let mut max_q_ema: HashMap<String, f64> = HashMap::new();

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("relative score task shutting down");
                break;
            }
            _ = interval.tick() => {},
        }

        let now = now_secs();
        let ups: Vec<Arc<Upstream>> = state.upstreams.iter().cloned().collect();

        // 1. 收集快照。None 表示本轮没有新鲜样本，与"样本值恰好为 0"是两回事。
        struct Snap {
            up: Arc<Upstream>,
            rate: Option<f64>,
            q: Option<f64>,
        }
        let mut snaps: Vec<Snap> = Vec::with_capacity(ups.len());
        for up in &ups {
            let rate_last = up.throughput_updated_secs.load(Ordering::Relaxed);
            let rate = (rate_last > 0 && now.saturating_sub(rate_last) < stale_secs)
                .then(|| load_f64(&up.throughput_rate_mibs));
            let q_last = up.probe_quality_updated_secs.load(Ordering::Relaxed);
            let q = (q_last > 0 && now.saturating_sub(q_last) < stale_secs)
                .then(|| load_f64(&up.probe_quality));
            snaps.push(Snap {
                up: Arc::clone(up),
                rate,
                q,
            });
        }

        // 2. 统计本轮各组 max，再对每组的 max 做 EMA
        let mut cur_max: HashMap<&str, (f64, f64)> = HashMap::new();
        for s in &snaps {
            for g in &s.up.groups {
                let e = cur_max.entry(g.as_str()).or_insert((0.0, 0.0));
                if let Some(rate) = s.rate {
                    e.0 = e.0.max(rate);
                }
                if let Some(q) = s.q {
                    e.1 = e.1.max(q);
                }
            }
        }
        for (g, (rate, q)) in &cur_max {
            update_group_max_ema(&mut max_rate_ema, g, *rate);
            update_group_max_ema(&mut max_q_ema, g, *q);
        }

        // 3. 写入相对分
        for snap in &snaps {
            let up = &snap.up;

            let rel_quic = snap.q.and_then(|q| {
                avg_relative_over_groups(&up.groups, |g| {
                    max_q_ema.get(g).map(|max| relative_score(q, *max))
                })
            });
            if let Some(rel) = rel_quic {
                up.quic_uplink_score.store(rel, Ordering::Relaxed);
                up.quic_downlink_score.store(rel, Ordering::Relaxed);
            }

            let rel_tcp = snap.rate.and_then(|rate| {
                avg_relative_over_groups(&up.groups, |g| {
                    max_rate_ema.get(g).map(|max| relative_score(rate, *max))
                })
            });
            if let Some(new) =
                next_tcp_score(up.tcp_score_raw(), up.tcp_score_initialized(), rel_tcp)
            {
                up.tcp_score.store(new, Ordering::Relaxed);
                up.tcp_score_initialized.store(true, Ordering::Relaxed);
            }
            // 本轮无样本时保留上一次实测值：不再写"乐观先验"，也不向 0 衰减。
            // 没有证据的链路保持未初始化，由 pick_score_based 的探索逻辑取样。
        }

        // 4. 按组给"零吞吐证据"的链路定上限
        let mut best_measured: HashMap<&str, u32> = HashMap::new();
        for s in &snaps {
            if !s.up.tcp_score_initialized() {
                continue;
            }
            let sc = s.up.score_at(now);
            for g in &s.up.groups {
                let e = best_measured.entry(g.as_str()).or_insert(0);
                *e = (*e).max(sc);
            }
        }
        for s in &snaps {
            if s.up.tcp_score_initialized() {
                continue;
            }
            // 多组链路取最保守的那个上限：只要它在任一有实测样本的组里，
            // 都不该压过该组的实测链路。已知取舍：它在"全未测组"里也会被这个
            // 较小的上限压住，权重低于该组内纯属本组的零样本链路；反之若取较大
            // 值，则会在这条链路的实测组里超配。单标量存不下两组不同的cap，
            // 需要按组存就得上 Map，代价是把 effective_score 变成依赖 group 的
            // 调用，pick 热路径与分数表都得跟着改。
            let cap =
                s.up.groups
                    .iter()
                    .filter_map(|g| best_measured.get(g.as_str()).copied())
                    .map(|best| unmeasured_cap_for(Some(best)))
                    .min()
                    .unwrap_or(UNMEASURED_SCORE_CAP);
            s.up.unmeasured_cap.store(cap, Ordering::Relaxed);
        }
    }
}

/// 定期打印所有 upstream 的详细分数信息（仅在 info 及以上日志级别启用时运行）
pub async fn run_score_printer(
    upstreams: Vec<Arc<Upstream>>,
    interval_secs: u64,
    cancel: CancellationToken,
) {
    // interval_secs = 0 表示禁用，直接返回
    if interval_secs == 0 {
        return;
    }

    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // 图例只在第一次输出分数表之前打印，避免每轮重复刷屏
    let mut legend_printed = false;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {},
        }

        if !tracing::enabled!(tracing::Level::INFO) {
            continue;
        }

        // 统一时间基准，确保同一轮计算基于同一时间点
        let now = now_secs();

        let mut scores: Vec<UpstreamScoreSnapshot> = Vec::new();
        for up in &upstreams {
            let quic_up_last = up.quic_uplink_last_update_secs();
            let quic_down_last = up.quic_downlink_last_update_secs();
            let rate_last = up.throughput_updated_secs.load(Ordering::Relaxed);
            let stale_secs = up.quic_stale_secs();
            scores.push(UpstreamScoreSnapshot {
                id: up.id.as_str(),
                tcp_raw: up.tcp_score_raw(),
                tcp_init: up.tcp_score_initialized(),
                quic_up_raw: up.quic_uplink_score_raw(),
                quic_up_age: if quic_up_last > 0 {
                    now.saturating_sub(quic_up_last)
                } else {
                    0
                },
                quic_up_init: quic_up_last > 0,
                quic_down_raw: up.quic_downlink_score_raw(),
                quic_down_age: if quic_down_last > 0 {
                    now.saturating_sub(quic_down_last)
                } else {
                    0
                },
                quic_down_init: quic_down_last > 0,
                // 原始实测速率（存 MiB/s，打印换算成 Mbps）：没有它，归一化后的 tcp 分无法自证
                rate_mibs: (rate_last > 0 && now.saturating_sub(rate_last) < stale_secs)
                    .then(|| load_f64(&up.throughput_rate_mibs)),
                eff_score: up.effective_score_at(now),
                gain: up.gain,
                groups: &up.groups,
                stale_secs,
            });
        }

        // 按 effective_score 降序排列
        scores.sort_by_key(|s| std::cmp::Reverse(s.eff_score));

        // 整轮只产生一条日志事件：多行内容在 logread 里仍然是一张对齐的表
        let mut msg = format!(
            "upstream scores ({}), sorted by effective score",
            scores.len()
        );
        if !legend_printed {
            msg.push('\n');
            msg.push_str(SCORE_TABLE_LEGEND);
            legend_printed = true;
        }
        msg.push('\n');
        msg.push_str(&format_score_table(&scores));
        info!("{}", msg.trim_end());
    }
}

/// 分数表的 flags 图例，仅在首次打印分数表之前输出一次。
const SCORE_TABLE_LEGEND: &str = concat!(
    "  flags: T=tcp U=quic-uplink D=quic-downlink !=stale ?=no-probe\n",
    "  age: seconds since last probe update as uplink/downlink, - = no sample\n",
    "  rate: measured per-connection downlink Mbps, - = no sample",
);

/// 所属组的展示文本；不属于任何组时与 rate/age 一致用 `-` 占位。
fn groups_label(groups: &[String]) -> String {
    if groups.is_empty() {
        "-".to_string()
    } else {
        groups.join(",")
    }
}

/// 把一轮分数快照渲染成对齐的表格，风格参考 `transmission-remote -pl` 的 peer 列表。
fn format_score_table(rows: &[UpstreamScoreSnapshot<'_>]) -> String {
    // 表头行固定占两字符，再按最长 id 自适应列宽
    let id_w = rows
        .iter()
        .map(|r| r.id.chars().count())
        .max()
        .unwrap_or(2)
        .max(2);
    let grp_w = rows
        .iter()
        .map(|r| groups_label(r.groups).chars().count())
        .max()
        .unwrap_or(3)
        .max(3);
    let mut out = format!(
        "  {id:<id_w$}  {flags:<5}  {score:>8}  {tcp:>4}  {qup:>4}  {qdn:>4}  {rate:>9}  {gain:>5}  {age:>7}  {grp:<grp_w$}\n",
        id = "id",
        flags = "flags",
        score = "score",
        tcp = "tcp",
        qup = "qup",
        qdn = "qdn",
        rate = "rate_mbps",
        gain = "gain",
        age = "age",
        grp = "grp",
        id_w = id_w,
        grp_w = grp_w,
    );

    for r in rows {
        let mut flags = String::with_capacity(5);
        if r.tcp_init {
            flags.push('T');
        }
        if r.quic_up_init {
            flags.push('U');
        }
        if r.quic_down_init {
            flags.push('D');
        }
        match (r.quic_up_init, r.quic_down_init) {
            (false, false) => flags.push('?'),
            _ => {
                let up_stale = r.quic_up_init && r.quic_up_age >= r.stale_secs;
                let down_stale = r.quic_down_init && r.quic_down_age >= r.stale_secs;
                if up_stale || down_stale {
                    flags.push('!');
                }
            }
        }

        let age = match (r.quic_up_init, r.quic_down_init) {
            (false, false) => "-".to_string(),
            // 固定 上行/下行 两段，避免 `-47` 被读成负数，也避免单向样本与双向同值混淆
            (true, false) => format!("{}/-", r.quic_up_age),
            (false, true) => format!("-/{}", r.quic_down_age),
            (true, true) if r.quic_up_age == r.quic_down_age => r.quic_up_age.to_string(),
            (true, true) => format!("{}/{}", r.quic_up_age, r.quic_down_age),
        };

        let rate = match r.rate_mibs {
            Some(v) => format!("{:.2}", v * MIB_TO_MBPS),
            None => "-".to_string(),
        };

        out.push_str(&format!(
            "  {id:<id_w$}  {flags:<5}  {score:>8}  {tcp:>4}  {qup:>4}  {qdn:>4}  {rate:>9}  {gain:>5.2}  {age:>7}  {grp:<grp_w$}\n",
            id = r.id,
            flags = flags,
            score = r.eff_score,
            tcp = r.tcp_raw,
            qup = r.quic_up_raw,
            qdn = r.quic_down_raw,
            rate = rate,
            gain = r.gain,
            age = age,
            grp = groups_label(r.groups),
            id_w = id_w,
            grp_w = grp_w,
        ));
    }

    out
}

/// 单个 upstream 的分数快照，用于调试打印
struct UpstreamScoreSnapshot<'a> {
    id: &'a str,
    tcp_raw: u32,
    tcp_init: bool,
    quic_up_raw: u32,
    quic_up_age: u64,
    quic_up_init: bool,
    quic_down_raw: u32,
    quic_down_age: u64,
    quic_down_init: bool,
    rate_mibs: Option<f64>,
    eff_score: u64,
    gain: f64,
    groups: &'a [String],
    stale_secs: u64,
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
        up.quic_uplink_last_update_secs
            .store(now_secs(), Ordering::Relaxed);
    }

    fn set_quic_downlink(up: &Upstream, score: u32) {
        up.quic_downlink_score.store(score, Ordering::Relaxed);
        up.quic_downlink_last_update_secs
            .store(now_secs(), Ordering::Relaxed);
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
    fn penalize_sets_all_to_default() {
        let up = make_upstream("e");
        up.penalize();
        assert_eq!(up.tcp_score.load(Ordering::Relaxed), DEFAULT_SCORE);
        assert!(up.tcp_score_initialized.load(Ordering::Relaxed));
        assert_eq!(up.quic_uplink_score.load(Ordering::Relaxed), DEFAULT_SCORE);
        assert_eq!(
            up.quic_downlink_score.load(Ordering::Relaxed),
            DEFAULT_SCORE
        );
    }

    #[test]
    fn quic_score_decays_linearly() {
        let up = make_upstream("stale");
        set_tcp_score(&up, 800);
        // 设置 QUIC 分数，但 last_update 在过期阈值 / 2 秒前
        let half_stale = now_secs() - DEFAULT_QUIC_STALE_SECS / 2;
        up.quic_uplink_score.store(800, Ordering::Relaxed);
        up.quic_uplink_last_update_secs
            .store(half_stale, Ordering::Relaxed);
        up.quic_downlink_score.store(800, Ordering::Relaxed);
        up.quic_downlink_last_update_secs
            .store(half_stale, Ordering::Relaxed);

        let s = up.score();
        // QUIC 方向经过半衰期衰减：800 * 0.5 = 400
        // tcp=800, quic=400, qw=40 => (800*60 + 400*40)/100 = 640
        assert!(s < 650 && s > 630, "expected ~640, got {s}");
    }

    #[test]
    fn quic_score_minimal_when_stale() {
        let up = make_upstream("dead");
        set_tcp_score(&up, 800);
        // last_update 超过过期阈值
        let old = now_secs() - DEFAULT_QUIC_STALE_SECS - 10;
        up.quic_uplink_score.store(800, Ordering::Relaxed);
        up.quic_uplink_last_update_secs
            .store(old, Ordering::Relaxed);
        up.quic_downlink_score.store(800, Ordering::Relaxed);
        up.quic_downlink_last_update_secs
            .store(old, Ordering::Relaxed);

        let s = up.score();
        // QUIC 衰减到最低分 MINIMAL_SCORE(10)，仍参与加权：(800*60 + 10*40)/100 = 484
        assert_eq!(s, 484, "expected 484, got {s}");
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
        UpstreamSet::new(items, tolerance, 40, DEFAULT_QUIC_STALE_SECS, 0).unwrap()
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
        let set = UpstreamSet::new(items.clone(), 50, 40, DEFAULT_QUIC_STALE_SECS, 0).unwrap();

        // 全部标记已初始化，否则 pick_score_based 的探索分支会以小概率
        // 无视 sticky 均匀随机选中 b/d，导致本测试偶发失败
        for u in &items {
            set_tcp_score(u, 500);
        }

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

    // ---------- 选路策略 ----------

    fn strategies(pairs: &[(&str, UpstreamStrategy)]) -> HashMap<String, UpstreamStrategy> {
        pairs.iter().map(|(g, s)| ((*g).to_string(), *s)).collect()
    }

    fn strategy_pick_seq(set: &UpstreamSet, group: &str, n: usize) -> Vec<String> {
        (0..n)
            .map(|_| set.pick_from_group(group).unwrap().id.clone())
            .collect()
    }

    #[test]
    fn strategy_for_falls_back_to_default_key() {
        let set = upstream_set(&["a", "b"], 0);
        assert_eq!(set.strategy_for("default"), UpstreamStrategy::Weighted);
        assert_eq!(set.strategy_for("missing"), UpstreamStrategy::Weighted);

        // `default` 键既给 default 分组，也给所有未列出的分组兜底
        let set = set.with_group_strategies(strategies(&[
            ("default", UpstreamStrategy::Lru),
            ("office", UpstreamStrategy::Rr),
        ]));
        assert_eq!(set.strategy_for("default"), UpstreamStrategy::Lru);
        assert_eq!(set.strategy_for("cn"), UpstreamStrategy::Lru);
        assert_eq!(set.strategy_for("office"), UpstreamStrategy::Rr);
    }

    #[test]
    fn rr_strategy_cycles_in_order() {
        let set = upstream_set(&["a", "b", "c"], 0)
            .with_group_strategies(strategies(&[("default", UpstreamStrategy::Rr)]));
        assert_eq!(
            strategy_pick_seq(&set, "default", 7),
            vec!["a", "b", "c", "a", "b", "c", "a"]
        );
    }

    #[test]
    fn random_strategy_ignores_scores() {
        let set = upstream_set(&["a", "b"], 0)
            .with_group_strategies(strategies(&[("default", UpstreamStrategy::Random)]));
        for u in set.iter() {
            set_tcp_score(u, if u.id == "a" { 900 } else { 100 });
        }
        let mut counts: HashMap<String, usize> = HashMap::new();
        for _ in 0..400 {
            *counts.entry(set.pick().unwrap().id.clone()).or_insert(0) += 1;
        }
        // 均匀随机：低分链路应拿到接近一半的选中次数，而不是被高分链路挤掉
        assert!(
            counts.get("b").copied().unwrap_or(0) > 100,
            "低分链路几乎没被选中: {counts:?}"
        );
    }

    #[test]
    fn best_strategy_always_picks_top_score() {
        let set = upstream_set(&["a", "b"], 0)
            .with_group_strategies(strategies(&[("default", UpstreamStrategy::Best)]));
        for u in set.iter() {
            set_tcp_score(u, if u.id == "a" { 200 } else { 900 });
        }
        for _ in 0..50 {
            assert_eq!(set.pick().unwrap().id, "b");
        }
    }

    #[test]
    fn draw_weights_are_squared_not_linear() {
        // 75 vs 225（gain 3）：平方权重 5625 : 50625 = 1:9。
        //
        // 抓线性权重回归靠两条断言，缺一不可：
        // 1. 总权重：平方 56250，线性只有 300；
        // 2. 边界：rand = 5624 必须落在下标 0。线性权重下（总 300）5624 % 300 = 224，
        //    已经跨过 75 的分界落到下标 1，断言失败。
        // 单看 rand = 5625 不够——取模后线性权重也可能恰好落到下标 1。
        let scores = [75, 225];
        let total = squared_weight_total(&scores);
        assert_eq!(total, 56_250, "平方权重的总权重");
        assert_eq!(draw_index_by_squared_score(&scores, 0), Some(0));
        assert_eq!(
            draw_index_by_squared_score(&scores, 5_624),
            Some(0),
            "5624 < 5625：平方权重下仍在下标 0 的区间里"
        );
        assert_eq!(draw_index_by_squared_score(&scores, 5_625), Some(1));
        assert_eq!(draw_index_by_squared_score(&scores, total - 1), Some(1));

        // 分数全零：没有可加权项，交由调用方退化处理
        assert_eq!(draw_index_by_squared_score(&[0, 0], 0), None);
    }

    #[test]
    fn weighted_without_scores_is_uniform_when_gains_are_equal() {
        // 关闭评分时所有链路停在基础分：gain 相同 → 平方权重相同 → 组内均匀随机
        let set = upstream_set(&["a", "b"], 0);
        for u in set.iter() {
            set_tcp_score(u, DEFAULT_SCORE);
        }
        let mut counts: HashMap<String, usize> = HashMap::new();
        for _ in 0..400 {
            *counts.entry(set.pick().unwrap().id.clone()).or_insert(0) += 1;
        }
        assert!(
            counts.get("a").copied().unwrap_or(0) > 100
                && counts.get("b").copied().unwrap_or(0) > 100,
            "gain 相同时应均摊: {counts:?}"
        );
    }

    #[test]
    fn weighted_without_scores_still_follows_gain() {
        // 同为基础分，但 gain 不同 → 平方加权仍然生效，不是"均匀随机"。
        // 注意 set_tcp_score 会把链路标记为已测量，因此这里没有 5% 探索干扰，
        // 期望命中率就是平方权重的 90%；线性权重只有 75%，用 82% 作分界。
        let items = vec![
            Upstream::new(
                "plain",
                "127.0.0.1:1080".parse().unwrap(),
                vec!["default".to_string()],
                1.0,
            ),
            Upstream::new(
                "boosted",
                "127.0.0.1:1081".parse().unwrap(),
                vec!["default".to_string()],
                3.0,
            ),
        ];
        let set = UpstreamSet::new(items, 0, 40, DEFAULT_QUIC_STALE_SECS, 0).unwrap();
        for u in set.iter() {
            set_tcp_score(u, DEFAULT_SCORE);
        }

        let mut boosted = 0usize;
        let rounds = 1000;
        for _ in 0..rounds {
            if set.pick().unwrap().id == "boosted" {
                boosted += 1;
            }
        }
        // 权重 75² : (75×3)² = 1:9，期望 900/1000；线性权重只会到 750
        assert!(
            boosted > 820,
            "gain 3 的命中率应接近平方权重的 90%，实际 {boosted}/{rounds}"
        );
    }

    #[test]
    fn exploration_precedes_sticky_on_unmeasured_links() {
        // 两条都未测量、分数全等、tolerance > 0：探索分支排在粘性之前，
        // 因此两个 id 都会出现。若哪天把探索挪到粘性之后，新链路会被粘性饿死，
        // 这条断言就会失败——这正是顺序契约。
        let set = upstream_set(&["a", "b"], 50);
        let mut seen = HashSet::new();
        for _ in 0..800 {
            seen.insert(set.pick().unwrap().id.clone());
        }
        assert_eq!(seen.len(), 2, "探索应能绕过粘性给新链路引流: {seen:?}");
    }

    #[test]
    fn tolerance_keeps_sticky_even_without_scores() {
        // 关闭评分 + 非零容忍度：分数全等也仍然粘住当前链路
        let set = upstream_set(&["a", "b"], 50);
        for u in set.iter() {
            set_tcp_score(u, DEFAULT_SCORE);
        }
        let first = set.pick().unwrap().id.clone();
        for _ in 0..20 {
            assert_eq!(
                set.pick().unwrap().id,
                first,
                "tolerance > 0 时分数全等也应粘住"
            );
        }
    }

    #[test]
    fn best_strategy_breaks_ties_randomly() {
        let set = upstream_set(&["a", "b"], 0)
            .with_group_strategies(strategies(&[("default", UpstreamStrategy::Best)]));
        for u in set.iter() {
            set_tcp_score(u, 500);
        }
        let mut seen = HashSet::new();
        for _ in 0..200 {
            seen.insert(set.pick().unwrap().id.clone());
        }
        assert_eq!(
            seen.len(),
            2,
            "同分时应随机打破，而不是固定选同一条: {seen:?}"
        );
    }

    #[test]
    fn lru_strategy_cycles_least_recently_used() {
        let set = upstream_set(&["a", "b", "c"], 0)
            .with_group_strategies(strategies(&[("default", UpstreamStrategy::Lru)]));
        let ids = strategy_pick_seq(&set, "default", 4);
        let mut first_round = ids[..3].to_vec();
        first_round.sort();
        assert_eq!(first_round, vec!["a", "b", "c"], "首轮应覆盖全部链路");
        assert_eq!(ids[3], ids[0], "第 4 次应回到最久未使用的链路");
    }

    #[test]
    fn least_conn_prefers_idle_upstream() {
        let set = upstream_set(&["a", "b"], 0)
            .with_group_strategies(strategies(&[("default", UpstreamStrategy::LeastConn)]));
        let a = set.find_by_id("a").unwrap();
        let t1 = a.track(1);
        let t2 = a.track(2);
        assert_eq!(a.active_conns(), 2);
        for _ in 0..10 {
            assert_eq!(set.pick().unwrap().id, "b");
        }

        drop(t1);
        drop(t2);
        assert_eq!(a.active_conns(), 0);
        let mut counts: HashMap<String, usize> = HashMap::new();
        for _ in 0..200 {
            *counts.entry(set.pick().unwrap().id.clone()).or_insert(0) += 1;
        }
        assert!(
            counts.get("a").copied().unwrap_or(0) > 40,
            "负载相同时两条链路都应被选中: {counts:?}"
        );
    }

    #[test]
    fn group_strategy_override_applies() {
        let items = vec![
            upstream_with_groups("a", vec!["default".to_string(), "office".to_string()]),
            upstream_with_groups("b", vec!["default".to_string(), "office".to_string()]),
            upstream_with_groups("c", vec!["office".to_string()]),
        ];
        let set = UpstreamSet::new(items, 0, 40, DEFAULT_QUIC_STALE_SECS, 0)
            .unwrap()
            .with_group_strategies(strategies(&[
                ("default", UpstreamStrategy::Random),
                ("office", UpstreamStrategy::Rr),
            ]));

        assert_eq!(set.strategy_for("default"), UpstreamStrategy::Random);
        assert_eq!(set.strategy_for("office"), UpstreamStrategy::Rr);
        assert_eq!(
            strategy_pick_seq(&set, "office", 3),
            vec!["a", "b", "c"],
            "office 组应走轮询"
        );
    }

    #[test]
    fn penalized_upstream_skipped_when_alternative_exists() {
        let set = upstream_set(&["a", "b"], 0)
            .with_group_strategies(strategies(&[("default", UpstreamStrategy::Rr)]));
        set.find_by_id("a").unwrap().penalize();
        for _ in 0..4 {
            assert_eq!(set.pick().unwrap().id, "b");
        }

        // 全组都在冷却期时不做过滤，否则整组直接不可用
        set.find_by_id("b").unwrap().penalize();
        assert!(set.pick().is_some());
    }

    #[test]
    fn penalize_cooldown_expires() {
        let up = upstream("a");
        let now = now_secs();
        assert!(!up.is_penalized_at(now));

        up.penalize();
        assert!(up.is_penalized_at(now));
        assert!(
            !up.is_penalized_at(now + PENALIZE_COOLDOWN_SECS + 1),
            "冷却期过后应自动回池"
        );
    }

    #[test]
    fn health_recovery_only_clears_its_own_cooldown() {
        let up = upstream("a");
        let now = now_secs();

        // 健康检查判死 → 恢复：解除
        up.penalize_by_health();
        assert!(up.is_penalized_at(now));
        up.clear_health_penalty();
        assert!(!up.is_penalized_at(now));

        // 业务失败 → 健康检查恢复：不得解除业务设置的冷却
        up.penalize();
        up.clear_health_penalty();
        assert!(
            up.is_penalized_at(now),
            "健康检查恢复不应替业务连接失败解除冷却"
        );
    }

    #[test]
    fn health_dead_state_is_sticky_until_a_successful_check() {
        let up = upstream("a");
        let far_future = now_secs() + PENALIZE_COOLDOWN_SECS * 1000;

        up.penalize_by_health();
        assert!(
            up.is_penalized_at(far_future),
            "健康判死没有 TTL，不能因为时间流逝自动回池"
        );

        up.clear_health_penalty();
        assert!(!up.is_penalized_at(far_future), "成功探测后才回池");
    }

    #[test]
    fn health_dead_link_is_avoided_until_cleared() {
        // 组内还有健康候选时一律避让判死链路；全组判死时回退到完整候选池
        let set = upstream_set(&["a", "b"], 0)
            .with_group_strategies(strategies(&[("default", UpstreamStrategy::Rr)]));
        let a = set.find_by_id("a").unwrap();
        let b = set.find_by_id("b").unwrap();

        a.penalize_by_health();
        for _ in 0..6 {
            assert_eq!(set.pick().unwrap().id, "b", "判死链路应被避开");
        }

        b.penalize_by_health();
        assert!(set.pick().is_some(), "全组判死时应回退到完整候选池");

        // a 解除判死后应是唯一未被避让的候选（b 仍判死），轮到它接流量
        a.clear_health_penalty();
        assert_eq!(set.pick().unwrap().id, "a", "恢复后的链路应重新参与选路");
    }

    #[test]
    fn health_recovery_keeps_business_cooldown_interleaved() {
        // 交错场景：健康检查只失败一次（未达阈值、没设置冷却），随后业务连接失败
        // 设置冷却，下一轮健康检查成功。不能把业务设置的冷却一起清掉。
        let up = upstream("a");
        let now = now_secs();

        up.health_failures.store(1, Ordering::Relaxed); // 未达阈值的失败
        up.penalize(); // 业务连接失败
        up.clear_health_penalty(); // 健康检查本轮成功
        assert!(
            up.is_penalized_at(now),
            "未达阈值的健康检查失败不应成为解除业务冷却的依据"
        );

        // 反过来：健康检查确实判死过，之后业务也失败，恢复只清健康检查那份
        up.penalize_by_health();
        up.penalize();
        up.clear_health_penalty();
        assert!(up.is_penalized_at(now), "业务失败设置的冷却仍在");
    }

    #[test]
    fn track_prunes_dead_entries_without_score_task() {
        // disable_upstream_score 模式下没有采样任务定期清理，track() 必须自己回收，
        // 否则 least_conn 的扫描成本会随历史连接数无界增长。
        let up = upstream("a");
        for _ in 0..1000 {
            drop(up.track(1));
        }
        assert_eq!(up.active_conns(), 0);
        assert!(
            up.lock_registry().len() < REGISTRY_PRUNE_EVERY as usize * 2,
            "死条目未被回收: {}",
            up.lock_registry().len()
        );
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
        let set = UpstreamSet::new(items, 0, 40, DEFAULT_QUIC_STALE_SECS, 0).unwrap();

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
        let set = UpstreamSet::new(items, 50, 40, DEFAULT_QUIC_STALE_SECS, 0).unwrap();

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
        let set2 = UpstreamSet::new(items2, 50, 40, DEFAULT_QUIC_STALE_SECS, 0).unwrap();
        {
            let mut cur = set2.current.lock().unwrap();
            cur.insert("default".to_string(), Some("a".to_string()));
        }
        // a effective=500, b effective=1500, diff=1000 > 50
        let picked = set2.pick().unwrap();
        assert_eq!(picked.id, "b", "should switch due to higher gain");
    }

    // ---------- QUIC 衰减逻辑一致性 ----------

    /// 手动设置 QUIC 分数和时间戳（绕过冷却）
    fn set_quic_uplink_at(up: &Upstream, score: u32, last_update: u64) {
        up.quic_uplink_score.store(score, Ordering::Relaxed);
        up.quic_uplink_last_update_secs
            .store(last_update, Ordering::Relaxed);
    }

    fn set_quic_downlink_at(up: &Upstream, score: u32, last_update: u64) {
        up.quic_downlink_score.store(score, Ordering::Relaxed);
        up.quic_downlink_last_update_secs
            .store(last_update, Ordering::Relaxed);
    }

    #[test]
    fn quic_score_effective_at_averages_both_links() {
        let up = make_upstream("decay_test");
        let now = 1_000_000;

        set_tcp_score(&up, 500);
        set_quic_uplink_at(&up, 800, now);
        set_quic_downlink_at(&up, 600, now);

        let quic_eff = up.quic_score_effective_at(now);
        assert_eq!(quic_eff, 700, "expected (800+600)/2 = 700");

        // 验证综合分
        let score = up.score_at(now);
        assert_eq!(score, 580, "expected (500*60 + 700*40)/100 = 580");
    }

    #[test]
    fn quic_score_effective_at_with_stale() {
        let up = make_upstream("stale_test");
        let now = 1_000_000;
        let old = now - DEFAULT_QUIC_STALE_SECS - 10;

        set_tcp_score(&up, 500);
        set_quic_uplink_at(&up, 800, old);
        set_quic_downlink_at(&up, 600, old);

        let quic_eff = up.quic_score_effective_at(now);
        // 超过过期阈值，应该降到 MINIMAL_SCORE
        assert_eq!(quic_eff, MINIMAL_SCORE, "expected MINIMAL_SCORE when stale");
    }

    #[test]
    fn quic_score_effective_at_partial_decay() {
        let up = make_upstream("partial_decay");
        let now = 1_000_000;
        // 90 秒前更新（半衰期）
        let half_stale = now - DEFAULT_QUIC_STALE_SECS / 2;

        set_tcp_score(&up, 500);
        set_quic_uplink_at(&up, 800, half_stale);
        set_quic_downlink_at(&up, 800, half_stale);

        let quic_eff = up.quic_score_effective_at(now);
        // 半衰期：800 * 0.5 = 400
        assert_eq!(quic_eff, 400, "expected 800 * 0.5 = 400 at half stale");
    }

    #[test]
    fn score_at_consistent_with_quic_effective() {
        let up = make_upstream("consistency_test");
        let now = 1_000_000;

        set_tcp_score(&up, 500);
        set_quic_uplink_at(&up, 800, now);

        let quic_eff = up.quic_score_effective_at(now);
        let score = up.score_at(now);

        // 只有 uplink 有效，quic = uplink = 800
        assert_eq!(quic_eff, 800);
        // (500 * 60 + 800 * 40) / 100 = 620
        assert_eq!(score, 620);
    }

    // ---------- effective_score_at ----------

    #[test]
    fn effective_score_at_uses_fixed_time() {
        let up = make_upstream("time_consistent");
        let now = 1_000_000;

        set_tcp_score(&up, 500);
        set_quic_uplink_at(&up, 500, now);

        let eff_at = up.effective_score_at(now);
        let score = up.score_at(now);

        // effective_score = score * gain = 500 * 1.0 = 500
        assert_eq!(eff_at, score as u64);
    }

    // ---------- interval_secs = 0 ----------

    #[tokio::test]
    async fn score_printer_exits_on_zero_interval() {
        let up = make_upstream("test");
        let upstreams = vec![up];
        let cancel = CancellationToken::new();

        // interval_secs = 0 应该立即返回
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            run_score_printer(upstreams, 0, cancel),
        )
        .await;
        assert!(
            result.is_ok(),
            "should exit immediately when interval_secs = 0"
        );
    }

    #[tokio::test]
    async fn score_printer_exits_on_cancel() {
        let up = make_upstream("test");
        let upstreams = vec![up];
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            run_score_printer(upstreams, 5, cancel_clone).await;
        });

        // 立即取消，任务进入 select! 后会发现取消状态
        cancel.cancel();

        // 验证：1) 一秒内退出 2) 没有 panic
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("task should exit within timeout")
            .expect("task should not panic");
    }

    // ---------- format_score_table ----------

    #[test]
    fn score_table_renders_flags_columns_and_alignment() {
        let poe_default = vec!["poe".to_string(), "default".to_string()];
        let youtube = vec!["youtube".to_string()];
        let gemini = vec!["gemini".to_string()];
        let no_group: Vec<String> = Vec::new();
        let rows = vec![
            UpstreamScoreSnapshot {
                id: "fast",
                tcp_raw: 942,
                tcp_init: true,
                quic_up_raw: 40,
                quic_up_age: 0,
                quic_up_init: true,
                quic_down_raw: 40,
                quic_down_age: 0,
                quic_down_init: true,
                rate_mibs: Some(12.345),
                eff_score: 491,
                gain: 0.85,
                groups: &poe_default,
                stale_secs: 180,
            },
            UpstreamScoreSnapshot {
                id: "stale_link",
                tcp_raw: 75,
                tcp_init: true,
                quic_up_raw: 498,
                quic_up_age: 200,
                quic_up_init: true,
                quic_down_raw: 498,
                quic_down_age: 200,
                quic_down_init: true,
                rate_mibs: Some(0.5),
                eff_score: 212,
                gain: 1.1,
                groups: &youtube,
                stale_secs: 180,
            },
            UpstreamScoreSnapshot {
                id: "down_only",
                tcp_raw: 75,
                tcp_init: false,
                quic_up_raw: 75,
                quic_up_age: 0,
                quic_up_init: false,
                quic_down_raw: 108,
                quic_down_age: 47,
                quic_down_init: true,
                rate_mibs: None,
                eff_score: 54,
                gain: 1.0,
                groups: &no_group,
                stale_secs: 180,
            },
            UpstreamScoreSnapshot {
                id: "up_only",
                tcp_raw: 75,
                tcp_init: true,
                quic_up_raw: 301,
                quic_up_age: 47,
                quic_up_init: true,
                quic_down_raw: 75,
                quic_down_age: 0,
                quic_down_init: false,
                rate_mibs: Some(3.0),
                eff_score: 173,
                gain: 1.0,
                groups: &gemini,
                stale_secs: 180,
            },
            UpstreamScoreSnapshot {
                id: "no_sample",
                tcp_raw: DEFAULT_SCORE,
                tcp_init: false,
                quic_up_raw: DEFAULT_SCORE,
                quic_up_age: 0,
                quic_up_init: false,
                quic_down_raw: DEFAULT_SCORE,
                quic_down_age: 0,
                quic_down_init: false,
                rate_mibs: None,
                eff_score: DEFAULT_SCORE as u64,
                gain: 1.0,
                groups: &poe_default,
                stale_secs: 180,
            },
        ];

        let table = format_score_table(&rows);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 6);

        // 所有行等宽，保证表头与各数值列对齐
        assert!(
            lines
                .iter()
                .all(|l| l.chars().count() == lines[0].chars().count()),
            "rows must share the same width:\n{table}"
        );
        assert!(lines[0].contains("flags") && lines[0].contains("score"));
        assert!(lines[0].contains("rate") && lines[0].contains("grp"));

        let fast: Vec<&str> = lines[1].split_whitespace().collect();
        assert_eq!(
            fast,
            [
                "fast",
                "TUD",
                "491",
                "942",
                "40",
                "40",
                "103.56",
                "0.85",
                "0",
                "poe,default"
            ]
        );

        // 超过 stale 阈值追加 !
        let stale: Vec<&str> = lines[2].split_whitespace().collect();
        assert_eq!(stale[1], "TUD!");
        assert_eq!(stale[5], "498");
        assert_eq!(stale[8], "200");

        // 只有下行样本：flags 无 T/U，age 固定 上行/下行 两段，`-` 占位
        let down_only: Vec<&str> = lines[3].split_whitespace().collect();
        assert_eq!(down_only[1], "D");
        assert_eq!(down_only[6], "-");
        assert_eq!(down_only[8], "-/47");

        // 只有上行样本：不能与"上下行同为 47 秒"混淆
        let up_only: Vec<&str> = lines[4].split_whitespace().collect();
        assert_eq!(up_only[1], "TU");
        assert_eq!(up_only[8], "47/-");

        // 无任何样本
        let no_sample: Vec<&str> = lines[5].split_whitespace().collect();
        assert_eq!(no_sample[1], "?");
        assert_eq!(no_sample[6], "-");
        assert_eq!(no_sample[8], "-");

        // 不属于任何组时与 rate/age 一致，用 `-` 占位
        assert_eq!(down_only[9], "-");
        assert_eq!(fast[9], "poe,default");
    }

    // ---------- per-connection rate / relative scoring ----------

    #[test]
    fn byte_weighted_rate_tracks_the_fattest_connection() {
        let mib = 1024 * 1024u128;
        let kib = 1024u128;

        // 单连接：退化为它自己的速率
        assert!((byte_weighted_mib_per_sec(2 * mib, (2 * mib) * (2 * mib), 1) - 2.0).abs() < 1e-9);

        // 10 条各 1MiB/s：仍是 1MiB/s，不随并发数放大
        let d = mib;
        let (sum_d, sum_sq) = (10 * d, 10 * d * d);
        assert!((byte_weighted_mib_per_sec(sum_d, sum_sq, 1) - 1.0).abs() < 1e-9);

        // 1 条 2MiB/s + 9 条 5KiB/s：接近那条大流，而不是被拉低到 0.2
        let big = 2 * mib;
        let small = 5 * kib;
        let (sum_d, sum_sq) = (big + 9 * small, big * big + 9 * small * small);
        let r = byte_weighted_mib_per_sec(sum_d, sum_sq, 1);
        assert!(
            r > 1.9 && r < 2.0,
            "fat connection should dominate, got {r}"
        );

        // 无数据时不除零
        assert_eq!(byte_weighted_mib_per_sec(0, 0, 0), 0.0);
    }

    #[test]
    fn unmeasured_cap_follows_group_best() {
        // 组内没有实测样本：用默认上限，让未测量链路彼此公平竞争
        assert_eq!(unmeasured_cap_for(None), UNMEASURED_SCORE_CAP);
        // 组内最佳实测 979 → 上限 326，平方加权下实测链路约拿 2/3 权重
        assert_eq!(unmeasured_cap_for(Some(979)), 979 / 3);
        // 组内唯一实测链路很差（18 分）：落到下限，否则探索空间被彻底掐死
        assert_eq!(unmeasured_cap_for(Some(18)), MIN_UNMEASURED_SCORE_CAP);
        // 不超过默认上限
        assert_eq!(unmeasured_cap_for(Some(10_000)), UNMEASURED_SCORE_CAP);
    }

    #[test]
    fn probe_only_score_is_capped_until_throughput_is_measured() {
        let up = Upstream::new(
            "probe_only",
            "127.0.0.1:20808".parse().unwrap(),
            vec!["poe".to_string()],
            1.0,
        );
        up.set_quic_weight(100); // 让综合分完全由 quic 决定
        up.quic_downlink_score.store(1000, Ordering::Relaxed);
        up.quic_downlink_last_update_secs
            .store(now_secs(), Ordering::Relaxed);

        // 只有探针分：被限幅，不能拿到满权重
        assert_eq!(up.score(), UNMEASURED_SCORE_CAP);
        assert!(!up.tcp_score_initialized());

        // 有了真实吞吐样本后不再受限
        up.tcp_score.store(900, Ordering::Relaxed);
        up.tcp_score_initialized.store(true, Ordering::Relaxed);
        assert_eq!(up.score(), 1000);
    }

    #[test]
    fn tcp_score_without_sample_keeps_old_value() {
        // 本轮无样本 = 无新证据，必须保留旧值（返回 None），不能当成 0 分
        assert_eq!(next_tcp_score(977, true, None), None);
        assert_eq!(next_tcp_score(0, false, None), None);
        // 首次拿到样本直接采用，不被默认分稀释
        assert_eq!(next_tcp_score(DEFAULT_SCORE, false, Some(800)), Some(800));
        // 已有样本时缓慢跟随，1/8 步长
        assert_eq!(next_tcp_score(800, true, Some(0)), Some(700));
        assert_eq!(next_tcp_score(0, true, Some(800)), Some(100));
        // 四舍五入：差值小于 8 时也要动，不能因整除截断卡死
        assert_eq!(next_tcp_score(993, true, Some(1000)), Some(994));
        assert_eq!(next_tcp_score(994, true, Some(1000)), Some(995));
    }

    #[test]
    fn rate_ema_overrides_stale_sample_instead_of_blending() {
        // 新鲜样本：50/50 混合
        assert!((blend_rate_mibs(2.0, 100, 110, 480, 4.0) - 3.0).abs() < 1e-9);
        // 首次采样（从未更新过）：直接覆盖
        assert!((blend_rate_mibs(0.0, 0, 110, 480, 4.0) - 4.0).abs() < 1e-9);
        // 旧值已过期：直接覆盖，不被几小时前的速率拉偏一半
        assert!((blend_rate_mibs(2.0, 100, 100 + 480, 480, 4.0) - 4.0).abs() < 1e-9);
    }

    #[test]
    fn fd_sample_first_read_only_establishes_baseline() {
        // 新连接第一次采样时可能一个字节都没收到，0 必须是合法基线，
        // 不能被当成"未初始化"而把后续突发永久跳过。
        let sample = FdSample {
            fd: -1,
            last_recv: AtomicU64::new(UNINIT_RECV),
        };
        assert_eq!(sample.last_recv.swap(0, Ordering::Relaxed), UNINIT_RECV);
        assert_eq!(sample.last_recv.swap(2 * 1024 * 1024, Ordering::Relaxed), 0);
    }

    #[test]
    fn relative_score_is_normalized_per_group() {
        let groups = vec!["poe".to_string(), "youtube".to_string()];
        let max_rate: HashMap<String, f64> = [
            // poe 组最强 10MiB/s，youtube 组最强 2MiB/s
            ("poe".to_string(), 10.0),
            ("youtube".to_string(), 2.0),
        ]
        .into_iter()
        .collect();
        // 同一速率在两组里的相对分不同：2MiB/s 在 poe 是 200，在 youtube 是 1000
        assert_eq!(
            avg_relative_over_groups(&groups, |g| max_rate
                .get(g)
                .map(|max| relative_score(2.0, *max))),
            Some((200 + 1000) / 2)
        );
        // 不在任何组里时没有相对分
        assert_eq!(avg_relative_over_groups(&[], |_| Some(500)), None);
        // 组内无 max（无样本）时返回 None，而不是 0
        let empty: HashMap<String, f64> = HashMap::new();
        assert_eq!(
            avg_relative_over_groups(&groups, |g| empty
                .get(g)
                .map(|max| relative_score(1.0, *max))),
            None
        );
    }

    #[test]
    fn group_max_ema_ignores_empty_rounds() {
        let mut map: HashMap<String, f64> = HashMap::new();
        update_group_max_ema(&mut map, "poe", 10.0);
        assert_eq!(map.get("poe"), Some(&10.0));
        // 本轮无样本不得把 max 拉向 0
        update_group_max_ema(&mut map, "poe", 0.0);
        assert_eq!(map.get("poe"), Some(&10.0));
        // 有样本时按 9:1 向新值靠拢
        update_group_max_ema(&mut map, "poe", 20.0);
        assert!((map["poe"] - 11.0).abs() < 1e-9);
    }

    // ---------- PickStats ----------
    #[test]
    fn pick_stats_record_and_count() {
        let ids: Vec<String> = ["vmshell", "vmshell_1444"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let stats = PickStats::new(1800, ids);
        stats.record_at(100, 0);
        stats.record_at(101, 0);
        stats.record_at(102, 1);
        let counts = stats.counts();
        assert_eq!(counts.len(), 2);
        // 按次数降序
        assert_eq!(counts[0], ("vmshell".to_string(), 2));
        assert_eq!(counts[1], ("vmshell_1444".to_string(), 1));
    }

    #[test]
    fn pick_stats_bucket_eviction() {
        // 桶宽 10 秒，窗口 30 秒
        let ids: Vec<String> = ["bbr", "brutal"].iter().map(|s| s.to_string()).collect();
        let stats = PickStats::new(30, ids);

        // t=1：0-9 秒桶，bbr 两次
        stats.record_at(1, 0);
        stats.record_at(8, 0);
        // t=12：10-19 秒桶，brutal 一次
        stats.record_at(12, 1);
        assert_eq!(
            stats.counts(),
            vec![("bbr".to_string(), 2), ("brutal".to_string(), 1)]
        );

        // t=41：窗口 30 秒，0-9 秒桶应被淘汰（end=10 <= cutoff=11）
        stats.record_at(41, 1);
        assert_eq!(stats.counts(), vec![("brutal".to_string(), 2)]);
    }

    #[test]
    fn pick_stats_cross_multiple_buckets() {
        let ids: Vec<String> = ["a"].iter().map(|s| s.to_string()).collect();
        let stats = PickStats::new(100, ids);

        // 跨越多个桶
        for t in [5, 15, 25, 35, 45] {
            stats.record_at(t, 0);
        }
        assert_eq!(stats.counts(), vec![("a".to_string(), 5)]);
    }

    #[test]
    fn pick_stats_long_gap_clears_all() {
        let ids: Vec<String> = ["x"].iter().map(|s| s.to_string()).collect();
        let stats = PickStats::new(30, ids);

        stats.record_at(100, 0);
        assert_eq!(stats.counts(), vec![("x".to_string(), 1)]);

        // 长时间无 pick 后，一次 record 清除所有旧桶
        stats.record_at(200, 0);
        assert_eq!(stats.counts(), vec![("x".to_string(), 1)]);
    }

    #[test]
    fn pick_stats_clock_rollback_uses_latest_bucket() {
        let ids: Vec<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let stats = PickStats::new(100, ids);

        // 正常记录到 t=50 桶
        stats.record_at(50, 0);
        stats.record_at(55, 0);
        // 时钟回拨到 t=30，应归入 t=50 桶而非创建新桶
        stats.record_at(30, 1);

        let counts = stats.counts();
        // 只有一个桶，两个 upstream 都在其中
        assert_eq!(counts.len(), 2);
        assert_eq!(counts[0], ("a".to_string(), 2));
        assert_eq!(counts[1], ("b".to_string(), 1));

        // 内部只应有一个桶
        let inner = stats.inner.lock().unwrap();
        assert_eq!(inner.buckets.len(), 1);
    }

    #[test]
    fn upstream_set_with_pick_stats() {
        let items: Vec<_> = ["a", "b"].iter().map(|id| upstream(id)).collect();
        let set = UpstreamSet::new(items, 0, 40, DEFAULT_QUIC_STALE_SECS, 1800).unwrap();
        // 多次 pick 应该记录统计
        for _ in 0..10 {
            set.pick().unwrap();
        }
        let stats = set.pick_stats.as_ref().unwrap();
        let counts = stats.counts();
        let total: u64 = counts.iter().map(|(_, c)| *c).sum();
        assert_eq!(total, 10);
    }

    #[test]
    fn upstream_set_disables_pick_stats_when_window_is_zero() {
        let items = vec![upstream("a")];
        let set = UpstreamSet::new(items, 0, 40, DEFAULT_QUIC_STALE_SECS, 0).unwrap();
        assert!(set.pick_stats.is_none());
    }

    #[test]
    fn single_upstream_pick_records_stats() {
        let items = vec![upstream("solo")];
        let set = UpstreamSet::new(items, 0, 40, DEFAULT_QUIC_STALE_SECS, 1800).unwrap();
        for _ in 0..5 {
            set.pick().unwrap();
        }
        let stats = set.pick_stats.as_ref().unwrap();
        let counts = stats.counts();
        let total: u64 = counts.iter().map(|(_, c)| *c).sum();
        assert_eq!(total, 5, "single upstream picks must be recorded");
        assert_eq!(counts[0], ("solo".to_string(), 5));
        let cur = set.current.lock().unwrap();
        assert_eq!(
            cur.get("default"),
            Some(&Some("solo".to_string())),
            "single upstream must be recorded in current"
        );
    }

    #[test]
    fn sticky_keep_pick_records_stats() {
        let items: Vec<_> = ["a", "b"].iter().map(|id| upstream(id)).collect();
        // 标记已初始化，避开 5% 探索路径（基于 fastrand 熵种子，逐平台抖动非确定性）
        for up in &items {
            set_tcp_score(up, 500);
            set_quic_uplink(up, 500);
        }
        let set = UpstreamSet::new(items, 1000, 40, DEFAULT_QUIC_STALE_SECS, 1800).unwrap();
        // 所有 upstream 同分，sticky 到 "a"
        {
            let mut cur = set.current.lock().unwrap();
            cur.insert("default".to_string(), Some("a".to_string()));
        }
        for _ in 0..5 {
            set.pick().unwrap();
        }
        let stats = set.pick_stats.as_ref().unwrap();
        let counts = stats.counts();
        let total: u64 = counts.iter().map(|(_, c)| *c).sum();
        assert_eq!(total, 5, "sticky keep picks must be recorded");
        assert_eq!(counts[0], ("a".to_string(), 5));
    }

    // ---------- probe_quality / relative_score ----------

    #[test]
    fn probe_quality_rejects_invalid() {
        assert_eq!(probe_quality(f64::NAN, 0.0, 1450), None);
        assert_eq!(probe_quality(-1.0, 0.0, 1450), None);
        assert_eq!(probe_quality(10.0, 1.5, 1450), None);
        assert_eq!(probe_quality(10.0, f64::INFINITY, 1450), None);
    }

    #[test]
    fn probe_quality_bounded_0_to_1() {
        let q = probe_quality(10.0, 0.0, 1450).unwrap();
        assert!((0.0..=1.0).contains(&q));
        let q_worst = probe_quality(10_000.0, 1.0, 100).unwrap();
        assert!((0.0..=1.0).contains(&q_worst));
    }

    #[test]
    fn probe_quality_monotonic_worse_metric_lower_score() {
        // RTT 增大 → 质量下降
        let good = probe_quality(10.0, 0.0, 1450).unwrap();
        let bad = probe_quality(300.0, 0.0, 1450).unwrap();
        assert!(good > bad, "higher RTT must lower quality");

        // 丢包增大 → 质量下降
        let no_loss = probe_quality(50.0, 0.0, 1450).unwrap();
        let high_loss = probe_quality(50.0, 0.2, 1450).unwrap();
        assert!(no_loss > high_loss, "higher loss must lower quality");

        // MTU 减小 → 质量下降
        let full_mtu = probe_quality(50.0, 0.0, 1400).unwrap();
        let low_mtu = probe_quality(50.0, 0.0, 800).unwrap();
        assert!(full_mtu > low_mtu, "lower MTU must lower quality");
    }

    #[test]
    fn relative_score_mapping() {
        assert_eq!(relative_score(50.0, 100.0), 500);
        assert_eq!(relative_score(100.0, 100.0), 1000);
        assert_eq!(relative_score(200.0, 100.0), 1000); // 超过 max 时 clamp
        assert_eq!(relative_score(0.0, 100.0), 0);
        assert_eq!(relative_score(50.0, 0.0), 0); // max 为 0 时返回 0
    }

    #[test]
    fn relative_score_scale_independent() {
        // 相对评分与绝对量纲无关：1 MiB/s 与 500 MiB/s 两种网络，
        // 只要比值相同，相对分相同（解决阈值固化问题）。
        assert_eq!(relative_score(1.0, 2.0), relative_score(500.0, 1000.0));
    }
}
