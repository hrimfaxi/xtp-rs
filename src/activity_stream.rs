//! TCP relay 的半关闭静默看门狗。
//!
//! `copy_bidirectional` 只在两个方向都读到 EOF 后才返回。对端只关闭写半边
//! （half-close）后永不关闭读半边时，relay 会永久挂起：连接长期停留在
//! `CLOSE-WAIT` / `FIN-WAIT-2`，持续泄漏 fd、内核 socket、conntrack 表项与
//! ephemeral port。本模块记录双向的活动与第一次半关闭的时刻，供
//! [`half_close_watchdog`] 判断「半关闭之后是否已经静默超时」。
//!
//! 设计要点：
//! - 计时只在**第一次半关闭之后**开始。双方都未半关闭的空闲长连接（交互式登录
//!   等）没有截止时间，永不误杀。
//! - 半关闭之后，任意一次成功转发（读出或写入字节）都会重新计时。
//! - 只有在写半边**真正关闭成功**时才记录半关闭，且只记录第一次。
//!
//! 接入点见 `src/util.rs` 的 `relay_tcp_streams`：仅在 `half_close_timeout > 0`
//! 且 `splice = false` 时把两侧套上 [`ActivityGuard`] 并与 [`half_close_watchdog`]
//! 赛跑；`splice = true` 走 zero-copy，数据不经过 `poll_read`/`poll_write`，无法
//! 观测，因此跳过看门狗（启动时 WARN 一次）。
//!
//! `portable-atomic` 回退：32 位 MIPS（本项目交叉编译目标）没有原生 64 位原子，
//! 需要 `portable-atomic` 的 `fallback` feature。该依赖在 xtp-rs 中已是非
//! optional，因此这里的 `cfg` 分派可直接生效。

#[cfg(not(target_has_atomic = "64"))]
use portable_atomic::{AtomicU64, Ordering};
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::{AtomicU64, Ordering};

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// 进程内共享的单调毫秒时钟。
///
/// 永不返回 0：`half_closed_millis` 用 0 表示「尚未半关闭」，若某个会话的半关闭
/// 恰好落在纪元第 0 毫秒，时间戳 0 就会与该状态混淆，看门狗会被静默解除武装。
fn now_millis() -> u64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

#[derive(Debug)]
struct ActivityState {
    /// 任一侧最后一次有字节流动的时刻。
    last_millis: AtomicU64,
    /// 两侧中先结束的那一侧结束的时刻；两侧都还开着时为 0。
    half_closed_millis: AtomicU64,
}

/// 一次 relay 两侧共享的进展与半关闭记录。
///
/// `copy_bidirectional` 要等两个方向都读到 EOF 才返回，所以对端永不关闭其半边的
/// 会话永远不会结束，它持有的 fd 与对应的 TCP 状态也就一直滞留。
///
/// 但仅仅「安静下来」就放弃同样是错的：那会把健康的空闲会话一并结束。因此截止
/// 时间只在某一个方向真正结束之后才开始计时。从那一刻起，存活方向在等对端关闭，
/// 而一个保持沉默的对端与一个永远不会关闭的对端无法区分。
#[derive(Debug, Clone)]
pub struct Activity {
    state: Arc<ActivityState>,
}

impl Activity {
    pub fn new() -> Self {
        Self {
            state: Arc::new(ActivityState {
                last_millis: AtomicU64::new(now_millis()),
                half_closed_millis: AtomicU64::new(0),
            }),
        }
    }

    fn touch(&self) {
        self.state
            .last_millis
            .store(now_millis(), Ordering::Relaxed);
    }

    fn half_closed(&self) {
        let _ = self.state.half_closed_millis.compare_exchange(
            0,
            now_millis(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// 自第一次半关闭以来存活方向已静默多久；两侧都还开着时返回 `None`。
    pub fn quiet_since_half_close(&self) -> Option<Duration> {
        let half_closed = self.state.half_closed_millis.load(Ordering::Relaxed);
        if half_closed == 0 {
            return None;
        }
        let last = self.state.last_millis.load(Ordering::Relaxed);
        Some(Duration::from_millis(
            now_millis().saturating_sub(last.max(half_closed)),
        ))
    }
}

impl Default for Activity {
    fn default() -> Self {
        Self::new()
    }
}

/// 包装一个流，记录流经它的每一个字节，以及它的写半边被关闭的时刻。
///
/// relay 的两侧都要包装：先被关闭的那一侧告诉我们是哪个方向结束了，因为
/// `copy_bidirectional` 在某个方向读到 EOF 后会关闭对向的 writer。
#[derive(Debug)]
pub struct ActivityGuard<S> {
    inner: S,
    activity: Activity,
}

impl<S> ActivityGuard<S> {
    pub fn new(inner: S, activity: Activity) -> Self {
        Self { inner, activity }
    }
}

impl<S> AsyncRead for ActivityGuard<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        let moved = match &poll {
            Poll::Ready(Ok(())) => buf.filled().len() - before,
            _ => 0,
        };
        if moved > 0 {
            this.activity.touch();
        }
        poll
    }
}

impl<S> AsyncWrite for ActivityGuard<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        let moved = match &poll {
            Poll::Ready(Ok(n)) => *n,
            _ => 0,
        };
        if moved > 0 {
            this.activity.touch();
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_shutdown(cx);
        if let Poll::Ready(Ok(())) = &poll {
            this.activity.half_closed();
        }
        poll
    }
}

/// 在一个方向已结束、另一个方向随后完全静默 `quiet` 之后返回。
///
/// 按固定步长轮询，使结束会话的唤醒时刻落在截止时间之后 `step` 之内，与 `quiet`
/// 具体取值无关。
pub async fn half_close_watchdog(activity: &Activity, quiet: Duration) {
    let step = quiet.min(Duration::from_secs(30));
    loop {
        tokio::time::sleep(step).await;
        if activity
            .quiet_since_half_close()
            .is_some_and(|silent| silent >= quiet)
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 这些用例跑在暂停时钟上，但不能比较精确毫秒：`now_millis` 读的是进程级共享
    /// 纪元，并行跑在各自 runtime 上的其他用例会改变它的亚毫秒部分。因此所有关于
    /// 静默时长的断言都用窗口，窗口宽到一毫秒的抖动无法决定结果。
    const TOLERANCE: Duration = Duration::from_secs(1);

    /// 自第一次半关闭以来测得的静默时长。
    fn quiet(activity: &Activity) -> Duration {
        activity
            .quiet_since_half_close()
            .expect("a session that half-closed must report its silence")
    }

    fn assert_still_quiet(activity: &Activity, at_least: Duration, why: &str) {
        let measured = quiet(activity);
        assert!(
            measured + TOLERANCE >= at_least,
            "{why}: expected about {at_least:?} of silence, measured {measured:?}"
        );
    }

    fn assert_restarted(activity: &Activity, why: &str) {
        let measured = quiet(activity);
        assert!(
            measured <= TOLERANCE,
            "{why}: the silence should have restarted, but it measured {measured:?}"
        );
    }

    /// 两个方向都还开着的会话根本没有截止时间，无论它安静多久。交互式登录这类
    /// 空闲连接就是靠这一点存活。
    #[tokio::test(start_paused = true)]
    async fn the_deadline_does_not_apply_before_a_half_close() {
        let activity = Activity::new();
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(activity.quiet_since_half_close(), None);
    }

    /// 静默从第一次半关闭开始计算，之后任何字节流动都会重启倒计时。
    #[tokio::test(start_paused = true)]
    async fn the_deadline_restarts_on_every_byte_after_the_half_close() {
        let activity = Activity::new();
        activity.half_closed();

        tokio::time::advance(Duration::from_secs(10)).await;
        assert_still_quiet(&activity, Duration::from_secs(10), "ten seconds passed");

        activity.touch();
        assert_restarted(&activity, "a byte moved after the half-close");

        tokio::time::advance(Duration::from_secs(10)).await;
        assert_still_quiet(
            &activity,
            Duration::from_secs(10),
            "the deadline ran again after being restarted",
        );
    }

    /// 看门狗需要两个条件同时成立：一个方向已结束，且存活方向随后静默了整个宽限期。
    #[tokio::test(start_paused = true)]
    async fn the_watchdog_waits_for_both_a_half_close_and_the_grace() {
        let grace = Duration::from_secs(600);
        let activity = Activity::new();

        // 两个方向都还开着时看门狗会一直循环，所以给它加上界，要求它在好几个宽限期
        // 之后仍在运行。
        let not_armed =
            tokio::time::timeout(3 * grace, half_close_watchdog(&activity, grace)).await;
        assert!(
            not_armed.is_err(),
            "a session with both directions still open must never be given up on"
        );

        activity.half_closed();
        let armed_at = tokio::time::Instant::now();
        half_close_watchdog(&activity, grace).await;
        let waited = armed_at.elapsed();
        assert!(
            waited >= grace,
            "the watchdog fired after {waited:?}, before the {grace:?} grace had elapsed"
        );
    }

    /// 只有真正移动了的字节才算活动：EOF 不填充缓冲区，它不是转发进展，也不能被当作
    /// 对端重新开始说话的信号。
    #[tokio::test(start_paused = true)]
    async fn an_eof_read_moves_no_bytes_and_does_not_restart_the_deadline() {
        let (mine, theirs) = tokio::io::duplex(64);
        let activity = Activity::new();
        let mut guarded = ActivityGuard::new(mine, activity.clone());

        activity.half_closed();
        tokio::time::advance(Duration::from_secs(5)).await;
        drop(theirs);

        let mut buf = [0u8; 8];
        assert_eq!(guarded.read(&mut buf).await.unwrap(), 0);
        assert_still_quiet(
            &activity,
            Duration::from_secs(5),
            "reading EOF resumed no traffic, so the deadline must keep running",
        );
    }

    /// guard 是活动记录的数据来源：任一半边有字节流过都算活动。
    #[tokio::test(start_paused = true)]
    async fn the_guard_records_bytes_moving_in_either_direction() {
        let (mine, mut theirs) = tokio::io::duplex(64);
        let activity = Activity::new();
        let mut guarded = ActivityGuard::new(mine, activity.clone());
        activity.half_closed();

        tokio::time::advance(Duration::from_secs(30)).await;
        guarded.write_all(b"hello").await.unwrap();
        assert_restarted(&activity, "a byte written through the guard");

        tokio::time::advance(Duration::from_secs(30)).await;
        theirs.write_all(b"world").await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(guarded.read(&mut buf).await.unwrap(), 5);
        assert_restarted(&activity, "a byte read through the guard");
    }

    /// 关闭被包装流的写半边就是给截止时间上膛的动作，且该时刻只记录一次，
    /// 不是每次 shutdown 都记录。
    #[tokio::test(start_paused = true)]
    async fn shutting_down_the_guarded_writer_arms_the_deadline_once() {
        let (mine, _theirs) = tokio::io::duplex(64);
        let activity = Activity::new();
        let mut guarded = ActivityGuard::new(mine, activity.clone());
        assert_eq!(activity.quiet_since_half_close(), None);

        guarded.shutdown().await.unwrap();
        assert_restarted(
            &activity,
            "shutting the write half down must arm the deadline",
        );

        tokio::time::advance(Duration::from_secs(10)).await;
        let _ = guarded.shutdown().await;
        assert_still_quiet(
            &activity,
            Duration::from_secs(10),
            "the half-close is recorded once, not on every shutdown",
        );
    }
}
