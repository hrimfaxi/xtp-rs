//! 带「半关闭静默超时」的双向转发。
//!
//! `copy_bidirectional` 只在两个方向都读到 EOF 后才返回。对端只关闭写半边
//! （half-close）后永不关闭读半边时，relay 会永久挂起：连接长期停留在
//! `CLOSE-WAIT` / `FIN-WAIT-2`，持续泄漏 fd、内核 socket、conntrack 表项与
//! ephemeral port。
//!
//! 超时逻辑放在 copy 循环内部：两侧套一层 [`Tracked`] 观测字节流动与 EOF，再用
//! 一个 `poll_fn` 同时驱动 `copy_bidirectional_with_sizes` 和一个 `Sleep`。相比
//! 「另起一个看门狗任务与 copy 赛跑」，这样没有同刻竞态（copy 永远先被 poll，
//! 正常结束天然优先，不需要 `select!` 的 biased），也没有轮询步长带来的精度损失。
//!
//! # 计时语义
//!
//! - 截止时间只在**一端读到 EOF 之后**才开始计。双方都未半关闭的空闲长连接
//!   （交互式登录等）没有截止时间，永不被误杀。
//! - 半关闭之后，任意一次成功转发（读出或写入字节）都会把截止时间推到
//!   `now + grace`。
//! - 只有真正移动了字节才算进展：EOF 不填充缓冲区，它不是转发进展。
//!
//! `grace` 是**配置的宽限期，不是实测静默时长**：计时到点就回收，不度量连接实际静默
//! 了多久，返回值里的秒数也只是这个配置值。Tokio 的 `Sleep` 是毫秒级计时，到期后还要
//! 等任务被调度，所以回收发生在「截止时间之后的第一次调度」，不是硬实时保证。
//!
//! # 上膛信号为什么是 EOF
//!
//! 以「读到 EOF」而不是「对向 shutdown 成功」上膛，差别只在写方向卡住时才显现：tokio
//! copy 在写方向返回 `Pending` 时会继续读以把缓冲补满（`CopyBuffer::poll_write_buf` 的
//! top-up），补到 EOF 就置 `read_done`，而缓冲里那点数据始终写不出去，这一方向便一直
//! 停在 `Running`——`poll_shutdown` 根本不会被调用。按 shutdown 上膛就永远不上膛，而
//! 那种连接正是要回收的对象。
//!
//! （裸 `TcpStream::poll_shutdown` 是同步 `shutdown(SHUT_WR)` 后立即返回 `Ready`，不存在
//! 「shutdown 被反压卡住」的形态；卡住的是 copy 自己的缓冲。）
//!
//! # 保护范围
//!
//! 上膛信号是 EOF，因此本模块回收的是**relay 已经观测到 EOF、此后双向再无字节进展**的
//! 会话。有一个不覆盖的边界：对向写入持续无法推进、copy 缓冲已经填满，而该方向的 EOF
//! 尚未被读取时，copy 会停止读该方向（缓冲填满后不再补读），于是这一方向不能继续发现
//! EOF；若另一方向也没有观测到 EOF，计时就不会上膛。旧实现（以 `poll_shutdown` 成功上膛）
//! 同样覆盖不到，不是本次引入的退化。要消除这个边界得改写 copy 循环本身。
//!
//! 注意这个边界不是「数据量超过 8 KB」这种阈值：只要写入还能接受字节，缓冲就会继续推进、
//! 也就能继续读到 EOF；真正的前提是「写入无法推进」且「缓冲已满」且「EOF 还在后面」三者
//! 同时成立。
//!
//! 接入点见 `src/util.rs` 的 `relay_tcp_streams`：仅在 `half_close_timeout > 0`
//! 且 `splice = false` 时启用；`splice = true` 走 zero-copy，数据由内核在 fd 之间
//! 搬运，不经过 `poll_read`/`poll_write`，这里观测不到（启动时 WARN 一次）。

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// 与 `tokio::io::copy_bidirectional` 的默认缓冲区一致：每个方向 8 KB。
///
/// 显式写出而不是用 `copy_bidirectional`，是为了让「禁用超时」和「启用超时」两条
/// 路径走同一个函数，只有是否包观测层的区别。
const BUF_SIZE: usize = 8 * 1024;

/// 半关闭静默超时产生的错误载荷。
///
/// 只作为 [`is_half_close_timeout`] 的标记，不携带信息。
#[derive(Debug)]
pub struct HalfCloseTimeout;

impl std::fmt::Display for HalfCloseTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("half-closed stream inactivity timeout")
    }
}

impl std::error::Error for HalfCloseTimeout {}

/// 该错误是否来自本模块的半关闭静默超时。
///
/// 不能只看 `ErrorKind::TimedOut`：真实 socket 也会返回它（`tcp_retries2` 耗尽、
/// `TCP_USER_TIMEOUT` 等），而调用方只对「超时回收」这一条路径做额外处理（发 RST、
/// 计入泄漏计数器），必须能精确区分。
pub fn is_half_close_timeout(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::TimedOut
        && e.get_ref()
            .is_some_and(|inner| inner.is::<HalfCloseTimeout>())
}

fn half_close_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, HalfCloseTimeout)
}

/// 双向转发 `a` 与 `b`，并回收「已观测到 EOF 且此后静默」的连接。
///
/// `grace = None` 表示禁用，行为与 `tokio::io::copy_bidirectional` 完全一致。
/// `grace = Some(_)` 时，一端 EOF 后双向静默超过 `grace` 即返回
/// [`io::ErrorKind::TimedOut`] 错误，且 [`is_half_close_timeout`] 为真。`grace` 是配置
/// 的宽限期而非实测静默时长，保护范围见模块文档。
///
/// 返回 `Err` 时两侧流都已无进展，调用方应尽快 drop 它们。
pub async fn copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    grace: Option<Duration>,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let Some(grace) = grace else {
        return tokio::io::copy_bidirectional_with_sizes(a, b, BUF_SIZE, BUF_SIZE).await;
    };

    // 两侧共用同一对 flag：计时是整条会话的——任一方向的进展都算进展，任一端先
    // EOF 都算半关闭。用原子量而不是 `Cell`，是为了让整个 future 保持 `Send`，
    // 同时避免每次读写都加锁。
    let eof = AtomicBool::new(false);
    let activity = AtomicBool::new(false);
    let mut a = Tracked {
        inner: a,
        eof: &eof,
        activity: &activity,
    };
    let mut b = Tracked {
        inner: b,
        eof: &eof,
        activity: &activity,
    };

    let copy = tokio::io::copy_bidirectional_with_sizes(&mut a, &mut b, BUF_SIZE, BUF_SIZE);
    tokio::pin!(copy);
    let timer = tokio::time::sleep(grace);
    tokio::pin!(timer);
    let mut armed = false;

    std::future::poll_fn(|cx| {
        // 永远先 poll copy：正常结束优先于超时。若改用 select!，必须加 biased，
        // 否则「最后一个 EOF 刚到达」与「计时恰好到期」同刻可轮询时有一半概率把
        // 本该正常 FIN 结束的会话按泄漏回收掉。
        if let Poll::Ready(result) = copy.as_mut().poll(cx) {
            return Poll::Ready(result);
        }

        // activity 表示「刚过去的这一次 poll 里有字节移动」，每次读取即清空。
        // 它只会被 copy 的 poll 内部置位，而这里总是在 copy 的 poll 之后读取，
        // 所以既不会漏掉重置，也不会重复消费。
        let moved = activity.swap(false, Ordering::Relaxed);
        if !eof.load(Ordering::Relaxed) {
            // 还没有任何一端半关闭：没有截止时间。
            return Poll::Pending;
        }
        if !armed || moved {
            timer.as_mut().reset(Instant::now() + grace);
            armed = true;
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(half_close_timeout()));
        }
        Poll::Pending
    })
    .await
}

/// 观测一层：记录「刚过去的这次 poll 里有字节移动」与「这一侧读到了 EOF」。
struct Tracked<'a, T: ?Sized> {
    inner: &'a mut T,
    eof: &'a AtomicBool,
    activity: &'a AtomicBool,
}

impl<T: AsyncRead + Unpin + ?Sized> AsyncRead for Tracked<'_, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let remaining = buf.remaining();
        let result = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            if buf.filled().len() > before {
                self.activity.store(true, Ordering::Relaxed);
            } else if remaining > 0 {
                // 缓冲区没满却一个字节都没读到：只有 EOF 一种可能。
                // `remaining == 0` 时无法区分「缓冲区本来就是满的」，不作判断。
                self.eof.store(true, Ordering::Relaxed);
            }
        }
        result
    }
}

impl<T: AsyncWrite + Unpin + ?Sized> AsyncWrite for Tracked<'_, T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.store(true, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::Waker;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    const GRACE_MS: u64 = 100;
    const GRACE: Duration = Duration::from_millis(GRACE_MS);

    /// 两个方向各一对 `duplex`：`client`/`server` 是测试端，中间的一对被 relay。
    fn relay(
        grace_ms: Option<u64>,
    ) -> (
        DuplexStream,
        DuplexStream,
        tokio::task::JoinHandle<io::Result<(u64, u64)>>,
    ) {
        let (client, mut a) = duplex(64);
        let (mut b, server) = duplex(64);
        let grace = grace_ms.map(Duration::from_millis);
        let task = tokio::spawn(async move { copy_bidirectional(&mut a, &mut b, grace).await });
        (client, server, task)
    }

    /// 推进暂停的时钟，然后给被唤醒的任务若干轮调度机会。
    ///
    /// `tokio::time::advance` 推进虚拟时钟，但**不保证**返回时到期计时器已经被 driver 处理
    /// （更不保证被唤醒的任务已经跑过）；`yield_now` 也不承诺让谁先跑。因此不要在 advance 之后
    /// 立刻断言「任务已完成」，而是给有限轮调度机会——`settle` 不移动时钟，所以精度由虚拟时间
    /// 断言保证，与调度顺序无关。
    ///
    /// 反过来的坑也要避开：断言「到点已完成」之前不能留下会让运行时空闲的 await，否则它会自动把
    /// 时钟推到下一个计时器，断言就退化成「最终会完成」，测不出判决点落在哪里。
    async fn advance(ms: u64) {
        tokio::time::advance(Duration::from_millis(ms)).await;
        settle().await;
    }

    /// 给有限轮调度机会，期间不移动时钟。
    async fn settle() {
        /// 轮数取得远大于单条会话需要的调度次数，同时保证有限、不依赖具体轮询顺序。
        const ROUNDS: usize = 32;
        for _ in 0..ROUNDS {
            tokio::task::yield_now().await;
        }
    }

    fn timed_out(result: io::Result<(u64, u64)>) -> bool {
        result.is_err_and(|e| is_half_close_timeout(&e))
    }

    /// 一端半关闭后静默，宽限期到了就回收；两个方向对称。
    ///
    /// 断言刻意拆成「宽限期内不得回收」和「到点必须已完成」两步，并核对虚拟时间没有越过
    /// 截止时间：只写一句 `advance(GRACE_MS); assert!(timed_out(task.await…))` 的话，空闲时
    /// 运行时会自动推进时钟，那就只证明了「最终会完成」，测不出判决点在哪里。
    ///
    /// 精度由虚拟时间给出（`settle` 不移动时钟），不依赖「哪一次 yield 调度了哪个任务」。
    #[tokio::test(start_paused = true)]
    async fn half_close_times_out_in_either_direction() {
        for reverse in [false, true] {
            let (mut client, mut server, task) = relay(Some(GRACE_MS));
            if reverse {
                std::mem::swap(&mut client, &mut server);
            }
            client.shutdown().await.unwrap();
            assert_eq!(server.read(&mut [0u8; 1]).await.unwrap(), 0);
            // 读到 EOF 与上膛发生在同一次 poll 里，而此刻虚拟时间还没有动过。
            let armed_at = Instant::now();

            advance(GRACE_MS - 1).await;
            assert!(!task.is_finished(), "宽限期内不得回收");
            advance(1).await;
            assert!(
                task.is_finished(),
                "到期后有限轮调度内必须已完成，不能靠后续 await 自动推进时钟来补"
            );
            assert_eq!(
                Instant::now() - armed_at,
                GRACE,
                "判决点应正好落在截止时间上，虚拟时间不得溢出到更晚"
            );
            assert!(timed_out(task.await.unwrap()), "宽限期到点必须回收");

            // relay 退出时两侧流被 drop，两个方向都应立刻看到终止。
            assert_eq!(client.read(&mut [0u8; 1]).await.unwrap(), 0);
            assert!(server.write_all(b"closed").await.is_err());
        }
    }

    /// 双方都未半关闭的空闲长连接无论静默多久都不回收：交互式登录靠这一点存活。
    #[tokio::test(start_paused = true)]
    async fn open_idle_stream_does_not_time_out() {
        let (mut client, mut server, task) = relay(Some(GRACE_MS));
        advance(GRACE_MS * 10).await;
        assert!(!task.is_finished(), "未半关闭的会话没有截止时间");

        client.write_all(b"hello").await.unwrap();
        let mut buf = [0; 5];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
        assert_eq!(task.await.unwrap().unwrap(), (5, 0));
    }

    /// 半关闭之后每一次成功的转发都重置倒计时，且字节计数不受观测层影响。
    #[tokio::test(start_paused = true)]
    async fn response_activity_resets_timeout_and_preserves_counts() {
        for reverse in [false, true] {
            let (mut client, mut server, task) = relay(Some(GRACE_MS));
            if reverse {
                std::mem::swap(&mut client, &mut server);
            }

            client.write_all(b"request").await.unwrap();
            client.shutdown().await.unwrap();
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request");

            // 每轮间隔 75ms < 宽限期 100ms，四轮累计远超一个宽限期仍不应被回收。
            for _ in 0..4 {
                advance(GRACE_MS * 3 / 4).await;
                server.write_all(b"reply").await.unwrap();
                let mut buf = [0; 5];
                client.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"reply");
                assert!(!task.is_finished(), "仍有进展，不得回收");
            }

            server.shutdown().await.unwrap();
            let expected = if reverse { (20, 7) } else { (7, 20) };
            assert_eq!(task.await.unwrap().unwrap(), expected);
        }
    }

    /// 有进展就不回收，进展一停倒计时重新开始。
    #[tokio::test(start_paused = true)]
    async fn timeout_restarts_after_response_activity_stops() {
        let (mut client, mut server, task) = relay(Some(GRACE_MS));
        client.shutdown().await.unwrap();
        assert_eq!(server.read(&mut [0u8; 1]).await.unwrap(), 0);

        advance(GRACE_MS * 3 / 4).await;
        server.write_all(b"x").await.unwrap();
        client.read_exact(&mut [0u8; 1]).await.unwrap();

        advance(GRACE_MS - 1).await;
        assert!(!task.is_finished(), "进展把倒计时推后了");
        advance(1).await;
        assert!(timed_out(task.await.unwrap()));
    }

    /// 一端读到 EOF 就必须开始计时，哪怕对向的 shutdown 还没完成。
    ///
    /// 上膛以「读到 EOF」为准，而不是「对向 shutdown 成功」。这条用例用一个 `poll_shutdown`
    /// 永久 `Pending` 的包装流把两种信号彻底分开：按后者上膛的实现在这里永远不会上膛。
    ///
    /// 注意这是**泛型流**的性质，裸 `TcpStream` 不是这种形态——`TcpStream::poll_shutdown` 是
    /// 同步 `shutdown(SHUT_WR)` 后立即 `Ready`，不存在「shutdown 被反压卡住」。生产路径上
    /// 真正需要「按 EOF 上膛」的形态是写方向卡住、`poll_shutdown` 根本轮不到被调用，
    /// 见 `eof_still_stuck_in_the_copy_buffer_times_out`。
    #[tokio::test(start_paused = true)]
    async fn eof_arms_the_deadline_even_when_shutdown_is_pending() {
        struct PendingShutdown(DuplexStream);

        impl AsyncRead for PendingShutdown {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }

        impl AsyncWrite for PendingShutdown {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.0).poll_write(cx, buf)
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_flush(cx)
            }

            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }

        let (mut client, mut a) = duplex(64);
        let (b, _server) = duplex(64);
        let mut b = PendingShutdown(b);
        client.shutdown().await.unwrap();
        let task =
            tokio::spawn(async move { copy_bidirectional(&mut a, &mut b, Some(GRACE)).await });

        advance(GRACE_MS).await;
        assert!(timed_out(task.await.unwrap()));
    }

    /// 写方向卡住、copy 缓冲里还压着写不出去的数据时，同一方向的 EOF 也会上膛并最终回收。
    ///
    /// 这是生产路径上真正需要按 EOF 上膛的形态：写方向 `Pending` 时 tokio copy 会继续读以把
    /// 缓冲补满，补到 EOF 就置 `read_done`，而缓冲里那点数据始终写不出去，该方向便一直停在
    /// `Running`——`ShuttingDown` 进不去，`poll_shutdown` 根本不会被调用。按「shutdown 成功」
    /// 上膛的实现对这种连接永不上膛，泄漏照旧。
    ///
    /// 这里用一个永不接受数据的写方向制造反压：8 字节进不了 copy 缓冲之外，且填不满 8 KB，
    /// 所以补读一定会读到 EOF。上膛时刻也是确定的：数据写入与 shutdown 都立即就绪、不让出
    /// 调度，relay 的第一次调度机会出现在时钟已被推到 `GRACE_MS` 之后，因此无论这几轮里被
    /// poll 几次，上膛都发生在虚拟时间 `GRACE_MS`。
    #[tokio::test(start_paused = true)]
    async fn eof_still_stuck_in_the_copy_buffer_times_out() {
        /// 写方向永不接受数据；读方向透传内层 duplex。记录 shutdown 是否被调用过，用来坐实
        /// 「这一方向根本没走到 shutdown」。
        struct BlockedWriter {
            inner: DuplexStream,
            shutdown_called: Arc<AtomicBool>,
        }

        impl AsyncRead for BlockedWriter {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_read(cx, buf)
            }
        }

        impl AsyncWrite for BlockedWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }

            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.shutdown_called.store(true, Ordering::Relaxed);
                Poll::Ready(Ok(()))
            }
        }

        let (mut client, mut a) = duplex(64);
        let (b, _server) = duplex(64);
        let shutdown_called = Arc::new(AtomicBool::new(false));
        let mut b = BlockedWriter {
            inner: b,
            shutdown_called: Arc::clone(&shutdown_called),
        };
        let task =
            tokio::spawn(async move { copy_bidirectional(&mut a, &mut b, Some(GRACE)).await });

        // 先让 relay 跑完一轮：此刻还没有数据，不会上膛。
        tokio::task::yield_now().await;
        assert!(!task.is_finished());

        // 数据与 FIN 一起就位。两个 `await` 都立即就绪、不让出调度，relay 最早只能在下面第一个
        // `advance` 的那一轮调度里被 poll：那时它读到 8 字节（进展）、写方向 Pending、再补读到
        // EOF，于是同一次 poll 里上膛，倒计时被推到「此刻 + 宽限期」。
        client.write_all(&[7u8; 8]).await.unwrap();
        client.shutdown().await.unwrap();
        let polled_at = Instant::now();

        advance(GRACE_MS).await;
        assert!(!task.is_finished(), "上膛才刚完成，不应已经回收");

        advance(GRACE_MS - 1).await;
        assert!(!task.is_finished(), "到期前不得回收");
        advance(1).await;
        assert!(task.is_finished(), "到期后有限轮调度内必须已完成");
        assert_eq!(
            Instant::now() - polled_at,
            GRACE * 2,
            "上膛在第一次 poll（+1 个宽限期），判决点应再往后一个宽限期"
        );
        assert!(timed_out(task.await.unwrap()));
        assert!(
            !shutdown_called.load(Ordering::Relaxed),
            "该方向始终停在 copy 的 Running 里、进不了 ShuttingDown，shutdown 不该被调用——\
             这正是「按 shutdown 成功上膛」的实现对这种连接永不上膛的原因"
        );
    }

    /// 存活方向的写入被反压卡死时同样要能回收：这是「对端只发不收」的形态，
    /// 「静默」判定的是 relay 自身的转发进展，不是内核/缓冲区里还有没有数据。
    ///
    /// 载荷必须大于 copy 缓冲（8 KB）：relay 会先把对端数据读进自己的缓冲再去写存活
    /// 方向，缓冲填满之前写入方一直有进展，不会真的卡住。
    #[tokio::test(start_paused = true)]
    async fn half_close_times_out_while_the_survivor_is_blocked_on_write() {
        let (mut client, mut server, task) = relay(Some(GRACE_MS));
        client.shutdown().await.unwrap();
        assert_eq!(server.read(&mut [0u8; 1]).await.unwrap(), 0);

        // 下游不再读，relay 往它的方向写满 64 字节缓冲后就卡死。
        let writer = tokio::spawn(async move { server.write_all(&[1; 64 * 1024]).await });
        tokio::task::yield_now().await;

        advance(GRACE_MS).await;
        assert!(timed_out(task.await.unwrap()));
        assert!(
            writer.await.unwrap().is_err(),
            "回收时被卡住的写入必须被中止"
        );
    }

    /// 最后一个方向的 EOF 与截止时间同刻可轮询时，必须让正常结束赢。
    ///
    /// 这是 `poll_fn` 里「永远先 poll copy」唯一能被检验的地方：同刻就绪时若先看计时器，一个
    /// 本该干净 FIN 结束的会话就会被按泄漏回收并发出 RST。
    ///
    /// 用**手动 poll**（waker 是空实现）而不是 spawn：`Sleep` 的 `Ready` 依赖计时轮处理
    /// （entry 由 driver fire 之后才转成已完成状态），而 `advance()` 只推进时钟，不保证计时轮
    /// 已被处理。本用例第一版就踩在这里——那次 poll 里计时器仍是 `Pending`，两个信号其实并不同
    /// 刻，于是 timer-first 变异也杀不掉它。把 future 拿在手里、由测试决定何时 poll，才能得到
    /// 判决条件本身：「计时器已 `Ready`」与「存活方向已读到 EOF」落在同一次 poll。
    ///
    /// 前提由对照组证明：同样时刻、但存活方向保持静默的那一组必须当次返回超时。timer-first 变异
    /// 则验证它确实在检验优先级——只有撞车断言会失败，对照组不受影响。
    #[tokio::test(start_paused = true)]
    async fn normal_completion_wins_over_the_deadline_at_the_same_instant() {
        /// 手动 poll 一次；`Some` 表示这一次就绪。
        fn poll_once<F: std::future::Future>(
            fut: Pin<&mut F>,
            cx: &mut Context<'_>,
        ) -> Option<F::Output> {
            match fut.poll(cx) {
                Poll::Ready(v) => Some(v),
                Poll::Pending => None,
            }
        }

        // 空 waker：future 不进运行时任务队列，只由测试手动 poll。
        let mut cx = Context::from_waker(Waker::noop());

        // 两组完全对称的会话，唯一差别是存活方向有没有同时读到 EOF。
        let (mut client, mut a) = duplex(64);
        let (mut b, mut server) = duplex(64);
        let (mut client2, mut a2) = duplex(64);
        // 对照组：存活方向全程静默，`_server2` 保持写半边开着即可。
        let (mut b2, _server2) = duplex(64);
        let mut colliding = std::pin::pin!(copy_bidirectional(&mut a, &mut b, Some(GRACE)));
        let mut control = std::pin::pin!(copy_bidirectional(&mut a2, &mut b2, Some(GRACE)));

        // 两侧都先半关闭：a→b 读到 EOF 并上膛，倒计时 = 此刻 + 宽限期。
        client.shutdown().await.unwrap();
        client2.shutdown().await.unwrap();
        assert!(poll_once(colliding.as_mut(), &mut cx).is_none());
        assert!(poll_once(control.as_mut(), &mut cx).is_none());
        let armed_at = Instant::now();

        // 只有撞车那一组的存活方向也走到 EOF，对照组保持静默。
        server.shutdown().await.unwrap();

        // 时钟推到截止时间。本用例不让运行时调度这两个 future，因此这次 advance 之后计时轮有
        // 机会被处理、到期的 `Sleep` 被触发；`Instant::now()` 仍等于截止时间，指针没有越过。
        // 处理是否真的发生了，由下面对照组的断言检查——没发生它会先在那里失败，而不是让撞车
        // 用例静默地变成空转。
        tokio::time::advance(GRACE).await;
        assert_eq!(Instant::now() - armed_at, GRACE);

        // 对照组：同样是已到期、且应当已被触发的计时器，但 copy 还没有结束 → 必须超时。
        // 这一条同时就是「这一刻计时器确实 Ready」的检查点，撞车用例才不是空转。
        assert!(
            timed_out(
                poll_once(control.as_mut(), &mut cx)
                    .expect("对照组此刻应当已到期并返回超时；卡在这里说明计时轮没被处理")
            ),
            "截止时间已到、copy 未结束，必须回收"
        );

        // 撞车用例：copy 与计时器同刻就绪 → 必须走正常结束，而不是按泄漏回收。
        assert_eq!(
            poll_once(colliding.as_mut(), &mut cx)
                .expect("存活方向已 EOF，这一次 poll 必须结束")
                .unwrap(),
            (0, 0),
            "同刻就绪时必须走正常结束"
        );
        assert_eq!(Instant::now() - armed_at, GRACE, "判决点仍是截止时间本身");
    }

    /// `None` 表示禁用：与未引入该机制时的行为一致。
    #[tokio::test(start_paused = true)]
    async fn none_disables_the_timeout() {
        let (mut client, mut server, task) = relay(None);
        client.shutdown().await.unwrap();
        assert_eq!(server.read(&mut [0u8; 1]).await.unwrap(), 0);

        advance(GRACE_MS * 1000).await;
        assert!(!task.is_finished(), "禁用时不得回收");

        server.shutdown().await.unwrap();
        assert_eq!(task.await.unwrap().unwrap(), (0, 0));
    }

    /// 只有本模块产生的超时才带标记：真实 socket 的 `ETIMEDOUT` 不能被误判成
    /// 「半关闭泄漏」，否则错误路径会白白发 RST、污染泄漏计数器。
    #[test]
    fn only_the_module_timeout_is_recognized() {
        assert!(is_half_close_timeout(&half_close_timeout()));
        assert!(is_half_close_timeout(&io::Error::new(
            io::ErrorKind::TimedOut,
            HalfCloseTimeout
        )));
        assert!(!is_half_close_timeout(&io::Error::from(
            io::ErrorKind::TimedOut
        )));
        assert!(!is_half_close_timeout(&io::Error::from(
            io::ErrorKind::ConnectionReset
        )));
    }

    /// 并发压测：128 个半关闭静默会话必须全部被回收，一个都不能漏。
    ///
    /// 暂停时钟下所有截止时间都从同一个时刻起算，因此这里是确定性的：任何一条会话漏掉回收，
    /// 对应的任务就不会结束。断言给的是**有限轮调度内全部结束**（`settle` 不移动时钟），不是
    /// 「`advance` 返回时立刻可见」——`advance` 不保证返回时到期计时器已被 driver 处理，也不
    /// 保证每个被唤醒的任务都已经跑完。
    #[tokio::test(start_paused = true)]
    async fn every_half_closed_session_is_reclaimed() {
        const SESSIONS: usize = 128;

        let mut clients = Vec::with_capacity(SESSIONS);
        let mut servers = Vec::with_capacity(SESSIONS);
        let mut tasks = Vec::with_capacity(SESSIONS);
        for _ in 0..SESSIONS {
            let (mut client, server, task) = relay(Some(GRACE_MS));
            client.shutdown().await.unwrap();
            clients.push(client);
            servers.push(server);
            tasks.push(task);
        }

        // 每个会话的半关闭都已被传递到对端，同时说明它的截止时间已经上膛。
        for server in servers.iter_mut() {
            assert_eq!(server.read(&mut [0u8; 1]).await.unwrap(), 0);
        }

        advance(GRACE_MS).await;
        assert!(
            tasks.iter().all(tokio::task::JoinHandle::is_finished),
            "所有半关闭静默会话都必须在有限轮调度内被回收"
        );
        for task in tasks {
            assert!(timed_out(task.await.unwrap()));
        }
        for mut client in clients {
            assert_eq!(client.read(&mut [0u8; 1]).await.unwrap(), 0);
        }
    }
}
