// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 高频活跃度写路径节流聚合器。
//!
//! [`ActivityWriteThrottle`] 为「幂等心跳特征」的落库路径提供去抖窗口：
//! 同 key 在 debounce 窗口内仅首次入队（后续调用直接去重返回，不产生新落库），
//! 条目到期后由后台 `tokio::interval` 批量落库。
//!
//! # 语义契约
//!
//! - **去抖窗口**：条目自入队起存活一个 debounce 窗口；窗口内同 key 的后续
//!   活跃度全部去重（不落库），窗口到期后条目被 flush 落库并移除，窗口外
//!   的下一次活跃度重新入队、再次落库。
//! - **有界与丢弃显性化**：待落库条目数受 `max_size` 约束；容量满时新 key
//!   非阻塞丢弃（record 为同步调用，绝不阻塞落库调用方），丢弃 = 跳过本次
//!   落库，`tracing::warn!` 显性记录并递增丢弃计数（不静默）；被丢弃 key
//!   未占用条目，容量释放后（窗口外）可恢复落库。
//! - **批量 flush 与防泄漏**：后台 flush 循环每个 debounce 周期将全部到期
//!   条目批量落库并清理；条目带截止时间（入队时间 + debounce），flush 只
//!   处理到期条目——即使长期不落库，条目数也受 `max_size` 硬约束，到期
//!   flush 保证已入队条目最终被清理，不泄漏。
//! - **写超时**：flush 对每次落库写施加 timeout 上限（[`Self::run_flush_loop`]
//!   后台任务串行执行，单条挂起不阻塞消费调用方）；写失败/超时的条目同样
//!   被清理并以 warn 显性化（不重试占用容量，窗口外活跃度重新入队）。
//! - **可观测**：每次丢弃即时 warn；后台循环每个周期对窗口内丢弃做汇总
//!   warn（累计丢弃数可从日志检索）。
//! - **进程退出不持久化**：待落库条目仅存于内存，进程退出即丢失。活跃度
//!   写路径为幂等心跳语义（下次活跃度会重新写入），可接受。
//! - **窗口内快照语义**：窗口内仅首次入队的载荷会被落库（后续去重调用不
//!   覆盖），落库记录是窗口内首次活跃度的快照而非窗口末态。
//!
//! # 容量边界的并发声明
//!
//! 容量检查与插入为两次同步操作，多线程竞争下实际条目数可能短暂越过
//! `max_size` 软上限一个写线程的窗口（单线程/单任务语义下精确）；硬性
//! 保证以不做阻塞为前提（入队路径绝不等待）。
//!
//! # 常量出处
//!
//! 三常量对齐 pomerium `authorize/access_tracker.go:20-24` 的量级。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// 截止时间使用 tokio 时钟（tokio::time::Instant）：随 runtime pause/advance
// 走，测试可用 pause 时钟精确驱动；非 pause 环境等价真实时间。
use tokio::time::Instant;

use dashmap::DashMap;

/// 活跃度节流器容量上限：待落库条目数硬约束。
///
/// 量级出处：pomerium `authorize/access_tracker.go:22`（`accessTrackerMaxSize = 1_000`）。
pub const ACTIVITY_THROTTLE_MAX_SIZE: usize = 1_000;

/// 活跃度去抖窗口：同 key 窗口内仅首次落库。
///
/// 量级出处：pomerium `authorize/access_tracker.go:23`（`accessTrackerDebouncePeriod = 10s`）。
pub const ACTIVITY_THROTTLE_DEBOUNCE: Duration = Duration::from_secs(10);

/// 单次落库写超时上限：挂起的写不得拖垮批量 flush。
///
/// 量级出处：pomerium `authorize/access_tracker.go:24`（`accessTrackerUpdateTimeout = 3s`）。
pub const ACTIVITY_THROTTLE_TIMEOUT: Duration = Duration::from_secs(3);

/// [`ActivityWriteThrottle::record`] 的处置结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// 已入队：本窗口首次活跃度，flush 时落库。
    Recorded,
    /// 去抖：同 key 窗口内已有待落库条目，跳过（幂等心跳语义）。
    Deduplicated,
    /// 丢弃：容量满（新 key）——跳过本次落库，窗口外重写；已 `warn` 显性化。
    Dropped,
}

/// 待落库条目：载荷 + 落库截止时间（防泄漏的清理依据）。
struct ThrottleEntry<W> {
    payload: W,
    deadline: Instant,
}

/// 高频活跃度写路径节流聚合器。
///
/// 同 key 在去抖窗口内仅保留首条待落库载荷（后续调用去重）；后台
/// [`Self::run_flush_loop`] 每个周期批量落库到期 key。待落库条目数受
/// `max_size` 约束，超限时非阻塞丢弃并 `tracing::warn!` 计数显性化
/// （丢弃 = 跳过本次落库，窗口外重写，不静默）。
///
/// 设计决策与语义契约详见模块文档。三常量量级出处：pomerium
/// `authorize/access_tracker.go:20-24`。
pub struct ActivityWriteThrottle<W> {
    /// 待落库条目（key → 载荷 + 截止时间）。
    entries: DashMap<String, ThrottleEntry<W>>,
    /// 待落库条目数上限（软上限，见模块文档并发声明）。
    max_size: usize,
    /// 去抖窗口（同时为后台 flush 周期）。
    debounce: Duration,
    /// 单次落库写超时。
    timeout: Duration,
    /// 容量丢弃累计（跨 flush 周期汇总，可观测口径见模块文档）。
    dropped: AtomicU64,
}

impl<W: std::fmt::Display + Send + Sync + 'static> ActivityWriteThrottle<W> {
    /// 以模块常量为参数创建节流器（默认量级，出处见常量文档）。
    pub fn new() -> Self {
        Self::with_limits(
            ACTIVITY_THROTTLE_MAX_SIZE,
            ACTIVITY_THROTTLE_DEBOUNCE,
            ACTIVITY_THROTTLE_TIMEOUT,
        )
    }

    /// 以显式参数创建节流器（测试/定制部署用）。
    pub fn with_limits(max_size: usize, debounce: Duration, timeout: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            max_size,
            debounce,
            timeout,
            dropped: AtomicU64::new(0),
        }
    }

    /// 记录一次活跃度（同步、非阻塞，绝不等待落库）。
    ///
    /// - 同 key 窗口内已有条目 → 去重（返回 [`RecordOutcome::Deduplicated`]，
    ///   落库的载荷保持窗口内首次快照；窗口锚定首次入队时间，去重不刷新
    ///   截止时间——持续活跃的 key 仍按窗口周期出账，不会因滑动窗口饿死）；
    /// - 新 key 且容量未满 → 入队（截止时间 = now + debounce）；
    /// - 新 key 且容量满 → 非阻塞丢弃（返回 [`RecordOutcome::Dropped`]），
    ///   丢弃计数递增并 `tracing::warn!` 显性化。
    pub fn record(&self, key: &str, payload: W) -> RecordOutcome {
        if self.entries.contains_key(key) {
            return RecordOutcome::Deduplicated;
        }
        if self.entries.len() >= self.max_size {
            let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(
                key = %key,
                payload = %payload,
                max_size = self.max_size,
                dropped_total = total,
                "credit: 活跃度节流容量满，丢弃本次落库（窗口外重写）"
            );
            return RecordOutcome::Dropped;
        }
        self.entries.insert(
            key.to_string(),
            ThrottleEntry {
                payload,
                deadline: Instant::now() + self.debounce,
            },
        );
        RecordOutcome::Recorded
    }

    /// 批量落库全部到期条目，返回处理的条目数（含写失败条目，均已清理）。
    ///
    /// 截止时间清理防泄漏：只处理 `deadline <= now` 的条目；单条写施加
    /// `timeout` 上限（写失败/超时的条目同样清理并以 `tracing::warn!`
    /// 显性化，不重试占用容量）。
    pub async fn flush_due<F, Fut, E>(&self, write: F) -> usize
    where
        F: Fn(String, W) -> Fut,
        Fut: std::future::Future<Output = Result<(), E>>,
        E: std::fmt::Display,
    {
        let now = Instant::now();
        let due_keys: Vec<String> = self
            .entries
            .iter()
            .filter(|item| item.value().deadline <= now)
            .map(|item| item.key().clone())
            .collect();
        if due_keys.is_empty() {
            return 0;
        }

        let mut handled = 0usize;
        for key in due_keys {
            // 先移除后写：失败/超时条目不回填容量（显性化后窗口外重写）
            let Some((_, entry)) = self.entries.remove(&key) else {
                continue;
            };
            handled += 1;
            let write = write(key.clone(), entry.payload);
            match tokio::time::timeout(self.timeout, write).await {
                Ok(Ok(())) => {},
                Ok(Err(e)) => {
                    tracing::warn!(
                        key = %key,
                        error = %e,
                        timeout_secs = self.timeout.as_secs(),
                        "credit: 活跃度落库写失败（条目已清理，窗口外活跃度重新入队）"
                    );
                },
                Err(_) => {
                    tracing::warn!(
                        key = %key,
                        timeout_secs = self.timeout.as_secs(),
                        "credit: 活跃度落库写超时（条目已清理，窗口外活跃度重新入队）"
                    );
                },
            }
        }
        handled
    }

    /// 后台 flush 循环：每个去抖周期批量落库到期 key 并汇总丢弃计数。
    ///
    /// 周期 = debounce；首 tick 即刻触发一次（此时条目未到期，为无操作）。
    /// 每周期汇总窗口内丢弃：累计丢弃数 > 上次已报告值时 `tracing::warn!`
    /// 输出增量（可从日志检索）。进程退出不持久化：待落库条目丢失由幂等
    /// 心跳语义兜底（下次活跃度重新写入）。
    pub async fn run_flush_loop<F, Fut, E>(&self, write: F)
    where
        F: Fn(String, W) -> Fut,
        Fut: std::future::Future<Output = Result<(), E>>,
        E: std::fmt::Display,
    {
        let mut interval = tokio::time::interval(self.debounce);
        let mut reported_dropped = 0u64;
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            self.flush_due(&write).await;
            let dropped = self.dropped.load(Ordering::Relaxed);
            if dropped > reported_dropped {
                tracing::warn!(
                    dropped_total = dropped,
                    new_dropped = dropped - reported_dropped,
                    debounce_secs = self.debounce.as_secs(),
                    "credit: 活跃度节流窗口内丢弃汇总（丢弃=跳过本次落库，窗口外重写）"
                );
                reported_dropped = dropped;
            }
        }
    }

    /// 当前待落库条目数（观测/测试用）。
    pub fn pending_len(&self) -> usize {
        self.entries.len()
    }

    /// 容量丢弃累计总数（观测/测试用）。
    pub fn dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl<W: std::fmt::Display + Send + Sync + 'static> Default for ActivityWriteThrottle<W> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ActivityWriteThrottle;
    use super::RecordOutcome;
    use super::ACTIVITY_THROTTLE_DEBOUNCE;
    use super::ACTIVITY_THROTTLE_MAX_SIZE;
    use super::ACTIVITY_THROTTLE_TIMEOUT;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::time::Duration;

    const DEBOUNCE: Duration = Duration::from_secs(10);
    const TIMEOUT: Duration = Duration::from_secs(3);

    type TestLog = Mutex<Vec<(String, i32)>>;

    /// 不失败写方：把 (key, payload) 记进共享日志。
    fn infallible_writer(
        log: Arc<TestLog>,
    ) -> impl Fn(String, i32) -> std::future::Ready<Result<(), std::convert::Infallible>> {
        move |key, payload| {
            std::future::ready({
                log.lock().push((key, payload));
                Ok(())
            })
        }
    }

    /// 让当前线程调度器排空已就绪任务（pause 时钟下无真实等待）。
    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    /// 进程内日志捕获 writer（fmt Layer 的 MakeWriter，收集格式化行）。
    #[derive(Clone)]
    struct LogCapture(Arc<Mutex<Vec<String>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = LogCaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            LogCaptureWriter(self.0.clone())
        }
    }

    struct LogCaptureWriter(Arc<Mutex<Vec<String>>>);

    impl std::io::Write for LogCaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().push(String::from_utf8_lossy(buf).to_string());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // ========================================================================
    // 去抖窗口
    // ========================================================================

    /// 同 key 窗口内仅首次入队（落库调用计数=1，窗口内首次快照落库）；
    /// 窗口外再次入队并再次落库。
    #[tokio::test(start_paused = true)]
    async fn debounce_window_persists_once_then_rewrites_outside_window() {
        let throttle = ActivityWriteThrottle::with_limits(10, DEBOUNCE, TIMEOUT);
        let log = Arc::new(TestLog::new(Vec::new()));

        assert_eq!(throttle.record("k", 1), RecordOutcome::Recorded);
        assert_eq!(throttle.record("k", 2), RecordOutcome::Deduplicated);
        assert_eq!(throttle.record("k", 3), RecordOutcome::Deduplicated);

        // 条目带截止时间：未到期不落库
        let flushed = throttle.flush_due(infallible_writer(log.clone())).await;
        assert_eq!(flushed, 0, "截止时间前不得落库");
        assert_eq!(log.lock().len(), 0);

        // 窗口到期 → 批量落库一次（仅窗口内首次入队的载荷）
        tokio::time::advance(DEBOUNCE).await;
        let flushed = throttle.flush_due(infallible_writer(log.clone())).await;
        assert_eq!(flushed, 1, "到期应批量落库");
        {
            let entries = log.lock();
            assert_eq!(entries.len(), 1, "窗口内落库调用计数应为 1");
            assert_eq!(
                entries[0],
                ("k".to_string(), 1),
                "落库应为窗口内首次入队的快照"
            );
        }
        assert_eq!(throttle.pending_len(), 0, "落库后条目应清理防泄漏");

        // 窗口外重新入队 → 再次落库
        assert_eq!(throttle.record("k", 9), RecordOutcome::Recorded);
        tokio::time::advance(DEBOUNCE).await;
        let flushed = throttle.flush_due(infallible_writer(log.clone())).await;
        assert_eq!(flushed, 1);
        let entries = log.lock();
        assert_eq!(entries.len(), 2, "窗口外应再次落库");
        assert_eq!(entries[1], ("k".to_string(), 9));
    }

    /// 窗口锚定首次入队：去重调用不刷新截止时间，持续活跃的 key 仍按窗口
    /// 出账（不因滑动窗口饿死）。
    #[tokio::test(start_paused = true)]
    async fn dedup_does_not_slide_window_anchor() {
        let throttle = ActivityWriteThrottle::with_limits(10, DEBOUNCE, TIMEOUT);
        let log = Arc::new(TestLog::new(Vec::new()));

        throttle.record("k", 1);
        // 窗口内持续活跃（t=1s / 5s / 9s 去重）
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(throttle.record("k", 2), RecordOutcome::Deduplicated);
        tokio::time::advance(Duration::from_secs(4)).await;
        assert_eq!(throttle.record("k", 3), RecordOutcome::Deduplicated);
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(throttle.record("k", 4), RecordOutcome::Deduplicated);

        // t=10s：窗口锚定首次入队（t=0）→ 到期落库，尽管 1s 前仍有活跃
        let flushed = throttle.flush_due(infallible_writer(log.clone())).await;
        assert_eq!(flushed, 1, "去重不刷新窗口，t=10s 应按首次入队锚点落库");
        assert_eq!(log.lock()[0].1, 1, "落库为窗口内首次快照");
    }

    // ========================================================================
    // 有界与丢弃显性化
    // ========================================================================

    /// max_size 满时新 key 非阻塞丢弃（record 同步返回，跳过本次落库），
    /// 丢弃计数递增；被丢弃 key 在容量释放后的窗口外可恢复落库。
    #[tokio::test(start_paused = true)]
    async fn capacity_full_drops_new_key_and_recovers_outside_window() {
        let throttle = ActivityWriteThrottle::with_limits(2, DEBOUNCE, TIMEOUT);
        let log = Arc::new(TestLog::new(Vec::new()));

        assert_eq!(throttle.record("k1", 1), RecordOutcome::Recorded);
        assert_eq!(throttle.record("k2", 2), RecordOutcome::Recorded);
        // 满容量：同步调用直接返回 Dropped（非阻塞）
        assert_eq!(throttle.record("k3", 3), RecordOutcome::Dropped);
        assert_eq!(throttle.dropped_total(), 1, "丢弃计数应递增");
        assert_eq!(throttle.record("k3", 3), RecordOutcome::Dropped);
        assert_eq!(throttle.dropped_total(), 2, "重复丢弃应继续递增");

        tokio::time::advance(DEBOUNCE).await;
        let flushed = throttle.flush_due(infallible_writer(log.clone())).await;
        assert_eq!(flushed, 2, "被丢弃的 k3 不得落库");
        assert_eq!(log.lock().len(), 2);

        // 容量已释放：被丢弃 key 窗口外恢复落库
        assert_eq!(throttle.record("k3", 3), RecordOutcome::Recorded);
        tokio::time::advance(DEBOUNCE).await;
        let flushed = throttle.flush_due(infallible_writer(log.clone())).await;
        assert_eq!(flushed, 1);
        assert_eq!(log.lock().len(), 3, "窗口外被丢弃 key 应恢复落库");
    }

    /// 容量丢弃必须输出结构性 warn（含 key 与累计丢弃数），显性化不静默。
    ///
    /// tracing interest 缓存是进程级全局态：并行运行的非订阅者测试可能抢先
    /// 首次注册事件 callsite 并缓存 `Interest::never`（事件被宏直接剔除，与
    /// 本线程订阅者无关，同 `web::request_id` 的 init_capture 先例）——故
    /// set_default 后显式重建，捕获缺失时重建重试。
    #[tokio::test(start_paused = true)]
    #[serial_test::serial]
    async fn capacity_drop_emits_structured_warning() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let logs = Arc::new(Mutex::new(Vec::<String>::new()));
        let _guard = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(LogCapture(logs.clone())),
            )
            .set_default();
        tracing::callsite::rebuild_interest_cache();

        let mut lines = Vec::<String>::new();
        for _ in 0..3 {
            let throttle = ActivityWriteThrottle::with_limits(1, DEBOUNCE, TIMEOUT);
            assert_eq!(throttle.record("first", 1), RecordOutcome::Recorded);
            assert_eq!(throttle.record("second", 2), RecordOutcome::Dropped);
            assert_eq!(throttle.dropped_total(), 1);

            lines = logs.lock().clone();
            if lines
                .iter()
                .any(|l| l.contains("丢弃") && l.contains("second") && l.contains("WARN"))
            {
                break;
            }
            tracing::callsite::rebuild_interest_cache();
        }
        assert!(
            lines
                .iter()
                .any(|l| l.contains("丢弃") && l.contains("second") && l.contains("WARN")),
            "容量丢弃应输出含 key 的 warn，实际: {:?}",
            lines
        );
    }

    // ========================================================================
    // 后台批量 flush（tokio::interval + pause 时钟）
    // ========================================================================

    /// 后台 flush 循环：到期 key 批量落库（pause 时钟驱动，无真实 sleep），
    /// 首个周期（条目未到期）不得提前落库。
    #[tokio::test(start_paused = true)]
    async fn flush_loop_batch_persists_due_keys() {
        let throttle = Arc::new(ActivityWriteThrottle::with_limits(10, DEBOUNCE, TIMEOUT));
        let log = Arc::new(TestLog::new(Vec::new()));

        let loop_throttle = throttle.clone();
        let loop_log = log.clone();
        tokio::spawn(async move {
            loop_throttle
                .run_flush_loop(move |key, payload| {
                    let log = loop_log.clone();
                    async move {
                        log.lock().push((key, payload));
                        Ok::<(), std::convert::Infallible>(())
                    }
                })
                .await;
        });

        throttle.record("k1", 1);
        throttle.record("k2", 2);
        // 未到期（首个 interval tick 在 t=0，条目截止时间在 +debounce）
        settle().await;
        assert_eq!(log.lock().len(), 0, "条目未到期时后台循环不得提前落库");

        tokio::time::advance(DEBOUNCE).await;
        settle().await;

        assert_eq!(log.lock().len(), 2, "到期 key 应由后台循环批量落库");
        assert_eq!(throttle.pending_len(), 0, "落库后条目应清理防泄漏");
    }

    /// 后台循环对窗口内丢弃做 tracing 汇总（累计丢弃数可从日志检索）。
    #[tokio::test(start_paused = true)]
    #[serial_test::serial]
    async fn flush_loop_summarizes_dropped_count() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let logs = Arc::new(Mutex::new(Vec::<String>::new()));
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(LogCapture(logs.clone())),
        );
        let _guard = subscriber.set_default();

        let throttle = Arc::new(ActivityWriteThrottle::with_limits(1, DEBOUNCE, TIMEOUT));
        let loop_throttle = throttle.clone();
        tokio::spawn(async move {
            loop_throttle
                .run_flush_loop(|_key, _payload| {
                    std::future::ready(Ok::<(), std::convert::Infallible>(()))
                })
                .await;
        });

        throttle.record("kept", 1);
        assert_eq!(throttle.record("dropped", 2), RecordOutcome::Dropped);

        tokio::time::advance(DEBOUNCE).await;
        settle().await;

        let lines = logs.lock();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("丢弃") && l.contains("WARN")),
            "后台循环应汇总窗口内丢弃，实际: {:?}",
            *lines
        );
    }

    // ========================================================================
    // 写超时与写失败的显性化
    // ========================================================================

    /// 单次落库写超时：挂起的写方不得卡死 flush，超时条目被清理并显性化。
    #[tokio::test(start_paused = true)]
    async fn flush_write_timeout_bounds_each_write() {
        let throttle = ActivityWriteThrottle::with_limits(4, DEBOUNCE, TIMEOUT);
        throttle.record("slow", 1);
        tokio::time::advance(DEBOUNCE).await;

        let hang = |_key: String, _payload: i32| async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok::<(), std::convert::Infallible>(())
        };
        // flush 与时钟推进并行：timeout 限时单次写
        let (flushed, _) = tokio::join!(throttle.flush_due(hang), tokio::time::advance(TIMEOUT));
        assert_eq!(flushed, 1, "超时写也计为已处理（条目清理）");
        assert_eq!(throttle.pending_len(), 0, "超时条目应被清理防泄漏");
    }

    /// 落库写失败不阻断 flush 批次：失败条目 warn 后清理，其余条目照常落库。
    #[tokio::test(start_paused = true)]
    async fn flush_write_error_does_not_block_batch() {
        let throttle = ActivityWriteThrottle::with_limits(4, DEBOUNCE, TIMEOUT);
        throttle.record("bad", 1);
        throttle.record("good", 2);
        tokio::time::advance(DEBOUNCE).await;

        let succeeded = Arc::new(Mutex::new(Vec::<i32>::new()));
        let sink = succeeded.clone();
        let writer = move |key: String, payload: i32| {
            let succeeded = sink.clone();
            async move {
                if key == "bad" {
                    Err("injected-failure".to_string())
                } else {
                    succeeded.lock().push(payload);
                    Ok(())
                }
            }
        };
        let flushed = throttle.flush_due(writer).await;
        assert_eq!(flushed, 2, "失败条目不阻断批次其余落库");
        assert_eq!(succeeded.lock().len(), 1, "失败条目不落库，其余应成功");
        assert_eq!(
            throttle.pending_len(),
            0,
            "失败条目同样清理（显性化后不占用容量）"
        );
    }

    /// 常量校验：三常量对齐 pomerium access_tracker.go:20-24 的量级。
    #[test]
    fn constants_align_with_pomerium_access_tracker() {
        assert_eq!(
            ACTIVITY_THROTTLE_MAX_SIZE, 1_000,
            "max_size 对齐 accessTrackerMaxSize（access_tracker.go:22）"
        );
        assert_eq!(
            ACTIVITY_THROTTLE_DEBOUNCE,
            Duration::from_secs(10),
            "debounce 对齐 accessTrackerDebouncePeriod（access_tracker.go:23）"
        );
        assert_eq!(
            ACTIVITY_THROTTLE_TIMEOUT,
            Duration::from_secs(3),
            "timeout 对齐 accessTrackerUpdateTimeout（access_tracker.go:24）"
        );
    }
}
