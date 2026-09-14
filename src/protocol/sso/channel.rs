//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! Redis pub/sub SsoChannel 实现。
//!
//! 基于 Redis pub/sub 实现跨实例 SSO 消息推送，替代 `NoopSsoChannel`。
//!
//! 仅在 `cache-redis` + `protocol-sso-server` feature 同时启用时编译。
//!
//! # 订阅生命周期（错误处理/可靠性修复）
//!
//! - `subscribe` 通过 oneshot 回传首次连接+订阅结果：连接/订阅失败时向调用方
//! 返回 `Err`（不再"假成功"）；
//! - 后台任务句柄保存到结构体（[`RedisPubSubSsoChannel::shutdown`] 可主动停止，
//! `Drop` 时自动 abort），任务失败可观测、资源可回收；
//! - 订阅建立后若连接断开（stream 结束），后台任务按可配置次数重连并重新
//! SUBSCRIBE（指数退避，见 [`RedisPubSubSsoChannel::with_reconnect_attempts`]），
//! 超过次数后记 error 日志退出。

use super::server::SsoChannel;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use futures::StreamExt;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

/// 断线重连默认最大尝试次数。
const DEFAULT_RECONNECT_ATTEMPTS: usize = 5;

/// 重连退避基数（毫秒）：第 n 次重试等待 `min(500 * n, 5000)` ms。
const RECONNECT_BACKOFF_BASE_MS: u64 = 500;
/// 重连退避上限（毫秒）。
const RECONNECT_BACKOFF_MAX_MS: u64 = 5000;

/// 基于 Redis pub/sub 的 SsoChannel 实现。
///
/// 使用 `redis::aio::ConnectionManager` 执行 PUBLISH 命令（支持自动重连），
/// 使用 `redis::Client` 创建独立的 PubSub 连接进行 SUBSCRIBE（订阅模式需要独占连接）。
///
/// **设计说明**：原始设计为 `new(connection_manager) -> Self`，
/// 但 `ConnectionManager` 是多路复用连接，不支持 pub/sub 订阅模式（SUBSCRIBE 会独占连接）。
/// 因此额外存储 `redis::Client` 用于创建独立的 PubSub 订阅连接。
pub struct RedisPubSubSsoChannel {
    /// Redis 客户端（用于创建独立的 PubSub 订阅连接）。
    client: redis::Client,
    /// 连接管理器（用于 PUBLISH 命令，支持自动重连）。
    connection_manager: redis::aio::ConnectionManager,
    /// 后台订阅任务句柄（不再即弃：供 shutdown/abort 回收，Drop 时统一停止）。
    tasks: parking_lot::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// 连接断开后最大重连尝试次数（0 = 不重连，一次性订阅语义）。
    max_reconnect_attempts: usize,
}

impl RedisPubSubSsoChannel {
    /// 创建新的 `RedisPubSubSsoChannel` 实例。
    ///
    /// # 参数
    /// - `connection_manager`: Redis 连接管理器（用于 PUBLISH 命令，支持自动重连）。
    /// - `client`: Redis 客户端（用于创建独立的 PubSub 订阅连接）。
    ///
    /// # 设计偏差
    /// 原始签名为 `new(connection_manager) -> Self`，
    /// 但 `ConnectionManager` 不支持 pub/sub 订阅模式，需额外传入 `redis::Client`。
    pub fn new(connection_manager: redis::aio::ConnectionManager, client: redis::Client) -> Self {
        Self {
            client,
            connection_manager,
            tasks: parking_lot::Mutex::new(Vec::new()),
            max_reconnect_attempts: DEFAULT_RECONNECT_ATTEMPTS,
        }
    }

    /// 配置断线重连最大尝试次数（默认 5 次；0 = 不重连，断连即结束订阅）。
    #[must_use]
    pub fn with_reconnect_attempts(mut self, attempts: usize) -> Self {
        self.max_reconnect_attempts = attempts;
        self
    }

    /// 停止全部后台订阅任务（abort 并清空句柄），返回被停止的任务数。
    ///
    /// 订阅任务被 abort 后，对应 topic 不再接收消息；PubSub 连接随任务结束释放。
    pub fn shutdown(&self) -> usize {
        let mut tasks = self.tasks.lock();
        let stopped = tasks.len();
        for handle in tasks.drain(..) {
            handle.abort();
        }
        stopped
    }

    /// 清理已结束的句柄并登记新任务句柄。
    fn track_task(&self, handle: tokio::task::JoinHandle<()>) {
        let mut tasks = self.tasks.lock();
        tasks.retain(|h| !h.is_finished());
        tasks.push(handle);
    }

    /// 第 `attempt` 次重连的退避时长（线性增长，封顶 5s）。
    fn backoff(attempt: usize) -> Duration {
        Duration::from_millis(
            (RECONNECT_BACKOFF_BASE_MS * attempt as u64).min(RECONNECT_BACKOFF_MAX_MS),
        )
    }
}

impl Drop for RedisPubSubSsoChannel {
    fn drop(&mut self) {
        // Drop 时 abort 全部订阅任务，避免任务泄漏（资源回收修复）
        for handle in self.tasks.lock().drain(..) {
            handle.abort();
        }
    }
}

#[async_trait]
impl SsoChannel for RedisPubSubSsoChannel {
    async fn push(&self, topic: &str, message: &str) -> GarrisonResult<()> {
        let mut conn = self.connection_manager.clone();
        redis::cmd("PUBLISH")
            .arg(topic)
            .arg(message)
            .query_async::<i64>(&mut conn)
            .await
            .map_err(|e| GarrisonError::Internal(format!("sso-redis-publish::{}", e)))?;
        Ok(())
    }

    async fn subscribe(
        &self,
        topic: &str,
        handler: Box<dyn Fn(String) + Send + Sync>,
    ) -> GarrisonResult<()> {
        let topic = topic.to_string();
        let client = self.client.clone();
        let handler = Arc::new(handler);
        let max_attempts = self.max_reconnect_attempts;

        // oneshot 回传首次连接+订阅结果：失败时调用方拿到 Err（不再"假成功"）
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<GarrisonResult<()>>();

        let handle = tokio::spawn(async move {
            let mut pubsub = match client.get_async_pubsub().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(
                        "Redis SUBSCRIBE connection failed: topic={}, err={}",
                        topic,
                        e
                    );
                    let _ = ready_tx.send(Err(GarrisonError::Internal(format!(
                        "sso-redis-subscribe-connect::{}",
                        e
                    ))));
                    return;
                },
            };

            if let Err(e) = pubsub.subscribe(&topic).await {
                tracing::error!(
                    "Redis SUBSCRIBE subscribe failed: topic={}, err={}",
                    topic,
                    e
                );
                let _ = ready_tx.send(Err(GarrisonError::Internal(format!(
                    "sso-redis-subscribe-register::{}",
                    e
                ))));
                return;
            }
            // 首次订阅成功，通知调用方
            let _ = ready_tx.send(Ok(()));

            // 消息循环 + 断线重连
            let mut attempt = 0usize;
            loop {
                {
                    let mut msg_stream = pubsub.on_message();
                    while let Some(msg) = msg_stream.next().await {
                        let payload: Result<String, _> = msg.get_payload();
                        match payload {
                            Ok(payload_str) => {
                                // 在 catch_unwind 中调用 handler，防止 panic 中断订阅
                                let handler_clone = handler.clone();
                                let result =
                                    std::panic::catch_unwind(AssertUnwindSafe(move || {
                                        handler_clone(payload_str);
                                    }));
                                if result.is_err() {
                                    tracing::warn!(
                                        "SSO channel handler panic: topic={}, continue subscribing",
                                        topic
                                    );
                                }
                            },
                            Err(e) => {
                                tracing::warn!(
                                    "Redis message payload parse failed: topic={}, err={}",
                                    topic,
                                    e
                                );
                            },
                        }
                    }
                }
                // Stream 结束表示连接断开：按可配置次数重连并重新 SUBSCRIBE
                if attempt >= max_attempts {
                    tracing::error!(
                        "Redis SUBSCRIBE stream ended and max reconnect attempts ({}), giving up: topic={}",
                        max_attempts,
                        topic
                    );
                    return;
                }
                attempt += 1;
                let backoff = Self::backoff(attempt);
                tracing::warn!(
                    "Redis SUBSCRIBE stream ended (connection lost): topic={}, reconnect attempt {}/{} in {:?}",
                    topic,
                    attempt,
                    max_attempts,
                    backoff
                );
                tokio::time::sleep(backoff).await;
                match client.get_async_pubsub().await {
                    Ok(mut p) => {
                        if let Err(e) = p.subscribe(&topic).await {
                            tracing::error!("Redis resubscribe failed: topic={}, err={}", topic, e);
                            return;
                        }
                        pubsub = p;
                        tracing::info!("Redis SUBSCRIBE reconnected: topic={}", topic);
                        attempt = 0;
                    },
                    Err(e) => {
                        tracing::warn!("Redis reconnect failed: topic={}, err={}", topic, e);
                    },
                }
            }
        });

        // 等待首次订阅结果：连接/订阅失败向调用方传播 Err。
        // 注意 oneshot 是双层 Result：外层 RecvError（发送端被 drop）+ 内层
        // 订阅结果——两层都要处理，内层 Err 不得吞掉（否则退回"假成功"）。
        // 失败时任务已结束（send 后即 return），句柄不登记——避免把已死亡的
        // 任务留在 tasks 中污染 shutdown 计数（订阅成功后才登记）。
        match ready_rx.await {
            // 内层 Ok：首次连接+订阅成功
            Ok(Ok(())) => {},
            // 内层 Err：连接/订阅失败，传播给调用方
            Ok(Err(e)) => return Err(e),
            // 发送端被 drop（订阅任务被 abort 等）——订阅未建立
            Err(_) => {
                return Err(GarrisonError::Internal(
                    "sso-redis-subscribe-task-ended::".to_string(),
                ))
            },
        }

        self.track_task(handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // 编译时验证（不需要真实 Redis 连接）
    // ========================================================================

    /// RedisPubSubSsoChannel 实现 SsoChannel trait（验收标准）。
    ///
    /// 编译时验证，不需要真实 Redis 连接。
    #[test]
    fn redis_pubsub_sso_channel_implements_sso_channel() {
        fn assert_sso_channel<T: SsoChannel>() {}
        assert_sso_channel::<RedisPubSubSsoChannel>();
    }

    /// RedisPubSubSsoChannel 是 Send + Sync（约束）。
    #[test]
    fn redis_pubsub_sso_channel_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RedisPubSubSsoChannel>();
    }

    // ========================================================================
    // 错误路径测试（无 Redis 依赖，确定性，任何环境都跑）
    // ========================================================================
    //
    // 利用 `redis::Client::get_connection_manager_lazy`（惰性连接：构造不触发
    // TCP 连接，首次命令才连接）指向必然拒绝连接的端口（127.0.0.1:1），
    // 在无 Redis 的环境下确定性触发连接失败分支。
    // 重试次数压到 1 次、退避压到 1ms，保证测试快速结束。

    /// 构造指向不可达端口（127.0.0.1:1）的 RedisPubSubSsoChannel。
    ///
    /// 惰性 ConnectionManager 构造不触发连接，因此本辅助函数在无 Redis
    /// 环境下也能确定性成功。
    fn make_channel_with_unreachable_port() -> RedisPubSubSsoChannel {
        use std::time::Duration;

        let client = redis::Client::open("redis://127.0.0.1:1").unwrap();
        let connection_manager = client
            .get_connection_manager_lazy(
                redis::aio::ConnectionManagerConfig::default()
                    .set_number_of_retries(1)
                    .set_min_delay(Duration::from_millis(1)),
            )
            .expect("惰性 ConnectionManager 构造不应触发连接");
        RedisPubSubSsoChannel::new(connection_manager, client)
    }

    /// push 到不可达端口返回 Err（覆盖 PUBLISH map_err 错误分支）。
    ///
    /// 惰性连接在首次 PUBLISH 时才尝试连接 127.0.0.1:1（必然 ECONNREFUSED），
    /// 错误经 map_err 包装为 `GarrisonError::Internal`（前缀 `sso-redis-publish::`）。
    #[tokio::test]
    async fn push_to_unreachable_redis_returns_err() {
        use std::time::Duration;

        let channel = make_channel_with_unreachable_port();
        let result = channel
            .push("garrison-channel-test-push-unreachable", "hello")
            .await;
        match result {
            Err(GarrisonError::Internal(msg)) => assert!(
                msg.contains("sso-redis-publish::"),
                "错误应带 sso-redis-publish:: 前缀，实际: {msg}"
            ),
            Ok(_) => panic!("push 到不可达端口应返回 Err，实际 Ok"),
            Err(other) => panic!("期望 Internal 错误，实际: {other:?}"),
        }
        // 留出后台重连任务的时间窗口，避免测试结束时产生悬挂告警日志
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    /// subscribe 对不可达端口返回 Err（错误处理修复：订阅失败不再"假成功"，
    /// 首次连接失败经 oneshot 传播给调用方，前缀 `sso-redis-subscribe-connect::`）。
    #[tokio::test]
    async fn subscribe_returns_err_when_redis_unreachable() {
        let channel = make_channel_with_unreachable_port();
        let result = channel
            .subscribe(
                "garrison-channel-test-subscribe-unreachable",
                Box::new(|_| {}),
            )
            .await;
        match result {
            Err(GarrisonError::Internal(msg)) => assert!(
                msg.contains("sso-redis-subscribe-connect::"),
                "错误应带 sso-redis-subscribe-connect:: 前缀，实际: {msg}"
            ),
            Ok(()) => panic!("subscribe 到不可达端口应返回 Err，实际 Ok（假成功已修复）"),
            Err(other) => panic!("期望 Internal 错误，实际: {other:?}"),
        }
        // 失败任务未登记：shutdown 应返回 0
        assert_eq!(channel.shutdown(), 0, "失败订阅不应登记任务句柄");
    }

    /// with_reconnect_attempts 配置重连次数（builder 链式调用）。
    ///
    /// `#[tokio::test]`：`get_connection_manager_lazy` 需要 Tokio runtime 上下文
    ///（redis 内部注册 waker/驱动，无 reactor 时 panic）。
    #[tokio::test]
    async fn with_reconnect_attempts_configures_reconnect_budget() {
        use std::time::Duration;

        let client = redis::Client::open("redis://127.0.0.1:1").unwrap();
        let connection_manager = client
            .get_connection_manager_lazy(
                redis::aio::ConnectionManagerConfig::default()
                    .set_number_of_retries(1)
                    .set_min_delay(Duration::from_millis(1)),
            )
            .expect("惰性 ConnectionManager 构造不应触发连接");
        let channel =
            RedisPubSubSsoChannel::new(connection_manager, client).with_reconnect_attempts(0);
        assert_eq!(channel.max_reconnect_attempts, 0, "应可配置重连次数");
        // 未订阅时 shutdown 返回 0（幂等）
        assert_eq!(channel.shutdown(), 0);
    }

    /// 重连退避计算：线性增长且封顶。
    #[test]
    fn backoff_grows_linearly_and_caps() {
        assert_eq!(
            RedisPubSubSsoChannel::backoff(1),
            Duration::from_millis(500)
        );
        assert_eq!(
            RedisPubSubSsoChannel::backoff(2),
            Duration::from_millis(1000)
        );
        assert_eq!(
            RedisPubSubSsoChannel::backoff(100),
            Duration::from_millis(RECONNECT_BACKOFF_MAX_MS),
            "退避应封顶 5s"
        );
    }

    /// `redis::Client::open` 对非法 URL 快速失败（构造期确定性校验，
    /// 不发起任何网络连接）。
    #[test]
    fn client_open_rejects_malformed_url() {
        assert!(redis::Client::open("not-a-redis-url").is_err());
    }

    // ========================================================================
    // 深层分支集成测试（运行时探活门控，约定同 tests/acceptance/environment.rs：
    // Redis 不可达时 eprintln!("[SKIP] …") 并 return——测试通过但不运行）
    // ========================================================================

    /// TCP 探活本地 Redis（127.0.0.1:6379）是否可达。
    async fn redis_reachable() -> bool {
        tokio::net::TcpStream::connect("127.0.0.1:6379")
            .await
            .is_ok()
    }

    /// Redis 不可达时的标准 [SKIP] 输出与跳过返回。
    fn skip_if_unreachable(guard: bool, scenario: &str) {
        if !guard {
            eprintln!(
                "[SKIP] Redis 不可达（127.0.0.1:6379 未监听），跳过 {scenario}（CI 将注入 \
                 Redis service 真实执行）"
            );
        }
    }

    /// 构造连接本地 Redis 的 RedisPubSubSsoChannel（调用前须探活通过）。
    async fn make_local_channel() -> RedisPubSubSsoChannel {
        let client = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let connection_manager = client
            .get_connection_manager()
            .await
            .expect("连接 Redis 失败");
        RedisPubSubSsoChannel::new(connection_manager, client)
    }

    /// 构造 RedisPubSubSsoChannel 实例（验收标准）。
    ///
    /// Redis 不可达时 [SKIP] 跳过（不失败）。
    #[tokio::test]
    async fn new_creates_instance_with_redis() {
        let reachable = redis_reachable().await;
        skip_if_unreachable(reachable, "new_creates_instance_with_redis");
        if !reachable {
            return;
        }

        let channel = make_local_channel().await;
        // 构造成功即验证
        let _ = &channel.client;
        let _ = &channel.connection_manager;
    }

    /// push 执行 PUBLISH 命令并返回 Ok（验收标准）。
    #[tokio::test]
    async fn push_executes_publish_command() {
        let reachable = redis_reachable().await;
        skip_if_unreachable(reachable, "push_executes_publish_command");
        if !reachable {
            return;
        }

        let channel = make_local_channel().await;
        let result = channel.push("garrison-channel-test-push", "hello").await;
        assert!(result.is_ok(), "PUBLISH 应返回 Ok: {:?}", result);
    }

    /// subscribe 启动后台 task 并接收消息（验收标准）。
    #[tokio::test]
    async fn subscribe_receives_published_message() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let reachable = redis_reachable().await;
        skip_if_unreachable(reachable, "subscribe_receives_published_message");
        if !reachable {
            return;
        }

        let channel = Arc::new(make_local_channel().await);

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let topic = "garrison-channel-test-subscribe-receive";

        // 订阅
        channel
            .subscribe(
                topic,
                Box::new(move |msg: String| {
                    if msg == "test-payload" {
                        counter_clone.fetch_add(1, Ordering::SeqCst);
                    }
                }),
            )
            .await
            .expect("subscribe 失败");

        // 等待订阅就绪（后台 task 建立 SUBSCRIBE 连接）
        tokio::time::sleep(Duration::from_millis(300)).await;

        // 发布消息
        channel.push(topic, "test-payload").await.unwrap();

        // 等待消息接收
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1, "应收到 1 条消息");

        // JoinHandle 已登记（不再即弃）：shutdown 可停止任务并返回计数
        let stopped = channel.shutdown();
        assert!(
            stopped >= 1,
            "shutdown 应停止至少 1 个订阅任务，实际: {stopped}"
        );
    }

    /// payload 非 UTF-8 时走解析失败 warn 分支：handler 不被调用，
    /// 且订阅不中断（后续合法消息仍可达）。
    #[tokio::test]
    async fn subscribe_ignores_non_utf8_payload() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let reachable = redis_reachable().await;
        skip_if_unreachable(reachable, "subscribe_ignores_non_utf8_payload");
        if !reachable {
            return;
        }

        let channel = Arc::new(make_local_channel().await);

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let topic = "garrison-channel-test-payload-parse";

        // 订阅：仅对合法标记消息计数
        channel
            .subscribe(
                topic,
                Box::new(move |msg: String| {
                    if msg == "after-invalid" {
                        counter_clone.fetch_add(1, Ordering::SeqCst);
                    }
                }),
            )
            .await
            .expect("subscribe 失败");
        tokio::time::sleep(Duration::from_millis(300)).await;

        // 另建独立 redis 连接发布非 UTF-8 字节（String 解析失败 → warn 分支）
        let publisher = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let mut pub_conn = publisher
            .get_multiplexed_async_connection()
            .await
            .expect("发布用连接应成功");
        let receivers: i64 = redis::cmd("PUBLISH")
            .arg(topic)
            .arg(&b"\xff\xfe\x00not-utf8"[..])
            .query_async(&mut pub_conn)
            .await
            .expect("PUBLISH 非 UTF-8 字节应成功");
        assert!(receivers >= 1, "消息应送达至少 1 个订阅者（证明订阅在线）");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "非 UTF-8 payload 解析失败，handler 不应被调用"
        );

        // 后续合法消息仍应收到（解析失败分支不中断订阅）
        let receivers: i64 = redis::cmd("PUBLISH")
            .arg(topic)
            .arg("after-invalid")
            .query_async(&mut pub_conn)
            .await
            .expect("PUBLISH 合法消息应成功");
        assert!(receivers >= 1, "合法消息应送达订阅者");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "合法 payload 应正常触发 handler（订阅未中断）"
        );
        channel.shutdown();
    }

    /// subscribe 的 handler panic 不中断订阅（约束，
    /// 覆盖 catch_unwind panic 恢复分支）。
    #[tokio::test]
    async fn subscribe_handler_panic_does_not_interrupt() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let reachable = redis_reachable().await;
        skip_if_unreachable(reachable, "subscribe_handler_panic_does_not_interrupt");
        if !reachable {
            return;
        }

        let channel = Arc::new(make_local_channel().await);

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let topic = "garrison-channel-test-handler-panic";

        // 订阅：handler 在第一次调用时 panic，第二次正常计数
        channel
            .subscribe(
                topic,
                Box::new(move |msg: String| {
                    let count = counter_clone.fetch_add(1, Ordering::SeqCst);
                    if count == 0 && msg == "panic-trigger" {
                        panic!("handler 首次调用 panic");
                    }
                }),
            )
            .await
            .expect("subscribe 失败");

        // 等待订阅就绪
        tokio::time::sleep(Duration::from_millis(300)).await;

        // 发布第一条消息（触发 panic）
        channel.push(topic, "panic-trigger").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        // 发布第二条消息（验证订阅未中断）
        channel.push(topic, "normal").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        // counter 应为 2（handler 被调用两次，第一次 panic 但不中断）
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "handler 应被调用两次（panic 不中断）"
        );
        channel.shutdown();
    }

    /// shutdown 后订阅任务被 abort：后续消息不再触发 handler（退订语义）。
    #[tokio::test]
    async fn shutdown_stops_message_delivery() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let reachable = redis_reachable().await;
        skip_if_unreachable(reachable, "shutdown_stops_message_delivery");
        if !reachable {
            return;
        }

        let channel = Arc::new(make_local_channel().await);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let topic = "garrison-channel-test-shutdown";

        channel
            .subscribe(
                topic,
                Box::new(move |_| {
                    counter_clone.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .await
            .expect("subscribe 失败");
        tokio::time::sleep(Duration::from_millis(300)).await;

        // 退订：abort 后台任务
        let stopped = channel.shutdown();
        assert!(stopped >= 1, "shutdown 应停止订阅任务");
        tokio::time::sleep(Duration::from_millis(100)).await;

        // shutdown 后发布的消息不应再触发 handler
        channel.push(topic, "after-shutdown").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "shutdown 后不应再收到消息（退订语义）"
        );
    }
}
