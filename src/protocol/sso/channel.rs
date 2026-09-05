//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Redis pub/sub SsoChannel 实现。
//!
//! 基于 Redis pub/sub 实现跨实例 SSO 消息推送，替代 `NoopSsoChannel`。
//!
//! 仅在 `cache-redis` + `protocol-sso-server` feature 同时启用时编译。

use super::server::SsoChannel;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use futures::StreamExt;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

/// 基于 Redis pub/sub 的 SsoChannel 实现。
///
/// 使用 `redis::aio::ConnectionManager` 执行 PUBLISH 命令（支持自动重连），
/// 使用 `redis::Client` 创建独立的 PubSub 连接进行 SUBSCRIBE（订阅模式需要独占连接）。
///
/// **设计说明**：spec R-005 原始设计为 `new(connection_manager) -> Self`，
/// 但 `ConnectionManager` 是多路复用连接，不支持 pub/sub 订阅模式（SUBSCRIBE 会独占连接）。
/// 因此额外存储 `redis::Client` 用于创建独立的 PubSub 订阅连接。
pub struct RedisPubSubSsoChannel {
    /// Redis 客户端（用于创建独立的 PubSub 订阅连接）。
    client: redis::Client,
    /// 连接管理器（用于 PUBLISH 命令，支持自动重连）。
    connection_manager: redis::aio::ConnectionManager,
}

impl RedisPubSubSsoChannel {
    /// 创建新的 `RedisPubSubSsoChannel` 实例。
    ///
    /// # 参数
    /// - `connection_manager`: Redis 连接管理器（用于 PUBLISH 命令，支持自动重连）。
    /// - `client`: Redis 客户端（用于创建独立的 PubSub 订阅连接）。
    ///
    /// # 设计偏差
    /// spec R-005 原始签名为 `new(connection_manager) -> Self`，
    /// 但 `ConnectionManager` 不支持 pub/sub 订阅模式，需额外传入 `redis::Client`。
    pub fn new(connection_manager: redis::aio::ConnectionManager, client: redis::Client) -> Self {
        Self {
            client,
            connection_manager,
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

        tokio::spawn(async move {
            let mut pubsub = match client.get_async_pubsub().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(
                        "Redis SUBSCRIBE connection failed: topic={}, err={}",
                        topic,
                        e
                    );
                    return;
                },
            };

            if let Err(e) = pubsub.subscribe(&topic).await {
                tracing::error!(
                    "Redis SUBSCRIBE subscribe failed: topic={}, err={}",
                    topic,
                    e
                );
                return;
            }

            let mut msg_stream = pubsub.on_message();
            while let Some(msg) = msg_stream.next().await {
                let payload: Result<String, _> = msg.get_payload();
                match payload {
                    Ok(payload_str) => {
                        // 在 catch_unwind 中调用 handler，防止 panic 中断订阅（spec R-005）
                        let handler_clone = handler.clone();
                        let result = std::panic::catch_unwind(AssertUnwindSafe(move || {
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
            // Stream 结束表示连接断开，后台 task 自然退出
            tracing::info!("Redis SUBSCRIBE stream ended: topic={}", topic);
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // 编译时验证（不需要真实 Redis 连接）
    // ========================================================================

    /// RedisPubSubSsoChannel 实现 SsoChannel trait（spec R-005 验收标准）。
    ///
    /// 编译时验证，不需要真实 Redis 连接。
    #[test]
    fn redis_pubsub_sso_channel_implements_sso_channel() {
        fn assert_sso_channel<T: SsoChannel>() {}
        assert_sso_channel::<RedisPubSubSsoChannel>();
    }

    /// RedisPubSubSsoChannel 是 Send + Sync（spec R-005 约束）。
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

    /// subscribe 对不可达端口仍返回 Ok（spec R-005 语义：连接失败仅由后台
    /// task 记日志，不向调用方传播——覆盖 spawn 后台任务 + get_async_pubsub
    /// 连接失败早退分支）。
    #[tokio::test]
    async fn subscribe_returns_ok_when_redis_unreachable() {
        use std::time::Duration;

        let channel = make_channel_with_unreachable_port();
        let result = channel
            .subscribe(
                "garrison-channel-test-subscribe-unreachable",
                Box::new(|_| {}),
            )
            .await;
        assert!(
            result.is_ok(),
            "subscribe 本身应返回 Ok（后台任务内部失败仅记日志），实际: {:?}",
            result
        );
        // 留出 spawn 的后台任务时间跑完连接失败分支（get_async_pubsub Err → 早退）
        tokio::time::sleep(Duration::from_millis(200)).await;
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

    /// 构造 RedisPubSubSsoChannel 实例（spec R-005 验收标准）。
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

    /// push 执行 PUBLISH 命令并返回 Ok（spec R-005 验收标准）。
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

    /// subscribe 启动后台 task 并接收消息（spec R-005 验收标准）。
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
    }

    /// subscribe 的 handler panic 不中断订阅（spec R-005 约束，
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
    }
}
