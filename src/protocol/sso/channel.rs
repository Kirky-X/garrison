//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Redis pub/sub SsoChannel 实现。
//!
//! 基于 Redis pub/sub 实现跨实例 SSO 消息推送，替代 `NoopSsoChannel`。
//!
//! 仅在 `cache-redis` + `protocol-sso-server` feature 同时启用时编译。

use super::server::SsoChannel;
use crate::error::{BulwarkError, BulwarkResult};
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
    async fn push(&self, topic: &str, message: &str) -> BulwarkResult<()> {
        let mut conn = self.connection_manager.clone();
        redis::cmd("PUBLISH")
            .arg(topic)
            .arg(message)
            .query_async::<i64>(&mut conn)
            .await
            .map_err(|e| BulwarkError::Internal(format!("sso-redis-publish::{}", e)))?;
        Ok(())
    }

    async fn subscribe(
        &self,
        topic: &str,
        handler: Box<dyn Fn(String) + Send + Sync>,
    ) -> BulwarkResult<()> {
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
    // 集成测试（需要真实 Redis 连接，默认 #[ignore]）
    // ========================================================================

    /// 构造 RedisPubSubSsoChannel 实例（spec R-005 验收标准）。
    ///
    /// 需要真实 Redis 连接，默认忽略。运行方式：
    /// `cargo test --lib --features cache-redis,protocol-sso-server -- --ignored channel::tests`
    #[tokio::test]
    #[ignore = "需要真实 Redis 连接（REDIS_URL 环境变量）"]
    async fn new_creates_instance_with_redis() {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let client = redis::Client::open(redis_url.as_str()).unwrap();
        let connection_manager = client
            .get_connection_manager()
            .await
            .expect("连接 Redis 失败");
        let channel = RedisPubSubSsoChannel::new(connection_manager, client);
        // 构造成功即验证
        let _ = &channel.client;
        let _ = &channel.connection_manager;
    }

    /// push 执行 PUBLISH 命令并返回 Ok（spec R-005 验收标准）。
    #[tokio::test]
    #[ignore = "需要真实 Redis 连接（REDIS_URL 环境变量）"]
    async fn push_executes_publish_command() {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let client = redis::Client::open(redis_url.as_str()).unwrap();
        let connection_manager = client
            .get_connection_manager()
            .await
            .expect("连接 Redis 失败");
        let channel = RedisPubSubSsoChannel::new(connection_manager, client);
        let result = channel.push("test-topic", "hello").await;
        assert!(result.is_ok(), "PUBLISH 应返回 Ok: {:?}", result);
    }

    /// subscribe 启动后台 task 并接收消息（spec R-005 验收标准）。
    #[tokio::test]
    #[ignore = "需要真实 Redis 连接（REDIS_URL 环境变量）"]
    async fn subscribe_receives_published_message() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let client = redis::Client::open(redis_url.as_str()).unwrap();
        let connection_manager = client
            .get_connection_manager()
            .await
            .expect("连接 Redis 失败");
        let channel = Arc::new(RedisPubSubSsoChannel::new(connection_manager, client));

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let topic = "test-sso-channel-subscribe";

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

        // 等待订阅就绪
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 发布消息
        channel.push(topic, "test-payload").await.unwrap();

        // 等待消息接收
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1, "应收到 1 条消息");
    }

    /// subscribe 的 handler panic 不中断订阅（spec R-005 约束）。
    #[tokio::test]
    #[ignore = "需要真实 Redis 连接（REDIS_URL 环境变量）"]
    async fn subscribe_handler_panic_does_not_interrupt() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let client = redis::Client::open(redis_url.as_str()).unwrap();
        let connection_manager = client
            .get_connection_manager()
            .await
            .expect("连接 Redis 失败");
        let channel = Arc::new(RedisPubSubSsoChannel::new(connection_manager, client));

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let topic = "test-sso-channel-panic";

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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 发布第一条消息（触发 panic）
        channel.push(topic, "panic-trigger").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 发布第二条消息（验证订阅未中断）
        channel.push(topic, "normal").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // counter 应为 2（handler 被调用两次，第一次 panic 但不中断）
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "handler 应被调用两次（panic 不中断）"
        );
    }
}
