// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Redis pub/sub SsoChannel 实现。
//!
//! 基于 oxcache `pubsub` 设施（[`oxcache::pubsub::RedisPubSub`]）实现跨实例
//! SSO 消息推送，替代 `NoopSsoChannel`。
//!
//! 仅在 `cache-redis` + `protocol-sso-server` feature 同时启用时编译。
//!
//! # 能力归属（2026-09 自研栈收敛）
//!
//! 发布/订阅/断线重连/handler panic 隔离/后台任务回收等 pub/sub 原语已下沉至
//! oxcache `pubsub` feature（`oxcache::pubsub::RedisPubSub`），本结构体仅做
//! garrison `SsoChannel` 契约适配与错误映射。行为级测试（消息收发、panic
//! 隔离、shutdown 停投递等）随实现位于 oxcache。
//!
//! # 订阅生命周期
//!
//! - `subscribe` 经 oneshot 回传首次连接+订阅结果：连接/订阅失败时向调用方
//!   返回 `Err`（不"假成功"）；
//! - 后台任务由 oxcache `RedisPubSub` 统一登记回收（shutdown/Drop abort）；
//! - 断线后按可配置次数线性退避重连（[`RedisPubSubSsoChannel::with_reconnect_attempts`]）。

use super::server::SsoChannel;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use std::sync::Arc;

/// 基于 Redis pub/sub 的 SsoChannel 实现。
///
/// 底层为 oxcache `RedisPubSub`：PUBLISH 走多路复用连接（自动重连），
/// SUBSCRIBE 使用专用订阅连接（订阅模式需要独占连接），断线按可配置
/// 次数线性退避重连（重连成功计数清零）。
pub struct RedisPubSubSsoChannel {
    /// oxcache pub/sub 设施（发布 + 订阅 + 重连 + 任务回收）。
    pubsub: oxcache::pubsub::RedisPubSub,
}

impl RedisPubSubSsoChannel {
    /// 从 Redis URL 创建通道（构造期 fail-fast：URL 非法或不可达即 `Err`）。
    pub async fn new(url: &str) -> GarrisonResult<Self> {
        let pubsub = oxcache::pubsub::RedisPubSub::new(url)
            .await
            .map_err(|e| GarrisonError::Internal(format!("sso-redis-init::{e}")))?;
        Ok(Self { pubsub })
    }

    /// 配置断线重连最大尝试次数（默认 5；0 = 不重连，断连即结束订阅）。
    #[must_use]
    pub fn with_reconnect_attempts(mut self, attempts: usize) -> Self {
        self.pubsub = self.pubsub.with_reconnect_attempts(attempts);
        self
    }

    /// 停止全部后台订阅任务（abort 并清空句柄），返回被停止的任务数。
    pub fn shutdown(&self) -> usize {
        self.pubsub.shutdown()
    }
}

#[async_trait]
impl SsoChannel for RedisPubSubSsoChannel {
    async fn push(&self, topic: &str, message: &str) -> GarrisonResult<()> {
        self.pubsub
            .publish(topic, message)
            .await
            .map(|_| ())
            .map_err(|e| GarrisonError::Internal(format!("sso-redis-publish::{e}")))
    }

    async fn subscribe(
        &self,
        topic: &str,
        handler: Box<dyn Fn(String) + Send + Sync>,
    ) -> GarrisonResult<()> {
        self.pubsub
            .subscribe(topic, Arc::new(handler))
            .await
            .map_err(|e| GarrisonError::Internal(format!("sso-redis-subscribe::{e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // 编译时验证（不需要真实 Redis 连接）
    // ========================================================================

    /// RedisPubSubSsoChannel 实现 SsoChannel trait（验收标准）。
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
    // 构造期 fail-fast（无 Redis 依赖，确定性，任何环境都跑）
    // ========================================================================

    /// 构造指向不可达端口（127.0.0.1:1）的通道返回 Err
    /// （oxcache RedisPubSub 构造期预发布连接，URL 不可达显性失败）。
    #[tokio::test]
    async fn new_with_unreachable_port_returns_err() {
        let result = RedisPubSubSsoChannel::new("redis://127.0.0.1:1").await;
        match result {
            Err(GarrisonError::Internal(msg)) => assert!(
                msg.contains("sso-redis-init::"),
                "错误应带 sso-redis-init:: 前缀，实际: {msg}"
            ),
            Ok(_) => panic!("构造指向不可达端口应返回 Err，实际 Ok"),
            Err(other) => panic!("期望 Internal 错误，实际: {other:?}"),
        }
    }

    /// 非法 URL 在构造期快速失败（确定性校验，不发起网络连接）。
    #[tokio::test]
    async fn new_rejects_malformed_url() {
        let result = RedisPubSubSsoChannel::new("not-a-redis-url").await;
        assert!(result.is_err(), "非法 URL 应构造失败");
    }

    // ========================================================================
    // 深层分支集成测试（运行时探活门控，约定同 tests/acceptance/environment.rs：
    // Redis 不可达时 eprintln!("[SKIP] …") 并 return——测试通过但不运行）。
    //
    // pub/sub 行为级测试（消息收发、非 UTF8 payload、handler panic 隔离、
    // shutdown 停投递、断线重连）已随实现下沉至 oxcache pubsub 模块；
    // 此处保留通道契约层面的端到端验证（push/subscribe 走通 SsoChannel trait）。
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

    /// 构造连接本地 Redis 的通道（调用前须探活通过）。
    async fn make_local_channel() -> RedisPubSubSsoChannel {
        RedisPubSubSsoChannel::new("redis://127.0.0.1:6379")
            .await
            .expect("连接 Redis 失败")
    }

    /// 构造实例（验收标准）。Redis 不可达时 [SKIP] 跳过（不失败）。
    #[tokio::test]
    async fn new_creates_instance_with_redis() {
        let reachable = redis_reachable().await;
        skip_if_unreachable(reachable, "new_creates_instance_with_redis");
        if !reachable {
            return;
        }

        let channel = make_local_channel().await;
        // 未订阅时 shutdown 幂等返回 0
        assert_eq!(channel.shutdown(), 0);
    }

    /// push 执行 PUBLISH 并返回 Ok（验收标准，走 SsoChannel trait 全链路）。
    #[tokio::test]
    async fn push_executes_publish_command() {
        let reachable = redis_reachable().await;
        skip_if_unreachable(reachable, "push_executes_publish_command");
        if !reachable {
            return;
        }

        let channel = make_local_channel().await;
        let result = channel.push("garrison-channel-test-push", "hello").await;
        assert!(result.is_ok(), "push 应成功，实际: {result:?}");
    }

    /// subscribe 建立订阅后能收到 push 的消息（SsoChannel trait 端到端）。
    #[tokio::test]
    async fn subscribe_receives_published_message() {
        let reachable = redis_reachable().await;
        skip_if_unreachable(reachable, "subscribe_receives_published_message");
        if !reachable {
            return;
        }

        let channel = make_local_channel().await;
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let topic = "garrison-channel-test-e2e";
        channel
            .subscribe(
                topic,
                Box::new(move |msg| {
                    let _ = tx.send(msg);
                }),
            )
            .await
            .expect("subscribe 应成功");

        // 订阅确认（subscribe oneshot 回传）与首条消息投递之间在 llvm-cov
        // 全量并发下可能显著慢于常规运行（曾致 CI Coverage 腿偶发超时）：
        // 带上限的"发布-等待-未达再发布"重试，保证确定性而非放宽断言。
        let mut received: Option<String> = None;
        for _ in 0..3 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            channel.push(topic, "test-payload").await.unwrap();
            if let Ok(msg) = rx.recv_timeout(std::time::Duration::from_secs(3)) {
                received = Some(msg);
                break;
            }
        }
        assert_eq!(
            received.as_deref(),
            Some("test-payload"),
            "应收到发布的消息"
        );
        channel.shutdown();
    }
}
