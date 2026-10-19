// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 限流执行后端抽象：把「计数器 + 窗口 + KV 存储」收敛为可切换的运行时。
//!
//! 默认实现沿 `GarrisonDao`（[`GarrisonDaoDistributedLimiter`] + [`GarrisonDaoStorage`]）；
//! 启用 `rate-limit-redis` 后可按 `GarrisonConfig::rate_limit_backend`
//! 切换到独立 Redis 限流运行时（`RedisLimiterBackend`），会话 / token /
//! geo / device 等数据仍留在原 DAO。
//!
//! # 设计边界
//!
//! - 只抽象「限流计数」所需的操作，不包装完整 `GarrisonDao`：避免按 key 前缀隐式路由，
//!   也避免会话操作被误送到 Redis。
//! - `reset_prefix` 为测试 / 运维辅助方法：DAO 后端经 `keys()`（可能为全表扫描），
//!   Redis 后端经 `SCAN`；生产热路径不得调用。

use crate::dao::GarrisonDao;
#[cfg(feature = "rate-limit-redis")]
use crate::error::GarrisonResult;
use async_trait::async_trait;
use limiteron::error::LimiteronError;
use limiteron::limiters::DistributedLimiter;
use limiteron::storage::Storage;
use std::sync::Arc;
use std::time::Duration;

use super::distributed::GarrisonDaoDistributedLimiter;
use super::errors::map_to_limiter_err;
use super::storage::GarrisonDaoStorage;

/// 限流执行后端：在 limiteron [`DistributedLimiter`] 之上补充 garrison 消费方需要的
/// 原子阈值判定、滑动窗口判定与前缀清理。
#[async_trait]
pub trait LimiterBackend: DistributedLimiter {
    /// 原子递增计数器并判断是否超过阈值（实现语义见各后端文档）。
    async fn atomic_check_and_incr(
        &self,
        key: &str,
        threshold: u64,
        ttl: Duration,
    ) -> Result<bool, LimiteronError>;

    /// 删除匹配 `{prefix}*` 的全部计数器（测试 / 运维辅助；生产慎用）。
    async fn reset_prefix(&self, prefix: &str) -> Result<(), LimiteronError>;

    /// 滑动窗口判定（`firewall-ratelimit` 门控）：返回 `(allowed, current_count, reset)`。
    #[cfg(feature = "firewall-ratelimit")]
    async fn allow_sliding_window(
        &self,
        key: &str,
        window_ms: u64,
        max_requests: u64,
    ) -> Result<(bool, u64, u64), LimiteronError>;
}

/// 限流运行时：计数器后端 + KV 存储后端成对出现，保证同一策略的计数与滑窗/验证码
/// 数据落在同一存储上。
#[derive(Clone)]
pub struct LimiterRuntime {
    /// 计数器后端。
    limiter: Arc<dyn LimiterBackend>,
    /// KV 存储后端（滑窗降级路径、验证码答案）。
    storage: Arc<dyn Storage>,
}

impl LimiterRuntime {
    /// 构造 DAO 后端运行时（默认路径，行为与 rc.3 一致）。
    pub fn dao(dao: Arc<dyn GarrisonDao>) -> Self {
        let limiter: Arc<dyn LimiterBackend> =
            Arc::new(GarrisonDaoDistributedLimiter::new(dao.clone()));
        let storage: Arc<dyn Storage> = Arc::new(GarrisonDaoStorage::new(dao));
        Self { limiter, storage }
    }

    /// 按配置选择运行时：`Memory` → DAO 后端；`Redis` → 独立 Redis 限流运行时。
    ///
    /// 连接失败返回 `GarrisonError::Config`（启动期 fail-closed，不静默降级到内存）。
    #[cfg(feature = "rate-limit-redis")]
    pub async fn from_config(
        config: &crate::config::GarrisonConfig,
        dao: Arc<dyn GarrisonDao>,
    ) -> GarrisonResult<Self> {
        use crate::strategy::rate_limiter_backend::RateLimitBackend;

        match &config.rate_limit_backend {
            RateLimitBackend::Memory => Ok(Self::dao(dao)),
            RateLimitBackend::Redis { redis_url } => {
                let backend = super::redis::RedisLimiterBackend::connect(redis_url).await?;
                Ok(Self::redis(backend))
            },
        }
    }

    /// 由已连接的 Redis 后端构造运行时（同一实例同时承担计数器与 KV 存储）。
    #[cfg(feature = "rate-limit-redis")]
    pub fn redis(backend: super::redis::RedisLimiterBackend) -> Self {
        let backend = Arc::new(backend);
        let limiter: Arc<dyn LimiterBackend> = backend.clone();
        let storage: Arc<dyn Storage> = backend;
        Self { limiter, storage }
    }

    /// 计数器后端（克隆 `Arc`）。
    pub fn limiter(&self) -> Arc<dyn LimiterBackend> {
        self.limiter.clone()
    }

    /// KV 存储后端（克隆 `Arc`）。
    pub fn storage(&self) -> Arc<dyn Storage> {
        self.storage.clone()
    }
}

#[async_trait]
impl LimiterBackend for GarrisonDaoDistributedLimiter {
    async fn atomic_check_and_incr(
        &self,
        key: &str,
        threshold: u64,
        ttl: Duration,
    ) -> Result<bool, LimiteronError> {
        GarrisonDaoDistributedLimiter::atomic_check_and_incr(self, key, threshold, ttl).await
    }

    async fn reset_prefix(&self, prefix: &str) -> Result<(), LimiteronError> {
        let pattern = format!("{prefix}*");
        let keys = self.dao.keys(&pattern).await.map_err(map_to_limiter_err)?;
        for key in keys {
            self.dao.delete(&key).await.map_err(map_to_limiter_err)?;
        }
        Ok(())
    }

    #[cfg(feature = "firewall-ratelimit")]
    async fn allow_sliding_window(
        &self,
        key: &str,
        window_ms: u64,
        max_requests: u64,
    ) -> Result<(bool, u64, u64), LimiteronError> {
        GarrisonDaoDistributedLimiter::allow_sliding_window(self, key, window_ms, max_requests)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    fn dao_runtime() -> (LimiterRuntime, Arc<MockDao>) {
        let dao = Arc::new(MockDao::new());
        (LimiterRuntime::dao(dao.clone()), dao)
    }

    /// DAO 后端的 `reset_prefix` 只清理匹配前缀的键。
    #[tokio::test]
    async fn dao_reset_prefix_removes_only_matching_keys() {
        let (runtime, dao) = dao_runtime();
        dao.set("fw:ip:1.1.1.1", "3", 60).await.unwrap();
        dao.set("fw:ip:2.2.2.2", "1", 60).await.unwrap();
        dao.set("fw:acct:1001", "2", 60).await.unwrap();

        runtime.limiter().reset_prefix("fw:ip:").await.unwrap();

        assert!(dao.get("fw:ip:1.1.1.1").await.unwrap().is_none());
        assert!(dao.get("fw:ip:2.2.2.2").await.unwrap().is_none());
        assert_eq!(
            dao.get("fw:acct:1001").await.unwrap().as_deref(),
            Some("2"),
            "非目标前缀不得被清理"
        );
    }

    /// DAO 后端的计数器与存储共享同一 DAO。
    #[tokio::test]
    async fn dao_runtime_counts_and_storage_share_backend() {
        let (runtime, dao) = dao_runtime();
        runtime
            .limiter()
            .incr_with_ttl("fw:ip:9.9.9.9", 1, Duration::from_secs(60))
            .await
            .unwrap();
        runtime
            .storage()
            .set("rl:ip:9.9.9.9:answer", "42", Some(60))
            .await
            .unwrap();

        assert_eq!(
            runtime.limiter().get_count("fw:ip:9.9.9.9").await.unwrap(),
            1
        );
        assert_eq!(
            dao.get("rl:ip:9.9.9.9:answer").await.unwrap().as_deref(),
            Some("42")
        );
    }

    /// `Memory` 配置走 DAO 后端，不触发 Redis 连接。
    #[cfg(feature = "rate-limit-redis")]
    #[tokio::test]
    async fn from_config_memory_uses_dao_backend() {
        let dao = Arc::new(MockDao::new());
        let config = crate::config::GarrisonConfig::default_config();
        let runtime = LimiterRuntime::from_config(&config, dao).await.unwrap();
        runtime
            .limiter()
            .incr_with_ttl("fw:acct:mem", 1, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(runtime.limiter().get_count("fw:acct:mem").await.unwrap(), 1);
    }
}
