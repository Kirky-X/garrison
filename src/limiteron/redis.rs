// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Redis 限流运行时（`rate-limit-redis` 门控）。
//!
//! 复用 `oxcache::backend::RedisBackend` 的连接管理 / 熔断能力与 limiteron
//! `RedisDistributedLimiter` 的 Lua 脚本契约，为 garrison 提供与会话 DAO 解耦的
//! 分布式限流后端：
//!
//! - 计数器（`incr` / `incr_with_ttl` / `get_count` / `reset`）：limiteron Lua 原子脚本；
//! - 滑动窗口：limiteron `SLIDING_WINDOW_SCRIPT`（Sorted Set）；
//! - KV 存储（滑窗降级路径、验证码答案）：oxcache `Cache` 异步 API；
//! - 前缀清理：oxcache `Cache::keys`（后端为 `SCAN`，非 `KEYS`）。
//!
//! # 连接与故障语义
//!
//! 连接在启动期建立，失败返回 `GarrisonError::Config`（fail-closed，不静默降级）；
//! 运行期 Lua/网络错误原样向上传播，由调用方按 fail-closed 处理。eval 超时钉定 1s
//! （limiteron 默认 5s 对登录热路径过长）。
//!
//! 非 TLS 连接受 oxcache 安全策略约束：生产应使用 `rediss://`；开发/测试可显式设置
//! `OXCACHE_ALLOW_INSECURE_REDIS=I_UNDERSTAND_THE_RISKS`（与 `cache-redis` 既有语义一致）。
//!
//! # 键空间
//!
//! 键名沿用 garrison 既有格式（`fw:ip:*` / `fw:acct:*` / `rl:*`），不做额外前缀；
//! 建议使用独立 Redis DB 或独立实例，避免与 oxcache 缓存键空间混用。

use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use limiteron::error::{LimiteronError, StorageError};
use limiteron::limiters::{DistributedLimiter, Limiter, RedisDistributedLimiter};
use limiteron::storage::Storage;
use oxcache::backend::RedisBackend;
use oxcache::Cache;
use std::sync::Arc;
use std::time::Duration;

use super::backend::LimiterBackend;
use crate::strategy::rate_limiter_backend::RateLimitBackend;

/// eval 超时：限制 Redis 抖动对登录热路径的拖拽（超时即错误，调用方 fail-closed）。
const REDIS_LIMITER_EVAL_TIMEOUT: Duration = Duration::from_secs(1);

/// Redis 限流后端：一个实例同时承担计数器与 KV 存储。
pub struct RedisLimiterBackend {
    /// 计数器（limiteron Redis 分布式限流器，内部持有独立 cache 句柄）。
    limiter: RedisDistributedLimiter,
    /// KV 存储 / 前缀扫描（与计数器共享同一 `RedisBackend`，不同 cache 句柄）。
    cache: Cache<String, String>,
}

impl RedisLimiterBackend {
    /// 建立 Redis 连接并构造双 cache 句柄（共享同一连接池 / 熔断器）。
    ///
    /// 错误：连接 / 缓存构建失败返回 `GarrisonError::Config`，消息复用
    /// [`RateLimitBackend`] 的脱敏 `Debug`，不落原始 URL 凭据。
    pub async fn connect(redis_url: &str) -> GarrisonResult<Self> {
        let endpoint = RateLimitBackend::Redis {
            redis_url: redis_url.to_string(),
        };
        let backend = Arc::new(
            RedisBackend::new(redis_url)
                .await
                .map_err(|e| config_error(&endpoint, "connect", &e))?,
        );

        let limiter_cache = Cache::<String, String>::builder()
            .backend_arc(backend.clone())
            .ttl_jitter(0.0)
            .build()
            .await
            .map_err(|e| config_error(&endpoint, "limiter-cache", &e))?;
        let storage_cache = Cache::<String, String>::builder()
            .backend_arc(backend)
            .ttl_jitter(0.0)
            .build()
            .await
            .map_err(|e| config_error(&endpoint, "storage-cache", &e))?;

        Ok(Self {
            // capacity / window_ms 仅供未使用的 `Limiter::allow`；实际调用均显式传窗口参数。
            limiter: RedisDistributedLimiter::new(limiter_cache, 1, 1000)
                .with_timeout(REDIS_LIMITER_EVAL_TIMEOUT),
            cache: storage_cache,
        })
    }
}

/// 构造连接/构建失败错误：`{:?}` 走 `RateLimitBackend` 的脱敏 Debug。
fn config_error(
    endpoint: &RateLimitBackend,
    stage: &str,
    e: &oxcache::OxCacheError,
) -> GarrisonError {
    // 底层错误文本可能回显连接串，这里只保留稳定错误码与脱敏 endpoint。
    let endpoint = format!("{:?}", endpoint);
    GarrisonError::Config(format!(
        "config-rate-limit-redis-connect::{}",
        crate::i18n::translate_detail(
            "config-rate-limit-redis-connect",
            &[
                ("stage", stage),
                ("endpoint", endpoint.as_str()),
                ("code", e.code()),
            ],
        )
    ))
}

fn map_oxcache_err(e: oxcache::OxCacheError) -> LimiteronError {
    LimiteronError::StorageError(StorageError::QueryError(format!(
        "oxcache-redis-limiter::{}",
        e.code()
    )))
}

fn map_oxcache_storage_err(e: oxcache::OxCacheError) -> StorageError {
    StorageError::QueryError(format!("oxcache-redis-limiter::{}", e.code()))
}

/// limiteron `Storage` TTL 语义 → oxcache TTL 参数：`None` / `Some(0)` 表示永久。
fn storage_ttl(ttl: Option<u64>) -> Option<Duration> {
    match ttl {
        None | Some(0) => None,
        Some(secs) => Some(Duration::from_secs(secs)),
    }
}

#[async_trait]
impl Limiter for RedisLimiterBackend {
    async fn allow(&self, cost: u64) -> Result<bool, LimiteronError> {
        self.limiter.allow(cost).await
    }
}

#[async_trait]
impl DistributedLimiter for RedisLimiterBackend {
    async fn incr(&self, key: &str, amount: u64) -> Result<u64, LimiteronError> {
        DistributedLimiter::incr(&self.limiter, key, amount).await
    }

    async fn incr_with_ttl(
        &self,
        key: &str,
        amount: u64,
        ttl: Duration,
    ) -> Result<u64, LimiteronError> {
        DistributedLimiter::incr_with_ttl(&self.limiter, key, amount, ttl).await
    }

    async fn get_count(&self, key: &str) -> Result<u64, LimiteronError> {
        DistributedLimiter::get_count(&self.limiter, key).await
    }

    async fn reset(&self, key: &str) -> Result<(), LimiteronError> {
        DistributedLimiter::reset(&self.limiter, key).await
    }
}

#[async_trait]
impl Storage for RedisLimiterBackend {
    async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
        let key = key.to_string();
        self.cache.get(&key).await.map_err(map_oxcache_storage_err)
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> Result<(), StorageError> {
        let key = key.to_string();
        let value = value.to_string();
        match storage_ttl(ttl) {
            None => self
                .cache
                .set(&key, &value)
                .await
                .map_err(map_oxcache_storage_err),
            Some(ttl) => self
                .cache
                .set_with_ttl(&key, &value, Some(ttl))
                .await
                .map_err(map_oxcache_storage_err),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let key = key.to_string();
        self.cache
            .delete(&key)
            .await
            .map_err(map_oxcache_storage_err)
    }
}

#[async_trait]
impl LimiterBackend for RedisLimiterBackend {
    async fn atomic_check_and_incr(
        &self,
        key: &str,
        threshold: u64,
        ttl: Duration,
    ) -> Result<bool, LimiteronError> {
        // 递增本身为 Lua 原子；阈值比较在客户端完成（与 DAO 后备路径同语义）。
        let count = DistributedLimiter::incr_with_ttl(&self.limiter, key, 1, ttl).await?;
        Ok(count <= threshold)
    }

    async fn reset_prefix(&self, prefix: &str) -> Result<(), LimiteronError> {
        let pattern = format!("{prefix}*");
        let keys = self.cache.keys(&pattern).await.map_err(map_oxcache_err)?;
        for key in keys {
            self.cache.delete(&key).await.map_err(map_oxcache_err)?;
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
        let (allowed, count) = RedisDistributedLimiter::allow_sliding_window(
            &self.limiter,
            key,
            window_ms,
            max_requests,
        )
        .await?;
        // 第三位（reset）当前消费方忽略；保留 0 以免伪造未校验的时钟信息。
        Ok((allowed, count.max(0) as u64, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::storage_ttl;
    use std::time::Duration;

    /// `None` / `Some(0)` 映射为永久；`Some(n)` 映射为 n 秒。
    #[test]
    fn storage_ttl_maps_zero_and_none_to_permanent() {
        assert_eq!(storage_ttl(None), None);
        assert_eq!(storage_ttl(Some(0)), None);
        assert_eq!(storage_ttl(Some(60)), Some(Duration::from_secs(60)));
    }
}
