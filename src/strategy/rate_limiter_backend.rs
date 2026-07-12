//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 限流器后端抽象模块。
//!
//! 定义 [`RateLimiterBackend`](crate::strategy::rate_limiter_backend::RateLimiterBackend) trait，统一内存限流器与 Redis 限流器的接口，
//! 业务方可通过 trait 对象在运行时切换后端实现。
//!
//! ## 设计
//!
//! - [`crate::strategy::rate_limiter::TokenBucketRateLimiter`]：内存实现，使用 `DashMap` + `AtomicU64`
//! - [`crate::strategy::redis_rate_limiter::RedisRateLimiter`]：Redis 实现，使用 Lua 脚本保证原子性
//!
//! trait 始终可用（无 feature gate），仅 RedisRateLimiter 受 `rate-limit-redis` feature 门控。

use crate::error::BulwarkResult;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ============================================================================
// RateLimiterBackend trait：限流器后端抽象
// ============================================================================

/// 限流器后端 trait，统一内存与 Redis 实现的接口。
///
/// 实现方负责令牌桶的存储与原子性保证：
/// - 内存实现（`TokenBucketRateLimiter`）使用 CAS 循环
/// - Redis 实现（`RedisRateLimiter`）使用 Lua 脚本
///
/// # 参数说明
///
/// - `key`：限流 key（如 IP / login_id）
/// - `capacity`：桶容量（最大令牌数）
/// - `refill_rate`：补充速率（tokens per second）
///
/// 内存实现忽略 `capacity` / `refill_rate` 参数（构造时已指定）；
/// Redis 实现将它们作为 Lua 脚本参数传入。
#[async_trait]
pub trait RateLimiterBackend: Send + Sync {
    /// 尝试获取 1 个令牌。
    ///
    /// # 返回
    /// - `Ok(true)`：成功获取 1 个令牌。
    /// - `Ok(false)`：令牌不足。
    /// - `Err`：后端错误（如 Redis 连接失败）。
    async fn try_acquire(&self, key: &str, capacity: u32, refill_rate: u32) -> BulwarkResult<bool>;

    /// 尝试获取 n 个令牌，不足时全部拒绝（不部分获取）。
    ///
    /// # 参数
    /// - `n`：请求获取的令牌数。
    ///
    /// # 返回
    /// - `Ok(true)`：成功获取 n 个令牌。
    /// - `Ok(false)`：令牌不足，拒绝全部请求。
    /// - `Err`：后端错误。
    async fn try_acquire_n(
        &self,
        key: &str,
        n: u32,
        capacity: u32,
        refill_rate: u32,
    ) -> BulwarkResult<bool>;
}

// ============================================================================
// RateLimitBackend enum：配置项，选择限流后端
// ============================================================================

/// 限流后端选择枚举，用于 `BulwarkConfig` 配置。
///
/// 默认 `Memory`（向后兼容）。启用 `rate-limit-redis` feature 后可选 `Redis`。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitBackend {
    /// 内存限流（`TokenBucketRateLimiter`，DashMap + AtomicU64）。
    #[default]
    Memory,
    /// Redis 限流（`RedisRateLimiter`，Lua 脚本原子操作）。
    Redis {
        /// Redis 连接 URL（如 `redis://127.0.0.1:6379/0`）。
        redis_url: String,
    },
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证默认后端为 Memory。
    #[test]
    fn default_is_memory() {
        assert_eq!(RateLimitBackend::default(), RateLimitBackend::Memory);
    }

    /// 验证 Redis 变体携带 redis_url。
    #[test]
    fn redis_variant_with_url() {
        let backend = RateLimitBackend::Redis {
            redis_url: "redis://127.0.0.1:6379/0".to_string(),
        };
        match backend {
            RateLimitBackend::Redis { redis_url } => {
                assert_eq!(redis_url, "redis://127.0.0.1:6379/0");
            },
            _ => panic!("应为 Redis 变体"),
        }
    }

    /// 验证 Memory 变体。
    #[test]
    fn memory_variant() {
        let backend = RateLimitBackend::Memory;
        assert!(matches!(backend, RateLimitBackend::Memory));
    }

    /// 验证序列化/反序列化 round-trip。
    #[test]
    fn serialization_round_trip() {
        let backends = vec![
            RateLimitBackend::Memory,
            RateLimitBackend::Redis {
                redis_url: "redis://localhost:6379".to_string(),
            },
        ];
        for original in backends {
            let json = serde_json::to_string(&original).unwrap();
            let deserialized: RateLimitBackend = serde_json::from_str(&json).unwrap();
            assert_eq!(original, deserialized, "序列化 round-trip 应保持相等");
        }
    }

    /// 验证枚举相等性比较。
    #[test]
    fn enum_equality() {
        assert_eq!(RateLimitBackend::Memory, RateLimitBackend::Memory);
        assert_ne!(
            RateLimitBackend::Memory,
            RateLimitBackend::Redis {
                redis_url: String::new()
            }
        );
    }
}
