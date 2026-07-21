//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 限流后端配置 enum。
//!
//! v0.7 起，所有限速实现统一由 [`limiteron`] 接管：
//! - 内存限流 → [`crate::limiteron::GarrisonDaoDistributedLimiter`]
//! - 分布式限流 → [`crate::limiteron::GarrisonDaoDistributedLimiter::atomic_check_and_incr`]
//! - 配额限流 → [`crate::limiteron::GarrisonDaoQuotaStorage`]
//! - 封禁记录 → [`crate::limiteron::GarrisonDaoBanStorage`]
//!
//! 本模块仅保留 `RateLimitBackend` 配置 enum，用于 `GarrisonConfig`
//! 表达限流后端选择（向后兼容 v0.6 配置）。运行时由 `GarrisonDaoDistributedLimiter`
//! 根据 `GarrisonDao` 后端（MockDao/SQLite/Redis 等）自动选择原子或降级实现。

use serde::{Deserialize, Serialize};

// ============================================================================
// RateLimitBackend enum：配置项，选择限流后端
// ============================================================================

/// 限流后端选择枚举，用于 `GarrisonConfig` 配置。
///
/// 默认 `Memory`（向后兼容）。启用 `rate-limit-redis` feature 后可选 `Redis`。
///
/// # v0.7 行为
///
/// 实际限流逻辑统一委托 [`crate::limiteron::GarrisonDaoDistributedLimiter`]，
/// 此 enum 仅作为配置占位与可观测性标记，不再驱动具体实现切换（limiteron
/// 通过 `GarrisonDao` 后端透明支持 Redis 原子操作）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitBackend {
    /// 内存限流（基于 GarrisonDaoDistributedLimiter + MockDao/SQLite）。
    #[default]
    Memory,
    /// Redis 限流（基于 GarrisonDaoDistributedLimiter + Redis 后端，走 eval_lua 原子脚本）。
    Redis {
        /// Redis 连接 URL（如 `redis://127.0.0.1:6379/0`）。
        redis_url: String,
    },
}

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
