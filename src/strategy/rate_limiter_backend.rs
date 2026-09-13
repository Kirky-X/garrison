//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 限流后端配置 enum。
//!
//! v0.7 起，所有限速实现统一由 `limiteron` 接管：
//! - 内存限流 → `crate::limiteron::GarrisonDaoDistributedLimiter`
//! - 分布式限流 → `crate::limiteron::GarrisonDaoDistributedLimiter::atomic_check_and_incr`
//! - 配额限流 → `crate::limiteron::GarrisonDaoQuotaStorage`
//! - 封禁记录 → `crate::limiteron::GarrisonDaoBanStorage`
//!
//! 本模块仅保留 `RateLimitBackend` 配置 enum，用于 `GarrisonConfig`
//! 表达限流后端选择。运行时由 `GarrisonDaoDistributedLimiter`
//! 根据 `GarrisonDao` 后端（MockDao/SQLite/Redis 等）自动选择原子或降级实现。

use serde::{Deserialize, Serialize};

// ============================================================================
// RateLimitBackend enum：配置项，选择限流后端
// ============================================================================

/// 限流后端选择枚举，用于 `GarrisonConfig` 配置。
///
/// 默认 `Memory`（进程内限流）。启用 `rate-limit-redis` feature 后可选 `Redis`。
///
/// # v0.7 行为
///
/// 实际限流逻辑统一委托 `crate::limiteron::GarrisonDaoDistributedLimiter`，
/// 此 enum 仅作为配置占位与可观测性标记，不再驱动具体实现切换（limiteron
/// 通过 `GarrisonDao` 后端透明支持 Redis 原子操作）。
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

/// 手动实现 `Debug`（ocr #2841/3484）：`redis_url` 可能内嵌凭据
/// （`redis://user:password@host:6379/0`）或敏感 query（`?password=...`），
/// 派生 `Debug` 会在日志/错误输出中原样泄露。此处对 URL 脱敏后输出。
impl std::fmt::Debug for RateLimitBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => f.debug_struct("Memory").finish(),
            Self::Redis { redis_url } => f
                .debug_struct("Redis")
                .field("redis_url", &redact_redis_url(redis_url))
                .finish(),
        }
    }
}

/// 脱敏 Redis URL：userinfo（`user:pass@`）替换为 `***`，含 query 时整体截断为 `?***`。
///
/// 无凭据的 URL 原样返回，便于运维识别实例。
fn redact_redis_url(url: &str) -> String {
    // scheme 之后、host 之前的 userinfo（密码可能含未转义的 '@'，取最后一个 '@' 分界）
    if let Some(scheme_end) = url.find("://") {
        let rest = &url[scheme_end + 3..];
        if let Some(at) = rest.rfind('@') {
            let host_part = &rest[at + 1..];
            return match host_part.split_once('?') {
                Some((host, _)) => format!("{}://***@{}?***", &url[..scheme_end], host),
                None => format!("{}://***@{}", &url[..scheme_end], host_part),
            };
        }
    }
    // 无 userinfo：可能凭据在 query（如 ?password=...），保守截断
    match url.split_once('?') {
        Some((base, _)) => format!("{}?***", base),
        None => url.to_string(),
    }
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

    /// ocr #2841/3484：Debug 输出必须脱敏凭据（userinfo / query）。
    #[test]
    fn debug_redacts_credentials() {
        let backend = RateLimitBackend::Redis {
            redis_url: "redis://user:p@ssw0rd@host:6379/0".to_string(),
        };
        let dbg = format!("{:?}", backend);
        assert!(
            !dbg.contains("p@ssw0rd") && !dbg.contains("redis://user"),
            "Debug 不得包含 userinfo 凭据，实际: {}",
            dbg
        );
        assert!(
            dbg.contains("***@host:6379/0"),
            "应保留 host 便于排查，实际: {}",
            dbg
        );

        let query_backend = RateLimitBackend::Redis {
            redis_url: "redis://host:6379/0?password=secret".to_string(),
        };
        let dbg = format!("{:?}", query_backend);
        assert!(
            !dbg.contains("secret"),
            "Debug 不得包含 query 凭据，实际: {}",
            dbg
        );

        let plain = RateLimitBackend::Redis {
            redis_url: "redis://127.0.0.1:6379/0".to_string(),
        };
        assert_eq!(
            format!("{:?}", plain),
            r#"Redis { redis_url: "redis://127.0.0.1:6379/0" }"#
        );
    }
}
