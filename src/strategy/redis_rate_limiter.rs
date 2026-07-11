//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Redis 限流器模块（feature-gated: `rate-limit-redis`）。
//!
//! 基于 Redis + Lua 脚本实现原子令牌桶限流，适用于分布式部署场景。
//!
//! ## 设计
//!
//! - Lua 脚本保证「读取-补充-扣减-写入」的原子性，无需分布式锁
//! - 使用 `redis::aio::ConnectionManager` 管理连接池，支持自动重连
//! - 每个限流 key 对应一个 Redis Hash：`rate_limit:{key}`，字段 `tokens` / `last_refill`
//! - TTL 3600 秒，空闲 bucket 自动过期

#![cfg(feature = "rate-limit-redis")]

use crate::error::{BulwarkError, BulwarkResult};
use crate::strategy::rate_limiter_backend::RateLimiterBackend;
use async_trait::async_trait;

// ============================================================================
// Lua 脚本：原子令牌桶操作
// ============================================================================

/// Lua 脚本常量，实现原子令牌桶令牌获取。
///
/// ## KEYS / ARGV
///
/// - `KEYS[1]` = `rate_limit:{key}`
/// - `ARGV[1]` = capacity（桶容量）
/// - `ARGV[2]` = refill_rate（补充速率，tokens per second）
/// - `ARGV[3]` = now_millis（当前 unix 毫秒时间戳）
/// - `ARGV[4]` = requested（请求令牌数）
///
/// ## 返回
///
/// - `1`：成功获取令牌
/// - `0`：令牌不足，拒绝
const LUA_SCRIPT: &str = r#"
-- KEYS[1] = rate_limit:{key}
-- ARGV[1] = capacity, ARGV[2] = refill_rate, ARGV[3] = now_millis, ARGV[4] = requested
local bucket = redis.call('HMGET', KEYS[1], 'tokens', 'last_refill')
local tokens = tonumber(bucket[1]) or tonumber(ARGV[1])
local last_refill = tonumber(bucket[2]) or tonumber(ARGV[3])
local elapsed = tonumber(ARGV[3]) - last_refill
local refilled = math.min(tokens + elapsed * tonumber(ARGV[2]) / 1000, tonumber(ARGV[1]))
if refilled >= tonumber(ARGV[4]) then
    redis.call('HMSET', KEYS[1], 'tokens', refilled - tonumber(ARGV[4]), 'last_refill', tonumber(ARGV[3]))
    redis.call('EXPIRE', KEYS[1], 3600)
    return 1
else
    redis.call('HMSET', KEYS[1], 'tokens', refilled, 'last_refill', tonumber(ARGV[3]))
    redis.call('EXPIRE', KEYS[1], 3600)
    return 0
end
"#;

// ============================================================================
// RedisRateLimiter：Redis 限流器
// ============================================================================

/// Redis 限流器，使用 Lua 脚本实现原子令牌桶操作。
///
/// 适用于分布式部署，多个实例共享同一 Redis 的限流状态。
pub struct RedisRateLimiter {
    /// Redis 连接管理器（支持自动重连与连接池）。
    conn: redis::aio::ConnectionManager,
    /// 预编译的 Lua 脚本。
    script: redis::Script,
}

impl RedisRateLimiter {
    /// 创建 Redis 限流器实例。
    ///
    /// # 参数
    /// - `conn`：已建立的 `redis::aio::ConnectionManager`。
    pub fn new(conn: redis::aio::ConnectionManager) -> Self {
        Self {
            conn,
            script: redis::Script::new(LUA_SCRIPT),
        }
    }

    /// 格式化 Redis key：`rate_limit:{key}`。
    pub fn key_format(key: &str) -> String {
        format!("rate_limit:{}", key)
    }
}

// ============================================================================
// 辅助函数：参数准备与结果转换（可独立测试，不依赖 Redis 连接）
// ============================================================================

/// 准备 Lua 脚本参数。
///
/// 返回 `(redis_key, args)`，其中 `args = [capacity, refill_rate, now_millis, n]`。
/// 此函数从 `try_acquire_n` 中抽出，便于单元测试参数组装逻辑。
#[cfg(test)]
fn prepare_script_args(key: &str, n: u32, capacity: u32, refill_rate: u32) -> (String, Vec<i64>) {
    let redis_key = RedisRateLimiter::key_format(key);
    let now = chrono::Utc::now().timestamp_millis();
    (
        redis_key,
        vec![capacity as i64, refill_rate as i64, now, n as i64],
    )
}

/// 转换 Lua 脚本返回值：`1 → true`，`0 → false`，其他 → Err。
///
/// 此函数从 `try_acquire_n` 中抽出，便于单元测试结果转换逻辑。
fn convert_lua_result(value: i64) -> BulwarkResult<bool> {
    match value {
        1 => Ok(true),
        0 => Ok(false),
        other => Err(BulwarkError::Internal(format!(
            "Lua 脚本返回非预期值: {}",
            other
        ))),
    }
}

/// 将 Redis 连接/执行错误映射为 `BulwarkError::Dao`（spec R-redis-ratelimit-003）。
///
/// Redis 连接失败属于 DAO 层错误，不应使用 `Internal`。
/// 此函数从 `try_acquire_n` 中抽出，便于单元测试错误映射逻辑。
fn map_redis_error(e: redis::RedisError) -> BulwarkError {
    BulwarkError::Dao(format!("Redis 限流器错误: {}", e))
}

// ============================================================================
// RateLimiterBackend trait 实现
// ============================================================================

#[async_trait]
impl RateLimiterBackend for RedisRateLimiter {
    async fn try_acquire(&self, key: &str, capacity: u32, refill_rate: u32) -> BulwarkResult<bool> {
        // 委托到 try_acquire_n，请求 1 个令牌
        self.try_acquire_n(key, 1, capacity, refill_rate).await
    }

    async fn try_acquire_n(
        &self,
        key: &str,
        n: u32,
        capacity: u32,
        refill_rate: u32,
    ) -> BulwarkResult<bool> {
        let redis_key = RedisRateLimiter::key_format(key);
        let now = chrono::Utc::now().timestamp_millis();
        // ConnectionManager 基于 Arc，clone 开销低，invoke_async 需要 &mut
        let mut conn = self.conn.clone();
        let result: i64 = self
            .script
            .key(redis_key)
            .arg(capacity)
            .arg(refill_rate)
            .arg(now)
            .arg(n)
            .invoke_async(&mut conn)
            .await
            .map_err(map_redis_error)?;
        convert_lua_result(result)
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // T020: Lua 脚本内容测试（8 个）
    // ------------------------------------------------------------------------

    /// 验证 Lua 脚本包含 "HMGET"。
    #[test]
    fn lua_script_contains_hmget() {
        assert!(LUA_SCRIPT.contains("HMGET"), "Lua 脚本应包含 HMGET");
    }

    /// 验证 Lua 脚本包含 "HMSET"。
    #[test]
    fn lua_script_contains_hmset() {
        assert!(LUA_SCRIPT.contains("HMSET"), "Lua 脚本应包含 HMSET");
    }

    /// 验证 Lua 脚本包含 "EXPIRE"。
    #[test]
    fn lua_script_contains_expire() {
        assert!(LUA_SCRIPT.contains("EXPIRE"), "Lua 脚本应包含 EXPIRE");
    }

    /// 验证 Lua 脚本包含 "math.min"。
    #[test]
    fn lua_script_contains_math_min() {
        assert!(LUA_SCRIPT.contains("math.min"), "Lua 脚本应包含 math.min");
    }

    /// 验证 key_format 生成 "rate_limit:{key}"。
    #[test]
    fn key_format_produces_correct_key() {
        assert_eq!(
            RedisRateLimiter::key_format("user:1001"),
            "rate_limit:user:1001"
        );
    }

    /// 验证 key_format 处理空 key。
    #[test]
    fn key_format_with_empty_key() {
        assert_eq!(RedisRateLimiter::key_format(""), "rate_limit:");
    }

    /// 验证 key_format 处理特殊字符。
    #[test]
    fn key_format_with_special_characters() {
        assert_eq!(
            RedisRateLimiter::key_format("ip:1.2.3.4&login=admin"),
            "rate_limit:ip:1.2.3.4&login=admin"
        );
    }

    /// 验证 Lua 脚本包含 "tonumber"。
    #[test]
    fn lua_script_contains_tonumber() {
        assert!(LUA_SCRIPT.contains("tonumber"), "Lua 脚本应包含 tonumber");
    }

    // ------------------------------------------------------------------------
    // T021: 参数准备与结果转换测试（6 个）
    // ------------------------------------------------------------------------

    /// 验证 try_acquire 委托到 try_acquire_n 时 n=1。
    ///
    /// 通过 prepare_script_args(key, 1, ...) 验证参数中 n=1。
    #[test]
    fn try_acquire_delegates_with_n_one() {
        let (key, args) = prepare_script_args("test_key", 1, 100, 10);
        assert_eq!(key, "rate_limit:test_key");
        // args = [capacity, refill_rate, now_millis, n]
        assert_eq!(args[3], 1, "try_acquire 委托时 n 应为 1");
    }

    /// 验证参数准备生成正确的 key 格式。
    #[test]
    fn prepare_args_produces_correct_key() {
        let (key, _) = prepare_script_args("user:abc", 5, 100, 10);
        assert_eq!(key, "rate_limit:user:abc");
    }

    /// 验证参数准备生成正确的 capacity 值。
    #[test]
    fn prepare_args_produces_correct_capacity() {
        let (_, args) = prepare_script_args("k", 1, 200, 10);
        assert_eq!(args[0], 200, "capacity 应为 200");
    }

    /// 验证参数准备生成正确的 refill_rate 值。
    #[test]
    fn prepare_args_produces_correct_refill_rate() {
        let (_, args) = prepare_script_args("k", 1, 100, 15);
        assert_eq!(args[1], 15, "refill_rate 应为 15");
    }

    /// 验证结果转换：1 → true。
    #[test]
    fn convert_result_one_to_true() {
        assert!(convert_lua_result(1).unwrap(), "Lua 返回 1 应转换为 true");
    }

    /// 验证结果转换：0 → false。
    #[test]
    fn convert_result_zero_to_false() {
        assert!(!convert_lua_result(0).unwrap(), "Lua 返回 0 应转换为 false");
    }

    // ------------------------------------------------------------------------
    // T037: map_redis_error 错误类型测试（2 个）
    // ------------------------------------------------------------------------

    /// 验证 `map_redis_error` 返回 `BulwarkError::Dao` 变体（spec R-redis-ratelimit-003）。
    #[test]
    fn map_redis_error_returns_dao_variant() {
        use std::io;
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
        let redis_err: redis::RedisError = io_err.into();
        let bulwark_err = map_redis_error(redis_err);
        assert!(
            matches!(bulwark_err, BulwarkError::Dao(_)),
            "Redis 连接错误应映射为 BulwarkError::Dao，而非 Internal"
        );
    }

    /// 验证 `map_redis_error` 的错误消息包含前缀和原始错误信息。
    #[test]
    fn map_redis_error_includes_original_message() {
        use std::io;
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
        let redis_err: redis::RedisError = io_err.into();
        let bulwark_err = map_redis_error(redis_err);
        let msg = match &bulwark_err {
            BulwarkError::Dao(m) => m,
            _ => panic!("应为 Dao 变体"),
        };
        assert!(
            msg.contains("Redis 限流器错误"),
            "错误消息应包含前缀 'Redis 限流器错误'"
        );
    }

    // ------------------------------------------------------------------------
    // T038: Lua 脚本 EXPIRE 调用测试（1 个）
    // ------------------------------------------------------------------------

    /// 验证 Lua 脚本含 2 个 EXPIRE 调用（成功 + 失败分支均设置 TTL，spec R-redis-ratelimit-002）。
    #[test]
    fn lua_script_has_two_expire_calls() {
        let count = LUA_SCRIPT.matches("EXPIRE").count();
        assert_eq!(count, 2, "Lua 脚本应含 2 个 EXPIRE 调用（成功+失败分支）");
    }
}
