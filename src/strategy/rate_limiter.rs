//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 通用令牌桶限流器模块。
//!
//! 提供基于令牌桶算法的内存限流器，使用 `DashMap` + `AtomicU64` 实现无锁并发。
//!
//! ## 数据结构
//!
//! - [`TokenBucket`](crate::strategy::rate_limiter::TokenBucket)：单个令牌桶，持有容量、补充速率、当前令牌数（`AtomicU64`）、
//!   上次补充时间戳（`AtomicU64`，unix 毫秒）
//! - [`TokenBucketRateLimiter`](crate::strategy::rate_limiter::TokenBucketRateLimiter)：限流器，管理多个 key 对应的 [`TokenBucket`](crate::strategy::rate_limiter::TokenBucket)
//!
//! ## 算法
//!
//! [`TokenBucketRateLimiter::try_acquire`](crate::strategy::rate_limiter::TokenBucketRateLimiter::try_acquire) 执行以下步骤：
//!
//! 1. 获取或创建 key 对应的 [`TokenBucket`](crate::strategy::rate_limiter::TokenBucket)
//! 2. 计算自上次补充以来的时间差（毫秒）
//! 3. 补充 token：`new_tokens = elapsed_millis * refill_rate / 1000`
//! 4. CAS 更新 tokens（不超过 capacity）
//! 5. CAS 更新 last_refill
//! 6. 如果 tokens >= 1，CAS 减 1 返回 true；否则返回 false

use crate::error::BulwarkResult;
use crate::strategy::rate_limiter_backend::RateLimiterBackend;
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// TokenBucket：单个令牌桶
// ============================================================================

/// 单个令牌桶，持有容量、补充速率、当前令牌数与上次补充时间戳。
///
/// 所有可变状态通过 `AtomicU64` 存储，支持无锁 CAS 并发更新。
/// 由 [`TokenBucketRateLimiter`] 内部创建与管理，外部无法直接构造。
pub struct TokenBucket {
    /// 桶容量（最大令牌数）。
    capacity: u32,
    /// 补充速率（tokens per second）。
    refill_rate: u32,
    /// 当前令牌数。
    tokens: AtomicU64,
    /// 上次补充时间戳（unix 毫秒）。
    last_refill: AtomicU64,
}

impl TokenBucket {
    /// 创建新的令牌桶，初始令牌数为满（capacity）。
    ///
    /// # 参数
    /// - `capacity`：桶容量。
    /// - `refill_rate`：补充速率（tokens per second）。
    /// - `now`：当前 unix 毫秒时间戳。
    fn new(capacity: u32, refill_rate: u32, now: u64) -> Self {
        Self {
            capacity,
            refill_rate,
            tokens: AtomicU64::new(capacity as u64),
            last_refill: AtomicU64::new(now),
        }
    }

    /// 补充令牌（CAS 循环）。
    ///
    /// 根据自上次补充以来的时间差计算新增令牌数，CAS 更新 tokens（不超过 capacity），
    /// CAS 更新 last_refill。`new_tokens == 0` 时直接返回（保留分数累加）。
    fn refill(&self, now: u64) {
        loop {
            let current = self.tokens.load(Ordering::Acquire);
            let last = self.last_refill.load(Ordering::Acquire);
            let elapsed = now.saturating_sub(last);
            let new_tokens = elapsed * self.refill_rate as u64 / 1000;
            if new_tokens == 0 {
                return;
            }
            let refilled = (current + new_tokens).min(self.capacity as u64);
            if refilled == current {
                // 已满，仅更新 last_refill
                let _ = self.last_refill.compare_exchange(
                    last,
                    now,
                    Ordering::Release,
                    Ordering::Relaxed,
                );
                return;
            }
            match self.tokens.compare_exchange(
                current,
                refilled,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let _ = self.last_refill.compare_exchange(
                        last,
                        now,
                        Ordering::Release,
                        Ordering::Relaxed,
                    );
                    return;
                },
                Err(_) => continue,
            }
        }
    }

    /// 尝试获取 1 个令牌（CAS 循环）。
    ///
    /// 先调用 [`refill`](Self::refill) 补充令牌，再 CAS 减 1。
    ///
    /// # 返回
    /// - `true`：成功获取 1 个令牌。
    /// - `false`：令牌不足。
    fn try_acquire_inner(&self, now: u64) -> bool {
        self.refill(now);
        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current < 1 {
                return false;
            }
            match self.tokens.compare_exchange(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    /// 尝试获取 n 个令牌（CAS 循环），不足时全部拒绝。
    ///
    /// 先调用 [`refill`](Self::refill) 补充令牌，再 CAS 减 n。
    ///
    /// # 参数
    /// - `now`：当前 unix 毫秒时间戳。
    /// - `n`：请求获取的令牌数。
    ///
    /// # 返回
    /// - `true`：成功获取 n 个令牌。
    /// - `false`：令牌不足，拒绝全部请求（不部分获取）。
    fn try_acquire_n_inner(&self, now: u64, n: u32) -> bool {
        self.refill(now);
        let need = n as u64;
        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current < need {
                return false;
            }
            match self.tokens.compare_exchange(
                current,
                current - need,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    /// 获取 last_refill 值（用于 cleanup 判定）。
    fn last_refill_millis(&self) -> u64 {
        self.last_refill.load(Ordering::Acquire)
    }

    /// 测试用：设置 last_refill 为指定值，用于模拟时间流逝。
    #[cfg(test)]
    fn set_last_refill_for_test(&self, millis: u64) {
        self.last_refill.store(millis, Ordering::Relaxed);
    }
}

// ============================================================================
// TokenBucketRateLimiter：令牌桶限流器
// ============================================================================

/// 令牌桶限流器，管理多个 key 对应的 [`TokenBucket`]。
///
/// 使用 `DashMap` 存储 key → [`TokenBucket`] 映射，`AtomicU64` CAS 实现无锁并发。
///
/// # 构造
///
/// ```ignore
/// use bulwark::strategy::rate_limiter::TokenBucketRateLimiter;
///
/// let limiter = TokenBucketRateLimiter::new(100, 10); // capacity=100, refill=10/s
/// ```
///
/// # 算法
///
/// `try_acquire` 执行以下步骤：
///
/// 1. 获取或创建 key 对应的 [`TokenBucket`]
/// 2. 计算自上次补充以来的时间差（毫秒）
/// 3. 补充 token：`new_tokens = elapsed_millis * refill_rate / 1000`
/// 4. CAS 更新 tokens（不超过 capacity）
/// 5. CAS 更新 last_refill
/// 6. 如果 tokens >= 1，CAS 减 1 返回 true；否则返回 false
pub struct TokenBucketRateLimiter {
    /// key → [`TokenBucket`] 映射。
    buckets: DashMap<String, TokenBucket>,
    /// 每个新 bucket 的容量。
    capacity: u32,
    /// 每个新 bucket 的补充速率（tokens per second）。
    refill_rate: u32,
}

impl TokenBucketRateLimiter {
    /// 创建令牌桶限流器实例。
    ///
    /// # 参数
    /// - `capacity`：每个 bucket 的容量（最大令牌数）。
    /// - `refill_rate`：每个 bucket 的补充速率（tokens per second）。
    pub fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            buckets: DashMap::new(),
            capacity,
            refill_rate,
        }
    }

    /// 尝试获取 1 个令牌。
    ///
    /// # 参数
    /// - `key`：限流 key（如 IP / login_id）。
    ///
    /// # 返回
    /// - `true`：成功获取 1 个令牌。
    /// - `false`：令牌不足。
    pub fn try_acquire(&self, key: &str) -> bool {
        let now = unix_millis();
        // 快路径：读锁获取已有 bucket（允许并发读）
        if let Some(bucket) = self.buckets.get(key) {
            return bucket.try_acquire_inner(now);
        }
        // 慢路径：创建新 bucket（写锁），释放后以读锁重新获取
        self.buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_rate, now));
        if let Some(bucket) = self.buckets.get(key) {
            bucket.try_acquire_inner(now)
        } else {
            // bucket 在插入与获取之间被 cleanup 移除（极罕见），放弃本次请求
            false
        }
    }

    /// 尝试获取 n 个令牌，不足时全部拒绝。
    ///
    /// # 参数
    /// - `key`：限流 key。
    /// - `n`：请求获取的令牌数。
    ///
    /// # 返回
    /// - `true`：成功获取 n 个令牌。
    /// - `false`：令牌不足，拒绝全部请求（不部分获取）。
    pub fn try_acquire_n(&self, key: &str, n: u32) -> bool {
        let now = unix_millis();
        if let Some(bucket) = self.buckets.get(key) {
            return bucket.try_acquire_n_inner(now, n);
        }
        self.buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_rate, now));
        if let Some(bucket) = self.buckets.get(key) {
            bucket.try_acquire_n_inner(now, n)
        } else {
            false
        }
    }

    /// 清理超过 `max_idle_secs` 未补充的 bucket。
    ///
    /// 以 `last_refill` 作为最近活动时间，超过 `max_idle_secs` 未补充的 bucket 被移除。
    /// 被清理的 bucket 在下次访问时以满桶重建，不影响限流正确性。
    ///
    /// # 参数
    /// - `max_idle_secs`：最大空闲时间（秒），超过此时间未补充令牌的 bucket 被移除。
    pub fn cleanup(&self, max_idle_secs: u64) {
        let now = unix_millis();
        let threshold_ms = max_idle_secs.saturating_mul(1000);
        self.buckets.retain(|_, bucket| {
            let last = bucket.last_refill_millis();
            now.saturating_sub(last) <= threshold_ms
        });
    }
}

// ============================================================================
// RateLimiterBackend trait 实现
// ============================================================================

/// 内存限流器实现 [`RateLimiterBackend`] trait。
///
/// `capacity` / `refill_rate` 参数被忽略——`TokenBucketRateLimiter` 在构造时
/// 已指定全局容量与补充速率，trait 参数仅为 Redis 后端所需。
#[async_trait]
impl RateLimiterBackend for TokenBucketRateLimiter {
    async fn try_acquire(
        &self,
        key: &str,
        _capacity: u32,
        _refill_rate: u32,
    ) -> BulwarkResult<bool> {
        Ok(self.try_acquire(key))
    }

    async fn try_acquire_n(
        &self,
        key: &str,
        n: u32,
        _capacity: u32,
        _refill_rate: u32,
    ) -> BulwarkResult<bool> {
        Ok(self.try_acquire_n(key, n))
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 获取当前 unix 毫秒时间戳。
///
/// 系统时间早于 `UNIX_EPOCH` 时返回 0（极罕见，不应在正常环境发生）。
fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // T004: try_acquire 突发后阻塞
    // ------------------------------------------------------------------------

    /// 验证 try_acquire：capacity=5, refill=1/s 时，前 5 次 true，第 6 次 false。
    ///
    /// 初始满桶（5 token），前 5 次各消耗 1 个；测试执行远小于 1s，无补充，
    /// 第 6 次因令牌耗尽返回 false。
    #[test]
    fn try_acquire_allows_burst_then_blocks() {
        let limiter = TokenBucketRateLimiter::new(5, 1);

        // 前 5 次应成功（初始满桶）
        for i in 1..=5 {
            assert!(
                limiter.try_acquire("key1"),
                "第 {} 次 try_acquire 应成功",
                i
            );
        }

        // 第 6 次应被拒绝（令牌耗尽，且测试执行远小于 1s，无补充）
        assert!(
            !limiter.try_acquire("key1"),
            "第 6 次 try_acquire 应被拒绝（令牌耗尽）"
        );
    }

    // ------------------------------------------------------------------------
    // T005: try_acquire_n 不足时拒绝
    // ------------------------------------------------------------------------

    /// 验证 try_acquire_n：capacity=10, 请求 n=15 时返回 false，剩余 token 仍为 10。
    ///
    /// 请求超过容量时全部拒绝（不部分获取），token 数不变。
    #[test]
    fn try_acquire_n_rejects_when_insufficient() {
        let limiter = TokenBucketRateLimiter::new(10, 1);

        // 请求 15 个 token（超过容量 10），应被拒绝
        assert!(!limiter.try_acquire_n("key1", 15), "请求超过容量应被拒绝");

        // 剩余 token 仍为 10，可以获取 10 个
        assert!(
            limiter.try_acquire_n("key1", 10),
            "被拒绝后应仍可获取 capacity 个 token"
        );
    }

    // ------------------------------------------------------------------------
    // 补充测试：try_acquire_n 成功获取
    // ------------------------------------------------------------------------

    /// 验证 try_acquire_n：请求 n <= tokens 时成功获取。
    #[test]
    fn try_acquire_n_succeeds_when_sufficient() {
        let limiter = TokenBucketRateLimiter::new(10, 1);

        // 请求 5 个 token（<= 容量 10），应成功
        assert!(limiter.try_acquire_n("key1", 5), "请求 <= 容量应成功");

        // 剩余 5 个，再请求 5 个应成功
        assert!(
            limiter.try_acquire_n("key1", 5),
            "剩余 5 个时应成功获取 5 个"
        );

        // 再请求 1 个应失败（已耗尽）
        assert!(!limiter.try_acquire_n("key1", 1), "耗尽后应失败");
    }

    // ------------------------------------------------------------------------
    // 补充测试：不同 key 隔离
    // ------------------------------------------------------------------------

    /// 验证不同 key 的令牌桶相互隔离。
    #[test]
    fn different_keys_are_isolated() {
        let limiter = TokenBucketRateLimiter::new(2, 1);

        // key1 耗尽 2 个 token
        assert!(limiter.try_acquire("key1"));
        assert!(limiter.try_acquire("key1"));
        assert!(!limiter.try_acquire("key1"), "key1 应已耗尽");

        // key2 不受影响，仍有 2 个 token
        assert!(limiter.try_acquire("key2"), "key2 应独立持有 token");
        assert!(limiter.try_acquire("key2"));
        assert!(!limiter.try_acquire("key2"), "key2 应已耗尽");
    }

    // ------------------------------------------------------------------------
    // 补充测试：令牌补充
    // ------------------------------------------------------------------------

    /// 验证令牌补充：refill_rate=1/s，模拟 2s 后应补充 token（受 capacity 上限）。
    #[test]
    fn token_refills_after_elapsed() {
        let limiter = TokenBucketRateLimiter::new(1, 1); // capacity=1, refill=1/s

        // 消耗唯一的 token
        assert!(limiter.try_acquire("key1"), "首次应成功");
        assert!(!limiter.try_acquire("key1"), "应已耗尽");

        // 模拟时间流逝：将 last_refill 设为 2 秒前（避免真实 sleep 拖慢测试）
        let now = unix_millis();
        if let Some(bucket) = limiter.buckets.get("key1") {
            bucket.set_last_refill_for_test(now - 2000);
        }

        // 应已补充 token（refill_rate=1/s × 2s = 2 tokens，但 capacity=1，refilled=1）
        assert!(limiter.try_acquire("key1"), "经过 2s 后应补充 token");
    }

    // ------------------------------------------------------------------------
    // 补充测试：cleanup 清理空闲 bucket
    // ------------------------------------------------------------------------

    /// 验证 cleanup：超过 max_idle_secs 未补充的 bucket 被清理。
    #[test]
    fn cleanup_removes_idle_buckets() {
        let limiter = TokenBucketRateLimiter::new(5, 1);

        // 创建两个 bucket
        limiter.try_acquire("active");
        limiter.try_acquire("idle");
        assert_eq!(limiter.buckets.len(), 2, "应有两个 bucket");

        // 将 "idle" bucket 的 last_refill 设为 120 秒前
        let now = unix_millis();
        if let Some(bucket) = limiter.buckets.get("idle") {
            bucket.set_last_refill_for_test(now - 120_000);
        }

        // cleanup(60)：清理超过 60 秒未补充的 bucket
        limiter.cleanup(60);

        assert_eq!(limiter.buckets.len(), 1, "应清理 1 个空闲 bucket");
        assert!(
            limiter.buckets.contains_key("active"),
            "active bucket 应保留"
        );
        assert!(
            !limiter.buckets.contains_key("idle"),
            "idle bucket 应被清理"
        );
    }

    /// 验证 cleanup：未超时的 bucket 不被清理。
    #[test]
    fn cleanup_keeps_active_buckets() {
        let limiter = TokenBucketRateLimiter::new(5, 1);

        limiter.try_acquire("key1");
        assert_eq!(limiter.buckets.len(), 1);

        // cleanup(60)：bucket 刚创建（last_refill ≈ now），不应被清理
        limiter.cleanup(60);

        assert_eq!(limiter.buckets.len(), 1, "未超时的 bucket 不应被清理");
    }

    // ------------------------------------------------------------------------
    // T019: RateLimiterBackend trait 方法测试
    // ------------------------------------------------------------------------

    /// 验证 trait 方法 try_acquire 成功获取令牌。
    #[tokio::test]
    async fn trait_try_acquire_success() {
        let limiter = TokenBucketRateLimiter::new(5, 1);
        // capacity/refill_rate 参数被忽略，传任意值
        // 使用 UFCS 调用 trait 方法（inherent try_acquire 签名不同）
        let result = RateLimiterBackend::try_acquire(&limiter, "key1", 999, 999).await;
        assert!(result.is_ok(), "trait try_acquire 应返回 Ok");
        assert!(result.unwrap(), "首次获取应成功");
    }

    /// 验证 trait 方法 try_acquire 令牌耗尽后返回 false。
    #[tokio::test]
    async fn trait_try_acquire_failure_when_exhausted() {
        let limiter = TokenBucketRateLimiter::new(1, 1);
        // 消耗唯一的 token
        assert!(RateLimiterBackend::try_acquire(&limiter, "key1", 0, 0)
            .await
            .unwrap());
        // 令牌耗尽，应返回 Ok(false)
        let result = RateLimiterBackend::try_acquire(&limiter, "key1", 0, 0).await;
        assert!(result.is_ok(), "trait try_acquire 应返回 Ok");
        assert!(!result.unwrap(), "令牌耗尽后应返回 false");
    }

    /// 验证 trait 方法 try_acquire_n 获取多个令牌。
    #[tokio::test]
    async fn trait_try_acquire_n() {
        let limiter = TokenBucketRateLimiter::new(10, 1);
        // 请求 5 个 token，应成功
        let result = RateLimiterBackend::try_acquire_n(&limiter, "key1", 5, 0, 0).await;
        assert!(result.is_ok(), "trait try_acquire_n 应返回 Ok");
        assert!(result.unwrap(), "请求 5 个 token（容量 10）应成功");

        // 请求超过剩余数量，应返回 Ok(false)
        let result = RateLimiterBackend::try_acquire_n(&limiter, "key1", 10, 0, 0).await;
        assert!(!result.unwrap(), "剩余 5 个时请求 10 个应返回 false");
    }

    /// 验证 trait 方法始终返回 Ok（不抛错）。
    #[tokio::test]
    async fn trait_method_returns_ok() {
        let limiter = TokenBucketRateLimiter::new(2, 1);
        // 多次调用，均应返回 Ok
        assert!(RateLimiterBackend::try_acquire(&limiter, "k", 0, 0)
            .await
            .is_ok());
        assert!(RateLimiterBackend::try_acquire(&limiter, "k", 0, 0)
            .await
            .is_ok());
        assert!(RateLimiterBackend::try_acquire(&limiter, "k", 0, 0)
            .await
            .is_ok());
        assert!(RateLimiterBackend::try_acquire_n(&limiter, "k", 1, 0, 0)
            .await
            .is_ok());
    }
}
