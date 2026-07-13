//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 暴力破解防护策略。
//!
//! `BruteForceStrategy` 实现 [`BulwarkFirewallStrategy`] trait，
//! 用 limiteron `BanStorage`（封禁记录）+ `DistributedLimiter`（原子计数）替换手写 DAO 逻辑。
//!
//! # 算法
//!
//! 1. 检查 `BanStorage::is_banned(ip)` → 已封禁则拦截（锁定期内）
//! 2. `DistributedLimiter::incr_with_ttl(count_key, 1, window)` → 原子递增计数
//! 3. count > max_attempts → `BanStorage::save(BanRecord)` → 返回 `FirewallBlocked`
//! 4. 否则返回 `Ok(())`
//!
//! # 改进（相比 v0.6 手写实现）
//!
//! - **原子计数**：`incr_with_ttl` 消除 TOCTOU 竞争窗口（原 get-then-set 非原子）
//! - **统一封禁管理**：`BanStorage` trait 提供封禁记录的统一抽象，支持 is_banned/save/remove_ban
//! - **count key**：保持 `bf:{ip}:count` 格式（通过 `DistributedLimiter` 原子递增）

use crate::constants::DaoKeyPrefix;
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::limiteron::{BulwarkDaoBanStorage, BulwarkDaoDistributedLimiter};
use crate::strategy::firewall::{BulwarkFirewallStrategy, FirewallContext};
use async_trait::async_trait;
use chrono::Utc;
use limiteron::limiters::DistributedLimiter;
use limiteron::storage::{BanRecord, BanStorage, BanTarget};
use std::sync::Arc;
use std::time::Duration;

/// 暴力破解防护配置。
///
/// 所有阈值显式配置（Rule 5 确定性逻辑），不交给模型判断。
#[derive(Debug, Clone)]
pub struct BruteForceConfig {
    /// 最大尝试次数（超阈值后拦截）。
    pub max_attempts: u32,
    /// 计数窗口（秒），过期后计数重置。
    pub window_seconds: u64,
    /// 锁定时长（秒），触发拦截后该 IP 持续被拦截。
    pub lock_seconds: u64,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window_seconds: 60,
            lock_seconds: 300,
        }
    }
}

/// 暴力破解防护策略，用 limiteron BanStorage + DistributedLimiter 实现。
///
/// # 构造
///
/// ```ignore
/// use std::sync::Arc;
/// use bulwark::dao::BulwarkDao;
/// use bulwark::strategy::firewall::brute_force::{BruteForceConfig, BruteForceStrategy};
///
/// let dao: Arc<dyn BulwarkDao> = /* oxcache 实现 */;
/// let strategy = BruteForceStrategy::new(BruteForceConfig::default(), dao);
/// ```
pub struct BruteForceStrategy {
    /// 配置（阈值 + 窗口 + 锁定时长）。
    config: BruteForceConfig,
    /// 封禁存储（limiteron BanStorage 适配器，替换手写 lock_key）。
    ban_storage: Arc<dyn BanStorage>,
    /// 分布式限流器（limiteron DistributedLimiter 适配器，原子计数替换手写 get+update）。
    limiter: Arc<dyn DistributedLimiter>,
}

impl BruteForceStrategy {
    /// 创建暴力破解防护策略实例。
    ///
    /// 内部创建 [`BulwarkDaoBanStorage`] + [`BulwarkDaoDistributedLimiter`] 适配器，
    /// 将 `dao` 桥接到 limiteron trait。
    ///
    /// # 参数
    /// - `config`: 配置（阈值 + 窗口 + 锁定时长）。
    /// - `dao`: DAO（oxcache 抽象，用于计数与锁定）。
    pub fn new(config: BruteForceConfig, dao: Arc<dyn BulwarkDao>) -> Self {
        let ban_storage = Arc::new(BulwarkDaoBanStorage::new(dao.clone()));
        let limiter = Arc::new(BulwarkDaoDistributedLimiter::new(dao));
        Self {
            config,
            ban_storage,
            limiter,
        }
    }
}

#[async_trait]
impl BulwarkFirewallStrategy for BruteForceStrategy {
    async fn check(&self, ctx: &FirewallContext) -> BulwarkResult<()> {
        let target = BanTarget::Ip(ctx.ip.clone());
        let count_key = format!("{}{}:count", DaoKeyPrefix::BruteForce, ctx.ip);

        // 1. 检查是否已被封禁（BanStorage 替换原 lock_key，统一封禁管理）
        if self
            .ban_storage
            .is_banned(&target)
            .await
            .map_err(|e| BulwarkError::Dao(format!("ban_storage is_banned 失败: {}", e)))?
            .is_some()
        {
            return Err(BulwarkError::FirewallBlocked(format!(
                "bruteforce: IP {} 已被锁定",
                ctx.ip
            )));
        }

        // 2. 原子递增计数（DistributedLimiter.incr_with_ttl 替换原 get+update，消除 TOCTOU）
        let new_count = self
            .limiter
            .incr_with_ttl(
                &count_key,
                1,
                Duration::from_secs(self.config.window_seconds),
            )
            .await
            .map_err(|e| BulwarkError::Dao(format!("limiter incr_with_ttl 失败: {}", e)))?;

        if new_count > self.config.max_attempts as u64 {
            // 3. 超阈值：封禁 IP（BanStorage.save 替换原 set lock_key）
            let record = BanRecord {
                target: target.clone(),
                ban_times: 1,
                duration: Duration::from_secs(self.config.lock_seconds),
                banned_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::seconds(self.config.lock_seconds as i64),
                is_manual: false,
                reason: format!(
                    "bruteforce: 尝试次数 {} 超过阈值 {}",
                    new_count, self.config.max_attempts
                ),
            };
            self.ban_storage
                .save(&record)
                .await
                .map_err(|e| BulwarkError::Dao(format!("ban_storage save 失败: {}", e)))?;
            Err(BulwarkError::FirewallBlocked(format!(
                "bruteforce: IP {} 尝试次数 {} 超过阈值 {}",
                ctx.ip, new_count, self.config.max_attempts
            )))
        } else {
            Ok(())
        }
    }
}

inventory::submit! {
    crate::strategy::firewall::StrategyRegistration {
        name: "bruteforce",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::error::BulwarkError;

    /// 验证暴力破解防护：max_attempts=5 时，连续 5 次通过，第 6 次被拦截。
    #[tokio::test]
    async fn bruteforce_blocks_after_max_attempts() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = BruteForceConfig {
            max_attempts: 5,
            window_seconds: 60,
            lock_seconds: 300,
        };
        let strategy = BruteForceStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 前 5 次通过
        for i in 1..=5 {
            assert!(strategy.check(&ctx).await.is_ok(), "第 {} 次应通过", i);
        }

        // 第 6 次被拦截
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "第 6 次应返回 FirewallBlocked，实际: {:?}",
            result
        );
    }

    /// 验证锁定后的 IP 被持续拦截（BanStorage 封禁记录生效）。
    ///
    /// 一旦请求触发锁定（BanStorage.save），后续所有请求都应被
    /// `is_banned` 拦截。
    #[tokio::test]
    async fn bruteforce_lock_persists_after_trigger() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = BruteForceConfig {
            max_attempts: 3,
            window_seconds: 60,
            lock_seconds: 300,
        };
        let strategy = BruteForceStrategy::new(config, dao);
        let ctx = FirewallContext::new("10.0.0.1");

        // 触发锁定（第 4 次超阈值）
        for _ in 0..4 {
            let _ = strategy.check(&ctx).await;
        }

        // 后续 5 次请求全部被拦截（BanStorage is_banned 生效）
        for i in 1..=5 {
            let result = strategy.check(&ctx).await;
            assert!(
                matches!(result, Err(BulwarkError::FirewallBlocked(_))),
                "锁定后第 {} 次请求应被拦截",
                i
            );
        }
    }

    /// 验证不同 IP 的计数互不干扰（key 隔离正确性）。
    #[tokio::test]
    async fn bruteforce_counts_isolated_per_ip() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = BruteForceConfig {
            max_attempts: 3,
            window_seconds: 60,
            lock_seconds: 300,
        };
        let strategy = BruteForceStrategy::new(config, dao);

        // IP-A 触发锁定
        let ctx_a = FirewallContext::new("192.168.1.100");
        for _ in 0..4 {
            let _ = strategy.check(&ctx_a).await;
        }

        // IP-B 应不受影响
        let ctx_b = FirewallContext::new("192.168.1.200");
        assert!(
            strategy.check(&ctx_b).await.is_ok(),
            "不同 IP 的计数不应互相影响"
        );
    }
}
