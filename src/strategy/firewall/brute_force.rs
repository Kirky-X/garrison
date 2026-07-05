//! 暴力破解防护策略（依据 spec firewall R-firewall-001）。
//!
//! `BruteForceStrategy` 实现 [`BulwarkFirewallStrategy`] trait，
//! 用 oxcache key `bf:{ip}:count` 计数，TTL=window_seconds，
//! 超阈值返回 [`BulwarkError::FirewallBlocked`](crate::error::BulwarkError::FirewallBlocked)。
//!
//! # 算法
//!
//! 1. 检查 `bf:{ip}:locked` 是否存在 → 存在则拦截（锁定期内）
//! 2. 读取 `bf:{ip}:count` → 不存在则初始化为 1（TTL=window_seconds）
//! 3. 存在则 +1（保留 TTL，不重置窗口）
//! 4. count > max_attempts → 设置 `bf:{ip}:locked`（TTL=lock_seconds），返回 `FirewallBlocked`
//! 5. 否则返回 `Ok(())`

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::strategy::firewall::{BulwarkFirewallStrategy, FirewallContext};
use async_trait::async_trait;
use std::sync::Arc;

/// 暴力破解防护配置（依据 spec firewall R-firewall-001）。
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

/// 暴力破解防护策略，用 oxcache 计数 + 锁定实现（依据 spec firewall R-firewall-001）。
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
    /// DAO（oxcache 抽象，用于计数与锁定）。
    dao: Arc<dyn BulwarkDao>,
}

impl BruteForceStrategy {
    /// 创建暴力破解防护策略实例。
    ///
    /// # 参数
    /// - `config`: 配置（阈值 + 窗口 + 锁定时长）。
    /// - `dao`: DAO（oxcache 抽象，用于计数与锁定）。
    pub fn new(config: BruteForceConfig, dao: Arc<dyn BulwarkDao>) -> Self {
        Self { config, dao }
    }
}

#[async_trait]
impl BulwarkFirewallStrategy for BruteForceStrategy {
    async fn check(&self, ctx: &FirewallContext) -> BulwarkResult<()> {
        let lock_key = format!("bf:{}:locked", ctx.ip);
        let count_key = format!("bf:{}:count", ctx.ip);

        // 1. 锁定期内直接拦截（无论 count 是否过期）
        if self.dao.get(&lock_key).await?.is_some() {
            return Err(BulwarkError::FirewallBlocked(format!(
                "bruteforce: IP {} 已被锁定",
                ctx.ip
            )));
        }

        // 2. 读取当前计数
        match self.dao.get(&count_key).await? {
            None => {
                // 首次访问：初始化计数为 1，TTL=window_seconds（固定窗口起点）
                self.dao
                    .set(&count_key, "1", self.config.window_seconds)
                    .await?;
                Ok(())
            },
            Some(val) => {
                let current: u32 = val.parse().unwrap_or(0);
                let new_count = current + 1;
                if new_count > self.config.max_attempts {
                    // 超阈值：设置锁定 key（TTL=lock_seconds），返回 FirewallBlocked
                    self.dao
                        .set(&lock_key, "1", self.config.lock_seconds)
                        .await?;
                    Err(BulwarkError::FirewallBlocked(format!(
                        "bruteforce: IP {} 尝试次数 {} 超过阈值 {}",
                        ctx.ip, new_count, self.config.max_attempts
                    )))
                } else {
                    // 未超阈值：update 保留原 TTL（固定窗口，不重置）
                    self.dao.update(&count_key, &new_count.to_string()).await?;
                    Ok(())
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::error::BulwarkError;

    /// 验证暴力破解防护：max_attempts=5 时，连续 5 次通过，第 6 次被拦截
    ///（依据 spec firewall R-firewall-001 验收标准 1）。
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
}
