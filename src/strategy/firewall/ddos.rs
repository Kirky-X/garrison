// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! DDoS 防护策略：`DDoSStrategy` 经 limiteron `GarrisonDaoDistributedLimiter::atomic_check_and_incr` 实现
//! 全局 + 单 IP 双重限流（fixed window counter 语义，禁止手写 token bucket）：1 秒 TTL 窗口内，
//! 单 IP 桶允许 `per_ip_rps` 次、全局桶允许 `burst` 次。
//!
//! 计数顺序为**先单 IP 后全局**：被单 IP 拦截的攻击流量不消耗全局额度；全局拦截时该 IP 桶已 +1，
//! 请求本就被拒绝、仅惩罚攻击者自身，不回滚（避免分布式 decr 补偿失败造成计数漂移）。
//! 与 `RateLimit`（滑动窗口，精确但内存占用高）不同，本策略固定窗口计数器允许突发、内存占用低；
//! 原子性：Redis 后端用 Lua 脚本（INCR + EXPIRE 原子），非 Redis 后端降级 `dao.incr`（进程内 Mutex 原子）。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::limiteron::GarrisonDaoDistributedLimiter;
use crate::strategy::firewall::{FirewallContext, GarrisonFirewallStrategy};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

/// DDoS 防护配置（Fixed Window Counter）：所有阈值显式配置，`per_ip_rps` 为单 IP 桶阈值（每秒请求数），`burst` 为全局桶阈值（1 秒窗口内允许的总请求数）。
#[derive(Debug, Clone)]
pub struct DDoSConfig {
    /// 单 IP 每秒最大请求数（单 IP 桶的 threshold）。
    pub per_ip_rps: u32,
    /// 全局突发上限（全局桶的 threshold，1 秒窗口内允许的总请求数）。
    pub burst: u32,
}

impl Default for DDoSConfig {
    fn default() -> Self {
        Self {
            per_ip_rps: 10,
            burst: 20,
        }
    }
}

/// DDoS 防护策略，委托 limiteron 的 `GarrisonDaoDistributedLimiter` 实现。
///
/// # 构造
///
/// ```ignore
/// use std::sync::Arc;
/// use garrison::dao::GarrisonDao;
/// use garrison::strategy::firewall::ddos::{DDoSConfig, DDoSStrategy};
///
/// let dao: Arc<dyn GarrisonDao> = /* oxcache 实现 */;
/// let config = DDoSConfig { per_ip_rps: 10, burst: 20 };
/// let strategy = DDoSStrategy::new(config, dao);
/// ```
pub struct DDoSStrategy {
    /// 配置（单 IP rps + 全局 burst）。
    config: DDoSConfig,
    /// limiteron 适配器（提供原子 check-and-increment）。
    limiter: GarrisonDaoDistributedLimiter,
}

impl DDoSStrategy {
    /// 创建 DDoS 防护策略实例。
    pub fn new(config: DDoSConfig, dao: Arc<dyn GarrisonDao>) -> Self {
        Self {
            config,
            limiter: GarrisonDaoDistributedLimiter::new(dao),
        }
    }
}

#[async_trait]
impl GarrisonFirewallStrategy for DDoSStrategy {
    async fn check(&self, ctx: &FirewallContext) -> GarrisonResult<()> {
        // 窗口 TTL：1 秒（fixed window counter 语义）
        const WINDOW_TTL: Duration = Duration::from_secs(1);

        // 先查单 IP 桶（threshold=per_ip_rps，1 秒窗口）：被拦截的攻击流量不消耗全局额度
        let ip_key = format!("ddos:ip:{}", ctx.ip);
        let ip_ok = self
            .limiter
            .atomic_check_and_incr(&ip_key, self.config.per_ip_rps as u64, WINDOW_TTL)
            .await
            .map_err(|e| GarrisonError::Dao(format!("strategy-ddos-ip::{}::{}", ctx.ip, e)))?;
        if !ip_ok {
            return Err(GarrisonError::FirewallBlocked(format!(
                "strategy-ddos-ip-blocked::{}::{}",
                ctx.ip, self.config.per_ip_rps
            )));
        }

        // 后查全局桶（threshold=burst）：全局拦截时该 IP 桶已 +1，请求本就拒绝，不回滚（见模块文档"计数顺序"）。
        let global_ok = self
            .limiter
            .atomic_check_and_incr("ddos:global", self.config.burst as u64, WINDOW_TTL)
            .await
            .map_err(|e| GarrisonError::Dao(format!("strategy-ddos-global::{}", e)))?;
        if !global_ok {
            return Err(GarrisonError::FirewallBlocked(format!(
                "strategy-ddos-global-blocked::{}",
                self.config.burst
            )));
        }

        Ok(())
    }
}

inventory::submit! {
    crate::strategy::firewall::StrategyRegistration {
        name: "ddos",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::error::GarrisonError;

    /// 验证全局 burst 限制：burst=3 时 1 秒窗口内前 3 次放行、第 4 次拦截（per_ip_rps=1000 放宽单 IP，确保拦截来自全局桶）。
    #[tokio::test]
    async fn ddos_global_burst_limit() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
            per_ip_rps: 1000, // per_ip 放宽，只测全局
            burst: 3,
        };
        let strategy = DDoSStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 前 3 次通过（全局桶计数 1,2,3 <= 3）
        for i in 1..=3 {
            assert!(strategy.check(&ctx).await.is_ok(), "第 {} 次应通过", i);
        }

        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(GarrisonError::FirewallBlocked(_))),
            "第 4 次应返回 FirewallBlocked，实际: {:?}",
            result
        );
    }

    /// 验证单 IP 限流隔离：per_ip_rps=2 时不同 IP 互不影响（burst=1000 放宽全局，确保拦截来自单 IP 桶）。
    #[tokio::test]
    async fn ddos_per_ip_isolation() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
            per_ip_rps: 2,
            burst: 1000, // 全局放宽，只测 per_ip
        };
        let strategy = DDoSStrategy::new(config, dao);

        let ctx_a = FirewallContext::new("192.168.1.1");
        let ctx_b = FirewallContext::new("192.168.1.2");

        // IP A 前 2 次通过（per_ip_a 计数 1,2 <= 2）
        for i in 1..=2 {
            assert!(
                strategy.check(&ctx_a).await.is_ok(),
                "IP A 第 {} 次应通过",
                i
            );
        }

        let result = strategy.check(&ctx_a).await;
        assert!(
            matches!(result, Err(GarrisonError::FirewallBlocked(_))),
            "IP A 第 3 次应被 per_ip 拦截，实际: {:?}",
            result
        );

        assert!(strategy.check(&ctx_b).await.is_ok(), "不同 IP 应互不影响");
    }

    /// 验证窗口 TTL 过期后计数重置：burst=2 消耗 2 次后第 3 次拦截；sleep 1.1s 后窗口过期，第 4 次重新计数通过。
    #[tokio::test]
    async fn ddos_window_reset_after_ttl() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
            per_ip_rps: 1000, // 放宽 per_ip，只测全局窗口重置
            burst: 2,
        };
        let strategy = DDoSStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 消耗全部 burst（count=1,2 <= 2，通过）
        assert!(strategy.check(&ctx).await.is_ok());
        assert!(strategy.check(&ctx).await.is_ok());

        assert!(matches!(
            strategy.check(&ctx).await,
            Err(GarrisonError::FirewallBlocked(_))
        ));

        // 等待窗口 TTL 过期（1s 窗口 + 0.1s 余量）
        tokio::time::sleep(Duration::from_millis(1100)).await;

        assert!(
            strategy.check(&ctx).await.is_ok(),
            "窗口 TTL 过期后应能通过（计数已重置）"
        );
    }

    /// 验证全局和单 IP 双重限制：burst=10、per_ip_rps=1 时，同一 IP 第 2 次被单 IP 桶拦截，全局桶仍允许。
    #[tokio::test]
    async fn ddos_dual_limit_per_ip_triggered_first() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
            per_ip_rps: 1,
            burst: 10,
        };
        let strategy = DDoSStrategy::new(config, dao);
        let ctx = FirewallContext::new("10.0.0.1");

        // 第 1 次：全局与 per_ip 均在额度内，通过
        assert!(strategy.check(&ctx).await.is_ok(), "第 1 次应通过");

        // 第 2 次：全局 count=2 <= 10 通过，但 per_ip count=2 > 1 拦截
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(GarrisonError::FirewallBlocked(_))),
            "第 2 次应被 per_ip 拦截（per_ip_rps=1），实际: {:?}",
            result
        );
        // 验证错误消息包含 IP 信息（区分 per_ip 拦截 vs 全局拦截）
        if let Err(GarrisonError::FirewallBlocked(msg)) = result {
            assert!(msg.contains("10.0.0.1"), "错误消息应包含 IP，实际: {}", msg);
        }
    }

    /// 验证 limiteron 错误映射：`ddos:global` 注入非数字脏数据后全局桶 incr 解析失败，返回 `strategy-ddos-global` 前缀的 `GarrisonError::Dao`（Fail Loud）。
    #[tokio::test]
    async fn ddos_limiter_error_maps_to_garrison_error() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        dao.set("ddos:global", "not-a-number", 60).await.unwrap();

        let config = DDoSConfig::default();
        let strategy = DDoSStrategy::new(config, dao);
        let ctx = FirewallContext::new("1.2.3.4");

        let result = strategy.check(&ctx).await;
        assert!(
            matches!(&result, Err(GarrisonError::Dao(msg)) if msg.contains("strategy-ddos-global")),
            "全局桶脏数据应映射为含 strategy-ddos-global 前缀的 GarrisonError::Dao，实际: {:?}",
            result
        );
    }

    /// 验证计数顺序：burst=3，per_ip_rps=2；被单 IP 桶拦截的请求不 incr 全局桶，
    /// 攻击 IP 第 3 次在单 IP 桶被拦、全局保持 2，正常 IP 仍能使用完整全局额度。
    #[tokio::test]
    async fn per_ip_block_does_not_consume_global_quota() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
            per_ip_rps: 2,
            burst: 3,
        };
        let strategy = DDoSStrategy::new(config, dao);
        let attacker = FirewallContext::new("9.9.9.9");

        // 攻击 IP 前 2 次通过（per_ip=1,2；global=1,2）
        assert!(
            strategy.check(&attacker).await.is_ok(),
            "攻击 IP 第 1 次应通过"
        );
        assert!(
            strategy.check(&attacker).await.is_ok(),
            "攻击 IP 第 2 次应通过"
        );

        assert!(matches!(
            strategy.check(&attacker).await,
            Err(GarrisonError::FirewallBlocked(msg)) if msg.contains("ddos-ip-blocked")
        ));

        // 正常 IP 第 1 次通过：单 IP 拦截不消耗全局额度
        let victim = FirewallContext::new("7.7.7.7");
        assert!(
            strategy.check(&victim).await.is_ok(),
            "单 IP 拦截不应消耗全局额度，正常 IP 第 1 次应通过"
        );
        // 第 2 次全局额度才真正耗尽（incr 后 4 > 3）
        assert!(matches!(
            strategy.check(&victim).await,
            Err(GarrisonError::FirewallBlocked(msg)) if msg.contains("ddos-global-blocked")
        ));
    }
}
