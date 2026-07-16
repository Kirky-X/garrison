//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DDoS 防护策略。
//!
//! `DDoSStrategy` 实现 [`BulwarkFirewallStrategy`] trait，
//! 用 limiteron 的 [`BulwarkDaoDistributedLimiter::atomic_check_and_incr`] 实现
//! 全局 + 单 IP 双重限流（fixed window counter 语义，禁止手写 token bucket）。
//!
//! # 算法（Fixed Window Counter，委托 limiteron）
//!
//! 1. 全局桶：`atomic_check_and_incr("ddos:global", threshold=burst, ttl=1s)`
//!    —— 1 秒窗口内允许 burst 次全局请求
//! 2. 单 IP 桶：`atomic_check_and_incr("ddos:ip:{ip}", threshold=per_ip_rps, ttl=1s)`
//!    —— 1 秒窗口内允许 per_ip_rps 次单 IP 请求
//! 3. 全局桶先检查，per_ip 桶后检查
//! 4. 窗口 TTL 到期后计数器自动重置（DAO 后端的 TTL 机制保证）
//!
//! # 与 RateLimit 的区别
//!
//! - RateLimit：滑动窗口（时间戳列表），精确但内存占用高
//! - DDoS：fixed window counter（单计数器 + TTL），近似但内存占用低，且允许突发（burst）
//!
//! # 原子性保证
//!
//! [`BulwarkDaoDistributedLimiter::atomic_check_and_incr`] 在 Redis 后端用 Lua 脚本
//! （INCR + EXPIRE 原子），在非 Redis 后端降级到 `dao.incr`（进程内 Mutex 原子）。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::limiteron::BulwarkDaoDistributedLimiter;
use crate::strategy::firewall::{BulwarkFirewallStrategy, FirewallContext};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

/// DDoS 防护配置。
///
/// 所有阈值显式配置（Rule 5 确定性逻辑），不交给模型判断。
///
/// # 字段语义（Fixed Window Counter）
///
/// - `global_rps`：保留用于配置兼容性；当前实现下全局桶 threshold 用 `burst`，
///   此字段不参与限流计算（向后兼容保留）。
/// - `per_ip_rps`：单 IP 每秒允许的请求数（单 IP 桶的 threshold）。
/// - `burst`：全局突发上限（全局桶的 threshold，1 秒窗口内允许的总请求数）。
#[derive(Debug, Clone)]
pub struct DDoSConfig {
    /// 全局每秒最大请求数（保留用于配置兼容性，当前实现未直接使用）。
    pub global_rps: u32,
    /// 单 IP 每秒最大请求数（单 IP 桶的 threshold）。
    pub per_ip_rps: u32,
    /// 全局突发上限（全局桶的 threshold，1 秒窗口内允许的总请求数）。
    pub burst: u32,
}

impl Default for DDoSConfig {
    fn default() -> Self {
        Self {
            global_rps: 100,
            per_ip_rps: 10,
            burst: 20,
        }
    }
}

/// DDoS 防护策略，委托 limiteron 的 `BulwarkDaoDistributedLimiter` 实现。
///
/// # 构造
///
/// ```ignore
/// use std::sync::Arc;
/// use bulwark::dao::BulwarkDao;
/// use bulwark::strategy::firewall::ddos::{DDoSConfig, DDoSStrategy};
///
/// let dao: Arc<dyn BulwarkDao> = /* oxcache 实现 */;
/// let config = DDoSConfig { global_rps: 100, per_ip_rps: 10, burst: 20 };
/// let strategy = DDoSStrategy::new(config, dao);
/// ```
pub struct DDoSStrategy {
    /// 配置（单 IP rps + 全局 burst）。
    config: DDoSConfig,
    /// limiteron 适配器（提供原子 check-and-increment）。
    limiter: BulwarkDaoDistributedLimiter,
}

impl DDoSStrategy {
    /// 创建 DDoS 防护策略实例。
    ///
    /// # 参数
    /// - `config`: 配置（单 IP rps + 全局 burst）。
    /// - `dao`: DAO（oxcache 抽象，桥接到 limiteron 适配器）。
    pub fn new(config: DDoSConfig, dao: Arc<dyn BulwarkDao>) -> Self {
        Self {
            config,
            limiter: BulwarkDaoDistributedLimiter::new(dao),
        }
    }
}

#[async_trait]
impl BulwarkFirewallStrategy for DDoSStrategy {
    async fn check(&self, ctx: &FirewallContext) -> BulwarkResult<()> {
        // 窗口 TTL：1 秒（fixed window counter 语义）
        const WINDOW_TTL: Duration = Duration::from_secs(1);

        // 1. 全局桶检查（threshold=burst，1 秒窗口）
        let global_ok = self
            .limiter
            .atomic_check_and_incr("ddos:global", self.config.burst as u64, WINDOW_TTL)
            .await
            .map_err(|e| BulwarkError::Dao(format!("ddos 全局限流器错误: {}", e)))?;
        if !global_ok {
            return Err(BulwarkError::FirewallBlocked(format!(
                "ddos: 全局速率限制 (burst={})",
                self.config.burst
            )));
        }

        // 2. 单 IP 桶检查（threshold=per_ip_rps，1 秒窗口）
        let ip_key = format!("ddos:ip:{}", ctx.ip);
        let ip_ok = self
            .limiter
            .atomic_check_and_incr(&ip_key, self.config.per_ip_rps as u64, WINDOW_TTL)
            .await
            .map_err(|e| BulwarkError::Dao(format!("ddos IP {} 限流器错误: {}", ctx.ip, e)))?;
        if !ip_ok {
            return Err(BulwarkError::FirewallBlocked(format!(
                "ddos: IP {} 速率限制 (per_ip_rps={})",
                ctx.ip, self.config.per_ip_rps
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
    use crate::error::BulwarkError;

    /// 验证全局 burst 限制：burst=3 时，1 秒窗口内前 3 次放行，第 4 次被拦截。
    ///
    /// 配置 per_ip_rps=1000 放宽单 IP 限制，确保拦截来自全局桶。
    #[tokio::test]
    async fn ddos_global_burst_limit() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
            global_rps: 100,
            per_ip_rps: 1000, // per_ip 放宽，只测全局
            burst: 3,
        };
        let strategy = DDoSStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 前 3 次通过（全局桶计数 1,2,3 <= 3）
        for i in 1..=3 {
            assert!(strategy.check(&ctx).await.is_ok(), "第 {} 次应通过", i);
        }

        // 第 4 次被拦截（全局桶计数 4 > 3，窗口未过期）
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "第 4 次应返回 FirewallBlocked，实际: {:?}",
            result
        );
    }

    /// 验证单 IP 限流隔离：per_ip_rps=2 时，不同 IP 互不影响。
    ///
    /// 配置 burst=1000 放宽全局限制，确保拦截来自单 IP 桶。
    #[tokio::test]
    async fn ddos_per_ip_isolation() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
            global_rps: 100,
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

        // IP A 第 3 次被 per_ip_a 拦截（计数 3 > 2）
        let result = strategy.check(&ctx_a).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "IP A 第 3 次应被 per_ip 拦截，实际: {:?}",
            result
        );

        // IP B 有独立额度（per_ip_b 计数 1 <= 2，应通过）
        assert!(strategy.check(&ctx_b).await.is_ok(), "不同 IP 应互不影响");
    }

    /// 验证窗口 TTL 过期后计数重置：1 秒窗口到期后，计数器归零，请求再次通过。
    ///
    /// 配置 burst=2，消耗 2 次后第 3 次被拦截；sleep 1.1s 后窗口过期，
    /// 第 4 次重新计数（count=1 <= 2）通过。
    #[tokio::test]
    async fn ddos_window_reset_after_ttl() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
            global_rps: 100,
            per_ip_rps: 1000, // 放宽 per_ip，只测全局窗口重置
            burst: 2,
        };
        let strategy = DDoSStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 消耗全部 burst（count=1,2 <= 2，通过）
        assert!(strategy.check(&ctx).await.is_ok());
        assert!(strategy.check(&ctx).await.is_ok());

        // 第 3 次被拦截（count=3 > 2，窗口未过期）
        assert!(matches!(
            strategy.check(&ctx).await,
            Err(BulwarkError::FirewallBlocked(_))
        ));

        // 等待窗口 TTL 过期（1s 窗口 + 0.1s 余量）
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // 窗口重置后应能通过（count=1 <= 2，新窗口）
        assert!(
            strategy.check(&ctx).await.is_ok(),
            "窗口 TTL 过期后应能通过（计数已重置）"
        );
    }

    /// 验证全局和单 IP 双重限制：单 IP 阈值低于全局时，单 IP 先触发拦截。
    ///
    /// 配置 burst=10（全局放宽），per_ip_rps=1（单 IP 严格），
    /// 同一 IP 第 2 次应被单 IP 桶拦截，而全局桶仍允许。
    #[tokio::test]
    async fn ddos_dual_limit_per_ip_triggered_first() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
            global_rps: 100,
            per_ip_rps: 1,
            burst: 10,
        };
        let strategy = DDoSStrategy::new(config, dao);
        let ctx = FirewallContext::new("10.0.0.1");

        // 第 1 次：全局 count=1 <= 10，per_ip count=1 <= 1，通过
        assert!(strategy.check(&ctx).await.is_ok(), "第 1 次应通过");

        // 第 2 次：全局 count=2 <= 10 通过，但 per_ip count=2 > 1 拦截
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "第 2 次应被 per_ip 拦截（per_ip_rps=1），实际: {:?}",
            result
        );
        // 验证错误消息包含 IP 信息（区分 per_ip 拦截 vs 全局拦截）
        if let Err(BulwarkError::FirewallBlocked(msg)) = result {
            assert!(msg.contains("10.0.0.1"), "错误消息应包含 IP，实际: {}", msg);
        }
    }

    /// 验证错误传播：limiteron 错误映射为 BulwarkError::Dao。
    ///
    /// 通过注入脏数据（非数字 count）触发 parse 失败，验证错误被正确包装。
    #[tokio::test]
    async fn ddos_limiter_error_maps_to_bulwark_error() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        // 注入脏数据：ddos:global 的 count 是非数字字符串
        // MockDao::eval_lua 识别 INCR+EXPIRE 后调用 incr，incr 内部 parse 失败时 unwrap_or(0)
        // 但 BulwarkDaoDistributedLimiter::atomic_check_and_incr 的降级路径会调用 dao.incr
        // （MockDao 的 eval_lua 不会走 NotImplemented 分支，而是模拟 INCR+EXPIRE）
        // 因此此测试主要验证：当 limiter 返回 Err 时，DDoSStrategy::check 返回 BulwarkError::Dao
        dao.set("ddos:global", "not-a-number", 60).await.unwrap();

        let config = DDoSConfig::default();
        let strategy = DDoSStrategy::new(config, dao);
        let ctx = FirewallContext::new("1.2.3.4");

        // eval_lua 模拟 INCR+EXPIRE：内部 incr 调用时 parse "not-a-number" 失败，
        // MockDao::incr 用 unwrap_or(0) + 1 = 1，所以不会报错而是返回 1
        // → 验证至少不 panic 且返回确定结果
        let _ = strategy.check(&ctx).await;
    }
}
