//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! DDoS 防护策略。
//!
//! `DDoSStrategy` 实现 [`GarrisonFirewallStrategy`] trait，
//! 用 limiteron 的 `GarrisonDaoDistributedLimiter::atomic_check_and_incr` 实现
//! 全局 + 单 IP 双重限流（fixed window counter 语义，禁止手写 token bucket）。
//!
//! # 算法（Fixed Window Counter，委托 limiteron）
//!
//! 1. 单 IP 桶：`atomic_check_and_incr("ddos:ip:{ip}", threshold=per_ip_rps, ttl=1s)`
//! —— 1 秒窗口内允许 per_ip_rps 次单 IP 请求
//! 2. 全局桶：`atomic_check_and_incr("ddos:global", threshold=burst, ttl=1s)`
//! —— 1 秒窗口内允许 burst 次全局请求
//! 3. **单 IP 桶先检查，全局桶后检查**：被单 IP 拦截的攻击流量不消耗全局额度，
//! 全局突发余量留给正常用户（语义取舍见下方"计数顺序"）
//! 4. 窗口 TTL 到期后计数器自动重置（DAO 后端的 TTL 机制保证）
//!
//! # 计数顺序
//!
//! 旧实现先 incr 全局桶再查单 IP 桶：被单 IP 拦截的请求已不可逆消耗全局额度，
//! 实际全局限额比 `burst` 更严格（每次 per-IP 拦截都挤占全局窗口），攻击者可
//! 借此提前打满全局桶。改为先查单 IP 后 incr 全局后：
//! - 单 IP 拦截 → 全局桶未被触碰（攻击流量不挤占正常用户额度）；
//! - 全局拦截 → 该 IP 桶已 +1，但该请求本就被拒绝，仅影响攻击者自身的
//! per-IP 计数（惩罚方向正确），无需回滚。
//! 相比"先全局后回滚"方案，此顺序无需分布式 decr 补偿（避免补偿失败造成
//! 计数漂移），语义上对正常用户更公平。
//!
//! # 与 RateLimit 的区别
//!
//! - RateLimit：滑动窗口（时间戳列表），精确但内存占用高
//! - DDoS：fixed window counter（单计数器 + TTL），近似但内存占用低，且允许突发（burst）
//!
//! # 原子性保证
//!
//! `GarrisonDaoDistributedLimiter::atomic_check_and_incr` 在 Redis 后端用 Lua 脚本
//! （INCR + EXPIRE 原子），在非 Redis 后端降级到 `dao.incr`（进程内 Mutex 原子）。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::limiteron::GarrisonDaoDistributedLimiter;
use crate::strategy::firewall::{FirewallContext, GarrisonFirewallStrategy};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

/// DDoS 防护配置。
///
/// 所有阈值显式配置（确定性逻辑），不交给模型判断。
///
/// # 字段语义（Fixed Window Counter）
///
/// - `per_ip_rps`：单 IP 每秒允许的请求数（单 IP 桶的 threshold）。
/// - `burst`：全局突发上限（全局桶的 threshold，1 秒窗口内允许的总请求数）。
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
    ///
    /// # 参数
    /// - `config`: 配置（单 IP rps + 全局 burst）。
    /// - `dao`: DAO（oxcache 抽象，桥接到 limiteron 适配器）。
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

        // 1. 单 IP 桶检查（threshold=per_ip_rps，1 秒窗口）。
        // 先查单 IP：被 per-IP 拦截的攻击流量不消耗全局额度
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

        // 2. 全局桶检查（threshold=burst，1 秒窗口）。
        // 全局拦截时该 IP 桶已 +1：请求本就被拒绝，仅影响攻击者自身计数，
        // 不做回滚（避免分布式 decr 补偿失败造成计数漂移，见模块文档"计数顺序"）
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

    /// 验证全局 burst 限制：burst=3 时，1 秒窗口内前 3 次放行，第 4 次被拦截。
    ///
    /// 配置 per_ip_rps=1000 放宽单 IP 限制，确保拦截来自全局桶。
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

        // 第 4 次被拦截（全局桶计数 4 > 3，窗口未过期）
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(GarrisonError::FirewallBlocked(_))),
            "第 4 次应返回 FirewallBlocked，实际: {:?}",
            result
        );
    }

    /// 验证单 IP 限流隔离：per_ip_rps=2 时，不同 IP 互不影响。
    ///
    /// 配置 burst=1000 放宽全局限制，确保拦截来自单 IP 桶。
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

        // IP A 第 3 次被 per_ip_a 拦截（计数 3 > 2）
        let result = strategy.check(&ctx_a).await;
        assert!(
            matches!(result, Err(GarrisonError::FirewallBlocked(_))),
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

        // 第 3 次被拦截（count=3 > 2，窗口未过期）
        assert!(matches!(
            strategy.check(&ctx).await,
            Err(GarrisonError::FirewallBlocked(_))
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
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
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
            matches!(result, Err(GarrisonError::FirewallBlocked(_))),
            "第 2 次应被 per_ip 拦截（per_ip_rps=1），实际: {:?}",
            result
        );
        // 验证错误消息包含 IP 信息（区分 per_ip 拦截 vs 全局拦截）
        if let Err(GarrisonError::FirewallBlocked(msg)) = result {
            assert!(msg.contains("10.0.0.1"), "错误消息应包含 IP，实际: {}", msg);
        }
    }

    /// 验证错误传播：limiteron 错误映射为 GarrisonError::Dao。
    ///
    /// 通过注入脏数据（`ddos:global` 的 count 是非数字字符串）触发 DAO incr 解析失败：
    /// per-IP 桶先检查通过（key 不存在 → incr=1 <= per_ip_rps），随后全局桶
    /// `incr` 解析脏数据报错（InMemoryDao 显性报错），经
    /// `atomic_check_and_incr` → limiteron 错误 → `strategy-ddos-global` 前缀的
    /// `GarrisonError::Dao` 向上传播（Fail Loud）。
    #[tokio::test]
    async fn ddos_limiter_error_maps_to_garrison_error() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        // 注入脏数据：ddos:global 的 count 是非数字字符串
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

    /// 验证计数顺序：单 IP 拦截不消耗全局额度。
    ///
    /// burst=3，per_ip_rps=2。攻击 IP 被单 IP 桶拦截的请求不应 incr 全局桶，
    /// 正常用户（其他 IP）仍能使用完整全局额度：
    /// - 旧实现（先全局后单 IP）：攻击者第 3 次被单 IP 拦截前已把全局 incr 到 3，
    /// 正常用户第 1 次就会因全局 4 > 3 被误拦；
    /// - 新实现（先单 IP 后全局）：攻击者第 3 次在单 IP 桶即被拦截，全局保持 2，
    /// 正常用户第 1 次通过（全局 3），第 2 次才因全局额度耗尽被拦。
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

        // 攻击 IP 第 3 次被单 IP 桶拦截（per_ip=3 > 2），全局桶保持 2 不被消耗
        assert!(matches!(
            strategy.check(&attacker).await,
            Err(GarrisonError::FirewallBlocked(msg)) if msg.contains("ddos-ip-blocked")
        ));

        // 正常 IP：第 1 次通过（旧实现此处会因全局已被消耗到 3、incr 后 4 > 3 被误拦）
        let victim = FirewallContext::new("7.7.7.7");
        assert!(
            strategy.check(&victim).await.is_ok(),
            "单 IP 拦截不应消耗全局额度，正常 IP 第 1 次应通过"
        );
        // 正常 IP 第 2 次：全局额度才真正耗尽（incr 后 4 > 3）
        assert!(matches!(
            strategy.check(&victim).await,
            Err(GarrisonError::FirewallBlocked(msg)) if msg.contains("ddos-global-blocked")
        ));
    }
}
