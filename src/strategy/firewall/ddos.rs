//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DDoS 防护策略。
//!
//! `DDoSStrategy` 实现 [`BulwarkFirewallStrategy`] trait，
//! 用 oxcache key `ddos:global` 与 `ddos:ip:{ip}` 存储 token bucket 状态，
//! 实现全局 + 单 IP 双重限流。
//!
//! # 算法（Token Bucket）
//!
//! 1. 每个桶存储 `tokens,last_refill_ms`（逗号分隔）
//! 2. 每次 check 先按时间差补充 token（`elapsed_sec * rps`，不超过 `burst`）
//! 3. `tokens >= 1` 则消耗 1 token 放行，否则拦截
//! 4. 全局桶先检查，per_ip 桶后检查
//!
//! # 与 RateLimit 的区别
//!
//! - RateLimit：滑动窗口（时间戳列表），精确但内存占用高
//! - DDoS：token bucket（两个数值），近似但内存占用低，且允许突发（burst）

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::strategy::firewall::{BulwarkFirewallStrategy, FirewallContext};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// DDoS 防护配置。
///
/// 所有阈值显式配置（Rule 5 确定性逻辑），不交给模型判断。
#[derive(Debug, Clone)]
pub struct DDoSConfig {
    /// 全局每秒最大请求数（所有 IP 共享的 token 补充速率）。
    pub global_rps: u32,
    /// 单 IP 每秒最大请求数（每个 IP 独立的 token 补充速率）。
    pub per_ip_rps: u32,
    /// 桶容量（允许的突发请求数，token 上限）。
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

/// DDoS 防护策略，用 oxcache token bucket 实现。
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
    /// 配置（全局 rps + 单 IP rps + burst）。
    config: DDoSConfig,
    /// DAO（oxcache 抽象，用于 token bucket 状态存储）。
    dao: Arc<dyn BulwarkDao>,
}

impl DDoSStrategy {
    /// 创建 DDoS 防护策略实例。
    ///
    /// # 参数
    /// - `config`: 配置（全局 rps + 单 IP rps + burst）。
    /// - `dao`: DAO（oxcache 抽象，用于 token bucket 状态存储）。
    pub fn new(config: DDoSConfig, dao: Arc<dyn BulwarkDao>) -> Self {
        Self { config, dao }
    }

    /// 检查并消耗一个 token。
    ///
    /// 桶状态存储格式 `"tokens,last_refill_ms"`（逗号分隔）。
    /// 先按时间差补充 token（不超过 burst），再判断是否 >= 1 可消耗。
    ///
    /// # 参数
    /// - `key`: 桶存储 key
    /// - `rps`: token 补充速率（每秒）
    /// - `burst`: 桶容量（token 上限）
    /// - `now_ms`: 当前毫秒时间戳
    /// - `ttl`: `None` 用 `set_permanent`，`Some(sec)` 用 `set` 带 TTL
    ///
    /// # 返回
    /// - `Ok(true)`: 消耗成功
    /// - `Ok(false)`: token 不足
    async fn check_bucket(
        &self,
        key: &str,
        rps: u32,
        burst: u32,
        now_ms: u64,
        ttl: Option<u64>,
    ) -> BulwarkResult<bool> {
        let stored = self.dao.get(key).await?;
        let (mut tokens, mut last_refill) = match stored.as_deref() {
            Some(s) => {
                let mut parts = s.splitn(2, ',');
                let t: f64 = parts
                    .next()
                    .and_then(|p| p.trim().parse().ok())
                    .unwrap_or(burst as f64);
                let l: u64 = parts
                    .next()
                    .and_then(|p| p.trim().parse().ok())
                    .unwrap_or(now_ms);
                (t, l)
            },
            None => (burst as f64, now_ms),
        };

        // 补充 token（按时间差，不超过 burst）
        let elapsed_sec = now_ms.saturating_sub(last_refill) as f64 / 1000.0;
        tokens = (tokens + elapsed_sec * rps as f64).min(burst as f64);
        last_refill = now_ms;

        let ok = if tokens >= 1.0 {
            tokens -= 1.0;
            true
        } else {
            false
        };

        // 写回桶状态（无论是否消耗，都更新 last_refill 避免重复计算时间差）
        let value = format!("{},{}", tokens, last_refill);
        match ttl {
            Some(sec) => self.dao.set(key, &value, sec).await?,
            None => self.dao.set_permanent(key, &value).await?,
        }
        Ok(ok)
    }
}

#[async_trait]
impl BulwarkFirewallStrategy for DDoSStrategy {
    async fn check(&self, ctx: &FirewallContext) -> BulwarkResult<()> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| BulwarkError::Dao(format!("系统时间错误: {}", e)))?
            .as_millis() as u64;

        // 1. 全局桶检查（set_permanent，不过期）
        let global_ok = self
            .check_bucket(
                "ddos:global",
                self.config.global_rps,
                self.config.burst,
                now_ms,
                None,
            )
            .await?;
        if !global_ok {
            return Err(BulwarkError::FirewallBlocked(format!(
                "ddos: 全局速率限制 (rps={}, burst={})",
                self.config.global_rps, self.config.burst
            )));
        }

        // 2. 单 IP 桶检查（TTL=60s，清理不活跃 IP）
        let ip_key = format!("ddos:ip:{}", ctx.ip);
        let ip_ok = self
            .check_bucket(
                &ip_key,
                self.config.per_ip_rps,
                self.config.burst,
                now_ms,
                Some(60),
            )
            .await?;
        if !ip_ok {
            return Err(BulwarkError::FirewallBlocked(format!(
                "ddos: IP {} 速率限制 (rps={}, burst={})",
                ctx.ip, self.config.per_ip_rps, self.config.burst
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

    /// 验证全局 burst 限制：global_rps=1, burst=3 时，
    /// 连续请求前 3 次放行（消耗 burst token），第 4 次被拦截
    #[tokio::test]
    async fn ddos_global_burst_limit() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
            global_rps: 1,
            per_ip_rps: 1000, // per_ip 放宽，只测全局
            burst: 3,
        };
        let strategy = DDoSStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 前 3 次通过（burst token 耗尽）
        for i in 1..=3 {
            assert!(strategy.check(&ctx).await.is_ok(), "第 {} 次应通过", i);
        }

        // 第 4 次被拦截（token 耗尽，时间差小，补充 < 1）
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "第 4 次应返回 FirewallBlocked，实际: {:?}",
            result
        );
    }

    /// 验证单 IP 限流隔离：per_ip_rps=1, burst=3 时，
    /// 不同 IP 互不影响。
    ///
    /// 全局桶与 per_ip 桶共享 burst，IP A 耗尽 per_ip 后需 sleep 让全局桶补充 token，
    /// 才能隔离出 per_ip_a 的拦截行为（避免全局桶成为瓶颈）。
    #[tokio::test]
    async fn ddos_per_ip_isolation() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
            global_rps: 100, // 100 token/sec，sleep 50ms 可补 5 token（capped at burst=3）
            per_ip_rps: 1,
            burst: 3,
        };
        let strategy = DDoSStrategy::new(config, dao);

        let ctx_a = FirewallContext::new("192.168.1.1");
        let ctx_b = FirewallContext::new("192.168.1.2");

        // IP A 前 3 次通过（per_ip burst 耗尽）
        for i in 1..=3 {
            assert!(
                strategy.check(&ctx_a).await.is_ok(),
                "IP A 第 {} 次应通过",
                i
            );
        }

        // 等待 50ms：全局桶补充 5 token（capped at 3）恢复满；
        // per_ip_a 仅补 0.05 token 仍不足（验证 per_ip 拦截）
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // IP A 第 4 次被 per_ip_a 拦截（全局桶已恢复通过，per_ip_a 仍不足）
        let result = strategy.check(&ctx_a).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "IP A 第 4 次应被 per_ip 拦截，实际: {:?}",
            result
        );

        // IP B 有独立额度（全局桶有 token，per_ip_b 初始满）
        assert!(strategy.check(&ctx_b).await.is_ok(), "不同 IP 应互不影响");
    }

    /// 验证 token 补充：消耗全部 token 后，等待足够时间，token 按rps补充
    #[tokio::test]
    async fn ddos_token_refill_after_sleep() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = DDoSConfig {
            global_rps: 10, // 10 token/sec
            per_ip_rps: 1000,
            burst: 2,
        };
        let strategy = DDoSStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 消耗全部 burst token
        assert!(strategy.check(&ctx).await.is_ok());
        assert!(strategy.check(&ctx).await.is_ok());
        // 第 3 次被拦截
        assert!(matches!(
            strategy.check(&ctx).await,
            Err(BulwarkError::FirewallBlocked(_))
        ));

        // 等待 200ms，应补充 10 * 0.2 = 2 token
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // 补充后应能通过 2 次
        assert!(
            strategy.check(&ctx).await.is_ok(),
            "补充后应能通过（token 已补充）"
        );
    }
}
