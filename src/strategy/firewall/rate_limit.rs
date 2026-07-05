//! 速率限制策略（依据 spec firewall R-firewall-002）。
//!
//! `RateLimitStrategy` 实现 [`BulwarkFirewallStrategy`] trait，
//! 用 oxcache key `rl:{scope}:{id}` 存储请求时间戳列表（逗号分隔），
//! 滑动窗口过滤过期时间戳后判断是否超阈值。
//!
//! # 算法（滑动窗口，非固定窗口）
//!
//! 1. 根据 scope 构造 key：`rl:ip:{ip}` / `rl:user:{login_id}` / `rl:tenant:{tenant_id}`
//! 2. 读取 key → 解析为毫秒时间戳列表
//! 3. 过滤掉 `now - window_seconds * 1000` 之前的时间戳（滑出窗口）
//! 4. 剩余数量 >= max_requests → 返回 `FirewallBlocked`
//! 5. 否则追加当前时间戳，回写（TTL=window_seconds，窗口无请求时自动过期）
//!
//! # 与 BruteForce 的区别
//!
//! - BruteForce：固定窗口计数（update 保留 TTL，不重置窗口）
//! - RateLimit：滑动窗口（每次请求追加时间戳，过滤过期）
//! - 滑动窗口避免边界突刺（固定窗口在窗口边界处可能瞬间放过 2× max_requests）

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::strategy::firewall::{BulwarkFirewallStrategy, FirewallContext};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// 速率限制作用域（依据 spec firewall R-firewall-002）。
///
/// 决定计数 key 的构造维度：
/// - `Ip`：按请求 IP 计数（`rl:ip:{ip}`）
/// - `User`：按登录主体计数（`rl:user:{login_id}`）
/// - `Tenant`：按租户计数（`rl:tenant:{tenant_id}`）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitScope {
    /// 按请求 IP 计数。
    Ip,
    /// 按登录主体 login_id 计数。
    User,
    /// 按租户 tenant_id 计数。
    Tenant,
}

/// 速率限制配置（依据 spec firewall R-firewall-002）。
///
/// 所有阈值显式配置（Rule 5 确定性逻辑），不交给模型判断。
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// 窗口内最大请求数（超阈值后拦截）。
    pub max_requests: u32,
    /// 窗口大小（秒），超过此时间的请求时间戳被滑出窗口。
    pub window_seconds: u64,
    /// 计数作用域（Ip / User / Tenant）。
    pub scope: RateLimitScope,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
        }
    }
}

/// 速率限制策略，用 oxcache 滑动窗口实现（依据 spec firewall R-firewall-002）。
///
/// # 构造
///
/// ```ignore
/// use std::sync::Arc;
/// use bulwark::dao::BulwarkDao;
/// use bulwark::strategy::firewall::rate_limit::{RateLimitConfig, RateLimitScope, RateLimitStrategy};
///
/// let dao: Arc<dyn BulwarkDao> = /* oxcache 实现 */;
/// let config = RateLimitConfig {
///     max_requests: 10,
///     window_seconds: 1,
///     scope: RateLimitScope::Ip,
/// };
/// let strategy = RateLimitStrategy::new(config, dao);
/// ```
pub struct RateLimitStrategy {
    /// 配置（阈值 + 窗口 + 作用域）。
    config: RateLimitConfig,
    /// DAO（oxcache 抽象，用于时间戳列表存储）。
    dao: Arc<dyn BulwarkDao>,
}

impl RateLimitStrategy {
    /// 创建速率限制策略实例。
    ///
    /// # 参数
    /// - `config`: 配置（阈值 + 窗口 + 作用域）。
    /// - `dao`: DAO（oxcache 抽象，用于时间戳列表存储）。
    pub fn new(config: RateLimitConfig, dao: Arc<dyn BulwarkDao>) -> Self {
        Self { config, dao }
    }

    /// 根据作用域构造计数 key 并返回作用域标识（用于错误消息）。
    ///
    /// # 错误
    /// - `scope=User` 且 `ctx.login_id` 为 None → `InvalidParam`（显性失败，Rule 12）
    /// - `scope=Tenant` 且 `ctx.tenant_id` 为 None → `InvalidParam`
    fn build_key(&self, ctx: &FirewallContext) -> BulwarkResult<(String, String)> {
        match self.config.scope {
            RateLimitScope::Ip => Ok((format!("rl:ip:{}", ctx.ip), ctx.ip.clone())),
            RateLimitScope::User => match ctx.login_id {
                Some(id) => Ok((format!("rl:user:{}", id), id.to_string())),
                None => Err(BulwarkError::InvalidParam(
                    "RateLimit scope=User 但 ctx.login_id 为 None".to_string(),
                )),
            },
            RateLimitScope::Tenant => match ctx.tenant_id {
                Some(id) => Ok((format!("rl:tenant:{}", id), id.to_string())),
                None => Err(BulwarkError::InvalidParam(
                    "RateLimit scope=Tenant 但 ctx.tenant_id 为 None".to_string(),
                )),
            },
        }
    }
}

#[async_trait]
impl BulwarkFirewallStrategy for RateLimitStrategy {
    async fn check(&self, ctx: &FirewallContext) -> BulwarkResult<()> {
        let (key, scope_id) = self.build_key(ctx)?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| BulwarkError::Dao(format!("系统时间错误: {}", e)))?
            .as_millis() as u64;
        let window_start = now_ms.saturating_sub(self.config.window_seconds * 1000);

        // 读取已有时间戳列表
        let stored = self.dao.get(&key).await?;
        let mut timestamps: Vec<u64> = stored
            .as_deref()
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse().ok())
            .collect();

        // 滑出窗口的时间戳清理
        timestamps.retain(|&t| t > window_start);

        // 剩余数量 >= max_requests → 拦截
        if timestamps.len() >= self.config.max_requests as usize {
            return Err(BulwarkError::FirewallBlocked(format!(
                "ratelimit: {} {} 窗口内请求数 {} 达到上限 {}",
                scope_id,
                format!("{:?}", self.config.scope).to_lowercase(),
                timestamps.len(),
                self.config.max_requests
            )));
        }

        // 追加当前时间戳，回写（TTL=window_seconds，窗口无请求时自动过期）
        timestamps.push(now_ms);
        let serialized: String = timestamps
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(",");
        self.dao
            .set(&key, &serialized, self.config.window_seconds)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::error::BulwarkError;

    /// 验证速率限制：max_requests=10, window_seconds=1 时，
    /// 1 秒内前 10 次返回 Ok，第 11 次返回 FirewallBlocked
    ///（依据 spec firewall R-firewall-002 验收标准 1）。
    #[tokio::test]
    async fn ratelimit_blocks_after_max_requests() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 1,
            scope: RateLimitScope::Ip,
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 前 10 次通过
        for i in 1..=10 {
            assert!(strategy.check(&ctx).await.is_ok(), "第 {} 次应通过", i);
        }

        // 第 11 次被拦截
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "第 11 次应返回 FirewallBlocked，实际: {:?}",
            result
        );
    }

    /// 验证 scope=User 时按 login_id 计数，不同用户互不影响。
    #[tokio::test]
    async fn ratelimit_scope_user_isolates_by_login_id() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 2,
            window_seconds: 60,
            scope: RateLimitScope::User,
        };
        let strategy = RateLimitStrategy::new(config, dao);

        let ctx_a = FirewallContext::new("192.168.1.1").with_login_id(1001);
        let ctx_b = FirewallContext::new("192.168.1.2").with_login_id(1002);

        // 用户 A 用完 2 次额度
        assert!(strategy.check(&ctx_a).await.is_ok());
        assert!(strategy.check(&ctx_a).await.is_ok());
        // 用户 A 第 3 次应被拦截
        assert!(matches!(
            strategy.check(&ctx_a).await,
            Err(BulwarkError::FirewallBlocked(_))
        ));
        // 用户 B 仍有额度
        assert!(strategy.check(&ctx_b).await.is_ok());
    }

    /// 验证 scope=User 且 login_id=None 时返回 InvalidParam（显性失败，Rule 12）。
    #[tokio::test]
    async fn ratelimit_scope_user_without_login_id_fails() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::User,
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1"); // 无 login_id

        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "scope=User 且 login_id=None 应返回 InvalidParam，实际: {:?}",
            result
        );
    }
}
