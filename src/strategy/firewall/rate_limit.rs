//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 速率限制策略。
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
//!
//! # 已知限制：TOCTOU 竞争窗口（M-2，P1）
//!
//! `check` 方法使用 read-modify-write 模式（`storage.get → parse/filter → storage.set`），
//! 在高并发场景下存在 TOCTOU（Time-of-Check-Time-of-Use）竞争窗口：
//!
//! 1. 线程 A 读取时间戳列表（count=N）
//! 2. 线程 B 读取同一时间戳列表（count=N）
//! 3. 线程 A 通过阈值检查，追加时间戳，回写（count=N+1）
//! 4. 线程 B 通过阈值检查，追加时间戳，回写（count=N+1，覆盖线程 A 的写入）
//!
//! **净效果**：高并发下可能放过略多于 `max_requests` 的请求（最坏情况 ~2× 并发数）。
//!
//! ## 为何不使用原子计数器（与 BruteForce 对比）
//!
//! `BruteForceStrategy` 用 [`limiteron::limiters::DistributedLimiter`] 的 `incr_with_ttl`
//! 原子递增计数器，无 TOCTOU 风险。但 `incr_with_ttl` 是**固定窗口**计数器，
//! 无法满足滑动窗口语义（每次请求需过滤已过期的时间戳）。
//!
//! 滑动窗口的过滤操作本质上是 read-modify-write，无法用单一原子原语实现。
//! 要彻底消除 TOCTOU，需要以下方案之一（均为未来工作）：
//!
//! - Redis Lua 脚本（原子 read-filter-check-write）
//! - CAS（compare-and-swap）原语
//! - 分布式锁（性能损失大）
//!
//! ## 当前缓解措施
//!
//! - **TTL 自动过期**：key 设置 `TTL=window_seconds`，窗口无请求时自动清理
//! - **时间戳过滤**：每次读取时过滤过期时间戳，避免窗口膨胀
//! - **阈值检查**：`current_threshold` 动态调整，提供一定的弹性缓冲
//! - **适用场景**：中低并发场景（<1000 QPS per key）下竞争窗口影响可忽略；
//!   超高并发场景建议改用 `BruteForceStrategy`（固定窗口，原子计数）
//!
//! 此限制与 M-4 BruteForce TOCTOU 处理方式一致（文档说明 + 测试加固，非代码修复）。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::limiteron::BulwarkDaoStorage;
use crate::strategy::firewall::{BulwarkFirewallStrategy, CaptchaChallenge, FirewallContext};
use async_trait::async_trait;
use limiteron::storage::Storage;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// 速率限制作用域。
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

/// 速率限制配置。
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
    /// 动态阈值上限。
    ///
    /// - `None`：禁用动态调整，固定使用 `max_requests` 作为阈值。
    /// - `Some(upper)`：允许 [`RateLimitStrategy::current_threshold`] 在
    ///   `[max_requests, upper]` 区间内根据历史流量动态调整。
    ///
    /// 调整规则见 [`RateLimitStrategy::adjust_threshold`]。
    pub dynamic_threshold: Option<usize>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: None,
        }
    }
}

/// 速率限制策略，用 limiteron `Storage` trait 滑动窗口实现。
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
///     dynamic_threshold: None,
/// };
/// let strategy = RateLimitStrategy::new(config, dao);
/// ```
pub struct RateLimitStrategy {
    /// 配置（阈值 + 窗口 + 作用域）。
    config: RateLimitConfig,
    /// 存储（limiteron Storage 适配器，替换 dao 的 get/set/delete）。
    storage: Arc<dyn Storage>,
}

impl RateLimitStrategy {
    /// 创建速率限制策略实例。
    ///
    /// 内部创建 [`BulwarkDaoStorage`] 适配器，将 `dao` 桥接到 limiteron `Storage` trait。
    ///
    /// # 参数
    /// - `config`: 配置（阈值 + 窗口 + 作用域 + 动态阈值上限）。
    /// - `dao`: DAO（oxcache 抽象，用于时间戳列表存储）。
    pub fn new(config: RateLimitConfig, dao: Arc<dyn BulwarkDao>) -> Self {
        let storage = Arc::new(BulwarkDaoStorage::new(dao));
        Self { config, storage }
    }

    /// 设置期望的验证码答案，供后续 [`CaptchaChallenge::verify_challenge`] 比对。
    ///
    /// 存储在 DAO 中（key 由 scope+id 派生，与计数 key 同前缀），TTL 与窗口一致，
    /// 窗口无后续请求时自动过期。
    ///
    /// # 参数
    /// - `ctx`: 防火墙上下文。
    /// - `answer`: 期望答案（明文，由调用方负责生成 captcha 图像）。
    pub async fn set_expected_answer(
        &self,
        ctx: &FirewallContext,
        answer: &str,
    ) -> BulwarkResult<()> {
        let (key, _) = self.build_key(ctx)?;
        // key 形如 `rl:ip:{ip}`，答案 key 复用前缀并追加 `:answer`
        let answer_key = format!("{}:answer", key);
        self.storage
            .set(&answer_key, answer, Some(self.config.window_seconds))
            .await
            .map_err(|e| BulwarkError::Dao(format!("strategy-limiter-storage::{}", e)))
    }

    /// 返回当前生效的速率阈值。
    ///
    /// - `dynamic_threshold=None` 时恒返回 `max_requests`。
    /// - `dynamic_threshold=Some(_)` 时返回 DAO 中持久化的当前阈值
    ///   （区间 `[max_requests, dynamic_threshold]`），缺省回退到 `max_requests`。
    pub async fn current_threshold(&self, ctx: &FirewallContext) -> BulwarkResult<usize> {
        let max = self.config.max_requests as usize;
        let Some(upper) = self.config.dynamic_threshold else {
            return Ok(max);
        };
        let (key, _) = self.build_key(ctx)?;
        let threshold_key = format!("{}:threshold", key);
        let stored = self
            .storage
            .get(&threshold_key)
            .await
            .map_err(|e| BulwarkError::Dao(format!("strategy-limiter-storage::{}", e)))?;
        let raw: usize = stored
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(max);
        // 钳制到 [max, upper]，防止历史脏数据越界
        Ok(raw.clamp(max, upper))
    }

    /// 根据观测到的历史流量调整阈值。
    ///
    /// 调整规则（确定性，Rule 5）：
    /// - `traffic_count >= current * 80%`（高负载）：阈值上调一步，封顶 `dynamic_threshold`。
    /// - `traffic_count < current * 20%`（低负载）：阈值下调一步，下限 `max_requests`。
    /// - 其余区间：不变。
    ///
    /// 仅在 `dynamic_threshold=Some(_)` 时生效；`None` 时直接返回 `max_requests`。
    ///
    /// # 已知限制：TOCTOU 竞争窗口（H-5）
    ///
    /// 此方法使用 read-modify-write（`current_threshold → 计算 → storage.set`），
    /// 高并发下存在 TOCTOU 竞争：两个并发调用可能读到相同的 `current` 值，
    /// 各自计算 `new_threshold` 后最后一次写入覆盖前一次。
    /// 与 `check` 方法的 TOCTOU 处理方式一致（文档说明，保留语义）。
    ///
    /// # 返回
    /// 调整后的当前阈值。
    pub async fn adjust_threshold(
        &self,
        ctx: &FirewallContext,
        traffic_count: usize,
    ) -> BulwarkResult<usize> {
        let max = self.config.max_requests as usize;
        let Some(upper) = self.config.dynamic_threshold else {
            return Ok(max);
        };
        let (key, _) = self.build_key(ctx)?;
        let threshold_key = format!("{}:threshold", key);

        let current = self.current_threshold(ctx).await?;

        // 步长：max_requests 的 10%，至少 1（确定性，Rule 5）
        let step = (max / 10).max(1);

        // 用整数比较替代浮点（Rule 5），避免精度问题
        // 高负载：traffic_count * 5 >= current * 4  <=>  traffic_count >= current * 0.8
        // 低负载：traffic_count * 5 <  current * 1  <=>  traffic_count <  current * 0.2
        let new_threshold = if traffic_count.saturating_mul(5) >= current.saturating_mul(4) {
            (current + step).min(upper)
        } else if traffic_count.saturating_mul(5) < current {
            current.saturating_sub(step).max(max)
        } else {
            current
        };

        // 持久化（TTL=window_seconds，与计数器同窗口）
        self.storage
            .set(
                &threshold_key,
                &new_threshold.to_string(),
                Some(self.config.window_seconds),
            )
            .await
            .map_err(|e| BulwarkError::Dao(format!("strategy-limiter-storage::{}", e)))?;

        Ok(new_threshold)
    }

    /// 根据作用域构造计数 key 并返回作用域标识（用于错误消息）。
    ///
    /// # 错误
    /// - `scope=User` 且 `ctx.login_id` 为 None → `InvalidParam`（显性失败，Rule 12）
    /// - `scope=Tenant` 且 `ctx.tenant_id` 为 None → `InvalidParam`
    fn build_key(&self, ctx: &FirewallContext) -> BulwarkResult<(String, String)> {
        match self.config.scope {
            RateLimitScope::Ip => Ok((format!("rl:ip:{}", ctx.ip), ctx.ip.clone())),
            RateLimitScope::User => match &ctx.login_id {
                Some(id) => Ok((format!("rl:user:{}", id), id.clone())),
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
            .map_err(|e| BulwarkError::Dao(format!("strategy-system-time::{}", e)))?
            .as_millis() as u64;
        let window_start = now_ms.saturating_sub(self.config.window_seconds * 1000);

        // 读取已有时间戳列表（limiteron Storage.get 替换 dao.get）
        let stored = self
            .storage
            .get(&key)
            .await
            .map_err(|e| BulwarkError::Dao(format!("strategy-limiter-storage::{}", e)))?;
        // M-3: parse 失败时 warn 记录脏数据，不静默丢弃
        let mut timestamps: Vec<u64> = stored
            .as_deref()
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|s| match s.parse::<u64>() {
                Ok(v) => Some(v),
                Err(_) => {
                    tracing::warn!(key = %key, raw = %s, "rate_limit: 时间戳 parse 失败，跳过该条目（可能存储层并发写入截断）");
                    None
                }
            })
            .collect();

        // 滑出窗口的时间戳清理
        timestamps.retain(|&t| t > window_start);

        // 剩余数量 >= 当前阈值 → 拦截
        // 使用 current_threshold 而非 max_requests，与 should_challenge 保持一致
        // （dynamic_threshold=None 时 current_threshold 恒等于 max_requests，行为不变）
        let threshold = self.current_threshold(ctx).await?;
        if timestamps.len() >= threshold {
            return Err(BulwarkError::FirewallBlocked(format!(
                "ratelimit: {} {} 窗口内请求数 {} 达到上限 {}",
                scope_id,
                format!("{:?}", self.config.scope).to_lowercase(),
                timestamps.len(),
                threshold
            )));
        }

        // 追加当前时间戳，回写（TTL=window_seconds，窗口无请求时自动过期）
        timestamps.push(now_ms);
        let serialized: String = timestamps
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(",");
        self.storage
            .set(&key, &serialized, Some(self.config.window_seconds))
            .await
            .map_err(|e| BulwarkError::Dao(format!("strategy-limiter-storage::{}", e)))?;
        Ok(())
    }
}

#[async_trait]
impl CaptchaChallenge for RateLimitStrategy {
    async fn should_challenge(&self, ctx: &FirewallContext) -> BulwarkResult<bool> {
        let (key, _) = self.build_key(ctx)?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| BulwarkError::Dao(format!("strategy-system-time::{}", e)))?
            .as_millis() as u64;
        let window_start = now_ms.saturating_sub(self.config.window_seconds * 1000);

        // 读取窗口内时间戳并过滤过期项（不修改状态，与 check 共享算法）
        let stored = self
            .storage
            .get(&key)
            .await
            .map_err(|e| BulwarkError::Dao(format!("strategy-limiter-storage::{}", e)))?;
        let count: usize = stored
            .as_deref()
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<u64>().ok())
            .filter(|&t| t > window_start)
            .count();

        let threshold = self.current_threshold(ctx).await?;
        // 80% 阈值触发挑战（整数运算避免浮点，Rule 5）
        // count >= threshold * 4/5  <=>  count * 5 >= threshold * 4
        Ok(count.saturating_mul(5) >= threshold.saturating_mul(4))
    }

    async fn verify_challenge(&self, ctx: &FirewallContext, answer: &str) -> BulwarkResult<bool> {
        let (key, _) = self.build_key(ctx)?;
        let answer_key = format!("{}:answer", key);
        let stored = self
            .storage
            .get(&answer_key)
            .await
            .map_err(|e| BulwarkError::Dao(format!("strategy-limiter-storage::{}", e)))?;
        let matched = stored.as_deref() == Some(answer);
        if matched {
            self.storage
                .delete(&answer_key)
                .await
                .map_err(|e| BulwarkError::Dao(format!("strategy-limiter-storage::{}", e)))?;
        }
        Ok(matched)
    }
}

inventory::submit! {
    crate::strategy::firewall::StrategyRegistration {
        name: "ratelimit",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::error::BulwarkError;

    /// 验证速率限制：max_requests=10, window_seconds=1 时，
    /// 1 秒内前 10 次返回 Ok，第 11 次返回 FirewallBlocked
    #[tokio::test]
    async fn ratelimit_blocks_after_max_requests() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 1,
            scope: RateLimitScope::Ip,
            dynamic_threshold: None,
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
            dynamic_threshold: None,
        };
        let strategy = RateLimitStrategy::new(config, dao);

        let ctx_a = FirewallContext::new("192.168.1.1").with_login_id("1001");
        let ctx_b = FirewallContext::new("192.168.1.2").with_login_id("1002");

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
            dynamic_threshold: None,
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

    // ========================================================================
    // 验证码挑战 + 动态阈值测试
    // ========================================================================

    /// T096-1: 接近阈值时 should_challenge 返回 true（80% 阈值触发挑战）。
    ///
    /// max_requests=10，调用 check 8 次后到达 80%，应触发挑战。
    #[tokio::test]
    async fn captcha_challenge_should_trigger_when_rate_limit_near() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: None,
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 消耗 8/10 = 80% 配额
        for _ in 0..8 {
            assert!(strategy.check(&ctx).await.is_ok());
        }

        let should = strategy
            .should_challenge(&ctx)
            .await
            .expect("should_challenge 不应报错");
        assert!(should, "达到 80% 阈值时应触发验证码挑战，实际: {}", should);
    }

    /// T096-2: 远低于阈值时 should_challenge 返回 false。
    ///
    /// max_requests=10，仅 1 次请求（10%），不应触发挑战。
    #[tokio::test]
    async fn captcha_challenge_should_not_trigger_when_below_threshold() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: None,
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 仅 1 次请求（10%），远低于 80% 阈值
        strategy.check(&ctx).await.expect("check 不应报错");

        let should = strategy
            .should_challenge(&ctx)
            .await
            .expect("should_challenge 不应报错");
        assert!(!should, "远低于阈值时不应触发挑战，实际: {}", should);
    }

    /// T096-3: 正确答案通过 verify_challenge 验证。
    #[tokio::test]
    async fn captcha_challenge_verify_correct_answer() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig::default();
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 设置期望答案
        strategy
            .set_expected_answer(&ctx, "abc123")
            .await
            .expect("set_expected_answer 不应报错");

        // 正确答案应通过
        let ok = strategy
            .verify_challenge(&ctx, "abc123")
            .await
            .expect("verify_challenge 不应报错");
        assert!(ok, "正确答案应通过验证");
    }

    /// T096-4: 错误答案验证失败。
    #[tokio::test]
    async fn captcha_challenge_verify_incorrect_answer() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig::default();
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        strategy
            .set_expected_answer(&ctx, "abc123")
            .await
            .expect("set_expected_answer 不应报错");

        // 错误答案应失败
        let ok = strategy
            .verify_challenge(&ctx, "wrong-answer")
            .await
            .expect("verify_challenge 不应报错");
        assert!(!ok, "错误答案应验证失败");
    }

    /// C-6: 验证码验证通过后立即删除，防止复用。
    #[tokio::test]
    async fn captcha_challenge_verify_deletes_answer_after_success() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig::default();
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        strategy
            .set_expected_answer(&ctx, "abc123")
            .await
            .expect("set_expected_answer 不应报错");

        // 第一次正确答案应通过
        let first = strategy
            .verify_challenge(&ctx, "abc123")
            .await
            .expect("首次 verify_challenge 不应报错");
        assert!(first, "首次正确答案应通过");

        // 第二次同一答案应失败（验证码已被删除，C-6 修复）
        let second = strategy
            .verify_challenge(&ctx, "abc123")
            .await
            .expect("二次 verify_challenge 不应报错");
        assert!(
            !second,
            "验证码验证通过后应被删除，二次使用同一答案应失败（C-6）"
        );
    }

    /// T096-5: 流量持续高时阈值上调。
    ///
    /// max_requests=10, dynamic_threshold=Some(20)。
    /// 初始阈值 10，传入 traffic_count >= 80% 应上调，封顶 20。
    #[tokio::test]
    async fn dynamic_threshold_increases_when_traffic_high() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: Some(20),
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 初始阈值 = max_requests = 10
        let initial = strategy
            .current_threshold(&ctx)
            .await
            .expect("current_threshold 不应报错");
        assert_eq!(initial, 10, "初始阈值应为 max_requests");

        // 高流量（9 >= 80% of 10 = 8）应触发上调
        let after_high = strategy
            .adjust_threshold(&ctx, 9)
            .await
            .expect("adjust_threshold 不应报错");
        assert!(after_high > 10, "高流量后阈值应上调，实际: {}", after_high);
        assert!(
            after_high <= 20,
            "阈值不应超过 dynamic_threshold 上限，实际: {}",
            after_high
        );

        // 持续高流量直到封顶 20
        let mut current = after_high;
        for i in 0..20 {
            current = strategy
                .adjust_threshold(&ctx, current)
                .await
                .expect("adjust_threshold 不应报错");
            if current >= 20 {
                break;
            }
            assert!(current <= 20, "第 {} 次调整后阈值越界: {}", i, current);
        }
        assert_eq!(
            current, 20,
            "持续高流量应封顶到 dynamic_threshold，实际: {}",
            current
        );
    }

    /// T096-6: 流量持续低时阈值下调。
    ///
    /// 先用高流量把阈值推到高位，再用低流量下调，下限 max_requests。
    #[tokio::test]
    async fn dynamic_threshold_decreases_when_traffic_low() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: Some(20),
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 先用高流量把阈值推到封顶 20
        let mut current = strategy
            .current_threshold(&ctx)
            .await
            .expect("current_threshold 不应报错");
        for _ in 0..20 {
            current = strategy
                .adjust_threshold(&ctx, current)
                .await
                .expect("adjust_threshold 不应报错");
            if current >= 20 {
                break;
            }
        }
        let peaked = current;
        assert_eq!(peaked, 20, "高流量应将阈值推到上限");

        // 低流量（0 << 20% of 20 = 4）应触发下调
        let after_low = strategy
            .adjust_threshold(&ctx, 0)
            .await
            .expect("adjust_threshold 不应报错");
        assert!(
            after_low < peaked,
            "低流量后阈值应下调，实际: {}",
            after_low
        );
        assert!(
            after_low >= 10,
            "阈值不应低于 max_requests，实际: {}",
            after_low
        );

        // 持续低流量直到下限 max_requests
        let mut current = after_low;
        for _ in 0..20 {
            current = strategy
                .adjust_threshold(&ctx, 0)
                .await
                .expect("adjust_threshold 不应报错");
            if current <= 10 {
                break;
            }
        }
        assert_eq!(
            current, 10,
            "持续低流量应触底到 max_requests，实际: {}",
            current
        );
    }

    /// T096-7: 动态阈值上调后 check 使用新阈值而非 max_requests（回归测试）。
    ///
    /// max_requests=10, dynamic_threshold=Some(20)。先用 adjust_threshold 把阈值推到 20，
    /// 再调用 check 11 次——若 check 仍用 max_requests=10，第 11 次会被拦截（bug）；
    /// 修复后 check 应使用 current_threshold=20，第 11 次仍通过。
    #[tokio::test]
    async fn check_uses_dynamic_threshold_not_max_requests() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = RateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
            scope: RateLimitScope::Ip,
            dynamic_threshold: Some(20),
        };
        let strategy = RateLimitStrategy::new(config, dao);
        let ctx = FirewallContext::new("192.168.1.1");

        // 把阈值推到封顶 20
        let mut current = strategy
            .current_threshold(&ctx)
            .await
            .expect("current_threshold 不应报错");
        for _ in 0..20 {
            current = strategy
                .adjust_threshold(&ctx, current)
                .await
                .expect("adjust_threshold 不应报错");
            if current >= 20 {
                break;
            }
        }
        assert_eq!(current, 20, "阈值应已上调到 20");

        // 用新阈值 20 的 80%（=16）触发 should_challenge
        // 先消耗 16 次（应全部通过，因为 16 < 20）
        for i in 1..=16 {
            assert!(
                strategy.check(&ctx).await.is_ok(),
                "动态阈值=20 时第 {} 次 check 应通过（旧 bug 会在此拦截）",
                i
            );
        }

        // 第 17~20 次仍应通过（20 是阈值，< 20 才通过，==20 时第 20 次的 timestamps.len()=19<20 通过，
        // 但第 21 次 timestamps.len()=20 >= 20 拦截）
        // 注意：check 每次成功后追加时间戳，所以第 N 次成功后列表有 N 个时间戳
        // 第 17 次 check 时列表有 16 个，16 < 20 通过；第 21 次时列表有 20 个，20 >= 20 拦截
        for i in 17..=20 {
            assert!(
                strategy.check(&ctx).await.is_ok(),
                "动态阈值=20 时第 {} 次 check 应通过",
                i
            );
        }

        // 第 21 次应被拦截（timestamps.len()=20 >= threshold=20）
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "动态阈值=20 时第 21 次 check 应被拦截，实际: {:?}",
            result
        );
    }
}
