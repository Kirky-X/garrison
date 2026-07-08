//! 用户级双态账号锁定子模块（v0.6.0 新增，吸收 keycloak UserLockoutStrategy）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 提供用户级 temporary + permanent 双态锁定，与 BruteForceStrategy（IP 级）组合使用。
//! 详见 spec `user-lockout`。
//!
//! # 核心类型（T011）
//!
//! - [`WaitStrategy`]：等待策略 enum（Multiple 倍数 / Linear 线性）
//! - [`UserLockoutConfig`]：用户级锁定配置（5 字段）
//! - [`LockoutState`]：锁定状态（4 字段，DAO 持久化）
//!
//! # 策略实现（T012）
//!
//! T012 将实现 `UserLockoutStrategy` + `BulwarkFirewallStrategy` trait。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::strategy::firewall::{BulwarkFirewallStrategy, FirewallContext, StrategyRegistration};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// 等待策略，计算临时锁定时长（依据 spec user-lockout R-user-lockout-002）。
///
/// - `Multiple`：倍数等待，第 N 次锁定时长 = `base_seconds × multiplier^(N-1)`
/// - `Linear`：线性等待，第 N 次锁定时长 = `base_seconds × N`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WaitStrategy {
    /// 倍数等待：第 N 次锁定时长 = `base_seconds × multiplier^(N-1)`。
    Multiple {
        /// 基础秒数。
        base_seconds: u64,
        /// 倍数（每次锁定时长乘以 multiplier）。
        multiplier: u32,
    },
    /// 线性等待：第 N 次锁定时长 = `base_seconds × N`。
    Linear {
        /// 基础秒数（每次锁定时长 = base_seconds × N）。
        base_seconds: u64,
    },
}

/// 用户级锁定配置（依据 spec user-lockout R-user-lockout-001）。
///
/// 含 5 个公开字段，控制锁定行为阈值与策略。
#[derive(Debug, Clone)]
pub struct UserLockoutConfig {
    /// 触发锁定的失败次数阈值（失败计数达到此值触发临时/永久锁定）。
    pub max_failure_factor: u32,
    /// 是否启用永久锁定（false 时仅临时锁定，不触发永久锁定）。
    pub permanent_lockout: bool,
    /// 永久锁定前的最大临时锁定次数（超过此值后下次触发锁定改为永久锁定）。
    pub max_temporary_lockouts: u32,
    /// 等待策略（计算临时锁定时长）。
    pub wait_strategy: WaitStrategy,
    /// 失败计数窗口（秒），过期后 failure_count 重置。
    pub failure_window_seconds: u64,
}

impl Default for UserLockoutConfig {
    fn default() -> Self {
        Self {
            max_failure_factor: 5,
            permanent_lockout: true,
            max_temporary_lockouts: 3,
            wait_strategy: WaitStrategy::Multiple {
                base_seconds: 60,
                multiplier: 2,
            },
            failure_window_seconds: 300,
        }
    }
}

/// 锁定状态，在 DAO 中以 `lockout:{user_id}` 为 key 持久化
/// （依据 spec user-lockout R-user-lockout-003）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockoutState {
    /// 当前失败次数（达 max_failure_factor 触发锁定）。
    pub failure_count: u32,
    /// 临时锁定次数（永久锁定前累计）。
    pub temporary_lockout_count: u32,
    /// 是否永久锁定（true 时无法自动解锁）。
    pub permanent_locked: bool,
    /// 锁定到期 Unix 时间戳（0 表示未锁定）。
    pub locked_until: i64,
}

impl Default for LockoutState {
    fn default() -> Self {
        Self {
            failure_count: 0,
            temporary_lockout_count: 0,
            permanent_locked: false,
            locked_until: 0,
        }
    }
}

// ============================================================================
// UserLockoutStrategy：用户级双态锁定策略（T012）
// ============================================================================

/// 当前 Unix 时间戳（秒）。
fn now_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 计算临时锁定时长（秒），依据 WaitStrategy 公式。
///
/// - Multiple: base × multiplier^(N-1)
/// - Linear: base × N
///
/// N 为当前临时锁定次数（调用前已自增，N >= 1）。
fn calculate_lock_seconds(strategy: &WaitStrategy, n: u32) -> u64 {
    match strategy {
        WaitStrategy::Multiple {
            base_seconds,
            multiplier,
        } => *base_seconds * (*multiplier as u64).pow(n - 1),
        WaitStrategy::Linear { base_seconds } => *base_seconds * n as u64,
    }
}

/// 用户级双态锁定策略（依据 spec user-lockout R-user-lockout-004~009）。
///
/// 实现 [`BulwarkFirewallStrategy`] trait，与 `BruteForceStrategy`（IP 级）组合使用。
/// 通过 `lockout:{user_id}` key 在 DAO 中持久化 [`LockoutState`]。
///
/// # 构造
///
/// ```ignore
/// use std::sync::Arc;
/// use bulwark::account::lockout::{UserLockoutConfig, UserLockoutStrategy};
/// use bulwark::dao::BulwarkDao;
///
/// let dao: Arc<dyn BulwarkDao> = /* oxcache 实现 */;
/// let strategy = UserLockoutStrategy::new(UserLockoutConfig::default(), dao);
/// ```
pub struct UserLockoutStrategy {
    /// 配置（阈值 + 等待策略 + 窗口）。
    config: UserLockoutConfig,
    /// DAO（oxcache 抽象，用于持久化 LockoutState）。
    dao: Arc<dyn BulwarkDao>,
}

impl UserLockoutStrategy {
    /// 创建用户级锁定策略实例。
    pub fn new(config: UserLockoutConfig, dao: Arc<dyn BulwarkDao>) -> Self {
        Self { config, dao }
    }

    /// 读取用户锁定状态（不存在则返回默认空状态）。
    async fn get_state(&self, user_id: &str) -> BulwarkResult<LockoutState> {
        let key = format!("lockout:{}", user_id);
        match self.dao.get(&key).await? {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| BulwarkError::Dao(format!("反序列化 LockoutState 失败: {}", e))),
            None => Ok(LockoutState::default()),
        }
    }

    /// 持久化用户锁定状态（TTL=0 永久存储，锁定状态不应自动过期）。
    async fn set_state(&self, user_id: &str, state: &LockoutState) -> BulwarkResult<()> {
        let key = format!("lockout:{}", user_id);
        let json = serde_json::to_string(state)
            .map_err(|e| BulwarkError::Dao(format!("序列化 LockoutState 失败: {}", e)))?;
        self.dao.set(&key, &json, 0).await
    }

    /// 记录登录失败，更新锁定状态（依据 spec R-user-lockout-006）。
    ///
    /// 逻辑：failure_count += 1 → 达阈值触发锁定 → 临时/永久锁定 → 持久化。
    pub async fn record_failure(&self, user_id: &str) -> BulwarkResult<()> {
        let mut state = self.get_state(user_id).await?;
        state.failure_count += 1;

        if state.failure_count >= self.config.max_failure_factor {
            if self.config.permanent_lockout
                && state.temporary_lockout_count + 1 > self.config.max_temporary_lockouts
            {
                // 永久锁定
                state.permanent_locked = true;
            } else {
                // 临时锁定
                state.temporary_lockout_count += 1;
                let lock_seconds = calculate_lock_seconds(
                    &self.config.wait_strategy,
                    state.temporary_lockout_count,
                );
                state.locked_until = now_timestamp() + lock_seconds as i64;
            }
        }

        self.set_state(user_id, &state).await
    }

    /// 记录登录成功，重置失败计数（依据 spec R-user-lockout-007）。
    ///
    /// 仅重置 failure_count，不修改 temporary_lockout_count/permanent_locked/locked_until。
    pub async fn record_success(&self, user_id: &str) -> BulwarkResult<()> {
        let mut state = self.get_state(user_id).await?;
        state.failure_count = 0;
        self.set_state(user_id, &state).await
    }

    /// 手动解锁，彻底清空锁定状态（依据 spec R-user-lockout-008）。
    pub async fn unlock(&self, user_id: &str) -> BulwarkResult<()> {
        let state = LockoutState::default();
        self.set_state(user_id, &state).await
    }
}

#[async_trait]
impl BulwarkFirewallStrategy for UserLockoutStrategy {
    async fn check(&self, ctx: &FirewallContext) -> BulwarkResult<()> {
        // (1) login_id 为 None 时跳过用户级检查
        let user_id = match &ctx.login_id {
            Some(id) => id.as_str(),
            None => return Ok(()),
        };

        // (2) 读取锁定状态
        let state = self.get_state(user_id).await?;

        // (3) 永久锁定 → 拦截
        if state.permanent_locked {
            return Err(BulwarkError::FirewallBlocked(format!(
                "user-lockout: 用户 {} 已被永久锁定",
                user_id
            )));
        }

        // (4) 临时锁定期内 → 拦截
        let now = now_timestamp();
        if state.locked_until > now {
            return Err(BulwarkError::FirewallBlocked(format!(
                "user-lockout: 用户 {} 已被临时锁定，直到 {}",
                user_id, state.locked_until
            )));
        }

        // (5) 否则允许
        Ok(())
    }
}

inventory::submit! {
    StrategyRegistration {
        name: "user-lockout",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 UserLockoutConfig::default() 返回预期默认值
    /// （R-user-lockout-001 验收标准）。
    #[test]
    fn config_default_matches_spec() {
        let config = UserLockoutConfig::default();
        assert_eq!(config.max_failure_factor, 5);
        assert!(config.permanent_lockout);
        assert_eq!(config.max_temporary_lockouts, 3);
        assert_eq!(config.failure_window_seconds, 300);
        match &config.wait_strategy {
            WaitStrategy::Multiple {
                base_seconds,
                multiplier,
            } => {
                assert_eq!(*base_seconds, 60);
                assert_eq!(*multiplier, 2);
            },
            other => panic!("默认 wait_strategy 应为 Multiple，实际: {:?}", other),
        }
    }

    /// 验证 WaitStrategy::Multiple 可被 serde 序列化与反序列化
    /// （R-user-lockout-002 验收标准）。
    #[test]
    fn wait_strategy_multiple_serde_roundtrip() {
        let strategy = WaitStrategy::Multiple {
            base_seconds: 60,
            multiplier: 2,
        };
        let json = serde_json::to_string(&strategy).expect("序列化 Multiple 失败");
        let deserialized: WaitStrategy =
            serde_json::from_str(&json).expect("反序列化 Multiple 失败");
        match deserialized {
            WaitStrategy::Multiple {
                base_seconds,
                multiplier,
            } => {
                assert_eq!(base_seconds, 60);
                assert_eq!(multiplier, 2);
            },
            other => panic!("反序列化后应为 Multiple，实际: {:?}", other),
        }
    }

    /// 验证 WaitStrategy::Linear 可被 serde 序列化与反序列化
    /// （R-user-lockout-002 验收标准）。
    #[test]
    fn wait_strategy_linear_serde_roundtrip() {
        let strategy = WaitStrategy::Linear { base_seconds: 30 };
        let json = serde_json::to_string(&strategy).expect("序列化 Linear 失败");
        let deserialized: WaitStrategy = serde_json::from_str(&json).expect("反序列化 Linear 失败");
        match deserialized {
            WaitStrategy::Linear { base_seconds } => {
                assert_eq!(base_seconds, 30);
            },
            other => panic!("反序列化后应为 Linear，实际: {:?}", other),
        }
    }

    /// 验证 LockoutState 可被 serde 序列化与反序列化
    /// （R-user-lockout-003 验收标准）。
    #[test]
    fn lockout_state_serde_roundtrip() {
        let state = LockoutState {
            failure_count: 3,
            temporary_lockout_count: 1,
            permanent_locked: false,
            locked_until: 1700000000,
        };
        let json = serde_json::to_string(&state).expect("序列化 LockoutState 失败");
        let deserialized: LockoutState =
            serde_json::from_str(&json).expect("反序列化 LockoutState 失败");
        assert_eq!(deserialized.failure_count, 3);
        assert_eq!(deserialized.temporary_lockout_count, 1);
        assert!(!deserialized.permanent_locked);
        assert_eq!(deserialized.locked_until, 1700000000);
    }

    /// 验证 UserLockoutConfig 可在外部构造自定义配置
    /// （R-user-lockout-001 验收标准：所有字段为 pub）。
    #[test]
    fn config_custom_construction() {
        let config = UserLockoutConfig {
            max_failure_factor: 10,
            permanent_lockout: false,
            max_temporary_lockouts: 5,
            wait_strategy: WaitStrategy::Linear { base_seconds: 30 },
            failure_window_seconds: 600,
        };
        assert_eq!(config.max_failure_factor, 10);
        assert!(!config.permanent_lockout);
        assert_eq!(config.max_temporary_lockouts, 5);
        assert_eq!(config.failure_window_seconds, 600);
        assert!(matches!(
            config.wait_strategy,
            WaitStrategy::Linear { base_seconds: 30 }
        ));
    }

    /// 验证 LockoutState::default() 返回全零/false 状态
    /// （用于初始化新用户的锁定状态）。
    #[test]
    fn lockout_state_default_is_clean() {
        let state = LockoutState::default();
        assert_eq!(state.failure_count, 0);
        assert_eq!(state.temporary_lockout_count, 0);
        assert!(!state.permanent_locked);
        assert_eq!(state.locked_until, 0);
    }

    /// 验证 WaitStrategy::Multiple 的锁定时长计算公式：base × multiplier^(N-1)
    /// （第 1 次 = 60，第 2 次 = 120，第 3 次 = 240）。
    #[test]
    fn wait_strategy_multiple_formula() {
        let base = 60u64;
        let multiplier = 2u32;
        // 第 1 次：60 × 2^0 = 60
        let n1 = base * (multiplier.pow(0) as u64);
        assert_eq!(n1, 60);
        // 第 2 次：60 × 2^1 = 120
        let n2 = base * (multiplier.pow(1) as u64);
        assert_eq!(n2, 120);
        // 第 3 次：60 × 2^2 = 240
        let n3 = base * (multiplier.pow(2) as u64);
        assert_eq!(n3, 240);
    }

    /// 验证 WaitStrategy::Linear 的锁定时长计算公式：base × N
    /// （第 1 次 = 30，第 2 次 = 60，第 3 次 = 90）。
    #[test]
    fn wait_strategy_linear_formula() {
        let base = 30u64;
        // 第 1 次：30 × 1 = 30
        assert_eq!(base * 1, 30);
        // 第 2 次：30 × 2 = 60
        assert_eq!(base * 2, 60);
        // 第 3 次：30 × 3 = 90
        assert_eq!(base * 3, 90);
    }

    // ===== T012: UserLockoutStrategy 测试 =====

    use crate::dao::tests::MockDao;
    use crate::strategy::firewall::FirewallContext;

    /// 辅助：创建默认配置的 UserLockoutStrategy + MockDao。
    fn make_strategy() -> (UserLockoutStrategy, Arc<dyn BulwarkDao>) {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let strategy = UserLockoutStrategy::new(UserLockoutConfig::default(), dao.clone());
        (strategy, dao)
    }

    /// 验证首次失败：failure_count=1，不触发锁定，check 通过。
    #[tokio::test]
    async fn record_failure_first_does_not_lock() {
        let (strategy, _) = make_strategy();
        strategy.record_failure("user1").await.unwrap();
        let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
        assert!(strategy.check(&ctx).await.is_ok(), "首次失败不应触发锁定");
    }

    /// 验证阈值触发临时锁定：max_failure_factor=5，5 次失败后临时锁定。
    #[tokio::test]
    async fn record_failure_triggers_temporary_lock_at_threshold() {
        let (strategy, _) = make_strategy();
        for _ in 0..4 {
            strategy.record_failure("user1").await.unwrap();
        }
        let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
        assert!(strategy.check(&ctx).await.is_ok(), "4 次失败不应触发锁定");

        strategy.record_failure("user1").await.unwrap();
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "5 次失败应触发临时锁定，实际: {:?}",
            result
        );
    }

    /// 验证临时锁定期间 check 拦截。
    #[tokio::test]
    async fn check_blocks_during_temporary_lockout() {
        let (strategy, _) = make_strategy();
        for _ in 0..5 {
            strategy.record_failure("user1").await.unwrap();
        }
        let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "临时锁定期内应拦截，实际: {:?}",
            result
        );
    }

    /// 验证永久锁定：超过 max_temporary_lockouts 后触发永久锁定。
    #[tokio::test]
    async fn permanent_lockout_after_max_temporary_lockouts() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = UserLockoutConfig {
            max_failure_factor: 2,
            permanent_lockout: true,
            max_temporary_lockouts: 1,
            wait_strategy: WaitStrategy::Linear { base_seconds: 10 },
            failure_window_seconds: 300,
        };
        let strategy = UserLockoutStrategy::new(config, dao);

        // 第 1 轮：2 次失败 → 临时锁定 #1
        strategy.record_failure("user1").await.unwrap();
        strategy.record_failure("user1").await.unwrap();

        // 第 2 轮：再 2 次失败 → 超过 max_temporary_lockouts=1 → 永久锁定
        strategy.record_failure("user1").await.unwrap();
        strategy.record_failure("user1").await.unwrap();

        let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(ref msg)) if msg.contains("永久锁定")),
            "超过 max_temporary_lockouts 应永久锁定，实际: {:?}",
            result
        );
    }

    /// 验证 unlock 手动解锁：解锁后 check 通过。
    #[tokio::test]
    async fn unlock_clears_lockout_state() {
        let (strategy, _) = make_strategy();
        for _ in 0..5 {
            strategy.record_failure("user1").await.unwrap();
        }
        let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
        assert!(strategy.check(&ctx).await.is_err(), "解锁前应被拦截");

        strategy.unlock("user1").await.unwrap();
        assert!(strategy.check(&ctx).await.is_ok(), "解锁后应通过");
    }

    /// 验证 WaitStrategy::Multiple 的 record_failure 时长计算
    /// （第 1 次 ≈ 60s，第 2 次 ≈ 120s）。
    #[tokio::test]
    async fn wait_strategy_multiple_record_failure_duration() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = UserLockoutConfig {
            max_failure_factor: 1,
            permanent_lockout: false,
            max_temporary_lockouts: 99,
            wait_strategy: WaitStrategy::Multiple {
                base_seconds: 60,
                multiplier: 2,
            },
            failure_window_seconds: 300,
        };
        let strategy = UserLockoutStrategy::new(config, dao);

        // 第 1 次临时锁定：locked_until - now ≈ 60
        strategy.record_failure("user1").await.unwrap();
        let state = strategy.get_state("user1").await.unwrap();
        let duration_1 = state.locked_until - now_timestamp();
        assert!(
            (55..=65).contains(&duration_1),
            "第 1 次临时锁定时长应 ≈ 60，实际: {}",
            duration_1
        );

        // 重置以触发第 2 次锁定
        let mut state = strategy.get_state("user1").await.unwrap();
        state.failure_count = 0;
        state.locked_until = 0;
        strategy.set_state("user1", &state).await.unwrap();

        // 第 2 次临时锁定：locked_until - now ≈ 120
        strategy.record_failure("user1").await.unwrap();
        let state = strategy.get_state("user1").await.unwrap();
        let duration_2 = state.locked_until - now_timestamp();
        assert!(
            (115..=125).contains(&duration_2),
            "第 2 次临时锁定时长应 ≈ 120，实际: {}",
            duration_2
        );
    }

    /// 验证 WaitStrategy::Linear 的 record_failure 时长计算
    /// （第 1 次 ≈ 30s，第 2 次 ≈ 60s）。
    #[tokio::test]
    async fn wait_strategy_linear_record_failure_duration() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = UserLockoutConfig {
            max_failure_factor: 1,
            permanent_lockout: false,
            max_temporary_lockouts: 99,
            wait_strategy: WaitStrategy::Linear { base_seconds: 30 },
            failure_window_seconds: 300,
        };
        let strategy = UserLockoutStrategy::new(config, dao);

        // 第 1 次临时锁定：locked_until - now ≈ 30
        strategy.record_failure("user1").await.unwrap();
        let state = strategy.get_state("user1").await.unwrap();
        let duration_1 = state.locked_until - now_timestamp();
        assert!(
            (25..=35).contains(&duration_1),
            "第 1 次临时锁定时长应 ≈ 30，实际: {}",
            duration_1
        );

        // 重置以触发第 2 次锁定
        let mut state = strategy.get_state("user1").await.unwrap();
        state.failure_count = 0;
        state.locked_until = 0;
        strategy.set_state("user1", &state).await.unwrap();

        // 第 2 次临时锁定：locked_until - now ≈ 60
        strategy.record_failure("user1").await.unwrap();
        let state = strategy.get_state("user1").await.unwrap();
        let duration_2 = state.locked_until - now_timestamp();
        assert!(
            (55..=65).contains(&duration_2),
            "第 2 次临时锁定时长应 ≈ 60，实际: {}",
            duration_2
        );
    }

    /// 验证 record_success 重置 failure_count 但不修改锁定字段。
    #[tokio::test]
    async fn record_success_resets_failure_count() {
        let (strategy, _) = make_strategy();
        for _ in 0..3 {
            strategy.record_failure("user1").await.unwrap();
        }
        let state = strategy.get_state("user1").await.unwrap();
        assert_eq!(state.failure_count, 3);

        strategy.record_success("user1").await.unwrap();
        let state = strategy.get_state("user1").await.unwrap();
        assert_eq!(
            state.failure_count, 0,
            "record_success 后 failure_count 应为 0"
        );
        assert_eq!(
            state.temporary_lockout_count, 0,
            "temporary_lockout_count 不应变"
        );
        assert!(!state.permanent_locked, "permanent_locked 不应变");
        assert_eq!(state.locked_until, 0, "locked_until 不应变");
    }

    /// 验证 locked_until 到期后 check 通过。
    #[tokio::test]
    async fn check_passes_after_temporary_lockout_expires() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = UserLockoutConfig {
            max_failure_factor: 1,
            permanent_lockout: false,
            max_temporary_lockouts: 99,
            wait_strategy: WaitStrategy::Linear { base_seconds: 1 },
            failure_window_seconds: 300,
        };
        let strategy = UserLockoutStrategy::new(config, dao);

        strategy.record_failure("user1").await.unwrap();
        let ctx = FirewallContext::new("1.1.1.1").with_login_id("user1");
        assert!(strategy.check(&ctx).await.is_err(), "锁定期内应拦截");

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert!(strategy.check(&ctx).await.is_ok(), "锁定到期后应通过");
    }

    /// 验证 ctx.login_id=None 时 check 返回 Ok(()) 跳过用户级检查。
    #[tokio::test]
    async fn check_skips_when_login_id_is_none() {
        let (strategy, _) = make_strategy();
        let ctx = FirewallContext::new("1.1.1.1");
        assert!(strategy.check(&ctx).await.is_ok(), "login_id=None 时应跳过");
    }

    /// 验证多用户隔离：用户 A 的锁定状态不影响用户 B。
    #[tokio::test]
    async fn multi_user_isolation() {
        let (strategy, _) = make_strategy();
        for _ in 0..5 {
            strategy.record_failure("alice").await.unwrap();
        }
        let ctx_a = FirewallContext::new("1.1.1.1").with_login_id("alice");
        let ctx_b = FirewallContext::new("2.2.2.2").with_login_id("bob");
        assert!(strategy.check(&ctx_a).await.is_err(), "用户 A 应被锁定");
        assert!(strategy.check(&ctx_b).await.is_ok(), "用户 B 不应受影响");
    }

    /// 验证 inventory 注册了 "user-lockout" 策略名称。
    #[test]
    fn user_lockout_registered_via_inventory() {
        use std::iter::Iterator;
        let _ = std::any::TypeId::of::<UserLockoutStrategy>();
        let names: Vec<&'static str> = inventory::iter::<StrategyRegistration>()
            .map(|r| r.name)
            .collect();
        assert!(
            names.contains(&"user-lockout"),
            "inventory 应注册 user-lockout 策略，实际: {:?}",
            names
        );
    }
}
