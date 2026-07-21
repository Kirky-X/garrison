//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 用户级双态锁定策略实现（T012）。
//!
//! 本文件包含 `UserLockoutStrategy` 的 impl 块、
//! [`GarrisonFirewallStrategy`](crate::strategy::firewall::GarrisonFirewallStrategy) trait 实现，
//! 以及辅助函数 `now_timestamp` / `calculate_lock_seconds`。
//!
//! 接口定义（struct 字段、enum）保留在 [`super`](crate::account::lockout) 模块。

use crate::constants::DaoKeyPrefix;
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::strategy::firewall::{FirewallContext, GarrisonFirewallStrategy, StrategyRegistration};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{LockoutState, UserLockoutConfig, UserLockoutStrategy, WaitStrategy};

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

/// 当前 Unix 时间戳（秒）。
pub(super) fn now_timestamp() -> i64 {
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
/// N 为当前临时锁定次数（调用前已自增，N >= 1）。n=0 时按 N=1 计算防御性兜底。
fn calculate_lock_seconds(strategy: &WaitStrategy, n: u32) -> u64 {
    // 防御性编程：n=0 时 `pow(n - 1)` 会下溢 panic，按 N=1 兜底（规则 12 显性化）
    let n = n.max(1);
    match strategy {
        WaitStrategy::Multiple {
            base_seconds,
            multiplier,
        } => *base_seconds * (*multiplier as u64).pow(n - 1),
        WaitStrategy::Linear { base_seconds } => *base_seconds * n as u64,
    }
}

impl UserLockoutStrategy {
    /// 创建用户级锁定策略实例。
    pub fn new(config: UserLockoutConfig, dao: Arc<dyn GarrisonDao>) -> Self {
        Self {
            config,
            dao,
            #[cfg(feature = "metrics-prometheus")]
            metrics: None,
        }
    }

    /// 注入账号安全指标（builder 模式，需启用 `metrics-prometheus` feature）。
    ///
    /// 注入后 `record_failure` 触发临时/永久锁定时调用 `record_lockout(permanent)`。
    /// 未注入时锁定逻辑不变，仅不记录指标。
    #[cfg(feature = "metrics-prometheus")]
    pub fn with_metrics(mut self, metrics: Arc<crate::account::metrics::AccountMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// 读取用户锁定状态（不存在则返回默认空状态）。
    pub(super) async fn get_state(&self, user_id: &str) -> GarrisonResult<LockoutState> {
        let key = DaoKeyPrefix::Lockout.build_key(user_id);
        match self.dao.get(&key).await? {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| GarrisonError::Dao(format!("account-lockout-deserialize::{}", e))),
            None => Ok(LockoutState::default()),
        }
    }

    /// 持久化用户锁定状态（TTL=0 永久存储，锁定状态不应自动过期）。
    pub(super) async fn set_state(
        &self,
        user_id: &str,
        state: &LockoutState,
    ) -> GarrisonResult<()> {
        let key = DaoKeyPrefix::Lockout.build_key(user_id);
        let json = serde_json::to_string(state)
            .map_err(|e| GarrisonError::Dao(format!("account-lockout-serialize::{}", e)))?;
        self.dao.set(&key, &json, 0).await
    }

    /// 记录登录失败，更新锁定状态。
    ///
    /// 逻辑：
    /// 1. 检查 failure_window_seconds 窗口是否过期 → 过期则重置 failure_count
    /// 2. failure_count += 1 → 达阈值触发锁定 → 临时/永久锁定 → 持久化
    pub async fn record_failure(&self, user_id: &str) -> GarrisonResult<()> {
        let mut state = self.get_state(user_id).await?;
        let now = now_timestamp();

        // 检查 failure_window_seconds 窗口：若首次失败距今超过窗口，重置计数
        match state.first_failure_at {
            Some(first_at) => {
                let window = self.config.failure_window_seconds as i64;
                if now - first_at > window {
                    // 窗口过期，重置失败计数
                    state.failure_count = 0;
                    state.first_failure_at = Some(now);
                }
                // 窗口内：继续累积计数，不更新 first_failure_at
            },
            None => {
                // 首次失败：记录时间戳
                state.first_failure_at = Some(now);
            },
        }

        state.failure_count += 1;

        if state.failure_count >= self.config.max_failure_factor {
            if self.config.permanent_lockout
                && state.temporary_lockout_count + 1 > self.config.max_temporary_lockouts
            {
                // 永久锁定
                state.permanent_locked = true;
                #[cfg(feature = "metrics-prometheus")]
                if let Some(metrics) = &self.metrics {
                    metrics.record_lockout(true);
                }
            } else {
                // 临时锁定
                state.temporary_lockout_count += 1;
                let lock_seconds = calculate_lock_seconds(
                    &self.config.wait_strategy,
                    state.temporary_lockout_count,
                );
                state.locked_until = now_timestamp() + lock_seconds as i64;
                #[cfg(feature = "metrics-prometheus")]
                if let Some(metrics) = &self.metrics {
                    metrics.record_lockout(false);
                }
            }
        }

        self.set_state(user_id, &state).await
    }

    /// 记录登录成功，重置失败计数。
    ///
    /// 仅重置 failure_count 和 first_failure_at，不修改 temporary_lockout_count/permanent_locked/locked_until。
    pub async fn record_success(&self, user_id: &str) -> GarrisonResult<()> {
        let mut state = self.get_state(user_id).await?;
        state.failure_count = 0;
        state.first_failure_at = None;
        self.set_state(user_id, &state).await
    }

    /// 手动解锁，彻底清空锁定状态。
    pub async fn unlock(&self, user_id: &str) -> GarrisonResult<()> {
        let state = LockoutState::default();
        self.set_state(user_id, &state).await
    }
}

#[async_trait]
impl GarrisonFirewallStrategy for UserLockoutStrategy {
    async fn check(&self, ctx: &FirewallContext) -> GarrisonResult<()> {
        // (1) login_id 为 None 时跳过用户级检查
        let user_id = match &ctx.login_id {
            Some(id) => id.as_str(),
            None => return Ok(()),
        };

        // (2) 读取锁定状态
        let state = self.get_state(user_id).await?;

        // (3) 永久锁定 → 拦截
        if state.permanent_locked {
            return Err(GarrisonError::FirewallBlocked(format!(
                "user-lockout: 用户 {} 已被永久锁定",
                user_id
            )));
        }

        // (4) 临时锁定期内 → 拦截
        let now = now_timestamp();
        if state.locked_until > now {
            return Err(GarrisonError::FirewallBlocked(format!(
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
