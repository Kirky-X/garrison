// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 用户级双态锁定策略实现。
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
    // 防御性编程：n=0 时 `pow(n - 1)` 会下溢 panic，按 N=1 兖底（显性化）
    let n = n.max(1);
    match strategy {
        WaitStrategy::Multiple {
            base_seconds,
            multiplier,
        } => {
            // 使用饱和算术防止整数溢出
            let factor = (*multiplier as u64).saturating_pow(n - 1);
            base_seconds.saturating_mul(factor)
        },
        WaitStrategy::Linear { base_seconds } => {
            // 使用饱和算术防止整数溢出
            base_seconds.saturating_mul(n as u64)
        },
    }
}

/// CAS 并发重试上限（`record_failure` / `record_success` 读改写冲突时重试次数）。
const MAX_STATE_CAS_RETRIES: u32 = 5;

impl UserLockoutStrategy {
    /// 创建用户级锁定策略实例。
    ///
    /// 构造时调用 [`UserLockoutConfig::validate`] 校验配置：非法配置（如
    /// `max_failure_factor = 0` 会导致首败即锁）以 `tracing::warn` 记录并回退到
    /// [`UserLockoutConfig::default`]，避免零值退化行为静默生效。
    pub fn new(config: UserLockoutConfig, dao: Arc<dyn GarrisonDao>) -> Self {
        let config = match config.validate() {
            Ok(()) => config,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "UserLockoutConfig invalid, falling back to default config \
                     (degenerate values such as max_failure_factor=0 would lock on first failure)"
                );
                UserLockoutConfig::default()
            },
        };
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

    /// CAS 原子写回锁定状态（expected = 读取时的原始 JSON）。
    ///
    /// # 返回
    /// - `Ok(true)`: CAS 成功，状态已写入。
    /// - `Ok(false)`: CAS 失败（状态已被并发修改，未写入）。
    pub(super) async fn cas_state(
        &self,
        user_id: &str,
        expected: Option<&str>,
        state: &LockoutState,
    ) -> GarrisonResult<bool> {
        let key = DaoKeyPrefix::Lockout.build_key(user_id);
        let json = serde_json::to_string(state)
            .map_err(|e| GarrisonError::Dao(format!("account-lockout-serialize::{}", e)))?;
        self.dao.compare_and_swap(&key, expected, &json, 0).await
    }

    /// 记录登录失败，更新锁定状态。
    ///
    /// 逻辑：
    /// 1. 检查 failure_window_seconds 窗口是否过期 → 过期则重置 failure_count
    /// 2. failure_count += 1 → 达阈值触发锁定 → 临时/永久锁定 → 持久化
    ///
    /// # 并发安全（CAS 原子读改写）
    ///
    /// 读（get/CAS-expected）→ 改 → 写（compare_and_swap）为原子序列：
    /// 同一用户并发调用时 CAS 冲突方自动重试（上限 `MAX_STATE_CAS_RETRIES`），
    /// 消除 get→mutate→set 非原子读改写导致的丢失自增。
    /// 重试耗尽返回 `GarrisonError::Dao`（fail-closed，不静默丢失失败计数）。
    pub async fn record_failure(&self, user_id: &str) -> GarrisonResult<()> {
        let now = now_timestamp();

        for attempt in 1..=MAX_STATE_CAS_RETRIES {
            // 1. 读取当前状态（原始 JSON 作为 CAS expected）
            let key = DaoKeyPrefix::Lockout.build_key(user_id);
            let old_json = self.dao.get(&key).await?;
            let mut state = match &old_json {
                Some(json) => serde_json::from_str(json).map_err(|e| {
                    GarrisonError::Dao(format!("account-lockout-deserialize::{}", e))
                })?,
                None => LockoutState::default(),
            };

            // 2. 检查 failure_window_seconds 窗口：若首次失败距今超过窗口，重置计数
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

            state.failure_count = state.failure_count.saturating_add(1);

            // 锁定触发标记（指标在 CAS 成功后记录，避免重试导致重复计数）。
            // 仅 metrics-prometheus 消费——特性面关闭时变量与赋值同步剥离，
            // 否则空.feature 组合下产生 unused_variables/unused_assignments 告警。
            #[cfg(feature = "metrics-prometheus")]
            let mut locked_permanent = false;
            #[cfg(feature = "metrics-prometheus")]
            let mut locked_temporary = false;

            if state.failure_count >= self.config.max_failure_factor {
                if self.config.permanent_lockout
                    && state.temporary_lockout_count.saturating_add(1)
                        > self.config.max_temporary_lockouts
                {
                    // 永久锁定
                    state.permanent_locked = true;
                    #[cfg(feature = "metrics-prometheus")]
                    {
                        locked_permanent = true;
                    }
                } else {
                    // 临时锁定
                    state.temporary_lockout_count = state.temporary_lockout_count.saturating_add(1);
                    let lock_seconds = calculate_lock_seconds(
                        &self.config.wait_strategy,
                        state.temporary_lockout_count,
                    );
                    // u64 → i64 用饱和转换（`as` 会把 u64::MAX 回绕为 -1，
                    // 使 locked_until 落在过去、锁定即刻失效），并用 saturating_add 防溢出
                    let lock_seconds_i64 = i64::try_from(lock_seconds).unwrap_or(i64::MAX);
                    state.locked_until = now.saturating_add(lock_seconds_i64);
                    #[cfg(feature = "metrics-prometheus")]
                    {
                        locked_temporary = true;
                    }
                }
            }

            // 3. CAS 原子写回；冲突则重试（读取-修改基于最新状态重新计算）
            if self.cas_state(user_id, old_json.as_deref(), &state).await? {
                #[cfg(feature = "metrics-prometheus")]
                if let Some(metrics) = &self.metrics {
                    if locked_permanent {
                        metrics.record_lockout(true);
                    } else if locked_temporary {
                        metrics.record_lockout(false);
                    }
                }
                return Ok(());
            }
            tracing::debug!(
                user_id = user_id,
                attempt = attempt,
                max_retries = MAX_STATE_CAS_RETRIES,
                "lockout state CAS conflict on record_failure, retrying"
            );
        }
        Err(GarrisonError::Dao(format!(
            "account-lockout-cas-retry-exhausted::{}",
            user_id
        )))
    }

    /// 记录登录成功，重置失败计数和临时锁定状态。
    ///
    /// 重置 failure_count、first_failure_at、temporary_lockout_count 和 locked_until，
    /// 不修改 permanent_locked（永久锁定不可通过登录成功解除）。
    ///
    /// # 并发安全
    ///
    /// 与 [`record_failure`](Self::record_failure) 相同的 CAS 原子读改写 +
    /// 重试（上限 `MAX_STATE_CAS_RETRIES`），避免并发下丢失重置或覆盖他方更新。
    pub async fn record_success(&self, user_id: &str) -> GarrisonResult<()> {
        for attempt in 1..=MAX_STATE_CAS_RETRIES {
            let key = DaoKeyPrefix::Lockout.build_key(user_id);
            let old_json = self.dao.get(&key).await?;
            let mut state = match &old_json {
                Some(json) => serde_json::from_str(json).map_err(|e| {
                    GarrisonError::Dao(format!("account-lockout-deserialize::{}", e))
                })?,
                None => LockoutState::default(),
            };
            state.failure_count = 0;
            state.first_failure_at = None;
            // 登录成功时清除临时锁定状态，避免下次失败立即触发更长锁定
            state.temporary_lockout_count = 0;
            state.locked_until = 0;

            if self.cas_state(user_id, old_json.as_deref(), &state).await? {
                return Ok(());
            }
            tracing::debug!(
                user_id = user_id,
                attempt = attempt,
                max_retries = MAX_STATE_CAS_RETRIES,
                "lockout state CAS conflict on record_success, retrying"
            );
        }
        Err(GarrisonError::Dao(format!(
            "account-lockout-cas-retry-exhausted::{}",
            user_id
        )))
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
                "user-lockout-permanent::{}",
                user_id
            )));
        }

        // (4) 临时锁定期内 → 拦截
        let now = now_timestamp();
        if state.locked_until > now {
            return Err(GarrisonError::FirewallBlocked(format!(
                "user-lockout-temporary::{}::{}",
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
