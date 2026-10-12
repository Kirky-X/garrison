// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 用户级双态锁定策略实现：`UserLockoutStrategy` 的 impl 块、`GarrisonFirewallStrategy` trait 实现与
//! 辅助函数 `now_timestamp` / `calculate_lock_seconds`；接口定义保留在 [`super`](crate::account::lockout) 模块。

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

/// 计算临时锁定时长（秒）：Multiple = base × multiplier^(N-1)，Linear = base × N；N 为当前临时锁定
/// 次数（调用前已自增，N ≥ 1）。n=0 时按 N=1 防御性兜底。
fn calculate_lock_seconds(strategy: &WaitStrategy, n: u32) -> u64 {
    // n=0 时 `pow(n - 1)` 会下溢 panic，按 N=1 兜底
    let n = n.max(1);
    match strategy {
        WaitStrategy::Multiple {
            base_seconds,
            multiplier,
        } => {
            let factor = (*multiplier as u64).saturating_pow(n - 1);
            base_seconds.saturating_mul(factor)
        },
        WaitStrategy::Linear { base_seconds } => base_seconds.saturating_mul(n as u64),
    }
}

/// CAS 并发重试上限（`record_failure` / `record_success` 读改写冲突时重试次数）。
const MAX_STATE_CAS_RETRIES: u32 = 5;

/// 单次失败记录触发的锁定类型（metrics 在 CAS 成功后按此分类记录）。
enum LockoutTrigger {
    /// 未达阈值，仅计数累积。
    None,
    /// 触发临时锁定（按退避策略延长）。
    Temporary,
    /// 触发永久锁定。
    Permanent,
}

impl UserLockoutStrategy {
    /// 创建用户级锁定策略实例。
    ///
    /// 构造时经 [`UserLockoutConfig::validate`] 校验：非法配置（零值退化，如 `max_failure_factor = 0`
    /// 首败即锁）以 `tracing::warn` 记录并回退 [`UserLockoutConfig::default`]。
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

    /// 注入指标（builder，需 `metrics-prometheus` feature）：注入后触发临时/永久锁定时调用
    /// `record_lockout`；未注入时锁定逻辑不变，仅不记录指标。
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

    /// CAS 原子写回锁定状态（expected = 读取时的原始 JSON）；`Ok(false)` 表示 CAS 失败未写入
    /// （状态已被并发修改）。
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

    /// 记录登录失败：窗口过期重置计数，自增后达阈值触发临时/永久锁定，CAS 写回。
    ///
    /// # 并发安全（CAS 原子读改写）
    ///
    /// 读 → 改 → CAS 为原子序列：并发冲突方自动重试（上限 `MAX_STATE_CAS_RETRIES`），消除非原子
    /// 读改写的丢失自增；重试耗尽返回 `GarrisonError::Dao`（fail-closed，不静默丢失失败计数）。
    pub async fn record_failure(&self, user_id: &str) -> GarrisonResult<()> {
        let now = now_timestamp();

        for attempt in 1..=MAX_STATE_CAS_RETRIES {
            let key = DaoKeyPrefix::Lockout.build_key(user_id);
            let old_json = self.dao.get(&key).await?;
            let mut state = match &old_json {
                Some(json) => serde_json::from_str(json).map_err(|e| {
                    GarrisonError::Dao(format!("account-lockout-deserialize::{}", e))
                })?,
                None => LockoutState::default(),
            };

            #[cfg_attr(not(feature = "metrics-prometheus"), allow(unused_variables))]
            let trigger = self.advance_failure_state(&mut state, now);

            if self.cas_state(user_id, old_json.as_deref(), &state).await? {
                // 指标在 CAS 成功后记录，避免重试导致重复计数
                #[cfg(feature = "metrics-prometheus")]
                if let Some(metrics) = &self.metrics {
                    match trigger {
                        LockoutTrigger::Permanent => metrics.record_lockout(true),
                        LockoutTrigger::Temporary => metrics.record_lockout(false),
                        LockoutTrigger::None => {},
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

    /// 单次失败的纯状态推进（持久化由调用方 CAS 负责）：窗口过期则重置计数，自增达
    /// `max_failure_factor` 触发锁定（永久条件满足走永久，否则按退避策略延长临时锁定）；
    /// 返回触发的锁定类型（metrics 记录用）。
    fn advance_failure_state(&self, state: &mut LockoutState, now: i64) -> LockoutTrigger {
        match state.first_failure_at {
            Some(first_at) if now - first_at > self.config.failure_window_seconds as i64 => {
                state.failure_count = 0;
                state.first_failure_at = Some(now);
            },
            None => {
                state.first_failure_at = Some(now);
            },
            // 窗口内：继续累积计数，不更新 first_failure_at
            Some(_) => {},
        }

        state.failure_count = state.failure_count.saturating_add(1);
        if state.failure_count < self.config.max_failure_factor {
            return LockoutTrigger::None;
        }

        if self.config.permanent_lockout
            && state.temporary_lockout_count.saturating_add(1) > self.config.max_temporary_lockouts
        {
            state.permanent_locked = true;
            return LockoutTrigger::Permanent;
        }

        // u64 → i64 用饱和转换（`as` 会把 u64::MAX 回绕为 -1，使 locked_until 落在过去、
        // 锁定即刻失效），并用 saturating_add 防溢出
        state.temporary_lockout_count = state.temporary_lockout_count.saturating_add(1);
        let lock_seconds =
            calculate_lock_seconds(&self.config.wait_strategy, state.temporary_lockout_count);
        let lock_seconds_i64 = i64::try_from(lock_seconds).unwrap_or(i64::MAX);
        state.locked_until = now.saturating_add(lock_seconds_i64);
        LockoutTrigger::Temporary
    }

    /// 记录登录成功：重置 failure_count / first_failure_at / temporary_lockout_count / locked_until，
    /// 不修改 `permanent_locked`（永久锁定不可通过登录成功解除）。
    ///
    /// # 并发安全
    ///
    /// 与 [`record_failure`](Self::record_failure) 相同的 CAS 原子读改写 + 重试（上限
    /// `MAX_STATE_CAS_RETRIES`），避免并发下丢失重置或覆盖他方更新。
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
        let user_id = match &ctx.login_id {
            Some(id) => id.as_str(),
            None => return Ok(()),
        };

        let state = self.get_state(user_id).await?;

        if state.permanent_locked {
            return Err(GarrisonError::FirewallBlocked(format!(
                "user-lockout-permanent::{}",
                user_id
            )));
        }

        let now = now_timestamp();
        if state.locked_until > now {
            return Err(GarrisonError::FirewallBlocked(format!(
                "user-lockout-temporary::{}::{}",
                user_id, state.locked_until
            )));
        }

        Ok(())
    }
}

inventory::submit! {
    StrategyRegistration {
        name: "user-lockout",
    }
}
