// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 用户级双态账号锁定子模块（吸收 Keycloak UserLockoutStrategy）：temporary + permanent 双态，
//! 与 IP 级 `BruteForceStrategy` 组合使用。
//!
//! 核心类型：`WaitStrategy`（倍数/线性等待）、[`UserLockoutConfig`](crate::account::lockout::UserLockoutConfig)
//! （5 字段配置）、[`LockoutState`](crate::account::lockout::LockoutState)（5 字段，DAO 持久化）；
//! `UserLockoutStrategy` 实现位于 [`strategy`](crate::account::lockout::strategy) 子模块。
//!
//! 持久化：状态经 [`GarrisonDao`](crate::dao::GarrisonDao) 落 `lockout:{user_id}` 键——SQL /
//! Redis TTL / 分布式后端由 DAO 的部署选型覆盖，无独立存储抽象。写入 TTL 策略见 `strategy`
//! 子模块：永久锁定与锁定升级计数永久驻留，纯计数窗口态在窗口到期后自然清理（键缺失读路径
//! 返回默认态，与窗口过期重置语义等价）。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 策略实现子模块（impl 块、辅助函数、inventory 注册）。
pub mod strategy;

#[cfg(test)]
pub mod tests;

/// 等待策略，计算临时锁定时长。
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

/// 用户级锁定配置（5 个公开字段：阈值 / 永久开关 / 临时锁定上限 / 等待策略 / 计数窗口）。
///
/// 字段 pub 以支持外部构造；零值/退化值（如 `max_failure_factor = 0` 首败即锁）由
/// [`validate`](Self::validate) 校验，[`UserLockoutStrategy::new`](crate::account::lockout::UserLockoutStrategy::new)
/// 构造时调用，非法配置 warn 后回退默认配置。
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

impl UserLockoutConfig {
    /// 校验配置合法性，防止零值退化行为。
    ///
    /// 规则：`max_failure_factor` / `failure_window_seconds` / `wait_strategy` 参数为 0（首败即锁 /
    /// 窗口永不重置 / 锁定即刻过期），或 `permanent_lockout` 下 `max_temporary_lockouts = 0` 时，
    /// 返回 [`GarrisonError::Config`] 并附具体原因。
    pub fn validate(&self) -> GarrisonResult<()> {
        if self.max_failure_factor == 0 {
            return Err(GarrisonError::Config(
                "lockout-config-max-failure-factor-zero::".to_string(),
            ));
        }
        if self.failure_window_seconds == 0 {
            return Err(GarrisonError::Config(
                "lockout-config-failure-window-zero::".to_string(),
            ));
        }
        if self.permanent_lockout && self.max_temporary_lockouts == 0 {
            return Err(GarrisonError::Config(
                "lockout-config-max-temporary-lockouts-zero::".to_string(),
            ));
        }
        match &self.wait_strategy {
            WaitStrategy::Multiple {
                base_seconds,
                multiplier,
            } => {
                if *base_seconds == 0 || *multiplier == 0 {
                    return Err(GarrisonError::Config(
                        "lockout-config-wait-strategy-zero::".to_string(),
                    ));
                }
            },
            WaitStrategy::Linear { base_seconds } => {
                if *base_seconds == 0 {
                    return Err(GarrisonError::Config(
                        "lockout-config-wait-strategy-zero::".to_string(),
                    ));
                }
            },
        }
        Ok(())
    }
}

/// 锁定状态，在 DAO 中以 `lockout:{user_id}` 为 key 持久化。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockoutState {
    /// 当前失败次数（达 max_failure_factor 触发锁定）。
    pub failure_count: u32,
    /// 临时锁定次数（永久锁定前累计）。
    pub temporary_lockout_count: u32,
    /// 是否永久锁定（true 时无法自动解锁）。
    pub permanent_locked: bool,
    /// 锁定到期 Unix 时间戳（0 表示未锁定）。
    pub locked_until: i64,
    /// 首次失败时间戳（用于 failure_window_seconds 窗口判断，None 表示无失败记录）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_failure_at: Option<i64>,
}

/// 用户级双态锁定策略：实现
/// [`GarrisonFirewallStrategy`](crate::strategy::firewall::GarrisonFirewallStrategy) trait，与 IP 级
/// `BruteForceStrategy` 组合，经 `lockout:{user_id}` key 持久化 [`LockoutState`]；impl 块位于 [`strategy`] 子模块。
///
/// # 构造
///
/// ```ignore
/// use std::sync::Arc;
/// use garrison::account::lockout::{UserLockoutConfig, UserLockoutStrategy};
/// use garrison::dao::GarrisonDao;
///
/// let dao: Arc<dyn GarrisonDao> = /* oxcache 实现 */;
/// let strategy = UserLockoutStrategy::new(UserLockoutConfig::default(), dao);
/// ```
pub struct UserLockoutStrategy {
    /// 配置（阈值 + 等待策略 + 窗口）。
    pub(super) config: UserLockoutConfig,
    /// DAO（oxcache 抽象，用于持久化 LockoutState）。
    pub(super) dao: Arc<dyn GarrisonDao>,
    /// 账号安全指标（可选，注入后触发锁定时调用 `record_lockout`）。
    #[cfg(feature = "metrics-prometheus")]
    pub(super) metrics: Option<Arc<crate::account::metrics::AccountMetrics>>,
}
