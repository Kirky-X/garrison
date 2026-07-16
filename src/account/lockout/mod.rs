//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 用户级双态账号锁定子模块（吸收 keycloak UserLockoutStrategy）。
//! 提供用户级 temporary + permanent 双态锁定，与 BruteForceStrategy（IP 级）组合使用。
//! 详见 spec `user-lockout`。
//!
//! # 核心类型（T011）
//!
//! - [`WaitStrategy`](crate::account::lockout::WaitStrategy)：等待策略 enum（Multiple 倍数 / Linear 线性）
//! - [`UserLockoutConfig`](crate::account::lockout::UserLockoutConfig)：用户级锁定配置（5 字段）
//! - [`LockoutState`](crate::account::lockout::LockoutState)：锁定状态（4 字段，DAO 持久化）
//!
//! # 策略实现（T012）
//!
//! T012 的 `UserLockoutStrategy` + `BulwarkFirewallStrategy` trait 实现位于 [`strategy`] 子模块。

use crate::dao::BulwarkDao;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 锁定状态存储抽象子模块。
///
/// v0.6.0 的 `UserLockoutStrategy` 直接通过 `BulwarkDao` 持久化 `LockoutState`，
/// 本子模块预留给未来版本的专用存储后端实现（Redis TTL / SQL 持久化 / 分布式锁定）。
pub mod storage;

/// 策略实现子模块（impl 块、辅助函数、inventory 注册）。
pub mod strategy;

#[cfg(test)]
pub mod tests;

/// 等待策略，计算临时锁定时长。
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

/// 用户级锁定配置。
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

// ============================================================================
// UserLockoutStrategy：用户级双态锁定策略（T012）
// ============================================================================

/// 用户级双态锁定策略。
///
/// 实现 [`BulwarkFirewallStrategy`](crate::strategy::firewall::BulwarkFirewallStrategy) trait，
/// 与 `BruteForceStrategy`（IP 级）组合使用。
/// 通过 `lockout:{user_id}` key 在 DAO 中持久化 [`LockoutState`]。
///
/// impl 块与 trait 实现位于 [`strategy`] 子模块。
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
    pub(super) config: UserLockoutConfig,
    /// DAO（oxcache 抽象，用于持久化 LockoutState）。
    pub(super) dao: Arc<dyn BulwarkDao>,
    /// 账号安全指标（可选，注入后触发锁定时调用 `record_lockout`）。
    #[cfg(feature = "metrics-prometheus")]
    pub(super) metrics: Option<Arc<crate::account::metrics::AccountMetrics>>,
}
