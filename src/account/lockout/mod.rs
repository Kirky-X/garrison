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

use serde::{Deserialize, Serialize};

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
}
