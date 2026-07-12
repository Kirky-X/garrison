//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 状态机模块，定义 Token 与 User 的显式状态机。
//! 以 FRD §4.2 / §4.3 为权威来源。
//!
//! ## 设计
//!
//! - [`TokenState`]：Token 生命周期状态（5 个状态 + 6 条合法转换路径）
//! - [`UserStatus`]：用户账号状态（5 个状态 + 9 条合法转换路径）
//!
//! 状态转换路径严格遵循 FRD，不混合 ADD 文档的路径（规则7 冲突以 FRD 为准）。
//!
//! ## 不在范围内
//!
//! - 与现有 Session / User 模块的集成（推迟到 v0.7.0）
//! - 状态机事件触发（推迟到 v0.7.0）
//! - 状态持久化到 dbnexus（推迟到 v0.7.0）

use crate::error::{BulwarkError, BulwarkResult};

// ============================================================================
// TokenState（FRD §4.3）
// ============================================================================

/// Token 生命周期状态（5 个状态）。
///
/// 依据 FRD §4.3，状态转换路径如下：
///
/// ```text
/// Issued → Active → Active（续期）
///                → Expired（TTL 到达）
///                → Revoked（logout / kickout）
///                → Refreshed（refresh_token）
/// Refreshed → Revoked（旧 Token 立即作废）
/// ```
///
/// `Expired` 与 `Revoked` 为终态，不可转换。
/// `Refreshed` 仅可转换到 `Revoked`（旧 Token 立即作废）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenState {
    /// 已签发，客户端尚未首次使用。
    Issued,
    /// 活跃中，每次访问续期 30min TTL。
    Active,
    /// 已过期（TTL 到达 / exp 字段过期）。终态。
    Expired,
    /// 已撤销（logout / kickout / 账号封禁）。终态。
    Revoked,
    /// 已刷新（refresh_token 调用后旧 Token 状态）。
    Refreshed,
}

// ============================================================================
// UserStatus（FRD §4.1 / §4.2）
// ============================================================================

/// 用户账号状态（5 个状态）。
///
/// 依据 FRD §4.2 状态转换规则表，转换路径如下：
///
/// ```text
/// Pending → Active / Suspended
/// Active → Suspended / Inactive / Deleted
/// Suspended → Active / Deleted
/// Inactive → Active / Deleted
/// Deleted（终态）
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserStatus {
    /// 待激活（注册 / 第三方首次登录）。
    Pending,
    /// 活跃。
    Active,
    /// 已封禁。
    Suspended,
    /// 长期未登录休眠。
    Inactive,
    /// 已删除。终态。
    Deleted,
}

mod impls;

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------
    // TokenState Display 测试
    // ----------------------------------------------------------------

    #[test]
    fn token_state_display_outputs_uppercase() {
        assert_eq!(format!("{}", TokenState::Issued), "ISSUED");
        assert_eq!(format!("{}", TokenState::Active), "ACTIVE");
        assert_eq!(format!("{}", TokenState::Expired), "EXPIRED");
        assert_eq!(format!("{}", TokenState::Revoked), "REVOKED");
        assert_eq!(format!("{}", TokenState::Refreshed), "REFRESHED");
    }

    // ----------------------------------------------------------------
    // TokenState can_transition_to 合法路径测试（R-state-002，6 条）
    // ----------------------------------------------------------------

    #[test]
    fn token_state_issued_to_active_is_valid() {
        assert!(TokenState::Issued.can_transition_to(TokenState::Active));
    }

    #[test]
    fn token_state_active_to_active_is_valid() {
        assert!(TokenState::Active.can_transition_to(TokenState::Active));
    }

    #[test]
    fn token_state_active_to_expired_is_valid() {
        assert!(TokenState::Active.can_transition_to(TokenState::Expired));
    }

    #[test]
    fn token_state_active_to_revoked_is_valid() {
        assert!(TokenState::Active.can_transition_to(TokenState::Revoked));
    }

    #[test]
    fn token_state_active_to_refreshed_is_valid() {
        assert!(TokenState::Active.can_transition_to(TokenState::Refreshed));
    }

    #[test]
    fn token_state_refreshed_to_revoked_is_valid() {
        assert!(TokenState::Refreshed.can_transition_to(TokenState::Revoked));
    }

    // ----------------------------------------------------------------
    // TokenState can_transition_to 非法路径测试（R-state-002）
    // ----------------------------------------------------------------

    #[test]
    fn token_state_issued_to_expired_is_invalid() {
        assert!(!TokenState::Issued.can_transition_to(TokenState::Expired));
    }

    #[test]
    fn token_state_issued_to_revoked_is_invalid() {
        assert!(!TokenState::Issued.can_transition_to(TokenState::Revoked));
    }

    #[test]
    fn token_state_issued_to_refreshed_is_invalid() {
        assert!(!TokenState::Issued.can_transition_to(TokenState::Refreshed));
    }

    #[test]
    fn token_state_expired_cannot_transition_to_anything() {
        use TokenState::*;
        for target in [Issued, Active, Expired, Revoked, Refreshed] {
            assert!(
                !Expired.can_transition_to(target),
                "Expired 不应能转换到 {:?}",
                target
            );
        }
    }

    #[test]
    fn token_state_revoked_cannot_transition_to_anything() {
        use TokenState::*;
        for target in [Issued, Active, Expired, Revoked, Refreshed] {
            assert!(
                !Revoked.can_transition_to(target),
                "Revoked 不应能转换到 {:?}",
                target
            );
        }
    }

    #[test]
    fn token_state_refreshed_to_active_is_invalid() {
        assert!(!TokenState::Refreshed.can_transition_to(TokenState::Active));
    }

    #[test]
    fn token_state_refreshed_to_expired_is_invalid() {
        assert!(!TokenState::Refreshed.can_transition_to(TokenState::Expired));
    }

    #[test]
    fn token_state_refreshed_to_refreshed_is_invalid() {
        assert!(!TokenState::Refreshed.can_transition_to(TokenState::Refreshed));
    }

    // ----------------------------------------------------------------
    // TokenState transition_to 测试（R-state-003）
    // ----------------------------------------------------------------

    #[test]
    fn token_state_transition_to_valid_returns_ok() {
        let result = TokenState::Issued.transition_to(TokenState::Active);
        assert_eq!(result.unwrap(), TokenState::Active);
    }

    #[test]
    fn token_state_transition_to_invalid_returns_err() {
        let result = TokenState::Expired.transition_to(TokenState::Active);
        assert!(result.is_err());
        match result {
            Err(BulwarkError::InvalidStateTransition { from, to }) => {
                assert_eq!(from, "Expired");
                assert_eq!(to, "Active");
            },
            _ => panic!("期望 InvalidStateTransition 错误"),
        }
    }

    // ----------------------------------------------------------------
    // TokenState Copy / Clone / PartialEq / Eq / Hash 测试
    // ----------------------------------------------------------------

    #[test]
    fn token_state_copy_semantics() {
        let state = TokenState::Active;
        let copied = state;
        assert_eq!(state, TokenState::Active);
        assert_eq!(copied, TokenState::Active);
    }

    // ----------------------------------------------------------------
    // UserStatus Display 测试
    // ----------------------------------------------------------------

    #[test]
    fn user_status_display_outputs_uppercase() {
        assert_eq!(format!("{}", UserStatus::Pending), "PENDING");
        assert_eq!(format!("{}", UserStatus::Active), "ACTIVE");
        assert_eq!(format!("{}", UserStatus::Suspended), "SUSPENDED");
        assert_eq!(format!("{}", UserStatus::Inactive), "INACTIVE");
        assert_eq!(format!("{}", UserStatus::Deleted), "DELETED");
    }

    // ----------------------------------------------------------------
    // UserStatus can_transition_to 合法路径测试（R-state-005，9 条）
    // ----------------------------------------------------------------

    #[test]
    fn user_status_pending_to_active_is_valid() {
        assert!(UserStatus::Pending.can_transition_to(UserStatus::Active));
    }

    #[test]
    fn user_status_pending_to_suspended_is_valid() {
        assert!(UserStatus::Pending.can_transition_to(UserStatus::Suspended));
    }

    #[test]
    fn user_status_active_to_suspended_is_valid() {
        assert!(UserStatus::Active.can_transition_to(UserStatus::Suspended));
    }

    #[test]
    fn user_status_active_to_inactive_is_valid() {
        assert!(UserStatus::Active.can_transition_to(UserStatus::Inactive));
    }

    #[test]
    fn user_status_active_to_deleted_is_valid() {
        assert!(UserStatus::Active.can_transition_to(UserStatus::Deleted));
    }

    #[test]
    fn user_status_suspended_to_active_is_valid() {
        assert!(UserStatus::Suspended.can_transition_to(UserStatus::Active));
    }

    #[test]
    fn user_status_suspended_to_deleted_is_valid() {
        assert!(UserStatus::Suspended.can_transition_to(UserStatus::Deleted));
    }

    #[test]
    fn user_status_inactive_to_active_is_valid() {
        assert!(UserStatus::Inactive.can_transition_to(UserStatus::Active));
    }

    #[test]
    fn user_status_inactive_to_deleted_is_valid() {
        assert!(UserStatus::Inactive.can_transition_to(UserStatus::Deleted));
    }

    // ----------------------------------------------------------------
    // UserStatus can_transition_to 非法路径测试（R-state-005）
    // ----------------------------------------------------------------

    #[test]
    fn user_status_pending_to_inactive_is_invalid() {
        assert!(!UserStatus::Pending.can_transition_to(UserStatus::Inactive));
    }

    #[test]
    fn user_status_pending_to_deleted_is_invalid() {
        assert!(!UserStatus::Pending.can_transition_to(UserStatus::Deleted));
    }

    #[test]
    fn user_status_active_to_pending_is_invalid() {
        assert!(!UserStatus::Active.can_transition_to(UserStatus::Pending));
    }

    #[test]
    fn user_status_suspended_to_pending_is_invalid() {
        assert!(!UserStatus::Suspended.can_transition_to(UserStatus::Pending));
    }

    #[test]
    fn user_status_suspended_to_inactive_is_invalid() {
        assert!(!UserStatus::Suspended.can_transition_to(UserStatus::Inactive));
    }

    #[test]
    fn user_status_inactive_to_suspended_is_invalid() {
        assert!(!UserStatus::Inactive.can_transition_to(UserStatus::Suspended));
    }

    #[test]
    fn user_status_inactive_to_pending_is_invalid() {
        assert!(!UserStatus::Inactive.can_transition_to(UserStatus::Pending));
    }

    #[test]
    fn user_status_deleted_cannot_transition_to_anything() {
        use UserStatus::*;
        for target in [Pending, Active, Suspended, Inactive, Deleted] {
            assert!(
                !Deleted.can_transition_to(target),
                "Deleted 不应能转换到 {:?}",
                target
            );
        }
    }

    // ----------------------------------------------------------------
    // UserStatus transition_to 测试（R-state-006）
    // ----------------------------------------------------------------

    #[test]
    fn user_status_transition_to_valid_returns_ok() {
        let result = UserStatus::Pending.transition_to(UserStatus::Active);
        assert_eq!(result.unwrap(), UserStatus::Active);
    }

    #[test]
    fn user_status_transition_to_invalid_returns_err() {
        let result = UserStatus::Deleted.transition_to(UserStatus::Active);
        assert!(result.is_err());
        match result {
            Err(BulwarkError::InvalidStateTransition { from, to }) => {
                assert_eq!(from, "Deleted");
                assert_eq!(to, "Active");
            },
            _ => panic!("期望 InvalidStateTransition 错误"),
        }
    }

    // ----------------------------------------------------------------
    // UserStatus Copy / Clone / PartialEq / Eq / Hash 测试
    // ----------------------------------------------------------------

    #[test]
    fn user_status_copy_semantics() {
        let status = UserStatus::Active;
        let copied = status;
        assert_eq!(status, UserStatus::Active);
        assert_eq!(copied, UserStatus::Active);
    }
}
