//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! state 模块测试（从 mod.rs 迁移，Rule 25 合规）。

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
