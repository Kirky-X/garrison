// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! TokenState / UserStatus 实现块（从 mod.rs 迁移）。

use super::*;

impl TokenState {
    /// 判断到 `target` 的转换是否合法：合法 6 条（`Issued → Active`、`Active → Active/Expired/Revoked/Refreshed`、`Refreshed → Revoked`（旧 Token 立即作废，写入黑名单）），其余（含终态转出、跳步）均返回 false。
    pub fn can_transition_to(self, target: TokenState) -> bool {
        use TokenState::*;
        matches!(
            (self, target),
            (Issued, Active)
                | (Active, Active)
                | (Active, Expired)
                | (Active, Revoked)
                | (Active, Refreshed)
                | (Refreshed, Revoked)
        )
    }

    /// 执行状态转换；非法时返回 `Err(GarrisonError::InvalidStateTransition { from, to })`。
    ///
    /// # 示例
    ///
    /// ```
    /// use garrison::state::TokenState;
    ///
    /// let active = TokenState::Issued.transition_to(TokenState::Active).unwrap();
    /// assert_eq!(active, TokenState::Active);
    ///
    /// // 非法转换
    /// let err = TokenState::Expired.transition_to(TokenState::Active).unwrap_err();
    /// assert!(format!("{:?}", err).contains("InvalidStateTransition"));
    /// ```
    pub fn transition_to(self, target: TokenState) -> GarrisonResult<TokenState> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(GarrisonError::InvalidStateTransition {
                from: format!("{:?}", self),
                to: format!("{:?}", target),
            })
        }
    }
}

impl std::fmt::Display for TokenState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use TokenState::*;
        match self {
            Issued => write!(f, "ISSUED"),
            Active => write!(f, "ACTIVE"),
            Expired => write!(f, "EXPIRED"),
            Revoked => write!(f, "REVOKED"),
            Refreshed => write!(f, "REFRESHED"),
        }
    }
}

impl UserStatus {
    /// 判断到 `target` 的转换是否合法：合法 9 条（`Pending → Active/Suspended`、`Active → Suspended/Inactive/Deleted`、`Suspended/Inactive → Active/Deleted`），其余（含终态转出、回退）均返回 false。
    pub fn can_transition_to(self, target: UserStatus) -> bool {
        use UserStatus::*;
        matches!(
            (self, target),
            (Pending, Active)
                | (Pending, Suspended)
                | (Active, Suspended)
                | (Active, Inactive)
                | (Active, Deleted)
                | (Suspended, Active)
                | (Suspended, Deleted)
                | (Inactive, Active)
                | (Inactive, Deleted)
        )
    }

    /// 执行状态转换；非法时返回 `Err(GarrisonError::InvalidStateTransition { from, to })`。
    ///
    /// # 示例
    ///
    /// ```
    /// use garrison::state::UserStatus;
    ///
    /// let active = UserStatus::Pending.transition_to(UserStatus::Active).unwrap();
    /// assert_eq!(active, UserStatus::Active);
    ///
    /// // 非法转换
    /// let err = UserStatus::Deleted.transition_to(UserStatus::Active).unwrap_err();
    /// assert!(format!("{:?}", err).contains("InvalidStateTransition"));
    /// ```
    pub fn transition_to(self, target: UserStatus) -> GarrisonResult<UserStatus> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(GarrisonError::InvalidStateTransition {
                from: format!("{:?}", self),
                to: format!("{:?}", target),
            })
        }
    }
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use UserStatus::*;
        match self {
            Pending => write!(f, "PENDING"),
            Active => write!(f, "ACTIVE"),
            Suspended => write!(f, "SUSPENDED"),
            Inactive => write!(f, "INACTIVE"),
            Deleted => write!(f, "DELETED"),
        }
    }
}
