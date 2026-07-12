//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! TokenState / UserStatus 实现块（从 mod.rs 迁移）。

use super::*;

impl TokenState {
    /// 判断从当前状态到 `target` 的转换是否合法。
    ///
    /// # 合法转换路径（6 条）
    ///
    /// - `Issued → Active`（客户端首次携带使用时）
    /// - `Active → Active`（续期 / 每次访问 +30min TTL）
    /// - `Active → Expired`（TTL 到达 / exp 字段过期）
    /// - `Active → Revoked`（logout / kickout / 账号封禁）
    /// - `Active → Refreshed`（refresh_token 调用 / 签发新 Token）
    /// - `Refreshed → Revoked`（旧 Token 立即作废，写入黑名单）
    ///
    /// # 非法转换路径（返回 false）
    ///
    /// - `Issued → Expired` / `Issued → Revoked` / `Issued → Refreshed`
    ///   （FRD §4.3 不允许，必须先经过 Active）
    /// - `Expired → *`（终态，不可转换）
    /// - `Revoked → *`（终态，不可转换）
    /// - `Refreshed → Active` / `Refreshed → Expired` / `Refreshed → Refreshed`
    ///   （FRD §4.3 不允许，旧 Token 立即作废）
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

    /// 执行状态转换，合法时返回 `Ok(target)`，非法时返回 `Err(InvalidStateTransition)`。
    ///
    /// # 参数
    /// - `target`: 目标状态。
    ///
    /// # 返回
    /// - `Ok(target)`: 转换合法。
    /// - `Err(BulwarkError::InvalidStateTransition { from, to })`: 转换非法。
    ///
    /// # 示例
    ///
    /// ```
    /// use bulwark::state::TokenState;
    ///
    /// let active = TokenState::Issued.transition_to(TokenState::Active).unwrap();
    /// assert_eq!(active, TokenState::Active);
    ///
    /// // 非法转换
    /// let err = TokenState::Expired.transition_to(TokenState::Active).unwrap_err();
    /// assert!(err.to_string().contains("非法状态转换"));
    /// ```
    pub fn transition_to(self, target: TokenState) -> BulwarkResult<TokenState> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(BulwarkError::InvalidStateTransition {
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
    /// 判断从当前状态到 `target` 的转换是否合法。
    ///
    /// # 合法转换路径（9 条）
    ///
    /// - `Pending → Active`（审核通过 / 邮箱验证）
    /// - `Pending → Suspended`（审核拒绝 / 风控拦截）
    /// - `Active → Suspended`（违规 / 管理员冻结）
    /// - `Active → Inactive`（长期未登录 / 90天）
    /// - `Active → Deleted`（用户注销）
    /// - `Suspended → Active`（管理员解封）
    /// - `Suspended → Deleted`（注销）
    /// - `Inactive → Active`（重新登录）
    /// - `Inactive → Deleted`（超期自动清理 / 180天）
    ///
    /// # 非法转换路径（返回 false）
    ///
    /// - `Pending → Inactive` / `Pending → Deleted`（必须先经 Active 或 Suspended）
    /// - `Active → Pending`（不可逆）
    /// - `Suspended → Pending` / `Suspended → Inactive`（必须先经 Active）
    /// - `Inactive → Suspended` / `Inactive → Pending`（必须先经 Active）
    /// - `Deleted → *`（终态）
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

    /// 执行状态转换，合法时返回 `Ok(target)`，非法时返回 `Err(InvalidStateTransition)`。
    ///
    /// # 参数
    /// - `target`: 目标状态。
    ///
    /// # 返回
    /// - `Ok(target)`: 转换合法。
    /// - `Err(BulwarkError::InvalidStateTransition { from, to })`: 转换非法。
    ///
    /// # 示例
    ///
    /// ```
    /// use bulwark::state::UserStatus;
    ///
    /// let active = UserStatus::Pending.transition_to(UserStatus::Active).unwrap();
    /// assert_eq!(active, UserStatus::Active);
    ///
    /// // 非法转换
    /// let err = UserStatus::Deleted.transition_to(UserStatus::Active).unwrap_err();
    /// assert!(err.to_string().contains("非法状态转换"));
    /// ```
    pub fn transition_to(self, target: UserStatus) -> BulwarkResult<UserStatus> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(BulwarkError::InvalidStateTransition {
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
