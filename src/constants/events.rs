//! 事件 reason 枚举，提供类型安全的事件原因标识。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use std::fmt;

/// 事件 reason 枚举。
///
/// 统一管理所有事件 reason 字符串，避免硬编码。
///
/// 目前覆盖以下事件变体的 reason 字段：
/// - [`crate::listener::BulwarkEvent::LoginFailure`]（`InvalidCredentials`）
/// - [`crate::listener::BulwarkEvent::Kickout`]（`Kickout` / `Logout` 等）
/// - [`crate::listener::BulwarkEvent::AccountLocked`]（`Locked`）
/// - [`crate::listener::BulwarkEvent::FirewallBlock`]（`Revoked` / `Expired` 等）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventReason {
    /// 无效凭证（v0.4.2 安全审计 A-014：user_not_found 与 wrong_password 统一）
    InvalidCredentials,
    /// 已过期
    Expired,
    /// 已吊销
    Revoked,
    /// 已锁定
    Locked,
    /// 主动登出
    Logout,
    /// 管理员踢出
    Kickout,
}

impl EventReason {
    /// 返回 reason 字符串。
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidCredentials => "invalid_credentials",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Locked => "locked",
            Self::Logout => "logout",
            Self::Kickout => "kickout",
        }
    }
}

impl fmt::Display for EventReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_reason_as_str_matches_expected() {
        assert_eq!(
            EventReason::InvalidCredentials.as_str(),
            "invalid_credentials"
        );
        assert_eq!(EventReason::Expired.as_str(), "expired");
        assert_eq!(EventReason::Revoked.as_str(), "revoked");
        assert_eq!(EventReason::Locked.as_str(), "locked");
        assert_eq!(EventReason::Logout.as_str(), "logout");
        assert_eq!(EventReason::Kickout.as_str(), "kickout");
    }

    #[test]
    fn event_reason_display_matches_as_str() {
        assert_eq!(
            format!("{}", EventReason::InvalidCredentials),
            "invalid_credentials"
        );
        assert_eq!(format!("{}", EventReason::Kickout), "kickout");
    }
}
