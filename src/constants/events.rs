// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 事件 reason 枚举，提供类型安全的事件原因标识。
use std::fmt;

/// 事件 reason 枚举，统一管理 reason 字符串避免硬编码；覆盖 `LoginFailure`（`InvalidCredentials`/`HashFormatError`）、`Kickout`、`AccountLocked`、`FirewallBlock` 等事件的 reason 字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventReason {
    /// 无效凭证（user_not_found 与 wrong_password 统一）
    InvalidCredentials,
    /// 密码哈希格式不支持（hasher.verify 失败，可泄露给运维定位）
    HashFormatError,
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
            Self::HashFormatError => "hash_format_error",
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
        assert_eq!(EventReason::HashFormatError.as_str(), "hash_format_error");
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
        assert_eq!(
            format!("{}", EventReason::HashFormatError),
            "hash_format_error"
        );
        assert_eq!(format!("{}", EventReason::Kickout), "kickout");
    }
}
