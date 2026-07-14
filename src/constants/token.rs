//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Token 类型枚举，统一管理 OAuth2/JWT token 类型字符串。

use std::fmt;

/// OAuth2 token 类型（RFC 6749 §7.1）。
///
/// 统一管理 token 类型字符串，避免硬编码。
/// - `Bearer`：RFC 6750 Bearer Token
/// - `Access`：access_token 记录类型（内部存储用）
/// - `Refresh`：refresh_token 记录类型（内部存储用）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenType {
    /// Bearer Token（RFC 6750）。
    Bearer,
    /// access_token 记录类型标识。
    Access,
    /// refresh_token 记录类型标识。
    Refresh,
}

impl TokenType {
    /// 返回 token 类型字符串。
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Bearer => "Bearer",
            Self::Access => "access",
            Self::Refresh => "refresh",
        }
    }
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
