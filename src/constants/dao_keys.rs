//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DAO key 前缀枚举，提供类型安全的 key 构造。

use std::fmt;

/// DAO key 前缀枚举。
///
/// 统一管理所有 DAO key 前缀，避免硬编码字符串。
/// 使用 `build_key()` 方法构造完整 key。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DaoKeyPrefix {
    /// 会话相关 key 前缀：`session:`
    Session,
    /// Token 相关 key 前缀：`token:`
    Token,
    /// 验证码相关 key 前缀：`captcha:`
    Captcha,
    /// SAML 相关 key 前缀：`saml:`
    Saml,
    /// 凭证相关 key 前缀：`cred:`
    Cred,
    /// 锁定相关 key 前缀：`lockout:`
    Lockout,
    /// 暴力破解防护相关 key 前缀：`bf:`
    BruteForce,
    /// 租户相关 key 前缀：`tenant:`
    Tenant,
    /// 角色相关 key 前缀：`role:`
    Role,
    /// 权限缓存 key 前缀：`perm:cache:`
    PermissionCache,
    /// 角色缓存 key 前缀：`role:cache:`
    RoleCache,
    /// 用户缓存 key 前缀：`user:cache:`
    UserCache,
    /// OAuth2 客户端 key 前缀：`oauth2:client:`
    OAuth2Client,
    /// OAuth2 授权码 key 前缀：`oauth2:authcode:`
    OAuth2AuthCode,
    /// OAuth2 access_token key 前缀：`oauth2:atoken:`
    OAuth2AccessToken,
    /// OAuth2 refresh_token key 前缀：`oauth2:rtoken:`
    ///
    /// # 废弃（v0.7.1）
    ///
    /// 启用 `db-sqlite` feature 并通过 `TokenHandler::with_refresh_rotation` 注入
    /// `RefreshTokenRotation` 后，refresh_token 走统一轮换路径（hash chain +
    /// reuse detection），不再使用 DAO 键值存储。
    ///
    /// 未启用 `db-sqlite` 时仍作为 fallback 路径使用（无 reuse detection，
    /// 文档明确标注安全风险）。
    #[deprecated(
        since = "0.7.1",
        note = "启用 db-sqlite feature + RefreshTokenRotation 走统一轮换路径"
    )]
    OAuth2RefreshToken,
}

impl DaoKeyPrefix {
    /// 返回前缀字符串（含末尾冒号）。
    #[allow(deprecated)]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Session => "session:",
            Self::Token => "token:",
            Self::Captcha => "captcha:",
            Self::Saml => "saml:",
            Self::Cred => "cred:",
            Self::Lockout => "lockout:",
            Self::BruteForce => "bf:",
            Self::Tenant => "tenant:",
            Self::Role => "role:",
            Self::PermissionCache => "perm:cache:",
            Self::RoleCache => "role:cache:",
            Self::UserCache => "user:cache:",
            Self::OAuth2Client => "oauth2:client:",
            Self::OAuth2AuthCode => "oauth2:authcode:",
            Self::OAuth2AccessToken => "oauth2:atoken:",
            Self::OAuth2RefreshToken => "oauth2:rtoken:",
        }
    }

    /// 构造完整 key：`prefix + id`。
    ///
    /// # 示例
    /// ```
    /// use garrison::constants::DaoKeyPrefix;
    /// assert_eq!(DaoKeyPrefix::Session.build_key("abc"), "session:abc");
    /// ```
    pub fn build_key(&self, id: &str) -> String {
        format!("{}{}", self.as_str(), id)
    }
}

impl fmt::Display for DaoKeyPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dao_key_prefix_as_str_returns_correct_string() {
        assert_eq!(DaoKeyPrefix::Session.as_str(), "session:");
        assert_eq!(DaoKeyPrefix::Token.as_str(), "token:");
        assert_eq!(DaoKeyPrefix::Captcha.as_str(), "captcha:");
        assert_eq!(DaoKeyPrefix::Saml.as_str(), "saml:");
        assert_eq!(DaoKeyPrefix::Cred.as_str(), "cred:");
        assert_eq!(DaoKeyPrefix::Lockout.as_str(), "lockout:");
        assert_eq!(DaoKeyPrefix::BruteForce.as_str(), "bf:");
        assert_eq!(DaoKeyPrefix::Tenant.as_str(), "tenant:");
        assert_eq!(DaoKeyPrefix::Role.as_str(), "role:");
        assert_eq!(DaoKeyPrefix::PermissionCache.as_str(), "perm:cache:");
        assert_eq!(DaoKeyPrefix::RoleCache.as_str(), "role:cache:");
        assert_eq!(DaoKeyPrefix::UserCache.as_str(), "user:cache:");
    }

    #[test]
    fn dao_key_prefix_build_key_returns_correct_string() {
        assert_eq!(DaoKeyPrefix::Session.build_key("abc"), "session:abc");
        assert_eq!(DaoKeyPrefix::Token.build_key("xyz123"), "token:xyz123");
        assert_eq!(
            DaoKeyPrefix::Captcha.build_key("img_001"),
            "captcha:img_001"
        );
        assert_eq!(DaoKeyPrefix::Cred.build_key("user:pass"), "cred:user:pass");
        assert_eq!(
            DaoKeyPrefix::BruteForce.build_key("192.168.1.1"),
            "bf:192.168.1.1"
        );
        assert_eq!(
            DaoKeyPrefix::PermissionCache.build_key("1001"),
            "perm:cache:1001"
        );
        assert_eq!(DaoKeyPrefix::RoleCache.build_key("1001"), "role:cache:1001");
        assert_eq!(DaoKeyPrefix::UserCache.build_key("1001"), "user:cache:1001");
    }

    #[test]
    fn dao_key_prefix_display_matches_as_str() {
        assert_eq!(format!("{}", DaoKeyPrefix::Session), "session:");
        assert_eq!(format!("{}", DaoKeyPrefix::Token), "token:");
    }
}
