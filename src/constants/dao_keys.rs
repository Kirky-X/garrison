// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! DAO key 前缀枚举，提供类型安全的 key 构造。

use std::fmt;

/// DAO key 前缀枚举，统一管理前缀字符串避免硬编码；用 `build_key()` 构造完整 key。
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
    /// OAuth2 授权码已签发 token 的吊销追踪前缀：`oauth2:codeused:`；授权码被原子消费（删除）后其签发的 access/refresh token 记录在此，供重放/双花检测吊销。
    OAuth2CodeUsed,
    /// MFA 编排相关 key 前缀：`mfa:`（恢复码 / 误用计数等）。
    Mfa,
    /// 找回密码流程 key 前缀：`pwdreset:`；flow 会话绑定（`bind:{jti}`）、一次性消费登记（`jti:{jti}`）与防枚举限流（`rate:{identifier}`）的独立键空间。
    PasswordReset,
}

impl DaoKeyPrefix {
    /// 返回前缀字符串（含末尾冒号）。
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
            Self::OAuth2CodeUsed => "oauth2:codeused:",
            Self::Mfa => "mfa:",
            Self::PasswordReset => "pwdreset:",
        }
    }

    /// 构造完整 key：`prefix + id`。
    ///
    /// id 不得含 `:`：多段前缀与含 `:` 的 id 拼接存在解析歧义（`Role`+`"cache:x"` 与 `RoleCache`+`"x"` 同得 `role:cache:x`），无法唯一反解出 (前缀, id)。
    /// debug 构建以 `debug_assert!` 拒绝（panic 早暴露，release 零开销不校验）；复合 id 请调用方先行编码（base64/hex）或自担反解与碰撞排查。
    ///
    /// # 示例
    /// ```
    /// use garrison::constants::DaoKeyPrefix;
    /// assert_eq!(DaoKeyPrefix::Session.build_key("abc"), "session:abc");
    /// ```
    pub fn build_key(&self, id: &str) -> String {
        // 冒号歧义防护：含 `:` 的 id 拼接后无法唯一反解（Role+"cache:x" 与 RoleCache+"x" 同得 "role:cache:x"），debug 拒绝、release 零开销不校验。
        debug_assert!(
            !id.contains(':'),
            "dao_keys::build_key: id must not contain ':' (ambiguous key) — got {:?}",
            id
        );
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
        assert_eq!(DaoKeyPrefix::Cred.build_key("user_pass"), "cred:user_pass");
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

    /// build_key 冒号歧义防护：debug 构建拒绝含 `:` 的 id（`Role`+`"cache:x"` 与 `RoleCache`+`"x"` 碰撞）；release 下 `debug_assert!` 编译期消除不 panic。
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "id must not contain ':'")]
    fn dao_key_prefix_build_key_rejects_colon_id_in_debug() {
        let _ = DaoKeyPrefix::Role.build_key("cache:x");
    }
}
