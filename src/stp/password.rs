//! PasswordLogic trait — 密码登录契约。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 从 v0.5.2 起，从 `BulwarkLogic` 上帝 trait 拆分；本 trait 承接密码登录 1 个方法。
//! super-trait 为 [`SessionLogic`]（密码校验通过后调用
//! [`login`](SessionLogic::login) 签发 token）。
//!
//! # LoginId 迁移（v0.4.2 spec R-login-id-type-003）
//!
//! `login_id` 参数从 `i64` 迁移为 `&LoginId`（对象安全）。
//! `BulwarkUtil` 保留 `impl Into<LoginId>` ergonomic 入口。

use crate::error::{BulwarkError, BulwarkResult};
use crate::stp::login_id::LoginId;
use crate::stp::session::SessionLogic;
use async_trait::async_trait;

/// 密码逻辑 trait，定义密码登录契约（0.4.2 新增，依据 spec auth-password-login）。
///
/// # 默认实现
///
/// [`login_with_password`](Self::login_with_password) 默认返回 `NotImplemented`
/// （未启用 `secure-password` + `db-sqlite` feature）。
/// 由 `BulwarkLogicDefault` 的 impl 覆写为：
/// 1) `UserRepository::find_by_username` 查询用户
/// 2) `PasswordHasher::verify` 校验密码
/// 3) 调用 [`SessionLogic::login`] 签发 token
///
/// # 安全约束
///
/// 用户不存在与密码错误统一返回 `InvalidParam("invalid password")`，
/// 日志和事件 reason 统一为 "invalid_credentials"（v0.4.2 安全审计 A-014），
/// 防止攻击者通过返回值或日志差异进行用户枚举。
#[async_trait]
pub trait PasswordLogic: SessionLogic {
    /// 密码登录：校验密码后签发 token。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用（作为 username 字符串查询 `UserRepository`）。
    /// - `password`: 明文密码（仅校验时临时持有，不存储）。
    ///
    /// # 返回
    /// - `Ok(token)`: 密码校验通过，返回新签发的 token 字符串。
    ///
    /// # 错误
    /// - 未启用 `secure-password` + `db-sqlite` feature：`BulwarkError::NotImplemented`。
    /// - 未注入 `password_hasher`：`BulwarkError::Config("password hasher not configured")`。
    /// - 未注入 `user_repository`：`BulwarkError::Config("user repository not configured")`。
    /// - 用户不存在 / 密码错误：`BulwarkError::InvalidParam("invalid password")`
    ///   （不泄露具体原因，防止用户枚举）。
    /// - 哈希格式不支持：`BulwarkError::InvalidParam("unsupported hash format")`。
    /// - DAO 查询失败：透传 `BulwarkError::Dao`。
    async fn login_with_password(
        &self,
        _login_id: &LoginId,
        _password: &str,
    ) -> BulwarkResult<String> {
        Err(BulwarkError::NotImplemented(
            "login_with_password 未实现：需启用 secure-password + db-sqlite feature".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BulwarkConfig;
    use crate::error::BulwarkResult;
    use crate::stp::core::BulwarkCore;
    use crate::stp::login_id::LoginId;
    use crate::stp::session::SessionLogic;
    use std::sync::Arc;

    /// 最小 mock：实现 `BulwarkCore` + `SessionLogic`（9 必需方法）。
    /// `PasswordLogic` 1 个方法有默认实现，空 impl 即可获得默认行为。
    struct MockPassword {
        config: Arc<BulwarkConfig>,
    }

    impl BulwarkCore for MockPassword {
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockPassword {
        async fn login(&self, _login_id: &LoginId) -> BulwarkResult<String> {
            Ok("mock-token".to_string())
        }
        async fn login_with_token(&self, _login_id: &LoginId, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout(&self) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout_by_login_id(&self, _login_id: &LoginId) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout(&self, _login_id: &LoginId) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout_by_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn revoke_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> BulwarkResult<bool> {
            Ok(true)
        }
        async fn get_login_id(&self) -> BulwarkResult<Option<LoginId>> {
            Ok(Some(LoginId::Numeric(42)))
        }
    }

    #[async_trait]
    impl PasswordLogic for MockPassword {}

    #[tokio::test]
    async fn login_with_password_default_returns_not_implemented() {
        let mock = MockPassword {
            config: Arc::new(BulwarkConfig::default()),
        };
        let id = LoginId::String("alice".to_string());
        let result = mock.login_with_password(&id, "secret").await;
        assert!(matches!(result, Err(BulwarkError::NotImplemented(_))));
    }
}
