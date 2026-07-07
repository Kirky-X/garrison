//! TokenLogic trait — Token 类型校验与刷新契约。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 从 v0.5.2 起，从 `BulwarkLogic` 上帝 trait 拆分；本 trait 承接 token 类型校验、
//! 显式 token 验证、token 刷新 5 个方法。super-trait 为 [`SessionLogic`]
//! （token 校验依赖会话状态，默认实现委托 [`check_login`](SessionLogic::check_login)）。
//!
//! # 返回类型迁移
//!
//! `verify_token()` 返回类型从 `BulwarkResult<i64>` 迁移为 `BulwarkResult<String>`
//! （v0.5.2 LoginId 迁移：删除 LoginId newtype，全栈使用 String/&str）。

use crate::error::{BulwarkError, BulwarkResult};
use crate::stp::session::SessionLogic;
use async_trait::async_trait;

/// Token 逻辑 trait，定义 token 类型校验、显式验证与刷新契约。
///
/// [借鉴 Sa-Token] 对应 `StpLogic` 的 token 类型区分与 `getTokenValue` 校验部分。
///
/// # 默认实现
///
/// - [`check_access_token`](Self::check_access_token) /
///   [`check_client_token`](Self::check_client_token) /
///   [`check_temp_token`](Self::check_temp_token)：委托
///   [`SessionLogic::check_login`]，已登录返回 `Ok(())`，未登录返回 `Err(NotLogin)`。
///   业务方可在子类 override 实现类型区分（如校验 token 是否为 access_token 类型）。
/// - [`verify_token`](Self::verify_token) /
///   [`refresh_token`](Self::refresh_token)：默认返回 `NotImplemented`，
///   由 `BulwarkLogicDefault` 的 impl 覆写为委托 `core-token::Token::verify` /
///   `JwtHandler::refresh`。
#[async_trait]
pub trait TokenLogic: SessionLogic {
    /// 校验 access_token 类型会话（0.5.0 新增，依据 spec annotation-macros P2 前置）。
    ///
    /// 语义别名：默认实现委托 [`check_login`](SessionLogic::check_login)，
    /// 已登录返回 `Ok(())`，未登录返回 `Err(NotLogin)`。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - 未登录：`BulwarkError::NotLogin`。
    async fn check_access_token(&self) -> BulwarkResult<()> {
        let valid = self.check_login().await?;
        if valid {
            Ok(())
        } else {
            Err(BulwarkError::NotLogin(
                "access_token 无效或未登录".to_string(),
            ))
        }
    }

    /// 校验 client_token 类型会话（0.5.0 新增，依据 spec annotation-macros P2 前置）。
    ///
    /// 语义别名：默认实现委托 [`check_login`](SessionLogic::check_login)。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - 未登录：`BulwarkError::NotLogin`。
    async fn check_client_token(&self) -> BulwarkResult<()> {
        let valid = self.check_login().await?;
        if valid {
            Ok(())
        } else {
            Err(BulwarkError::NotLogin(
                "client_token 无效或未登录".to_string(),
            ))
        }
    }

    /// 校验 temp_token 类型会话（0.5.0 新增，依据 spec annotation-macros P2 前置）。
    ///
    /// 语义别名：默认实现委托 [`check_login`](SessionLogic::check_login)。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - 未登录：`BulwarkError::NotLogin`。
    async fn check_temp_token(&self) -> BulwarkResult<()> {
        let valid = self.check_login().await?;
        if valid {
            Ok(())
        } else {
            Err(BulwarkError::NotLogin(
                "temp_token 无效或未登录".to_string(),
            ))
        }
    }

    /// 验证显式传入的 token 并返回关联的 `String`（0.2.0 新增，依据 spec core-auth-api）。
    ///
    /// 委托 `core-token::Token::verify` 实现。与
    /// [`check_login`](SessionLogic::check_login) 区别：
    /// `check_login` 从 task_local 读取 token；`verify_token` 接收显式 token 参数。
    ///
    /// # 参数
    /// - `token`: 待验证的 token 字符串。
    ///
    /// # 返回
    /// - `Ok(login_id)`: token 有效，返回关联的 `String`。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidToken`: token 无效或不包含 login_id。
    /// - `BulwarkError::NotImplemented`: 默认实现未委托 Token trait。
    async fn verify_token(&self, _token: &str) -> BulwarkResult<String> {
        Err(BulwarkError::NotImplemented(
            "verify_token 需子类 override 委托 core-token::Token::verify".to_string(),
        ))
    }

    /// 刷新 token（0.2.0 新增，依据 spec core-auth-api）。
    ///
    /// 仅在启用 `protocol-jwt` feature 时由 `JwtHandler` 提供有效实现。
    ///
    /// # 参数
    /// - `token`: 待刷新的旧 token 字符串。
    ///
    /// # 返回
    /// - `Ok(new_token)`: 刷新后的新 token 字符串。
    ///
    /// # 错误
    /// - `BulwarkError::NotImplemented`: 未启用 protocol-jwt feature。
    /// - `BulwarkError::InvalidToken`: token 已过期或无效。
    async fn refresh_token(&self, _token: &str) -> BulwarkResult<String> {
        Err(BulwarkError::NotImplemented(
            "refresh_token 需启用 protocol-jwt feature".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BulwarkConfig;
    use crate::error::BulwarkResult;
    use crate::stp::core::BulwarkCore;
    use crate::stp::session::SessionLogic;
    use std::sync::Arc;

    /// 最小 mock：实现 `BulwarkCore` + `SessionLogic`（9 必需方法）。
    /// `TokenLogic` 5 个方法均有默认实现，空 impl 即可获得全部默认行为。
    struct MockToken {
        config: Arc<BulwarkConfig>,
        logged_in: bool,
    }

    impl BulwarkCore for MockToken {
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockToken {
        async fn login(&self, _login_id: &str) -> BulwarkResult<String> {
            Ok("mock-token".to_string())
        }
        async fn login_with_token(&self, _login_id: &str, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout(&self) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout_by_login_id(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout_by_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn revoke_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> BulwarkResult<bool> {
            Ok(self.logged_in)
        }
        async fn get_login_id(&self) -> BulwarkResult<Option<String>> {
            if self.logged_in {
                Ok(Some("42".to_string()))
            } else {
                Ok(None)
            }
        }
    }

    #[async_trait]
    impl TokenLogic for MockToken {}

    #[tokio::test]
    async fn check_access_token_ok_when_logged_in() {
        let mock = MockToken {
            config: Arc::new(BulwarkConfig::default()),
            logged_in: true,
        };
        mock.check_access_token().await.unwrap();
    }

    #[tokio::test]
    async fn check_access_token_denies_when_not_logged_in() {
        let mock = MockToken {
            config: Arc::new(BulwarkConfig::default()),
            logged_in: false,
        };
        let result = mock.check_access_token().await;
        assert!(matches!(result, Err(BulwarkError::NotLogin(_))));
    }

    #[tokio::test]
    async fn verify_token_default_returns_not_implemented() {
        let mock = MockToken {
            config: Arc::new(BulwarkConfig::default()),
            logged_in: true,
        };
        let result = mock.verify_token("some-token").await;
        assert!(matches!(result, Err(BulwarkError::NotImplemented(_))));
    }

    #[tokio::test]
    async fn refresh_token_default_returns_not_implemented() {
        let mock = MockToken {
            config: Arc::new(BulwarkConfig::default()),
            logged_in: true,
        };
        let result = mock.refresh_token("old").await;
        assert!(matches!(result, Err(BulwarkError::NotImplemented(_))));
    }
}
