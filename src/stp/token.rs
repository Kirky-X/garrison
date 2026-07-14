//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! TokenLogic trait — Token 类型校验与刷新契约。
//! 从 v0.5.2 起，从 `BulwarkLogic` 上帝 trait 拆分；本 trait 承接 token 类型校验、
//! 显式 token 验证、token 刷新 5 个方法。super-trait 为 [`SessionLogic`]
//! （token 校验依赖会话状态，默认实现委托 [`check_login`](SessionLogic::check_login)）。
//!
//! # 返回类型迁移
//!
//! `verify_token()` 返回类型从 `BulwarkResult<i64>` 迁移为 `BulwarkResult<String>`
//! （v0.5.2 LoginId 迁移：删除 LoginId newtype，全栈使用 String/&str）。

use super::BulwarkLogicDefault;
use crate::core::token::TokenStyleFactory;
use crate::error::{BulwarkError, BulwarkResult};
#[cfg(feature = "listener")]
use crate::listener::BulwarkEvent;
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
    /// 校验 access_token 类型会话。
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

    /// 校验 client_token 类型会话。
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

    /// 校验 temp_token 类型会话。
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

    /// 验证显式传入的 token 并返回关联的 `String`。
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

    /// 刷新 token。
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

// ============================================================================
// BulwarkLogicDefault impl
// ============================================================================

#[async_trait]
impl TokenLogic for BulwarkLogicDefault {
    async fn verify_token(&self, token: &str) -> BulwarkResult<String> {
        // 委托 core-token::Token::verify
        // spec: "不泄露 token 具体失效原因（统一 InvalidToken）"
        let token_handler =
            TokenStyleFactory::new(&self.config.token_style, &self.config.jwt_secret)?;
        match token_handler.verify(token) {
            Ok(Some(login_id)) => Ok(login_id),
            Ok(None) => Err(BulwarkError::InvalidToken(
                "token 无效或不包含 login_id".to_string(),
            )),
            Err(_) => Err(BulwarkError::InvalidToken("token 无效".to_string())),
        }
    }

    #[cfg(feature = "protocol-jwt")]
    async fn refresh_token(&self, token: &str) -> BulwarkResult<String> {
        // 启用 protocol-jwt 时委托 JwtHandler::refresh
        if self.config.token_style != "jwt" {
            return Err(BulwarkError::NotImplemented(
                "refresh_token 仅在 token_style=jwt 时可用".to_string(),
            ));
        }
        // 获取 login_id（用于 plugin/listener 回调）
        let login_id = self.verify_token(token).await?;
        let handler = crate::protocol::jwt::JwtHandler::new(&self.config.jwt_secret);
        let new_token = handler.refresh(token, self.config.timeout)?;
        // auto-wire: 触发 plugin on_login（新 token）
        if let Some(pm) = &self.plugin_manager {
            pm.on_login(&login_id, &new_token);
        }
        // 广播 TokenRefresh 事件（替换原 Login 事件）
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::TokenRefresh {
                login_id,
                old_token: token.to_string(),
                new_token: new_token.clone(),
                request_context: None,
            })
            .await;
        }
        Ok(new_token)
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
        async fn login(
            &self,
            _login_id: &str,
            _params: &crate::stp::LoginParams,
        ) -> BulwarkResult<String> {
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

    /// 验证 `check_client_token` 在已登录时返回 Ok(())。
    ///
    /// 覆盖 trait 默认实现 `check_client_token` 的 Ok 分支（token.rs 第 69-78 行）。
    #[tokio::test]
    async fn check_client_token_ok_when_logged_in() {
        let mock = MockToken {
            config: Arc::new(BulwarkConfig::default()),
            logged_in: true,
        };
        mock.check_client_token().await.unwrap();
    }

    /// 验证 `check_client_token` 在未登录时返回 Err(NotLogin)。
    ///
    /// 覆盖 trait 默认实现 `check_client_token` 的 Err 分支。
    #[tokio::test]
    async fn check_client_token_denies_when_not_logged_in() {
        let mock = MockToken {
            config: Arc::new(BulwarkConfig::default()),
            logged_in: false,
        };
        let result = mock.check_client_token().await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(ref msg)) if msg.contains("client_token")),
            "未登录时应返回 NotLogin 包含 'client_token'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_temp_token` 在已登录时返回 Ok(())。
    ///
    /// 覆盖 trait 默认实现 `check_temp_token` 的 Ok 分支（token.rs 第 89-98 行）。
    #[tokio::test]
    async fn check_temp_token_ok_when_logged_in() {
        let mock = MockToken {
            config: Arc::new(BulwarkConfig::default()),
            logged_in: true,
        };
        mock.check_temp_token().await.unwrap();
    }

    /// 验证 `check_temp_token` 在未登录时返回 Err(NotLogin)。
    ///
    /// 覆盖 trait 默认实现 `check_temp_token` 的 Err 分支。
    #[tokio::test]
    async fn check_temp_token_denies_when_not_logged_in() {
        let mock = MockToken {
            config: Arc::new(BulwarkConfig::default()),
            logged_in: false,
        };
        let result = mock.check_temp_token().await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(ref msg)) if msg.contains("temp_token")),
            "未登录时应返回 NotLogin 包含 'temp_token'，实际: {:?}",
            result
        );
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

    // ========================================================================
    // BulwarkLogicDefault impl 覆盖测试（verify_token / refresh_token）
    // ========================================================================

    mod default_impl_coverage {
        use super::*;
        use crate::dao::BulwarkDao;
        use crate::session::BulwarkSession;
        use crate::stp::mock::{MockDao, MockFirewall};
        use crate::strategy::BulwarkPermissionStrategy;
        use std::sync::Arc;

        /// 构造 BulwarkLogicDefault，token_style 可配置。
        fn make_logic(token_style: &str) -> BulwarkLogicDefault {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = token_style.to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            BulwarkLogicDefault::new(session, Arc::new(config), firewall)
        }

        /// verify_token + simple token_style → 返回 login_id。
        ///
        /// 覆盖 token.rs 第 147-159 行 BulwarkLogicDefault::verify_token 的
        /// `Ok(Some(login_id))` 分支。
        ///
        /// 注意：SimpleTokenStyle::verify 使用 `split_once('-')` 在首个 `-` 处分割，
        /// 因此 login_id 不能包含 `-`（否则只会提取首个 `-` 前的部分）。
        #[tokio::test]
        async fn verify_token_simple_style_returns_login_id() {
            let logic = make_logic("simple");
            // simple 格式: <login_id>-<uuid>，login_id 不含 `-`
            let token = format!("verifyuser-{}", uuid::Uuid::new_v4());
            let result = logic.verify_token(&token).await;
            assert!(
                result.is_ok(),
                "simple token verify_token 应返回 Ok，实际: {:?}",
                result
            );
            assert_eq!(
                result.unwrap(),
                "verifyuser",
                "verify_token 应提取 login_id 'verifyuser'"
            );
        }

        /// verify_token + uuid token_style → 返回 InvalidToken（UUID 无法编码 login_id）。
        ///
        /// 覆盖 token.rs 第 154-156 行 `Ok(None)` → `Err(InvalidToken)` 分支。
        #[tokio::test]
        async fn verify_token_uuid_style_returns_invalid_token() {
            let logic = make_logic("uuid");
            let result = logic.verify_token("some-uuid-token").await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidToken(ref msg)) if msg.contains("不包含 login_id")),
                "uuid token verify_token 应返回 InvalidToken 包含 '不包含 login_id'，实际: {:?}",
                result
            );
        }

        /// verify_token + 无效 simple token（无连字符）→ 返回 InvalidToken。
        ///
        /// 覆盖 token.rs 第 157 行 `Err(_) => Err(InvalidToken)` 分支。
        ///
        /// 注意：SimpleTokenStyle::parse 在无 `-` 时返回 Err，
        /// 但 verify 使用 split_once 返回 Ok(None) → InvalidToken。
        #[tokio::test]
        async fn verify_token_invalid_simple_token_returns_invalid_token() {
            let logic = make_logic("simple");
            // 无连字符的 simple token：split_once('-') 返回 None → Ok(None) → InvalidToken
            let result = logic.verify_token("nodashtoken").await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidToken(_))),
                "无效 simple token 应返回 InvalidToken，实际: {:?}",
                result
            );
        }

        /// verify_token + JWT token → 返回 login_id。
        ///
        /// 覆盖 token.rs 第 153 行 `Ok(Some(login_id))` 分支（JWT 路径）。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn verify_token_jwt_style_returns_login_id() {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.jwt_secret = "verify-jwt-secret".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

            // 签发 JWT token
            let handler = crate::protocol::jwt::JwtHandler::new("verify-jwt-secret");
            let jwt_token = handler.sign("jwt-verify-user", 3600).unwrap();

            let result = logic.verify_token(&jwt_token).await;
            assert!(
                result.is_ok(),
                "JWT token verify_token 应返回 Ok，实际: {:?}",
                result
            );
            assert_eq!(
                result.unwrap(),
                "jwt-verify-user",
                "verify_token 应提取 login_id 'jwt-verify-user'"
            );
        }

        /// verify_token + 无效 JWT → 返回 InvalidToken。
        ///
        /// 覆盖 token.rs 第 157 行 `Err(_) => Err(InvalidToken("token 无效"))` 分支。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn verify_token_invalid_jwt_returns_invalid_token() {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.jwt_secret = "verify-jwt-secret".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

            let result = logic.verify_token("invalid.jwt.token").await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidToken(_))),
                "无效 JWT 应返回 InvalidToken，实际: {:?}",
                result
            );
        }

        /// refresh_token + 非 JWT token_style → 返回 NotImplemented。
        ///
        /// 覆盖 token.rs 第 164-168 行 `token_style != "jwt"` → NotImplemented 分支。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn refresh_token_non_jwt_style_returns_not_implemented() {
            let logic = make_logic("uuid");
            let result = logic.refresh_token("any-token").await;
            assert!(
                matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("jwt")),
                "非 JWT token_style refresh_token 应返回 NotImplemented 包含 'jwt'，实际: {:?}",
                result
            );
        }

        /// refresh_token + JWT token_style + 有效 token → 返回新 token。
        ///
        /// 覆盖 token.rs 第 162-189 行 refresh_token 成功路径。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn refresh_token_jwt_valid_returns_new_token() {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.jwt_secret = "refresh-jwt-secret".to_string();
            config.timeout = 3600;
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

            // 签发 JWT token
            let handler = crate::protocol::jwt::JwtHandler::new("refresh-jwt-secret");
            let old_token = handler.sign("refresh-user", 3600).unwrap();

            let result = logic.refresh_token(&old_token).await;
            assert!(
                result.is_ok(),
                "JWT refresh_token 应返回 Ok，实际: {:?}",
                result
            );
            let new_token = result.unwrap();
            assert_ne!(
                new_token, old_token,
                "refresh_token 应返回新 token，与旧 token 不同"
            );
        }

        /// refresh_token + 无效 JWT → 返回错误（verify_token 失败）。
        ///
        /// 覆盖 token.rs 第 170 行 `let login_id = self.verify_token(token).await?` 错误传播。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn refresh_token_invalid_jwt_returns_error() {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.jwt_secret = "refresh-jwt-secret".to_string();
            config.timeout = 3600;
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

            let result = logic.refresh_token("invalid.jwt.token").await;
            assert!(
                result.is_err(),
                "无效 JWT refresh_token 应返回 Err，实际: {:?}",
                result
            );
        }
    }
}
