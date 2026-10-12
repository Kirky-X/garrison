// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! TokenLogic trait — Token 类型校验与刷新契约。
//! super-trait 为 [`SessionLogic`]（token 校验依赖会话状态）；`verify_token()` 返回 `GarrisonResult<String>`（LoginId 形式，全栈 String/&str）。

use super::GarrisonLogicDefault;
use crate::core::token::TokenStyleFactory;
use crate::error::{GarrisonError, GarrisonResult};
use crate::loc;
// GarrisonEvent 仅在 refresh_token（protocol-jwt）中使用，故 import 门控 listener + protocol-jwt，避免 unused import 警告
#[cfg(all(feature = "listener", feature = "protocol-jwt"))]
use crate::listener::GarrisonEvent;
use crate::stp::session::SessionLogic;
use async_trait::async_trait;

/// 统一三个 check_*_token 默认实现的语义：委托 [`SessionLogic::check_login`]，未登录统一返回 `NotLogin`（不区分 token 类型，防类型信息泄露）。
async fn ensure_valid_token_session(session: &dyn SessionLogic) -> GarrisonResult<()> {
    let valid = session.check_login().await?;
    if valid {
        Ok(())
    } else {
        Err(GarrisonError::NotLogin(
            "stp-token-invalid-or-not-login::".to_string(),
        ))
    }
}

#[async_trait]
/// Token 类型校验、显式验证与刷新契约（对应 `StpLogic` 的 token 类型区分与 `getTokenValue` 校验部分）。
/// 类型校验默认委托 [`SessionLogic::check_login`]；`verify_token` / `refresh_token` 默认 `NotImplemented`，由 `GarrisonLogicDefault` 覆写。
pub trait TokenLogic: SessionLogic {
    /// 校验 access_token 类型会话：默认委托 [`check_login`](SessionLogic::check_login)，未登录返回 `NotLogin`。
    async fn check_access_token(&self) -> GarrisonResult<()>
    where
        Self: Sized,
    {
        ensure_valid_token_session(self).await
    }
    /// 校验 client_token 类型会话：默认委托 [`check_login`](SessionLogic::check_login)，未登录返回 `NotLogin`。
    async fn check_client_token(&self) -> GarrisonResult<()>
    where
        Self: Sized,
    {
        ensure_valid_token_session(self).await
    }

    /// 校验 temp_token 类型会话：默认委托 [`check_login`](SessionLogic::check_login)，未登录返回 `NotLogin`。
    async fn check_temp_token(&self) -> GarrisonResult<()>
    where
        Self: Sized,
    {
        ensure_valid_token_session(self).await
    }

    /// 验证显式传入的 token 并返回关联 login_id：与 [`check_login`](SessionLogic::check_login) 不同，token 由参数传入而非 task_local。
    /// 默认返回 `NotImplemented`（`GarrisonLogicDefault` 覆写为委托 `core-token::Token::verify`）；token 无效返回 `InvalidToken`。
    async fn verify_token(&self, _token: &str) -> GarrisonResult<String> {
        Err(GarrisonError::NotImplemented(loc!(
            "stp-verify-token-not-implemented",
            ""
        )))
    }

    /// 刷新 token，仅在 `protocol-jwt` 下由 `JwtHandler` 提供有效实现；默认返回 `NotImplemented`，token 过期/无效返回 `InvalidToken`。
    async fn refresh_token(&self, _token: &str) -> GarrisonResult<String> {
        Err(GarrisonError::NotImplemented(loc!(
            "stp-refresh-token-not-implemented",
            ""
        )))
    }
}

// GarrisonLogicDefault impl

#[async_trait]
impl TokenLogic for GarrisonLogicDefault {
    async fn verify_token(&self, token: &str) -> GarrisonResult<String> {
        // 不泄露 token 具体失效原因：所有失败统一映射 InvalidToken
        let token_handler = TokenStyleFactory::new_with_jwt_keys(
            &self.config.token_style,
            self.config.jwt_secret.as_str(),
            Some(&self.config.jwt_algorithm),
            self.config.jwt_rsa_private_key_pem.as_deref(),
            self.config.jwt_ec_private_key_pem.as_deref(),
            self.config.jwt_ed_private_key_pem.as_deref(),
        )?;
        match token_handler.verify(token) {
            Ok(Some(login_id)) => Ok(login_id),
            Ok(None) => Err(GarrisonError::InvalidToken(
                "stp-token-invalid-or-no-login-id::".to_string(),
            )),
            Err(_) => Err(GarrisonError::InvalidToken(
                "stp-token-invalid::".to_string(),
            )),
        }
    }

    #[cfg(feature = "protocol-jwt")]
    async fn refresh_token(&self, token: &str) -> GarrisonResult<String> {
        if self.config.token_style != "jwt" {
            return Err(GarrisonError::NotImplemented(loc!(
                "stp-refresh-token-jwt-only",
                ""
            )));
        }
        // 获取 login_id（用于 plugin/listener 回调）
        let login_id = self.verify_token(token).await?;
        let handler = crate::protocol::jwt::JwtHandler::from_algorithm_parts(
            &self.config.jwt_algorithm,
            self.config.jwt_secret.as_str(),
            self.config.jwt_rsa_private_key_pem.as_deref(),
            self.config.jwt_ec_private_key_pem.as_deref(),
            self.config.jwt_ed_private_key_pem.as_deref(),
        )?;
        // 黑名单前置检查：verify 只验签名+exp 不读黑名单，不拦截则已 logout/revoke 的旧 token 在自然过期前仍可 refresh 铸出新 jti 新 token，整体绕过吊销。
        if self.config.enable_jwt_revocation {
            if let Ok(claims) = handler.verify(token) {
                if let Some(jti) = &claims.jti {
                    let key = format!("jwt:blacklist:{}", jti);
                    let revoked = self.session.dao().get(&key).await?;
                    if revoked.is_some() {
                        return Err(GarrisonError::InvalidToken(
                            "stp-refresh-token-revoked::".to_string(),
                        ));
                    }
                }
            }
        }
        let new_token = handler.refresh(token, self.config.timeout)?;
        // 签发新 token 后将旧 jti 写入黑名单，消除新旧双重有效窗口（写失败仅 warn 不阻断）；带泄露重用检测的完整轮换走 RefreshTokenRotation 路径。
        self.blacklist_jwt_jti(token).await;
        // 触发 plugin on_login（新 token）
        if let Some(pm) = &self.plugin_manager {
            pm.on_login(&login_id, &new_token);
        }
        // 广播 TokenRefresh 事件（替换原 Login 事件），字段携掩码 token（经 listener::mask_token_for_event），避免明文 token 进日志。
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&GarrisonEvent::TokenRefresh {
                login_id,
                old_token: crate::listener::mask_token_for_event(token),
                new_token: crate::listener::mask_token_for_event(&new_token),
                request_context: None,
            })
            .await;
        }
        Ok(new_token)
    }
}

#[cfg(test)]
mod tests {
    // protocol-zeroize 下 jwt_secret 字段为 Zeroizing<String>，关闭时退化为 String；`.into()` 是跨 feature 兼容的必要转换，被 clippy 误报。
    #![allow(clippy::useless_conversion)]
    use super::*;
    use crate::config::GarrisonConfig;
    use crate::error::GarrisonResult;
    use crate::stp::core::GarrisonCore;
    use crate::stp::session::SessionLogic;
    use std::sync::Arc;

    /// 最小 mock：实现 `GarrisonCore` + `SessionLogic`；`TokenLogic` 5 个方法均有默认实现，空 impl 即可。
    struct MockToken {
        config: Arc<GarrisonConfig>,
        logged_in: bool,
    }

    impl GarrisonCore for MockToken {
        fn config(&self) -> Arc<GarrisonConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockToken {
        async fn login(
            &self,
            _login_id: &str,
            _params: &crate::stp::LoginParams,
        ) -> GarrisonResult<String> {
            Ok("mock-token".to_string())
        }
        async fn login_with_token(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn logout(&self) -> GarrisonResult<()> {
            Ok(())
        }
        async fn logout_by_login_id(&self, _login_id: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn kickout(&self, _login_id: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn kickout_by_token(&self, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn revoke_token(&self, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> GarrisonResult<bool> {
            Ok(self.logged_in)
        }
        async fn get_login_id(&self) -> GarrisonResult<Option<String>> {
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
            config: Arc::new(GarrisonConfig::default()),
            logged_in: true,
        };
        mock.check_access_token().await.unwrap();
    }

    #[tokio::test]
    async fn check_access_token_denies_when_not_logged_in() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: false,
        };
        let result = mock.check_access_token().await;
        assert!(matches!(result, Err(GarrisonError::NotLogin(_))));
    }

    /// 验证 `check_client_token` 在已登录时返回 Ok(())（覆盖默认实现 Ok 分支）。
    #[tokio::test]
    async fn check_client_token_ok_when_logged_in() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: true,
        };
        mock.check_client_token().await.unwrap();
    }

    /// 验证 `check_client_token` 在未登录时返回 Err(NotLogin)（覆盖默认实现 Err 分支）。
    #[tokio::test]
    async fn check_client_token_denies_when_not_logged_in() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: false,
        };
        let result = mock.check_client_token().await;
        assert!(
            matches!(result, Err(GarrisonError::NotLogin(ref msg)) if msg.contains("stp-token-invalid-or-not-login")),
            "未登录时应返回 NotLogin 包含 'client_token'，实际: {:?}",
            result
        );
    }

    /// 验证 `check_temp_token` 在已登录时返回 Ok(())（覆盖默认实现 Ok 分支）。
    #[tokio::test]
    async fn check_temp_token_ok_when_logged_in() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: true,
        };
        mock.check_temp_token().await.unwrap();
    }

    /// 验证 `check_temp_token` 在未登录时返回 Err(NotLogin)（覆盖默认实现 Err 分支）。
    #[tokio::test]
    async fn check_temp_token_denies_when_not_logged_in() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: false,
        };
        let result = mock.check_temp_token().await;
        assert!(
            matches!(result, Err(GarrisonError::NotLogin(ref msg)) if msg.contains("stp-token-invalid-or-not-login")),
            "未登录时应返回 NotLogin 包含 'temp_token'，实际: {:?}",
            result
        );
    }

    /// 共享辅助函数：已登录返回 `Ok(())`，未登录统一返回 `NotLogin`（不区分 token 类型，防类型信息泄露）；三个 check_*_token 均委托它。
    #[tokio::test]
    async fn ensure_valid_token_session_helper_ok_when_logged_in() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: true,
        };
        ensure_valid_token_session(&mock).await.unwrap();
    }

    /// 验证共享辅助函数在未登录时返回统一 `NotLogin` 错误。
    #[tokio::test]
    async fn ensure_valid_token_session_helper_denies_when_not_logged_in() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: false,
        };
        let result = ensure_valid_token_session(&mock).await;
        assert!(
            matches!(result, Err(GarrisonError::NotLogin(ref msg)) if msg.contains("stp-token-invalid-or-not-login")),
            "未登录时应返回 NotLogin 统一错误，实际: {:?}",
            result
        );
    }

    /// 三个 token 类型校验默认实现的错误消息完全一致（不泄露具体 token 类型）。
    #[tokio::test]
    async fn all_token_type_checks_share_identical_error_semantics() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: false,
        };
        let access = mock.check_access_token().await;
        let client = mock.check_client_token().await;
        let temp = mock.check_temp_token().await;
        for result in [access, client, temp] {
            let msg = result.expect_err("未登录时应返回 Err");
            // 通过模式匹配提取内部消息（Debug 已脱敏，不直接输出内部 key）
            let inner = match &msg {
                GarrisonError::NotLogin(s) => s.clone(),
                other => format!("{:?}", other),
            };
            assert!(
                inner.contains("stp-token-invalid-or-not-login"),
                "token 类型校验错误消息应统一包含 stp-token-invalid-or-not-login，实际: {}",
                inner
            );
        }
    }

    #[tokio::test]
    async fn verify_token_default_returns_not_implemented() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: true,
        };
        let result = mock.verify_token("some-token").await;
        assert!(matches!(result, Err(GarrisonError::NotImplemented(_))));
    }

    #[tokio::test]
    async fn refresh_token_default_returns_not_implemented() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: true,
        };
        let result = mock.refresh_token("old").await;
        assert!(matches!(result, Err(GarrisonError::NotImplemented(_))));
    }

    // MockToken SessionLogic 方法覆盖测试

    /// MockToken::login 返回 "mock-token"。
    #[tokio::test]
    async fn mock_token_login_returns_token() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: false,
        };
        let token = mock
            .login("alice", &crate::stp::LoginParams::default())
            .await
            .unwrap();
        assert_eq!(token, "mock-token");
    }

    /// MockToken::login_with_token / logout / logout_by_login_id / kickout /
    /// kickout_by_token / revoke_token 均返回 Ok(())。
    #[tokio::test]
    async fn mock_token_session_methods_return_ok() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: true,
        };
        mock.login_with_token("alice", "tok").await.unwrap();
        mock.logout().await.unwrap();
        mock.logout_by_login_id("alice").await.unwrap();
        mock.kickout("alice").await.unwrap();
        mock.kickout_by_token("tok").await.unwrap();
        mock.revoke_token("tok").await.unwrap();
    }

    /// MockToken::config 返回内部 config 的 Arc clone。
    #[tokio::test]
    async fn mock_token_config_returns_arc_clone() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: true,
        };
        let c1 = mock.config();
        let c2 = mock.config();
        assert!(Arc::ptr_eq(&c1, &c2), "两次 config() 应返回同一 Arc");
    }

    /// MockToken::get_login_id 在 logged_in=true 时返回 Some("42")。
    #[tokio::test]
    async fn mock_token_get_login_id_when_logged_in() {
        let mock = MockToken {
            config: Arc::new(GarrisonConfig::default()),
            logged_in: true,
        };
        let id = mock.get_login_id().await.unwrap();
        assert_eq!(id.as_deref(), Some("42"));
    }

    // GarrisonLogicDefault impl 覆盖测试（verify_token / refresh_token）

    mod default_impl_coverage {
        use super::*;
        use crate::dao::GarrisonDao;
        use crate::session::GarrisonSession;
        use crate::stp::mock::{MockDao, MockFirewall};
        use crate::strategy::GarrisonPermissionStrategy;
        use std::sync::Arc;

        ///simple 模式测试用的 HMAC 密钥（与 make_logic 中设置的 jwt_secret 一致）。
        const STP_TOKEN_SIMPLE_TEST_SECRET: &str = "stp-token-simple-test-secret-0123456789";

        ///构造测试用 JwtSecret（兼容 protocol-zeroize 启用/禁用两种配置）。
        fn test_jwt_secret(secret: &str) -> crate::config::JwtSecret {
            #[cfg(feature = "protocol-zeroize")]
            {
                secret.to_string().into()
            }
            #[cfg(not(feature = "protocol-zeroize"))]
            {
                secret.to_string()
            }
        }

        /// 构造 GarrisonLogicDefault，token_style 可配置。
        fn make_logic(token_style: &str) -> GarrisonLogicDefault {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = token_style.to_string();
            // simple 模式 verify_token 委托 core-token SimpleTokenStyle（需 HMAC），设置非空 jwt_secret 避免 fail-closed。
            if token_style == "simple" {
                config.jwt_secret = test_jwt_secret(STP_TOKEN_SIMPLE_TEST_SECRET);
            }
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            GarrisonLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
                Arc::new(crate::account::disable::DefaultDisableRepository::new(
                    dao.clone(),
                )),
            )
        }

        /// verify_token + simple token_style → 返回 login_id（覆盖 `Ok(Some(login_id))` 分支）。
        /// SimpleTokenStyle 为 HMAC-SHA256 格式 `<login_id>-<uuid>.<hmac>`，需用其 generate 生成合法 token；login_id 不能含 `-`。
        #[cfg(feature = "secure-simple-token")]
        #[tokio::test]
        async fn verify_token_simple_style_returns_login_id() {
            let logic = make_logic("simple");
            let style =
                crate::core::token::SimpleTokenStyle::new(STP_TOKEN_SIMPLE_TEST_SECRET.to_string());
            let token = crate::core::token::Token::generate(&style, "verifyuser", 3600).unwrap();
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

        /// verify_token + uuid token_style → InvalidToken（UUID 无法编码 login_id，覆盖 `Ok(None)` 分支）。
        #[tokio::test]
        async fn verify_token_uuid_style_returns_invalid_token() {
            let logic = make_logic("uuid");
            let result = logic.verify_token("some-uuid-token").await;
            assert!(
                matches!(result, Err(GarrisonError::InvalidToken(ref msg)) if msg.contains("stp-token-invalid-or-no-login-id")),
                "uuid token verify_token 应返回 InvalidToken 包含 '不包含 login_id'，实际: {:?}",
                result
            );
        }

        /// verify_token + 无效 simple token（无连字符）→ InvalidToken（verify 用 split_once 返回 Ok(None)，覆盖 `Err(_)` 分支）。
        #[tokio::test]
        async fn verify_token_invalid_simple_token_returns_invalid_token() {
            let logic = make_logic("simple");
            let result = logic.verify_token("nodashtoken").await;
            assert!(
                matches!(result, Err(GarrisonError::InvalidToken(_))),
                "无效 simple token 应返回 InvalidToken，实际: {:?}",
                result
            );
        }

        /// verify_token + JWT token → 返回 login_id（覆盖 JWT 路径 `Ok(Some(login_id))` 分支）。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn verify_token_jwt_style_returns_login_id() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.jwt_secret = "verify-jwt-secret-0000000000000000".to_string().into();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
                Arc::new(crate::account::disable::DefaultDisableRepository::new(
                    dao.clone(),
                )),
            );

            let handler =
                crate::protocol::jwt::JwtHandler::new("verify-jwt-secret-0000000000000000");
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

        /// verify_token + 无效 JWT → InvalidToken（覆盖 `Err(_)` 分支）。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn verify_token_invalid_jwt_returns_invalid_token() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.jwt_secret = "verify-jwt-secret-0000000000000000".to_string().into();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
                Arc::new(crate::account::disable::DefaultDisableRepository::new(
                    dao.clone(),
                )),
            );

            let result = logic.verify_token("invalid.jwt.token").await;
            assert!(
                matches!(result, Err(GarrisonError::InvalidToken(_))),
                "无效 JWT 应返回 InvalidToken，实际: {:?}",
                result
            );
        }

        /// refresh_token + 非 JWT token_style → NotImplemented（覆盖 `token_style != "jwt"` 分支）。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn refresh_token_non_jwt_style_returns_not_implemented() {
            let logic = make_logic("uuid");
            let result = logic.refresh_token("any-token").await;
            assert!(
                matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("jwt")),
                "非 JWT token_style refresh_token 应返回 NotImplemented 包含 'jwt'，实际: {:?}",
                result
            );
        }

        /// refresh_token + JWT + 有效 token → 返回新 token（覆盖 refresh_token 成功路径）。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn refresh_token_jwt_valid_returns_new_token() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.jwt_secret = "refresh-jwt-secret-0000000000000000".to_string().into();
            config.timeout = 3600;
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
                Arc::new(crate::account::disable::DefaultDisableRepository::new(
                    dao.clone(),
                )),
            );

            let handler =
                crate::protocol::jwt::JwtHandler::new("refresh-jwt-secret-0000000000000000");
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

        /// 回归：黑名单旧 token 不得经 refresh 铸出新 token（verify 不读黑名单，无前置检查则吊销被整体绕过）。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn refresh_token_rejects_blacklisted_token() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.enable_jwt_revocation = true;
            config.jwt_secret = test_jwt_secret("jwt-refresh-revoke-secret-32bytes-x");
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
                Arc::new(crate::account::disable::DefaultDisableRepository::new(
                    dao.clone(),
                )),
            );

            let old_token = logic
                .login("user-bl", &crate::stp::LoginParams::default())
                .await
                .expect("login 应成功");

            // 模拟 logout/revoke：将旧 token 的 jti 写入黑名单
            logic.blacklist_jwt_jti(&old_token).await;

            let result = logic.refresh_token(&old_token).await;
            assert!(
                matches!(result, Err(GarrisonError::InvalidToken(ref msg)) if msg.contains("stp-refresh-token-revoked")),
                "黑名单 token refresh 应被拒，实际: {:?}",
                result
            );
        }

        /// refresh_token + 无效 JWT → verify_token 错误透传。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn refresh_token_invalid_jwt_returns_error() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.jwt_secret = "refresh-jwt-secret-0000000000000000".to_string().into();
            config.timeout = 3600;
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
                Arc::new(crate::account::disable::DefaultDisableRepository::new(
                    dao.clone(),
                )),
            );

            let result = logic.refresh_token("invalid.jwt.token").await;
            assert!(
                result.is_err(),
                "无效 JWT refresh_token 应返回 Err，实际: {:?}",
                result
            );
        }

        /// refresh_token 后旧 access token jti 入黑名单（立即失效）：Stateless JWT 无 session 可销毁，黑名单是唯一撤销手段。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn refresh_token_revokes_old_token() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.enable_jwt_revocation = true;
            config.jwt_secret = test_jwt_secret("jwt-refresh-revoke-secret-32bytes-x");
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
                Arc::new(crate::account::disable::DefaultDisableRepository::new(
                    dao.clone(),
                )),
            );

            let old_token = logic
                .login("user-refresh", &crate::stp::LoginParams::default())
                .await
                .expect("login 应成功");

            let new_token = logic
                .refresh_token(&old_token)
                .await
                .expect("refresh 应成功");
            assert_ne!(old_token, new_token);

            let handler = crate::protocol::jwt::JwtHandler::from_algorithm_parts(
                "HS256",
                test_jwt_secret("jwt-refresh-revoke-secret-32bytes-x").as_str(),
                None,
                None,
                None,
            )
            .expect("handler 构造应成功");
            let jti = handler
                .verify(&old_token)
                .expect("旧 token 签名仍可验")
                .jti
                .expect("JWT 应包含 jti");
            let key = format!("jwt:blacklist:{}", jti);
            let value = dao.get(&key).await.expect("dao get 应成功");
            assert!(value.is_some(), "refresh 后旧 token 的 jti 应被写入黑名单");
        }
    }
}
