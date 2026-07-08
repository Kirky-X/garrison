//! SessionLogic trait — 会话生命周期管理契约（登录/登出/踢出/校验）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 从 v0.5.2 起，原 `BulwarkLogic` 上帝 trait 拆分为 6 个细粒度 trait；
//! 本 trait 承接会话生命周期相关 10 个方法，super-trait 为 [`BulwarkCore`]。
//!
//! # LoginId 迁移（v0.5.2）
//!
//! 所有 `login_id: i64` 签名迁移为 `login_id: &str`（对象安全，可作 `dyn`）。
//! `BulwarkUtil` 保留 `impl Into<String>` ergonomic 入口，自动 `.into()` 后传引用。
//! `get_login_id()` 返回类型从 `Option<i64>` 迁移为 `Option<String>`。

use super::current_token;
use super::BulwarkLogicDefault;
use super::JwtMode;
use crate::error::{BulwarkError, BulwarkResult};
#[cfg(feature = "listener")]
use crate::listener::BulwarkEvent;
use crate::stp::core::BulwarkCore;
use crate::stp::token::TokenLogic;
use async_trait::async_trait;

/// 会话逻辑 trait，定义登录/登出/踢出/校验完整契约。
///
/// [借鉴 Sa-Token] 对应 `StpLogic` 的会话生命周期部分。
///
/// # 方法分组
///
/// - 登录：[`login`](Self::login) / [`login_with_token`](Self::login_with_token) /
///   [`login_by_token`](Self::login_by_token)（默认返回 `NotImplemented`）
/// - 登出：[`logout`](Self::logout) / [`logout_by_login_id`](Self::logout_by_login_id)
/// - 踢出：[`kickout`](Self::kickout) / [`kickout_by_token`](Self::kickout_by_token)
/// - 吊销：[`revoke_token`](Self::revoke_token)
/// - 校验：[`check_login`](Self::check_login) / [`get_login_id`](Self::get_login_id)
///
/// # 对象安全
///
/// 所有方法参数均为具体类型（`&str`），无泛型参数，trait 对象安全，
/// 可作 `dyn SessionLogic` 使用。`BulwarkManager` 返回 `Arc<BulwarkLogicDefault>`
/// 后，可通过 trait 方法解析调用本 trait 方法（需 `use crate::stp::SessionLogic`）。
#[async_trait]
pub trait SessionLogic: BulwarkCore {
    /// 执行登录：生成 token + 创建会话。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用（字符串形式，如 "42" / "alice" / UUID）。
    ///
    /// # 返回
    /// 生成的 token 字符串。
    ///
    /// # 错误
    /// - token 生成失败（如 `token_style` 非法）：`BulwarkError::Config`。
    /// - 会话创建失败：透传 `BulwarkError`。
    async fn login(&self, login_id: &str) -> BulwarkResult<String>;

    /// 执行登录（自定义 token）：用指定 token 创建会话。
    ///
    /// 用于 token 转发、自定义 token 生成等场景。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用。
    /// - `token`: 自定义 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话创建失败：透传 `BulwarkError`。
    async fn login_with_token(&self, login_id: &str, token: &str) -> BulwarkResult<()>;

    /// 执行登出：从 task_local 获取当前 token 并销毁。
    ///
    /// 未登录时调用幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn logout(&self) -> BulwarkResult<()>;

    /// 按账号登出：销毁指定 `login_id` 的所有会话。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn logout_by_login_id(&self, login_id: &str) -> BulwarkResult<()>;

    /// 踢出用户：按账号踢出（语义等同 [`logout_by_login_id`](Self::logout_by_login_id)）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn kickout(&self, login_id: &str) -> BulwarkResult<()>;

    /// 踢出会话：按 token 踢出（语义等同 `logout(token)`）。
    ///
    /// # 参数
    /// - `token`: 待踢出的 token 字符串。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn kickout_by_token(&self, token: &str) -> BulwarkResult<()>;

    /// 主动吊销 token：销毁指定 token 的会话并广播 `RevokeToken` 事件
    /// （v0.4.2 新增，依据 spec listener-events-extend R-002）。
    ///
    /// 与 [`logout`](Self::logout) 的区别：`logout` 从 task_local 读取当前 token
    /// （用户主动登出语义）；`revoke_token` 接收显式 token 参数（管理员/系统吊销语义）。
    ///
    /// # 参数
    /// - `token`: 待吊销的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；token 不存在时幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn revoke_token(&self, token: &str) -> BulwarkResult<()>;

    /// 检查登录状态：从 task_local 获取 token 验证有效性。
    ///
    /// # 返回
    /// - `Ok(true)`: token 有效且 Account-Session 未过期。
    /// - `Ok(false)`: token 无效或未登录（`throw_on_not_login=false`）。
    ///
    /// # 错误
    /// - 未登录且 `throw_on_not_login=true`：抛 `BulwarkError::Session`。
    /// - DAO 读取失败：透传 `BulwarkError`。
    async fn check_login(&self) -> BulwarkResult<bool>;

    /// 获取当前登录 ID。
    ///
    /// # 返回
    /// - `Some(login_id)`: token 有效，返回关联的 `login_id`（字符串形式）。
    /// - `None`: 未登录或 token 无效。
    ///
    /// # 错误
    /// - DAO 读取失败：透传 `BulwarkError`。
    async fn get_login_id(&self) -> BulwarkResult<Option<String>>;

    /// 通过外部 token 反向建立会话（0.2.0 新增，依据 spec core-auth-api）。
    ///
    /// 用于 OAuth2/SSO 场景：外部 token 已通过协议层校验后，
    /// 调用此方法在当前上下文建立内部会话。
    ///
    /// # 参数
    /// - `token`: 外部 token 字符串（如 OAuth2 access_token / SSO ticket）。
    ///
    /// # 错误
    /// - 默认实现：`BulwarkError::NotImplemented`（未启用 protocol-oauth2/protocol-sso）。
    async fn login_by_token(&self, _token: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(
            "login_by_token 需启用 protocol-oauth2 或 protocol-sso feature".to_string(),
        ))
    }
}

// ============================================================================
// BulwarkLogicDefault impl
// ============================================================================

#[async_trait]
impl SessionLogic for BulwarkLogicDefault {
    async fn login(&self, login_id: &str) -> BulwarkResult<String> {
        // emit metrics：登录尝试（成功/失败均记录，依据 spec observability-stack）
        #[cfg(feature = "metrics-prometheus")]
        let start = std::time::Instant::now();
        let result = self.login_inner(login_id).await;
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_login(result.is_ok());
            m.observe_token_validation(start.elapsed());
        }
        result
    }

    async fn login_with_token(&self, login_id: &str, token: &str) -> BulwarkResult<()> {
        self.session.create(login_id, token).await
    }

    async fn logout(&self) -> BulwarkResult<()> {
        // 未登录时幂等返回 Ok（不抛错）
        match current_token() {
            Ok(token) => {
                // 获取 login_id（用于 plugin/listener 回调），注销前查询
                let login_id = self
                    .session
                    .get_token_session(&token)
                    .await?
                    .map(|ts| ts.login_id);
                self.session.logout(&token).await?;
                // auto-wire: 触发 plugin on_logout + listener Logout 事件
                if let (Some(pm), Some(id)) = (&self.plugin_manager, login_id.as_ref()) {
                    pm.on_logout(id, &token);
                }
                #[cfg(feature = "listener")]
                if let (Some(lm), Some(id)) = (&self.listener_manager, login_id) {
                    lm.broadcast(&BulwarkEvent::Logout {
                        login_id: id,
                        token: token.clone(),
                    })
                    .await;
                }
                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    async fn logout_by_login_id(&self, login_id: &str) -> BulwarkResult<()> {
        self.session.logout_by_login_id(login_id).await
    }

    async fn kickout(&self, login_id: &str) -> BulwarkResult<()> {
        // kickout 语义等同 logout_by_login_id
        self.session.logout_by_login_id(login_id).await?;
        // auto-wire: 触发 listener Kickout 事件（plugin 无 kickout 钩子）
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::Kickout {
                login_id: login_id.to_string(),
                token: String::new(),
                reason: "管理员强制下线".to_string(),
            })
            .await;
        }
        Ok(())
    }

    async fn kickout_by_token(&self, token: &str) -> BulwarkResult<()> {
        // kickout_by_token 语义等同 logout(token)
        self.session.logout(token).await
    }

    async fn revoke_token(&self, token: &str) -> BulwarkResult<()> {
        // 销毁 Token-Session（幂等：token 不存在也返回 Ok）
        self.session.logout(token).await?;
        // v0.4.2: 广播 RevokeToken 事件（依据 spec listener-events-extend R-002）
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::RevokeToken {
                token: token.to_string(),
            })
            .await;
        }
        Ok(())
    }

    async fn check_login(&self) -> BulwarkResult<bool> {
        let token = match current_token() {
            Ok(t) => t,
            Err(_) => {
                // 未设置 token = 未登录（保持现有 throw_on_not_login 语义）
                if self.config.throw_on_not_login {
                    return Err(BulwarkError::Session("未登录".to_string()));
                }
                return Ok(false);
            },
        };

        match self.jwt_mode {
            JwtMode::Stateless => self.check_login_stateless(&token),
            JwtMode::Mixin => self.check_login_mixin(&token).await,
            JwtMode::Simple => self.check_login_simple(&token).await,
        }
    }

    async fn get_login_id(&self) -> BulwarkResult<Option<String>> {
        match current_token() {
            Ok(token) => match self.session.get_token_session(&token).await? {
                Some(ts) => Ok(Some(ts.login_id)),
                None => Ok(None),
            },
            Err(_) => Ok(None),
        }
    }

    async fn login_by_token(&self, token: &str) -> BulwarkResult<()> {
        // 获取 login_id：优先委托 auth_logic，否则使用 verify_token（TokenStyleFactory）
        let login_id = if let Some(auth) = &self.auth_logic {
            auth.verify_token(token).await?
        } else {
            self.verify_token(token).await?
        };
        // 建立内部会话（使用同一 token）
        self.session.create(&login_id, token).await?;
        // auto-wire: 触发 plugin on_login + listener Login 事件
        if let Some(pm) = &self.plugin_manager {
            pm.on_login(&login_id, token);
        }
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::Login {
                login_id,
                token: token.to_string(),
                device: None,
            })
            .await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BulwarkConfig;
    use std::sync::Arc;

    /// 最小 mock：实现 `BulwarkCore` + 9 个必需 `SessionLogic` 方法
    /// （`login_by_token` 有默认实现，无需覆写）。
    struct MockSession {
        config: Arc<BulwarkConfig>,
    }

    impl BulwarkCore for MockSession {
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockSession {
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
            Ok(true)
        }
        async fn get_login_id(&self) -> BulwarkResult<Option<String>> {
            Ok(Some("42".to_string()))
        }
    }

    /// 验证 `login` 接受 `&str`（Numeric 与 String 形式）。
    /// 调用方通过 `BulwarkUtil::login("42")` 或 `BulwarkUtil::login(42i64.to_string())`。
    #[tokio::test]
    async fn login_accepts_str_ref() {
        let mock = MockSession {
            config: Arc::new(BulwarkConfig::default()),
        };
        let t1 = mock.login("42").await.unwrap();
        let t2 = mock.login("alice").await.unwrap();
        assert_eq!(t1, "mock-token");
        assert_eq!(t2, "mock-token");
    }

    /// 验证 `login_with_token` 接受 `&str`。
    #[tokio::test]
    async fn login_with_token_accepts_str_ref() {
        let mock = MockSession {
            config: Arc::new(BulwarkConfig::default()),
        };
        mock.login_with_token("user-uuid", "tok").await.unwrap();
    }

    /// 验证 `get_login_id` 返回 `String`（v0.5.2 返回类型迁移）。
    #[tokio::test]
    async fn get_login_id_returns_string() {
        let mock = MockSession {
            config: Arc::new(BulwarkConfig::default()),
        };
        let id = mock.get_login_id().await.unwrap().unwrap();
        assert_eq!(id, "42");
    }

    /// 验证 `login_by_token` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn login_by_token_default_returns_not_implemented() {
        let mock = MockSession {
            config: Arc::new(BulwarkConfig::default()),
        };
        let result = mock.login_by_token("external").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(_))),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }
}
