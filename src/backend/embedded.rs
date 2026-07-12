//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BackendEmbedded — 进程内认证后端实现。
//!
//! 委托全局 `BulwarkManager` 单例，通过 `with_current_token` 将显式 token 参数
//! 转换为 task_local 上下文，适配 `BulwarkLogicDefault` 的子 trait 方法签名。
//!
//! # 设计
//!
//! - **零字段 struct**：BulwarkManager 使用全局单例（`BULWARK_MANAGER`），
//!   BackendEmbedded 无需持有任何引用
//! - **token 适配**：AuthBackend 方法接受显式 token 参数，
//!   BulwarkLogicDefault 方法从 task_local `CURRENT_TOKEN` 获取 token，
//!   通过 `with_current_token` 桥接两种模式
//! - **bool 适配**：`check_safe`/`check_disable` 在 BulwarkLogicDefault 中返回
//!   `Result<()>`（Ok=通过，Err=未通过），AuthBackend 要求 `Result<bool>`，
//!   适配时区分业务错误（NotSafe/DisableService）与系统错误

use crate::error::{BulwarkError, BulwarkResult};
use crate::manager::BulwarkManager;
use crate::stp::mfa::MfaLogic;
use crate::stp::permission::PermissionLogic;
use crate::stp::session::SessionLogic;
use crate::stp::with_current_token;
use async_trait::async_trait;

use super::types::{LoginParams, SessionData, TokenInfo};
use super::AuthBackend;

/// 进程内认证后端，委托全局 BulwarkManager 单例。
///
/// 通过 `BackendEmbedded::new()` 构造，可作为 `Arc<dyn AuthBackend>` 使用。
/// 所有方法通过 `BulwarkManager::logic()` 获取 `BulwarkLogicDefault`，
/// 再委托到对应的子 trait 方法。
pub struct BackendEmbedded;

impl BackendEmbedded {
    /// 创建 BackendEmbedded 实例。
    ///
    /// BulwarkManager 必须已通过 `BulwarkManager::init()` 初始化，
    /// 否则所有方法调用返回 `BulwarkError::Session`。
    pub fn new() -> Self {
        Self
    }
}

impl Default for BackendEmbedded {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthBackend for BackendEmbedded {
    async fn login(&self, login_id: &str, params: &LoginParams) -> BulwarkResult<String> {
        let logic = BulwarkManager::logic()?;
        logic.login(login_id, params).await
    }

    async fn logout(&self, token: &str) -> BulwarkResult<()> {
        let logic = BulwarkManager::logic()?;
        with_current_token(token.to_string(), async { logic.logout().await }).await
    }

    async fn check_login(&self, token: &str) -> BulwarkResult<bool> {
        let logic = BulwarkManager::logic()?;
        with_current_token(token.to_string(), async { logic.check_login().await }).await
    }

    async fn check_permission(&self, token: &str, permission: &str) -> BulwarkResult<()> {
        let logic = BulwarkManager::logic()?;
        let perm = permission.to_string();
        with_current_token(token.to_string(), async move {
            logic.check_permission(&perm).await
        })
        .await
    }

    async fn check_role(&self, token: &str, role: &str) -> BulwarkResult<()> {
        let logic = BulwarkManager::logic()?;
        let role = role.to_string();
        with_current_token(
            token.to_string(),
            async move { logic.check_role(&role).await },
        )
        .await
    }

    async fn check_safe(&self, token: &str) -> BulwarkResult<bool> {
        let logic = BulwarkManager::logic()?;
        with_current_token(token.to_string(), async {
            match logic.check_safe().await {
                Ok(()) => Ok(true),
                Err(BulwarkError::NotSafe { .. }) => Ok(false),
                Err(e) => Err(e),
            }
        })
        .await
    }

    async fn check_disable(&self, token: &str) -> BulwarkResult<bool> {
        let logic = BulwarkManager::logic()?;
        with_current_token(token.to_string(), async {
            match logic.check_disable().await {
                Ok(()) => Ok(false),
                Err(BulwarkError::DisableService { .. }) => Ok(true),
                Err(e) => Err(e),
            }
        })
        .await
    }

    async fn check_api_key(&self, api_key: &str, namespace: &str) -> BulwarkResult<()> {
        let logic = BulwarkManager::logic()?;
        let ns = namespace.to_string();
        with_current_token(api_key.to_string(), async move {
            logic.check_api_key(&ns).await
        })
        .await
    }

    async fn get_token_info(&self, token: &str) -> BulwarkResult<TokenInfo> {
        let logic = BulwarkManager::logic()?;
        let ts = logic
            .session
            .get_token_session(token)
            .await?
            .ok_or_else(|| BulwarkError::InvalidToken("token 无效或已过期".to_string()))?;
        Ok(TokenInfo {
            token: ts.token,
            created_at: ts.created_at,
            last_active_at: ts.last_active_at,
        })
    }

    async fn get_session(&self, token: &str) -> BulwarkResult<SessionData> {
        let logic = BulwarkManager::logic()?;
        logic
            .session
            .get_token_session(token)
            .await?
            .ok_or_else(|| BulwarkError::InvalidToken("token 无效或已过期".to_string()))
    }

    async fn kickout(&self, login_id: &str) -> BulwarkResult<()> {
        let logic = BulwarkManager::logic()?;
        logic.kickout(login_id).await
    }

    async fn switch_to(&self, token: &str, target_login_id: &str) -> BulwarkResult<()> {
        let logic = BulwarkManager::logic()?;
        let auth_logic = logic.auth_logic.as_ref().ok_or_else(|| {
            BulwarkError::NotImplemented("auth_logic 未注入，switch_to 不可用".to_string())
        })?;
        auth_logic.switch_to(token, target_login_id).await
    }

    async fn renew_to_equivalent(&self, token: &str) -> BulwarkResult<String> {
        let logic = BulwarkManager::logic()?;
        let auth_logic = logic.auth_logic.as_ref().ok_or_else(|| {
            BulwarkError::NotImplemented(
                "auth_logic 未注入，renew_to_equivalent 不可用".to_string(),
            )
        })?;
        auth_logic.renew_to_equivalent(token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BulwarkConfig;
    use crate::dao::BulwarkDao;
    use crate::stp::mock::{MockDao, MockInterface};
    use crate::stp::BulwarkInterface;
    use serial_test::serial;
    use std::sync::Arc;

    /// 初始化全局 BulwarkManager，返回 BackendEmbedded 实例。
    fn setup_backend() -> BackendEmbedded {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = false;
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
        BulwarkManager::init(dao, Arc::new(config), interface).unwrap();
        BackendEmbedded::new()
    }

    #[tokio::test]
    #[serial]
    async fn test_login_returns_token() {
        let backend = setup_backend();
        let token = backend
            .login("user1", &LoginParams::default())
            .await
            .unwrap();
        assert!(!token.is_empty());
    }

    #[tokio::test]
    #[serial]
    async fn test_check_login_valid_token() {
        let backend = setup_backend();
        let token = backend
            .login("user1", &LoginParams::default())
            .await
            .unwrap();
        assert!(backend.check_login(&token).await.unwrap());
    }

    #[tokio::test]
    #[serial]
    async fn test_check_login_invalid_token() {
        let backend = setup_backend();
        assert!(!backend.check_login("invalid-token").await.unwrap());
    }

    #[tokio::test]
    #[serial]
    async fn test_logout_invalidates_token() {
        let backend = setup_backend();
        let token = backend
            .login("user1", &LoginParams::default())
            .await
            .unwrap();
        backend.logout(&token).await.unwrap();
        assert!(!backend.check_login(&token).await.unwrap());
    }

    #[tokio::test]
    #[serial]
    async fn test_kickout_invalidates_all_sessions() {
        let backend = setup_backend();
        let t1 = backend
            .login("user1", &LoginParams::default())
            .await
            .unwrap();
        let t2 = backend
            .login("user1", &LoginParams::default())
            .await
            .unwrap();
        backend.kickout("user1").await.unwrap();
        assert!(!backend.check_login(&t1).await.unwrap());
        assert!(!backend.check_login(&t2).await.unwrap());
    }

    #[tokio::test]
    #[serial]
    async fn test_get_token_info() {
        let backend = setup_backend();
        let token = backend
            .login("user1", &LoginParams::default())
            .await
            .unwrap();
        let info = backend.get_token_info(&token).await.unwrap();
        assert_eq!(info.token, token);
        assert!(info.created_at > 0);
        assert!(info.last_active_at >= info.created_at);
    }

    #[tokio::test]
    #[serial]
    async fn test_get_token_info_invalid_token() {
        let backend = setup_backend();
        let result = backend.get_token_info("invalid").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BulwarkError::InvalidToken(_) => {},
            e => panic!("期望 InvalidToken，实际: {:?}", e),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_get_session() {
        let backend = setup_backend();
        let token = backend
            .login("user1", &LoginParams::default())
            .await
            .unwrap();
        let session = backend.get_session(&token).await.unwrap();
        assert_eq!(session.token, token);
        assert_eq!(session.login_id, "user1");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_session_invalid_token() {
        let backend = setup_backend();
        let result = backend.get_session("invalid").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_check_safe_default_returns_true() {
        let backend = setup_backend();
        let token = backend
            .login("user1", &LoginParams::default())
            .await
            .unwrap();
        // 默认未启用 MFA，check_safe 返回 true
        assert!(backend.check_safe(&token).await.unwrap());
    }

    #[tokio::test]
    #[serial]
    async fn test_check_disable_default_returns_false() {
        let backend = setup_backend();
        let token = backend
            .login("user1", &LoginParams::default())
            .await
            .unwrap();
        // 默认未注入 disable_repository，check_disable 返回 false
        assert!(!backend.check_disable(&token).await.unwrap());
    }

    #[tokio::test]
    #[serial]
    async fn test_switch_to_default_guard_denies() {
        let backend = setup_backend();
        let token = backend
            .login("user1", &LoginParams::default())
            .await
            .unwrap();
        // 默认 DenyAllSwitchToGuard 拒绝所有切换（安全默认）
        let result = backend.switch_to(&token, "user2").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BulwarkError::NotPermission(_) => {},
            e => panic!("期望 NotPermission，实际: {:?}", e),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_renew_to_equivalent_returns_new_token() {
        let backend = setup_backend();
        let old_token = backend
            .login("user1", &LoginParams::default())
            .await
            .unwrap();
        let new_token = backend.renew_to_equivalent(&old_token).await.unwrap();
        assert_ne!(old_token, new_token);
        // 旧 token 应失效
        assert!(!backend.check_login(&old_token).await.unwrap());
        // 新 token 应有效
        assert!(backend.check_login(&new_token).await.unwrap());
    }

    #[tokio::test]
    #[serial]
    async fn test_check_permission_invalid_token() {
        let backend = setup_backend();
        let result = backend.check_permission("invalid", "user:read").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_dyn_dispatch_with_backend_embedded() {
        let backend: Arc<dyn AuthBackend> = Arc::new(setup_backend());
        let token = backend
            .login("dyn-user", &LoginParams::default())
            .await
            .unwrap();
        assert!(backend.check_login(&token).await.unwrap());
    }
}
