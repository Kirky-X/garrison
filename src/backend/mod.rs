//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! AuthBackend — 认证后端统一抽象。
//!
//! 提供 13 个 async 方法的 trait 接口，支持两种部署模式：
//! - **BackendEmbedded**（`backend-embedded` feature）：进程内认证，委托 GarrisonManager
//! - **BackendRemote**（`backend-remote` feature）：HTTP 客户端，连接远程 Auth Server
//!
//! # 设计原则
//!
//! - **trait + dyn object 切换**（Rule 2 简洁优先）：不使用 typestate 模式，
//!   AuthBackend 只是一个 trait，通过 `Arc<dyn AuthBackend>` 在 Embedded/Remote 间切换
//! - **方法签名接受 token 参数**：与 GarrisonUtil 静态方法（从 task_local 获取 token）不同，
//!   AuthBackend 方法显式接受 token/login_id 参数，适用于远程调用场景
//! - **复用现有类型**（Rule 8）：LoginParams / TokenInfo / SessionData 复用 garrison 现有类型

use crate::error::GarrisonResult;
use async_trait::async_trait;

pub mod types;

#[cfg(feature = "backend-embedded")]
pub mod embedded;

#[cfg(feature = "backend-remote")]
pub mod remote;

#[cfg(feature = "backend-kit")]
pub mod kit_builder;

pub use types::*;

#[cfg(feature = "backend-embedded")]
pub use embedded::BackendEmbedded;

#[cfg(feature = "backend-remote")]
pub use remote::BackendRemote;

#[cfg(feature = "backend-kit")]
pub use kit_builder::{BackendKitError, BackendModule};

/// 认证后端统一抽象。
///
/// 13 个 async 方法覆盖登录/登出/校验/查询/管理全生命周期。
/// 通过 `Arc<dyn AuthBackend>` 实现 Embedded/Remote 模式切换。
///
/// # 方法分类
///
/// | 分类 | 方法 |
/// |------|------|
/// | 登录/登出 | `login` / `logout` |
/// | 状态校验 | `check_login` / `check_safe` / `check_disable` |
/// | 权限校验 | `check_permission` / `check_role` / `check_api_key` |
/// | 信息查询 | `get_token_info` / `get_session` |
/// | 会话管理 | `kickout` / `switch_to` / `renew_to_equivalent` |
#[async_trait]
pub trait AuthBackend: Send + Sync {
    /// 执行登录，返回生成的 token。
    ///
    /// # 参数
    /// - `login_id`：登录主体标识
    /// - `params`：登录参数（设备/IP/UA/remember_me/require_mfa）
    async fn login(&self, login_id: &str, params: &LoginParams) -> GarrisonResult<String>;

    /// 执行登出，销毁指定 token 的会话。
    async fn logout(&self, token: &str) -> GarrisonResult<()>;

    /// 校验 token 是否处于登录状态。
    ///
    /// 返回 `true` 表示已登录且未过期，`false` 表示未登录或已过期。
    async fn check_login(&self, token: &str) -> GarrisonResult<bool>;

    /// 校验 token 是否拥有指定权限。
    ///
    /// 返回 `Ok(())` 表示有权限，返回 `Err` 表示无权限或 token 无效。
    async fn check_permission(&self, token: &str, permission: &str) -> GarrisonResult<()>;

    /// 校验 token 是否拥有指定角色。
    ///
    /// 返回 `Ok(())` 表示有角色，返回 `Err` 表示无角色或 token 无效。
    async fn check_role(&self, token: &str, role: &str) -> GarrisonResult<()>;

    /// 校验 token 是否处于二级认证（Safe Auth）状态。
    ///
    /// 返回 `true` 表示已开启二级认证，`false` 表示未开启。
    async fn check_safe(&self, token: &str) -> GarrisonResult<bool>;

    /// 校验 token 是否被禁用。
    ///
    /// 返回 `true` 表示已禁用，`false` 表示未禁用。
    async fn check_disable(&self, token: &str) -> GarrisonResult<bool>;

    /// 校验 API Key 是否有效。
    ///
    /// # 参数
    /// - `api_key`：API Key 字符串
    /// - `namespace`：命名空间（租户隔离标识）
    async fn check_api_key(&self, api_key: &str, namespace: &str) -> GarrisonResult<()>;

    /// 获取 token 的基本信息。
    ///
    /// 返回 `TokenInfo`（token 字符串 / 创建时间 / 最后活跃时间）。
    async fn get_token_info(&self, token: &str) -> GarrisonResult<TokenInfo>;

    /// 获取 token 的 session 数据。
    ///
    /// 返回 `SessionData`（login_id / 创建时间 / 活跃时间 / 自定义属性 / 设备信息）。
    async fn get_session(&self, token: &str) -> GarrisonResult<SessionData>;

    /// 踢出指定登录主体的所有会话。
    async fn kickout(&self, login_id: &str) -> GarrisonResult<()>;

    /// 切换登录主体（保持当前 token，切换 login_id）。
    ///
    /// 将当前 token 关联的会话切换到 `target_login_id`，
    /// 保留原 token 字符串与 session attrs（device/ip/ua 等），
    /// 在 attrs["switched_from"] 记录原始 login_id。
    async fn switch_to(&self, token: &str, target_login_id: &str) -> GarrisonResult<()>;

    /// 续期 token 到等价的新 token。
    ///
    /// 返回续期后的新 token 字符串。
    async fn renew_to_equivalent(&self, token: &str) -> GarrisonResult<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Mock AuthBackend 实现，用于测试 trait 基本结构。
    struct MockAuthBackend;

    #[async_trait]
    impl AuthBackend for MockAuthBackend {
        async fn login(&self, login_id: &str, _params: &LoginParams) -> GarrisonResult<String> {
            Ok(format!("mock-token-{}", login_id))
        }

        async fn logout(&self, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn check_login(&self, token: &str) -> GarrisonResult<bool> {
            Ok(token.starts_with("mock-token-"))
        }

        async fn check_permission(&self, _token: &str, _permission: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn check_role(&self, _token: &str, _role: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn check_safe(&self, _token: &str) -> GarrisonResult<bool> {
            Ok(false)
        }

        async fn check_disable(&self, _token: &str) -> GarrisonResult<bool> {
            Ok(false)
        }

        async fn check_api_key(&self, _api_key: &str, _namespace: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn get_token_info(&self, token: &str) -> GarrisonResult<TokenInfo> {
            Ok(TokenInfo {
                token: token.to_string(),
                created_at: 1000,
                last_active_at: 2000,
            })
        }

        async fn get_session(&self, token: &str) -> GarrisonResult<SessionData> {
            Ok(SessionData {
                token: token.to_string(),
                login_id: "mock-user".to_string(),
                created_at: 1000,
                last_active_at: 2000,
                attrs: std::collections::HashMap::new(),
                device: None,
                ip: None,
                user_agent: None,
                safe_services: std::collections::HashMap::new(),
                #[cfg(feature = "dynamic-active-timeout")]
                dynamic_active_timeout: None,
                #[cfg(feature = "anonymous-session")]
                is_anon: false,
            })
        }

        async fn kickout(&self, _login_id: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn switch_to(&self, _token: &str, target_login_id: &str) -> GarrisonResult<()> {
            let _ = target_login_id;
            Ok(())
        }

        async fn renew_to_equivalent(&self, token: &str) -> GarrisonResult<String> {
            Ok(format!("mock-renewed-{}", token))
        }
    }

    #[tokio::test]
    async fn test_trait_can_be_implemented() {
        let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
        assert!(backend.check_login("any").await.is_ok());
    }

    #[tokio::test]
    async fn test_login_returns_token() {
        let backend = MockAuthBackend;
        let params = LoginParams::default();
        let token = backend.login("user1", &params).await.unwrap();
        assert_eq!(token, "mock-token-user1");
    }

    #[tokio::test]
    async fn test_check_login_validates_token() {
        let backend = MockAuthBackend;
        assert!(backend.check_login("mock-token-user1").await.unwrap());
        assert!(!backend.check_login("invalid-token").await.unwrap());
    }

    #[tokio::test]
    async fn test_get_token_info_returns_info() {
        let backend = MockAuthBackend;
        let info = backend.get_token_info("mock-token").await.unwrap();
        assert_eq!(info.token, "mock-token");
        assert_eq!(info.created_at, 1000);
        assert_eq!(info.last_active_at, 2000);
    }

    #[tokio::test]
    async fn test_get_session_returns_data() {
        let backend = MockAuthBackend;
        let session = backend.get_session("mock-token").await.unwrap();
        assert_eq!(session.token, "mock-token");
        assert_eq!(session.login_id, "mock-user");
    }

    #[tokio::test]
    async fn test_dyn_dispatch() {
        let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
        let token = backend
            .login("dyn-user", &LoginParams::default())
            .await
            .unwrap();
        assert_eq!(token, "mock-token-dyn-user");
        assert!(backend.check_login(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_switch_to_succeeds() {
        let backend = MockAuthBackend;
        backend
            .switch_to("current-token", "new-user")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_renew_to_equivalent_returns_renewed_token() {
        let backend = MockAuthBackend;
        let renewed = backend.renew_to_equivalent("old-token").await.unwrap();
        assert_eq!(renewed, "mock-renewed-old-token");
    }

    #[test]
    fn test_check_login_request_serialization() {
        let req = CheckLoginRequest {
            token: "test-token".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("test-token"));
        let de: CheckLoginRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(de.token, "test-token");
    }

    #[test]
    fn test_check_permission_request_serialization() {
        let req = CheckPermissionRequest {
            token: "tok".to_string(),
            permission: "user:read".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("user:read"));
    }

    #[test]
    fn test_api_response_ok() {
        let resp = ApiResponse::ok("data".to_string());
        assert!(resp.data.is_some());
        assert!(resp.error_code.is_none());
        let result = resp.into_result().unwrap();
        assert_eq!(result, "data");
    }

    #[test]
    fn test_api_response_err() {
        let resp = ApiResponse::<String>::err("NOT_FOUND", "resource not found");
        assert!(resp.data.is_none());
        assert_eq!(resp.error_code.as_ref().unwrap(), "NOT_FOUND");
        let result = resp.into_result();
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, "NOT_FOUND");
        assert_eq!(msg, "resource not found");
    }
}
