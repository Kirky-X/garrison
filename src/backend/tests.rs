//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! AuthBackend 内联测试。
//!
//! 从 `src/backend/mod.rs` 外移（规则 10 mod/crate 接口隔离）。
//! 测试 MockAuthBackend 实现 trait 基本结构 + 序列化/反序列化。

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
