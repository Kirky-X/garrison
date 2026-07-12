//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BackendRemote — 远程认证后端实现。
//!
//! 通过 HTTP API 连接远程 Auth Server，将 AuthBackend 方法映射为 REST 请求。
//!
//! # 设计
//!
//! - **reqwest::Client**：支持 TLS/mTLS 配置，连接池复用
//! - **统一 API 包装**：`ApiResponse<T>` 包装所有响应，成功时 `data` 有值，失败时 `error_code` + `message`
//! - **X-API-Key 头**：每个请求携带 API Key 用于服务间认证
//! - **错误映射**：网络错误 → `BulwarkError::Network`，API 错误 → 根据 `error_code` 映射

use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use std::time::Duration;

use super::types::{
    ApiResponse, CheckApiKeyRequest, CheckLoginRequest, CheckPermissionRequest, CheckRoleRequest,
    KickoutRequest, LoginParams, LoginRequest, LogoutRequest, RenewToEquivalentRequest,
    SessionData, SwitchToRequest, TokenInfo,
};
use super::AuthBackend;

/// 远程认证后端，通过 HTTP API 连接远程 Auth Server。
///
/// # 端点映射
///
/// | 方法 | 端点 | 请求体 | 响应 data |
/// |------|------|--------|-----------|
/// | login | POST /api/v1/auth/login | LoginRequest | String |
/// | logout | POST /api/v1/auth/logout | LogoutRequest | () |
/// | check_login | POST /api/v1/auth/check-login | CheckLoginRequest | bool |
/// | check_permission | POST /api/v1/auth/check-permission | CheckPermissionRequest | () |
/// | check_role | POST /api/v1/auth/check-role | CheckRoleRequest | () |
/// | check_safe | POST /api/v1/auth/check-safe | CheckLoginRequest | bool |
/// | check_disable | POST /api/v1/auth/check-disable | CheckLoginRequest | bool |
/// | check_api_key | POST /api/v1/auth/check-api-key | CheckApiKeyRequest | () |
/// | get_token_info | POST /api/v1/auth/get-token-info | CheckLoginRequest | TokenInfo |
/// | get_session | POST /api/v1/auth/get-session | CheckLoginRequest | SessionData |
/// | kickout | POST /api/v1/auth/kickout | KickoutRequest | () |
/// | switch_to | POST /api/v1/auth/switch-to | SwitchToRequest | () |
/// | renew_to_equivalent | POST /api/v1/auth/renew-to-equivalent | RenewToEquivalentRequest | String |
pub struct BackendRemote {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl BackendRemote {
    /// 创建 BackendRemote 实例。
    ///
    /// # 参数
    /// - `base_url`：Auth Server 基础 URL（如 "https://auth-internal:8443"）
    /// - `api_key`：服务间认证 API Key
    /// - `timeout`：请求超时
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        timeout: Duration,
    ) -> BulwarkResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| BulwarkError::Network(format!("构建 HTTP 客户端失败: {}", e)))?;
        Ok(Self {
            client,
            base_url: base_url.into(),
            api_key: api_key.into(),
        })
    }

    /// 发送 POST 请求并解析响应为 `ApiResponse<T>`。
    ///
    /// 统一处理：
    /// - 请求构建（URL + X-API-Key 头 + JSON body）
    /// - 网络错误映射
    /// - HTTP 状态码检查
    /// - 响应反序列化
    async fn post<Req, T>(&self, path: &str, req: &Req) -> BulwarkResult<ApiResponse<T>>
    where
        Req: serde::Serialize,
        T: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(req)
            .send()
            .await
            .map_err(|e| BulwarkError::Network(format!("HTTP 请求失败: {}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(BulwarkError::Network(format!(
                "HTTP {}: {}",
                status.as_u16(),
                body
            )));
        }

        resp.json::<ApiResponse<T>>()
            .await
            .map_err(|e| BulwarkError::Network(format!("响应反序列化失败: {}", e)))
    }

    /// 发送 POST 请求，解析 `ApiResponse<T>` 并提取 `data`。
    ///
    /// 用于返回有数据的方法（login → String, check_login → bool 等）。
    async fn post_and_extract<Req, T>(&self, path: &str, req: &Req) -> BulwarkResult<T>
    where
        Req: serde::Serialize,
        T: serde::de::DeserializeOwned,
    {
        let api_resp = self.post::<Req, T>(path, req).await?;
        api_resp
            .into_result()
            .map_err(|(code, msg)| BulwarkError::Network(format!("API 错误 [{}]: {}", code, msg)))
    }

    /// 发送 POST 请求，检查 `error_code` 判断成功/失败（无 data 提取）。
    ///
    /// 用于返回 `()` 的方法（logout, check_permission, check_role 等）。
    /// `ApiResponse<()>` 的 `data` 字段在 JSON 中为 `null`，无法通过 `into_result` 区分成功/失败，
    /// 因此直接检查 `error_code` 是否存在。
    async fn post_unit<Req>(&self, path: &str, req: &Req) -> BulwarkResult<()>
    where
        Req: serde::Serialize,
    {
        let api_resp = self.post::<Req, ()>(path, req).await?;
        if let Some(code) = api_resp.error_code {
            return Err(BulwarkError::Network(format!(
                "API 错误 [{}]: {}",
                code,
                api_resp.message.unwrap_or_default()
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl AuthBackend for BackendRemote {
    async fn login(&self, login_id: &str, params: &LoginParams) -> BulwarkResult<String> {
        let req = LoginRequest {
            login_id: login_id.to_string(),
            params: params.clone(),
        };
        self.post_and_extract("/api/v1/auth/login", &req).await
    }

    async fn logout(&self, token: &str) -> BulwarkResult<()> {
        let req = LogoutRequest {
            token: token.to_string(),
        };
        self.post_unit("/api/v1/auth/logout", &req).await
    }

    async fn check_login(&self, token: &str) -> BulwarkResult<bool> {
        let req = CheckLoginRequest {
            token: token.to_string(),
        };
        self.post_and_extract("/api/v1/auth/check-login", &req)
            .await
    }

    async fn check_permission(&self, token: &str, permission: &str) -> BulwarkResult<()> {
        let req = CheckPermissionRequest {
            token: token.to_string(),
            permission: permission.to_string(),
        };
        self.post_unit("/api/v1/auth/check-permission", &req).await
    }

    async fn check_role(&self, token: &str, role: &str) -> BulwarkResult<()> {
        let req = CheckRoleRequest {
            token: token.to_string(),
            role: role.to_string(),
        };
        self.post_unit("/api/v1/auth/check-role", &req).await
    }

    async fn check_safe(&self, token: &str) -> BulwarkResult<bool> {
        let req = CheckLoginRequest {
            token: token.to_string(),
        };
        self.post_and_extract("/api/v1/auth/check-safe", &req).await
    }

    async fn check_disable(&self, token: &str) -> BulwarkResult<bool> {
        let req = CheckLoginRequest {
            token: token.to_string(),
        };
        self.post_and_extract("/api/v1/auth/check-disable", &req)
            .await
    }

    async fn check_api_key(&self, api_key: &str, namespace: &str) -> BulwarkResult<()> {
        let req = CheckApiKeyRequest {
            api_key: api_key.to_string(),
            namespace: namespace.to_string(),
        };
        self.post_unit("/api/v1/auth/check-api-key", &req).await
    }

    async fn get_token_info(&self, token: &str) -> BulwarkResult<TokenInfo> {
        let req = CheckLoginRequest {
            token: token.to_string(),
        };
        self.post_and_extract("/api/v1/auth/get-token-info", &req)
            .await
    }

    async fn get_session(&self, token: &str) -> BulwarkResult<SessionData> {
        let req = CheckLoginRequest {
            token: token.to_string(),
        };
        self.post_and_extract("/api/v1/auth/get-session", &req)
            .await
    }

    async fn kickout(&self, login_id: &str) -> BulwarkResult<()> {
        let req = KickoutRequest {
            login_id: login_id.to_string(),
        };
        self.post_unit("/api/v1/auth/kickout", &req).await
    }

    async fn switch_to(&self, token: &str, target_login_id: &str) -> BulwarkResult<()> {
        let req = SwitchToRequest {
            token: token.to_string(),
            target_login_id: target_login_id.to_string(),
        };
        self.post_unit("/api/v1/auth/switch-to", &req).await
    }

    async fn renew_to_equivalent(&self, token: &str) -> BulwarkResult<String> {
        let req = RenewToEquivalentRequest {
            token: token.to_string(),
        };
        self.post_and_extract("/api/v1/auth/renew-to-equivalent", &req)
            .await
    }
}

/// BackendRemote 构建器，支持 mTLS 客户端证书配置。
///
/// # 示例
///
/// ```ignore
/// use bulwark::backend::BackendRemoteBuilder;
/// use std::time::Duration;
///
/// let remote = BackendRemoteBuilder::new("https://auth:8443", "api-key")
///     .with_timeout(Duration::from_secs(10))
///     .with_client_cert(cert_pem, key_pem)
///     .build()?;
/// ```
pub struct BackendRemoteBuilder {
    base_url: String,
    api_key: String,
    timeout: Duration,
    client_cert: Option<Vec<u8>>,
    client_key: Option<Vec<u8>>,
    ca_cert: Option<Vec<u8>>,
}

impl BackendRemoteBuilder {
    /// 创建构建器实例。
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            timeout: Duration::from_secs(30),
            client_cert: None,
            client_key: None,
            ca_cert: None,
        }
    }

    /// 设置请求超时（默认 30 秒）。
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 设置 mTLS 客户端证书（PEM 格式）。
    pub fn with_client_cert(mut self, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Self {
        self.client_cert = Some(cert_pem);
        self.client_key = Some(key_pem);
        self
    }

    /// 设置自定义 CA 证书（PEM 格式），用于自签名服务器证书。
    pub fn with_ca_cert(mut self, ca_pem: Vec<u8>) -> Self {
        self.ca_cert = Some(ca_pem);
        self
    }

    /// 构建 BackendRemote 实例。
    pub fn build(self) -> BulwarkResult<BackendRemote> {
        let mut builder = reqwest::Client::builder().timeout(self.timeout);

        // 加载 CA 证书（用于自签名服务器）
        if let Some(ca_pem) = self.ca_cert {
            let cert = reqwest::Certificate::from_pem(&ca_pem)
                .map_err(|e| BulwarkError::Network(format!("加载 CA 证书失败: {}", e)))?;
            builder = builder.add_root_certificate(cert);
        }

        // 加载 mTLS 客户端证书
        if let (Some(cert_pem), Some(key_pem)) = (self.client_cert, self.client_key) {
            // reqwest::Identity::from_pem 接受包含证书+私钥的 PEM
            let mut combined = cert_pem;
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&combined)
                .map_err(|e| BulwarkError::Network(format!("加载客户端证书失败: {}", e)))?;
            builder = builder.identity(identity);
        }

        let client = builder
            .build()
            .map_err(|e| BulwarkError::Network(format!("构建 HTTP 客户端失败: {}", e)))?;

        Ok(BackendRemote {
            client,
            base_url: self.base_url,
            api_key: self.api_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// 启动 mock server 并创建 BackendRemote 指向它。
    async fn setup_remote() -> (MockServer, BackendRemote) {
        let server = MockServer::start().await;
        let remote =
            BackendRemote::new(server.uri(), "test-api-key", Duration::from_secs(5)).unwrap();
        (server, remote)
    }

    #[tokio::test]
    async fn test_check_login_returns_true() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-login"))
            .and(header("X-API-Key", "test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": true,
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        let result = remote.check_login("valid-token").await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_check_login_returns_false() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": false,
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        let result = remote.check_login("invalid-token").await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_login_returns_token() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "generated-token-123",
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        let token = remote
            .login("user1", &LoginParams::default())
            .await
            .unwrap();
        assert_eq!(token, "generated-token-123");
    }

    #[tokio::test]
    async fn test_logout_succeeds() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/logout"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        remote.logout("some-token").await.unwrap();
    }

    #[tokio::test]
    async fn test_check_permission_succeeds() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-permission"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        remote.check_permission("token", "user:read").await.unwrap();
    }

    #[tokio::test]
    async fn test_check_permission_api_error() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-permission"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": "NOT_PERMISSION",
                "message": "无权限"
            })))
            .mount(&server)
            .await;

        let result = remote.check_permission("token", "user:read").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_check_role_succeeds() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-role"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        remote.check_role("token", "admin").await.unwrap();
    }

    #[tokio::test]
    async fn test_check_safe_returns_true() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-safe"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": true,
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        assert!(remote.check_safe("token").await.unwrap());
    }

    #[tokio::test]
    async fn test_check_disable_returns_false() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-disable"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": false,
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        assert!(!remote.check_disable("token").await.unwrap());
    }

    #[tokio::test]
    async fn test_check_api_key_succeeds() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        remote.check_api_key("api-key", "default").await.unwrap();
    }

    #[tokio::test]
    async fn test_get_token_info() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/get-token-info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "token": "test-token",
                    "created_at": 1000,
                    "last_active_at": 2000
                },
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        let info = remote.get_token_info("test-token").await.unwrap();
        assert_eq!(info.token, "test-token");
        assert_eq!(info.created_at, 1000);
        assert_eq!(info.last_active_at, 2000);
    }

    #[tokio::test]
    async fn test_get_session() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/get-session"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "token": "test-token",
                    "login_id": "user1",
                    "created_at": 1000,
                    "last_active_at": 2000,
                    "attrs": {},
                    "device": null,
                    "ip": null,
                    "user_agent": null,
                    "safe_services": {}
                },
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        let session = remote.get_session("test-token").await.unwrap();
        assert_eq!(session.token, "test-token");
        assert_eq!(session.login_id, "user1");
    }

    #[tokio::test]
    async fn test_kickout_succeeds() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/kickout"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        remote.kickout("user1").await.unwrap();
    }

    #[tokio::test]
    async fn test_switch_to_succeeds() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/switch-to"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        remote.switch_to("token", "user2").await.unwrap();
    }

    #[tokio::test]
    async fn test_renew_to_equivalent_returns_new_token() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/renew-to-equivalent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "new-token-456",
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        let new_token = remote.renew_to_equivalent("old-token").await.unwrap();
        assert_eq!(new_token, "new-token-456");
    }

    // ========================================================================
    // 网络错误处理测试（T095）
    // ========================================================================

    #[tokio::test]
    async fn test_network_error_connection_refused() {
        // 指向不存在的端口，触发连接失败
        let remote =
            BackendRemote::new("http://127.0.0.1:1", "api-key", Duration::from_secs(1)).unwrap();

        let result = remote.check_login("token").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BulwarkError::Network(_) => {},
            e => panic!("期望 Network 错误，实际: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_http_500_error() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-login"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let result = remote.check_login("token").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BulwarkError::Network(_) => {},
            e => panic!("期望 Network 错误，实际: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_api_error_response() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": "INVALID_TOKEN",
                "message": "token 已过期"
            })))
            .mount(&server)
            .await;

        let result = remote.check_login("token").await;
        assert!(result.is_err());
    }

    // ========================================================================
    // Builder 测试（T098）
    // ========================================================================

    #[tokio::test]
    async fn test_builder_basic() {
        let (server, _remote) = setup_remote().await;
        let remote = BackendRemoteBuilder::new(server.uri(), "builder-key")
            .with_timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-login"))
            .and(header("X-API-Key", "builder-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": true,
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        assert!(remote.check_login("token").await.unwrap());
    }

    #[tokio::test]
    async fn test_builder_with_ca_cert() {
        // 生成自签名证书用于测试
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let ca_pem = cert.cert.der().clone();
        let _ca_cert = reqwest::Certificate::from_der(&ca_pem).unwrap();

        // 使用 CA 证书构建（验证不 panic）
        let result = BackendRemoteBuilder::new("https://localhost:8443", "key")
            .with_ca_cert(cert.cert.pem().as_bytes().to_vec())
            .build();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dyn_dispatch_with_backend_remote() {
        let (server, remote) = setup_remote().await;
        let backend: Arc<dyn AuthBackend> = Arc::new(remote);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "dyn-token",
                "error_code": null,
                "message": null
            })))
            .mount(&server)
            .await;

        let token = backend
            .login("user", &LoginParams::default())
            .await
            .unwrap();
        assert_eq!(token, "dyn-token");
    }
}
