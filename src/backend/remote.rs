//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
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
//! - **base_url 校验**：构造期校验 scheme 必须为 `http://` 或
//! `https://`（`http://` 会以明文传输 X-API-Key，记录 `tracing::warn`）；
//! URL 拼接做斜杠规范化（base 尾斜杠与 path 头斜杠去重）
//! - **错误映射**：网络错误 → `GarrisonError::Network`；
//! API 错误按 `error_code` 映射——已知业务码透传为对应类型错误
//! （`NOT_LOGIN`/`INVALID_TOKEN`/`TOKEN_REVOKED`/`EXPIRED_TOKEN` → NotLogin/InvalidToken/…，
//! `NOT_PERMISSION` → NotPermission，`NOT_ROLE` → NotRole，
//! `NOT_SAFE` → NotSafe，`DISABLE_SERVICE` → DisableService），
//! 未知码 → `Network`（消息带 `backend-api-error::CODE::MESSAGE` 前缀约定，
//! 与 `circuit-open::` 前缀模式一致）；服务端 `message` 全程保留
//! - **embedded 语义对齐**：`check_safe` 将 `NOT_SAFE` 业务错误映射为
//! `Ok(false)`，`check_disable` 将 `DISABLE_SERVICE` 映射为 `Ok(true)`，
//! 与 `BackendEmbedded` 的 bool 适配语义一致（远程 `DISABLE_SERVICE` 的解封时间
//! 无法从响应恢复，`until` 置 `None`）

use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

use super::types::{
    ApiResponse, CheckApiKeyRequest, CheckLoginRequest, CheckPermissionRequest, CheckRoleRequest,
    KickoutRequest, LoginParams, LoginRequest, LogoutRequest, RenewToEquivalentRequest,
    SessionData, SwitchToRequest, TokenInfo,
};
use super::AuthBackend;
#[cfg(feature = "backend-remote")]
use crate::limiteron::CircuitBreakerWrapper;

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
    /// 可选的熔断器，保护远程调用避免级联故障。
    circuit_breaker: Option<Arc<CircuitBreakerWrapper>>,
}

impl BackendRemote {
    /// 创建 BackendRemote 实例。
    ///
    /// # 参数
    /// - `base_url`：Auth Server 基础 URL（如 "https://auth-internal:8443"）
    /// - `api_key`：服务间认证 API Key
    /// - `timeout`：请求超时
    ///
    /// # 错误
    /// - `base_url` scheme 非 `http://`/`https://`：返回 `GarrisonError::InvalidParam`
    /// （拒绝 `ftp://` 等任意 scheme；`http://` 允许但记录明文传输警告）
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        timeout: Duration,
    ) -> GarrisonResult<Self> {
        let base_url = validate_base_url(&base_url.into())?;
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| GarrisonError::Network(format!("backend-http-client-build::{}", e)))?;
        Ok(Self {
            client,
            base_url,
            api_key: api_key.into(),
            circuit_breaker: None,
        })
    }

    /// 启用熔断器保护。
    ///
    /// 启用后，所有 `post` 请求将通过熔断器包裹执行。
    /// 当连续失败次数达到阈值时，熔断器打开并快速拒绝后续请求。
    pub fn with_circuit_breaker(mut self, cb: Arc<CircuitBreakerWrapper>) -> Self {
        self.circuit_breaker = Some(cb);
        self
    }

    /// 发送 POST 请求并解析响应为 `ApiResponse<T>`。
    ///
    /// 统一处理：
    /// - 请求构建（URL + X-API-Key 头 + JSON body）
    /// - 网络错误映射
    /// - HTTP 状态码检查
    /// - 响应反序列化
    async fn post<Req, T>(&self, path: &str, req: &Req) -> GarrisonResult<ApiResponse<T>>
    where
        Req: serde::Serialize,
        T: serde::de::DeserializeOwned,
    {
        // 斜杠规范化：base 尾斜杠 + path 头斜杠去重，避免裸拼接产生 `//`
        let url = build_url(&self.base_url, path);
        // 若启用熔断器，通过熔断器包裹 HTTP 调用
        if let Some(ref cb) = self.circuit_breaker {
            let api_key = &self.api_key;
            let client = &self.client;
            // 借用局部变量避免闭包捕获 &self
            let do_request = || async { Self::do_http_post(client, &url, api_key, req).await };
            cb.execute(do_request).await
        } else {
            Self::do_http_post(&self.client, &url, &self.api_key, req).await
        }
    }

    /// 实际 HTTP POST 执行逻辑（供熔断器包裹或直接调用）。
    async fn do_http_post<Req, T>(
        client: &reqwest::Client,
        url: &str,
        api_key: &str,
        req: &Req,
    ) -> GarrisonResult<ApiResponse<T>>
    where
        Req: serde::Serialize,
        T: serde::de::DeserializeOwned,
    {
        let resp = client
            .post(url)
            .header("X-API-Key", api_key)
            .json(req)
            .send()
            .await
            .map_err(|e| GarrisonError::Network(format!("backend-http-request::{}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(GarrisonError::Network(format!(
                "HTTP {}: {}",
                status.as_u16(),
                body
            )));
        }

        resp.json::<ApiResponse<T>>()
            .await
            .map_err(|e| GarrisonError::Network(format!("backend-response-deser::{}", e)))
    }

    /// 发送 POST 请求，解析 `ApiResponse<T>` 并提取 `data`。
    ///
    /// 用于返回有数据的方法（login → String, check_login → bool 等）。
    /// API 错误经 [`api_error`] 按 `error_code` 映射为类型化错误（message 保留）。
    async fn post_and_extract<Req, T>(&self, path: &str, req: &Req) -> GarrisonResult<T>
    where
        Req: serde::Serialize,
        T: serde::de::DeserializeOwned,
    {
        let api_resp = self.post::<Req, T>(path, req).await?;
        api_resp
            .into_result()
            .map_err(|(code, msg)| api_error(&code, &msg))
    }

    /// 发送 POST 请求，检查 `error_code` 判断成功/失败（无 data 提取）。
    ///
    /// 用于返回 `()` 的方法（logout, check_permission, check_role 等）。
    /// `ApiResponse<()>` 的 `data` 字段在 JSON 中为 `null`，无法通过 `into_result` 区分成功/失败，
    /// 因此直接检查 `error_code` 是否存在。API 错误经 [`api_error`] 按 `error_code`
    /// 映射为类型化错误（message 保留）。
    async fn post_unit<Req>(&self, path: &str, req: &Req) -> GarrisonResult<()>
    where
        Req: serde::Serialize,
    {
        let api_resp = self.post::<Req, ()>(path, req).await?;
        if let (Some(code), message) = (&api_resp.error_code, &api_resp.message) {
            return Err(api_error(
                code,
                message.as_deref().unwrap_or("backend-unknown-error::"),
            ));
        }
        Ok(())
    }
}

/// 校验并规范化 base_url。
///
/// - scheme 必须为 `http://` 或 `https://`（大小写不敏感），否则返回
/// `GarrisonError::InvalidParam`——`BackendRemote` 每个请求都携带
/// `X-API-Key`，任意 scheme 会放大凭据泄露面；
/// - `http://` 允许（内网/测试场景）但记录明文传输 `tracing::warn`；
/// - 返回去除尾斜杠后的 base_url（斜杠规范化在拼接时配合 [`build_url`]）。
fn validate_base_url(base_url: &str) -> GarrisonResult<String> {
    let trimmed = base_url.trim_end_matches('/');
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok(trimmed.to_string());
    }
    if lower.starts_with("http://") {
        tracing::warn!(
            base_url = %trimmed,
            "BackendRemote base_url 使用明文 http://，X-API-Key 可能被网络路径窃听；生产环境应使用 https://"
        );
        return Ok(trimmed.to_string());
    }
    Err(GarrisonError::InvalidParam(format!(
        "backend-remote-base-url-invalid-scheme::{}",
        base_url
    )))
}

/// 拼接 base_url 与 path，斜杠规范化。
///
/// base 尾部斜杠与 path 头部斜杠去重，保证恰好一个 `/` 分隔：
/// `("https://h:8443", "/api/x")` 与 `("https://h:8443/", "api/x")` 等价。
fn build_url(base_url: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

/// 将远程 API 错误码映射为 `GarrisonError`。
///
/// - 已知业务码透传为对应类型错误（与 `error.rs::parts_and_msg_key` 的错误码约定一致），
/// 调用方可按类型匹配（如 `check_safe` 匹配 `NotSafe`）；
/// - 未知码 → `GarrisonError::Network`，消息带 `backend-api-error::CODE::MESSAGE`
/// 前缀约定（与 `circuit-open::` 前缀模式一致）；
/// - 服务端 `message` 在所有路径保留（不再丢弃）。
/// - 限制：`DISABLE_SERVICE` 的解封时间戳远程响应不可恢复，`until` 置 `None`。
fn api_error(code: &str, message: &str) -> GarrisonError {
    let mapped = match code {
        "NOT_LOGIN" => GarrisonError::NotLogin(format!("remote::{}", message)),
        "INVALID_TOKEN" => GarrisonError::InvalidToken(format!("remote::{}", message)),
        "TOKEN_REVOKED" => GarrisonError::TokenRevoked(format!("remote::{}", message)),
        "EXPIRED_TOKEN" => GarrisonError::ExpiredToken(format!("remote::{}", message)),
        "NOT_PERMISSION" => GarrisonError::NotPermission(format!("remote::{}", message)),
        "NOT_ROLE" => GarrisonError::NotRole(format!("remote::{}", message)),
        "NOT_SAFE" => GarrisonError::NotSafe {
            reason: message.to_string(),
        },
        "DISABLE_SERVICE" => GarrisonError::DisableService {
            service: "remote".to_string(),
            until: None,
        },
        _ => return GarrisonError::Network(format!("backend-api-error::{}::{}", code, message)),
    };
    tracing::debug!(error_code = %code, api_message = %message, "remote backend API business error mapped");
    mapped
}

#[async_trait]
impl AuthBackend for BackendRemote {
    async fn login(&self, login_id: &str, params: &LoginParams) -> GarrisonResult<String> {
        let req = LoginRequest {
            login_id: login_id.to_string(),
            params: params.clone(),
        };
        self.post_and_extract("/api/v1/auth/login", &req).await
    }

    async fn logout(&self, token: &str) -> GarrisonResult<()> {
        let req = LogoutRequest {
            token: token.to_string(),
        };
        self.post_unit("/api/v1/auth/logout", &req).await
    }

    async fn check_login(&self, token: &str) -> GarrisonResult<bool> {
        let req = CheckLoginRequest {
            token: token.to_string(),
        };
        self.post_and_extract("/api/v1/auth/check-login", &req)
            .await
    }

    async fn check_permission(&self, token: &str, permission: &str) -> GarrisonResult<()> {
        let req = CheckPermissionRequest {
            token: token.to_string(),
            permission: permission.to_string(),
        };
        self.post_unit("/api/v1/auth/check-permission", &req).await
    }

    async fn check_role(&self, token: &str, role: &str) -> GarrisonResult<()> {
        let req = CheckRoleRequest {
            token: token.to_string(),
            role: role.to_string(),
        };
        self.post_unit("/api/v1/auth/check-role", &req).await
    }

    async fn check_safe(&self, token: &str) -> GarrisonResult<bool> {
        let req = CheckLoginRequest {
            token: token.to_string(),
        };
        // 与 BackendEmbedded 语义对齐——API 返回 NOT_SAFE 业务错误
        // 表示「未完成二次认证」→ Ok(false)，其余错误向上抛
        match self.post_and_extract("/api/v1/auth/check-safe", &req).await {
            Ok(safe) => Ok(safe),
            Err(GarrisonError::NotSafe { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn check_disable(&self, token: &str) -> GarrisonResult<bool> {
        let req = CheckLoginRequest {
            token: token.to_string(),
        };
        // 与 BackendEmbedded 语义对齐——API 返回 DISABLE_SERVICE 业务错误
        // 表示「账号被封禁」→ Ok(true)，其余错误向上抛
        // （解封时间戳无法从远程响应恢复，DisableService.until 置 None）
        match self
            .post_and_extract("/api/v1/auth/check-disable", &req)
            .await
        {
            Ok(disabled) => Ok(disabled),
            Err(GarrisonError::DisableService { .. }) => Ok(true),
            Err(e) => Err(e),
        }
    }

    async fn check_api_key(&self, api_key: &str, namespace: &str) -> GarrisonResult<()> {
        let req = CheckApiKeyRequest {
            api_key: api_key.to_string(),
            namespace: namespace.to_string(),
        };
        self.post_unit("/api/v1/auth/check-api-key", &req).await
    }

    async fn get_token_info(&self, token: &str) -> GarrisonResult<TokenInfo> {
        let req = CheckLoginRequest {
            token: token.to_string(),
        };
        self.post_and_extract("/api/v1/auth/get-token-info", &req)
            .await
    }

    async fn get_session(&self, token: &str) -> GarrisonResult<SessionData> {
        let req = CheckLoginRequest {
            token: token.to_string(),
        };
        self.post_and_extract("/api/v1/auth/get-session", &req)
            .await
    }

    async fn kickout(&self, login_id: &str) -> GarrisonResult<()> {
        let req = KickoutRequest {
            login_id: login_id.to_string(),
        };
        self.post_unit("/api/v1/auth/kickout", &req).await
    }

    async fn switch_to(&self, token: &str, target_login_id: &str) -> GarrisonResult<()> {
        let req = SwitchToRequest {
            token: token.to_string(),
            target_login_id: target_login_id.to_string(),
        };
        self.post_unit("/api/v1/auth/switch-to", &req).await
    }

    async fn renew_to_equivalent(&self, token: &str) -> GarrisonResult<String> {
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
/// use garrison::backend::BackendRemoteBuilder;
/// use std::time::Duration;
///
/// let remote = BackendRemoteBuilder::new("https://auth:8443", "api-key")
/// .with_timeout(Duration::from_secs(10))
/// .with_client_cert(cert_pem, key_pem)
/// .build()?;
/// ```
pub struct BackendRemoteBuilder {
    base_url: String,
    api_key: String,
    timeout: Duration,
    client_cert: Option<Vec<u8>>,
    client_key: Option<Vec<u8>>,
    ca_cert: Option<Vec<u8>>,
    circuit_breaker: Option<Arc<CircuitBreakerWrapper>>,
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
            circuit_breaker: None,
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

    /// 启用熔断器保护。
    ///
    /// 熔断器将包裹所有 HTTP 调用，连续失败达到阈值后自动打开，
    /// 快速拒绝后续请求直到超时后探测恢复。
    pub fn with_circuit_breaker(mut self, cb: Arc<CircuitBreakerWrapper>) -> Self {
        self.circuit_breaker = Some(cb);
        self
    }

    /// 构建 BackendRemote 实例。
    ///
    /// # 错误
    /// - `base_url` scheme 非 `http://`/`https://`：返回 `GarrisonError::InvalidParam`
    /// （与 [`BackendRemote::new`] 相同的 scheme 校验）
    pub fn build(self) -> GarrisonResult<BackendRemote> {
        let base_url = validate_base_url(&self.base_url)?;
        let mut builder = reqwest::Client::builder().timeout(self.timeout);

        // 加载 CA 证书（用于自签名服务器）
        if let Some(ca_pem) = self.ca_cert {
            let cert = reqwest::Certificate::from_pem(&ca_pem)
                .map_err(|e| GarrisonError::Network(format!("backend-ca-load::{}", e)))?;
            builder = builder.add_root_certificate(cert);
        }

        // 加载 mTLS 客户端证书
        if let (Some(cert_pem), Some(key_pem)) = (self.client_cert, self.client_key) {
            // reqwest::Identity::from_pem 接受包含证书+私钥的 PEM
            let mut combined = cert_pem;
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&combined)
                .map_err(|e| GarrisonError::Network(format!("backend-client-cert-load::{}", e)))?;
            builder = builder.identity(identity);
        }

        let client = builder
            .build()
            .map_err(|e| GarrisonError::Network(format!("backend-http-client-build::{}", e)))?;

        Ok(BackendRemote {
            client,
            base_url,
            api_key: self.api_key,
            circuit_breaker: self.circuit_breaker,
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
    // 网络错误处理测试
    // ========================================================================

    #[tokio::test]
    async fn test_network_error_connection_refused() {
        // 指向不存在的端口，触发连接失败
        let remote =
            BackendRemote::new("http://127.0.0.1:1", "api-key", Duration::from_secs(1)).unwrap();

        let result = remote.check_login("token").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            GarrisonError::Network(_) => {},
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
            GarrisonError::Network(_) => {},
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
    // Builder 测试
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
        let _remote = result.expect("有效 CA 证书构建应成功");
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

    // ========================================================================
    // base_url scheme 校验与 URL 规范化测试
    // ========================================================================

    #[tokio::test]
    async fn test_invalid_scheme_rejected_in_new_and_builder() {
        for bad in ["ftp://auth:8443", "unix:///run/auth.sock", "auth:8443", ""] {
            assert!(
                BackendRemote::new(bad, "key", Duration::from_secs(1)).is_err(),
                "new() 应拒绝非法 scheme: {bad}"
            );
            assert!(
                BackendRemoteBuilder::new(bad, "key").build().is_err(),
                "builder() 应拒绝非法 scheme: {bad}"
            );
        }
    }

    #[tokio::test]
    async fn test_http_scheme_accepted_with_warn() {
        // http:// 允许（内网/测试），仅 warn
        let remote =
            BackendRemote::new("http://127.0.0.1:1", "key", Duration::from_secs(1)).unwrap();
        let _ = remote;
    }

    #[test]
    fn test_build_url_normalizes_slashes() {
        assert_eq!(
            build_url("https://h:8443", "/api/x"),
            "https://h:8443/api/x"
        );
        assert_eq!(
            build_url("https://h:8443/", "/api/x"),
            "https://h:8443/api/x"
        );
        assert_eq!(
            build_url("https://h:8443//", "//api/x"),
            "https://h:8443/api/x"
        );
    }

    // ========================================================================
    // error_code → 类型化错误映射测试
    // ========================================================================

    #[tokio::test]
    async fn test_check_safe_not_safe_maps_to_false() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-safe"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": "NOT_SAFE",
                "message": "MFA_TOTP_REQUIRED"
            })))
            .mount(&server)
            .await;

        // 与 embedded 语义对齐：NOT_SAFE → Ok(false)
        assert!(!remote.check_safe("token").await.unwrap());
    }

    #[tokio::test]
    async fn test_check_disable_service_maps_to_true() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-disable"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": "DISABLE_SERVICE",
                "message": "账号已被封禁"
            })))
            .mount(&server)
            .await;

        // 与 embedded 语义对齐：DISABLE_SERVICE → Ok(true)
        assert!(remote.check_disable("token").await.unwrap());
    }

    #[tokio::test]
    async fn test_api_error_maps_to_typed_error_with_message() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": "EXPIRED_TOKEN",
                "message": "token 已过期"
            })))
            .mount(&server)
            .await;

        let result = remote.check_login("token").await;
        match result {
            Err(GarrisonError::ExpiredToken(msg)) => {
                // 服务端 message 必须保留
                assert!(
                    msg.contains("token 已过期"),
                    "message 应保留，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 ExpiredToken 错误，实际: {:?}", other),
            Ok(_) => panic!("期望 Err，实际 Ok"),
        }
    }

    #[tokio::test]
    async fn test_unknown_api_error_keeps_prefix_convention() {
        let (server, remote) = setup_remote().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": "SOME_FUTURE_CODE",
                "message": "未来新增的错误"
            })))
            .mount(&server)
            .await;

        match remote.check_login("token").await {
            Err(GarrisonError::Network(msg)) => {
                assert!(
                    msg.contains("backend-api-error::SOME_FUTURE_CODE::未来新增的错误"),
                    "未知码应保留 backend-api-error::CODE::MESSAGE 前缀约定，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => panic!("期望 Err，实际 Ok"),
        }
    }
}
