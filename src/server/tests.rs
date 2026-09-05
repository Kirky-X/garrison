//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use super::*;
use crate::backend::types::LoginParams;
use crate::error::GarrisonError;
#[cfg(feature = "oauth2-server")]
use crate::GarrisonDao;
use crate::GarrisonResult;
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

/// 测试用 Mock AuthBackend。
struct MockAuthBackend;

#[async_trait]
impl AuthBackend for MockAuthBackend {
    async fn login(&self, login_id: &str, _params: &LoginParams) -> GarrisonResult<String> {
        Ok(format!("token-{}", login_id))
    }
    async fn logout(&self, _token: &str) -> GarrisonResult<()> {
        Ok(())
    }
    async fn check_login(&self, token: &str) -> GarrisonResult<bool> {
        Ok(token.starts_with("token-"))
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
    async fn get_token_info(
        &self,
        token: &str,
    ) -> GarrisonResult<crate::backend::types::TokenInfo> {
        Ok(crate::backend::types::TokenInfo {
            token: token.to_string(),
            created_at: 1000,
            last_active_at: 2000,
        })
    }
    async fn get_session(&self, token: &str) -> GarrisonResult<crate::backend::types::SessionData> {
        Ok(crate::backend::types::SessionData {
            token: token.to_string(),
            login_id: "mock-user".to_string(),
            created_at: 1000,
            last_active_at: 2000,
            attrs: std::collections::HashMap::new(),
            device: None,
            ip: None,
            user_agent: None,
            safe_services: std::collections::HashMap::new(),
            #[cfg(feature = "session-extra")]
            dynamic_active_timeout: None,
            #[cfg(feature = "session-extra")]
            is_anon: false,
            effective_timeout: None,
        })
    }
    async fn kickout(&self, _login_id: &str) -> GarrisonResult<()> {
        Ok(())
    }
    async fn switch_to(&self, _token: &str, _target_login_id: &str) -> GarrisonResult<()> {
        Ok(())
    }
    async fn renew_to_equivalent(&self, token: &str) -> GarrisonResult<String> {
        Ok(format!("renewed-{}", token))
    }
}

fn make_server() -> GarrisonAuthServer {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    GarrisonAuthServer::new(backend)
        .with_internal_api_key("test-api-key")
        .with_rate_limit(100)
}

#[tokio::test]
async fn test_external_router_handles_login() {
    let server = make_server();
    let app = server.external_router();
    let body = serde_json::json!({
        "login_id": "user1",
        "params": LoginParams::default()
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(resp_json["data"], "token-user1");
}

#[tokio::test]
async fn test_internal_router_handles_health() {
    let server = make_server();
    let app = server.internal_router();
    // health 端点需要 API Key
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/auth/health")
                .header("x-api-key", "test-api-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(resp_json["data"], "ok");
}

#[tokio::test]
async fn test_internal_router_rejects_missing_api_key() {
    let server = make_server();
    let app = server.internal_router();
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/auth/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_external_router_rate_limit() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_internal_api_key("test-api-key")
        .with_rate_limit(2);
    let app = server.external_router();
    let body = serde_json::json!({
        "login_id": "user1",
        "params": LoginParams::default()
    });

    // 前 2 个请求成功
    for _ in 0..2 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // 第 3 个请求被限速
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_builder_methods() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_external_port(9000)
        .with_internal_port(9001)
        .with_rate_limit(50)
        .with_internal_api_key("my-key");

    assert_eq!(server.config.external_port, 9000);
    assert_eq!(server.config.internal_port, 9001);
    assert_eq!(server.config.external_rate_limit_per_ip, 50);
    assert_eq!(server.config.internal_api_key, "my-key");
}

#[tokio::test]
async fn test_default_config() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend);
    assert_eq!(server.config.external_port, 8080);
    assert_eq!(server.config.internal_port, 8081);
    assert_eq!(server.config.external_rate_limit_per_ip, 100);
    assert!(
        server.config.internal_api_key.is_empty(),
        "Default internal_api_key 必须为空（fail-closed，M-SAST-1/M-5）"
    );
}

/// 测试 new_with_kit 通过 AsyncKit 构建后端并创建 server。
#[cfg(feature = "backend-kit")]
#[tokio::test]
async fn test_new_with_kit_builds_server() {
    use crate::backend::BackendModule;
    use trait_kit::kit::AsyncKit;

    let mut kit = AsyncKit::new();
    kit.register::<BackendModule>()
        .expect("register BackendModule failed");
    let kit = kit.build().await.expect("kit build failed");
    let server = GarrisonAuthServer::new_with_kit(kit)
        .await
        .expect("new_with_kit failed");
    // 验证 server 用默认配置创建
    assert_eq!(server.config.external_port, 8080);
    assert_eq!(server.config.internal_port, 8081);
}

/// 测试 new_with_kit 在 kit 未注册 BackendModule 时返回错误。
#[cfg(feature = "backend-kit")]
#[tokio::test]
async fn test_new_with_kit_missing_module_fails() {
    use trait_kit::kit::AsyncKit;

    let kit = AsyncKit::new();
    let kit = kit.build().await.expect("empty build should succeed");
    let result = GarrisonAuthServer::new_with_kit(kit).await;
    assert!(
        result.is_err(),
        "new_with_kit 应在 kit 未注册 BackendModule 时返回错误"
    );
}

/// 测试 with_tls 设置 TLS 配置（feature = "tls"）。
///
/// 验证 with_tls(cert_path, key_path) 后 server.tls_config 含正确的证书/密钥路径。
#[cfg(feature = "tls")]
#[tokio::test]
async fn test_with_tls_sets_config() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend).with_tls("/path/to/cert.pem", "/path/to/key.pem");

    let tls_config = server
        .tls_config
        .as_ref()
        .expect("with_tls 后 tls_config 必须为 Some");
    assert_eq!(
        tls_config.cert_path,
        std::path::PathBuf::from("/path/to/cert.pem")
    );
    assert_eq!(
        tls_config.key_path,
        std::path::PathBuf::from("/path/to/key.pem")
    );
}

/// 测试未调用 with_tls 时 tls_config 为 None（feature = "tls"）。
#[cfg(feature = "tls")]
#[tokio::test]
async fn test_without_tls_config_is_none() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend);
    assert!(
        server.tls_config.is_none(),
        "未调用 with_tls 时 tls_config 必须为 None"
    );
}

/// 测试 with_tls 链式调用不破坏其他 builder 设置（feature = "tls"）。
#[cfg(feature = "tls")]
#[tokio::test]
async fn test_with_tls_chainable() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_external_port(9000)
        .with_internal_port(9001)
        .with_rate_limit(50)
        .with_internal_api_key("my-key")
        .with_tls("/cert.pem", "/key.pem");

    assert_eq!(server.config.external_port, 9000);
    assert_eq!(server.config.internal_port, 9001);
    assert_eq!(server.config.external_rate_limit_per_ip, 50);
    assert_eq!(server.config.internal_api_key, "my-key");
    assert!(server.tls_config.is_some());
}

// ========================================================================
// to_api_response 测试
// ========================================================================

/// 测试 to_api_response 在 Ok 时返回包含数据的成功响应。
#[test]
fn test_to_api_response_ok() {
    let result: Result<i32, GarrisonError> = Ok(42);
    let resp = to_api_response(result);
    assert_eq!(resp.data, Some(42));
    assert!(resp.error_code.is_none());
    assert!(resp.message.is_none());
}

/// 测试 to_api_response 在 Err 时返回包含错误码和消息的失败响应。
#[test]
fn test_to_api_response_err() {
    let result: Result<i32, GarrisonError> = Err(GarrisonError::Internal("test error".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("INTERNAL_ERROR"));
    assert_eq!(resp.message.as_deref(), Some("内部错误"));
}

// ========================================================================
// 路由 path-filter 测试
// ========================================================================

/// 测试外网路由拒绝内网路径（返回 404）。
///
/// external_path_filter 中间件仅放行 login/logout/refresh，
/// 内网端点（如 check/login）应被拦截。
#[tokio::test]
async fn test_external_router_rejects_internal_path() {
    let server = make_server();
    let app = server.external_router();
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/auth/check/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// 测试内网路由拒绝外网路径（返回 404）。
///
/// internal_path_filter 中间件拒绝 login/logout/refresh，
/// 即使携带有效 API Key 也应被拦截。
#[tokio::test]
async fn test_internal_router_rejects_external_path() {
    let server = make_server();
    let app = server.internal_router();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("x-api-key", "test-api-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// 测试内网路由在 API Key 错误时返回 401。
#[tokio::test]
async fn test_internal_router_rejects_wrong_api_key() {
    let server = make_server();
    let app = server.internal_router();
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/auth/health")
                .header("x-api-key", "wrong-api-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ========================================================================
// AuthServerConfig 测试
// ========================================================================

/// 测试 AuthServerConfig::default() 返回正确的默认值。
#[test]
fn test_auth_server_config_default() {
    let config = AuthServerConfig::default();
    assert_eq!(config.external_port, 8080);
    assert_eq!(config.internal_port, 8081);
    assert_eq!(config.external_rate_limit_per_ip, 100);
    assert!(
        config.internal_api_key.is_empty(),
        "Default internal_api_key 必须为空（fail-closed）"
    );
}

// ========================================================================
// listen() 测试（覆盖 listen 方法的主要代码路径）
// ========================================================================

/// 测试 listen 在未配置 `internal_api_key` 时被 `validate()` 短路（fail-closed）。
///
/// 注意：本测试**不**触达端口绑定路径。`listen()` 首行调用
/// `self.config.validate()`，因 `internal_api_key` 为空直接返回 Config 错误，
/// 外网端口即使被占用也不会触发 bind 失败。
/// 真正覆盖 bind 失败路径的测试见 `test_listen_bind_failure_external_port_with_valid_config`。
#[tokio::test]
async fn test_listen_validates_config_first_external() {
    // 占用外网端口（但 validate 短路，此占用无实际影响）
    let external_listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .expect("绑定测试端口应成功");
    let external_port = external_listener
        .local_addr()
        .expect("获取端口应成功")
        .port();

    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    // 未调用 with_internal_api_key → validate 失败，listen 在 bind 前短路
    let server = GarrisonAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(0); // 内网用随机端口

    let result = server.listen().await;
    assert!(
        matches!(&result, Err(GarrisonError::Config(msg)) if msg.contains("server-internal-api-key-missing")),
        "未配置 internal_api_key 时 listen 应返回 Config 错误（validate 短路），实际: {:?}",
        result
    );
    // external_listener 在函数结束时 drop
}

/// 测试 listen 在未配置 `internal_api_key` 时被 `validate()` 短路（内网端口场景）。
///
/// 与 `test_listen_validates_config_first_external` 对称，覆盖内网端口场景。
/// 注意：错误来源是 validate 校验而非 bind 失败。
#[tokio::test]
async fn test_listen_validates_config_first_internal() {
    let internal_listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .expect("绑定测试端口应成功");
    let internal_port = internal_listener
        .local_addr()
        .expect("获取端口应成功")
        .port();

    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    // 未调用 with_internal_api_key → validate 失败，listen 在 bind 前短路
    let server = GarrisonAuthServer::new(backend)
        .with_external_port(0) // 外网用随机端口
        .with_internal_port(internal_port);

    let result = server.listen().await;
    assert!(
        matches!(&result, Err(GarrisonError::Config(msg)) if msg.contains("server-internal-api-key-missing")),
        "未配置 internal_api_key 时 listen 应返回 Config 错误（validate 短路），实际: {:?}",
        result
    );
}

/// 测试 listen 成功启动后持续运行（不立即返回）。
///
/// 使用 tokio::select! 在 listen 和 sleep 之间竞争，
/// 如果 listen 在 300ms 内未返回，说明服务器已成功启动。
#[tokio::test]
async fn test_listen_starts_and_runs() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_external_port(0)
        .with_internal_port(0)
        .with_internal_api_key("test-api-key");

    tokio::select! {
        result = server.listen() => {
            panic!("listen 不应在 300ms 内返回: {:?}", result);
        },
        _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => {
            // listen 在正常运行中，测试通过
        },
    }
}

/// 测试 listen 在 TLS 证书文件不存在时返回错误（feature = "tls"）。
///
/// 设置不存在的证书路径，listen 内部 TLS 配置加载失败 → 返回错误。
#[cfg(feature = "tls")]
#[tokio::test]
async fn test_listen_tls_returns_error_when_cert_not_found() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_external_port(0)
        .with_internal_port(0)
        .with_tls("/nonexistent/cert.pem", "/nonexistent/key.pem");

    let result = server.listen().await;
    assert!(result.is_err(), "TLS 证书不存在时 listen 应返回错误");
}

// ========================================================================
// to_api_response 补充测试（覆盖更多 GarrisonError 变体）
// ========================================================================

/// 测试 to_api_response 处理 NotLogin 错误（401 + NOT_LOGIN）。
#[test]
fn test_to_api_response_with_not_login_error() {
    let result: Result<i32, GarrisonError> =
        Err(GarrisonError::NotLogin("not logged in".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("NOT_LOGIN"));
    assert_eq!(resp.message.as_deref(), Some("未登录"));
}

/// 测试 to_api_response 处理 Dao 错误（500 + DAO_ERROR）。
#[test]
fn test_to_api_response_with_dao_error() {
    let result: Result<i32, GarrisonError> =
        Err(GarrisonError::Dao("db connection failed".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("DAO_ERROR"));
    assert_eq!(resp.message.as_deref(), Some("数据访问错误"));
}

/// 测试 to_api_response 处理 InvalidParam 错误（400 + INVALID_PARAM）。
#[test]
fn test_to_api_response_with_invalid_param_error() {
    let result: Result<i32, GarrisonError> =
        Err(GarrisonError::InvalidParam("missing field".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("INVALID_PARAM"));
    assert_eq!(resp.message.as_deref(), Some("参数无效"));
}

/// 测试 to_api_response 处理 NotPermission 错误（403 + NOT_PERMISSION）。
#[test]
fn test_to_api_response_with_not_permission_error() {
    let result: Result<i32, GarrisonError> =
        Err(GarrisonError::NotPermission("admin:read".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("NOT_PERMISSION"));
    assert_eq!(resp.message.as_deref(), Some("无权限"));
}

/// 测试 to_api_response 处理 ExpiredToken 错误（401 + EXPIRED_TOKEN）。
#[test]
fn test_to_api_response_with_expired_token_error() {
    let result: Result<i32, GarrisonError> =
        Err(GarrisonError::ExpiredToken("token-abc".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("EXPIRED_TOKEN"));
    assert_eq!(resp.message.as_deref(), Some("Token 已过期"));
}

// ========================================================================
// to_api_response 补充测试（覆盖剩余 GarrisonError 变体）
// ========================================================================

/// 测试 to_api_response 处理 NotRole 错误（403 + NOT_ROLE）。
#[test]
fn test_to_api_response_with_not_role_error() {
    let result: Result<i32, GarrisonError> = Err(GarrisonError::NotRole("admin".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("NOT_ROLE"));
    assert_eq!(resp.message.as_deref(), Some("无角色"));
}

/// 测试 to_api_response 处理 InvalidToken 错误（401 + INVALID_TOKEN）。
#[test]
fn test_to_api_response_with_invalid_token_error() {
    let result: Result<i32, GarrisonError> =
        Err(GarrisonError::InvalidToken("bad-format".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("INVALID_TOKEN"));
    assert_eq!(resp.message.as_deref(), Some("Token 无效"));
}

/// 测试 to_api_response 处理 TokenRevoked 错误（401 + TOKEN_REVOKED）。
#[test]
fn test_to_api_response_with_token_revoked_error() {
    let result: Result<i32, GarrisonError> =
        Err(GarrisonError::TokenRevoked("revoked-token".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("TOKEN_REVOKED"));
    assert_eq!(resp.message.as_deref(), Some("Token 已吊销"));
}

/// 测试 to_api_response 处理 Config 错误（500 + CONFIG_ERROR）。
#[test]
fn test_to_api_response_with_config_error() {
    let result: Result<i32, GarrisonError> =
        Err(GarrisonError::Config("invalid config".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("CONFIG_ERROR"));
    assert_eq!(resp.message.as_deref(), Some("配置错误"));
}

/// 测试 to_api_response 处理 Session 错误（500 + SESSION_ERROR）。
#[test]
fn test_to_api_response_with_session_error() {
    let result: Result<i32, GarrisonError> =
        Err(GarrisonError::Session("session expired".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("SESSION_ERROR"));
    assert_eq!(resp.message.as_deref(), Some("会话错误"));
}

/// 测试 to_api_response 处理 Network 错误（502 + NETWORK_ERROR）。
#[test]
fn test_to_api_response_with_network_error() {
    let result: Result<i32, GarrisonError> = Err(GarrisonError::Network("timeout".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("NETWORK_ERROR"));
    assert_eq!(resp.message.as_deref(), Some("网络错误"));
}

/// 测试 to_api_response 处理 NotImplemented 错误（501 + NOT_IMPLEMENTED）。
#[test]
fn test_to_api_response_with_not_implemented_error() {
    let result: Result<i32, GarrisonError> =
        Err(GarrisonError::NotImplemented("not yet".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("NOT_IMPLEMENTED"));
    assert_eq!(resp.message.as_deref(), Some("未实现"));
}

/// 测试 to_api_response 处理 FirewallBlocked 错误（403 + FIREWALL_BLOCKED）。
#[test]
fn test_to_api_response_with_firewall_blocked_error() {
    let result: Result<i32, GarrisonError> =
        Err(GarrisonError::FirewallBlocked("bruteforce".to_string()));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("FIREWALL_BLOCKED"));
    assert_eq!(resp.message.as_deref(), Some("防火墙拦截"));
}

/// 测试 to_api_response 处理 DisableService 错误（403 + DISABLE_SERVICE）。
#[test]
fn test_to_api_response_with_disable_service_error() {
    let result: Result<i32, GarrisonError> = Err(GarrisonError::DisableService {
        service: "default".to_string(),
        until: None,
    });
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("DISABLE_SERVICE"));
    assert_eq!(resp.message.as_deref(), Some("账号已被封禁"));
}

/// 测试 to_api_response 处理 NotSafe 错误（400 + NOT_SAFE）。
#[test]
fn test_to_api_response_with_not_safe_error() {
    let result: Result<i32, GarrisonError> = Err(GarrisonError::NotSafe {
        reason: "MFA_REQUIRED".to_string(),
    });
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("NOT_SAFE"));
    assert_eq!(resp.message.as_deref(), Some("未完成二次认证"));
}

/// 测试 to_api_response 处理 SmsRateLimitExceeded 错误（429 + SMS_RATE_LIMIT_EXCEEDED）。
#[test]
fn test_to_api_response_with_sms_rate_limit_exceeded_error() {
    let result: Result<i32, GarrisonError> = Err(GarrisonError::SmsRateLimitExceeded {
        window: "hourly".to_string(),
    });
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("SMS_RATE_LIMIT_EXCEEDED"));
    assert_eq!(resp.message.as_deref(), Some("短信发送频繁"));
}

/// 测试 to_api_response 处理 SmsVerifyMaxAttempts 错误（400 + SMS_VERIFY_MAX_ATTEMPTS）。
#[test]
fn test_to_api_response_with_sms_verify_max_attempts_error() {
    let result: Result<i32, GarrisonError> = Err(GarrisonError::SmsVerifyMaxAttempts);
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("SMS_VERIFY_MAX_ATTEMPTS"));
    assert_eq!(resp.message.as_deref(), Some("验证码尝试次数超限"));
}

/// 测试 to_api_response 处理 SmsCodeNotFound 错误（400 + SMS_CODE_NOT_FOUND）。
#[test]
fn test_to_api_response_with_sms_code_not_found_error() {
    let result: Result<i32, GarrisonError> = Err(GarrisonError::SmsCodeNotFound);
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("SMS_CODE_NOT_FOUND"));
    assert_eq!(resp.message.as_deref(), Some("验证码不存在或已过期"));
}

/// 测试 to_api_response 处理 SmsChannelRecycled 错误（403 + SMS_CHANNEL_RECYCLED）。
#[test]
fn test_to_api_response_with_sms_channel_recycled_error() {
    let result: Result<i32, GarrisonError> = Err(GarrisonError::SmsChannelRecycled);
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("SMS_CHANNEL_RECYCLED"));
    assert_eq!(resp.message.as_deref(), Some("短信通道已回收"));
}

/// 测试 to_api_response 处理 Exception(code=-1) 错误（401 + NOT_LOGIN + exception_code）。
#[test]
fn test_to_api_response_with_exception_not_login() {
    use crate::exception::GarrisonException;
    let result: Result<i32, GarrisonError> = Err(GarrisonError::Exception(Box::new(
        GarrisonException::new(-1, "请先登录"),
    )));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("NOT_LOGIN"));
    assert_eq!(resp.message.as_deref(), Some("未登录"));
}

/// 测试 to_api_response 处理 Exception(code=-2) 错误（403 + NOT_PERMISSION + exception_code）。
#[test]
fn test_to_api_response_with_exception_not_permission() {
    use crate::exception::GarrisonException;
    let result: Result<i32, GarrisonError> = Err(GarrisonError::Exception(Box::new(
        GarrisonException::new(-2, "无权限"),
    )));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("NOT_PERMISSION"));
    assert_eq!(resp.message.as_deref(), Some("无权限"));
}

/// 测试 to_api_response 处理 Exception(其他 code) 错误（500 + EXCEPTION + exception_code）。
#[test]
fn test_to_api_response_with_exception_other_code() {
    use crate::exception::GarrisonException;
    let result: Result<i32, GarrisonError> = Err(GarrisonError::Exception(Box::new(
        GarrisonException::new(1001, "业务异常"),
    )));
    let resp = to_api_response(result);
    assert!(resp.data.is_none());
    assert_eq!(resp.error_code.as_deref(), Some("EXCEPTION"));
    assert_eq!(resp.message.as_deref(), Some("业务异常"));
}

// ========================================================================
// 限速边缘条件测试
// ========================================================================

/// 测试 rate_limit(0) 时所有外网请求被限速（429）。
///
/// capacity=0 时 token bucket 初始为空，无令牌可消耗 → 所有请求 429。
#[tokio::test]
async fn test_rate_limit_zero_rejects_all_requests() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_internal_api_key("test-api-key")
        .with_rate_limit(0);
    let app = server.external_router();
    let body = serde_json::json!({
        "login_id": "user1",
        "params": LoginParams::default()
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limit=0 时所有请求应被限速"
    );
}

/// 测试空 API Key 时内网请求被拒绝（401）。
///
/// with_internal_api_key("") 设置空 key，api_key_auth_middleware 应拒绝所有请求。
#[tokio::test]
async fn test_empty_internal_api_key_rejects_all() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_internal_api_key("")
        .with_rate_limit(100);
    let app = server.internal_router();
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/auth/health")
                .header("x-api-key", "")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "空 API Key 应拒绝所有内网请求"
    );
}

// ========================================================================
// OAuth2 路由集成测试（feature = "oauth2-server"）
// ========================================================================

/// 简化 Mock DAO，仅实现 GarrisonDao 的 5 个必需方法。
#[cfg(feature = "oauth2-server")]
struct SimpleMockDao;

#[cfg(feature = "oauth2-server")]
#[async_trait]
impl GarrisonDao for SimpleMockDao {
    async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
        Ok(None)
    }
    async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
        Ok(())
    }
    async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
        Ok(())
    }
    async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
        Ok(())
    }
    async fn delete(&self, _key: &str) -> GarrisonResult<()> {
        Ok(())
    }
    crate::atomic_test_fallback!();
}

/// 简化 Mock OAuth2ClientStore，仅实现 trait 的 5 个方法。
#[cfg(feature = "oauth2-server")]
struct SimpleMockClientStore;

#[cfg(feature = "oauth2-server")]
#[async_trait]
impl crate::oauth2_server::client::OAuth2ClientStore for SimpleMockClientStore {
    async fn create(
        &self,
        _client: crate::oauth2_server::client::OAuth2Client,
    ) -> GarrisonResult<()> {
        Ok(())
    }
    async fn get(
        &self,
        _client_id: &str,
    ) -> GarrisonResult<Option<crate::oauth2_server::client::OAuth2Client>> {
        Ok(None)
    }
    async fn update(
        &self,
        _client: crate::oauth2_server::client::OAuth2Client,
    ) -> GarrisonResult<()> {
        Ok(())
    }
    async fn delete(&self, _client_id: &str) -> GarrisonResult<()> {
        Ok(())
    }
    async fn list(&self) -> GarrisonResult<Vec<crate::oauth2_server::client::OAuth2Client>> {
        Ok(Vec::new())
    }
}

/// 测试 with_oauth2 设置 oauth2_state 后 external_router 包含 OAuth2 端点。
///
/// 验证 /oauth2/token 端点不再返回 404（而是返回 OAuth2 handler 的响应）。
#[cfg(feature = "oauth2-server")]
#[tokio::test]
async fn test_external_router_includes_oauth2_routes_when_set() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(SimpleMockDao);
    let store: Arc<dyn crate::oauth2_server::client::OAuth2ClientStore> =
        Arc::new(SimpleMockClientStore);
    let oauth2_state = Arc::new(oauth2_routes::OAuth2State::new(
        store,
        dao,
        "http://localhost/login".to_string(),
    ));

    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_internal_api_key("test-api-key")
        .with_rate_limit(100)
        .with_oauth2(oauth2_state);

    let app = server.external_router();

    // /oauth2/authorize 端点应存在（不再 404，而是返回 OAuth2 handler 响应）
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth2/authorize?response_type=code&client_id=test&redirect_uri=http://localhost/cb&code_challenge=test&code_challenge_method=S256&state=xyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // 不应返回 404（路由存在），具体状态码由 OAuth2 handler 决定
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "with_oauth2 设置后 /oauth2/authorize 端点应存在"
    );
}

/// 测试 with_oauth2 设置 oauth2_state 后 internal_router 包含 OAuth2 introspect 端点。
#[cfg(feature = "oauth2-server")]
#[tokio::test]
async fn test_internal_router_includes_oauth2_routes_when_set() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(SimpleMockDao);
    let store: Arc<dyn crate::oauth2_server::client::OAuth2ClientStore> =
        Arc::new(SimpleMockClientStore);
    let oauth2_state = Arc::new(oauth2_routes::OAuth2State::new(
        store,
        dao,
        "http://localhost/login".to_string(),
    ));

    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_internal_api_key("test-api-key")
        .with_rate_limit(100)
        .with_oauth2(oauth2_state);

    let app = server.internal_router();

    // /oauth2/introspect 端点应存在（不再 404）
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/introspect")
                .header("x-api-key", "test-api-key")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"token":"test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "with_oauth2 设置后 /oauth2/introspect 端点应存在"
    );
}

/// 测试未设置 oauth2_state 时 external_router 不包含 OAuth2 端点（404）。
#[cfg(feature = "oauth2-server")]
#[tokio::test]
async fn test_external_router_excludes_oauth2_routes_when_not_set() {
    let server = make_server();
    let app = server.external_router();
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth2/authorize")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "未设置 oauth2_state 时 /oauth2/authorize 应返回 404"
    );
}

/// 测试未设置 oauth2_state 时 internal_router 不包含 OAuth2 端点（404）。
#[cfg(feature = "oauth2-server")]
#[tokio::test]
async fn test_internal_router_excludes_oauth2_routes_when_not_set() {
    let server = make_server();
    let app = server.internal_router();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/introspect")
                .header("x-api-key", "test-api-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "未设置 oauth2_state 时 /oauth2/introspect 应返回 404"
    );
}

/// 测试 with_oauth2 链式调用不破坏其他 builder 设置。
#[cfg(feature = "oauth2-server")]
#[tokio::test]
async fn test_with_oauth2_chainable() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(SimpleMockDao);
    let store: Arc<dyn crate::oauth2_server::client::OAuth2ClientStore> =
        Arc::new(SimpleMockClientStore);
    let oauth2_state = Arc::new(oauth2_routes::OAuth2State::new(
        store,
        dao,
        "http://localhost/login".to_string(),
    ));

    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_external_port(9000)
        .with_internal_port(9001)
        .with_rate_limit(50)
        .with_internal_api_key("my-key")
        .with_oauth2(oauth2_state);

    assert_eq!(server.config.external_port, 9000);
    assert_eq!(server.config.internal_port, 9001);
    assert_eq!(server.config.external_rate_limit_per_ip, 50);
    assert_eq!(server.config.internal_api_key, "my-key");
    assert!(
        server.oauth2_state.is_some(),
        "with_oauth2 后 oauth2_state 必须为 Some"
    );
}

// ========================================================================
// builder 边缘条件测试
// ========================================================================

/// 测试 with_rate_limit 设置极大值时正常工作。
#[tokio::test]
async fn test_with_rate_limit_large_value() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_internal_api_key("test-api-key")
        .with_rate_limit(u32::MAX);
    assert_eq!(server.config.external_rate_limit_per_ip, u32::MAX);
}

/// 测试 with_internal_api_key 接受 &str 和 String。
#[tokio::test]
async fn test_with_internal_api_key_accepts_str_and_string() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);

    // &str
    let server1 = GarrisonAuthServer::new(backend.clone()).with_internal_api_key("str-key");
    assert_eq!(server1.config.internal_api_key, "str-key");

    // String
    let server2 = GarrisonAuthServer::new(backend).with_internal_api_key("string-key".to_string());
    assert_eq!(server2.config.internal_api_key, "string-key");
}

// ========================================================================
// body limit 配置测试
// ========================================================================

/// AuthServerConfig 默认 body limit 值正确（外网 256KB、内网 1MB）。
#[tokio::test]
async fn test_default_body_limits() {
    let config = AuthServerConfig::default();
    assert_eq!(config.external_body_limit, 256 * 1024, "外网默认应为 256KB");
    assert_eq!(config.internal_body_limit, 1024 * 1024, "内网默认应为 1MB");
}

/// builder 方法可覆盖默认 body limit 值。
#[tokio::test]
async fn test_with_body_limits() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_external_body_limit(512 * 1024)
        .with_internal_body_limits(2 * 1024 * 1024);
    assert_eq!(server.config.external_body_limit, 512 * 1024);
    assert_eq!(server.config.internal_body_limit, 2 * 1024 * 1024);
}

// ========================================================================
// 覆盖率补测：listen 校验失败 / 真实 bind 失败分支 / builder 补充 / 租户解析器两态
// ========================================================================

/// 测试 listen 在 `internal_api_key` 未配置时被 config validate 短路（fail-closed）。
///
/// 覆盖 `listen()` 首行 `self.config.validate().map_err(GarrisonError::Config)?`
/// 错误分支：校验失败时不进入端口绑定，直接返回 Config 错误。
#[tokio::test]
async fn test_listen_validate_fails_when_internal_api_key_empty() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    // 不调用 with_internal_api_key → 默认空串 → validate 失败
    let server = GarrisonAuthServer::new(backend)
        .with_external_port(0)
        .with_internal_port(0);

    let result = server.listen().await;
    assert!(
        matches!(result, Err(GarrisonError::Config(ref msg)) if msg.contains("server-internal-api-key-missing")),
        "空 internal_api_key 时 listen 应返回 Config 错误，实际: {:?}",
        result
    );
}

/// 测试 listen 在配置合法且外网端口被占用时返回 bind 错误。
///
/// 与 `test_listen_validates_config_first_external` 的区别：本测试设置
/// 了合法 api_key，validate 通过后真正进入 tokio::spawn 的 bind 路径，覆盖
/// 外网 `TcpListener::bind` 失败分支与 select 的 external 错误臂。
#[tokio::test]
async fn test_listen_bind_failure_external_port_with_valid_config() {
    let external_listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .expect("占用测试端口应成功");
    let external_port = external_listener.local_addr().unwrap().port();

    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(0)
        .with_internal_api_key("test-api-key");

    let result = server.listen().await;
    assert!(
        matches!(result, Err(GarrisonError::Internal(ref msg)) if msg.contains("server-external-bind")),
        "外网端口被占用应返回 server-external-bind 错误，实际: {:?}",
        result
    );
}

/// 测试 listen 在配置合法且内网端口被占用时返回 bind 错误。
///
/// 覆盖内网 `TcpListener::bind` 失败分支与 select 的 internal 错误臂
///（M-1：internal 失败时显式 abort external task）。
#[tokio::test]
async fn test_listen_bind_failure_internal_port_with_valid_config() {
    let internal_listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .expect("占用测试端口应成功");
    let internal_port = internal_listener.local_addr().unwrap().port();

    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_external_port(0)
        .with_internal_port(internal_port)
        .with_internal_api_key("test-api-key");

    let result = server.listen().await;
    assert!(
        matches!(result, Err(GarrisonError::Internal(ref msg)) if msg.contains("server-internal-bind")),
        "内网端口被占用应返回 server-internal-bind 错误，实际: {:?}",
        result
    );
}

/// 测试 with_trusted_proxies / with_rate_limit_max_entries builder 存储配置。
#[tokio::test]
async fn test_with_trusted_proxies_and_rate_limit_max_entries() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let proxies = ["127.0.0.1".parse::<std::net::IpAddr>().unwrap()].to_vec();
    let server = GarrisonAuthServer::new(backend)
        .with_trusted_proxies(proxies.clone())
        .with_rate_limit_max_entries(1234);

    assert_eq!(server.config.rate_limit_trusted_proxies, proxies);
    assert_eq!(server.config.rate_limit_max_entries, 1234);
}

/// 测试 with_tenant_resolver 两态（feature = "tenant-isolation"）：
/// 默认 `None`（不挂载租户中间件），`Some(..)` 时 external / internal 路由
/// 均挂载租户解析中间件（路由可正常构建）。
#[cfg(feature = "tenant-isolation")]
#[tokio::test]
async fn test_with_tenant_resolver_states_none_and_some() {
    use crate::context::tenant::HeaderTenantResolver;

    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);

    // None 态（默认）
    let server_none = GarrisonAuthServer::new(backend.clone())
        .with_internal_api_key("test-api-key")
        .with_rate_limit(100);
    assert!(
        server_none.tenant_resolver.is_none(),
        "默认不应注入租户解析器"
    );
    // None 态路由构建不受影响
    let _ = server_none.external_router();
    let _ = server_none.internal_router();

    // Some 态
    let server_some = GarrisonAuthServer::new(backend)
        .with_internal_api_key("test-api-key")
        .with_rate_limit(100)
        .with_tenant_resolver(Some(Arc::new(HeaderTenantResolver)));
    assert!(
        server_some.tenant_resolver.is_some(),
        "with_tenant_resolver(Some(..)) 后应持有解析器"
    );
    // Some 态下 external / internal 路由挂载租户中间件后仍可构建
    let _ = server_some.external_router();
    let _ = server_some.internal_router();
}

/// 测试 with_oauth2 + with_tenant_resolver 组合：OAuth2 router merge 前单独
/// 注入租户中间件（axum merge 不合并 layer），external / internal 端点均可达。
#[cfg(all(feature = "tenant-isolation", feature = "oauth2-server"))]
#[tokio::test]
async fn test_oauth2_with_tenant_resolver_routes_reachable() {
    use crate::context::tenant::HeaderTenantResolver;

    let dao: Arc<dyn GarrisonDao> = Arc::new(SimpleMockDao);
    let store: Arc<dyn crate::oauth2_server::client::OAuth2ClientStore> =
        Arc::new(SimpleMockClientStore);
    let oauth2_state = Arc::new(oauth2_routes::OAuth2State::new(
        store,
        dao,
        "http://localhost/login".to_string(),
    ));

    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
    let server = GarrisonAuthServer::new(backend)
        .with_internal_api_key("test-api-key")
        .with_rate_limit(100)
        .with_tenant_resolver(Some(Arc::new(HeaderTenantResolver)))
        .with_oauth2(oauth2_state);

    let external_app = server.external_router();
    let internal_app = server.internal_router();

    // external：带合法租户头的 authorize 请求不被租户中间件阻断
    //（SimpleMockClientStore 无注册客户端 → OAuth2 handler 返回业务错误 400；
    // 若租户中间件缺失/解析失败则表现为 404/500，均视为路由装配失败）
    let resp = external_app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth2/authorize?response_type=code&client_id=test")
                .header("x-tenant-id", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "oauth2 + 租户中间件组合下 /oauth2/authorize 应存在"
    );
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "合法租户头不应被租户中间件拒绝（500），实际: {status}"
    );
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "合法租户头不应触发 401，实际: {status}"
    );

    // internal：introspect 端点在租户中间件 + merge 后仍存在（OAuth2 handler
    // 有自己的响应语义，不 404 即证明 merge 与租户中间件注入未破坏路由）
    let resp = internal_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/introspect")
                .header("x-tenant-id", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "oauth2 + 租户中间件组合下 /oauth2/introspect 应存在"
    );
}
