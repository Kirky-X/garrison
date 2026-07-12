//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BulwarkAuthServer 端到端集成测试（T110/T111）。
//!
//! 测试流程：
//! 1. 创建 MockAuthBackend（实现 AuthBackend trait）
//! 2. 使用随机端口启动 BulwarkAuthServer
//! 3. 使用 reqwest::Client 调用 HTTP 端点
//! 4. 验证响应
//!
//! # 测试覆盖
//!
//! - 外网端点：login / logout / refresh
//! - 内网端点：check-login / get-token-info / health 等
//! - 中间件：rate_limit / api_key_auth / audit_log
//! - 错误响应：401（无 API Key）/ 429（限速）/ 错误码映射

#![cfg(feature = "auth-server")]

use async_trait::async_trait;
use bulwark::backend::types::{LoginParams, SessionData, TokenInfo};
use bulwark::backend::AuthBackend;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::server::BulwarkAuthServer;
use std::collections::HashMap;
use std::sync::Arc;

/// 测试用 Mock AuthBackend。
///
/// 使用 in-memory HashMap 存储已登录的 token，模拟简单的登录/校验流程。
struct MockAuthBackend {
    tokens: parking_lot::Mutex<HashMap<String, String>>,
}

impl MockAuthBackend {
    fn new() -> Self {
        Self {
            tokens: parking_lot::Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl AuthBackend for MockAuthBackend {
    async fn login(&self, login_id: &str, _params: &LoginParams) -> BulwarkResult<String> {
        let token = format!("token-{}-{}", login_id, uuid_like());
        self.tokens
            .lock()
            .insert(token.clone(), login_id.to_string());
        Ok(token)
    }

    async fn logout(&self, token: &str) -> BulwarkResult<()> {
        self.tokens.lock().remove(token);
        Ok(())
    }

    async fn check_login(&self, token: &str) -> BulwarkResult<bool> {
        Ok(self.tokens.lock().contains_key(token))
    }

    async fn check_permission(&self, token: &str, _permission: &str) -> BulwarkResult<()> {
        if !self.tokens.lock().contains_key(token) {
            return Err(BulwarkError::InvalidToken("token 无效".to_string()));
        }
        Ok(())
    }

    async fn check_role(&self, token: &str, _role: &str) -> BulwarkResult<()> {
        if !self.tokens.lock().contains_key(token) {
            return Err(BulwarkError::InvalidToken("token 无效".to_string()));
        }
        Ok(())
    }

    async fn check_safe(&self, _token: &str) -> BulwarkResult<bool> {
        Ok(false)
    }

    async fn check_disable(&self, _token: &str) -> BulwarkResult<bool> {
        Ok(false)
    }

    async fn check_api_key(&self, api_key: &str, _namespace: &str) -> BulwarkResult<()> {
        if api_key == "invalid" {
            return Err(BulwarkError::InvalidToken("API Key 无效".to_string()));
        }
        Ok(())
    }

    async fn get_token_info(&self, token: &str) -> BulwarkResult<TokenInfo> {
        if !self.tokens.lock().contains_key(token) {
            return Err(BulwarkError::InvalidToken("token 无效".to_string()));
        }
        Ok(TokenInfo {
            token: token.to_string(),
            created_at: 1000,
            last_active_at: 2000,
        })
    }

    async fn get_session(&self, token: &str) -> BulwarkResult<SessionData> {
        let login_id = self
            .tokens
            .lock()
            .get(token)
            .cloned()
            .ok_or_else(|| BulwarkError::InvalidToken("token 无效".to_string()))?;
        Ok(SessionData {
            token: token.to_string(),
            login_id,
            created_at: 1000,
            last_active_at: 2000,
            attrs: HashMap::new(),
            device: None,
            ip: None,
            user_agent: None,
            safe_services: HashMap::new(),
        })
    }

    async fn kickout(&self, login_id: &str) -> BulwarkResult<()> {
        let mut tokens = self.tokens.lock();
        tokens.retain(|_, v| v != login_id);
        Ok(())
    }

    async fn switch_to(&self, token: &str, target_login_id: &str) -> BulwarkResult<()> {
        let mut tokens = self.tokens.lock();
        if let Some(v) = tokens.get_mut(token) {
            *v = target_login_id.to_string();
            Ok(())
        } else {
            Err(BulwarkError::InvalidToken("token 无效".to_string()))
        }
    }

    async fn renew_to_equivalent(&self, token: &str) -> BulwarkResult<String> {
        let login_id = self
            .tokens
            .lock()
            .get(token)
            .cloned()
            .ok_or_else(|| BulwarkError::InvalidToken("token 无效".to_string()))?;
        let new_token = format!("token-{}-{}", login_id, uuid_like());
        let mut tokens = self.tokens.lock();
        tokens.remove(token);
        tokens.insert(new_token.clone(), login_id);
        Ok(new_token)
    }
}

/// 生成一个简单的伪 UUID（不依赖 uuid crate）。
fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos)
}

/// 启动测试服务器，返回 (external_url, internal_url, server_handle)。
///
/// 使用随机端口避免冲突。
async fn start_test_server(
    rate_limit: u32,
    api_key: &str,
) -> (String, String, tokio::task::JoinHandle<()>) {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend::new());

    // 绑定随机端口
    let external_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let external_port = external_listener.local_addr().unwrap().port();
    let internal_port = internal_listener.local_addr().unwrap().port();

    let external_url = format!("http://127.0.0.1:{}", external_port);
    let internal_url = format!("http://127.0.0.1:{}", internal_port);

    let server = BulwarkAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        .with_internal_api_key(api_key);

    // 分别构建 router 并使用已绑定的 listener 启动
    let external_router = server.external_router();
    let internal_router = server.internal_router();

    let handle = tokio::spawn(async move {
        let (ext_res, int_res) = tokio::join!(
            axum::serve(external_listener, external_router),
            axum::serve(internal_listener, internal_router)
        );
        if let Err(e) = ext_res {
            eprintln!("外网服务器异常: {}", e);
        }
        if let Err(e) = int_res {
            eprintln!("内网服务器异常: {}", e);
        }
    });

    // 等待服务器启动
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    (external_url, internal_url, handle)
}

#[tokio::test]
async fn test_external_login_and_check() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    // 通过外网端口登录
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["data"].as_str().unwrap().to_string();
    assert!(token.starts_with("token-user1-"));

    // 通过内网端口校验
    let resp = client
        .post(format!("{}/api/v1/auth/check-login", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], true);
}

#[tokio::test]
async fn test_internal_health_endpoint() {
    let (_external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], "ok");
}

#[tokio::test]
async fn test_internal_rejects_missing_api_key() {
    let (_external_url, internal_url, _handle) = start_test_server(100, "secret-key").await;
    let client = reqwest::Client::new();

    // 不带 X-API-Key 头
    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_internal_rejects_wrong_api_key() {
    let (_external_url, internal_url, _handle) = start_test_server(100, "secret-key").await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .header("x-api-key", "wrong-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_external_logout_invalidates_token() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    // 登录
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["data"].as_str().unwrap().to_string();

    // 登出
    let resp = client
        .post(format!("{}/api/v1/auth/logout", external_url))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 校验 token 已失效
    let resp = client
        .post(format!("{}/api/v1/auth/check-login", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], false);
}

#[tokio::test]
async fn test_external_refresh_returns_new_token() {
    let (external_url, _internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    // 登录
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let old_token = body["data"].as_str().unwrap().to_string();

    // 刷新
    let resp = client
        .post(format!("{}/api/v1/auth/refresh", external_url))
        .json(&serde_json::json!({ "token": old_token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let new_token = body["data"].as_str().unwrap().to_string();
    assert_ne!(old_token, new_token);
}

#[tokio::test]
async fn test_internal_get_token_info() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    // 登录
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["data"].as_str().unwrap().to_string();

    // 获取 token info
    let resp = client
        .post(format!("{}/api/v1/auth/get-token-info", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["token"], token);
    assert_eq!(body["data"]["created_at"], 1000);
}

#[tokio::test]
async fn test_internal_get_session() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    // 登录
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["data"].as_str().unwrap().to_string();

    // 获取 session
    let resp = client
        .post(format!("{}/api/v1/auth/get-session", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["login_id"], "user1");
}

#[tokio::test]
async fn test_internal_kickout() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    // 登录两个 token
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .unwrap();
    let t1: String = resp.json::<serde_json::Value>().await.unwrap()["data"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .unwrap();
    let t2: String = resp.json::<serde_json::Value>().await.unwrap()["data"]
        .as_str()
        .unwrap()
        .to_string();

    // 踢出 user1
    let resp = client
        .post(format!("{}/api/v1/auth/kickout", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "login_id": "user1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 两个 token 都应失效
    for token in [t1, t2] {
        let resp = client
            .post(format!("{}/api/v1/auth/check-login", internal_url))
            .header("x-api-key", "test-key")
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["data"], false);
    }
}

#[tokio::test]
async fn test_external_rate_limit_returns_429() {
    // 限速 2 req/s
    let (external_url, _internal_url, _handle) = start_test_server(2, "test-key").await;
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "login_id": "user1",
        "params": LoginParams::default()
    });

    // 前 2 个请求成功
    for _ in 0..2 {
        let resp = client
            .post(format!("{}/api/v1/auth/login", external_url))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // 第 3 个请求被限速
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
}

#[tokio::test]
async fn test_internal_check_permission_with_invalid_token() {
    let (_external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/auth/check-permission", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": "invalid-token",
            "permission": "user:read"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error_code"], "INVALID_TOKEN");
}

#[tokio::test]
async fn test_internal_switch_to() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    // 登录
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .unwrap();
    let token: String = resp.json::<serde_json::Value>().await.unwrap()["data"]
        .as_str()
        .unwrap()
        .to_string();

    // 切换到 user2
    let resp = client
        .post(format!("{}/api/v1/auth/switch-to", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": token,
            "target_login_id": "user2"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 验证 session 中 login_id 已切换
    let resp = client
        .post(format!("{}/api/v1/auth/get-session", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["login_id"], "user2");
}
