// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! server 域验收。
//!
//! - `GarrisonAuthServer` 外网/内网端点验收（12 个场景）；
//! - oauth2_server 端点级验收（`#[cfg(feature = "oauth2-server")]`）：
//!   authorize 重定向 / token 4 种 grant / revoke / introspect（RFC 6749/7009/7662），
//!   装配参考 `src/oauth2_server/*` 与 `tests/e2e/oauth2_flow.rs`；
//! - auth_server 二进制 smoke（`#[cfg(feature = "auth-server")]`）：
//!   以子进程方式验证 `src/bin/auth_server.rs` 的 env 装配 + listen() 真实启动
//!   与 fail-closed 契约（缺失 / 空串 `GARRISON_INTERNAL_API_KEY` → exit(1)，
//!   端口被占用 → bind 失败 → 非零退出码）。
//!
//! 全局装配同 `tests/auth_server_integration.rs`：随机端口 + `MockAuthBackend`
//!（in-memory token 表，测试替身）经 HTTP 访问真实端点。本域不触碰
//! `GarrisonManager` 全局单例，但按验收域惯例统一 `#[serial]` 串行
//!（与其他域共享测试进程，避免任何潜在的全局登记表串扰）。

use crate::relay::SendRelayRetry;
use async_trait::async_trait;
use garrison::backend::types::{LoginParams, SessionData, TokenInfo};
use garrison::backend::AuthBackend;
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::server::GarrisonAuthServer;
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// MockAuthBackend：AuthBackend trait 测试替身（迁自 tests/auth_server_integration.rs）
// ============================================================================
//
// 仓库内产品 `AuthBackend` 实现（`BackendEmbedded` / `BackendRemote`）需要业务方
// 提供 `GarrisonInterface` 或远程服务，无法在验收域确定性装配；in-memory token
// 表保证断言确定性（`created_at=1000`、`token-<login_id>-` 前缀、INVALID_TOKEN）。
// 沿用原文件标注：产品实现就绪后此替身可替换，断言语义保持不变。

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
    async fn login(&self, login_id: &str, _params: &LoginParams) -> GarrisonResult<String> {
        let token = format!("token-{}-{}", login_id, uuid_like());
        self.tokens
            .lock()
            .insert(token.clone(), login_id.to_string());
        Ok(token)
    }

    async fn logout(&self, token: &str) -> GarrisonResult<()> {
        self.tokens.lock().remove(token);
        Ok(())
    }

    async fn check_login(&self, token: &str) -> GarrisonResult<bool> {
        Ok(self.tokens.lock().contains_key(token))
    }

    async fn check_permission(&self, token: &str, _permission: &str) -> GarrisonResult<()> {
        if !self.tokens.lock().contains_key(token) {
            return Err(GarrisonError::InvalidToken("token 无效".to_string()));
        }
        Ok(())
    }

    async fn check_role(&self, token: &str, _role: &str) -> GarrisonResult<()> {
        if !self.tokens.lock().contains_key(token) {
            return Err(GarrisonError::InvalidToken("token 无效".to_string()));
        }
        Ok(())
    }

    async fn check_safe(&self, _token: &str) -> GarrisonResult<bool> {
        Ok(false)
    }

    async fn check_disable(&self, _token: &str) -> GarrisonResult<bool> {
        Ok(false)
    }

    async fn check_api_key(&self, api_key: &str, _namespace: &str) -> GarrisonResult<()> {
        if api_key == "invalid" {
            return Err(GarrisonError::InvalidToken("API Key 无效".to_string()));
        }
        Ok(())
    }

    async fn get_token_info(&self, token: &str) -> GarrisonResult<TokenInfo> {
        if !self.tokens.lock().contains_key(token) {
            return Err(GarrisonError::InvalidToken("token 无效".to_string()));
        }
        Ok(TokenInfo {
            token: token.to_string(),
            created_at: 1000,
            last_active_at: 2000,
        })
    }

    async fn get_session(&self, token: &str) -> GarrisonResult<SessionData> {
        let login_id = self
            .tokens
            .lock()
            .get(token)
            .cloned()
            .ok_or_else(|| GarrisonError::InvalidToken("token 无效".to_string()))?;
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
            #[cfg(feature = "session-extra")]
            dynamic_active_timeout: None,
            #[cfg(feature = "session-extra")]
            is_anon: false,
            effective_timeout: None,
            amr_ledger: Vec::new(),
            auth_time: None,
        })
    }

    async fn kickout(&self, login_id: &str) -> GarrisonResult<()> {
        let mut tokens = self.tokens.lock();
        tokens.retain(|_, v| v != login_id);
        Ok(())
    }

    async fn switch_to(&self, token: &str, target_login_id: &str) -> GarrisonResult<()> {
        let mut tokens = self.tokens.lock();
        if let Some(v) = tokens.get_mut(token) {
            *v = target_login_id.to_string();
            Ok(())
        } else {
            Err(GarrisonError::InvalidToken("token 无效".to_string()))
        }
    }

    async fn renew_to_equivalent(&self, token: &str) -> GarrisonResult<String> {
        let login_id = self
            .tokens
            .lock()
            .get(token)
            .cloned()
            .ok_or_else(|| GarrisonError::InvalidToken("token 无效".to_string()))?;
        let new_token = format!("token-{}-{}", login_id, uuid_like());
        let mut tokens = self.tokens.lock();
        tokens.remove(token);
        tokens.insert(new_token.clone(), login_id);
        Ok(new_token)
    }
}

/// 生成一个简单的伪 UUID（不依赖 uuid crate，迁自 tests/auth_server_integration.rs）。
fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos)
}

// ============================================================================
// 装配辅助：双端口测试服务器（迁自 tests/auth_server_integration.rs::start_test_server）
// ============================================================================

/// 启动测试服务器，返回 (external_url, internal_url, server_handle)。
///
/// 双端口：外网（login/logout/refresh + OAuth2 外网端点）、
/// 内网（check-*/get-* 等，需 `x-api-key`）。随机端口避免冲突。
async fn start_test_server(
    rate_limit: u32,
    api_key: &str,
) -> (String, String, tokio::task::JoinHandle<()>) {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend::new());

    let external_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let external_port = external_listener.local_addr().unwrap().port();
    let internal_port = internal_listener.local_addr().unwrap().port();

    let external_url = format!("http://127.0.0.1:{}", external_port);
    let internal_url = format!("http://127.0.0.1:{}", internal_port);

    let server = GarrisonAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        // C-1: 验收测试显式开启外网 login（框架默认 404，secure-by-default）
        .with_external_login_enabled(true)
        .with_internal_api_key(api_key);

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

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (external_url, internal_url, handle)
}

/// 经外网端口登录并返回 token（多个场景共用）。
async fn http_login(client: &reqwest::Client, external_url: &str, login_id: &str) -> String {
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": login_id,
            "params": LoginParams::default()
        }))
        .send_relay_retry()
        .await
        .expect("login 请求应送达服务器");
    assert_eq!(resp.status(), 200, "login 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    body["data"].as_str().unwrap().to_string()
}

/// 不跟随重定向的 reqwest 客户端（OAuth2 authorize 302 场景专用——跟随 302
/// 会去解析假域名 `auth.example.com` 而失败；同 tests/e2e 的
/// `make_no_redirect_client` 惯例）。
#[cfg(feature = "oauth2-server")]
fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("构造不重定向 reqwest 客户端失败")
}

/// 经内网端口 check-login 并返回 `data` 字段（多场景共用）。
async fn http_check_login(
    client: &reqwest::Client,
    internal_url: &str,
    api_key: &str,
    token: &str,
) -> serde_json::Value {
    let resp = client
        .post(format!("{}/api/v1/auth/check-login", internal_url))
        .header("x-api-key", api_key)
        .json(&serde_json::json!({ "token": token }))
        .send_relay_retry()
        .await
        .expect("check-login 请求应送达服务器");
    assert_eq!(resp.status(), 200, "check-login 应返回 200");
    resp.json::<serde_json::Value>().await.unwrap()["data"].clone()
}

// ------------------------------------------------------------------------
// 外网 login/logout/refresh + 内网校验（正常）
// ------------------------------------------------------------------------

/// （正常）：外网 login 签发 `token-<login_id>-` 前缀 token，
/// 内网 check-login 经 `X-API-Key` 校验返回 `data=true`。
/// 迁自 tests/auth_server_integration.rs::test_external_login_and_check
#[tokio::test]
#[serial]
async fn acc_srv_001_external_login_and_internal_check() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let token = http_login(&client, &external_url, "user1").await;
    assert!(
        token.starts_with("token-user1-"),
        "token 应带 login_id 前缀"
    );

    assert_eq!(
        http_check_login(&client, &internal_url, "test-key", &token).await,
        serde_json::json!(true),
        "内网 check-login 应校验通过"
    );
}

/// （正常）：内网 health 端点返回 `{"data": "ok"}`。
/// 迁自 tests/auth_server_integration.rs::test_internal_health_endpoint
#[tokio::test]
#[serial]
async fn acc_srv_002_internal_health_endpoint() {
    let (_external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .header("x-api-key", "test-key")
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "health 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], "ok");
}

/// （正常）：外网 logout 使 token 失效——同一 token 的
/// 内网 check-login 返回 `data=false`。
/// 迁自 tests/auth_server_integration.rs::test_external_logout_invalidates_token
#[tokio::test]
#[serial]
async fn acc_srv_003_external_logout_invalidates_token() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let token = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/logout", external_url))
        .json(&serde_json::json!({ "token": token }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "logout 应返回 200");

    assert_eq!(
        http_check_login(&client, &internal_url, "test-key", &token).await,
        serde_json::json!(false),
        "logout 后 token 应失效"
    );
}

/// （正常）：外网 refresh 轮换出新 token（新旧不同）。
/// 迁自 tests/auth_server_integration.rs::test_external_refresh_returns_new_token
#[tokio::test]
#[serial]
async fn acc_srv_004_external_refresh_returns_new_token() {
    let (external_url, _internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let old_token = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/refresh", external_url))
        .json(&serde_json::json!({ "token": old_token }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "refresh 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    let new_token = body["data"].as_str().unwrap().to_string();
    assert_ne!(old_token, new_token, "refresh 应签发新 token");
}

/// （正常）：内网 get-token-info 返回 token 元数据
///（`data.token` 一致、`created_at=1000` 与 mock 契约一致）。
/// GAR-23: 所有权校验强制必填，请求携带与主体一致的 caller_login_id。
/// 迁自 tests/auth_server_integration.rs::test_internal_get_token_info
#[tokio::test]
#[serial]
async fn acc_srv_005_internal_get_token_info() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let token = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/get-token-info", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token, "caller_login_id": "user1" }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["token"], token);
    assert_eq!(body["data"]["created_at"], 1000);
}

/// （正常）：内网 get-session 返回会话主体
///（`data.login_id` 与登录主体一致）。
/// GAR-23: 所有权校验强制必填，请求携带与主体一致的 caller_login_id。
/// 迁自 tests/auth_server_integration.rs::test_internal_get_session
#[tokio::test]
#[serial]
async fn acc_srv_006_internal_get_session() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let token = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/get-session", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token, "caller_login_id": "user1" }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["login_id"], "user1");
}

// ------------------------------------------------------------------------
// 内网 X-API-Key 互斥 / 踢出 / 切换（正常 + 异常）
// ------------------------------------------------------------------------

/// （异常）：内网端点缺少 / 错误的 `X-API-Key` 一律 401。
/// 迁自 tests/auth_server_integration.rs::test_internal_rejects_missing_api_key
/// 与 tests/auth_server_integration.rs::test_internal_rejects_wrong_api_key
#[tokio::test]
#[serial]
async fn acc_srv_007_internal_rejects_missing_and_wrong_api_key() {
    let (_external_url, internal_url, _handle) = start_test_server(100, "secret-key").await;
    let client = reqwest::Client::new();

    // 缺少 X-API-Key
    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "缺 X-API-Key 应返回 401");

    // 错误的 X-API-Key
    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .header("x-api-key", "wrong-key")
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "错误 X-API-Key 应返回 401");
}

/// （正常+异常）：内网 kickout 后同账号全部 token 失效
///（check-login 均为 `data=false`）。
/// 迁自 tests/auth_server_integration.rs::test_internal_kickout
#[tokio::test]
#[serial]
async fn acc_srv_008_internal_kickout_invalidates_all_tokens() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let t1 = http_login(&client, &external_url, "user1").await;
    let t2 = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/kickout", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "login_id": "user1", "caller_login_id": "user1" }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "kickout 应返回 200");

    for token in [t1, t2] {
        assert_eq!(
            http_check_login(&client, &internal_url, "test-key", &token).await,
            serde_json::json!(false),
            "kickout 后 token 应失效"
        );
    }
}

/// （正常）：内网 switch-to 切换会话主体——get-session 反查
/// `login_id` 变为目标主体。
/// 迁自 tests/auth_server_integration.rs::test_internal_switch_to
#[tokio::test]
#[serial]
async fn acc_srv_009_internal_switch_to_changes_session_subject() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let token = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/switch-to", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": token,
            "target_login_id": "user2",
            "caller_login_id": "user1"
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "switch-to 应返回 200");

    let resp = client
        .post(format!("{}/api/v1/auth/get-session", internal_url))
        .header("x-api-key", "test-key")
        // GAR-23: caller_login_id 强制必填；switch-to 后会话主体已是 user2
        .json(&serde_json::json!({ "token": token, "caller_login_id": "user2" }))
        .send_relay_retry()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["login_id"], "user2", "切换后主体应为 user2");
}

// ------------------------------------------------------------------------
// 限速 / 中间件错误码映射 / 内外网路径互斥（异常）
// ------------------------------------------------------------------------

/// （异常）：外网限速——`rate_limit=2` 时第 3 个并发登录请求返回 429。
/// 迁自 tests/auth_server_integration.rs::test_external_rate_limit_returns_429
#[tokio::test]
#[serial]
async fn acc_srv_010_external_rate_limit_returns_429() {
    let (external_url, _internal_url, _handle) = start_test_server(2, "test-key").await;
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "login_id": "user1",
        "params": LoginParams::default()
    });

    for _ in 0..2 {
        let resp = client
            .post(format!("{}/api/v1/auth/login", external_url))
            .json(&body)
            .send_relay_retry()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "限速窗口内请求应成功");
    }

    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&body)
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "超限速应返回 429");
}

/// （异常）：内网 check-permission 对无效 token 返回中间件
/// 错误码映射 `error_code=INVALID_TOKEN`（业务错误以 200 + error_code 表达）。
/// 迁自 tests/auth_server_integration.rs::test_internal_check_permission_with_invalid_token
#[tokio::test]
#[serial]
async fn acc_srv_011_internal_check_permission_invalid_token_error_code() {
    let (_external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/auth/check-permission", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": "invalid-token",
            "permission": "user:read"
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "业务错误以 200 + error_code 表达");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error_code"], "INVALID_TOKEN");
}

/// （异常）：内外网路径互斥——外网端口拒绝内网路径（404）；
/// 内网端口拒绝外网路径 login：带 API Key 时由 path-filter 拒绝（404），
/// 缺 API Key 时由更外层的 api_key_auth 中间件先拒绝（401）。
/// 迁自 tests/auth_server_integration.rs 的 router path-filter 语义
///（外网仅 login/logout/refresh；内网拒绝三者，见 src/server/middleware.rs）。
#[tokio::test]
#[serial]
async fn acc_srv_012_external_internal_paths_mutually_exclusive() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    // 外网调用内网专属端点 → 404
    let resp = client
        .get(format!("{}/api/v1/auth/health", external_url))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "外网端口不应暴露内网端点");

    // 内网调用外网专属端点（带 API Key 通过 api_key_auth → path-filter 拒绝）
    let resp = client
        .post(format!("{}/api/v1/auth/login", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "内网端口不应暴露外网端点");

    // 缺 API Key 时内网登录被外层 api_key_auth 中间件拒绝（先于 path-filter）
    let resp = client
        .post(format!("{}/api/v1/auth/login", internal_url))
        .json(&serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "缺 X-API-Key 内网请求应 401（中间件顺序）"
    );
}

// ------------------------------------------------------------------------
// 安全审计回归（GAR-13/14/23/25/27/28/29）
// ------------------------------------------------------------------------

/// GAR-23（异常→修复后）：内网 get-session / get-token-info 缺失
/// `caller_login_id` 一律 400（fail-closed），不再 warn+放行返回会话。
#[tokio::test]
#[serial]
async fn acc_srv_023_get_session_missing_caller_fail_closed() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();
    let token = http_login(&client, &external_url, "user1").await;

    for uri in ["/api/v1/auth/get-session", "/api/v1/auth/get-token-info"] {
        let resp = client
            .post(format!("{}{}", internal_url, uri))
            .header("x-api-key", "test-key")
            .json(&serde_json::json!({ "token": token }))
            .send_relay_retry()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            400,
            "{uri} 缺失 caller_login_id 应 fail-closed 返回 4xx"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body.get("data").is_none(), "{uri} 拒绝响应不得携带会话数据");
    }

    // 跨用户 caller 仍保持 NOT_PERMISSION 语义（原 A5 契约不变）
    let resp = client
        .post(format!("{}/api/v1/auth/get-session", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": token,
            "caller_login_id": "someone-else"
        }))
        .send_relay_retry()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error_code"], "NOT_PERMISSION");
}

/// GAR-27：外网 login 畸形类型 body 返回统一 JSON 错误体——
/// 不回显内部 Rust 类型名 / 字段名 / 字节偏移，状态码保持 4xx。
#[tokio::test]
#[serial]
async fn acc_srv_024_external_422_rejection_sanitized() {
    let (external_url, _internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .header("content-type", "application/json")
        .body("[1,2,3]".to_string())
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16() / 100, 4, "状态码保持 4xx");
    let text = resp.text().await.unwrap();
    for leaked in [
        "LoginRequest",
        "LoginParams",
        "struct",
        "expected",
        "line",
        "column",
    ] {
        assert!(
            !text.contains(leaked),
            "响应不得泄露 {leaked}，实际: {text}"
        );
    }
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["error"], "bad_request");
}

/// GAR-29：外网 login 读体超限（>256KB）返回 413 统一 JSON 错误体，
/// 不再以空 body 透传出误导性 400 EOF。
#[tokio::test]
#[serial]
async fn acc_srv_025_external_oversize_body_returns_413() {
    let (external_url, _internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let oversize = vec![b'x'; 256 * 1024 + 1];
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .header("content-type", "application/json")
        .body(oversize)
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413, "超限 body 应返回 413");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "payload_too_large");
}

/// GAR-29 残留收口：**非 login** 端点超限 body（>256KB）不再透传 axum 裸
/// 413 text/plain 诊断体，而是与 login 路径统一的 JSON 错误体（refresh 走
/// `DefaultBodyLimit` → `LengthLimitError` 413，由 sanitize 中间件归一）。
#[tokio::test]
#[serial]
async fn acc_srv_034_external_non_login_oversize_body_returns_413_json() {
    let (external_url, _internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let oversize = vec![b'x'; 256 * 1024 + 1];
    let resp = client
        .post(format!("{}/api/v1/auth/refresh", external_url))
        .header("content-type", "application/json")
        .body(oversize)
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413, "超限 body 应保持 413 语义");
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/json",
        "非 login 路径 413 应归一为 JSON 错误体（不再透传 text/plain 诊断）"
    );
    let text = resp.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("413 错误体应为合法 JSON: {e}，实际: {text}"));
    assert_eq!(body["error"], "payload_too_large");
    assert_eq!(body["message"], "request body exceeds size limit");
    assert!(
        !text.contains("buffer"),
        "不得回显 axum 内部诊断，实际: {text}"
    );
}

/// GAR-28：重复 X-API-Key 头（任意顺序组合）一律 401 fail-closed。
#[tokio::test]
#[serial]
async fn acc_srv_026_internal_duplicate_api_key_header_rejected() {
    let (_external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    for (first, second) in [("wrong-key", "test-key"), ("test-key", "wrong-key")] {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            "x-api-key",
            reqwest::header::HeaderValue::from_str(first).unwrap(),
        );
        headers.append(
            "x-api-key",
            reqwest::header::HeaderValue::from_str(second).unwrap(),
        );
        let resp = client
            .get(format!("{}/api/v1/auth/health", internal_url))
            .headers(headers)
            .send_relay_retry()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            401,
            "重复 X-API-Key 头（{first} + {second}）应 fail-closed 401"
        );
    }
}

/// GAR-25：内网 API Key 连续失败达阈值后锁定——窗口内正确 key 也 429
/// 并携带 Retry-After（with_api_key_lockout 显式配置的小阈值）。
#[tokio::test]
#[serial]
async fn acc_srv_027_internal_api_key_lockout_after_threshold() {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend::new());
    let external_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let external_port = external_listener.local_addr().unwrap().port();
    let internal_port = internal_listener.local_addr().unwrap().port();

    let server = GarrisonAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(1000)
        .with_external_login_enabled(true)
        .with_internal_api_key("test-key")
        // 阈值 2：两次失败即锁定，便于验收断言
        .with_api_key_lockout(2, 300);

    let external_url = format!("http://127.0.0.1:{}", external_port);
    let internal_url = format!("http://127.0.0.1:{}", internal_port);
    let external_router = server.external_router();
    let internal_router = server.internal_router();
    let _handle = tokio::spawn(async move {
        let _ = tokio::join!(
            axum::serve(external_listener, external_router),
            axum::serve(internal_listener, internal_router)
        );
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let health_url = format!("{}/api/v1/auth/health", internal_url);

    // 第 1 次失败：401
    let resp = client
        .get(&health_url)
        .header("x-api-key", "wrong")
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "未达阈值仍 401");

    // 第 2 次失败：达阈值即锁定（429 + Retry-After）
    let resp = client
        .get(&health_url)
        .header("x-api-key", "wrong")
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "达阈值请求应返回 429");
    assert!(
        resp.headers().get("retry-after").is_some(),
        "应携带 Retry-After"
    );

    // 锁定窗口内：正确 key 也 429
    let resp = client
        .get(&health_url)
        .header("x-api-key", "test-key")
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "锁定窗口内正确 key 也应 429");
}

/// GAR-13：auth-server 聚合含 web-security-headers 后，token 承载端点
/// 响应携带 Cache-Control: no-store / X-Content-Type-Options / X-Frame-Options。
#[cfg(feature = "web-security-headers")]
#[tokio::test]
#[serial]
async fn acc_srv_028_auth_responses_have_security_headers() {
    let (external_url, _internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let token = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/refresh", external_url))
        .json(&serde_json::json!({ "token": token }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "no-store",
        "GAR-13: token 承载端点应带 Cache-Control: no-store（CWE-525）"
    );
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
}

/// GAR-14：健康探针最小化——外网仅 /healthz 且无版本字段；/readyz 仅内网；
/// 内网 /readyz 默认剥离 checks[].details（GARRISON_HEALTH_DETAILS 未开启）。
#[cfg(feature = "server-health-check")]
#[tokio::test]
#[serial]
async fn acc_srv_029_health_probes_minimized() {
    // readiness 注册表为进程级全局态，先清空保证确定性
    sdforge::health::clear_readiness_checks();
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    // 外网 /healthz：仅 {"status":"healthy"}，无版本字段
    let resp = client
        .get(format!("{}/healthz", external_url))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body,
        serde_json::json!({"status": "healthy"}),
        "外网 healthz 仅含 status，不回显 sdforge 版本号"
    );

    // 外网 /readyz：不暴露
    let resp = client
        .get(format!("{}/readyz", external_url))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "外网端口不应暴露 /readyz");

    // 内网 /readyz：无 API Key 可达（K8s 探针语义），默认无 details
    let resp = client
        .get(format!("{}/readyz", internal_url))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ready");
    if let Some(checks) = body["checks"].as_array() {
        for check in checks {
            assert!(
                check.get("details").is_none(),
                "默认应剥离 details，实际: {check}"
            );
        }
    }
}

// ------------------------------------------------------------------------
// oauth2_server 端点级验收（#[cfg(feature = "oauth2-server")]）
// ------------------------------------------------------------------------
//
// 装配参考 `src/oauth2_server/*` 单元测试 + `tests/e2e/oauth2_flow.rs`：
// `DaoOAuth2ClientStore`（InMemoryDao）+ `OAuth2State` 经
// `GarrisonAuthServer::with_oauth2` 挂载双端口端点：
// 外网 GET /oauth2/authorize、POST /oauth2/token、POST /oauth2/revoke；
// 内网 POST /oauth2/introspect（需 x-api-key）。

/// 经 `GarrisonAuthServer` 启动含 OAuth2 端点的双端口服务器。
///
/// OAuth2State 由调用方装配（其内部 client store 由调用方持有并注册客户端），
/// 返回 (external_url, internal_url, handle)。
#[cfg(feature = "oauth2-server")]
async fn start_test_server_with_oauth2(
    rate_limit: u32,
    api_key: &str,
    state: Arc<garrison::server::oauth2_routes::OAuth2State>,
) -> (String, String, tokio::task::JoinHandle<()>) {
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend::new());

    let external_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let external_port = external_listener.local_addr().unwrap().port();
    let internal_port = internal_listener.local_addr().unwrap().port();

    let external_url = format!("http://127.0.0.1:{}", external_port);
    let internal_url = format!("http://127.0.0.1:{}", internal_port);

    let server = GarrisonAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        // C-1: 验收测试显式开启外网 login（框架默认 404，secure-by-default）
        .with_external_login_enabled(true)
        .with_internal_api_key(api_key)
        .with_oauth2(state);

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

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (external_url, internal_url, handle)
}

/// 默认 OAuth2State：InMemoryDao + 可注册客户端 store（4 端点 handler 全装配）。
#[cfg(feature = "oauth2-server")]
fn default_oauth2_state() -> (
    Arc<garrison::server::oauth2_routes::OAuth2State>,
    Arc<dyn garrison::oauth2_server::client::OAuth2ClientStore>,
) {
    use garrison::dao::{GarrisonDao, InMemoryDao};
    use garrison::oauth2_server::client::{DaoOAuth2ClientStore, OAuth2ClientStore};
    use garrison::server::oauth2_routes::OAuth2State;

    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let store: Arc<dyn OAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
    let state = Arc::new(OAuth2State::new(
        store.clone(),
        dao,
        "https://auth.example.com/login".to_string(),
    ));
    (state, store)
}

/// 创建测试用 OAuth2Client（支持全部 4 种 grant type，scope=["read"]）。
#[cfg(feature = "oauth2-server")]
fn make_full_oauth2_client(id: &str) -> garrison::oauth2_server::client::OAuth2Client {
    use garrison::oauth2_server::client::{GrantType, OAuth2Client};
    OAuth2Client::new(
        id,
        "secret-123",
        vec!["https://app.example.com/cb".into()],
        vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            GrantType::Password,
        ],
        vec!["read".into()],
    )
    .unwrap()
}

/// RFC 7636 Appendix B 测试向量 code_verifier（43 字符，合法长度）。
#[cfg(feature = "oauth2-server")]
const RFC7636_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// 从 `302 Location` 响应中提取授权码。
#[cfg(feature = "oauth2-server")]
fn extract_auth_code(location: &str) -> String {
    location
        .split("code=")
        .nth(1)
        .expect("Location 应含 code 参数")
        .split('&')
        .next()
        .unwrap()
        .to_string()
}

/// （正常+异常）：authorize 端点重定向——已登录（Bearer token）
/// 重定向到 redirect_uri 携带 code+state；未登录重定向到登录页（return_to 保留参数）。
#[cfg(feature = "oauth2-server")]
#[tokio::test]
#[serial]
async fn acc_srv_013_authorize_redirect_logged_in_and_anonymous() {
    use garrison::oauth2_server::authorize::generate_code_challenge;

    let (state, store) = default_oauth2_state();
    let (external_url, _internal_url, _handle) =
        start_test_server_with_oauth2(100, "test-key", state).await;
    let client = no_redirect_client();
    store
        .create(make_full_oauth2_client("srv-013-client"))
        .await
        .unwrap();

    let challenge = generate_code_challenge(RFC7636_VERIFIER);
    let uri = format!(
        "{}/oauth2/authorize?response_type=code&client_id=srv-013-client&\
         redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=read&state=xyz&\
         code_challenge={}&code_challenge_method=S256",
        external_url, challenge
    );

    // 异常侧：未登录 → 302 到登录页（LoginRequired）
    let resp = client.get(&uri).send_relay_retry().await.unwrap();
    assert_eq!(resp.status(), 302, "未登录应重定向（FOUND）");
    let login_location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        login_location.starts_with("https://auth.example.com/login?return_to="),
        "未登录应重定向到登录页，实际: {login_location}"
    );

    // 正常侧：已登录（Bearer token）→ 302 到 redirect_uri 携带 code + state
    let token = http_login(&client, &external_url, "1001").await;
    let resp = client
        .get(&uri)
        .header("Authorization", format!("Bearer {token}"))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302, "已登录应重定向（FOUND）");
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with("https://app.example.com/cb?code="),
        "已登录应重定向到 redirect_uri 携带 code，实际: {location}"
    );
    assert!(location.contains("state=xyz"), "state 应原样回传");

    // 授权码可被原子消费（一次性）
    let code = extract_auth_code(location);
    assert!(!code.is_empty(), "授权码不应为空");
}

/// （正常+异常）：token 端点 authorization_code grant——
/// PKCE 校验 + 签发 access/refresh token；code 一次性（重放 → 400 invalid_grant）；
/// 成功响应含 RFC 6749 §5.1 no-store 缓存头。
#[cfg(feature = "oauth2-server")]
#[tokio::test]
#[serial]
async fn acc_srv_014_token_authorization_code_grant_pkce() {
    use garrison::oauth2_server::authorize::generate_code_challenge;

    let (state, store) = default_oauth2_state();
    let (external_url, _internal_url, _handle) =
        start_test_server_with_oauth2(100, "test-key", state).await;
    let client = no_redirect_client();
    store
        .create(make_full_oauth2_client("srv-014-client"))
        .await
        .unwrap();

    // 1. authorize 获取授权码（先登录）
    let token = http_login(&client, &external_url, "1001").await;
    let challenge = generate_code_challenge(RFC7636_VERIFIER);
    let uri = format!(
        "{}/oauth2/authorize?response_type=code&client_id=srv-014-client&\
         redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=read&\
         code_challenge={}&code_challenge_method=S256",
        external_url, challenge
    );
    let resp = client
        .get(&uri)
        .header("Authorization", format!("Bearer {token}"))
        .send_relay_retry()
        .await
        .unwrap();
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let code = extract_auth_code(location);

    // 2. token 交换（PKCE code_verifier）
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .form(&serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": "srv-014-client",
            "client_secret": "secret-123",
            "code": code,
            "redirect_uri": "https://app.example.com/cb",
            "code_verifier": RFC7636_VERIFIER
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "authorization_code 交换应返回 200");
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "no-store",
        "token 响应应含 Cache-Control: no-store（RFC 6749 §5.1）"
    );
    assert_eq!(
        resp.headers().get("pragma").unwrap(),
        "no-cache",
        "token 响应应含 Pragma: no-cache（RFC 6749 §5.1）"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 3600);
    assert_eq!(body["scope"], "read");
    assert!(!body["access_token"].as_str().unwrap().is_empty());
    assert!(
        body["refresh_token"].as_str().is_some(),
        "authorization_code grant 应返回 refresh_token"
    );

    // 3. 异常侧：code 一次性（重放 → invalid_grant）
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .form(&serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": "srv-014-client",
            "client_secret": "secret-123",
            "code": code,
            "redirect_uri": "https://app.example.com/cb",
            "code_verifier": RFC7636_VERIFIER
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "授权码重放应返回 400");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "OAUTH2_ERROR", "重放应返回 OAuth2 错误");

    // 4. 异常侧：错误 code_verifier → invalid_grant
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .form(&serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": "srv-014-client",
            "client_secret": "secret-123",
            "code": "no-such-code",
            "redirect_uri": "https://app.example.com/cb",
            "code_verifier": RFC7636_VERIFIER
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "无效 code 应返回 400");
}

/// （正常）：token 端点 client_credentials grant——签发
/// access_token（无 refresh_token），scope 校验通过。
#[cfg(feature = "oauth2-server")]
#[tokio::test]
#[serial]
async fn acc_srv_015_token_client_credentials_grant() {
    let (state, store) = default_oauth2_state();
    let (external_url, _internal_url, _handle) =
        start_test_server_with_oauth2(100, "test-key", state).await;
    let client = reqwest::Client::new();
    store
        .create(make_full_oauth2_client("srv-015-client"))
        .await
        .unwrap();

    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .form(&serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "srv-015-client",
            "client_secret": "secret-123",
            "scope": "read"
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "client_credentials 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 3600);
    assert_eq!(body["scope"], "read");
    assert!(!body["access_token"].as_str().unwrap().is_empty());
    assert!(
        body["refresh_token"].is_null(),
        "client_credentials 不应返回 refresh_token"
    );

    // 异常侧：未知 client_id / 错误 secret → 400
    for bad in [
        serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "ghost-client",
            "client_secret": "secret-123"
        }),
        serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "srv-015-client",
            "client_secret": "wrong-secret"
        }),
    ] {
        let resp = client
            .post(format!("{}/oauth2/token", external_url))
            .form(&bad)
            .send_relay_retry()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "无效客户端凭证应返回 400");
    }
}

/// （正常+异常）：token 端点 password grant——正确凭证签发
/// token（含 refresh_token + scope）；错误凭证返回 invalid_grant。
#[cfg(feature = "oauth2-server")]
#[tokio::test]
#[serial]
async fn acc_srv_016_token_password_grant() {
    use garrison::dao::{GarrisonDao, InMemoryDao};
    use garrison::oauth2_server::authorize::AuthorizeHandler;
    use garrison::oauth2_server::client::{DaoOAuth2ClientStore, OAuth2ClientStore};
    use garrison::oauth2_server::introspect::IntrospectHandler;
    use garrison::oauth2_server::revoke::RevokeHandler;
    use garrison::oauth2_server::token::{
        PasswordRateLimiter, PasswordVerifier, TokenHandler, TokenRateLimiter,
    };
    use garrison::server::oauth2_routes::OAuth2State;

    // 注入 PasswordVerifier 的 state（OAuth2State::new 不注入验证器，需手动装配）
    struct TestPasswordVerifier;
    #[async_trait]
    impl PasswordVerifier for TestPasswordVerifier {
        async fn verify(&self, username: &str, password: &str) -> GarrisonResult<Option<i64>> {
            if username == "alice" && password == "wonderland" {
                Ok(Some(5001))
            } else {
                Ok(None)
            }
        }
    }

    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let store: Arc<dyn OAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
    let authorize_handler = Arc::new(AuthorizeHandler::new(
        store.clone(),
        dao.clone(),
        "https://auth.example.com/login".to_string(),
    ));
    let token_handler = Arc::new(
        TokenHandler::new(
            store.clone(),
            dao.clone(),
            authorize_handler.clone(),
            Arc::new(PasswordRateLimiter::new(1000, 300)),
            Arc::new(TokenRateLimiter::with_limits(100_000, 60, 100_000, 60)),
        )
        .with_password_verifier(Arc::new(TestPasswordVerifier)),
    );
    let revoke_handler = Arc::new(RevokeHandler::new(store.clone(), token_handler.clone()));
    let store_for_register = store.clone();
    let introspect_handler = Arc::new(IntrospectHandler::new(store.clone(), token_handler.clone()));
    let state = Arc::new(OAuth2State {
        authorize_handler,
        token_handler,
        revoke_handler,
        introspect_handler,
        client_store: store.clone(),
        // 本测试不配置非对称签名密钥，JWKS 端点 fail-closed 返回 404
        jwks_source: None,
        issuer: None,
        jwks_keystore: None,
        oidc_discovery_enabled: false,
        password_grant_advertised: false,
        jwks_retention_secs: garrison::config::DEFAULT_JWKS_RETENTION_SECS,
        scopes_cache: tokio::sync::RwLock::new(None),
        jwks_doc_cache: tokio::sync::Mutex::new(None),
    });

    let (external_url, _internal_url, _handle) =
        start_test_server_with_oauth2(100, "test-key", state).await;
    store_for_register
        .create(make_full_oauth2_client("srv-016-client"))
        .await
        .unwrap();
    let client = reqwest::Client::new();

    // 正常侧：正确凭证 → 200 + access/refresh token
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .form(&serde_json::json!({
            "grant_type": "password",
            "client_id": "srv-016-client",
            "client_secret": "secret-123",
            "username": "alice",
            "password": "wonderland",
            "scope": "read"
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "正确凭证 password grant 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "read");
    assert!(!body["access_token"].as_str().unwrap().is_empty());
    assert!(body["refresh_token"].as_str().is_some());

    // 异常侧：错误密码 → 400（invalid_grant）
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .form(&serde_json::json!({
            "grant_type": "password",
            "client_id": "srv-016-client",
            "client_secret": "secret-123",
            "username": "alice",
            "password": "wrong",
            "scope": "read"
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "错误密码应返回 400");
}

/// （正常+异常）：token 端点 refresh_token grant——轮换出新
/// access/refresh token；旧 refresh_token 重放返回 invalid_grant（DAO 轮换路径
/// 删除旧记录后的隐式 reuse detection）。
#[cfg(feature = "oauth2-server")]
#[tokio::test]
#[serial]
async fn acc_srv_017_token_refresh_token_grant_rotates() {
    use garrison::oauth2_server::authorize::generate_code_challenge;

    let (state, store) = default_oauth2_state();
    let (external_url, _internal_url, _handle) =
        start_test_server_with_oauth2(100, "test-key", state).await;
    let client = no_redirect_client();
    store
        .create(make_full_oauth2_client("srv-017-client"))
        .await
        .unwrap();

    // 1. 授权码流程取得 refresh_token
    let token = http_login(&client, &external_url, "1001").await;
    let challenge = generate_code_challenge(RFC7636_VERIFIER);
    let uri = format!(
        "{}/oauth2/authorize?response_type=code&client_id=srv-017-client&\
         redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&\
         code_challenge={}&code_challenge_method=S256",
        external_url, challenge
    );
    let resp = client
        .get(&uri)
        .header("Authorization", format!("Bearer {token}"))
        .send_relay_retry()
        .await
        .unwrap();
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let code = extract_auth_code(location);

    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .form(&serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": "srv-017-client",
            "client_secret": "secret-123",
            "code": code,
            "redirect_uri": "https://app.example.com/cb",
            "code_verifier": RFC7636_VERIFIER
        }))
        .send_relay_retry()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // 2. refresh grant → 200，新 access/refresh token（轮换）
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .form(&serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": "srv-017-client",
            "client_secret": "secret-123",
            "refresh_token": refresh_token
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "refresh_token grant 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(!body["access_token"].as_str().unwrap().is_empty());
    let new_refresh = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(new_refresh, refresh_token, "refresh_token 应轮换出新值");

    // 3. 异常侧：旧 refresh_token 重放 → 400 invalid_grant
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .form(&serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": "srv-017-client",
            "client_secret": "secret-123",
            "refresh_token": refresh_token
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "旧 refresh_token 重放应返回 400");
}

/// （正常+异常）：revoke + introspect——revoke 返回 204 且
/// token 立即失活（introspect active=false）；未知 token introspect 返回
/// active=false 且状态码 200；客户端凭证错误被拒。
#[cfg(feature = "oauth2-server")]
#[tokio::test]
#[serial]
async fn acc_srv_018_revoke_then_introspect_inactive() {
    let (state, store) = default_oauth2_state();
    let (external_url, internal_url, _handle) =
        start_test_server_with_oauth2(100, "test-key", state).await;
    let client = reqwest::Client::new();
    store
        .create(make_full_oauth2_client("srv-018-client"))
        .await
        .unwrap();

    // 1. client_credentials 签发 access_token
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .form(&serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "srv-018-client",
            "client_secret": "secret-123"
        }))
        .send_relay_retry()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let access_token = body["access_token"].as_str().unwrap().to_string();

    // 2. 正常侧：introspect 活跃 token → active=true + 元数据
    let resp = client
        .post(format!("{}/oauth2/introspect", internal_url))
        .header("x-api-key", "test-key")
        .form(&serde_json::json!({
            "token": access_token,
            "client_id": "srv-018-client",
            "client_secret": "secret-123"
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "introspect 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["active"], true, "有效 token 应 active=true");
    assert_eq!(body["client_id"], "srv-018-client");
    assert_eq!(body["token_type"], "Bearer");

    // 3. revoke → 204（RFC 7009 成功无 body）
    let resp = client
        .post(format!("{}/oauth2/revoke", external_url))
        .form(&serde_json::json!({
            "token": access_token,
            "client_id": "srv-018-client",
            "client_secret": "secret-123"
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "revoke 成功应返回 204 No Content");

    // 4. 异常侧：revoke 后 introspect active=false；未知 token 亦 active=false
    for token in [access_token.clone(), "ghost-token".to_string()] {
        let resp = client
            .post(format!("{}/oauth2/introspect", internal_url))
            .header("x-api-key", "test-key")
            .form(&serde_json::json!({
                "token": token,
                "client_id": "srv-018-client",
                "client_secret": "secret-123"
            }))
            .send_relay_retry()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "introspect 未知/已撤销 token 仍返回 200"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["active"], false, "已撤销/未知 token 应 active=false");
    }

    // 5. 异常侧：revoke 携带错误客户端凭证 → 400
    let resp = client
        .post(format!("{}/oauth2/revoke", external_url))
        .form(&serde_json::json!({
            "token": access_token,
            "client_id": "srv-018-client",
            "client_secret": "wrong-secret"
        }))
        .send_relay_retry()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "revoke 客户端认证失败应返回 400");
}

// ------------------------------------------------------------------------
// auth_server 二进制 smoke（#[cfg(feature = "auth-server")]）
// ------------------------------------------------------------------------
//
// `src/bin/auth_server.rs` 是自含二进制：从环境变量装配
// `GarrisonAuthServer::new(backend).with_*_port().with_rate_limit()
// .with_internal_api_key()` 后以 bin 侧 bind+serve 启动（自含配置校验 +
// 路由构建 + 端口绑定，不依赖 GarrisonManager 全局初始化）；fail-closed：
// `GARRISON_INTERNAL_API_KEY` 缺失 / 空串 / 长度不足 32 字节、绑定地址或
// 可信代理解析失败、外网登录非回环绑定未确认（GARRISON_EXTERNAL_LOGIN_ACK）
// 时均 `std::process::exit(1)`。
//
// 实现说明：
// - 经 `CARGO_BIN_EXE_auth_server` 定位二进制（bin 的 required-features =
// auth-server ⊂ 本 target 的 full，测试构建时必然已编译）；
// - tokio 的 `process` feature 在依赖图中未启用（不为此新增依赖），故用
// `std::process::Command` 同步子进程 + 异步 reqwest 轮询的组合，
// 退出等待以 `try_wait()` 轮询模拟 `tokio::process` 语义；
// - env 经 Command 注入（默认继承父进程其余环境），不触碰测试进程自身
// 环境变量，无需 set_var 串行保护；注入的 API Key 均为测试占位串，
// 禁止写入真实凭据。

/// 探测一个空闲本地端口（绑定 `127.0.0.1:0` 读取端口后立即释放）。
#[cfg(feature = "auth-server")]
fn probe_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("绑定 127.0.0.1:0 应成功")
        .local_addr()
        .expect("读取本地端口应成功")
        .port()
}

/// 测试占位字段加密密钥（非真实钥材）：bin 在 `field-encryption` feature 下
/// 启动期 fail-closed 校验 `GARRISON_FIELD_ENCRYPTION_KEYS`（`key_id:hex64`，
/// hex64 = 32 字节 AES-256 钥材 hex 编码，key_id 非空且不含冒号），缺失即
/// exit 1（src/bin/auth_server.rs `setup_garrison_manager`）。
/// acc_srv_019（成功路径烟测）与 acc_srv_022/032/033（要求失败仅来自
/// 端口冲突 / ACK 语义）必须注入使语义成立；acc_srv_020/021/030/031 在
/// 该校验之前即被 bootstrap 安全装配 gate 拒绝，无需注入。
#[cfg(feature = "auth-server")]
const TEST_FIELD_ENCRYPTION_KEYS: &str =
    "test-only-field-key-0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// 合规测试占位 API Key（≥32 字节，非真实凭据）：bin 对
/// `GARRISON_INTERNAL_API_KEY` 强制最低 32 字节（GAR-33 fail-closed）。
#[cfg(feature = "auth-server")]
const TEST_API_KEY: &str = "test-only-not-a-real-key-0123456789abcdef";

/// 以给定 env 覆盖 / 移除项启动 auth_server 子进程（stdout/stderr 置空，
/// 避免污染测试输出；其余环境继承自测试进程）。
#[cfg(feature = "auth-server")]
fn spawn_auth_server_process(
    env_overrides: &[(&str, &str)],
    env_removals: &[&str],
) -> std::process::Child {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_auth_server"));
    for &(key, value) in env_overrides {
        cmd.env(key, value);
    }
    for &key in env_removals {
        cmd.env_remove(key);
    }
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    cmd.spawn().expect("auth_server 子进程应成功启动")
}

/// 轮询等待子进程退出（`try_wait` 每 100ms 一次），返回退出状态。
#[cfg(feature = "auth-server")]
async fn wait_for_exit(child: &mut std::process::Child) -> std::process::ExitStatus {
    let deadline = std::time::Duration::from_secs(30);
    tokio::time::timeout(deadline, async {
        loop {
            if let Some(status) = child.try_wait().expect("try_wait 不应失败") {
                return status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("auth_server 子进程应在 30s 内退出")
}

/// （正常）：auth_server 二进制正常启动 smoke——注入双端口与
/// API Key（测试占位串）环境变量后：
/// 1. 外网端口 `/api/v1/auth/health` 可达：拿到任意 HTTP 响应即证明
/// 「进程存活且可响应 HTTP」（health 是内网专属端点，外网经 path-filter
/// 返回 404，语义同 ，故此处不断言 200）；
/// 2. 内网端口 `/api/v1/auth/health`（带 x-api-key）返回 200 + `{"data":"ok"}`：
/// health 不依赖 GarrisonManager，端到端验证 env 装配 + 路由构建 + 中间件。
#[cfg(feature = "auth-server")]
#[tokio::test]
#[serial]
async fn acc_srv_019_auth_server_bin_startup_smoke() {
    // 先探测两个空闲端口再释放（子进程稍后绑定；毫秒级竞态窗口测试可接受）
    let external_port = probe_free_port();
    let internal_port = probe_free_port();
    let external_port = external_port.to_string();
    let internal_port = internal_port.to_string();
    // 合规测试占位串（≥32 字节，非真实凭据）
    let test_api_key = TEST_API_KEY;

    let mut child = spawn_auth_server_process(
        &[
            ("GARRISON_EXTERNAL_PORT", external_port.as_str()),
            ("GARRISON_INTERNAL_PORT", internal_port.as_str()),
            ("GARRISON_INTERNAL_API_KEY", test_api_key),
            // field-encryption feature 下 bin 启动期 fail-closed，缺失即 exit 1
            ("GARRISON_FIELD_ENCRYPTION_KEYS", TEST_FIELD_ENCRYPTION_KEYS),
        ],
        &[],
    );

    // 1. 轮询外网端口（最多 60 次 × 500ms = 30s）直到拿到任意 HTTP 响应。
    // 30s 预算：过载环境（多套件并发 / testcontainers 拉镜像）下 debug 构建
    // 冷启动可超过 10s——2026-09-11 E2E 实录 acc_srv_019 因此假失败；
    // 本测试语义是「二进制可启动并可响应」，非启动耗时基线。
    let client = reqwest::Client::new();
    let external_health = format!("http://127.0.0.1:{}/api/v1/auth/health", external_port);
    let mut external_up = false;
    for _ in 0..60 {
        match client.get(&external_health).send_relay_retry().await {
            Ok(resp) => {
                let _ = resp.status(); // 预期 404（path-filter），任意响应即存活
                external_up = true;
                break;
            },
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
        }
    }
    assert!(
        external_up,
        "auth_server 进程应在 30s 内于外网端口 {} 响应 HTTP",
        external_port
    );

    // 2. 内网 health（带 x-api-key）→ 200 + {"data":"ok"}
    let resp = client
        .get(format!(
            "http://127.0.0.1:{}/api/v1/auth/health",
            internal_port
        ))
        .header("x-api-key", test_api_key)
        .send_relay_retry()
        .await
        .expect("内网 health 请求应送达（进程已确认存活）");
    assert_eq!(resp.status(), 200, "内网 health 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], "ok", "内网 health 应返回 data=ok");

    // 清理：杀死子进程（避免悬挂进程占用端口）
    let _ = child.kill();
    let _ = child.wait();
}

/// （异常）：fail-closed——缺失 `GARRISON_INTERNAL_API_KEY`
/// （显式从 env 移除，防父环境已有）时，进程以退出码 1 拒绝启动。
#[cfg(feature = "auth-server")]
#[tokio::test]
#[serial]
async fn acc_srv_020_auth_server_exits_without_api_key() {
    let external_port = probe_free_port().to_string();
    let internal_port = probe_free_port().to_string();

    let mut child = spawn_auth_server_process(
        &[
            ("GARRISON_EXTERNAL_PORT", external_port.as_str()),
            ("GARRISON_INTERNAL_PORT", internal_port.as_str()),
        ],
        &["GARRISON_INTERNAL_API_KEY"],
    );

    let status = wait_for_exit(&mut child).await;
    assert_eq!(
        status.code(),
        Some(1),
        "缺失 GARRISON_INTERNAL_API_KEY 应以退出码 1 拒绝启动（fail-closed）"
    );
    // 子进程已退出，清理无副作用
    let _ = child.kill();
    let _ = child.wait();
}

/// （异常）：fail-closed——`GARRISON_INTERNAL_API_KEY` 为空串时，
/// 进程以退出码 1 拒绝启动。
#[cfg(feature = "auth-server")]
#[tokio::test]
#[serial]
async fn acc_srv_021_auth_server_exits_with_empty_api_key() {
    let external_port = probe_free_port().to_string();
    let internal_port = probe_free_port().to_string();

    let mut child = spawn_auth_server_process(
        &[
            ("GARRISON_EXTERNAL_PORT", external_port.as_str()),
            ("GARRISON_INTERNAL_PORT", internal_port.as_str()),
            ("GARRISON_INTERNAL_API_KEY", ""),
        ],
        &[],
    );

    let status = wait_for_exit(&mut child).await;
    assert_eq!(
        status.code(),
        Some(1),
        "空串 GARRISON_INTERNAL_API_KEY 应以退出码 1 拒绝启动（fail-closed）"
    );
    let _ = child.kill();
    let _ = child.wait();
}

/// （异常）：端口冲突 fail-fast——外网端口被测试进程占住
///（listener 全程保持监听，杜绝"绑定后 drop 再被子进程抢到"的竞态）时，
/// auth_server 子进程 `listen()` 的 `TcpListener::bind` 返回 `Err`
///（`server-external-bind::...`）→ `main()` 返回 `Err` → 以非零退出码终止。
///
/// 与 /021 的 env fail-closed 不同，本场景验证的是
/// `GarrisonAuthServer::listen` 的 bind 失败传播契约（bin 层 `if let Err` → 返回 Err）。
#[cfg(feature = "auth-server")]
#[tokio::test]
#[serial]
async fn acc_srv_022_auth_server_bin_port_conflict_exits_nonzero() {
    // 1. 占住一个端口并【保持监听不 drop】：std::net::TcpListener 绑定后即进入
    // LISTEN 状态，子进程对同端口（含 0.0.0.0 通配）的任何 bind 均 EADDRINUSE
    let occupier = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定 127.0.0.1:0 应成功");
    let external_port = occupier.local_addr().expect("读取本地端口应成功").port();
    // 内网端口用空闲端口，保证失败源唯一（外网 bind 冲突）
    let internal_port = probe_free_port().to_string();
    let external_port = external_port.to_string();

    // 2. 启动子进程并注入被占端口；API Key 与字段加密钥均为明显测试占位串
    //（非真实凭据），确保 env 校验全部通过、失败仅来自端口冲突
    let mut child = spawn_auth_server_process(
        &[
            ("GARRISON_EXTERNAL_PORT", external_port.as_str()),
            ("GARRISON_INTERNAL_PORT", internal_port.as_str()),
            ("GARRISON_INTERNAL_API_KEY", TEST_API_KEY),
            // field-encryption fail-closed 校验先于 bind，缺失会掩盖端口冲突失败源
            ("GARRISON_FIELD_ENCRYPTION_KEYS", TEST_FIELD_ENCRYPTION_KEYS),
        ],
        &[],
    );

    // 3. 断言子进程以非零码退出（bind 失败 → listen 返回 Err → bin 返回 Err）
    let status = wait_for_exit(&mut child).await;
    assert_ne!(
        status.code(),
        Some(0),
        "外网端口被占用时 auth_server 应以非零退出码终止，实际: {status:?}"
    );

    // 4. 测试内监听最后 drop，释放占用的端口
    drop(occupier);
}

/// 轮询一个 URL 直到拿到任意 HTTP 响应（证明进程存活且在服务），
/// 30s 预算与 acc_srv_019 一致（debug 构建冷启动可超过 10s）。
#[cfg(feature = "auth-server")]
async fn poll_http_alive(url: &str) -> bool {
    let client = reqwest::Client::new();
    for _ in 0..60 {
        match client.get(url).send_relay_retry().await {
            Ok(_) => return true,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
        }
    }
    false
}

/// （异常）：fail-closed（GAR-33）——`GARRISON_INTERNAL_API_KEY` 不足 32 字节时，
/// 管理面唯一凭证强度不达标，进程以退出码 1 拒绝启动。
#[cfg(feature = "auth-server")]
#[tokio::test]
#[serial]
async fn acc_srv_030_auth_server_exits_with_short_api_key() {
    let external_port = probe_free_port().to_string();
    let internal_port = probe_free_port().to_string();

    let mut child = spawn_auth_server_process(
        &[
            ("GARRISON_EXTERNAL_PORT", external_port.as_str()),
            ("GARRISON_INTERNAL_PORT", internal_port.as_str()),
            // 24 字节 < 32 字节下限
            ("GARRISON_INTERNAL_API_KEY", "test-only-not-a-real-key"),
        ],
        &[],
    );

    let status = wait_for_exit(&mut child).await;
    assert_eq!(
        status.code(),
        Some(1),
        "不足 32 字节的 GARRISON_INTERNAL_API_KEY 应以退出码 1 拒绝启动（fail-closed）"
    );
    let _ = child.kill();
    let _ = child.wait();
}

/// （异常）：fail-closed（GAR-34）——`GARRISON_TRUSTED_PROXIES` 含非法字面量
/// 或公网 IP（可被路径中间设备伪造，不得进入 XFF 信任边界）时拒绝启动。
#[cfg(feature = "auth-server")]
#[tokio::test]
#[serial]
async fn acc_srv_031_auth_server_exits_with_invalid_trusted_proxies() {
    let external_port = probe_free_port().to_string();
    let internal_port = probe_free_port().to_string();
    let mut env = [
        ("GARRISON_EXTERNAL_PORT", external_port.as_str()),
        ("GARRISON_INTERNAL_PORT", internal_port.as_str()),
        ("GARRISON_INTERNAL_API_KEY", TEST_API_KEY),
    ]
    .to_vec();

    // 非法字面量
    env.push(("GARRISON_TRUSTED_PROXIES", "not-an-ip"));
    let mut child = spawn_auth_server_process(&env, &[]);
    let status = wait_for_exit(&mut child).await;
    assert_eq!(
        status.code(),
        Some(1),
        "非法 GARRISON_TRUSTED_PROXIES 应以退出码 1 拒绝启动（fail-closed）"
    );
    let _ = child.kill();
    let _ = child.wait();

    // 公网地址（与框架 AuthServerConfig::validate 同策略）
    env.pop();
    env.push(("GARRISON_TRUSTED_PROXIES", "10.0.0.1,8.8.8.8"));
    let mut child = spawn_auth_server_process(&env, &[]);
    let status = wait_for_exit(&mut child).await;
    assert_eq!(
        status.code(),
        Some(1),
        "公网可信代理 IP 应以退出码 1 拒绝启动（fail-closed）"
    );
    let _ = child.kill();
    let _ = child.wait();
}

/// （异常 + 正常）：GAR-03 分层收口——外网登录开启且外网绑定为非回环地址时，
/// 未提供 `GARRISON_EXTERNAL_LOGIN_ACK`（或值非精确匹配）即拒绝启动；
/// 精确匹配 `i-understand-no-credential-check` 后方可启动。
#[cfg(feature = "auth-server")]
#[tokio::test]
#[serial]
async fn acc_srv_032_auth_server_external_login_non_loopback_requires_ack() {
    let external_port = probe_free_port().to_string();
    let internal_port = probe_free_port().to_string();
    let mut env = [
        ("GARRISON_EXTERNAL_PORT", external_port.as_str()),
        ("GARRISON_INTERNAL_PORT", internal_port.as_str()),
        ("GARRISON_INTERNAL_API_KEY", TEST_API_KEY),
        ("GARRISON_FIELD_ENCRYPTION_KEYS", TEST_FIELD_ENCRYPTION_KEYS),
        ("GARRISON_EXTERNAL_LOGIN_ENABLED", "true"),
        ("GARRISON_EXTERNAL_BIND", "0.0.0.0"),
    ]
    .to_vec();

    // 1. 无 ACK（显式移除，防父环境已有）→ 拒绝启动
    let mut child = spawn_auth_server_process(&env, &["GARRISON_EXTERNAL_LOGIN_ACK"]);
    let status = wait_for_exit(&mut child).await;
    assert_eq!(
        status.code(),
        Some(1),
        "非回环绑定 + 外网登录开启且无 ACK 应以退出码 1 拒绝启动（fail-closed）"
    );
    let _ = child.kill();
    let _ = child.wait();

    // 2. ACK 大小写不匹配（精确匹配语义）→ 拒绝启动
    env.push((
        "GARRISON_EXTERNAL_LOGIN_ACK",
        "I-UNDERSTAND-NO-CREDENTIAL-CHECK",
    ));
    let mut child = spawn_auth_server_process(&env, &[]);
    let status = wait_for_exit(&mut child).await;
    assert_eq!(
        status.code(),
        Some(1),
        "ACK 值非精确匹配应以退出码 1 拒绝启动"
    );
    let _ = child.kill();
    let _ = child.wait();

    // 3. ACK 精确匹配 → 进程存活并对外网端口响应 HTTP
    env.pop();
    env.push((
        "GARRISON_EXTERNAL_LOGIN_ACK",
        "i-understand-no-credential-check",
    ));
    let mut child = spawn_auth_server_process(&env, &[]);
    let external_health = format!("http://127.0.0.1:{}/api/v1/auth/health", external_port);
    assert!(
        poll_http_alive(&external_health).await,
        "提供精确 ACK 后 auth_server 应在 30s 内于外网端口 {} 响应 HTTP",
        external_port
    );
    let _ = child.kill();
    let _ = child.wait();
}

/// （正常）：GAR-03 分层收口的回环豁免——外网登录开启但绑定保持默认回环
/// （127.0.0.1）时，无需 `GARRISON_EXTERNAL_LOGIN_ACK` 即可启动。
#[cfg(feature = "auth-server")]
#[tokio::test]
#[serial]
async fn acc_srv_033_auth_server_external_login_loopback_starts_without_ack() {
    let external_port = probe_free_port().to_string();
    let internal_port = probe_free_port().to_string();

    let mut child = spawn_auth_server_process(
        &[
            ("GARRISON_EXTERNAL_PORT", external_port.as_str()),
            ("GARRISON_INTERNAL_PORT", internal_port.as_str()),
            ("GARRISON_INTERNAL_API_KEY", TEST_API_KEY),
            ("GARRISON_FIELD_ENCRYPTION_KEYS", TEST_FIELD_ENCRYPTION_KEYS),
            ("GARRISON_EXTERNAL_LOGIN_ENABLED", "true"),
        ],
        // 显式移除绑定地址与 ACK，防父环境污染（语义依赖「缺省回环 + 无 ACK」）
        &["GARRISON_EXTERNAL_BIND", "GARRISON_EXTERNAL_LOGIN_ACK"],
    );
    let external_health = format!("http://127.0.0.1:{}/api/v1/auth/health", external_port);
    assert!(
        poll_http_alive(&external_health).await,
        "回环绑定 + 外网登录开启应无需 ACK 正常启动（外网端口 {}）",
        external_port
    );
    let _ = child.kill();
    let _ = child.wait();
}
