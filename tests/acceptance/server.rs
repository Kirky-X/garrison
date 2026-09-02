//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! server 域验收（spec `acceptance-matrix` R-acceptance-matrix-001，任务 T033）。
//!
//! 场景编号 `ACC-SRV-NNN`：
//! - ACC-SRV-001..012：`GarrisonAuthServer` 外网/内网端点验收，吸收重构
//!   `tests/auth_server_integration.rs` 全部 12 个测试（每个场景标注
//!   「迁自 tests/auth_server_integration.rs::<测试名>」，Phase 4 迁移追溯）；
//! - ACC-SRV-013..018：oauth2_server 端点级验收（`#[cfg(feature = "oauth2-server")]`）：
//!   authorize 重定向 / token 4 种 grant / revoke / introspect（RFC 6749/7009/7662），
//!   装配参考 `src/oauth2_server/*` 与 `tests/e2e/oauth2_flow.rs`。
//!
//! 全局装配同 `tests/auth_server_integration.rs`：随机端口 + `MockAuthBackend`
//!（in-memory token 表，测试替身）经 HTTP 访问真实端点。本域不触碰
//! `GarrisonManager` 全局单例，但按验收域惯例统一 `#[serial]` 串行
//!（与其他域共享测试进程，避免任何潜在的全局登记表串扰）。

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
        .send()
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
        .send()
        .await
        .expect("check-login 请求应送达服务器");
    assert_eq!(resp.status(), 200, "check-login 应返回 200");
    resp.json::<serde_json::Value>().await.unwrap()["data"].clone()
}

// ------------------------------------------------------------------------
// ACC-SRV-001..006：外网 login/logout/refresh + 内网校验（正常）
// ------------------------------------------------------------------------

/// ACC-SRV-001（正常）：外网 login 签发 `token-<login_id>-` 前缀 token，
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

/// ACC-SRV-002（正常）：内网 health 端点返回 `{"data": "ok"}`。
/// 迁自 tests/auth_server_integration.rs::test_internal_health_endpoint
#[tokio::test]
#[serial]
async fn acc_srv_002_internal_health_endpoint() {
    let (_external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "health 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], "ok");
}

/// ACC-SRV-003（正常）：外网 logout 使 token 失效——同一 token 的
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
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "logout 应返回 200");

    assert_eq!(
        http_check_login(&client, &internal_url, "test-key", &token).await,
        serde_json::json!(false),
        "logout 后 token 应失效"
    );
}

/// ACC-SRV-004（正常）：外网 refresh 轮换出新 token（新旧不同）。
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
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "refresh 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    let new_token = body["data"].as_str().unwrap().to_string();
    assert_ne!(old_token, new_token, "refresh 应签发新 token");
}

/// ACC-SRV-005（正常）：内网 get-token-info 返回 token 元数据
///（`data.token` 一致、`created_at=1000` 与 mock 契约一致）。
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
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["token"], token);
    assert_eq!(body["data"]["created_at"], 1000);
}

/// ACC-SRV-006（正常）：内网 get-session 返回会话主体
///（`data.login_id` 与登录主体一致）。
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
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["login_id"], "user1");
}

// ------------------------------------------------------------------------
// ACC-SRV-007..009：内网 X-API-Key 互斥 / 踢出 / 切换（正常 + 异常）
// ------------------------------------------------------------------------

/// ACC-SRV-007（异常）：内网端点缺少 / 错误的 `X-API-Key` 一律 401。
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
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "缺 X-API-Key 应返回 401");

    // 错误的 X-API-Key
    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .header("x-api-key", "wrong-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "错误 X-API-Key 应返回 401");
}

/// ACC-SRV-008（正常+异常）：内网 kickout 后同账号全部 token 失效
///（check-login 均为 `data=false`）。
/// 迁自 tests/auth_server_integration.rs::test_internal_kickout
#[tokio::test]
#[serial]
async fn acc_srv_008_internal_kickout_invalidates_all_tokens() {
    let (external_url, internal_url, _handle) = start_test_server(100, "test-key").await;
    let client = reqwest::Client::new();

    // 同一账号登录两个 token
    let t1 = http_login(&client, &external_url, "user1").await;
    let t2 = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/kickout", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "login_id": "user1", "caller_login_id": "user1" }))
        .send()
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

/// ACC-SRV-009（正常）：内网 switch-to 切换会话主体——get-session 反查
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
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "switch-to 应返回 200");

    let resp = client
        .post(format!("{}/api/v1/auth/get-session", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["login_id"], "user2", "切换后主体应为 user2");
}

// ------------------------------------------------------------------------
// ACC-SRV-010..012：限速 / 中间件错误码映射 / 内外网路径互斥（异常）
// ------------------------------------------------------------------------

/// ACC-SRV-010（异常）：外网限速——`rate_limit=2` 时第 3 个并发登录请求返回 429。
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

    // 前 2 个请求成功
    for _ in 0..2 {
        let resp = client
            .post(format!("{}/api/v1/auth/login", external_url))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "限速窗口内请求应成功");
    }

    // 第 3 个请求被限速
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "超限速应返回 429");
}

/// ACC-SRV-011（异常）：内网 check-permission 对无效 token 返回中间件
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
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "业务错误以 200 + error_code 表达");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error_code"], "INVALID_TOKEN");
}

/// ACC-SRV-012（异常）：内外网路径互斥——外网端口拒绝内网路径（404）；
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
        .send()
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
        .send()
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
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "缺 X-API-Key 内网请求应 401（中间件顺序）"
    );
}

// ------------------------------------------------------------------------
// ACC-SRV-013..018：oauth2_server 端点级验收（#[cfg(feature = "oauth2-server")]）
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

/// ACC-SRV-013（正常+异常）：authorize 端点重定向——已登录（Bearer token）
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
    let resp = client.get(&uri).send().await.unwrap();
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
        .send()
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

/// ACC-SRV-014（正常+异常）：token 端点 authorization_code grant——
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
        .send()
        .await
        .unwrap();
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let code = extract_auth_code(location);

    // 2. token 交换（PKCE code_verifier）
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": "srv-014-client",
            "client_secret": "secret-123",
            "code": code,
            "redirect_uri": "https://app.example.com/cb",
            "code_verifier": RFC7636_VERIFIER
        }))
        .send()
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
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": "srv-014-client",
            "client_secret": "secret-123",
            "code": code,
            "redirect_uri": "https://app.example.com/cb",
            "code_verifier": RFC7636_VERIFIER
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "授权码重放应返回 400");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "OAUTH2_ERROR", "重放应返回 OAuth2 错误");

    // 4. 异常侧：错误 code_verifier → invalid_grant
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": "srv-014-client",
            "client_secret": "secret-123",
            "code": "no-such-code",
            "redirect_uri": "https://app.example.com/cb",
            "code_verifier": RFC7636_VERIFIER
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "无效 code 应返回 400");
}

/// ACC-SRV-015（正常）：token 端点 client_credentials grant——签发
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
        .json(&serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "srv-015-client",
            "client_secret": "secret-123",
            "scope": "read"
        }))
        .send()
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
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "无效客户端凭证应返回 400");
    }
}

/// ACC-SRV-016（正常+异常）：token 端点 password grant——正确凭证签发
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
    use garrison::oauth2_server::token::{PasswordVerifier, TokenHandler};
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
        TokenHandler::new(store.clone(), dao.clone(), authorize_handler.clone())
            .with_password_verifier(Arc::new(TestPasswordVerifier)),
    );
    let revoke_handler = Arc::new(RevokeHandler::new(store.clone(), token_handler.clone()));
    let store_for_register = store.clone();
    let introspect_handler = Arc::new(IntrospectHandler::new(store, token_handler.clone()));
    let state = Arc::new(OAuth2State {
        authorize_handler,
        token_handler,
        revoke_handler,
        introspect_handler,
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
        .json(&serde_json::json!({
            "grant_type": "password",
            "client_id": "srv-016-client",
            "client_secret": "secret-123",
            "username": "alice",
            "password": "wonderland",
            "scope": "read"
        }))
        .send()
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
        .json(&serde_json::json!({
            "grant_type": "password",
            "client_id": "srv-016-client",
            "client_secret": "secret-123",
            "username": "alice",
            "password": "wrong",
            "scope": "read"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "错误密码应返回 400");
}

/// ACC-SRV-017（正常+异常）：token 端点 refresh_token grant——轮换出新
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
        .send()
        .await
        .unwrap();
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let code = extract_auth_code(location);

    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": "srv-017-client",
            "client_secret": "secret-123",
            "code": code,
            "redirect_uri": "https://app.example.com/cb",
            "code_verifier": RFC7636_VERIFIER
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // 2. refresh grant → 200，新 access/refresh token（轮换）
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .json(&serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": "srv-017-client",
            "client_secret": "secret-123",
            "refresh_token": refresh_token
        }))
        .send()
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
        .json(&serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": "srv-017-client",
            "client_secret": "secret-123",
            "refresh_token": refresh_token
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "旧 refresh_token 重放应返回 400");
}

/// ACC-SRV-018（正常+异常）：revoke + introspect——revoke 返回 204 且
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
        .json(&serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "srv-018-client",
            "client_secret": "secret-123"
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let access_token = body["access_token"].as_str().unwrap().to_string();

    // 2. 正常侧：introspect 活跃 token → active=true + 元数据
    let resp = client
        .post(format!("{}/oauth2/introspect", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": access_token,
            "client_id": "srv-018-client",
            "client_secret": "secret-123"
        }))
        .send()
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
        .json(&serde_json::json!({
            "token": access_token,
            "client_id": "srv-018-client",
            "client_secret": "secret-123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "revoke 成功应返回 204 No Content");

    // 4. 异常侧：revoke 后 introspect active=false；未知 token 亦 active=false
    for token in [access_token.clone(), "ghost-token".to_string()] {
        let resp = client
            .post(format!("{}/oauth2/introspect", internal_url))
            .header("x-api-key", "test-key")
            .json(&serde_json::json!({
                "token": token,
                "client_id": "srv-018-client",
                "client_secret": "secret-123"
            }))
            .send()
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
        .json(&serde_json::json!({
            "token": access_token,
            "client_id": "srv-018-client",
            "client_secret": "wrong-secret"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "revoke 客户端认证失败应返回 400");
}
