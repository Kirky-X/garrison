// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 扫码登录真实双端验收（feature = "protocol-qrlogin"，依赖 auth-server）。
//!
//! 双端语义：Web 端（待登录的 PC 浏览器）与 App 端（已登录的确认设备）各持
//! **独立的 reqwest Client**（独立连接池，设备间不共享任何客户端状态），唯一
//! 共享的真实状态在服务器端——MockAuthBackend 会话表与 qrlogin DAO（InMemoryDao）。
//!
//! - 全链路：Web create → App 经真实 HTTP `/api/v1/auth/login` 登录 → App scan
//!   （Bearer App 会话）→ Web poll(scanned) → App confirm → Web poll 兑换出
//!   真实会话 token → 内网 get-session 闭环核验 token 归属确认者；
//! - 异常路径：无/假 Bearer 401、伪造票据 400、cancel 流程、并发 poll 仅一胜出；
//! - Quishing 防御用户可见面：create 的 Chrome UA 经确认页摘要以 `Chrome`
//!   设备标签回传 App 端。
//!
//! 装配同 `server.rs`：随机端口 + `axum::serve` 后台任务 + `#[serial]` 串行。

use async_trait::async_trait;
use garrison::backend::types::{LoginParams, SessionData, TokenInfo};
use garrison::backend::AuthBackend;
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::protocol::qrlogin::{QrLoginService, QrLoginSessionIssuer};
use garrison::server::GarrisonAuthServer;
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// 共享会话表：双端的唯一真实状态
// ============================================================================

/// token → login_id 会话表（服务器端唯一真实状态，双端共享）。
#[derive(Default)]
struct TokenStore {
    tokens: parking_lot::Mutex<HashMap<String, String>>,
}

impl TokenStore {
    fn issue(&self, login_id: &str) -> String {
        let token = format!("token-{}-{}", login_id, uuid_like());
        self.tokens
            .lock()
            .insert(token.clone(), login_id.to_string());
        token
    }

    fn resolve(&self, token: &str) -> GarrisonResult<String> {
        self.tokens
            .lock()
            .get(token)
            .cloned()
            .ok_or_else(|| GarrisonError::InvalidToken("token 无效".to_string()))
    }
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut buf = nanos.to_string().into_bytes();
    // 纳秒时间戳抗碰撞补强：进程内静态计数器后缀
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    buf.extend(SEQ.fetch_add(1, Ordering::Relaxed).to_string().into_bytes());
    String::from_utf8(buf).unwrap()
}

// ============================================================================
// MockAuthBackend：AuthBackend trait 测试替身（共享 TokenStore）
// ============================================================================

struct MockAuthBackend {
    store: Arc<TokenStore>,
}

#[async_trait]
impl AuthBackend for MockAuthBackend {
    async fn login(&self, login_id: &str, _params: &LoginParams) -> GarrisonResult<String> {
        Ok(self.store.issue(login_id))
    }

    async fn logout(&self, token: &str) -> GarrisonResult<()> {
        self.store.tokens.lock().remove(token);
        Ok(())
    }

    async fn check_login(&self, token: &str) -> GarrisonResult<bool> {
        Ok(self.store.tokens.lock().contains_key(token))
    }

    async fn check_permission(&self, token: &str, _permission: &str) -> GarrisonResult<()> {
        self.store.resolve(token)?;
        Ok(())
    }

    async fn check_role(&self, token: &str, _role: &str) -> GarrisonResult<()> {
        self.store.resolve(token)?;
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
        self.store.resolve(token)?;
        Ok(TokenInfo {
            token: token.to_string(),
            created_at: 1000,
            last_active_at: 2000,
        })
    }

    async fn get_session(&self, token: &str) -> GarrisonResult<SessionData> {
        let login_id = self.store.resolve(token)?;
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

    async fn switch_to(&self, _token: &str, _target_login_id: &str) -> GarrisonResult<()> {
        Ok(())
    }

    async fn kickout(&self, login_id: &str) -> GarrisonResult<()> {
        self.store
            .tokens
            .lock()
            .retain(|_, owner| owner != login_id);
        Ok(())
    }

    async fn renew_to_equivalent(&self, token: &str) -> GarrisonResult<String> {
        let login_id = self.store.resolve(token)?;
        let new_token = self.store.issue(&login_id);
        self.store.tokens.lock().remove(token);
        Ok(new_token)
    }
}

// ============================================================================
// StoreIssuer：扫码登录会话签发端口（与 MockAuthBackend 同源会话表）
// ============================================================================

struct StoreIssuer {
    store: Arc<TokenStore>,
}

#[async_trait]
impl QrLoginSessionIssuer for StoreIssuer {
    async fn resolve_app_login_id(&self, app_token: &str) -> GarrisonResult<String> {
        self.store.resolve(app_token)
    }

    async fn issue_session(&self, login_id: &str) -> GarrisonResult<String> {
        Ok(self.store.issue(login_id))
    }
}

// ============================================================================
// 服务器装配与双端 HTTP 工具
// ============================================================================

/// 启动真实双端口服务器（外网含 qrlogin 4 端点），返回 (外网 URL, 内网 URL, 句柄)。
async fn start_test_server() -> (String, String, tokio::task::JoinHandle<()>) {
    let store = Arc::new(TokenStore::default());
    let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend {
        store: Arc::clone(&store),
    });

    let dao: Arc<dyn garrison::dao::GarrisonDao> = Arc::new(garrison::dao::InMemoryDao::new());
    let service = Arc::new(QrLoginService::new(dao, "acceptance-qrlogin-secret").unwrap());
    let qrlogin_state = Arc::new(garrison::server::qrlogin_routes::QrLoginHttpState {
        service,
        issuer: Arc::new(StoreIssuer {
            store: Arc::clone(&store),
        }),
    });

    let external_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let external_port = external_listener.local_addr().unwrap().port();
    let internal_port = internal_listener.local_addr().unwrap().port();
    let external_url = format!("http://127.0.0.1:{}", external_port);
    let internal_url = format!("http://127.0.0.1:{}", internal_port);

    let server = GarrisonAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(1000)
        .with_external_login_enabled(true)
        .with_internal_api_key("acceptance-internal-key")
        .with_qrlogin(qrlogin_state);

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

/// 双端各持一个独立 reqwest Client（设备间零共享状态）。
fn device_client() -> reqwest::Client {
    reqwest::Client::new()
}

/// POST JSON（可带 Bearer），返回 (状态码, JSON)。
async fn post_json(
    client: &reqwest::Client,
    url: &str,
    body: serde_json::Value,
    bearer: Option<&str>,
) -> (reqwest::StatusCode, serde_json::Value) {
    let mut req = client.post(url).json(&body);
    if let Some(token) = bearer {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.expect("请求应送达服务器");
    let status = resp.status();
    let json: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Web 端（设备 1）创建扫码会话，返回 (qr_id, qr_content)。
async fn web_create(client: &reqwest::Client, external_url: &str) -> (String, String) {
    let resp = client
        .post(format!("{}/qrlogin/create", external_url))
        .header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
        )
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("create 请求应送达服务器");
    assert_eq!(resp.status(), reqwest::StatusCode::OK, "create 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    (
        body["qr_id"].as_str().unwrap().to_string(),
        body["qr_content"].as_str().unwrap().to_string(),
    )
}

/// Web 端轮询。
async fn web_poll(client: &reqwest::Client, external_url: &str, qr_id: &str) -> serde_json::Value {
    let (status, body) = post_json(
        client,
        &format!("{}/qrlogin/poll", external_url),
        serde_json::json!({ "qr_id": qr_id }),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "poll 应返回 200");
    body
}

/// App 端（设备 2）经真实 HTTP 登录获取会话 token。
async fn app_login(client: &reqwest::Client, external_url: &str, login_id: &str) -> String {
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": login_id,
            "params": LoginParams::default()
        }))
        .send()
        .await
        .expect("login 请求应送达服务器");
    assert_eq!(resp.status(), reqwest::StatusCode::OK, "login 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    body["data"].as_str().unwrap().to_string()
}

// ============================================================================
// 场景 1：双端全链路（核心验收）
// ============================================================================

/// 双端全链路：Web create → App 真实登录 → scan → poll(scanned) → confirm →
/// poll 兑换出真实会话 → 内网 get-session 核验归属确认者。
#[tokio::test]
#[serial]
async fn dual_device_full_flow_confirmed_and_exchange() {
    let (external_url, internal_url, _handle) = start_test_server().await;
    let web = device_client();
    let app = device_client();

    // ① Web 端创建扫码会话
    let (qr_id, qr_content) = web_create(&web, &external_url).await;
    assert_eq!(qr_id.len(), 64, "qr_id 应为 64 hex");
    assert!(qr_content.contains("t="), "qr_content 应含签名票据参数");

    // ② Web 端首次轮询：待扫码
    let poll_body = web_poll(&web, &external_url, &qr_id).await;
    assert_eq!(poll_body["status"], "pending");

    // ③ App 端已登录（真实 HTTP 登录流）
    let app_token = app_login(&app, &external_url, "app-user").await;

    // ④ App 端扫码：持 Bearer 提交扫到的二维码内容，收到一次性确认凭据
    //    与待登录端脱敏摘要（create 的 Chrome UA → 设备标签 Chrome）
    let (status, scan_body) = post_json(
        &app,
        &format!("{}/qrlogin/scan", external_url),
        serde_json::json!({ "qr_content": qr_content }),
        Some(&app_token),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "scan 应返回 200");
    let confirm_token = scan_body["confirm_token"].as_str().unwrap().to_string();
    assert_eq!(
        scan_body["web_device_label"], "Chrome",
        "确认页设备标签应为 Chrome（Quishing 防御用户可见面）"
    );

    // ⑤ Web 端轮询：已扫码待确认
    let poll_body = web_poll(&web, &external_url, &qr_id).await;
    assert_eq!(poll_body["status"], "scanned");

    // ⑥ App 端确认
    let (status, confirm_body) = post_json(
        &app,
        &format!("{}/qrlogin/confirm", external_url),
        serde_json::json!({ "confirm_token": confirm_token, "action": "confirm" }),
        Some(&app_token),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "confirm 应返回 200");
    assert_eq!(confirm_body["status"], "confirmed");

    // ⑦ Web 端轮询：Confirmed 分支原子兑换并签发真实会话
    let final_poll = web_poll(&web, &external_url, &qr_id).await;
    assert_eq!(final_poll["status"], "confirmed");
    let web_token = final_poll["token"].as_str().unwrap().to_string();
    assert!(
        !web_token.is_empty() && web_token != app_token,
        "兑换出的应是新会话 token，且不等于 App 端 token"
    );

    // ⑧ 闭环核验：兑换出的 token 是服务器上的真实会话，归属确认者 app-user
    let verifier = device_client();
    let resp = verifier
        .post(format!("{}/api/v1/auth/get-session", internal_url))
        .header("x-api-key", "acceptance-internal-key")
        .json(&serde_json::json!({ "token": web_token }))
        .send()
        .await
        .expect("get-session 请求应送达服务器");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "get-session 应返回 200"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["data"]["login_id"], "app-user",
        "兑换出的会话应归属确认者（App 端登录主体）"
    );
}

// ============================================================================
// 场景 2：扫码端点认证边界
// ============================================================================

/// 无 Bearer / 伪造 Bearer 均被 401 拒绝（扫码 ≠ 确认，确认凭据不外发）。
#[tokio::test]
#[serial]
async fn scan_rejects_missing_and_invalid_bearer() {
    let (external_url, _internal_url, _handle) = start_test_server().await;
    let web = device_client();
    let attacker = device_client();
    let (_, qr_content) = web_create(&web, &external_url).await;

    // 无 Bearer
    let (status, body) = post_json(
        &attacker,
        &format!("{}/qrlogin/scan", external_url),
        serde_json::json!({ "qr_content": qr_content }),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("app session token"));

    // 伪造 Bearer（不在服务器会话表中）
    let (status, _) = post_json(
        &attacker,
        &format!("{}/qrlogin/scan", external_url),
        serde_json::json!({ "qr_content": qr_content }),
        Some("forged-app-token"),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
}

/// 有效 Bearer + 伪造票据 → 400（验签 fail-closed）。
#[tokio::test]
#[serial]
async fn scan_forged_ticket_rejected() {
    let (external_url, _internal_url, _handle) = start_test_server().await;
    let app = device_client();
    let app_token = app_login(&app, &external_url, "app-user").await;

    let (status, body) = post_json(
        &app,
        &format!("{}/qrlogin/scan", external_url),
        serde_json::json!({ "qr_content": "garrison://qrlogin?t=forged.bad_sig" }),
        Some(&app_token),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap().contains("signature"),
        "错误应含签名语义，实际: {}",
        body["error"]
    );
}

// ============================================================================
// 场景 3：取消流程与重放
// ============================================================================

/// App 端取消：Web 端见 cancelled；重放已消费的 confirm_token 被拒。
#[tokio::test]
#[serial]
async fn dual_device_cancel_flow_and_replay_rejected() {
    let (external_url, _internal_url, _handle) = start_test_server().await;
    let web = device_client();
    let app = device_client();
    let (qr_id, qr_content) = web_create(&web, &external_url).await;
    let app_token = app_login(&app, &external_url, "app-user").await;

    let (_, scan_body) = post_json(
        &app,
        &format!("{}/qrlogin/scan", external_url),
        serde_json::json!({ "qr_content": qr_content }),
        Some(&app_token),
    )
    .await;
    let confirm_token = scan_body["confirm_token"].as_str().unwrap().to_string();

    // App 端在确认页选择取消
    let (status, confirm_body) = post_json(
        &app,
        &format!("{}/qrlogin/confirm", external_url),
        serde_json::json!({ "confirm_token": confirm_token, "action": "cancel" }),
        Some(&app_token),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(confirm_body["status"], "cancelled");

    // Web 端轮询：cancelled（无账号信息泄露）
    let poll_body = web_poll(&web, &external_url, &qr_id).await;
    assert_eq!(poll_body["status"], "cancelled");
    assert!(poll_body.get("token").is_none(), "取消后不得下发 token");

    // 重放已消费的 confirm_token：fail-closed
    let (status, _) = post_json(
        &app,
        &format!("{}/qrlogin/confirm", external_url),
        serde_json::json!({ "confirm_token": confirm_token, "action": "confirm" }),
        Some(&app_token),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
}

// ============================================================================
// 场景 4：并发轮询原子兑换
// ============================================================================

/// 两台 Web 设备（或刷新页）并发轮询同一 Confirmed 会话：仅一者兑换成功。
#[tokio::test]
#[serial]
async fn dual_device_concurrent_poll_single_winner() {
    let (external_url, _internal_url, _handle) = start_test_server().await;
    let web_a = device_client();
    let web_b = device_client();
    let app = device_client();
    let (qr_id, qr_content) = web_create(&web_a, &external_url).await;
    let app_token = app_login(&app, &external_url, "app-user").await;

    let (_, scan_body) = post_json(
        &app,
        &format!("{}/qrlogin/scan", external_url),
        serde_json::json!({ "qr_content": qr_content }),
        Some(&app_token),
    )
    .await;
    let confirm_token = scan_body["confirm_token"].as_str().unwrap().to_string();

    let (_, confirm_body) = post_json(
        &app,
        &format!("{}/qrlogin/confirm", external_url),
        serde_json::json!({ "confirm_token": confirm_token, "action": "confirm" }),
        Some(&app_token),
    )
    .await;
    assert_eq!(confirm_body["status"], "confirmed");

    // 两台 Web 设备并发轮询（真实 HTTP 竞争）
    let url_a = format!("{}/qrlogin/poll", external_url);
    let url_b = url_a.clone();
    let (res_a, res_b) = tokio::join!(
        post_json(&web_a, &url_a, serde_json::json!({ "qr_id": qr_id }), None),
        post_json(&web_b, &url_b, serde_json::json!({ "qr_id": qr_id }), None),
    );
    let outcomes = [res_a.1, res_b.1];
    let confirmed = outcomes
        .iter()
        .filter(|o| o["status"] == "confirmed")
        .count();
    let expired = outcomes.iter().filter(|o| o["status"] == "expired").count();
    assert_eq!(confirmed, 1, "并发兑换仅一者成功");
    assert_eq!(expired, 1, "另一者应见 expired（原子性）");

    // 落败方响应不得含任何账号信息（匿名轮询信息边界）
    let loser = outcomes.iter().find(|o| o["status"] == "expired").unwrap();
    assert!(loser.get("token").is_none(), "落败方不得下发 token");
}
