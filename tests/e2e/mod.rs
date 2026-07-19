//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! E2E 测试公共辅助模块。
//!
//! 提供 BulwarkAuthServer + BackendEmbedded 全栈测试基础：
//! - `setup_backend()`：初始化全局 BulwarkManager（BulwarkDaoOxcache + MockInterface），返回 BackendEmbedded
//! - `setup_backend_with_dao()`：同上但返回共享 DAO（供 OAuth2State 使用）
//! - `start_e2e_server()`：随机端口启动 BulwarkAuthServer，返回 (external_url, internal_url, handle)
//! - `start_e2e_server_with_oauth2()`：含 OAuth2 端点
//!
//! # 租户隔离
//!
//! `full` feature 启用 `tenant-isolation`，`start_e2e_server*` 自动注入
//! `HeaderTenantResolver` + `tenant_resolution_middleware`，`make_client()`
//! 默认携带 `X-Tenant-Id: 0` header，使 `current_tenant_id_or_error()` 在
//! `check_permission` / `check_role` / 审计日志等场景能正确读取租户上下文。
//!
//! 所有 E2E 测试使用 `#[serial_test::serial]` 保证 BulwarkManager 全局单例安全。

#![allow(dead_code)]

use bulwark::backend::{AuthBackend, BackendEmbedded};
use bulwark::config::BulwarkConfig;
use bulwark::context::tenant::HeaderTenantResolver;
use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use bulwark::manager::BulwarkManager;
use bulwark::oauth2_server::client::DaoOAuth2ClientStore;
use bulwark::server::BulwarkAuthServer;
use bulwark::stp::BulwarkInterface;
use once_cell::sync::OnceCell;
use std::sync::Arc;

pub mod api_authz_boundary;
pub mod api_boundary;
pub mod api_errors;
pub mod api_happy;
pub mod auth_flow;
pub mod error_scenarios;
pub mod har_recorder;
pub mod log_analyzer;
pub mod middleware;
pub mod mock;
pub mod oauth2_flow;
pub mod pentest;
pub mod perf;
pub mod permission_flow;
pub mod remote;
pub mod session_flow;

/// E2E 测试用的空权限/空角色 mock 接口实现。
///
/// `BulwarkInterface` trait 实现位于 [`mock`] 子模块（规则 25 接口隔离）。
pub(super) struct MockInterface;

/// 创建 BulwarkDaoOxcache 实例（真实 oxcache 实现，非 Mock）。
async fn make_dao() -> Arc<dyn BulwarkDao> {
    Arc::new(BulwarkDaoOxcache::new().await.unwrap())
}

/// 初始化全局 BulwarkManager 并返回 BackendEmbedded 实例。
///
/// 每次调用先 `reset_for_test()` 清空全局状态，再用 BulwarkDaoOxcache + MockInterface 重新 init。
/// 返回的 BackendEmbedded 委托 BulwarkManager 全局单例，测试真实 auth 逻辑链路。
pub async fn setup_backend() -> BackendEmbedded {
    BulwarkManager::reset_for_test();
    let dao = make_dao().await;
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    BulwarkManager::init(dao, Arc::new(config), interface).unwrap();
    BackendEmbedded::new()
}

/// 初始化 BulwarkManager 并返回共享的 DAO（用于 OAuth2State）。
///
/// OAuth2 E2E 测试需要 DaoOAuth2ClientStore 与 BulwarkManager 共享同一 DAO，
/// 此函数返回 dao 引用供 OAuth2State 构造使用。
pub async fn setup_backend_with_dao() -> (BackendEmbedded, Arc<dyn BulwarkDao>) {
    BulwarkManager::reset_for_test();
    let dao = make_dao().await;
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    BulwarkManager::init(dao.clone(), Arc::new(config), interface).unwrap();
    (BackendEmbedded::new(), dao)
}

/// 随机端口启动 E2E 测试服务器（无 OAuth2）。
///
/// 返回 (external_url, internal_url, JoinHandle)。
/// 使用 BackendEmbedded 作为后端，测试真实 auth 逻辑。
pub async fn start_e2e_server(
    rate_limit: u32,
    api_key: &str,
) -> (String, String, tokio::task::JoinHandle<()>) {
    let backend: Arc<dyn AuthBackend> = Arc::new(setup_backend().await);

    let external_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let external_port = external_listener.local_addr().unwrap().port();
    let internal_port = internal_listener.local_addr().unwrap().port();

    let external_url = format!("http://127.0.0.1:{}", external_port);
    let internal_url = format!("http://127.0.0.1:{}", internal_port);

    // tenant-isolation feature 启用时注入 HeaderTenantResolver，使
    // tenant_resolution_middleware 解析 X-Tenant-Id header 进入 TENANT scope
    #[cfg(feature = "tenant-isolation")]
    let server = BulwarkAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        .with_internal_api_key(api_key)
        .with_tenant_resolver(Some(Arc::new(HeaderTenantResolver)));
    #[cfg(not(feature = "tenant-isolation"))]
    let server = BulwarkAuthServer::new(backend)
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
            eprintln!("E2E 外网服务器异常: {}", e);
        }
        if let Err(e) = int_res {
            eprintln!("E2E 内网服务器异常: {}", e);
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (external_url, internal_url, handle)
}

/// 随机端口启动 E2E 测试服务器（含 OAuth2 端点）。
///
/// 返回 (external_url, internal_url, JoinHandle, OAuth2ClientStore)。
/// OAuth2State 使用 DaoOAuth2ClientStore + 共享 BulwarkDaoOxcache。
pub async fn start_e2e_server_with_oauth2(
    rate_limit: u32,
    api_key: &str,
) -> (
    String,
    String,
    tokio::task::JoinHandle<()>,
    Arc<dyn bulwark::oauth2_server::client::OAuth2ClientStore>,
) {
    let (backend, dao) = setup_backend_with_dao().await;
    let backend: Arc<dyn AuthBackend> = Arc::new(backend);

    let store: Arc<dyn bulwark::oauth2_server::client::OAuth2ClientStore> =
        Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
    let oauth2_state = Arc::new(bulwark::server::oauth2_routes::OAuth2State::new(
        store.clone(),
        dao,
        "http://localhost/login".to_string(),
    ));

    let external_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let external_port = external_listener.local_addr().unwrap().port();
    let internal_port = internal_listener.local_addr().unwrap().port();

    let external_url = format!("http://127.0.0.1:{}", external_port);
    let internal_url = format!("http://127.0.0.1:{}", internal_port);

    // tenant-isolation feature 启用时注入 HeaderTenantResolver，使
    // tenant_resolution_middleware 解析 X-Tenant-Id header 进入 TENANT scope
    #[cfg(feature = "tenant-isolation")]
    let server = BulwarkAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        .with_internal_api_key(api_key)
        .with_oauth2(oauth2_state)
        .with_tenant_resolver(Some(Arc::new(HeaderTenantResolver)));
    #[cfg(not(feature = "tenant-isolation"))]
    let server = BulwarkAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        .with_internal_api_key(api_key)
        .with_oauth2(oauth2_state);

    let external_router = server.external_router();
    let internal_router = server.internal_router();

    let handle = tokio::spawn(async move {
        let (ext_res, int_res) = tokio::join!(
            axum::serve(external_listener, external_router),
            axum::serve(internal_listener, internal_router)
        );
        if let Err(e) = ext_res {
            eprintln!("E2E OAuth2 外网服务器异常: {}", e);
        }
        if let Err(e) = int_res {
            eprintln!("E2E OAuth2 内网服务器异常: {}", e);
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (external_url, internal_url, handle, store)
}

/// 构造默认租户上下文所需的 HTTP headers。
///
/// `tenant-isolation` feature 启用时插入 `X-Tenant-Id: 0`（默认租户），
/// 未启用时返回空 HeaderMap。供 `make_client` 与 `make_no_redirect_client`
/// 共享，避免重复实现（DRY）。
pub(super) fn default_tenant_headers() -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    #[cfg(feature = "tenant-isolation")]
    {
        headers.insert(
            "X-Tenant-Id",
            reqwest::header::HeaderValue::from_static("0"),
        );
    }
    headers
}

/// 创建 reqwest 客户端。
///
/// `tenant-isolation` feature 启用时，`start_e2e_server*` 会注入
/// `HeaderTenantResolver` + `tenant_resolution_middleware`，要求所有请求
/// 携带 `X-Tenant-Id` header。客户端通过 `default_headers` 设置默认值
/// `X-Tenant-Id: 0`（默认租户），所有 E2E 测试无需单独添加。
pub fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .default_headers(default_tenant_headers())
        .build()
        .expect("构造 reqwest 客户端失败")
}

/// 通过 HTTP 登录，返回 token。
pub async fn http_login(client: &reqwest::Client, external_url: &str, login_id: &str) -> String {
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": login_id,
            "params": bulwark::backend::types::LoginParams::default()
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    body["data"].as_str().unwrap().to_string()
}

/// 在默认租户上下文（tenant_id=0）内注册 OAuth2 客户端。
///
/// `start_e2e_server_with_oauth2` 注入 `tenant_resolution_middleware` 后，
/// server 端在 TENANT scope 内读写 DAO（key 含 `tenant:0:` 前缀）。
/// 测试代码直接调用 `store.create` 不在 TENANT scope 内，写入的 key 无前缀，
/// 导致 server 端读取时找不到。本 helper 用 `with_default_tenant` 包裹，
/// 保证写入 key 与 server 端读取 key 一致。
///
/// # 依赖
/// `testing` feature（间接通过 `with_default_tenant` 的 `cfg(any(test, feature = "testing"))`）。
///
/// # 失败处理
/// `store.create` 失败时 panic 并透传完整错误信息（规则 12 失败显性化）。
pub async fn register_oauth2_client(
    store: &dyn bulwark::oauth2_server::client::OAuth2ClientStore,
    client: bulwark::oauth2_server::client::OAuth2Client,
) {
    bulwark::context::tenant::with_default_tenant(async {
        if let Err(e) = store.create(client).await {
            panic!("register_oauth2_client failed: {e:?}");
        }
    })
    .await;
}

/// HTTP 抓包日志共享单例（OnceCell）。
///
/// 首次调用 `open_http_log()` 时以 truncate 模式打开 `logs/e2e_http.jsonl`，
/// 后续调用复用同一 `Arc<Mutex<BufWriter<File>>>`，所有 `RecordingClient`
/// 共享同一文件句柄。
static HTTP_LOG: OnceCell<Arc<parking_lot::Mutex<std::io::BufWriter<std::fs::File>>>> =
    OnceCell::new();

/// 打开 HTTP 抓包日志文件（共享单例）。
///
/// 若 `logs/` 目录不存在则创建。文件以 truncate 模式打开（每次测试运行清空），
/// 后续调用复用同一 `Arc<Mutex<BufWriter<File>>>`。
///
/// # 失败处理
/// 创建目录 / 打开文件失败时 panic（规则 12 失败显性化），测试无法继续。
pub fn open_http_log() -> Arc<parking_lot::Mutex<std::io::BufWriter<std::fs::File>>> {
    HTTP_LOG
        .get_or_init(|| {
            std::fs::create_dir_all("logs").expect("创建 logs/ 目录失败");
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open("logs/e2e_http.jsonl")
                .expect("打开 logs/e2e_http.jsonl 失败");
            Arc::new(parking_lot::Mutex::new(std::io::BufWriter::new(file)))
        })
        .clone()
}

/// 创建带 HTTP 抓包能力的 `RecordingClient`。
///
/// 共享 `open_http_log()` 单例作为日志写入端，设置初始 `test_name`。
/// 调用方可在测试中通过 `set_test_name()` 切换 test_name。
pub fn make_recording_client(test_name: &str) -> har_recorder::RecordingClient {
    let log_writer = open_http_log();
    har_recorder::RecordingClient::new(log_writer, test_name.to_string())
}

/// 断言 check-login 响应表达"token 已失效/拒绝"语义。
///
/// # Spec 与实际行为差异（spawn_child 模式）
///
/// `examples/auth_server.rs::serve()` 使用 `BulwarkConfig::default_config()`，
/// `throw_on_not_login` 默认为 `true`。`start_e2e_server()` 的 in-process 模式
/// 显式设置 `throw_on_not_login=false`，二者行为不同：
///
/// | 模式 | throw_on_not_login | 无效 token check-login 响应 |
/// |------|-------------------|---------------------------|
/// | in-process | false | `{"data": false}` |
/// | spawn_child | true  | `{"error_code": "SESSION_ERROR", "message": "会话错误"}` |
///
/// 用户约束"禁止修改 src/ 主 crate 代码 - 只能修改 tests/e2e/ 目录下的文件"，
/// 且 specmark T002 规定 `serve()` 用 `default_config()`，不可调整 config。
/// 因此 `RemoteContext::setup()` 走 spawn_child 分支时，测试断言需同时接受
/// 两种表达方式：`data=false` 或 `error_code` 存在（业务层拒绝语义）。
///
/// # 参数
/// - `body`: check-login 响应 JSON。
/// - `context`: 失败时的上下文描述（用于 panic message）。
pub fn assert_check_login_denied(body: &serde_json::Value, context: &str) {
    let data_false = body["data"] == false;
    let has_error_code = body.get("error_code").is_some() && !body["error_code"].is_null();
    assert!(
        data_false || has_error_code,
        "{}: check-login 应表达拒绝语义（data=false 或 error_code 存在），实际 body={:?}",
        context,
        body
    );
}

/// 初始化全局 BulwarkManager（`is_concurrent=false` 配置），返回 BackendEmbedded。
///
/// 与 `setup_backend()` 唯一差异：`config.is_concurrent = false`，使同账号新登录
/// 踢出旧会话（`ReplacedLoginExitMode::OldDevice` 默认行为）。
///
/// 供 `pentest::session_hijack::pentest_session_hijack_concurrent_login_disabled` 使用
/// （T046 需要验证 `is_concurrent=false` 时同账号多设备登录互踢）。
/// `RemoteContext::spawn_child()` 走 `serve()` + `default_config()` 无法自定义此字段，
/// 故提供 in-process 变体（spec 已预判此偏差）。
pub async fn setup_backend_no_concurrent() -> BackendEmbedded {
    BulwarkManager::reset_for_test();
    let dao = make_dao().await;
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    config.is_concurrent = false;
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    BulwarkManager::init(dao, Arc::new(config), interface).unwrap();
    BackendEmbedded::new()
}

/// 随机端口启动 E2E 测试服务器（`is_concurrent=false` 配置）。
///
/// 与 `start_e2e_server()` 行为一致，唯一差异：调用 `setup_backend_no_concurrent()`
/// 构造 `is_concurrent=false` 的全局 BulwarkManager，使同账号多设备登录互踢。
/// 供 T046 会话劫持测试使用。
pub async fn start_e2e_server_no_concurrent(
    rate_limit: u32,
    api_key: &str,
) -> (String, String, tokio::task::JoinHandle<()>) {
    let backend: Arc<dyn AuthBackend> = Arc::new(setup_backend_no_concurrent().await);

    let external_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let external_port = external_listener.local_addr().unwrap().port();
    let internal_port = internal_listener.local_addr().unwrap().port();

    let external_url = format!("http://127.0.0.1:{}", external_port);
    let internal_url = format!("http://127.0.0.1:{}", internal_port);

    #[cfg(feature = "tenant-isolation")]
    let server = BulwarkAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        .with_internal_api_key(api_key)
        .with_tenant_resolver(Some(Arc::new(HeaderTenantResolver)));
    #[cfg(not(feature = "tenant-isolation"))]
    let server = BulwarkAuthServer::new(backend)
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
            eprintln!("E2E no_concurrent 外网服务器异常: {}", e);
        }
        if let Err(e) = int_res {
            eprintln!("E2E no_concurrent 内网服务器异常: {}", e);
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (external_url, internal_url, handle)
}
