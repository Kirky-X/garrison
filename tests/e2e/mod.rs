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
//! 所有 E2E 测试使用 `#[serial_test::serial]` 保证 BulwarkManager 全局单例安全。

#![allow(dead_code)]

use async_trait::async_trait;
use bulwark::backend::{AuthBackend, BackendEmbedded};
use bulwark::config::BulwarkConfig;
use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use bulwark::error::BulwarkResult;
use bulwark::manager::BulwarkManager;
use bulwark::oauth2_server::client::DaoOAuth2ClientStore;
use bulwark::server::BulwarkAuthServer;
use bulwark::stp::BulwarkInterface;
use std::sync::Arc;

pub mod auth_flow;
pub mod error_scenarios;
pub mod middleware;
pub mod oauth2_flow;
pub mod permission_flow;
pub mod session_flow;

struct MockInterface;

#[async_trait]
impl BulwarkInterface for MockInterface {
    async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
}

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

/// 创建 reqwest 客户端。
pub fn make_client() -> reqwest::Client {
    reqwest::Client::new()
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
