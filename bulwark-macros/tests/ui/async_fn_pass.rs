//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use bulwark::{
    check_access_token, check_api_key, check_client_token, check_login, check_permission,
    check_role, check_temp_token,
};
use axum::response::IntoResponse;

#[check_login]
async fn async_login_handler() -> &'static str {
    "ok"
}

#[check_permission("user:read")]
async fn async_perm_handler() -> &'static str {
    "ok"
}

#[check_role("admin")]
async fn async_role_handler() -> &'static str {
    "ok"
}

#[check_access_token]
async fn async_access_token_handler() -> &'static str {
    "ok"
}

#[check_client_token]
async fn async_client_token_handler() -> &'static str {
    "ok"
}

#[check_temp_token]
async fn async_temp_token_handler() -> &'static str {
    "ok"
}

#[check_api_key]
async fn async_api_key_handler() -> &'static str {
    "ok"
}

#[check_api_key(namespace = "internal")]
async fn async_api_key_ns_handler() -> &'static str {
    "ok"
}

// v0.7.0 命名参数形式（含 resource，vuln-0006 修复）
#[check_permission(permission = "order:read", resource = "Resource::\"order\"", abac = "resource.user_id == principal.id")]
async fn async_named_abac_handler() -> &'static str {
    "ok"
}

#[check_permission(permission = "user:read")]
async fn async_named_no_abac_handler() -> &'static str {
    "ok"
}

fn main() {
    let _ = async_login_handler;
    let _ = async_perm_handler;
    let _ = async_role_handler;
    let _ = async_access_token_handler;
    let _ = async_client_token_handler;
    let _ = async_temp_token_handler;
    let _ = async_api_key_handler;
    let _ = async_api_key_ns_handler;
    let _ = async_named_abac_handler;
    let _ = async_named_no_abac_handler;
}
