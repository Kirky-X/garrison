//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use bulwark::{
    check_access_token, check_api_key, check_client_token, check_login, check_permission,
    check_role, check_temp_token,
};
use axum::response::IntoResponse;

#[check_login]
fn sync_login_handler() -> &'static str {
    "ok"
}

#[check_permission("user:read")]
fn sync_perm_handler() -> &'static str {
    "ok"
}

#[check_role("admin")]
fn sync_role_handler() -> &'static str {
    "ok"
}

#[check_access_token]
fn sync_access_token_handler() -> &'static str {
    "ok"
}

#[check_client_token]
fn sync_client_token_handler() -> &'static str {
    "ok"
}

#[check_temp_token]
fn sync_temp_token_handler() -> &'static str {
    "ok"
}

#[check_api_key]
fn sync_api_key_handler() -> &'static str {
    "ok"
}

#[check_api_key(namespace = "internal")]
fn sync_api_key_ns_handler() -> &'static str {
    "ok"
}

fn main() {
    let _ = sync_login_handler;
    let _ = sync_perm_handler;
    let _ = sync_role_handler;
    let _ = sync_access_token_handler;
    let _ = sync_client_token_handler;
    let _ = sync_temp_token_handler;
    let _ = sync_api_key_handler;
    let _ = sync_api_key_ns_handler;
}
