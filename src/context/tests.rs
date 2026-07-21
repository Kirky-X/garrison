//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! context 模块测试（从 mod.rs 迁移，Rule 25 合规）。

use super::mock::MockResponse;
use super::*;

/// 验证 set_cookie 默认方法委托到 set_cookie_with_config。
#[test]
fn set_cookie_default_delegates_to_set_cookie_with_config() {
    let mut resp = MockResponse::new();
    let result = resp.set_cookie("session", "abc123");
    assert!(result.is_ok());
    assert_eq!(resp.cookies.get("session"), Some(&"abc123".to_string()));
}

/// 验证 set_cookie 默认方法使用 default_config。
#[test]
fn set_cookie_default_uses_default_config() {
    let mut resp = MockResponse::new();
    // set_cookie 默认方法应使用 GarrisonConfig::default_config()
    // MockResponse 的 set_cookie_with_config 忽略 config，仅验证调用链
    let result = resp.set_cookie("token", "xyz");
    assert!(result.is_ok());
    assert_eq!(resp.cookies.get("token"), Some(&"xyz".to_string()));
}

/// 验证 set_status 和 set_header 基本行为。
#[test]
fn mock_response_set_status_and_header() {
    let mut resp = MockResponse::new();
    resp.set_status(401).unwrap();
    resp.set_header("X-Custom", "value").unwrap();
    assert_eq!(resp.status, Some(401));
    assert_eq!(resp.headers.get("X-Custom"), Some(&"value".to_string()));
}

// ========================================================================
// T011 前后端分离行为变更测试
// ========================================================================

/// 验证 frontend_separation=true 时 effective_is_read_header 强制返回 true。
#[test]
fn t011_effective_is_read_header_frontend_separation_forces_true() {
    let mut config = crate::config::GarrisonConfig::default_config();
    config.is_read_header = false;
    config.frontend_separation = true;
    assert!(effective_is_read_header(&config));
}

/// 验证 frontend_separation=false 时 effective_is_read_header 遵循原配置。
#[test]
fn t011_effective_is_read_header_no_separation_respects_config() {
    let mut config = crate::config::GarrisonConfig::default_config();
    config.is_read_header = false;
    config.frontend_separation = false;
    assert!(!effective_is_read_header(&config));
}

/// 验证 frontend_separation=true 时 effective_is_read_cookie 强制返回 false。
#[test]
fn t011_effective_is_read_cookie_frontend_separation_forces_false() {
    let mut config = crate::config::GarrisonConfig::default_config();
    config.is_read_cookie = true;
    config.frontend_separation = true;
    assert!(!effective_is_read_cookie(&config));
}

/// 验证 frontend_separation=false 时 effective_is_read_cookie 遵循原配置。
#[test]
fn t011_effective_is_read_cookie_no_separation_respects_config() {
    let mut config = crate::config::GarrisonConfig::default_config();
    config.is_read_cookie = true;
    config.frontend_separation = false;
    assert!(effective_is_read_cookie(&config));
}

/// 验证 frontend_separation=true 时 set_cookie_with_frontend_check 跳过 Cookie 设置。
#[test]
fn t011_set_cookie_with_frontend_check_separation_skips_cookie() {
    let mut resp = MockResponse::new();
    let mut config = crate::config::GarrisonConfig::default_config();
    config.frontend_separation = true;
    let result = resp.set_cookie_with_frontend_check("session", "abc123", &config);
    assert!(result.is_ok());
    assert!(resp.cookies.is_empty());
}

/// 验证 frontend_separation=false 时 set_cookie_with_frontend_check 保持原有 Cookie 行为。
#[test]
fn t011_set_cookie_with_frontend_check_no_separation_sets_cookie() {
    let mut resp = MockResponse::new();
    let mut config = crate::config::GarrisonConfig::default_config();
    config.frontend_separation = false;
    let result = resp.set_cookie_with_frontend_check("session", "abc123", &config);
    assert!(result.is_ok());
    assert_eq!(resp.cookies.get("session"), Some(&"abc123".to_string()));
}
