// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Web 适配层 Cookie 安全默认与配置覆盖（v1.0 门禁 T006-T008）。

use garrison::config::GarrisonConfig;
use garrison::context::{build_set_cookie_value, CookieType, GarrisonResponse};
use garrison::error::GarrisonResult;

#[derive(Default)]
struct MockResponse {
    headers: Vec<(String, String)>,
}

impl GarrisonResponse for MockResponse {
    fn set_status(&mut self, _code: u16) -> GarrisonResult<()> {
        Ok(())
    }

    fn set_header(&mut self, name: &str, value: &str) -> GarrisonResult<()> {
        self.headers.push((name.to_string(), value.to_string()));
        Ok(())
    }
}

fn set_cookie_header(response: &MockResponse) -> &str {
    response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, value)| value.as_str())
        .expect("response should contain Set-Cookie")
}

#[test]
fn default_cookie_uses_secure_profile_defaults() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.cookie_same_site, "Lax");

    #[cfg(feature = "development")]
    assert!(
        !config.cookie_secure,
        "development profile must default to non-Secure"
    );
    #[cfg(not(feature = "development"))]
    assert!(
        config.cookie_secure,
        "non-development profile must default to Secure"
    );

    let cookie = CookieType::token(&config).expect("default cookie config should be valid");
    let value = build_set_cookie_value(&cookie, "token-value", config.cookie_secure)
        .expect("cookie build should succeed");

    assert!(
        value.contains("HttpOnly"),
        "cookie must be HttpOnly: {value}"
    );
    assert!(
        value.contains("SameSite=Lax"),
        "cookie must be SameSite=Lax: {value}"
    );
    assert!(value.contains("Path=/"), "cookie must be Path=/: {value}");
    #[cfg(feature = "development")]
    assert!(
        !value.contains("; Secure"),
        "development cookie must not be Secure: {value}"
    );
    #[cfg(not(feature = "development"))]
    assert!(
        value.contains("; Secure"),
        "non-development cookie must be Secure: {value}"
    );
}

#[test]
fn response_adapter_uses_single_cookie_builder() {
    let config = GarrisonConfig::default_config();
    let mut response = MockResponse::default();
    response
        .set_cookie_with_config("garrison_token", "token-value", &config)
        .expect("set_cookie_with_config should succeed");

    let value = set_cookie_header(&response);
    assert!(value.starts_with("garrison_token=token-value"));
    assert!(value.contains("HttpOnly"));
    assert!(value.contains("SameSite=Lax"));
    assert!(value.contains("Path=/"));
    #[cfg(not(feature = "development"))]
    assert!(value.contains("; Secure"));
}

#[test]
fn explicit_config_override_wins() {
    let mut config = GarrisonConfig::default_config();
    config.cookie_secure = false;
    config.cookie_same_site = "Strict".to_string();

    let cookie = CookieType::token(&config).expect("configured cookie should be valid");
    let value = build_set_cookie_value(&cookie, "token-value", config.cookie_secure)
        .expect("cookie build should succeed");

    assert!(
        !value.contains("; Secure"),
        "explicit insecure override must win: {value}"
    );
    assert!(
        value.contains("SameSite=Strict"),
        "explicit SameSite override must win: {value}"
    );
}

#[test]
fn same_site_none_downgrades_without_secure() {
    let mut config = GarrisonConfig::default_config();
    config.cookie_secure = false;
    config.cookie_same_site = "None".to_string();

    let cookie = CookieType::token(&config).expect("configured cookie should be valid");
    let value = build_set_cookie_value(&cookie, "token-value", config.cookie_secure)
        .expect("cookie build should succeed");

    assert!(
        value.contains("SameSite=Lax"),
        "SameSite=None without Secure must downgrade to Lax: {value}"
    );
    assert!(!value.contains("SameSite=None"));
}
