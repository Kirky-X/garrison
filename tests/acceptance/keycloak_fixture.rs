// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 真实 Keycloak 测试夹具（OAuth2/OIDC 协议验收共享）。
//!
//! 2026-09 起协议层验收禁止 wiremock 模拟授权服务器（用户裁定：仅单元测试
//! 可 mock），一律打 docker-compose.e2e.yml 拉起的真实 Keycloak 26。realm
//! 数据由 `scripts/keycloak_provision.py` 幂等供给（realm=garrison，客户端
//! `garrison-cli`，用户 `alice`）。
//!
//! 授权码获取：garrison 无浏览器，此处以 reqwest（禁自动重定向 + cookie
//! jar）驱动 Keycloak 真实登录表单流——GET auth → 200 登录页 → 解析
//! `<form action>` → POST 凭证 → 302 回调 Location 提取 `code` + `state`。
//! 这是真实用户登录路径（同一套表单/cookie/action 语义），非协议模拟。
//!
//! 门控约定：Keycloak 不可达时 `eprintln!("[SKIP] …")` 并 `return`——与
//! tests/acceptance/environment.rs 的外部服务门控语义一致。

#![cfg(feature = "protocol-oauth2")]

use std::time::Duration;

/// Keycloak 根地址：`GARRISON_TEST_KEYCLOAK_URL` 可覆盖
///（默认 compose 映射的 `http://127.0.0.1:18090`）。
pub(crate) fn keycloak_base() -> String {
    std::env::var("GARRISON_TEST_KEYCLOAK_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18090".to_string())
}

/// garrison realm 根 URL（KeycloakProvider::base_url / expected_iss 同值）。
pub(crate) fn realm_base() -> String {
    format!("{}/realms/garrison", keycloak_base())
}

/// OIDC 端点前缀（`{realm}/protocol/openid-connect`）。
pub(crate) fn oidc_base() -> String {
    format!("{}/protocol/openid-connect", realm_base())
}

pub(crate) const CLIENT_ID: &str = "garrison-cli";
pub(crate) const CLIENT_SECRET: &str = "garrison-cli-secret";
pub(crate) const USERNAME: &str = "alice";
pub(crate) const PASSWORD: &str = "alice-password-2026";
/// 回调地址（localhost http 例外，OAuth2Client 构造校验放行；已注册于客户端）
pub(crate) const REDIRECT_LOCAL: &str = "http://127.0.0.1:18081/callback";
/// https 回调地址（已注册于客户端；测试只解析 Location，不实际访问）
pub(crate) const REDIRECT_HTTPS: &str = "https://app.example.com/callback";

/// 真实 Keycloak 访问夹具。每测试自建实例（reqwest Client 可克隆共享连接池）。
pub(crate) struct KeycloakFixture {
    /// 禁自动重定向 + cookie jar：驱动真实登录表单流所需。
    browser: reqwest::Client,
    plain: reqwest::Client,
}

impl KeycloakFixture {
    pub(crate) fn new() -> Self {
        let browser = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(true)
            .timeout(Duration::from_secs(15))
            .build()
            .expect("构造登录流 reqwest 客户端应成功");
        let plain = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("构造 plain reqwest 客户端应成功");
        Self { browser, plain }
    }

    /// Keycloak 探活：realm discovery 可达即视为可用。
    /// 不可达时打印 `[SKIP]`（与 environment.rs 门控约定一致）并返回 false。
    pub(crate) async fn available_or_skip(&self, scenario: &str) -> bool {
        let url = format!("{}/.well-known/openid-configuration", realm_base());
        let ok = self
            .plain
            .get(&url)
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if !ok {
            eprintln!(
                "[SKIP] {scenario}: Keycloak 不可达（{} 未监听或 realm 未供给，\
                 见 scripts/keycloak_provision.py），跳过真实 IdP 场景",
                keycloak_base()
            );
        }
        ok
    }

    /// 构造指向真实 Keycloak 的 `OAuth2Client`。
    pub(crate) fn oauth2_client(
        &self,
        client_secret: &str,
        redirect_uri: &str,
    ) -> garrison::protocol::oauth2::OAuth2Client {
        garrison::protocol::oauth2::OAuth2Client::new(
            CLIENT_ID,
            client_secret,
            redirect_uri,
            format!("{}/auth", oidc_base()),
            format!("{}/token", oidc_base()),
        )
        .expect("OAuth2Client 构造失败（真实 Keycloak 端点均为本机 http）")
    }

    /// 驱动真实登录表单流获取授权码。
    ///
    /// `code_challenge` 传 `Some` 时授权请求携带 PKCE S256 参数；`scope` 传
    /// `Some("openid")` 时携带 scope。返回 `(code, state)`（state 来自回调
    /// Location，供调用方做真实 CSRF 比对）。
    pub(crate) async fn obtain_auth_code(
        &self,
        scope: Option<&str>,
        redirect_uri: &str,
        state: &str,
        code_challenge: Option<&str>,
    ) -> Result<(String, String), String> {
        let mut url = format!(
            "{}/auth?response_type=code&client_id={}&redirect_uri={}&state={}",
            oidc_base(),
            urlencoded(CLIENT_ID),
            urlencoded(redirect_uri),
            urlencoded(state),
        );
        if let Some(s) = scope {
            url.push_str("&scope=");
            url.push_str(&urlencoded(s));
        }
        if let Some(challenge) = code_challenge {
            url.push_str("&code_challenge=");
            url.push_str(&urlencoded(challenge));
            url.push_str("&code_challenge_method=S256");
        }

        // 1) GET auth → 200 登录页（无会话时 Keycloak 直接回表单，无 302）
        let resp = self
            .browser
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("GET auth 失败: {e}"))?;
        let page = resp
            .error_for_status()
            .map_err(|e| format!("auth 页非 2xx: {e}"))?;
        let html = page
            .text()
            .await
            .map_err(|e| format!("读登录页失败: {e}"))?;
        let action =
            extract_form_action(&html).ok_or_else(|| "登录页未解析到 <form action>".to_string())?;

        // 2) POST 凭证 → 302 回调 Location 携带 code + state
        let resp = self
            .browser
            .post(&action)
            .form(&[("username", USERNAME), ("password", PASSWORD)])
            .send()
            .await
            .map_err(|e| format!("POST 登录凭证失败: {e}"))?;
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                format!(
                    "登录后无 302 Location（凭证错误或表单流异常，status={}）",
                    resp.status()
                )
            })?
            .to_string();
        let code = query_param(&location, "code")
            .ok_or_else(|| format!("回调 Location 无 code: {location}"))?;
        let returned_state = query_param(&location, "state")
            .ok_or_else(|| format!("回调 Location 无 state: {location}"))?;
        Ok((code, returned_state))
    }

    /// 直连 token 端点（raw form 请求，供 password grant / 内省对照等场景）。
    pub(crate) async fn post_form(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<reqwest::Response, String> {
        self.plain
            .post(format!(
                "{oidc_base}{path}",
                oidc_base = oidc_base(),
                path = path
            ))
            .form(form)
            .send()
            .await
            .map_err(|e| format!("POST {path} 失败: {e}"))
    }
}

/// RFC 7009 撤销端点路径（[`KeycloakFixture::post_form`] 的 path 入参）。
pub(crate) const REVOKE_PATH: &str = "/revoke";

/// URL 百分号编码（与 OAuth2Client 的保留字符集一致：`A-Z a-z 0-9 - _ . ~`）。
fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            },
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 从登录页 HTML 提取第一个 `<form ... action="...">`（Keycloak 表单 action
/// 属性内 `&` 转义为 `&amp;`，需还原）。
fn extract_form_action(html: &str) -> Option<String> {
    let idx = html.find("action=\"")? + "action=\"".len();
    let rest = &html[idx..];
    let end = rest.find('"')?;
    Some(rest[..end].replace("&amp;", "&"))
}

/// 从 URL 提取查询参数首值。
fn query_param(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{extract_form_action, query_param, urlencoded};

    #[test]
    fn urlencoded_preserves_unreserved_and_encodes_rest() {
        assert_eq!(urlencoded("aB3-_.~"), "aB3-_.~");
        assert_eq!(urlencoded("a b/c:d"), "a%20b%2Fc%3Ad");
    }

    #[test]
    fn extract_form_action_unescapes_amp() {
        let html = r#"<form id="kc-form-login" action="http://kc/login-actions/authenticate?a=1&amp;b=2" method="post">"#;
        assert_eq!(
            extract_form_action(html).unwrap(),
            "http://kc/login-actions/authenticate?a=1&b=2"
        );
    }

    #[test]
    fn query_param_extracts_first_value() {
        let url = "http://cb?state=acc-state&session_state=x&code=abc.123";
        assert_eq!(query_param(url, "code").unwrap(), "abc.123");
        assert_eq!(query_param(url, "state").unwrap(), "acc-state");
        assert!(query_param(url, "missing").is_none());
        assert!(query_param("http://cb", "code").is_none());
    }
}
