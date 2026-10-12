// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! CSRF 防护中间件（Double-Submit Cookie）：安全方法懒生成 token 写 Cookie 后放行；
//! 受保护方法校验 Origin/Referer 与 Host 同源 + Header/Cookie token 常量时间一致。
//! fail-closed：Origin 与 Referer 均缺失即 403（非浏览器客户端需显式发与 Host 一致的 Origin
//! 或加入 `excluded_paths`）；`enabled == false` 或路径命中 `excluded_paths` 时放行。
//! 配置见 [`CsrfConfig`](crate::web::csrf::CsrfConfig)。

use crate::context::{build_set_cookie_value, CookiePath, CookieScope, CookieType};
use crate::error::GarrisonResult;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

/// CSRF cookie 默认有效期（秒）：`Max-Age` 限制 token 生命周期，防 XSS/日志泄露的 token 被无限 replay。
const CSRF_TOKEN_TTL_SECS: i64 = 3600;

/// CSRF 防护配置（默认启用，secure-by-default；受保护方法默认 POST/PUT/PATCH/DELETE）。
///
/// # 配置示例
///
/// ```toml
/// [csrf_config]
/// enabled = true
/// excluded_paths = ["/api/webhook"]
/// cookie_name = "my_csrf"
/// cookie_domain = "example.com"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CsrfConfig {
    /// 是否启用 CSRF 防护。
    pub enabled: bool,
    /// CSRF Cookie 名称。
    pub cookie_name: String,
    /// CSRF Header 名称（客户端通过此 Header 提交 token）。
    pub header_name: String,
    /// 排除校验的路径列表（精确匹配）。
    pub excluded_paths: Vec<String>,
    /// 受保护方法列表（大小写不敏感）。
    pub protected_methods: Vec<String>,
    /// 是否在 Cookie 中设置 Secure 标志（默认 `true`，与 GarrisonConfig 一致）。
    pub cookie_secure: bool,
    /// CSRF Cookie 的 Domain 属性：`None`（默认）不设置（Cookie 仅对当前 host 生效，最严格作用域）；
    /// `Some(d)` 设置 `Domain=<d>` 并扩大到全部子域——子域不可信（如用户托管页面）时应保持 `None`。
    pub cookie_domain: Option<String>,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cookie_name: "garrison_csrf_token".to_string(),
            header_name: "X-CSRF-Token".to_string(),
            excluded_paths: Vec::new(),
            protected_methods: vec![
                "POST".to_string(),
                "PUT".to_string(),
                "PATCH".to_string(),
                "DELETE".to_string(),
            ],
            cookie_secure: true,
            cookie_domain: None,
        }
    }
}

// generate_csrf_token + validate_csrf_token

/// 生成 CSRF token：读 OS CSPRNG（`getrandom::fill`）32 字节，URL-safe Base64 无填充（约 43 字符）。
pub fn generate_csrf_token() -> GarrisonResult<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let mut bytes = [0u8; 32];
    // 直接读 OS CSPRNG（getrandom::fill），无用户态 DRBG 缓冲——与 oauth2 授权码路径同一安全立场
    getrandom::fill(&mut bytes).expect("OS CSPRNG 不可用");
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// 校验 CSRF token（常量时间比较，防时序攻击）：长度 + 逐字节比较统一委托
/// [`crate::secure::ct_eq::constant_time_eq`]（ADR-0003 决策 2：消除本地第二实现，不提前返回）；
/// 任一 token 为空视为非法输入返回 `false`，否则长度一致且逐字节匹配返回 `true`。
pub fn validate_csrf_token(header_token: &str, cookie_token: &str) -> bool {
    let h = header_token.as_bytes();
    let c = cookie_token.as_bytes();

    // 空 token 非法：非短路 & 保证与后续比较无条件聚合
    let non_empty = !h.is_empty() & !c.is_empty();

    let bytes_eq = crate::secure::ct_eq::constant_time_eq(h, c);

    non_empty & bytes_eq
}

// garrison_csrf_middleware

/// 从请求 headers 中提取指定名称的 Cookie 值。
fn extract_cookie_value(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=') {
            if name.trim() == cookie_name {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// CSRF cookie 构建点输入：SameSite=Lax 固定，Max-Age 为 token TTL；Secure 上下文不进入本构造，
/// 前缀在读取名/构建值阶段按 `cookie_secure` 解析。
fn csrf_cookie_type(cookie_name: &str, cookie_domain: Option<&str>) -> CookieType {
    CookieType {
        name: cookie_name.to_string(),
        scope: CookieScope::LaxHttpOnly,
        path: CookiePath::Root,
        domain: cookie_domain.filter(|d| !d.is_empty()).map(str::to_string),
        max_age: Some(CSRF_TOKEN_TTL_SECS),
    }
}

/// 构建 Set-Cookie 值（委托 context 层单一构建点 [`build_set_cookie_value`]）：属性顺序与
/// `__Host-`/`__Secure-` 前缀由构建点强制（production + Secure 下无 Domain 为 `__Host-<name>`，
/// 有 Domain 为 `__Secure-<name>`）。`Domain` 扩大作用域到子域，仅确需跨子域共享时传 `Some`；
/// 构建失败（name/domain 含注入字符等）返回 [`GarrisonError::Context`]，调用方不得产出 Set-Cookie 头（fail-fast）。
fn build_set_cookie(
    cookie_name: &str,
    token: &str,
    cookie_secure: bool,
    cookie_domain: Option<&str>,
) -> GarrisonResult<String> {
    let cookie = csrf_cookie_type(cookie_name, cookie_domain);
    build_set_cookie_value(&cookie, token, cookie_secure)
}

/// 从绝对 URI（Origin/Referer header 值）提取 `host[:port]`：归一化去除显式默认端口
/// （https:443 / http:80——浏览器对带/不带默认端口发送的 Host 一致，不归一化会误拒同源请求）；
/// 解析失败或无 host 返回 `None`。
fn extract_origin_host(uri_str: &str) -> Option<String> {
    let uri: axum::http::Uri = uri_str.parse().ok()?;
    let host = uri.host()?;
    let port = uri.port_u16();
    // 默认端口归一化：https:443 / http:80 等价于不带端口
    let is_default_port = matches!(
        (uri.scheme_str(), port),
        (Some("https"), Some(443)) | (Some("http"), Some(80))
    );
    match (port, is_default_port) {
        (Some(p), false) => Some(format!("{}:{}", host, p)),
        _ => Some(host.to_string()),
    }
}

/// 归一化 Host header：一律去除 `:80`/`:443`（Host 不含 scheme），与 [`extract_origin_host`] 对齐
/// （代理场景 `Host: example.com:443` 与 `Origin: https://example.com` 视为同源）；
/// 非默认端口保留（不同端口即不同源），IPv6（`[::1]:8080`）安全处理。
fn normalize_host(host: &str) -> String {
    if let Some(rest) = host.strip_prefix('[') {
        // IPv6 字面量：[addr] 或 [addr]:port
        match rest.split_once(']') {
            Some((addr, after)) => {
                match after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()) {
                    Some(80) | Some(443) => format!("[{}]", addr),
                    _ => host.to_string(),
                }
            },
            None => host.to_string(),
        }
    } else {
        match host.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>().ok() {
                Some(80) | Some(443) => h.to_string(),
                _ => host.to_string(),
            },
            None => host.to_string(),
        }
    }
}

/// 校验 Origin/Referer 与 Host 是否同源：优先 `Origin`，缺失回退 `Referer`，双方归一化默认端口后严格比较；
/// Host 缺失或两者均缺失返回 `false`。后者是刻意的 fail-closed（即使 token 校验正确也 403）：
/// 浏览器跨站 POST 必带 Origin/Referer，非浏览器客户端需显式发与 Host 一致的 `Origin`
/// 或加入 [`CsrfConfig::excluded_paths`]。
fn validate_same_origin(headers: &HeaderMap) -> bool {
    let host = match headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => normalize_host(h),
        None => return false,
    };

    // 优先 Origin
    if let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        return extract_origin_host(origin)
            .map(|oh| oh == host)
            .unwrap_or(false);
    }

    if let Some(referer) = headers
        .get(axum::http::header::REFERER)
        .and_then(|v| v.to_str().ok())
    {
        return extract_origin_host(referer)
            .map(|rh| rh == host)
            .unwrap_or(false);
    }

    // Origin/Referer 均缺失 → false → 403（fail-closed）
    false
}

/// CSRF 防护中间件：基于 [`CsrfConfig`] 校验请求（安全方法懒生成 token 写 Cookie，受保护方法同源 + 双份 token 校验）。
///
/// # 使用
///
/// ```ignore
/// use garrison::web::csrf::{garrison_csrf_middleware, CsrfConfig};
/// use std::sync::Arc;
/// use axum::Router;
///
/// let config = CsrfConfig { enabled: true, ..Default::default() };
/// let app = Router::new()
/// .route("/api", axum::routing::get(|| async { "ok" }))
/// .layer(axum::middleware::from_fn_with_state(
/// Arc::new(config),
/// garrison_csrf_middleware,
/// ));
/// ```
pub async fn garrison_csrf_middleware(
    State(config): State<std::sync::Arc<CsrfConfig>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let method = req.method().as_str().to_string();
    // 写读同名：读侧查找名与 build_set_cookie 走同一前缀解析（production + Secure 下为 __Host-/__Secure-）
    let cookie_name = csrf_cookie_type(&config.cookie_name, config.cookie_domain.as_deref())
        .resolved_name(config.cookie_secure);
    let is_protected = config
        .protected_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(&method));

    if is_protected {
        // 受保护方法：校验 CSRF token
        if !config.enabled {
            return next.run(req).await;
        }
        let path = req.uri().path().to_string();
        if config.excluded_paths.iter().any(|p| p == &path) {
            return next.run(req).await;
        }
        // Origin/Referer 同源校验（defense-in-depth）
        if !validate_same_origin(req.headers()) {
            return (StatusCode::FORBIDDEN, "CSRF origin validation failed").into_response();
        }
        let cookie_token = extract_cookie_value(req.headers(), &cookie_name);
        let header_token = req
            .headers()
            .get(config.header_name.as_str())
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        match (cookie_token, header_token) {
            (Some(ct), Some(ht)) => {
                if validate_csrf_token(&ht, &ct) {
                    next.run(req).await
                } else {
                    (StatusCode::FORBIDDEN, "CSRF token validation failed").into_response()
                }
            },
            _ => (StatusCode::FORBIDDEN, "CSRF token missing").into_response(),
        }
    } else {
        // 安全方法：懒生成 CSRF token
        let has_cookie = extract_cookie_value(req.headers(), &cookie_name).is_some();
        let mut resp = next.run(req).await;
        if !has_cookie {
            if let Ok(token) = generate_csrf_token() {
                match build_set_cookie(
                    &config.cookie_name,
                    &token,
                    config.cookie_secure,
                    config.cookie_domain.as_deref(),
                ) {
                    Ok(set_cookie) => {
                        if let Ok(value) = HeaderValue::from_str(&set_cookie) {
                            resp.headers_mut()
                                .append(axum::http::header::SET_COOKIE, value);
                        }
                    },
                    // 静默丢 cookie 是可观测事件：构建点拒绝（name/domain 注入等）warn 显性化
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "{}",
                            crate::i18n::translate_detail(
                                "logs-csrf-set-cookie-build-failed",
                                &[]
                            )
                        );
                    },
                }
            }
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use std::sync::Arc;
    use tower::ServiceExt;

    // ----------------------------------------------------------------
    // 辅助函数
    // ----------------------------------------------------------------

    fn make_app(config: CsrfConfig) -> Router {
        Router::new()
            .route(
                "/api/test",
                get(|| async { "ok" })
                    .post(|| async { "ok" })
                    .put(|| async { "ok" })
                    .delete(|| async { "ok" })
                    .options(|| async { "ok" }),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(config),
                garrison_csrf_middleware,
            ))
    }

    fn make_request(method: &str, path: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    /// 默认配置下 CSRF cookie 的解析名（production 前缀感知，
    /// 供请求 fixture 与写侧构建点保持写读同名）。
    fn default_csrf_cookie_name() -> String {
        let config = CsrfConfig::default();
        csrf_cookie_type(&config.cookie_name, config.cookie_domain.as_deref())
            .resolved_name(config.cookie_secure)
    }

    fn make_request_with_csrf(
        method: &str,
        path: &str,
        cookie_token: &str,
        header_token: &str,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("host", "example.com")
            .header("origin", "https://example.com")
            .header(
                "cookie",
                format!("{}={}", default_csrf_cookie_name(), cookie_token),
            )
            .header("X-CSRF-Token", header_token)
            .body(Body::empty())
            .unwrap()
    }

    fn make_request_with_cookie(method: &str, path: &str, cookie: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap()
    }

    /// 判断字符串是否仅包含 URL-safe base64 字符（无填充）。
    fn is_url_safe_base64_no_pad(s: &str) -> bool {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    // generate_csrf_token + validate_csrf_token 单元测试

    #[test]
    fn token_length_is_43_chars() {
        let token = generate_csrf_token().unwrap();
        assert_eq!(
            token.len(),
            43,
            "32 字节 base64 URL-safe no-pad 应为 43 字符"
        );
    }

    #[test]
    fn token_format_is_url_safe_base64() {
        let token = generate_csrf_token().unwrap();
        assert!(
            is_url_safe_base64_no_pad(&token),
            "token 应仅包含 URL-safe base64 字符（A-Za-z0-9-_），无填充"
        );
    }

    #[test]
    fn two_tokens_are_different() {
        let t1 = generate_csrf_token().unwrap();
        let t2 = generate_csrf_token().unwrap();
        assert_ne!(t1, t2, "两次生成的 token 不应相同");
    }

    #[test]
    fn validate_same_tokens_returns_true() {
        let token = generate_csrf_token().unwrap();
        assert!(validate_csrf_token(&token, &token));
    }

    #[test]
    fn validate_different_tokens_returns_false() {
        let t1 = generate_csrf_token().unwrap();
        let t2 = generate_csrf_token().unwrap();
        assert!(!validate_csrf_token(&t1, &t2));
    }

    #[test]
    fn validate_different_lengths_returns_false() {
        assert!(!validate_csrf_token("abc", "abcdef"));
    }

    #[test]
    fn validate_empty_tokens_returns_false() {
        assert!(!validate_csrf_token("", ""));
    }

    #[test]
    fn validate_one_empty_token_returns_false() {
        assert!(!validate_csrf_token("abc", ""));
        assert!(!validate_csrf_token("", "abc"));
    }

    // CsrfConfig 单元测试

    #[test]
    fn csrf_config_default_values() {
        let config = CsrfConfig::default();
        assert!(config.enabled, "VULN-0006: 默认应启用 CSRF 防护");
        assert_eq!(config.cookie_name, "garrison_csrf_token");
        assert_eq!(config.header_name, "X-CSRF-Token");
        assert!(config.excluded_paths.is_empty());
        assert_eq!(
            config.protected_methods,
            vec!["POST", "PUT", "PATCH", "DELETE"]
        );
        assert!(config.cookie_secure, "cookie_secure 默认应为 true");
        assert!(
            config.cookie_domain.is_none(),
            "C3: 默认 cookie_domain 应为 None"
        );
    }

    #[test]
    fn csrf_config_custom_values() {
        let config = CsrfConfig {
            enabled: true,
            cookie_name: "my_csrf".to_string(),
            header_name: "X-MY-CSRF".to_string(),
            excluded_paths: vec!["/webhook".to_string()],
            protected_methods: vec!["POST".to_string()],
            cookie_secure: false,
            cookie_domain: Some("example.com".to_string()),
        };
        assert!(config.enabled);
        assert_eq!(config.cookie_name, "my_csrf");
        assert_eq!(config.header_name, "X-MY-CSRF");
        assert_eq!(config.excluded_paths, vec!["/webhook"]);
        assert_eq!(config.protected_methods, vec!["POST"]);
        assert!(!config.cookie_secure);
        assert_eq!(
            config.cookie_domain.as_deref(),
            Some("example.com"),
            "C3: 自定义 cookie_domain 应正确设置"
        );
    }

    #[test]
    fn csrf_config_enabled_field() {
        let mut config = CsrfConfig::default();
        assert!(config.enabled, "VULN-0006: 默认应启用");
        config.enabled = false;
        assert!(!config.enabled);
    }

    #[test]
    fn csrf_config_cookie_name_customization() {
        let config = CsrfConfig {
            cookie_name: "custom_csrf_token".to_string(),
            ..Default::default()
        };
        assert_eq!(config.cookie_name, "custom_csrf_token");
    }

    #[test]
    fn csrf_config_protected_methods_customization() {
        let config = CsrfConfig {
            protected_methods: vec!["POST".to_string(), "PUT".to_string()],
            ..Default::default()
        };
        assert_eq!(config.protected_methods, vec!["POST", "PUT"]);
    }

    // CsrfConfig 默认启用测试

    /// CsrfConfig::default() 应默认启用 CSRF 防护（secure-by-default）。
    #[test]
    fn csrf_config_default_enabled_is_true() {
        let config = CsrfConfig::default();
        assert!(
            config.enabled,
            "VULN-0006: CsrfConfig::default().enabled 必须为 true（secure-by-default）"
        );
    }

    // garrison_csrf_middleware 集成测试

    #[tokio::test]
    async fn get_without_cookie_sets_csrf_cookie() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let set_cookie = resp.headers().get("set-cookie").expect("应设置 Set-Cookie");
        let cookie_str = set_cookie.to_str().unwrap();
        assert!(
            cookie_str.starts_with(&format!("{}=", default_csrf_cookie_name())),
            "Set-Cookie 应以解析后的 cookie_name 开头（写读同名），实际: {}",
            cookie_str
        );
        assert!(cookie_str.contains("HttpOnly"));
        assert!(cookie_str.contains("SameSite=Lax"));
        assert!(cookie_str.contains("Path=/"));
        assert!(
            cookie_str.contains("Secure"),
            "默认 cookie_secure=true 应包含 Secure 标志"
        );
    }

    #[tokio::test]
    async fn get_with_existing_cookie_does_not_set_new_cookie() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_cookie(
                "GET",
                "/api/test",
                &format!("{}=existing_token_value", default_csrf_cookie_name()),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("set-cookie").is_none(),
            "已有 CSRF cookie 时不应设置新 cookie"
        );
    }

    #[tokio::test]
    async fn post_without_token_returns_403() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request("POST", "/api/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_with_mismatched_tokens_returns_403() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_csrf(
                "POST",
                "/api/test",
                "cookie_token_value",
                "different_header_token",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_with_matching_tokens_passes_through() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let token = generate_csrf_token().unwrap();
        let resp = app
            .oneshot(make_request_with_csrf("POST", "/api/test", &token, &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_always_passes_through() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn head_passes_through() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request("HEAD", "/api/test"))
            .await
            .unwrap();
        // HEAD 请求由 axum 自动处理（get handler 兼容 HEAD），返回 200
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn options_passes_through() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request("OPTIONS", "/api/test"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn excluded_paths_skip_validation() {
        let config = CsrfConfig {
            enabled: true,
            excluded_paths: vec!["/api/test".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        // POST 无 token，但路径在 excluded_paths 中，应放行
        let resp = app
            .oneshot(make_request("POST", "/api/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn put_with_matching_tokens_passes() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let token = generate_csrf_token().unwrap();
        let resp = app
            .oneshot(make_request_with_csrf("PUT", "/api/test", &token, &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn delete_with_matching_tokens_passes() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let token = generate_csrf_token().unwrap();
        let resp = app
            .oneshot(make_request_with_csrf(
                "DELETE",
                "/api/test",
                &token,
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn disabled_config_passes_all() {
        let config = CsrfConfig {
            enabled: false,
            ..Default::default()
        };
        let app = make_app(config);
        // POST 无 token，但 enabled=false，应放行
        let resp = app
            .clone()
            .oneshot(make_request("POST", "/api/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // GET 也应放行
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Origin/Referer 同源校验测试

    /// 受保护方法的跨源请求（Origin 不匹配 Host）应被拒绝。
    #[tokio::test]
    async fn csrf_middleware_rejects_cross_origin_request() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let token = generate_csrf_token().unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/api/test")
            .header("host", "example.com")
            .header("origin", "https://evil.com")
            .header(
                "cookie",
                format!("{}={}", default_csrf_cookie_name(), token),
            )
            .header("X-CSRF-Token", &token)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "VULN-0006: 跨源请求应被 CSRF 中间件拒绝"
        );
    }

    /// 受保护方法的同源请求（Origin 匹配 Host）应通过。
    #[tokio::test]
    async fn csrf_middleware_allows_same_origin_request() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let token = generate_csrf_token().unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/api/test")
            .header("host", "example.com")
            .header("origin", "https://example.com")
            .header(
                "cookie",
                format!("{}={}", default_csrf_cookie_name(), token),
            )
            .header("X-CSRF-Token", &token)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "VULN-0006: 同源请求应通过 CSRF 中间件"
        );
    }

    // 默认端口归一化

    /// extract_origin_host 归一化默认端口：https:443 / http:80 → 不带端口。
    #[test]
    fn extract_origin_host_normalizes_default_ports() {
        assert_eq!(
            extract_origin_host("https://example.com:443/page").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            extract_origin_host("http://example.com:80/path").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            extract_origin_host("http://localhost:3000").as_deref(),
            Some("localhost:3000")
        );
        assert_eq!(
            extract_origin_host("https://example.com:8443").as_deref(),
            Some("example.com:8443")
        );
        assert_eq!(
            extract_origin_host("https://example.com/x").as_deref(),
            Some("example.com")
        );
    }

    /// normalize_host 去除默认端口，保留非默认端口，正确处理 IPv6。
    #[test]
    fn normalize_host_strips_default_ports() {
        assert_eq!(normalize_host("example.com"), "example.com");
        assert_eq!(normalize_host("example.com:443"), "example.com");
        assert_eq!(normalize_host("example.com:80"), "example.com");
        assert_eq!(normalize_host("example.com:8080"), "example.com:8080");
        assert_eq!(normalize_host("[::1]:443"), "[::1]");
        assert_eq!(normalize_host("[::1]:8080"), "[::1]:8080");
        assert_eq!(normalize_host("[::1]"), "[::1]");
    }

    /// 显式默认端口的同源请求（Origin https://example.com:443 vs Host example.com）不应被误拒。
    #[tokio::test]
    async fn csrf_middleware_allows_origin_with_default_port() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let token = generate_csrf_token().unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/api/test")
            .header("host", "example.com")
            .header("origin", "https://example.com:443")
            .header(
                "cookie",
                format!("{}={}", default_csrf_cookie_name(), token),
            )
            .header("X-CSRF-Token", &token)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Origin 显式默认端口 :443 应与 Host example.com 视为同源"
        );
    }

    /// Host 带显式默认端口（代理场景）与无端口 Origin 应视为同源。
    #[tokio::test]
    async fn csrf_middleware_allows_host_with_default_port() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let token = generate_csrf_token().unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/api/test")
            .header("host", "example.com:443")
            .header("origin", "https://example.com")
            .header(
                "cookie",
                format!("{}={}", default_csrf_cookie_name(), token),
            )
            .header("X-CSRF-Token", &token)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Host 显式默认端口 :443 应与 Origin https://example.com 视为同源"
        );
    }

    // cookie_domain 字段测试

    /// build_set_cookie 不传 cookie_domain 时不应包含 Domain 属性。
    #[test]
    fn build_set_cookie_without_domain() {
        let cookie = build_set_cookie("garrison_csrf_token", "abc123", true, None).unwrap();
        assert!(
            !cookie.contains("Domain="),
            "C3: cookie_domain=None 时不应包含 Domain 属性，实际: {}",
            cookie
        );
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/"));
    }

    /// build_set_cookie 传 Some(domain) 时应包含 `; Domain=<domain>`。
    #[test]
    fn build_set_cookie_with_domain() {
        let cookie =
            build_set_cookie("garrison_csrf_token", "abc123", true, Some("example.com")).unwrap();
        assert!(
            cookie.contains("; Domain=example.com"),
            "C3: cookie_domain=Some(\"example.com\") 时应包含 `; Domain=example.com`，实际: {}",
            cookie
        );
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/"));
    }

    /// build_set_cookie 传 Some("") 时应忽略空 Domain（不输出 Domain 属性）。
    #[test]
    fn build_set_cookie_with_empty_domain_ignored() {
        let cookie = build_set_cookie("garrison_csrf_token", "abc123", true, Some("")).unwrap();
        assert!(
            !cookie.contains("Domain="),
            "C3: 空字符串 Domain 应被忽略，实际: {}",
            cookie
        );
    }

    /// build_set_cookie 不启用 Secure 且无 Domain 时格式正确。
    #[test]
    fn build_set_cookie_no_secure_no_domain() {
        let cookie = build_set_cookie("csrf", "tok", false, None).unwrap();
        assert!(!cookie.contains("Secure"));
        assert!(!cookie.contains("Domain="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/"));
    }

    /// build_set_cookie 同时启用 Secure 与 Domain 时格式正确。
    #[test]
    fn build_set_cookie_secure_and_domain() {
        let cookie = build_set_cookie("csrf", "tok", true, Some("api.example.com")).unwrap();
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("; Domain=api.example.com"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/"));
    }

    /// 默认配置（cookie_domain=None）的 GET 请求 Set-Cookie 不应含 Domain。
    #[tokio::test]
    async fn middleware_default_no_domain_in_set_cookie() {
        let config = CsrfConfig::default();
        let app = make_app(config);
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let set_cookie = resp.headers().get("set-cookie").expect("应设置 Set-Cookie");
        let cookie_str = set_cookie.to_str().unwrap();
        assert!(
            !cookie_str.contains("Domain="),
            "C3: 默认配置不应含 Domain 属性，实际: {}",
            cookie_str
        );
    }

    /// 配置 cookie_domain=Some("example.com") 时 GET 请求 Set-Cookie 应含 Domain。
    #[tokio::test]
    async fn middleware_with_domain_in_set_cookie() {
        let config = CsrfConfig {
            cookie_domain: Some("example.com".to_string()),
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let set_cookie = resp.headers().get("set-cookie").expect("应设置 Set-Cookie");
        let cookie_str = set_cookie.to_str().unwrap();
        assert!(
            cookie_str.contains("; Domain=example.com"),
            "C3: 配置 cookie_domain 后 Set-Cookie 应含 `; Domain=example.com`，实际: {}",
            cookie_str
        );
    }

    /// 配置 cookie_domain=Some("api.example.com") 验证子域场景。
    #[tokio::test]
    async fn middleware_with_subdomain_in_set_cookie() {
        let config = CsrfConfig {
            cookie_domain: Some("api.example.com".to_string()),
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .clone()
            .oneshot(make_request("GET", "/api/test"))
            .await
            .unwrap();
        let set_cookie = resp.headers().get("set-cookie").expect("应设置 Set-Cookie");
        let cookie_str = set_cookie.to_str().unwrap();
        assert!(
            cookie_str.contains("; Domain=api.example.com"),
            "C3: 子域场景应正确设置 Domain，实际: {}",
            cookie_str
        );
        // 已有 cookie 时不重新设置（fixture 名与该配置的写侧解析名一致）
        let read_config = CsrfConfig {
            cookie_domain: Some("api.example.com".to_string()),
            ..Default::default()
        };
        let existing_name = csrf_cookie_type(
            &read_config.cookie_name,
            read_config.cookie_domain.as_deref(),
        )
        .resolved_name(read_config.cookie_secure);
        let resp2 = app
            .oneshot(make_request_with_cookie(
                "GET",
                "/api/test",
                &format!("{}=existing", existing_name),
            ))
            .await
            .unwrap();
        assert!(
            resp2.headers().get("set-cookie").is_none(),
            "C3: 已有 cookie 时不应重新设置"
        );
    }

    // 单一构建点：写读同名 roundtrip

    /// 写读同名：build_set_cookie 产出的名字与读侧解析名一致（覆盖 Secure×Domain 组合，production 下含 `__Host-`/`__Secure-` 前缀）。
    #[test]
    fn csrf_cookie_write_read_name_roundtrip() {
        for (secure, domain) in [(true, None), (true, Some("example.com")), (false, None)] {
            let cookie = build_set_cookie("garrison_csrf_token", "tok", secure, domain).unwrap();
            let read_name = csrf_cookie_type("garrison_csrf_token", domain).resolved_name(secure);
            assert!(
                cookie.starts_with(&format!("{}=", read_name)),
                "secure={} domain={:?} 写读名字应一致，实际: {}",
                secure,
                domain,
                cookie
            );
        }
    }

    // production 前缀断言由 src/context/cookie.rs 的 production 测试模块在 production 门禁真实执行；
    // csrf 写读 roundtrip 由上方 csrf_cookie_write_read_name_roundtrip 在 full 门禁覆盖
    // （production 不含 web-csrf，full 不含 production，两门禁下重复断言均不可达）。
}
