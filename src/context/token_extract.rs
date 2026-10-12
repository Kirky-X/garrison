//! Token 提取公共模块。
//!
//! `strip_bearer_prefix` / `parse_cookie_value` / `extract_token_from_headers` 供 web 框架适配器
//! （`web_actix` / `web_warp`）与 context 适配器共用，消除跨文件重复实现。
//!
//! `http` crate 是必需依赖，故本模块无需 feature gate；`warp::http::HeaderMap` / `axum::http::HeaderMap`
//! 是其 re-export 可直接传入，`actix_web::http::header::HeaderMap` 是独立类型，通过 [`HeaderLookup`] trait 适配。

use crate::config::GarrisonConfig;
use crate::error::{GarrisonError, GarrisonResult};
use http::HeaderMap;

// HeaderLookup trait：抽象 HeaderMap 类型差异

/// Header 查找抽象 trait，用于 `extract_token_from_headers` 泛型约束。
///
/// `http::HeaderMap`（v1.x）与 `actix_http::header::HeaderMap` 是不同类型（actix-web 4.x 依赖
/// `http` v0.2），用纯字符串接口（`&str` → `Option<&str>`）彻底规避版本冲突，使该函数可同时接受两者。
/// `http::HeaderMap` 的实现在本模块提供，actix 侧在 `web_actix/mod.rs` 提供（需 `web-actix` feature）。
pub trait HeaderLookup {
    /// 按 header name（小写字符串）查找值，返回 header 值的字符串切片。
    fn get_header(&self, name: &str) -> Option<&str>;
}

impl HeaderLookup for HeaderMap {
    fn get_header(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|v| v.to_str().ok())
    }
}

// 公共函数

/// 大小写不敏感地剥离 `Bearer ` 前缀（RFC 7235），支持 `Bearer` / `bearer` / `BEARER` 等任意大小写。
///
/// 前缀不匹配、字符串过短或前缀后为空（如 `"Bearer "`）返回 `None`：返回 `Some("")` 会让下游
/// 拿到空 token，构成认证旁路风险。保证返回的 token 非空。
pub fn strip_bearer_prefix(auth_str: &str) -> Option<&str> {
    let prefix = "bearer ";
    // 用 get(..n) 而非 auth_str[..n]：n 落在多字节 UTF-8 字符中间时返回 None 而非 panic，
    // 避免恶意非 ASCII header 触发 DoS。
    let head = auth_str.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        let rest = &auth_str[prefix.len()..];
        if rest.is_empty() {
            return None;
        }
        Some(rest)
    } else {
        None
    }
}

/// 从 Cookie header 值中按名称提取单个 cookie 值，返回首个匹配 `name` 的值；未找到或 header 为空返回 `None`。
///
/// 用 `get(1..)` 而非 `&v[1..]` 防止空值 panic（如 `"name="`）。
pub fn parse_cookie_value(cookie_header: &str, name: &str) -> Option<String> {
    if cookie_header.is_empty() {
        return None;
    }
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(eq_pos) = cookie.find('=') {
            let (k, v) = cookie.split_at(eq_pos);
            if k == name {
                return v.get(1..).map(|s| s.to_string());
            }
        }
    }
    None
}

/// C7: 检查 HTTP 方法是否允许从 body 提取 token（仅 `POST` / `PUT` / `PATCH`，大小写不敏感）。
///
/// 其他方法不应从 body 提取：RFC 7231 规定 GET/HEAD/DELETE 语义上不应有 body，部分代理 / CDN / WAF
/// 会丢弃或拒绝转发；且允许 GET 携带 token 可被构造恶意链接（如
/// `<img src="https://victim.com/api?token=attacker_token">`）在用户不知情时替换正常 token（CSRF 变种）。
pub fn is_body_token_allowed_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("POST")
        || method.eq_ignore_ascii_case("PUT")
        || method.eq_ignore_ascii_case("PATCH")
}

/// 从 `HeaderMap` 提取 token，返回首个命中的 token，均无则 `Ok(None)`。
///
/// 提取顺序：`Authorization: Bearer <token>` → 自定义 `token_name` header（二者仅当 `is_read_header`）
/// → `Cookie: token_name=<token>`（仅当 `is_read_cookie`）。
///
/// 泛型 `H: HeaderLookup` 使本函数可同时接受 `http::HeaderMap`（warp / axum）与
/// `actix_http::header::HeaderMap`（actix-web），两种类型经 [`HeaderLookup`] 统一抽象。
pub fn extract_token_from_headers<H: HeaderLookup>(
    headers: &H,
    config: &GarrisonConfig,
) -> Result<Option<String>, GarrisonError> {
    if config.is_read_header {
        if let Some(auth) = headers.get_header("authorization") {
            if let Some(token) = strip_bearer_prefix(auth) {
                return Ok(Some(token.to_string()));
            }
        }
        if let Some(token) = headers.get_header(&config.token_name) {
            return Ok(Some(token.to_string()));
        }
    }
    if config.is_read_cookie {
        // production + Secure 上下文下 cookie 解析名带 __Host- 前缀，与写侧同名
        if let Some(token) = parse_cookie_value(
            headers.get_header("cookie").unwrap_or(""),
            &crate::context::token_cookie_name(config),
        ) {
            return Ok(Some(token));
        }
    }
    Ok(None)
}

/// 从请求三部分统一提取 token（header → cookie → body 三级优先级），供 actix / warp / axum 适配器共用。
///
/// 通过闭包参数适配不同框架的 header / cookie 访问方式；`is_read_header` / `is_read_cookie` /
/// `is_read_body` 分别控制三级，body 级另有 C7 方法限制（POST/PUT/PATCH）→ Content-Type: application/json
/// → JSON 提取。
pub fn extract_token_from_request_parts(
    config: &GarrisonConfig,
    body_bytes: &[u8],
    method: &str,
    mut header_fn: impl FnMut(&str) -> GarrisonResult<Option<String>>,
    mut cookie_fn: impl FnMut(&str) -> GarrisonResult<Option<String>>,
) -> GarrisonResult<Option<String>> {
    if config.is_read_header {
        if let Some(auth) = header_fn("Authorization")? {
            if let Some(token) = strip_bearer_prefix(&auth) {
                return Ok(Some(token.to_string()));
            }
        }
        if let Some(token) = header_fn(&config.token_name)? {
            return Ok(Some(token));
        }
    }
    // production + Secure 上下文下 cookie 解析名带 __Host- 前缀，与写侧同名
    if config.is_read_cookie {
        if let Some(token) = cookie_fn(&crate::context::token_cookie_name(config))? {
            return Ok(Some(token));
        }
    }
    if config.is_read_body && !body_bytes.is_empty() {
        return extract_token_from_body(config, body_bytes, method, header_fn);
    }
    Ok(None)
}

/// Body 级 token 提取子流程（C7 方法限制 → 大小护栏 → JSON 字段提取）。
///
/// 仅在 `is_read_body` 且 body 非空时由 [`extract_token_from_request_parts`] 调用；不可提取条件
/// （方法受限 / 超 1MB 解析护栏 / 非 JSON / 无目标字段）一律 `Ok(None)` fail-closed 跳过，
/// 仅 Content-Type 读取失败透传错误。
fn extract_token_from_body(
    config: &GarrisonConfig,
    body_bytes: &[u8],
    method: &str,
    mut header_fn: impl FnMut(&str) -> GarrisonResult<Option<String>>,
) -> GarrisonResult<Option<String>> {
    if !is_body_token_allowed_method(method) {
        tracing::warn!(
            method = method,
            "C7: HTTP method does not allow extracting token from body, skipping body read"
        );
        return Ok(None);
    }
    // DoS 防护：超大 body（数十 MB JSON）会在 token 校验前引发过量堆分配，超限直接跳过 body 提取。
    // 上限固定 1MB（与常见网关 body 限制对齐）。
    const MAX_BODY_TOKEN_PARSE_BYTES: usize = 1024 * 1024;
    if body_bytes.len() > MAX_BODY_TOKEN_PARSE_BYTES {
        tracing::warn!(
            size = body_bytes.len(),
            limit = MAX_BODY_TOKEN_PARSE_BYTES,
            "request body exceeds token-extraction parse limit, skipping body token read"
        );
        return Ok(None);
    }
    let content_type = header_fn("Content-Type")?.unwrap_or_default();
    // RFC 9110：media type 不区分大小写，Application/JSON 等不应静默跳过 body 提取
    if content_type
        .to_ascii_lowercase()
        .contains("application/json")
    {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
            if let Some(token) = value.get(&config.token_name).and_then(|v| v.as_str()) {
                return Ok(Some(token.to_string()));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header;
    use http::HeaderValue;

    // strip_bearer_prefix 测试
    /// `Bearer ` 前缀标准大小写。
    #[test]
    fn strip_bearer_prefix_standard() {
        assert_eq!(strip_bearer_prefix("Bearer my_token"), Some("my_token"));
    }

    /// `bearer ` 前缀小写。
    #[test]
    fn strip_bearer_prefix_lowercase() {
        assert_eq!(strip_bearer_prefix("bearer my_token"), Some("my_token"));
    }

    /// `BEARER ` 前缀大写。
    #[test]
    fn strip_bearer_prefix_uppercase() {
        assert_eq!(strip_bearer_prefix("BEARER my_token"), Some("my_token"));
    }

    /// `BeArEr ` 混合大小写。
    #[test]
    fn strip_bearer_prefix_mixed_case() {
        assert_eq!(strip_bearer_prefix("BeArEr my_token"), Some("my_token"));
    }

    /// 无 Bearer 前缀返回 None。
    #[test]
    fn strip_bearer_prefix_no_prefix() {
        assert_eq!(strip_bearer_prefix("my_token"), None);
        assert_eq!(strip_bearer_prefix("Basic abc123"), None);
    }

    /// 空字符串返回 None。
    #[test]
    fn strip_bearer_prefix_empty() {
        assert_eq!(strip_bearer_prefix(""), None);
    }

    /// 字符串短于 `"bearer "` 返回 None。
    #[test]
    fn strip_bearer_prefix_shorter_than_prefix() {
        assert_eq!(strip_bearer_prefix("Bear"), None);
        assert_eq!(strip_bearer_prefix("bearer"), None);
    }

    /// 多字节 UTF-8 header 值不应 panic（回归测试）。
    ///
    /// 4 个 `é`（8 字节）使 `prefix.len()=7` 落在最后一个 `é` 中间（字节 7 非字符起始边界）：
    /// 修复前 `auth_str[..prefix.len()]` panic（byte index 7 is not a char boundary），攻击者可用
    /// 非 ASCII Authorization header 远程 DoS；`get(..prefix.len())` 返回 None 后函数返回 None。
    #[test]
    fn strip_bearer_prefix_multibyte_no_panic() {
        let auth_str = "éééé"; // 0xC3 0xA9 × 4 = 8 字节
        assert_eq!(strip_bearer_prefix(auth_str), None);
    }

    /// 仅前缀无 token 返回 None（空 token 不得下发给下游）。
    #[test]
    fn strip_bearer_prefix_only_prefix() {
        // 空 token 构成认证旁路风险（下游拿到空 token）
        assert_eq!(strip_bearer_prefix("Bearer "), None);
    }

    // parse_cookie_value 测试

    /// 从单 cookie 提取值。
    #[test]
    fn parse_cookie_value_single() {
        assert_eq!(
            parse_cookie_value("token=abc123", "token"),
            Some("abc123".to_string())
        );
    }

    /// 从多 cookie 提取目标值。
    #[test]
    fn parse_cookie_value_multiple() {
        assert_eq!(
            parse_cookie_value("session=xyz; token=target_tok; other=val", "token"),
            Some("target_tok".to_string())
        );
    }

    /// 未找到返回 None。
    #[test]
    fn parse_cookie_value_not_found() {
        assert_eq!(parse_cookie_value("session=abc", "token"), None);
    }

    /// 空 header 返回 None。
    #[test]
    fn parse_cookie_value_empty_header() {
        assert_eq!(parse_cookie_value("", "token"), None);
    }

    /// 空值 cookie（如 "name="）返回空字符串而非 panic。
    #[test]
    fn parse_cookie_value_empty_value_no_panic() {
        assert_eq!(parse_cookie_value("name=", "name"), Some("".to_string()));
    }

    // extract_token_from_headers 测试
    /// 从 Authorization: Bearer 提取 token。
    #[test]
    fn extract_token_from_bearer_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my_token_123"),
        );
        let config = GarrisonConfig::default_config();
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("my_token_123".to_string()));
    }

    /// Bearer 前缀大小写不敏感（RFC 7235）。
    #[test]
    fn extract_token_bearer_case_insensitive() {
        let config = GarrisonConfig::default_config();
        for prefix in &["Bearer", "bearer", "BEARER", "BeArEr"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("{} tok_{}", prefix, prefix)).unwrap(),
            );
            let token = extract_token_from_headers(&headers, &config).unwrap();
            assert_eq!(
                token,
                Some(format!("tok_{}", prefix)),
                "前缀 '{}' 应能提取 token",
                prefix
            );
        }
    }

    /// 从自定义 token_name header 提取 token（非 Authorization）。
    #[test]
    fn extract_token_from_custom_token_name_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "garrison_token",
            HeaderValue::from_static("custom_header_tok"),
        );
        let config = GarrisonConfig::default_config();
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("custom_header_tok".to_string()));
    }

    /// 从 cookie 提取 token。
    #[test]
    fn extract_token_from_cookie() {
        let config = GarrisonConfig::default_config();
        let cookie_value = format!(
            "{}=cookie_tok_456",
            crate::context::token_cookie_name(&config)
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&cookie_value).unwrap(),
        );
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("cookie_tok_456".to_string()));
    }

    /// 无 token 时返回 None。
    #[test]
    fn extract_token_returns_none_when_missing() {
        let headers = HeaderMap::new();
        let config = GarrisonConfig::default_config();
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, None);
    }

    /// Authorization Bearer 优先级高于 cookie。
    #[test]
    fn extract_token_bearer_priority_over_cookie() {
        let config = GarrisonConfig::default_config();
        let cookie_value = format!("{}=cookie_tok", crate::context::token_cookie_name(&config));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header_tok"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&cookie_value).unwrap(),
        );
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("header_tok".to_string()));
    }

    /// 自定义 token_name header 优先级高于 cookie。
    #[test]
    fn extract_token_custom_header_priority_over_cookie() {
        let config = GarrisonConfig::default_config();
        let cookie_value = format!("{}=cookie_tok", crate::context::token_cookie_name(&config));
        let mut headers = HeaderMap::new();
        headers.insert(
            "garrison_token",
            HeaderValue::from_static("custom_header_tok"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&cookie_value).unwrap(),
        );
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("custom_header_tok".to_string()));
    }

    /// is_read_header=false 时不从 header 提取，但仍可从 cookie 提取。
    #[test]
    fn extract_token_skips_header_when_disabled() {
        let config = GarrisonConfig::default_config();
        let cookie_value = format!("{}=cookie_tok", crate::context::token_cookie_name(&config));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header_tok"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&cookie_value).unwrap(),
        );
        let mut config = config;
        config.is_read_header = false;
        // header 关闭，应走 cookie 路径
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("cookie_tok".to_string()));
    }

    /// is_read_cookie=false 时不从 cookie 提取，但仍可从 header 提取。
    #[test]
    fn extract_token_skips_cookie_when_disabled() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header_tok"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("garrison_token=cookie_tok"),
        );
        let mut config = GarrisonConfig::default_config();
        config.is_read_cookie = false;
        // cookie 关闭，应走 header 路径
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("header_tok".to_string()));
    }

    /// is_read_header=false + is_read_cookie=false 时返回 None。
    #[test]
    fn extract_token_returns_none_when_both_disabled() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header_tok"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("garrison_token=cookie_tok"),
        );
        let mut config = GarrisonConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = false;
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, None);
    }

    /// Cookie 中有多项时正确提取目标 token_name。
    #[test]
    fn extract_token_from_cookie_with_multiple_pairs() {
        let config = GarrisonConfig::default_config();
        let cookie_value = format!(
            "session=abc; {}=target_tok; other=val",
            crate::context::token_cookie_name(&config)
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&cookie_value).unwrap(),
        );
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("target_tok".to_string()));
    }

    /// Authorization header 存在但无 Bearer 前缀时，回退到自定义 header / cookie。
    #[test]
    fn extract_token_falls_back_when_no_bearer_prefix() {
        let config = GarrisonConfig::default_config();
        let cookie_value = format!("{}=cookie_tok", crate::context::token_cookie_name(&config));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic abc123"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&cookie_value).unwrap(),
        );
        // Authorization 无 Bearer 前缀，应回退到 cookie
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("cookie_tok".to_string()));
    }

    // is_body_token_allowed_method 测试（C7）
    /// C7: POST 方法应允许从 body 提取 token。
    #[test]
    fn c7_is_body_token_allowed_method_post() {
        assert!(is_body_token_allowed_method("POST"));
    }

    /// C7: PUT / PATCH 方法应允许从 body 提取 token。
    #[test]
    fn c7_is_body_token_allowed_method_put_patch() {
        assert!(is_body_token_allowed_method("PUT"));
        assert!(is_body_token_allowed_method("PATCH"));
    }

    /// C7: GET / HEAD / DELETE / OPTIONS / CONNECT / TRACE 应拒绝从 body 提取 token。
    ///
    /// 这些方法语义上不应携带 body（RFC 7231），允许从 body 提取会引入 CSRF 变种攻击。
    #[test]
    fn c7_is_body_token_allowed_method_rejects_others() {
        assert!(!is_body_token_allowed_method("GET"));
        assert!(!is_body_token_allowed_method("HEAD"));
        assert!(!is_body_token_allowed_method("DELETE"));
        assert!(!is_body_token_allowed_method("OPTIONS"));
        assert!(!is_body_token_allowed_method("CONNECT"));
        assert!(!is_body_token_allowed_method("TRACE"));
    }

    /// C7: 方法判断应大小写不敏感；空字符串与未知方法应拒绝。
    #[test]
    fn c7_is_body_token_allowed_method_case_insensitive_and_edge() {
        assert!(is_body_token_allowed_method("post"));
        assert!(is_body_token_allowed_method("Put"));
        assert!(is_body_token_allowed_method("pAtCh"));
        assert!(is_body_token_allowed_method("PoSt"));
        assert!(!is_body_token_allowed_method(""));
        assert!(!is_body_token_allowed_method("unknown"));
        assert!(!is_body_token_allowed_method("POST ")); // 带空格
        assert!(!is_body_token_allowed_method(" POST")); // 带空格
    }

    // extract_token_from_request_parts 补充测试
    /// Content-Type 大小写不敏感（RFC 9110）：`Application/JSON` 不应静默跳过 body 提取。
    #[test]
    fn extract_from_body_content_type_case_insensitive() {
        let config = GarrisonConfig::default_config();
        let mut config = config;
        config.is_read_header = false;
        config.is_read_cookie = false;
        config.is_read_body = true;
        config.token_name = "token".to_string();
        let body = br#"{"token":"case_tok"}"#;
        for ct in &[
            "application/json",
            "Application/JSON",
            "APPLICATION/JSON; charset=utf-8",
        ] {
            let token = extract_token_from_request_parts(
                &config,
                body,
                "POST",
                |name| {
                    if name == "Content-Type" {
                        Ok(Some(ct.to_string()))
                    } else {
                        Ok(None)
                    }
                },
                |_| Ok(None),
            )
            .unwrap();
            assert_eq!(
                token,
                Some("case_tok".to_string()),
                "Content-Type '{ct}' 应大小写不敏感地命中 body 提取"
            );
        }
    }

    /// 超过 1MB 上限的 body 不进入 JSON 解析，直接跳过 body 提取。
    #[test]
    fn extract_from_body_skips_oversized_body() {
        let mut config = GarrisonConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = false;
        config.is_read_body = true;
        config.token_name = "token".to_string();
        // 构造 > 1MB 的合法 JSON body
        let mut body = String::from(r#"{"pad":""#);
        body.push_str(&"a".repeat(1024 * 1024 + 1));
        body.push_str(r#"","token":"big_tok"}"#);
        let token = extract_token_from_request_parts(
            &config,
            body.as_bytes(),
            "POST",
            |name| {
                if name == "Content-Type" {
                    Ok(Some("application/json".to_string()))
                } else {
                    Ok(None)
                }
            },
            |_| Ok(None),
        )
        .unwrap();
        assert_eq!(
            token, None,
            "超过 1MB 的 body 不应解析（防 DoS），应返回 None"
        );
    }

    /// `Authorization: Bearer `（空前缀）不再返回空 token。
    #[test]
    fn extract_from_parts_empty_bearer_returns_none() {
        let config = GarrisonConfig::default_config();
        let token = extract_token_from_request_parts(
            &config,
            &[],
            "GET",
            |name| {
                if name == "Authorization" {
                    Ok(Some("Bearer ".to_string()))
                } else {
                    Ok(None)
                }
            },
            |_| Ok(None),
        )
        .unwrap();
        assert_eq!(token, None, "空前缀 Bearer 应返回 None 而非 Some(\"\")");
    }

    // production 前缀：读侧同名命中（写读同名一致性）
    /// production + Secure 上下文：读侧命中带 `__Host-` 前缀的 token cookie。
    #[cfg(feature = "production")]
    #[test]
    fn extract_token_from_headers_hits_host_prefixed_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-garrison_token=host_prefixed_tok"),
        );
        let config = GarrisonConfig::default_config();
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("host_prefixed_tok".to_string()));
    }

    /// production + Secure 上下文：`extract_token_from_request_parts` 向 cookie_fn 传入与写侧一致的 `__Host-` 前缀名。
    #[cfg(feature = "production")]
    #[test]
    fn extract_from_parts_queries_host_prefixed_cookie_name() {
        let mut config = GarrisonConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = true;
        let token = extract_token_from_request_parts(
            &config,
            &[],
            "GET",
            |_| Ok(None),
            |name| {
                assert_eq!(
                    name, "__Host-garrison_token",
                    "cookie 查询名应与 production 写侧前缀名一致"
                );
                Ok(Some("parts_tok".to_string()))
            },
        )
        .unwrap();
        assert_eq!(token, Some("parts_tok".to_string()));
    }
}
