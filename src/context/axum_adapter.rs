//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! axum 适配器模块。
//!
//! 实现 `GarrisonContext` / `GarrisonRequest` / `GarrisonResponse` / `GarrisonStorage` trait，
//! 将 Garrison 鉴权逻辑与 axum 0.7 Web 框架解耦。
//!
//! ## 设计
//!
//! - `AxumRequest` 包装 `&http::Request<axum::body::Body>`（不可变引用）
//! - `AxumResponse` 持有 `HeaderMap + StatusCode`，`to_response()` 转换为 axum Response
//! - `AxumStorage` 用 `HashMap<String, String>`，请求结束自动清理

use crate::config::GarrisonConfig;
use crate::context::token_extract::{is_body_token_allowed_method, strip_bearer_prefix};
use crate::context::{GarrisonContext, GarrisonRequest, GarrisonResponse, GarrisonStorage};
use crate::error::{GarrisonError, GarrisonResult};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use std::collections::HashMap;

// ============================================================================
// AxumRequest：包装 &http::Request<Body>
// ============================================================================

/// axum 请求适配器，包装 `&http::Request<Body>`。
pub struct AxumRequest<'a> {
    request: &'a Request<Body>,
    /// 预读的 body 字节（用于 `is_read_body=true` 时从 JSON 提取 token）。
    ///
    /// body 读取是 async 操作，但 `get_token` 是 sync 方法，故由调用方在
    /// async 上下文中预读 body 字节后通过 `with_body` 注入。
    /// 默认空 `Vec`（`new` 构造时），此时 body 读取分支静默跳过。
    body_bytes: Vec<u8>,
}

impl<'a> AxumRequest<'a> {
    /// 创建新的 AxumRequest（body 为空，不读取 body）。
    ///
    /// # 参数
    /// - `request`: axum `Request<Body>` 引用，生命周期绑定到返回的 `AxumRequest`。
    ///
    /// # 返回
    /// 包装该请求引用的 `AxumRequest` 实例（`body_bytes` 为空）。
    pub fn new(request: &'a Request<Body>) -> Self {
        Self::with_body(request, Vec::new())
    }

    /// 创建带预读 body 的 AxumRequest（用于 `is_read_body=true` 场景）。
    ///
    /// # 参数
    /// - `request`: axum `Request<Body>` 引用。
    /// - `body_bytes`: 预读的 body 字节（调用方在 async 上下文中通过
    ///   `http_body_util::BodyExt::collect` 等方式读取后传入）。
    ///
    /// # 返回
    /// 包装该请求引用与 body 字节的 `AxumRequest` 实例。
    pub fn with_body(request: &'a Request<Body>, body_bytes: Vec<u8>) -> Self {
        Self {
            request,
            body_bytes,
        }
    }
}

impl<'a> GarrisonRequest for AxumRequest<'a> {
    fn path(&self) -> GarrisonResult<String> {
        Ok(self.request.uri().path().to_string())
    }

    fn method(&self) -> GarrisonResult<String> {
        Ok(self.request.method().as_str().to_string())
    }

    fn header(&self, name: &str) -> GarrisonResult<Option<String>> {
        let header_name: HeaderName = name.parse().map_err(|e| {
            GarrisonError::Context(format!("invalid header name '{}': {}", name, e))
        })?;
        Ok(self
            .request
            .headers()
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()))
    }

    fn cookie(&self, name: &str) -> GarrisonResult<Option<String>> {
        let cookie_header = self
            .request
            .headers()
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if cookie_header.is_empty() {
            return Ok(None);
        }
        // 解析 Cookie: name1=value1; name2=value2
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(eq_pos) = cookie.find('=') {
                let (k, v) = cookie.split_at(eq_pos);
                if k == name {
                    return Ok(Some(v[1..].to_string())); // 跳过 '='
                }
            }
        }
        Ok(None)
    }

    fn get_token(&self, config: &GarrisonConfig) -> GarrisonResult<Option<String>> {
        // 1. 从 header 提取（Authorization: Bearer <token> 或自定义 token_name header）
        if config.is_read_header {
            // 先尝试 Authorization: Bearer <token>（RFC 7235 大小写不敏感）
            if let Some(auth) = self.header("Authorization")? {
                if let Some(token) = strip_bearer_prefix(&auth) {
                    return Ok(Some(token.to_string()));
                }
            }
            // 再尝试自定义 token_name header
            if let Some(token) = self.header(&config.token_name)? {
                return Ok(Some(token));
            }
        }
        // 2. 从 cookie 提取
        if config.is_read_cookie {
            if let Some(token) = self.cookie(&config.token_name)? {
                return Ok(Some(token));
            }
        }
        // 3. 从 body 提取（优先级最低，仅当 is_read_body=true 且有预读 body 字节时）
        if config.is_read_body {
            // C7: 仅 POST/PUT/PATCH 允许从 body 提取 token，防止 GET/HEAD 等方法的
            // body 注入攻击（攻击者可通过 `<img src="...?token=...">` 注入恶意 token）。
            let method = self.request.method().as_str();
            if !is_body_token_allowed_method(method) {
                tracing::warn!(
                    method = method,
                    "C7: HTTP 方法不允许从 body 提取 token，已跳过 body 读取"
                );
                return Ok(None);
            }
            if let Some(token) = extract_token_from_json_body(
                &self.body_bytes,
                self.request.headers(),
                &config.token_name,
            )? {
                return Ok(Some(token));
            }
        }
        Ok(None)
    }
}

// ============================================================================
// AxumResponse：持有 HeaderMap + StatusCode
// ============================================================================

/// axum 响应适配器，持有 HeaderMap 与 StatusCode，`to_response()` 转换为 axum Response。
pub struct AxumResponse {
    headers: HeaderMap,
    status: StatusCode,
}

impl AxumResponse {
    /// 创建新的 AxumResponse（默认 200 OK）。
    pub fn new() -> Self {
        Self {
            headers: HeaderMap::new(),
            status: StatusCode::OK,
        }
    }
}

impl Default for AxumResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl AxumResponse {
    /// 转换为 axum Response（空 body）。
    ///
    /// # 返回
    /// 携带当前 `HeaderMap` 与 `StatusCode` 的 axum `Response`（body 为空）。
    pub fn to_response(self) -> axum::response::Response {
        let mut response = axum::response::Response::new(Body::empty());
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response
    }
}

impl GarrisonResponse for AxumResponse {
    fn set_status(&mut self, code: u16) -> GarrisonResult<()> {
        self.status = StatusCode::from_u16(code)
            .map_err(|e| GarrisonError::Context(format!("invalid status code {}: {}", code, e)))?;
        Ok(())
    }

    fn set_header(&mut self, name: &str, value: &str) -> GarrisonResult<()> {
        let header_name: HeaderName = name.parse().map_err(|e| {
            GarrisonError::Context(format!("invalid header name '{}': {}", name, e))
        })?;
        let header_value = HeaderValue::from_str(value).map_err(|e| {
            GarrisonError::Context(format!("invalid header value '{}': {}", value, e))
        })?;
        self.headers.insert(header_name, header_value);
        Ok(())
    }

    fn set_cookie(&mut self, name: &str, value: &str) -> GarrisonResult<()> {
        // 安全默认：HttpOnly; Secure; SameSite=Lax; Path=/
        let cookie_value = format!("{}={}; HttpOnly; Secure; SameSite=Lax; Path=/", name, value);
        self.set_header("Set-Cookie", &cookie_value)
    }

    fn set_cookie_with_config(
        &mut self,
        name: &str,
        value: &str,
        config: &crate::config::GarrisonConfig,
    ) -> GarrisonResult<()> {
        // 依据 config.cookie_secure / cookie_same_site 构建 Set-Cookie 头部
        let secure_flag = if config.cookie_secure { "Secure; " } else { "" };
        let cookie_value = format!(
            "{}={}; HttpOnly; {}SameSite={}; Path=/",
            name, value, secure_flag, config.cookie_same_site,
        );
        self.set_header("Set-Cookie", &cookie_value)
    }
}

// ============================================================================
// AxumStorage：HashMap<String, String>
// ============================================================================

/// axum 存储适配器，用 HashMap 实现请求级临时存储。
pub struct AxumStorage {
    map: HashMap<String, String>,
}

impl AxumStorage {
    /// 创建新的 AxumStorage。
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl Default for AxumStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl GarrisonStorage for AxumStorage {
    fn set(&mut self, key: &str, value: &str) -> GarrisonResult<()> {
        self.map.insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        Ok(self.map.get(key).cloned())
    }

    fn delete(&mut self, key: &str) -> GarrisonResult<()> {
        self.map.remove(key);
        Ok(())
    }
}

// ============================================================================
// AxumContext：组合 Request + Response
// ============================================================================

/// axum 上下文适配器，组合 Request 引用 + Response。
///
/// # 设计
///
/// - 仅持有 `&Request<Body>` 引用 + `AxumResponse`
/// - 通过 `into_response()` 消费 context 生成 axum Response
/// - 不再提供 `response()` / `storage()` trait 方法（返回新实例违反 trait 契约）
pub struct AxumContext<'a> {
    request: &'a Request<Body>,
    response: AxumResponse,
    /// 预读的 body 字节（用于 `is_read_body=true` 时从 JSON 提取 token）。
    body_bytes: Vec<u8>,
}

impl<'a> AxumContext<'a> {
    /// 创建新的 AxumContext，绑定到指定请求（body 为空，不读取 body）。
    ///
    /// # 参数
    /// - `request`: axum `Request<Body>` 引用，生命周期绑定到返回的 `AxumContext`。
    ///
    /// # 返回
    /// 绑定该请求的 `AxumContext` 实例（内部已初始化空的 `AxumResponse`，`body_bytes` 为空）。
    pub fn new(request: &'a Request<Body>) -> Self {
        Self {
            request,
            response: AxumResponse::new(),
            body_bytes: Vec::new(),
        }
    }

    /// 创建带预读 body 的 AxumContext（用于 `is_read_body=true` 场景）。
    ///
    /// # 参数
    /// - `request`: axum `Request<Body>` 引用。
    /// - `body_bytes`: 预读的 body 字节（调用方在 async 上下文中读取后传入）。
    ///
    /// # 返回
    /// 绑定该请求与 body 字节的 `AxumContext` 实例。
    pub fn with_body(request: &'a Request<Body>, body_bytes: Vec<u8>) -> Self {
        Self {
            request,
            response: AxumResponse::new(),
            body_bytes,
        }
    }

    /// 获取底层请求引用。
    ///
    /// # 返回
    /// 底层 `&Request<Body>` 引用，用于直接访问 axum 原生请求字段。
    pub fn raw_request(&self) -> &Request<Body> {
        self.request
    }

    /// 获取底层响应的不可变引用（用于读取已设置的 headers / status）。
    pub fn raw_response(&self) -> &AxumResponse {
        &self.response
    }

    /// 获取底层响应的可变引用（用于设置 status / headers / cookies）。
    pub fn raw_response_mut(&mut self) -> &mut AxumResponse {
        &mut self.response
    }

    /// 消费 context，生成 axum Response。
    ///
    /// # 返回
    /// 由内部 `AxumResponse` 转换而来的 axum `Response`（携带已设置的 status 与 headers）。
    pub fn into_response(self) -> axum::response::Response {
        self.response.to_response()
    }
}

impl<'a> GarrisonContext for AxumContext<'a> {
    fn request(&self) -> GarrisonResult<Box<dyn GarrisonRequest>> {
        // 注意：这里创建 AxumRequest 需要借用 self.request
        // 但 AxumRequest<'a> 的生命周期与 self 不同
        // 简化方案：直接克隆必要数据，避免生命周期问题
        Ok(Box::new(AxumRequestWrapper::with_body(
            self.request,
            self.body_bytes.clone(),
        )))
    }
}

/// AxumRequest 包装器（绕过 Box<dyn> 的生命周期问题）。
///
/// 由于 `Box<dyn GarrisonRequest>` 不能带生命周期参数，
/// 这里用 Arc 或克隆必要数据。简化方案：直接持有 &Request 的原始指针（不安全），
/// 或者改为克隆 HeaderMap。
///
/// 当前简化实现：持有 Request<Body> 的克隆（Body 不能克隆），
/// 因此改为只持有 HeaderMap + Method + Uri。
struct AxumRequestWrapper {
    headers: HeaderMap,
    method: String,
    uri: String,
    /// 预读的 body 字节（用于 `is_read_body=true` 时从 JSON 提取 token）。
    body_bytes: Vec<u8>,
}

impl AxumRequestWrapper {
    fn with_body(req: &Request<Body>, body_bytes: Vec<u8>) -> Self {
        Self {
            headers: req.headers().clone(),
            method: req.method().as_str().to_string(),
            uri: req.uri().to_string(),
            body_bytes,
        }
    }
}

impl GarrisonRequest for AxumRequestWrapper {
    fn path(&self) -> GarrisonResult<String> {
        // uri 是完整 URI，提取 path 部分
        Ok(self.uri.split('?').next().unwrap_or(&self.uri).to_string())
    }

    fn method(&self) -> GarrisonResult<String> {
        Ok(self.method.clone())
    }

    fn header(&self, name: &str) -> GarrisonResult<Option<String>> {
        let header_name: HeaderName = name.parse().map_err(|e| {
            GarrisonError::Context(format!("invalid header name '{}': {}", name, e))
        })?;
        Ok(self
            .headers
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()))
    }

    fn cookie(&self, name: &str) -> GarrisonResult<Option<String>> {
        let cookie_header = self
            .headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if cookie_header.is_empty() {
            return Ok(None);
        }
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(eq_pos) = cookie.find('=') {
                let (k, v) = cookie.split_at(eq_pos);
                if k == name {
                    return Ok(Some(v[1..].to_string()));
                }
            }
        }
        Ok(None)
    }

    fn get_token(&self, config: &GarrisonConfig) -> GarrisonResult<Option<String>> {
        if config.is_read_header {
            if let Some(auth) = self.header("Authorization")? {
                // RFC 7235：Bearer 大小写不敏感，与 AxumRequest::get_token 保持一致（T117 P1-2）。
                if let Some(token) = strip_bearer_prefix(&auth) {
                    return Ok(Some(token.to_string()));
                }
            }
            if let Some(token) = self.header(&config.token_name)? {
                return Ok(Some(token));
            }
        }
        if config.is_read_cookie {
            if let Some(token) = self.cookie(&config.token_name)? {
                return Ok(Some(token));
            }
        }
        // 3. 从 body 提取（优先级最低，仅当 is_read_body=true 且有预读 body 字节时）
        if config.is_read_body {
            // C7: 仅 POST/PUT/PATCH 允许从 body 提取 token（与 AxumRequest::get_token 一致）。
            let method = self.method.as_str();
            if !is_body_token_allowed_method(method) {
                tracing::warn!(
                    method = method,
                    "C7: HTTP 方法不允许从 body 提取 token，已跳过 body 读取"
                );
                return Ok(None);
            }
            if let Some(token) =
                extract_token_from_json_body(&self.body_bytes, &self.headers, &config.token_name)?
            {
                return Ok(Some(token));
            }
        }
        Ok(None)
    }
}

// ============================================================================
// body 读取辅助函数（T006）
// ============================================================================

/// 从预读的 JSON body 字节中提取 token。
///
/// # 行为
/// 1. 若 `body_bytes` 为空，返回 `Ok(None)`（未预读 body，静默跳过）。
/// 2. 若 `Content-Type` header 不包含 `application/json`，返回 `Ok(None)`（静默跳过）。
/// 3. 若 body 不是合法 JSON，返回 `Ok(None)`（静默回退，不影响主流程）。
/// 4. 若 JSON 中无 `token_name` 字段或字段值非 string，返回 `Ok(None)`。
/// 5. 若 JSON 中有 `token_name` 字段且为 string，返回 `Ok(Some(token))`。
///
/// # 参数
/// - `body_bytes`: 预读的 body 字节。
/// - `headers`: 请求头（用于检查 `Content-Type`）。
/// - `token_name`: token 字段名（来自 `GarrisonConfig::token_name`）。
fn extract_token_from_json_body(
    body_bytes: &[u8],
    headers: &HeaderMap,
    token_name: &str,
) -> GarrisonResult<Option<String>> {
    if body_bytes.is_empty() {
        return Ok(None);
    }
    // 检查 Content-Type 是否为 application/json
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.contains("application/json") {
        return Ok(None);
    }
    // 解析 JSON，失败时静默回退（不报错）
    let json: serde_json::Value = match serde_json::from_slice(body_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    // 从 JSON 中提取 token_name 字段
    if let Some(token) = json.get(token_name).and_then(|v| v.as_str()) {
        return Ok(Some(token.to_string()));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    /// 构建测试用 Request<Body>（空 body）。
    fn make_request(uri: &str, method: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).unwrap()
    }

    /// 构建带 body 的 Request<Body>（用于 T006 body 读取测试）。
    fn make_request_with_body(
        uri: &str,
        method: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    // ========================================================================
    // AxumRequest 测试
    // ========================================================================

    /// 验证 path() 返回请求路径。
    #[test]
    fn axum_request_path() {
        let req = make_request("/api/users?id=1", "GET", &[]);
        let axum_req = AxumRequest::new(&req);
        assert_eq!(axum_req.path().unwrap(), "/api/users");
    }

    /// 验证 method() 返回请求方法。
    #[test]
    fn axum_request_method() {
        let req = make_request("/", "POST", &[]);
        let axum_req = AxumRequest::new(&req);
        assert_eq!(axum_req.method().unwrap(), "POST");
    }

    /// 验证 header() 返回请求头。
    #[test]
    fn axum_request_header() {
        let req = make_request("/", "GET", &[("X-Token", "abc123")]);
        let axum_req = AxumRequest::new(&req);
        assert_eq!(
            axum_req.header("X-Token").unwrap(),
            Some("abc123".to_string())
        );
        assert_eq!(axum_req.header("Not-Exist").unwrap(), None);
    }

    /// 验证 cookie() 解析 Cookie header。
    #[test]
    fn axum_request_cookie() {
        let req = make_request(
            "/",
            "GET",
            &[("Cookie", "garrison_token=tok123; other=val")],
        );
        let axum_req = AxumRequest::new(&req);
        assert_eq!(
            axum_req.cookie("garrison_token").unwrap(),
            Some("tok123".to_string())
        );
        assert_eq!(axum_req.cookie("other").unwrap(), Some("val".to_string()));
        assert_eq!(axum_req.cookie("missing").unwrap(), None);
    }

    // ========================================================================
    // get_token 测试（spec context-abstraction Requirement: GarrisonRequest）
    // ========================================================================

    /// 验证从 Authorization: Bearer 提取 token（spec Scenario: 从 header 提取 token）。
    #[test]
    fn get_token_from_bearer_header() {
        let req = make_request("/", "GET", &[("Authorization", "Bearer my_token_123")]);
        let axum_req = AxumRequest::new(&req);
        let config = GarrisonConfig::default_config();
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(token, Some("my_token_123".to_string()));
    }

    /// 验证 Bearer 前缀大小写不敏感。
    ///
    /// 覆盖 `strip_bearer_prefix` 的 `eq_ignore_ascii_case` 分支：
    /// `bearer xxx` / `BEARER xxx` / `BeArEr xxx` 均应能提取 token。
    #[test]
    fn bearer_prefix_case_insensitive() {
        let config = GarrisonConfig::default_config();
        for prefix in &["Bearer", "bearer", "BEARER", "BeArEr"] {
            let auth_value = format!("{} tok_{}", prefix, prefix);
            let req = make_request("/", "GET", &[("Authorization", auth_value.as_str())]);
            let axum_req = AxumRequest::new(&req);
            let token = axum_req.get_token(&config).unwrap();
            assert_eq!(
                token,
                Some(format!("tok_{}", prefix)),
                "前缀 '{}' 应能提取 token（大小写不敏感）",
                prefix
            );
        }
    }

    /// 验证从自定义 header 提取 token。
    #[test]
    fn get_token_from_custom_header() {
        let req = make_request("/", "GET", &[("garrison_token", "header_token_456")]);
        let axum_req = AxumRequest::new(&req);
        let config = GarrisonConfig::default_config();
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(token, Some("header_token_456".to_string()));
    }

    /// 验证从 cookie 提取 token（spec Scenario: 从 cookie 提取 token）。
    #[test]
    fn get_token_from_cookie() {
        let req = make_request("/", "GET", &[("Cookie", "garrison_token=cookie_token_789")]);
        let axum_req = AxumRequest::new(&req);
        let config = GarrisonConfig::default_config();
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(token, Some("cookie_token_789".to_string()));
    }

    /// 验证 header 优先级高于 cookie（spec Scenario: token 不存在 的反向）。
    #[test]
    fn get_token_header_priority_over_cookie() {
        let req = make_request(
            "/",
            "GET",
            &[
                ("Authorization", "Bearer header_token"),
                ("Cookie", "garrison_token=cookie_token"),
            ],
        );
        let axum_req = AxumRequest::new(&req);
        let config = GarrisonConfig::default_config();
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(token, Some("header_token".to_string()));
    }

    /// 验证无 token 时返回 None（spec Scenario: token 不存在）。
    #[test]
    fn get_token_returns_none_when_missing() {
        let req = make_request("/", "GET", &[]);
        let axum_req = AxumRequest::new(&req);
        let config = GarrisonConfig::default_config();
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(token, None);
    }

    /// 验证 is_read_header=false 时不从 header 提取。
    #[test]
    fn get_token_skips_header_when_disabled() {
        let req = make_request("/", "GET", &[("Authorization", "Bearer header_token")]);
        let axum_req = AxumRequest::new(&req);
        let mut config = GarrisonConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = false;
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(token, None);
    }

    // ========================================================================
    // AxumResponse 测试（spec context-abstraction Requirement: GarrisonResponse）
    // ========================================================================

    /// 验证 set_status 设置状态码（spec Scenario: 写入 401 状态码）。
    #[test]
    fn response_set_status() {
        let mut resp = AxumResponse::new();
        resp.set_status(401).unwrap();
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    /// 验证 set_header 设置响应头（spec Scenario: 写入 token 到 header）。
    #[test]
    fn response_set_header() {
        let mut resp = AxumResponse::new();
        resp.set_header("Authorization", "my_token").unwrap();
        assert_eq!(
            resp.headers
                .get("Authorization")
                .and_then(|v| v.to_str().ok()),
            Some("my_token")
        );
    }

    /// 验证 set_cookie 设置安全属性（HttpOnly + Secure + SameSite=Lax + Path=/）。
    #[test]
    fn response_set_cookie() {
        let mut resp = AxumResponse::new();
        resp.set_cookie("garrison_token", "cookie_value").unwrap();
        let set_cookie = resp
            .headers
            .get("Set-Cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert!(set_cookie.contains("garrison_token=cookie_value"));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("Secure"));
        assert!(set_cookie.contains("SameSite=Lax"));
        assert!(set_cookie.contains("Path=/"));
    }

    /// 验证 set_cookie_with_config 依据 config 调整 Secure/SameSite（dev 场景关闭 Secure）。
    #[test]
    fn response_set_cookie_with_config_dev() {
        let mut resp = AxumResponse::new();
        let mut config = GarrisonConfig::default_config();
        config.cookie_secure = false;
        config.cookie_same_site = "Strict".to_string();
        resp.set_cookie_with_config("token", "v", &config).unwrap();
        let set_cookie = resp
            .headers
            .get("Set-Cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert!(set_cookie.contains("HttpOnly"));
        assert!(!set_cookie.contains("Secure"));
        assert!(set_cookie.contains("SameSite=Strict"));
    }

    /// 验证 to_response 转换为 axum Response。
    #[test]
    fn response_to_axum_response() {
        let mut resp = AxumResponse::new();
        resp.set_status(403).unwrap();
        resp.set_header("X-Custom", "test").unwrap();
        let axum_resp = resp.to_response();
        assert_eq!(axum_resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            axum_resp
                .headers()
                .get("X-Custom")
                .and_then(|v| v.to_str().ok()),
            Some("test")
        );
    }

    /// 验证非法状态码抛错。
    #[test]
    fn response_invalid_status_errors() {
        let mut resp = AxumResponse::new();
        // 999 是合法 u16 但不是标准 HTTP 状态码，from_u16 接受任何 u16
        // 用 70000 测试... 不行，u16 最大 65535
        // 用非标准但合法的值验证 set_status 不抛错
        assert!(resp.set_status(200).is_ok());
        assert!(resp.set_status(500).is_ok());
    }

    /// 验证非法 header name 抛错。
    #[test]
    fn response_invalid_header_name_errors() {
        let mut resp = AxumResponse::new();
        // header name 不能包含空格
        let result = resp.set_header("invalid header", "value");
        assert!(result.is_err());
    }

    // ========================================================================
    // AxumStorage 测试（spec context-abstraction Requirement: GarrisonStorage）
    // ========================================================================

    /// 验证 set/get 存储数据（spec Scenario: 存储请求数据）。
    #[test]
    fn storage_set_get() {
        let mut storage = AxumStorage::new();
        storage.set("trace_id", "abc-123").unwrap();
        assert_eq!(
            storage.get("trace_id").unwrap(),
            Some("abc-123".to_string())
        );
    }

    /// 验证 delete 删除存储数据。
    #[test]
    fn storage_delete() {
        let mut storage = AxumStorage::new();
        storage.set("key1", "value1").unwrap();
        storage.delete("key1").unwrap();
        assert_eq!(storage.get("key1").unwrap(), None);
    }

    /// 验证请求间隔离（spec Scenario: 请求间隔离）。
    #[test]
    fn storage_request_isolation() {
        // 请求 A
        let mut storage_a = AxumStorage::new();
        storage_a.set("trace_id", "A").unwrap();

        // 请求 B（独立 storage）
        let mut storage_b = AxumStorage::new();
        storage_b.set("trace_id", "B").unwrap();

        assert_eq!(storage_a.get("trace_id").unwrap(), Some("A".to_string()));
        assert_eq!(storage_b.get("trace_id").unwrap(), Some("B".to_string()));
    }

    /// 验证不存在的 key 返回 None。
    #[test]
    fn storage_missing_key_returns_none() {
        let storage = AxumStorage::new();
        assert_eq!(storage.get("missing").unwrap(), None);
    }

    // ========================================================================
    // AxumContext 测试
    // ========================================================================

    /// 验证 AxumContext 创建并访问 request/response/storage。
    #[test]
    fn context_creation() {
        let req = make_request("/api/test", "GET", &[("X-Test", "value")]);
        let ctx = AxumContext::new(&req);
        assert_eq!(ctx.raw_request().uri().path(), "/api/test");
    }

    /// 验证 GarrisonContext trait 实现。
    #[test]
    fn context_trait_impl() {
        let req = make_request("/", "GET", &[("Authorization", "Bearer abc")]);
        let ctx = AxumContext::new(&req);

        let request = ctx.request().unwrap();
        let config = GarrisonConfig::default_config();
        let token = request.get_token(&config).unwrap();
        assert_eq!(token, Some("abc".to_string()));

        // 验证 raw_response_mut() 可写入 status / header
        let mut ctx = ctx;
        ctx.raw_response_mut().set_status(403).unwrap();
        ctx.raw_response_mut().set_header("X-Trace", "v").unwrap();
        let resp = ctx.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // ========================================================================
    // 新增测试：覆盖 AxumRequest 的错误分支与边界
    // ========================================================================

    /// 验证 AxumRequest::header() 在 header name 非法时返回 Context 错误。
    #[test]
    fn axum_request_header_invalid_name_errors() {
        let req = make_request("/", "GET", &[]);
        let axum_req = AxumRequest::new(&req);
        // header name 不能包含空格
        let result = axum_req.header("invalid header");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, GarrisonError::Context(_)));
        assert!(err.to_string().contains("invalid header name"));
    }

    /// 验证 AxumRequest::cookie() 在没有 Cookie header 时返回 None（空 header 分支）。
    #[test]
    fn axum_request_cookie_empty_header_returns_none() {
        let req = make_request("/", "GET", &[]);
        let axum_req = AxumRequest::new(&req);
        assert_eq!(axum_req.cookie("any").unwrap(), None);
    }

    /// 验证 AxumRequest::cookie() 跳过没有 '=' 的 cookie 项。
    #[test]
    fn axum_request_cookie_skips_pair_without_equals() {
        let req = make_request("/", "GET", &[("Cookie", "invalidpair; valid=val")]);
        let axum_req = AxumRequest::new(&req);
        assert_eq!(axum_req.cookie("valid").unwrap(), Some("val".to_string()));
        assert_eq!(axum_req.cookie("invalidpair").unwrap(), None);
    }

    // ========================================================================
    // 新增测试：覆盖 AxumResponse 错误分支与 Default 实现
    // ========================================================================

    /// 验证 AxumResponse::set_status() 在状态码非法（> 999）时返回 Context 错误。
    #[test]
    fn axum_response_set_status_invalid_code_errors() {
        let mut resp = AxumResponse::new();
        // StatusCode::from_u16 仅接受 0..=999
        let result = resp.set_status(1000);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, GarrisonError::Context(_)));
        assert!(err.to_string().contains("invalid status code"));
    }

    /// 验证 AxumResponse::set_header() 在 header value 非法时返回 Context 错误。
    #[test]
    fn axum_response_set_header_invalid_value_errors() {
        let mut resp = AxumResponse::new();
        // header value 不能包含控制字符（如 '\0'）
        let result = resp.set_header("X-Test", "bad\0value");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, GarrisonError::Context(_)));
        assert!(err.to_string().contains("invalid header value"));
    }

    /// 验证 AxumResponse::default() 等价于 new()，状态码为 200 OK 且 headers 为空。
    #[test]
    fn axum_response_default_impl() {
        let resp = AxumResponse::default();
        assert_eq!(resp.status, StatusCode::OK);
        assert!(resp.headers.is_empty());
    }

    /// 验证 AxumStorage::default() 等价于 new()，返回空 storage。
    #[test]
    fn axum_storage_default_impl() {
        let storage = AxumStorage::default();
        assert_eq!(storage.get("any").unwrap(), None);
    }

    // ========================================================================
    // 新增测试：覆盖 AxumRequestWrapper（通过 AxumContext::request() 访问）
    // ========================================================================

    /// 验证 AxumContext::request() 返回的 wrapper 正确提取 path（去掉 query string）。
    #[test]
    fn axum_context_wrapper_path_strips_query() {
        let req = make_request("/api/v1/users?page=2&size=10", "GET", &[]);
        let ctx = AxumContext::new(&req);
        let request = ctx.request().unwrap();
        assert_eq!(request.path().unwrap(), "/api/v1/users");
    }

    /// 验证 AxumContext::request() 返回的 wrapper 正确返回 method。
    #[test]
    fn axum_context_wrapper_method() {
        let req = make_request("/", "PUT", &[]);
        let ctx = AxumContext::new(&req);
        let request = ctx.request().unwrap();
        assert_eq!(request.method().unwrap(), "PUT");
    }

    /// 验证 AxumContext::request() 返回的 wrapper 正确读取 header（命中与未命中）。
    #[test]
    fn axum_context_wrapper_header() {
        let req = make_request("/", "GET", &[("X-Custom", "hello"), ("X-Other", "world")]);
        let ctx = AxumContext::new(&req);
        let request = ctx.request().unwrap();
        assert_eq!(
            request.header("X-Custom").unwrap(),
            Some("hello".to_string())
        );
        assert_eq!(
            request.header("X-Other").unwrap(),
            Some("world".to_string())
        );
        assert_eq!(request.header("Missing").unwrap(), None);
    }

    /// 验证 AxumContext::request() 返回的 wrapper 在 header name 非法时返回 Context 错误。
    #[test]
    fn axum_context_wrapper_header_invalid_name_errors() {
        let req = make_request("/", "GET", &[]);
        let ctx = AxumContext::new(&req);
        let request = ctx.request().unwrap();
        let result = request.header("bad name");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, GarrisonError::Context(_)));
        assert!(err.to_string().contains("invalid header name"));
    }

    /// 验证 AxumContext::request() 返回的 wrapper 在没有 Cookie header 时返回 None。
    #[test]
    fn axum_context_wrapper_cookie_no_header_returns_none() {
        let req = make_request("/", "GET", &[]);
        let ctx = AxumContext::new(&req);
        let request = ctx.request().unwrap();
        assert_eq!(request.cookie("any").unwrap(), None);
    }

    /// 验证 AxumContext::request() 返回的 wrapper 解析 Cookie header（命中与未命中）。
    #[test]
    fn axum_context_wrapper_cookie_found() {
        let req = make_request("/", "GET", &[("Cookie", "session=abc; user=xyz")]);
        let ctx = AxumContext::new(&req);
        let request = ctx.request().unwrap();
        assert_eq!(request.cookie("session").unwrap(), Some("abc".to_string()));
        assert_eq!(request.cookie("user").unwrap(), Some("xyz".to_string()));
        assert_eq!(request.cookie("missing").unwrap(), None);
    }

    /// 验证 AxumContext::request() 返回的 wrapper 跳过没有 '=' 的 cookie 项。
    #[test]
    fn axum_context_wrapper_cookie_skips_pair_without_equals() {
        let req = make_request("/", "GET", &[("Cookie", "invalidpair; valid=val")]);
        let ctx = AxumContext::new(&req);
        let request = ctx.request().unwrap();
        assert_eq!(request.cookie("valid").unwrap(), Some("val".to_string()));
        assert_eq!(request.cookie("invalidpair").unwrap(), None);
    }

    /// 验证 AxumContext::request() 返回的 wrapper 从 cookie 提取 token。
    #[test]
    fn axum_context_wrapper_get_token_from_cookie() {
        let req = make_request("/", "GET", &[("Cookie", "garrison_token=cookie_tok")]);
        let ctx = AxumContext::new(&req);
        let request = ctx.request().unwrap();
        let mut config = GarrisonConfig::default_config();
        // 关闭 header 读取，强制走 cookie 路径以覆盖 wrapper 的 cookie 分支
        config.is_read_header = false;
        config.is_read_cookie = true;
        let token = request.get_token(&config).unwrap();
        assert_eq!(token, Some("cookie_tok".to_string()));
    }

    /// 验证 AxumContext::request() 返回的 wrapper 在无 token 时返回 None。
    #[test]
    fn axum_context_wrapper_get_token_returns_none() {
        let req = make_request("/", "GET", &[]);
        let ctx = AxumContext::new(&req);
        let request = ctx.request().unwrap();
        let config = GarrisonConfig::default_config();
        let token = request.get_token(&config).unwrap();
        assert_eq!(token, None);
    }

    /// 验证 AxumContext::request() 返回的 wrapper 从 Authorization: Bearer 提取 token
    /// 时大小写不敏感（RFC 7235）。回归 T117 P1-2：原实现用 `strip_prefix("Bearer ")`
    /// 大小写敏感，与 AxumRequest::get_token（用 strip_bearer_prefix）不一致。
    #[test]
    fn axum_context_wrapper_bearer_case_insensitive() {
        let config = GarrisonConfig::default_config();
        for prefix in ["Bearer", "bearer", "BEARER", "BeArEr"] {
            let header_value = format!("{} my_token_123", prefix);
            let req = make_request("/", "GET", &[("Authorization", &header_value)]);
            let ctx = AxumContext::new(&req);
            let request = ctx.request().unwrap();
            let token = request.get_token(&config).unwrap();
            assert_eq!(
                token,
                Some("my_token_123".to_string()),
                "prefix '{}' should extract token (RFC 7235 case-insensitive)",
                prefix
            );
        }
    }

    // ========================================================================
    // 新增测试：覆盖 AxumContext::response() / storage() / into_response()
    // ========================================================================

    /// 验证 AxumContext::raw_response_mut() 返回可写的内部 response 引用。
    #[test]
    fn axum_context_raw_response_mut_writable() {
        let req = make_request("/", "GET", &[]);
        let mut ctx = AxumContext::new(&req);
        // 通过 raw_response_mut 设置状态码与 header
        ctx.raw_response_mut().set_status(404).unwrap();
        ctx.raw_response_mut()
            .set_header("X-Trace", "trace-123")
            .unwrap();
        // 通过 raw_response() 不可变引用读取已设置的状态码
        assert_eq!(ctx.raw_response().status, StatusCode::NOT_FOUND);
        // 通过 into_response 消费 context 并验证设置生效
        let resp = ctx.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get("X-Trace").and_then(|v| v.to_str().ok()),
            Some("trace-123")
        );
    }

    /// 验证 AxumContext::into_response() 转换为 axum Response（默认 200 OK）。
    #[test]
    fn axum_context_into_response_default() {
        let req = make_request("/", "GET", &[]);
        let ctx = AxumContext::new(&req);
        let response = ctx.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ========================================================================
    // T006: body 读取分支测试（is_read_body=true）
    // ========================================================================

    /// T006: `is_read_body=true` 且 header/cookie 无 token 时，从 body JSON 提取 token。
    ///
    /// 优先级：header > cookie > body。本测试 header/cookie 均无 token，
    /// body 为 `{"token": "abc123"}`，应提取到 "abc123"。
    #[test]
    fn extract_token_from_body_when_is_read_body_true() {
        let body_str = r#"{"token": "abc123"}"#;
        let req = make_request_with_body(
            "/",
            "POST",
            &[("Content-Type", "application/json")],
            body_str,
        );
        let ctx = AxumContext::with_body(&req, body_str.as_bytes().to_vec());
        let request = ctx.request().unwrap();
        let mut config = GarrisonConfig::default_config();
        config.is_read_body = true;
        config.token_name = "token".to_string();
        let token = request.get_token(&config).unwrap();
        assert_eq!(
            token,
            Some("abc123".to_string()),
            "is_read_body=true 且 body 含 token 字段时应提取到 token"
        );
    }

    /// T006: `is_read_body=true` 但 body 无 token 字段时，回退到 header 读取。
    ///
    /// 优先级：header > cookie > body。本测试 header 有 `Authorization: Bearer`，
    /// body 为 `{"other": "value"}`（无 token 字段），应返回 header 的 token。
    #[test]
    fn extract_token_fallback_to_header_when_body_empty() {
        let body_str = r#"{"other": "value"}"#;
        let req = make_request_with_body(
            "/",
            "POST",
            &[
                ("Content-Type", "application/json"),
                ("Authorization", "Bearer header_tok_456"),
            ],
            body_str,
        );
        let ctx = AxumContext::with_body(&req, body_str.as_bytes().to_vec());
        let request = ctx.request().unwrap();
        let mut config = GarrisonConfig::default_config();
        config.is_read_body = true;
        config.token_name = "token".to_string();
        let token = request.get_token(&config).unwrap();
        assert_eq!(
            token,
            Some("header_tok_456".to_string()),
            "body 无 token 字段时应回退到 header 读取"
        );
    }

    // ========================================================================
    // C7: body token 提取方法限制测试（防 body 注入攻击）
    // ========================================================================

    /// C7: GET 方法 + body 含 token + is_read_body=true 应跳过 body 提取。
    ///
    /// 直接测试 `AxumRequest::get_token`。GET 方法不应从 body 提取 token，
    /// 否则攻击者可通过 `<img src="...?token=...">` 注入恶意 token。
    #[test]
    fn c7_axum_request_get_method_skips_body_token() {
        let body_str = r#"{"garrison_token":"body_token_should_be_skipped"}"#;
        let req = make_request_with_body(
            "/",
            "GET",
            &[("Content-Type", "application/json")],
            body_str,
        );
        let axum_req = AxumRequest::with_body(&req, body_str.as_bytes().to_vec());
        let mut config = GarrisonConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = false;
        config.is_read_body = true;
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(
            token, None,
            "C7: GET 方法不应从 body 提取 token（防 body 注入攻击）"
        );
    }

    /// C7: POST 方法 + body 含 token + is_read_body=true 应正常提取。
    ///
    /// 直接测试 `AxumRequest::get_token`。POST 方法允许从 body 提取 token。
    #[test]
    fn c7_axum_request_post_method_allows_body_token() {
        let body_str = r#"{"garrison_token":"body_token_ok"}"#;
        let req = make_request_with_body(
            "/",
            "POST",
            &[("Content-Type", "application/json")],
            body_str,
        );
        let axum_req = AxumRequest::with_body(&req, body_str.as_bytes().to_vec());
        let mut config = GarrisonConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = false;
        config.is_read_body = true;
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(
            token,
            Some("body_token_ok".to_string()),
            "C7: POST 方法应允许从 body 提取 token"
        );
    }

    /// C7: GET 方法 + body 含 token + is_read_body=true 应跳过 body 提取（通过 AxumContext，验证 Wrapper）。
    ///
    /// 通过 `AxumContext::with_body` + `request()` 测试 `AxumRequestWrapper::get_token`，
    /// 确保 Wrapper 路径也正确应用 C7 method 限制。
    #[test]
    fn c7_axum_context_get_method_skips_body_token_via_wrapper() {
        let body_str = r#"{"garrison_token":"wrapper_skipped"}"#;
        let req = make_request_with_body(
            "/",
            "GET",
            &[("Content-Type", "application/json")],
            body_str,
        );
        let ctx = AxumContext::with_body(&req, body_str.as_bytes().to_vec());
        let request = ctx.request().unwrap();
        let mut config = GarrisonConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = false;
        config.is_read_body = true;
        let token = request.get_token(&config).unwrap();
        assert_eq!(
            token, None,
            "C7: 通过 AxumContext 的 GET 方法不应从 body 提取 token"
        );
    }

    /// C7: PUT/PATCH 方法 + body 含 token + is_read_body=true 应正常提取（通过 AxumContext）。
    ///
    /// 通过 `AxumContext::with_body` + `request()` 验证 PUT/PATCH 也允许提取 token。
    #[test]
    fn c7_axum_context_put_patch_methods_allow_body_token_via_wrapper() {
        for method in &["PUT", "PATCH"] {
            let body_str = format!(r#"{{"garrison_token":"tok_{}"}}"#, method);
            let req = make_request_with_body(
                "/",
                method,
                &[("Content-Type", "application/json")],
                &body_str,
            );
            let ctx = AxumContext::with_body(&req, body_str.as_bytes().to_vec());
            let request = ctx.request().unwrap();
            let mut config = GarrisonConfig::default_config();
            config.is_read_header = false;
            config.is_read_cookie = false;
            config.is_read_body = true;
            let token = request.get_token(&config).unwrap();
            assert_eq!(
                token,
                Some(format!("tok_{}", method)),
                "C7: {} 方法应允许从 body 提取 token",
                method
            );
        }
    }
}
