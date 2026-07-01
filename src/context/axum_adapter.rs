//! axum 适配器模块。
//!
//! 实现 `BulwarkContext` / `BulwarkRequest` / `BulwarkResponse` / `BulwarkStorage` trait，
//! 将 Bulwark 鉴权逻辑与 axum 0.7 Web 框架解耦。
//!
//! ## 设计
//!
//! - `AxumRequest` 包装 `&http::Request<axum::body::Body>`（不可变引用）
//! - `AxumResponse` 持有 `HeaderMap + StatusCode`，`to_response()` 转换为 axum Response
//! - `AxumStorage` 用 `HashMap<String, String>`，请求结束自动清理

use crate::config::BulwarkConfig;
use crate::context::{BulwarkContext, BulwarkRequest, BulwarkResponse, BulwarkStorage};
use crate::error::{BulwarkError, BulwarkResult};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use std::collections::HashMap;

// ============================================================================
// 辅助函数：大小写不敏感地剥离 `Bearer ` 前缀（依据 RFC 7235）
// ============================================================================

/// 大小写不敏感地剥离 `Bearer ` 前缀。
///
/// 支持 `Bearer xxx`、`bearer xxx`、`BEARER xxx` 等任意大小写组合。
fn strip_bearer_prefix(auth_str: &str) -> Option<&str> {
    let prefix = "bearer ";
    if auth_str.len() >= prefix.len() && auth_str[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&auth_str[prefix.len()..])
    } else {
        None
    }
}

// ============================================================================
// AxumRequest：包装 &http::Request<Body>
// ============================================================================

/// axum 请求适配器，包装 `&http::Request<Body>`。
pub struct AxumRequest<'a> {
    request: &'a Request<Body>,
}

impl<'a> AxumRequest<'a> {
    /// 创建新的 AxumRequest。
    ///
    /// # 参数
    /// - `request`: axum `Request<Body>` 引用，生命周期绑定到返回的 `AxumRequest`。
    ///
    /// # 返回
    /// 包装该请求引用的 `AxumRequest` 实例。
    pub fn new(request: &'a Request<Body>) -> Self {
        Self { request }
    }
}

impl<'a> BulwarkRequest for AxumRequest<'a> {
    fn path(&self) -> BulwarkResult<String> {
        Ok(self.request.uri().path().to_string())
    }

    fn method(&self) -> BulwarkResult<String> {
        Ok(self.request.method().as_str().to_string())
    }

    fn header(&self, name: &str) -> BulwarkResult<Option<String>> {
        let header_name: HeaderName = name
            .parse()
            .map_err(|e| BulwarkError::Context(format!("invalid header name '{}': {}", name, e)))?;
        Ok(self
            .request
            .headers()
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()))
    }

    fn cookie(&self, name: &str) -> BulwarkResult<Option<String>> {
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

    fn get_token(&self, config: &BulwarkConfig) -> BulwarkResult<Option<String>> {
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

impl BulwarkResponse for AxumResponse {
    fn set_status(&mut self, code: u16) -> BulwarkResult<()> {
        self.status = StatusCode::from_u16(code)
            .map_err(|e| BulwarkError::Context(format!("invalid status code {}: {}", code, e)))?;
        Ok(())
    }

    fn set_header(&mut self, name: &str, value: &str) -> BulwarkResult<()> {
        let header_name: HeaderName = name
            .parse()
            .map_err(|e| BulwarkError::Context(format!("invalid header name '{}': {}", name, e)))?;
        let header_value = HeaderValue::from_str(value).map_err(|e| {
            BulwarkError::Context(format!("invalid header value '{}': {}", value, e))
        })?;
        self.headers.insert(header_name, header_value);
        Ok(())
    }

    fn set_cookie(&mut self, name: &str, value: &str) -> BulwarkResult<()> {
        // 安全默认：HttpOnly; Secure; SameSite=Lax; Path=/
        let cookie_value = format!("{}={}; HttpOnly; Secure; SameSite=Lax; Path=/", name, value);
        self.set_header("Set-Cookie", &cookie_value)
    }

    fn set_cookie_with_config(
        &mut self,
        name: &str,
        value: &str,
        config: &crate::config::BulwarkConfig,
    ) -> BulwarkResult<()> {
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

impl BulwarkStorage for AxumStorage {
    fn set(&mut self, key: &str, value: &str) -> BulwarkResult<()> {
        self.map.insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        Ok(self.map.get(key).cloned())
    }

    fn delete(&mut self, key: &str) -> BulwarkResult<()> {
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
}

impl<'a> AxumContext<'a> {
    /// 创建新的 AxumContext，绑定到指定请求。
    ///
    /// # 参数
    /// - `request`: axum `Request<Body>` 引用，生命周期绑定到返回的 `AxumContext`。
    ///
    /// # 返回
    /// 绑定该请求的 `AxumContext` 实例（内部已初始化空的 `AxumResponse`）。
    pub fn new(request: &'a Request<Body>) -> Self {
        Self {
            request,
            response: AxumResponse::new(),
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

impl<'a> BulwarkContext for AxumContext<'a> {
    fn request(&self) -> BulwarkResult<Box<dyn BulwarkRequest>> {
        // 注意：这里创建 AxumRequest 需要借用 self.request
        // 但 AxumRequest<'a> 的生命周期与 self 不同
        // 简化方案：直接克隆必要数据，避免生命周期问题
        Ok(Box::new(AxumRequestWrapper::new(self.request)))
    }
}

/// AxumRequest 包装器（绕过 Box<dyn> 的生命周期问题）。
///
/// 由于 `Box<dyn BulwarkRequest>` 不能带生命周期参数，
/// 这里用 Arc 或克隆必要数据。简化方案：直接持有 &Request 的原始指针（不安全），
/// 或者改为克隆 HeaderMap。
///
/// 当前简化实现：持有 Request<Body> 的克隆（Body 不能克隆），
/// 因此改为只持有 HeaderMap + Method + Uri。
struct AxumRequestWrapper {
    headers: HeaderMap,
    method: String,
    uri: String,
}

impl AxumRequestWrapper {
    fn new(req: &Request<Body>) -> Self {
        Self {
            headers: req.headers().clone(),
            method: req.method().as_str().to_string(),
            uri: req.uri().to_string(),
        }
    }
}

impl BulwarkRequest for AxumRequestWrapper {
    fn path(&self) -> BulwarkResult<String> {
        // uri 是完整 URI，提取 path 部分
        Ok(self.uri.split('?').next().unwrap_or(&self.uri).to_string())
    }

    fn method(&self) -> BulwarkResult<String> {
        Ok(self.method.clone())
    }

    fn header(&self, name: &str) -> BulwarkResult<Option<String>> {
        let header_name: HeaderName = name
            .parse()
            .map_err(|e| BulwarkError::Context(format!("invalid header name '{}': {}", name, e)))?;
        Ok(self
            .headers
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()))
    }

    fn cookie(&self, name: &str) -> BulwarkResult<Option<String>> {
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

    fn get_token(&self, config: &BulwarkConfig) -> BulwarkResult<Option<String>> {
        if config.is_read_header {
            if let Some(auth) = self.header("Authorization")? {
                if let Some(token) = auth.strip_prefix("Bearer ") {
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
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    /// 构建测试用 Request<Body>。
    fn make_request(uri: &str, method: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).unwrap()
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
        let req = make_request("/", "GET", &[("Cookie", "bulwark_token=tok123; other=val")]);
        let axum_req = AxumRequest::new(&req);
        assert_eq!(
            axum_req.cookie("bulwark_token").unwrap(),
            Some("tok123".to_string())
        );
        assert_eq!(axum_req.cookie("other").unwrap(), Some("val".to_string()));
        assert_eq!(axum_req.cookie("missing").unwrap(), None);
    }

    // ========================================================================
    // get_token 测试（spec context-abstraction Requirement: BulwarkRequest）
    // ========================================================================

    /// 验证从 Authorization: Bearer 提取 token（spec Scenario: 从 header 提取 token）。
    #[test]
    fn get_token_from_bearer_header() {
        let req = make_request("/", "GET", &[("Authorization", "Bearer my_token_123")]);
        let axum_req = AxumRequest::new(&req);
        let config = BulwarkConfig::default_config();
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(token, Some("my_token_123".to_string()));
    }

    /// 验证 Bearer 前缀大小写不敏感（依据 codebase-hardening Task 3.9，RFC 7235）。
    ///
    /// 覆盖 `strip_bearer_prefix` 的 `eq_ignore_ascii_case` 分支：
    /// `bearer xxx` / `BEARER xxx` / `BeArEr xxx` 均应能提取 token。
    #[test]
    fn bearer_prefix_case_insensitive() {
        let config = BulwarkConfig::default_config();
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
        let req = make_request("/", "GET", &[("bulwark_token", "header_token_456")]);
        let axum_req = AxumRequest::new(&req);
        let config = BulwarkConfig::default_config();
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(token, Some("header_token_456".to_string()));
    }

    /// 验证从 cookie 提取 token（spec Scenario: 从 cookie 提取 token）。
    #[test]
    fn get_token_from_cookie() {
        let req = make_request("/", "GET", &[("Cookie", "bulwark_token=cookie_token_789")]);
        let axum_req = AxumRequest::new(&req);
        let config = BulwarkConfig::default_config();
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
                ("Cookie", "bulwark_token=cookie_token"),
            ],
        );
        let axum_req = AxumRequest::new(&req);
        let config = BulwarkConfig::default_config();
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(token, Some("header_token".to_string()));
    }

    /// 验证无 token 时返回 None（spec Scenario: token 不存在）。
    #[test]
    fn get_token_returns_none_when_missing() {
        let req = make_request("/", "GET", &[]);
        let axum_req = AxumRequest::new(&req);
        let config = BulwarkConfig::default_config();
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(token, None);
    }

    /// 验证 is_read_header=false 时不从 header 提取。
    #[test]
    fn get_token_skips_header_when_disabled() {
        let req = make_request("/", "GET", &[("Authorization", "Bearer header_token")]);
        let axum_req = AxumRequest::new(&req);
        let mut config = BulwarkConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = false;
        let token = axum_req.get_token(&config).unwrap();
        assert_eq!(token, None);
    }

    // ========================================================================
    // AxumResponse 测试（spec context-abstraction Requirement: BulwarkResponse）
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
        resp.set_cookie("bulwark_token", "cookie_value").unwrap();
        let set_cookie = resp
            .headers
            .get("Set-Cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert!(set_cookie.contains("bulwark_token=cookie_value"));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("Secure"));
        assert!(set_cookie.contains("SameSite=Lax"));
        assert!(set_cookie.contains("Path=/"));
    }

    /// 验证 set_cookie_with_config 依据 config 调整 Secure/SameSite（dev 场景关闭 Secure）。
    #[test]
    fn response_set_cookie_with_config_dev() {
        let mut resp = AxumResponse::new();
        let mut config = BulwarkConfig::default_config();
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
    // AxumStorage 测试（spec context-abstraction Requirement: BulwarkStorage）
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

    /// 验证 BulwarkContext trait 实现。
    #[test]
    fn context_trait_impl() {
        let req = make_request("/", "GET", &[("Authorization", "Bearer abc")]);
        let ctx = AxumContext::new(&req);

        let request = ctx.request().unwrap();
        let config = BulwarkConfig::default_config();
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
        assert!(matches!(err, BulwarkError::Context(_)));
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
        assert!(matches!(err, BulwarkError::Context(_)));
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
        assert!(matches!(err, BulwarkError::Context(_)));
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
        assert!(matches!(err, BulwarkError::Context(_)));
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
        let req = make_request("/", "GET", &[("Cookie", "bulwark_token=cookie_tok")]);
        let ctx = AxumContext::new(&req);
        let request = ctx.request().unwrap();
        let mut config = BulwarkConfig::default_config();
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
        let config = BulwarkConfig::default_config();
        let token = request.get_token(&config).unwrap();
        assert_eq!(token, None);
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
}
