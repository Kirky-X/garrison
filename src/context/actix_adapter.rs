//! actix-web 适配器模块。
//!
//! 实现 `BulwarkContext` / `BulwarkRequest` / `BulwarkResponse` / `BulwarkStorage` trait，
//! 将 Bulwark 鉴权逻辑与 actix-web 4 Web 框架解耦。
//!
//! ## 设计
//!
//! - `ActixRequest` 包装 `&actix_web::HttpRequest`（不可变引用）
//! - `ActixResponse` 持有 `HeaderMap + StatusCode`
//! - `ActixStorage` 用 `HashMap<String, String>`
//! - `ActixContext` 组合 `&HttpRequest + ActixResponse + ActixStorage`

use crate::config::BulwarkConfig;
use crate::context::token_extract::strip_bearer_prefix;
use crate::context::{BulwarkContext, BulwarkRequest, BulwarkResponse, BulwarkStorage};
use crate::error::{BulwarkError, BulwarkResult};
use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
use actix_web::http::StatusCode;
use actix_web::HttpRequest;
use std::collections::HashMap;

// ============================================================================
// ActixRequest：包装 &HttpRequest
// ============================================================================

/// actix-web 请求适配器，包装 `&HttpRequest`。
pub struct ActixRequest<'a> {
    request: &'a HttpRequest,
}

impl<'a> ActixRequest<'a> {
    /// 创建新的 ActixRequest。
    ///
    /// # 参数
    /// - `request`: actix-web `HttpRequest` 引用，生命周期绑定到返回的 `ActixRequest`。
    ///
    /// # 返回
    /// 包装该请求引用的 `ActixRequest` 实例。
    pub fn new(request: &'a HttpRequest) -> Self {
        Self { request }
    }
}

impl<'a> BulwarkRequest for ActixRequest<'a> {
    fn path(&self) -> BulwarkResult<String> {
        Ok(self.request.path().to_string())
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
            .get("cookie")
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
// ActixResponse：持有 HeaderMap + StatusCode
// ============================================================================

/// actix-web 响应适配器，持有 HeaderMap 与 StatusCode。
pub struct ActixResponse {
    headers: HeaderMap,
    status: StatusCode,
}

impl ActixResponse {
    /// 创建新的 ActixResponse（默认 200 OK）。
    pub fn new() -> Self {
        Self {
            headers: HeaderMap::new(),
            status: StatusCode::OK,
        }
    }
}

impl Default for ActixResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl BulwarkResponse for ActixResponse {
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
// ActixStorage：HashMap<String, String>
// ============================================================================

/// actix-web 存储适配器，用 HashMap 实现请求级临时存储。
pub struct ActixStorage {
    map: HashMap<String, String>,
}

impl ActixStorage {
    /// 创建新的 ActixStorage。
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl Default for ActixStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl BulwarkStorage for ActixStorage {
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
// ActixContext：组合 Request + Response + Storage
// ============================================================================

/// actix-web 上下文适配器，组合 Request 引用 + Response + Storage。
///
/// # 设计
///
/// - 持有 `&HttpRequest` 引用 + `ActixResponse` + `ActixStorage`
/// - 通过 `raw_response_mut()` 写入 status / headers / cookies
/// - 通过 `raw_storage_mut()` 写入请求级临时数据
pub struct ActixContext<'a> {
    request: &'a HttpRequest,
    response: ActixResponse,
    storage: ActixStorage,
}

impl<'a> ActixContext<'a> {
    /// 创建新的 ActixContext，绑定到指定请求。
    ///
    /// # 参数
    /// - `request`: actix-web `HttpRequest` 引用，生命周期绑定到返回的 `ActixContext`。
    ///
    /// # 返回
    /// 绑定该请求的 `ActixContext` 实例（内部已初始化空的 `ActixResponse` 与 `ActixStorage`）。
    pub fn new(request: &'a HttpRequest) -> Self {
        Self {
            request,
            response: ActixResponse::new(),
            storage: ActixStorage::new(),
        }
    }

    /// 获取底层请求引用。
    ///
    /// # 返回
    /// 底层 `&HttpRequest` 引用，用于直接访问 actix-web 原生请求字段。
    pub fn raw_request(&self) -> &HttpRequest {
        self.request
    }

    /// 获取底层响应的不可变引用（用于读取已设置的 headers / status）。
    pub fn raw_response(&self) -> &ActixResponse {
        &self.response
    }

    /// 获取底层响应的可变引用（用于设置 status / headers / cookies）。
    pub fn raw_response_mut(&mut self) -> &mut ActixResponse {
        &mut self.response
    }

    /// 获取底层存储的不可变引用。
    pub fn raw_storage(&self) -> &ActixStorage {
        &self.storage
    }

    /// 获取底层存储的可变引用（用于 set / delete）。
    pub fn raw_storage_mut(&mut self) -> &mut ActixStorage {
        &mut self.storage
    }
}

impl<'a> BulwarkContext for ActixContext<'a> {
    fn request(&self) -> BulwarkResult<Box<dyn BulwarkRequest>> {
        // 由于 Box<dyn BulwarkRequest> 不能带生命周期参数，
        // 使用 ActixRequestWrapper 克隆必要数据（path / method / headers）
        Ok(Box::new(ActixRequestWrapper::new(self.request)))
    }
}

/// ActixRequest 包装器（绕过 Box<dyn> 的生命周期问题）。
///
/// 由于 `Box<dyn BulwarkRequest>` 不能带生命周期参数，
/// 这里克隆必要数据（path / method / headers）以实现 owned 的 `BulwarkRequest`。
struct ActixRequestWrapper {
    path: String,
    method: String,
    headers: HeaderMap,
}

impl ActixRequestWrapper {
    fn new(req: &HttpRequest) -> Self {
        Self {
            path: req.path().to_string(),
            method: req.method().as_str().to_string(),
            headers: req.headers().clone(),
        }
    }
}

impl BulwarkRequest for ActixRequestWrapper {
    fn path(&self) -> BulwarkResult<String> {
        Ok(self.path.clone())
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
            .get("cookie")
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
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    /// 构建测试用 HttpRequest。
    fn make_request(uri: &str, method: &str, headers: &[(&str, &str)]) -> HttpRequest {
        let mut req = TestRequest::default()
            .uri(uri)
            .method(method.parse().unwrap());
        for (name, value) in headers {
            req = req.insert_header((*name, *value));
        }
        req.to_http_request()
    }

    // ========================================================================
    // ActixRequest 测试
    // ========================================================================

    /// 验证 path() 返回请求路径。
    #[test]
    fn actix_request_path() {
        let req = make_request("/api/users", "GET", &[]);
        let actix_req = ActixRequest::new(&req);
        assert_eq!(actix_req.path().unwrap(), "/api/users");
    }

    /// 验证 method() 返回请求方法。
    #[test]
    fn actix_request_method() {
        let req = make_request("/", "POST", &[]);
        let actix_req = ActixRequest::new(&req);
        assert_eq!(actix_req.method().unwrap(), "POST");
    }

    /// 验证 header() 返回请求头（命中与未命中）。
    #[test]
    fn actix_request_header_returns_value() {
        let req = make_request("/", "GET", &[("X-Token", "abc123")]);
        let actix_req = ActixRequest::new(&req);
        assert_eq!(
            actix_req.header("X-Token").unwrap(),
            Some("abc123".to_string())
        );
        assert_eq!(actix_req.header("Not-Exist").unwrap(), None);
    }

    /// 验证 cookie() 解析 Cookie header（命中与未命中）。
    #[test]
    fn actix_request_cookie_returns_value() {
        let req = make_request("/", "GET", &[("Cookie", "bulwark_token=tok123; other=val")]);
        let actix_req = ActixRequest::new(&req);
        assert_eq!(
            actix_req.cookie("bulwark_token").unwrap(),
            Some("tok123".to_string())
        );
        assert_eq!(actix_req.cookie("other").unwrap(), Some("val".to_string()));
        assert_eq!(actix_req.cookie("missing").unwrap(), None);
    }

    /// 验证 cookie() 在没有 Cookie header 时返回 None。
    #[test]
    fn actix_request_cookie_empty_header_returns_none() {
        let req = make_request("/", "GET", &[]);
        let actix_req = ActixRequest::new(&req);
        assert_eq!(actix_req.cookie("any").unwrap(), None);
    }

    /// 验证 cookie() 跳过没有 '=' 的 cookie 项。
    #[test]
    fn actix_request_cookie_skips_pair_without_equals() {
        let req = make_request("/", "GET", &[("Cookie", "invalidpair; valid=val")]);
        let actix_req = ActixRequest::new(&req);
        assert_eq!(actix_req.cookie("valid").unwrap(), Some("val".to_string()));
        assert_eq!(actix_req.cookie("invalidpair").unwrap(), None);
    }

    /// 验证 header() 在 header name 非法时返回 Context 错误。
    #[test]
    fn actix_request_header_invalid_name_errors() {
        let req = make_request("/", "GET", &[]);
        let actix_req = ActixRequest::new(&req);
        let result = actix_req.header("invalid header");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BulwarkError::Context(_)));
        assert!(err.to_string().contains("invalid header name"));
    }

    // ========================================================================
    // get_token 测试
    // ========================================================================

    /// 验证从 Authorization: Bearer 提取 token。
    #[test]
    fn actix_request_get_token_from_header() {
        let req = make_request("/", "GET", &[("Authorization", "Bearer my_token_123")]);
        let actix_req = ActixRequest::new(&req);
        let config = BulwarkConfig::default_config();
        let token = actix_req.get_token(&config).unwrap();
        assert_eq!(token, Some("my_token_123".to_string()));
    }

    /// 验证 Bearer 前缀大小写不敏感（依据 RFC 7235）。
    #[test]
    fn actix_request_bearer_prefix_case_insensitive() {
        let config = BulwarkConfig::default_config();
        for prefix in &["Bearer", "bearer", "BEARER", "BeArEr"] {
            let auth_value = format!("{} tok_{}", prefix, prefix);
            let req = make_request("/", "GET", &[("Authorization", auth_value.as_str())]);
            let actix_req = ActixRequest::new(&req);
            let token = actix_req.get_token(&config).unwrap();
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
    fn actix_request_get_token_from_custom_header() {
        let req = make_request("/", "GET", &[("bulwark_token", "header_token_456")]);
        let actix_req = ActixRequest::new(&req);
        let config = BulwarkConfig::default_config();
        let token = actix_req.get_token(&config).unwrap();
        assert_eq!(token, Some("header_token_456".to_string()));
    }

    /// 验证从 cookie 提取 token。
    #[test]
    fn actix_request_get_token_from_cookie() {
        let req = make_request("/", "GET", &[("Cookie", "bulwark_token=cookie_token_789")]);
        let actix_req = ActixRequest::new(&req);
        let config = BulwarkConfig::default_config();
        let token = actix_req.get_token(&config).unwrap();
        assert_eq!(token, Some("cookie_token_789".to_string()));
    }

    /// 验证 header 优先级高于 cookie。
    #[test]
    fn actix_request_get_token_header_priority_over_cookie() {
        let req = make_request(
            "/",
            "GET",
            &[
                ("Authorization", "Bearer header_token"),
                ("Cookie", "bulwark_token=cookie_token"),
            ],
        );
        let actix_req = ActixRequest::new(&req);
        let config = BulwarkConfig::default_config();
        let token = actix_req.get_token(&config).unwrap();
        assert_eq!(token, Some("header_token".to_string()));
    }

    /// 验证无 token 时返回 None。
    #[test]
    fn actix_request_get_token_returns_none_when_missing() {
        let req = make_request("/", "GET", &[]);
        let actix_req = ActixRequest::new(&req);
        let config = BulwarkConfig::default_config();
        let token = actix_req.get_token(&config).unwrap();
        assert_eq!(token, None);
    }

    /// 验证 is_read_header=false 时不从 header 提取。
    #[test]
    fn actix_request_get_token_skips_header_when_disabled() {
        let req = make_request("/", "GET", &[("Authorization", "Bearer header_token")]);
        let actix_req = ActixRequest::new(&req);
        let mut config = BulwarkConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = false;
        let token = actix_req.get_token(&config).unwrap();
        assert_eq!(token, None);
    }

    // ========================================================================
    // ActixResponse 测试
    // ========================================================================

    /// 验证 set_status 设置状态码。
    #[test]
    fn actix_response_set_status() {
        let mut resp = ActixResponse::new();
        resp.set_status(401).unwrap();
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    /// 验证 set_header 设置响应头。
    #[test]
    fn actix_response_set_header() {
        let mut resp = ActixResponse::new();
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
    fn actix_response_set_cookie_writes_header() {
        let mut resp = ActixResponse::new();
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
    fn actix_response_set_cookie_with_config_dev() {
        let mut resp = ActixResponse::new();
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

    /// 验证 set_status 在状态码非法（> 999）时返回 Context 错误。
    #[test]
    fn actix_response_set_status_invalid_code_errors() {
        let mut resp = ActixResponse::new();
        let result = resp.set_status(1000);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BulwarkError::Context(_)));
        assert!(err.to_string().contains("invalid status code"));
    }

    /// 验证 set_header 在 header value 非法时返回 Context 错误。
    #[test]
    fn actix_response_set_header_invalid_value_errors() {
        let mut resp = ActixResponse::new();
        let result = resp.set_header("X-Test", "bad\0value");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BulwarkError::Context(_)));
        assert!(err.to_string().contains("invalid header value"));
    }

    /// 验证 set_header 在 header name 非法时返回 Context 错误。
    #[test]
    fn actix_response_set_header_invalid_name_errors() {
        let mut resp = ActixResponse::new();
        let result = resp.set_header("invalid header", "value");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BulwarkError::Context(_)));
    }

    /// 验证 Default 实现等价于 new()。
    #[test]
    fn actix_response_default_impl() {
        let resp = ActixResponse::default();
        assert_eq!(resp.status, StatusCode::OK);
        assert!(resp.headers.is_empty());
    }

    // ========================================================================
    // ActixStorage 测试
    // ========================================================================

    /// 验证 set/get/delete 存储数据。
    #[test]
    fn actix_storage_set_get_delete() {
        let mut storage = ActixStorage::new();
        storage.set("trace_id", "abc-123").unwrap();
        assert_eq!(
            storage.get("trace_id").unwrap(),
            Some("abc-123".to_string())
        );
        storage.delete("trace_id").unwrap();
        assert_eq!(storage.get("trace_id").unwrap(), None);
    }

    /// 验证请求间隔离。
    #[test]
    fn actix_storage_request_isolation() {
        let mut storage_a = ActixStorage::new();
        storage_a.set("trace_id", "A").unwrap();

        let mut storage_b = ActixStorage::new();
        storage_b.set("trace_id", "B").unwrap();

        assert_eq!(storage_a.get("trace_id").unwrap(), Some("A".to_string()));
        assert_eq!(storage_b.get("trace_id").unwrap(), Some("B".to_string()));
    }

    /// 验证不存在的 key 返回 None。
    #[test]
    fn actix_storage_missing_key_returns_none() {
        let storage = ActixStorage::new();
        assert_eq!(storage.get("missing").unwrap(), None);
    }

    /// 验证 Default 实现等价于 new()。
    #[test]
    fn actix_storage_default_impl() {
        let storage = ActixStorage::default();
        assert_eq!(storage.get("any").unwrap(), None);
    }

    // ========================================================================
    // ActixContext 测试
    // ========================================================================

    /// 验证 BulwarkContext::request() 返回 Box<dyn BulwarkRequest>。
    #[test]
    fn actix_context_request_returns_box() {
        let req = make_request("/api/test", "GET", &[("Authorization", "Bearer abc")]);
        let ctx = ActixContext::new(&req);

        let request = ctx.request().unwrap();
        let config = BulwarkConfig::default_config();
        let token = request.get_token(&config).unwrap();
        assert_eq!(token, Some("abc".to_string()));
    }

    /// 验证 ActixContext::request() 返回的 wrapper 正确提取 path。
    #[test]
    fn actix_context_wrapper_path() {
        let req = make_request("/api/v1/users", "GET", &[]);
        let ctx = ActixContext::new(&req);
        let request = ctx.request().unwrap();
        assert_eq!(request.path().unwrap(), "/api/v1/users");
    }

    /// 验证 ActixContext::request() 返回的 wrapper 正确返回 method。
    #[test]
    fn actix_context_wrapper_method() {
        let req = make_request("/", "PUT", &[]);
        let ctx = ActixContext::new(&req);
        let request = ctx.request().unwrap();
        assert_eq!(request.method().unwrap(), "PUT");
    }

    /// 验证 ActixContext::request() 返回的 wrapper 正确读取 header。
    #[test]
    fn actix_context_wrapper_header() {
        let req = make_request("/", "GET", &[("X-Custom", "hello")]);
        let ctx = ActixContext::new(&req);
        let request = ctx.request().unwrap();
        assert_eq!(
            request.header("X-Custom").unwrap(),
            Some("hello".to_string())
        );
        assert_eq!(request.header("Missing").unwrap(), None);
    }

    /// 验证 ActixContext::request() 返回的 wrapper 从 cookie 提取 token。
    #[test]
    fn actix_context_wrapper_get_token_from_cookie() {
        let req = make_request("/", "GET", &[("Cookie", "bulwark_token=cookie_tok")]);
        let ctx = ActixContext::new(&req);
        let request = ctx.request().unwrap();
        let mut config = BulwarkConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = true;
        let token = request.get_token(&config).unwrap();
        assert_eq!(token, Some("cookie_tok".to_string()));
    }

    /// 验证 raw_response_mut() 返回可写的内部 response 引用。
    #[test]
    fn actix_context_raw_response_mut_writable() {
        let req = make_request("/", "GET", &[]);
        let mut ctx = ActixContext::new(&req);
        ctx.raw_response_mut().set_status(404).unwrap();
        ctx.raw_response_mut()
            .set_header("X-Trace", "trace-123")
            .unwrap();
        assert_eq!(ctx.raw_response().status, StatusCode::NOT_FOUND);
    }

    /// 验证 raw_storage_mut() 返回可写的内部 storage 引用。
    #[test]
    fn actix_context_raw_storage_mut_writable() {
        let req = make_request("/", "GET", &[]);
        let mut ctx = ActixContext::new(&req);
        ctx.raw_storage_mut().set("key", "value").unwrap();
        assert_eq!(
            ctx.raw_storage().get("key").unwrap(),
            Some("value".to_string())
        );
    }

    /// 验证 raw_request() 返回底层请求引用。
    #[test]
    fn actix_context_raw_request() {
        let req = make_request("/api/test", "GET", &[]);
        let ctx = ActixContext::new(&req);
        assert_eq!(ctx.raw_request().path(), "/api/test");
    }
}
