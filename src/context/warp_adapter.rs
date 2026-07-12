//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! warp 适配器模块。
//!
//! 实现 `BulwarkContext` / `BulwarkRequest` / `BulwarkResponse` / `BulwarkStorage` trait，
//! 将 Bulwark 鉴权逻辑与 warp 0.4 Web 框架解耦。
//!
//! ## 设计
//!
//! - `WarpRequest` 持有 `warp::http::HeaderMap` + path + method（克隆数据，owned）
//! - `WarpResponse` 持有 `HeaderMap + StatusCode`
//! - `WarpStorage` 用 `HashMap<String, String>`
//! - `WarpContext` 组合 `WarpRequest + WarpResponse + WarpStorage`

use crate::config::BulwarkConfig;
use crate::context::token_extract::strip_bearer_prefix;
use crate::context::{BulwarkContext, BulwarkRequest, BulwarkResponse, BulwarkStorage};
use crate::error::{BulwarkError, BulwarkResult};
use std::collections::HashMap;
use warp::http::header::{HeaderMap, HeaderName, HeaderValue};
use warp::http::StatusCode;

// ============================================================================
// WarpRequest：持有 path + method + HeaderMap（owned）
// ============================================================================

/// warp 请求适配器，持有 path / method / HeaderMap（owned）。
///
/// # 设计
///
/// 与 `ActixRequest`（持有引用）不同，`WarpRequest` 持有 owned 数据，
/// 因为 warp 的 Filter 体系通常在中间件层就已提取出 HeaderMap。
pub struct WarpRequest {
    path: String,
    method: String,
    headers: HeaderMap,
    /// 预读的 body 字节（用于 `is_read_body=true` 时从 JSON 提取 token）。
    ///
    /// body 读取是 async 操作，但 `get_token` 是 sync 方法，故由调用方在
    /// async 上下文中预读 body 字节后通过 `with_body` 注入。
    /// 默认空 `Vec`（`new` 构造时），此时 body 读取分支静默跳过。
    body_bytes: Vec<u8>,
}

impl WarpRequest {
    /// 创建新的 WarpRequest（body 为空，不读取 body）。
    ///
    /// # 参数
    /// - `path`: 请求路径（如 `/api/users`）。
    /// - `method`: 请求方法（如 `GET` / `POST`）。
    /// - `headers`: 请求头 `HeaderMap`。
    ///
    /// # 返回
    /// 持有 owned 数据的 `WarpRequest` 实例（`body_bytes` 为空）。
    pub fn new(path: String, method: String, headers: HeaderMap) -> Self {
        Self {
            path,
            method,
            headers,
            body_bytes: Vec::new(),
        }
    }

    /// 创建带预读 body 的 WarpRequest（用于 `is_read_body=true` 场景）。
    ///
    /// # 参数
    /// - `path`: 请求路径。
    /// - `method`: 请求方法。
    /// - `headers`: 请求头 `HeaderMap`。
    /// - `body_bytes`: 预读的 body 字节（调用方在 async 上下文中读取后传入）。
    ///
    /// # 返回
    /// 持有 owned 数据与 body 字节的 `WarpRequest` 实例。
    pub fn with_body(
        path: String,
        method: String,
        headers: HeaderMap,
        body_bytes: Vec<u8>,
    ) -> Self {
        Self {
            path,
            method,
            headers,
            body_bytes,
        }
    }
}

impl BulwarkRequest for WarpRequest {
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
        // 3. 从 body 提取（优先级最低，仅当 is_read_body=true 且有预读 body 字节时）
        if config.is_read_body && !self.body_bytes.is_empty() {
            // 检查 Content-Type: application/json
            let content_type = self.header("Content-Type")?.unwrap_or_default();
            if content_type.contains("application/json") {
                // 静默解析 JSON 并提取 token_name 字段（失败回退 None，不报错）
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&self.body_bytes) {
                    if let Some(token) = value.get(&config.token_name).and_then(|v| v.as_str()) {
                        return Ok(Some(token.to_string()));
                    }
                }
            }
        }
        Ok(None)
    }
}

// ============================================================================
// WarpResponse：持有 HeaderMap + StatusCode
// ============================================================================

/// warp 响应适配器，持有 HeaderMap 与 StatusCode。
pub struct WarpResponse {
    headers: HeaderMap,
    status: StatusCode,
}

impl WarpResponse {
    /// 创建新的 WarpResponse（默认 200 OK）。
    pub fn new() -> Self {
        Self {
            headers: HeaderMap::new(),
            status: StatusCode::OK,
        }
    }
}

impl Default for WarpResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl BulwarkResponse for WarpResponse {
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
// WarpStorage：HashMap<String, String>
// ============================================================================

/// warp 存储适配器，用 HashMap 实现请求级临时存储。
pub struct WarpStorage {
    map: HashMap<String, String>,
}

impl WarpStorage {
    /// 创建新的 WarpStorage。
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl Default for WarpStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl BulwarkStorage for WarpStorage {
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
// WarpContext：组合 Request + Response + Storage
// ============================================================================

/// warp 上下文适配器，组合 Request + Response + Storage。
///
/// # 设计
///
/// - 持有 `WarpRequest`（owned）+ `WarpResponse` + `WarpStorage`
/// - 通过 `raw_response_mut()` 写入 status / headers / cookies
/// - 通过 `raw_storage_mut()` 写入请求级临时数据
pub struct WarpContext {
    request_data: WarpRequest,
    response: WarpResponse,
    storage: WarpStorage,
    /// 预读的 body 字节（用于 `is_read_body=true` 时从 JSON 提取 token）。
    ///
    /// body 读取是 async 操作，但 `get_token` 是 sync 方法，故由调用方在
    /// async 上下文中预读 body 字节后通过 `with_body` 注入。
    /// 默认空 `Vec`（`new` 构造时），此时 body 读取分支静默跳过。
    body_bytes: Vec<u8>,
}

impl WarpContext {
    /// 创建新的 WarpContext（body 为空，不读取 body）。
    ///
    /// # 参数
    /// - `path`: 请求路径。
    /// - `method`: 请求方法。
    /// - `headers`: 请求头 `HeaderMap`。
    ///
    /// # 返回
    /// 包含请求数据的 `WarpContext` 实例（内部已初始化空的 `WarpResponse` 与 `WarpStorage`，
    /// `body_bytes` 为空）。
    pub fn new(path: String, method: String, headers: HeaderMap) -> Self {
        Self {
            request_data: WarpRequest::new(path, method, headers),
            response: WarpResponse::new(),
            storage: WarpStorage::new(),
            body_bytes: Vec::new(),
        }
    }

    /// 创建带预读 body 的 WarpContext（用于 `is_read_body=true` 场景）。
    ///
    /// # 参数
    /// - `path`: 请求路径。
    /// - `method`: 请求方法。
    /// - `headers`: 请求头 `HeaderMap`。
    /// - `body_bytes`: 预读的 body 字节（调用方在 async 上下文中读取后传入）。
    ///
    /// # 返回
    /// 包含请求数据与 body 字节的 `WarpContext` 实例。
    pub fn with_body(
        path: String,
        method: String,
        headers: HeaderMap,
        body_bytes: Vec<u8>,
    ) -> Self {
        Self {
            request_data: WarpRequest::new(path, method, headers),
            response: WarpResponse::new(),
            storage: WarpStorage::new(),
            body_bytes,
        }
    }

    /// 获取底层响应的不可变引用（用于读取已设置的 headers / status）。
    pub fn raw_response(&self) -> &WarpResponse {
        &self.response
    }

    /// 获取底层响应的可变引用（用于设置 status / headers / cookies）。
    pub fn raw_response_mut(&mut self) -> &mut WarpResponse {
        &mut self.response
    }

    /// 获取底层存储的不可变引用。
    pub fn raw_storage(&self) -> &WarpStorage {
        &self.storage
    }

    /// 获取底层存储的可变引用（用于 set / delete）。
    pub fn raw_storage_mut(&mut self) -> &mut WarpStorage {
        &mut self.storage
    }
}

impl BulwarkContext for WarpContext {
    fn request(&self) -> BulwarkResult<Box<dyn BulwarkRequest>> {
        // WarpRequest 已 owned，直接克隆数据构造新实例（含 body_bytes）
        Ok(Box::new(WarpRequest::with_body(
            self.request_data.path.clone(),
            self.request_data.method.clone(),
            self.request_data.headers.clone(),
            self.body_bytes.clone(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构建测试用 HeaderMap。
    fn make_headers(headers: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.insert(
                name.parse::<HeaderName>().unwrap(),
                value.parse::<HeaderValue>().unwrap(),
            );
        }
        map
    }

    /// 构建测试用 WarpRequest。
    fn make_warp_request(path: &str, method: &str, headers: &[(&str, &str)]) -> WarpRequest {
        WarpRequest::new(path.to_string(), method.to_string(), make_headers(headers))
    }

    // ========================================================================
    // WarpRequest 测试
    // ========================================================================

    /// 验证 path() 返回请求路径。
    #[test]
    fn warp_request_path() {
        let req = make_warp_request("/api/users", "GET", &[]);
        assert_eq!(req.path().unwrap(), "/api/users");
    }

    /// 验证 method() 返回请求方法。
    #[test]
    fn warp_request_method() {
        let req = make_warp_request("/", "POST", &[]);
        assert_eq!(req.method().unwrap(), "POST");
    }

    /// 验证 header() 返回请求头（命中与未命中）。
    #[test]
    fn warp_request_header_returns_value() {
        let req = make_warp_request("/", "GET", &[("X-Token", "abc123")]);
        assert_eq!(req.header("X-Token").unwrap(), Some("abc123".to_string()));
        assert_eq!(req.header("Not-Exist").unwrap(), None);
    }

    /// 验证 cookie() 解析 Cookie header（命中与未命中）。
    #[test]
    fn warp_request_cookie_returns_value() {
        let req = make_warp_request("/", "GET", &[("Cookie", "bulwark_token=tok123; other=val")]);
        assert_eq!(
            req.cookie("bulwark_token").unwrap(),
            Some("tok123".to_string())
        );
        assert_eq!(req.cookie("other").unwrap(), Some("val".to_string()));
        assert_eq!(req.cookie("missing").unwrap(), None);
    }

    /// 验证 cookie() 在没有 Cookie header 时返回 None。
    #[test]
    fn warp_request_cookie_empty_header_returns_none() {
        let req = make_warp_request("/", "GET", &[]);
        assert_eq!(req.cookie("any").unwrap(), None);
    }

    /// 验证 cookie() 跳过没有 '=' 的 cookie 项。
    #[test]
    fn warp_request_cookie_skips_pair_without_equals() {
        let req = make_warp_request("/", "GET", &[("Cookie", "invalidpair; valid=val")]);
        assert_eq!(req.cookie("valid").unwrap(), Some("val".to_string()));
        assert_eq!(req.cookie("invalidpair").unwrap(), None);
    }

    /// 验证 header() 在 header name 非法时返回 Context 错误。
    #[test]
    fn warp_request_header_invalid_name_errors() {
        let req = make_warp_request("/", "GET", &[]);
        let result = req.header("invalid header");
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
    fn warp_request_get_token_from_header() {
        let req = make_warp_request("/", "GET", &[("Authorization", "Bearer my_token_123")]);
        let config = BulwarkConfig::default_config();
        let token = req.get_token(&config).unwrap();
        assert_eq!(token, Some("my_token_123".to_string()));
    }

    /// 验证 Bearer 前缀大小写不敏感。
    #[test]
    fn warp_request_bearer_prefix_case_insensitive() {
        let config = BulwarkConfig::default_config();
        for prefix in &["Bearer", "bearer", "BEARER", "BeArEr"] {
            let auth_value = format!("{} tok_{}", prefix, prefix);
            let req = make_warp_request("/", "GET", &[("Authorization", auth_value.as_str())]);
            let token = req.get_token(&config).unwrap();
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
    fn warp_request_get_token_from_custom_header() {
        let req = make_warp_request("/", "GET", &[("bulwark_token", "header_token_456")]);
        let config = BulwarkConfig::default_config();
        let token = req.get_token(&config).unwrap();
        assert_eq!(token, Some("header_token_456".to_string()));
    }

    /// 验证从 cookie 提取 token。
    #[test]
    fn warp_request_get_token_from_cookie() {
        let req = make_warp_request("/", "GET", &[("Cookie", "bulwark_token=cookie_token_789")]);
        let config = BulwarkConfig::default_config();
        let token = req.get_token(&config).unwrap();
        assert_eq!(token, Some("cookie_token_789".to_string()));
    }

    /// 验证 header 优先级高于 cookie。
    #[test]
    fn warp_request_get_token_header_priority_over_cookie() {
        let req = make_warp_request(
            "/",
            "GET",
            &[
                ("Authorization", "Bearer header_token"),
                ("Cookie", "bulwark_token=cookie_token"),
            ],
        );
        let config = BulwarkConfig::default_config();
        let token = req.get_token(&config).unwrap();
        assert_eq!(token, Some("header_token".to_string()));
    }

    /// 验证无 token 时返回 None。
    #[test]
    fn warp_request_get_token_returns_none_when_missing() {
        let req = make_warp_request("/", "GET", &[]);
        let config = BulwarkConfig::default_config();
        let token = req.get_token(&config).unwrap();
        assert_eq!(token, None);
    }

    /// 验证 is_read_header=false 时不从 header 提取。
    #[test]
    fn warp_request_get_token_skips_header_when_disabled() {
        let req = make_warp_request("/", "GET", &[("Authorization", "Bearer header_token")]);
        let mut config = BulwarkConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = false;
        let token = req.get_token(&config).unwrap();
        assert_eq!(token, None);
    }

    // ========================================================================
    // WarpResponse 测试
    // ========================================================================

    /// 验证 set_status 设置状态码。
    #[test]
    fn warp_response_set_status() {
        let mut resp = WarpResponse::new();
        resp.set_status(401).unwrap();
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    /// 验证 set_header 设置响应头。
    #[test]
    fn warp_response_set_header() {
        let mut resp = WarpResponse::new();
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
    fn warp_response_set_cookie_writes_header() {
        let mut resp = WarpResponse::new();
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
    fn warp_response_set_cookie_with_config_dev() {
        let mut resp = WarpResponse::new();
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
    fn warp_response_set_status_invalid_code_errors() {
        let mut resp = WarpResponse::new();
        let result = resp.set_status(1000);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BulwarkError::Context(_)));
        assert!(err.to_string().contains("invalid status code"));
    }

    /// 验证 set_header 在 header value 非法时返回 Context 错误。
    #[test]
    fn warp_response_set_header_invalid_value_errors() {
        let mut resp = WarpResponse::new();
        let result = resp.set_header("X-Test", "bad\0value");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BulwarkError::Context(_)));
        assert!(err.to_string().contains("invalid header value"));
    }

    /// 验证 set_header 在 header name 非法时返回 Context 错误。
    #[test]
    fn warp_response_set_header_invalid_name_errors() {
        let mut resp = WarpResponse::new();
        let result = resp.set_header("invalid header", "value");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BulwarkError::Context(_)));
    }

    /// 验证 Default 实现等价于 new()。
    #[test]
    fn warp_response_default_impl() {
        let resp = WarpResponse::default();
        assert_eq!(resp.status, StatusCode::OK);
        assert!(resp.headers.is_empty());
    }

    // ========================================================================
    // WarpStorage 测试
    // ========================================================================

    /// 验证 set/get/delete 存储数据。
    #[test]
    fn warp_storage_set_get_delete() {
        let mut storage = WarpStorage::new();
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
    fn warp_storage_request_isolation() {
        let mut storage_a = WarpStorage::new();
        storage_a.set("trace_id", "A").unwrap();

        let mut storage_b = WarpStorage::new();
        storage_b.set("trace_id", "B").unwrap();

        assert_eq!(storage_a.get("trace_id").unwrap(), Some("A".to_string()));
        assert_eq!(storage_b.get("trace_id").unwrap(), Some("B".to_string()));
    }

    /// 验证不存在的 key 返回 None。
    #[test]
    fn warp_storage_missing_key_returns_none() {
        let storage = WarpStorage::new();
        assert_eq!(storage.get("missing").unwrap(), None);
    }

    /// 验证 Default 实现等价于 new()。
    #[test]
    fn warp_storage_default_impl() {
        let storage = WarpStorage::default();
        assert_eq!(storage.get("any").unwrap(), None);
    }

    // ========================================================================
    // WarpContext 测试
    // ========================================================================

    /// 验证 BulwarkContext::request() 返回 Box<dyn BulwarkRequest>。
    #[test]
    fn warp_context_request_returns_box() {
        let ctx = WarpContext::new(
            "/api/test".to_string(),
            "GET".to_string(),
            make_headers(&[("Authorization", "Bearer abc")]),
        );

        let request = ctx.request().unwrap();
        let config = BulwarkConfig::default_config();
        let token = request.get_token(&config).unwrap();
        assert_eq!(token, Some("abc".to_string()));
    }

    /// 验证 WarpContext::request() 返回的 wrapper 正确提取 path。
    #[test]
    fn warp_context_wrapper_path() {
        let ctx = WarpContext::new(
            "/api/v1/users".to_string(),
            "GET".to_string(),
            make_headers(&[]),
        );
        let request = ctx.request().unwrap();
        assert_eq!(request.path().unwrap(), "/api/v1/users");
    }

    /// 验证 WarpContext::request() 返回的 wrapper 正确返回 method。
    #[test]
    fn warp_context_wrapper_method() {
        let ctx = WarpContext::new("/".to_string(), "PUT".to_string(), make_headers(&[]));
        let request = ctx.request().unwrap();
        assert_eq!(request.method().unwrap(), "PUT");
    }

    /// 验证 WarpContext::request() 返回的 wrapper 正确读取 header。
    #[test]
    fn warp_context_wrapper_header() {
        let ctx = WarpContext::new(
            "/".to_string(),
            "GET".to_string(),
            make_headers(&[("X-Custom", "hello")]),
        );
        let request = ctx.request().unwrap();
        assert_eq!(
            request.header("X-Custom").unwrap(),
            Some("hello".to_string())
        );
        assert_eq!(request.header("Missing").unwrap(), None);
    }

    /// 验证 WarpContext::request() 返回的 wrapper 从 cookie 提取 token。
    #[test]
    fn warp_context_wrapper_get_token_from_cookie() {
        let ctx = WarpContext::new(
            "/".to_string(),
            "GET".to_string(),
            make_headers(&[("Cookie", "bulwark_token=cookie_tok")]),
        );
        let request = ctx.request().unwrap();
        let mut config = BulwarkConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = true;
        let token = request.get_token(&config).unwrap();
        assert_eq!(token, Some("cookie_tok".to_string()));
    }

    /// 验证 raw_response_mut() 返回可写的内部 response 引用。
    #[test]
    fn warp_context_raw_response_mut_writable() {
        let mut ctx = WarpContext::new("/".to_string(), "GET".to_string(), make_headers(&[]));
        ctx.raw_response_mut().set_status(404).unwrap();
        ctx.raw_response_mut()
            .set_header("X-Trace", "trace-123")
            .unwrap();
        assert_eq!(ctx.raw_response().status, StatusCode::NOT_FOUND);
    }

    /// 验证 raw_storage_mut() 返回可写的内部 storage 引用。
    #[test]
    fn warp_context_raw_storage_mut_writable() {
        let mut ctx = WarpContext::new("/".to_string(), "GET".to_string(), make_headers(&[]));
        ctx.raw_storage_mut().set("key", "value").unwrap();
        assert_eq!(
            ctx.raw_storage().get("key").unwrap(),
            Some("value".to_string())
        );
    }

    // ========================================================================
    // get_token body 读取测试（T007）
    // ========================================================================

    /// 验证 is_read_body=true 时从 JSON body 的 token_name 字段提取 token。
    #[test]
    fn extract_token_from_body_when_is_read_body_true() {
        let req = WarpRequest::with_body(
            "/".to_string(),
            "POST".to_string(),
            make_headers(&[("Content-Type", "application/json")]),
            br#"{"bulwark_token":"body_token_456"}"#.to_vec(),
        );
        let mut config = BulwarkConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = false;
        config.is_read_body = true;
        let token = req.get_token(&config).unwrap();
        assert_eq!(token, Some("body_token_456".to_string()));
    }

    // ========================================================================
    // Context 层 body 读取测试（HIGH-002 回归）
    // ========================================================================

    /// 验证 `WarpContext::with_body()` 通过 `request()` 传递 `body_bytes`，
    /// 使 `BulwarkRequest::get_token()` 能从 JSON body 提取 token。
    ///
    /// 回归 HIGH-002：原 `WarpContext` 缺失 `body_bytes` 字段与 `with_body` 方法，
    /// `request()` 用 `WarpRequest::new()` 丢弃 body_bytes，导致 Context 层 body 读取功能不可用。
    #[test]
    fn warp_context_with_body_extracts_token_from_body() {
        let ctx = WarpContext::with_body(
            "/".to_string(),
            "POST".to_string(),
            make_headers(&[("Content-Type", "application/json")]),
            br#"{"bulwark_token":"ctx_body_token"}"#.to_vec(),
        );
        let request = ctx.request().unwrap();
        let mut config = BulwarkConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = false;
        config.is_read_body = true;
        let token = request.get_token(&config).unwrap();
        assert_eq!(
            token,
            Some("ctx_body_token".to_string()),
            "WarpContext::with_body 应通过 request() 传递 body_bytes，使 get_token 能从 body 提取 token"
        );
    }
}
