//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 上下文模块，提供请求 / 响应 / 存储上下文抽象。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的上下文抽象层，
//! 通过 trait 隔离 Web 框架差异，实现框架无关的鉴权逻辑。
//!
//! ## 架构
//!
//! - `BulwarkContext`：上下文入口，提供 request/response/storage 访问
//! - `BulwarkRequest`：HTTP 请求抽象（path/method/header/cookie/get_token）
//! - `BulwarkResponse`：HTTP 响应抽象（set_status/set_header/set_cookie）
//! - `BulwarkStorage`：请求级临时存储（set/get/delete，请求结束清理）
//!
//! ## axum 适配器
//!
//! `feature = "web-axum"` 时提供 `AxumContext` 实现：
//! - `AxumRequest` 包装 `&http::Request<axum::body::Body>`
//! - `AxumResponse` 持有 `HeaderMap + StatusCode`，`to_response()` 转换为 axum Response
//! - `AxumStorage` 用 `HashMap<String, String>`
//!
//! ## actix-web 适配器
//!
//! `feature = "web-actix"` 时提供 `ActixContext` 实现：
//! - `ActixRequest` 包装 `&actix_web::HttpRequest`
//! - `ActixResponse` 持有 `HeaderMap + StatusCode`
//! - `ActixStorage` 用 `HashMap<String, String>`
//!
//! ## warp 适配器
//!
//! `feature = "web-warp"` 时提供 `WarpContext` 实现：
//! - `WarpRequest` 持有 `warp::http::HeaderMap` + path + method（owned）
//! - `WarpResponse` 持有 `HeaderMap + StatusCode`
//! - `WarpStorage` 用 `HashMap<String, String>`

use crate::error::BulwarkResult;

// ============================================================================
// 多租户隔离上下文
// ============================================================================

pub mod tenant;

// ============================================================================
// Token 提取公共函数（供 web 框架适配器与 context 适配器共用，无 feature gate）
// ============================================================================

pub mod token_extract;

pub use token_extract::{extract_token_from_headers, strip_bearer_prefix, HeaderLookup};

// ============================================================================
// 登录主体
// ============================================================================

/// 当前请求的登录主体。
///
/// 携带从 token 解析出的 `login_id`，由各 web 框架的 extractor
/// （`web_actix::extractor::BulwarkPrincipal` / `web_warp::extractor::BulwarkPrincipal`）
/// 从 `Authorization: Bearer <token>` header 提取并填充。
///
/// # 字段
///
/// - `login_id`: 当前登录用户 ID，从 token-session 映射解析得到。
///
/// # 使用示例
///
/// ```ignore
/// use bulwark::context::BulwarkPrincipal;
///
/// fn handler(principal: BulwarkPrincipal) -> String {
///     format!("login_id = {}", principal.login_id)
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulwarkPrincipal {
    /// 当前登录用户 ID（从 token-session 映射解析）。
    pub login_id: String,
}

/// 上下文 trait，提供请求访问入口。
///
/// [借鉴 Sa-Token] 对应 `SaTokenContext`，
/// 各 Web 框架适配需实现此 trait。
///
/// # 设计
///
/// 仅暴露 `request()` 方法获取请求对象。
/// 响应数据写入由具体适配器（如 `AxumContext::raw_response_mut()` / `into_response()`）提供，
/// 避免 trait 方法返回新实例破坏状态共享。
pub trait BulwarkContext {
    /// 获取当前请求对象。
    fn request(&self) -> BulwarkResult<Box<dyn BulwarkRequest>>;
}

/// 请求抽象 trait，提供 HTTP 请求数据访问。
///
/// [借鉴 Sa-Token] 对应 `SaTokenRequest`。
pub trait BulwarkRequest {
    /// 获取请求路径。
    fn path(&self) -> BulwarkResult<String>;

    /// 获取请求方法（GET / POST 等）。
    fn method(&self) -> BulwarkResult<String>;

    /// 获取请求头。
    ///
    /// # 参数
    /// - `name`: 头部字段名。
    ///
    /// # 返回
    /// - `Some(value)`: 头部存在。
    /// - `None`: 头部不存在。
    fn header(&self, name: &str) -> BulwarkResult<Option<String>>;

    /// 获取 Cookie 值。
    ///
    /// # 参数
    /// - `name`: Cookie 名称。
    ///
    /// # 返回
    /// - `Some(value)`: Cookie 存在。
    /// - `None`: Cookie 不存在。
    fn cookie(&self, name: &str) -> BulwarkResult<Option<String>>;

    /// 从请求中提取 Token。
    ///
    /// 提取顺序依据 `BulwarkConfig`：
    /// - 若 `is_read_header` 为 true，从 `Authorization: Bearer <token>` 或自定义 header 提取
    /// - 若 `is_read_cookie` 为 true，从 cookie `token_name` 提取
    /// - 返回第一个找到的 token，若都不存在返回 None
    ///
    /// # 参数
    /// - `config`: 配置，决定从 header 还是 cookie 提取。
    ///
    /// # 返回
    /// - `Some(token)`: 成功提取的 Token 字符串（header 优先于 cookie）。
    /// - `None`: 未在 header 或 cookie 中找到 Token。
    fn get_token(&self, config: &crate::config::BulwarkConfig) -> BulwarkResult<Option<String>>;
}

/// 响应抽象 trait，提供 HTTP 响应数据写入。
///
/// [借鉴 Sa-Token] 对应 `SaTokenResponse`。
pub trait BulwarkResponse {
    /// 设置响应状态码。
    ///
    /// # 参数
    /// - `code`: HTTP 状态码（如 401 未登录、403 无权限）。
    fn set_status(&mut self, code: u16) -> BulwarkResult<()>;

    /// 设置响应头。
    ///
    /// # 参数
    /// - `name`: 头部字段名。
    /// - `value`: 头部字段值。
    fn set_header(&mut self, name: &str, value: &str) -> BulwarkResult<()>;

    /// 设置响应 Cookie（默认带 `HttpOnly; Secure; SameSite=Lax; Path=/` 安全属性）。
    ///
    /// 安全默认：调用此方法不需要任何额外参数即可获得安全属性。
    /// 如需自定义 Secure/SameSite（如 dev HTTP 环境关闭 Secure），使用 `set_cookie_with_config`。
    ///
    /// # 参数
    /// - `name`: Cookie 名称。
    /// - `value`: Cookie 值。
    fn set_cookie(&mut self, name: &str, value: &str) -> BulwarkResult<()> {
        self.set_cookie_with_config(name, value, &crate::config::BulwarkConfig::default_config())
    }

    /// 设置响应 Cookie。
    ///
    /// # 参数
    /// - `name`: Cookie 名称。
    /// - `value`: Cookie 值。
    /// - `config`: 全局配置，读取 `cookie_secure` / `cookie_same_site` 字段。
    fn set_cookie_with_config(
        &mut self,
        name: &str,
        value: &str,
        config: &crate::config::BulwarkConfig,
    ) -> BulwarkResult<()>;
}

/// 存储抽象 trait，提供请求级临时数据存储。
///
/// [借鉴 Sa-Token] 对应 `SaTokenStorage`，
/// 用于在单次请求范围内传递数据（如 trace_id、用户上下文）。
pub trait BulwarkStorage {
    /// 存储键值对。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `value`: 存储值。
    fn set(&mut self, key: &str, value: &str) -> BulwarkResult<()>;

    /// 获取存储值。
    ///
    /// # 参数
    /// - `key`: 存储键。
    ///
    /// # 返回
    /// - `Some(value)`: 键存在。
    /// - `None`: 键不存在。
    fn get(&self, key: &str) -> BulwarkResult<Option<String>>;

    /// 删除存储值。
    ///
    /// # 参数
    /// - `key`: 存储键。
    fn delete(&mut self, key: &str) -> BulwarkResult<()>;
}

// ============================================================================
// axum 适配器（feature = "web-axum"）
// ============================================================================

#[cfg(feature = "web-axum")]
pub mod axum_adapter;

#[cfg(feature = "web-axum")]
pub use axum_adapter::{AxumContext, AxumRequest, AxumResponse, AxumStorage};

// ============================================================================
// actix-web 适配器（feature = "web-actix"）
// ============================================================================

#[cfg(feature = "web-actix")]
pub mod actix_adapter;

#[cfg(feature = "web-actix")]
pub use actix_adapter::{ActixContext, ActixRequest, ActixResponse, ActixStorage};

// ============================================================================
// warp 适配器（feature = "web-warp"）
// ============================================================================

#[cfg(feature = "web-warp")]
pub mod warp_adapter;

#[cfg(feature = "web-warp")]
pub use warp_adapter::{WarpContext, WarpRequest, WarpResponse, WarpStorage};

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Mock 响应实现，用于测试 BulwarkResponse trait 的默认方法。
    struct MockResponse {
        cookies: HashMap<String, String>,
        headers: HashMap<String, String>,
        status: Option<u16>,
    }

    impl MockResponse {
        fn new() -> Self {
            Self {
                cookies: HashMap::new(),
                headers: HashMap::new(),
                status: None,
            }
        }
    }

    impl BulwarkResponse for MockResponse {
        fn set_status(&mut self, code: u16) -> BulwarkResult<()> {
            self.status = Some(code);
            Ok(())
        }

        fn set_header(&mut self, name: &str, value: &str) -> BulwarkResult<()> {
            self.headers.insert(name.to_string(), value.to_string());
            Ok(())
        }

        fn set_cookie_with_config(
            &mut self,
            name: &str,
            value: &str,
            _config: &crate::config::BulwarkConfig,
        ) -> BulwarkResult<()> {
            self.cookies.insert(name.to_string(), value.to_string());
            Ok(())
        }
    }

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
        // set_cookie 默认方法应使用 BulwarkConfig::default_config()
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
}
