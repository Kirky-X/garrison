//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! 上下文模块，提供请求 / 响应 / 存储上下文抽象。
//!
//! 对应 上下文抽象层，
//! 通过 trait 隔离 Web 框架差异，实现框架无关的鉴权逻辑。
//!
//! ## 架构
//!
//! - `GarrisonContext`：上下文入口，提供 request/response/storage 访问
//! - `GarrisonRequest`：HTTP 请求抽象（path/method/header/cookie/get_token）
//! - `GarrisonResponse`：HTTP 响应抽象（set_status/set_header/set_cookie）
//! - `GarrisonStorage`：请求级临时存储（set/get/delete，请求结束清理）
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

use crate::error::{GarrisonError, GarrisonResult};

// ============================================================================
// 多租户隔离上下文
// ============================================================================

pub mod tenant;

// ============================================================================
// Token 提取公共函数（供 web 框架适配器与 context 适配器共用，无 feature gate）
// ============================================================================

pub mod token_extract;

pub use token_extract::{
    extract_token_from_headers, extract_token_from_request_parts, is_body_token_allowed_method,
    strip_bearer_prefix, HeaderLookup,
};

// ============================================================================
// 登录主体
// ============================================================================

/// 当前请求的登录主体。
///
/// 携带从 token 解析出的 `login_id`，由各 web 框架的 extractor
/// （`web_actix::extractor::GarrisonPrincipal` / `web_warp::extractor::GarrisonPrincipal`）
/// 从 `Authorization: Bearer <token>` header 提取并填充。
///
/// # 字段
///
/// - `login_id`: 当前登录用户 ID，从 token-session 映射解析得到。
///
/// # 使用示例
///
/// ```ignore
/// use garrison::context::GarrisonPrincipal;
///
/// fn handler(principal: GarrisonPrincipal) -> String {
/// format!("login_id = {}", principal.login_id)
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarrisonPrincipal {
    /// 当前登录用户 ID（从 token-session 映射解析）。
    pub login_id: String,
}

/// 上下文 trait，提供请求访问入口。
///
/// 对应 `SaTokenContext`，
/// 各 Web 框架适配需实现此 trait。
///
/// # 设计
///
/// 仅暴露 `request()` 方法获取请求对象。
/// 响应数据写入由具体适配器（如 `AxumContext::raw_response_mut()` / `into_response()`）提供，
/// 避免 trait 方法返回新实例破坏状态共享。
pub trait GarrisonContext {
    /// 获取当前请求对象。
    fn request(&self) -> GarrisonResult<Box<dyn GarrisonRequest>>;
}

/// 请求抽象 trait，提供 HTTP 请求数据访问。
///
/// 对应 `SaTokenRequest`。
pub trait GarrisonRequest {
    /// 获取请求路径。
    fn path(&self) -> GarrisonResult<String>;

    /// 获取请求方法（GET / POST 等）。
    fn method(&self) -> GarrisonResult<String>;

    /// 获取请求头。
    ///
    /// # 参数
    /// - `name`: 头部字段名。
    ///
    /// # 返回
    /// - `Some(value)`: 头部存在。
    /// - `None`: 头部不存在。
    fn header(&self, name: &str) -> GarrisonResult<Option<String>>;

    /// 获取 Cookie 值。
    ///
    /// # 参数
    /// - `name`: Cookie 名称。
    ///
    /// # 返回
    /// - `Some(value)`: Cookie 存在。
    /// - `None`: Cookie 不存在。
    fn cookie(&self, name: &str) -> GarrisonResult<Option<String>>;

    /// 从请求中提取 Token。
    ///
    /// 提取顺序依据 `GarrisonConfig`：
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
    fn get_token(&self, config: &crate::config::GarrisonConfig) -> GarrisonResult<Option<String>>;
}

/// 响应抽象 trait，提供 HTTP 响应数据写入。
///
/// 对应 `SaTokenResponse`。
pub trait GarrisonResponse {
    /// 设置响应状态码。
    ///
    /// # 参数
    /// - `code`: HTTP 状态码（如 401 未登录、403 无权限）。
    fn set_status(&mut self, code: u16) -> GarrisonResult<()>;

    /// 设置响应头。
    ///
    /// # 参数
    /// - `name`: 头部字段名。
    /// - `value`: 头部字段值。
    fn set_header(&mut self, name: &str, value: &str) -> GarrisonResult<()>;

    /// 设置响应 Cookie（默认带 `HttpOnly; Secure; SameSite=Lax; Path=/` 安全属性）。
    ///
    /// 安全默认：调用此方法不需要任何额外参数即可获得安全属性。
    /// 如需自定义 Secure/SameSite（如 dev HTTP 环境关闭 Secure），使用 `set_cookie_with_config`。
    ///
    /// # 前后端分离模式
    ///
    /// 本便捷方法无 `config` 参数，`frontend_separation` 检查基于
    /// `GarrisonConfig::default_config()`（对齐 [`GarrisonResponse::set_cookie_with_frontend_check`]）。
    /// 需要 per-request 配置时，请使用
    /// `set_cookie_with_frontend_check(name, value, &config)`。
    ///
    /// # 参数
    /// - `name`: Cookie 名称。
    /// - `value`: Cookie 值。
    fn set_cookie(&mut self, name: &str, value: &str) -> GarrisonResult<()> {
        self.set_cookie_with_frontend_check(
            name,
            value,
            &crate::config::GarrisonConfig::default_config(),
        )
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
        config: &crate::config::GarrisonConfig,
    ) -> GarrisonResult<()>;

    /// 设置响应 Cookie（受 `frontend_separation` 控制）。
    ///
    /// 前后端分离模式（`frontend_separation=true`）跳过 Cookie 设置，直接返回 `Ok(())`；
    /// 否则委托给 `set_cookie_with_config` 保持原有行为。
    ///
    /// # 参数
    ///
    /// - `name`: Cookie 名称。
    /// - `value`: Cookie 值。
    /// - `config`: 全局配置，读取 `frontend_separation` 字段。
    fn set_cookie_with_frontend_check(
        &mut self,
        name: &str,
        value: &str,
        config: &crate::config::GarrisonConfig,
    ) -> GarrisonResult<()> {
        if config.frontend_separation {
            return Ok(());
        }
        self.set_cookie_with_config(name, value, config)
    }
}

/// 存储抽象 trait，提供请求级临时数据存储。
///
/// 对应 `SaTokenStorage`，
/// 用于在单次请求范围内传递数据（如 trace_id、用户上下文）。
pub trait GarrisonStorage {
    /// 存储键值对。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `value`: 存储值。
    fn set(&mut self, key: &str, value: &str) -> GarrisonResult<()>;

    /// 获取存储值。
    ///
    /// # 参数
    /// - `key`: 存储键。
    ///
    /// # 返回
    /// - `Some(value)`: 键存在。
    /// - `None`: 键不存在。
    fn get(&self, key: &str) -> GarrisonResult<Option<String>>;

    /// 删除存储值。
    ///
    /// # 参数
    /// - `key`: 存储键。
    fn delete(&mut self, key: &str) -> GarrisonResult<()>;
}

// ============================================================================
// 前后端分离模式辅助函数（实现迁移至 helpers.rs）
// ============================================================================

mod helpers;
pub use helpers::{effective_is_read_cookie, effective_is_read_header};

// ============================================================================
// Set-Cookie 注入防护（供各框架适配器共用）
// ============================================================================

/// 校验 Set-Cookie 的 name/value 合法性，防止 Cookie 头注入。
///
/// `Set-Cookie` 头按 `name=value; attr1; attr2` 拼接：若 name/value 含 `;`、
/// 控制字符或空格等分隔符，攻击者可注入 `Domain=` / `HttpOnly` 移除等恶意属性，
/// 或破坏头部结构。本函数不引入 percent-encoding 依赖，直接拒绝非法输入。
///
/// # 规则
///
/// - `name`：非空，且仅允许 RFC 6265 `token` 字符（字母数字与 `!#$%&'*+-.^_`|~`），
/// 拒绝 `=`、`;`、空格与控制字符。
/// - `value`：允许空串（用于清除 cookie），但拒绝控制字符（< 0x21 或 0x7F）、
///   空格、`;`、`,`、`\`、`"`。
///
/// # 错误
///
/// - `GarrisonError::Context`：name 或 value 含非法字符时返回。
#[cfg_attr(
    not(any(feature = "web-axum", feature = "web-actix", feature = "web-warp")),
    allow(dead_code)
)]
pub(crate) fn validate_cookie_name_value(name: &str, value: &str) -> GarrisonResult<()> {
    let name_ok = !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        });
    if !name_ok {
        return Err(GarrisonError::Context(format!(
            "ctx-invalid-cookie-name::{name}"
        )));
    }
    // value：拒绝控制字符/空格（< 0x21、0x7F）与 RFC 6265 排除字符 ; , \ "
    let value_ok = !value
        .bytes()
        .any(|b| b < 0x21 || b == 0x7F || matches!(b, b';' | b',' | b'\\' | b'"'));
    if !value_ok {
        return Err(GarrisonError::Context(
            "ctx-invalid-cookie-value::cookie value must not contain control chars, space, ';', ',', '\\\\' or '\"'".to_string(),
        ));
    }
    Ok(())
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

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
