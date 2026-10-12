// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 上下文模块，提供请求 / 响应 / 存储上下文抽象（对应 SaToken 上下文抽象层）。
//!
//! 经 trait 隔离 Web 框架差异，实现框架无关的鉴权逻辑：`GarrisonContext` 为入口，
//! `GarrisonRequest` / `GarrisonResponse` / `GarrisonStorage` 分别抽象 HTTP 请求、
//! 响应写入与请求级临时存储。
//!
//! axum / actix-web / warp 适配器分别在 `web-axum` / `web-actix` / `web-warp` feature 下提供。

use crate::error::{GarrisonError, GarrisonResult};

// 多租户隔离上下文
pub mod tenant;

// Token 提取公共函数（供 web 框架适配器与 context 适配器共用，无 feature gate）
pub mod token_extract;

// 请求标识（request id）task-local 上下文（无 feature gate）
pub mod request_id;

pub use request_id::{
    current, generate, inject_request_id_into_error_body, is_valid_inbound_request_id,
    propagate_or_generate, scope, RequestId, MAX_INBOUND_LEN, REQUEST_ID_BODY_FIELD,
    REQUEST_ID_HEADER, RETRY_AFTER_HEADER,
};

pub use token_extract::{
    extract_token_from_headers, extract_token_from_request_parts, is_body_token_allowed_method,
    strip_bearer_prefix, HeaderLookup,
};

// Set-Cookie 单一构建点（CookieType + 安全不变式）
pub mod cookie;

pub use cookie::{build_set_cookie_value, token_cookie_name, CookiePath, CookieScope, CookieType};

// 登录主体
/// 当前请求的登录主体。
///
/// 携带从 token 解析出的 `login_id`，由各 web 框架的 extractor
/// （`web_actix::extractor::GarrisonPrincipal` / `web_warp::extractor::GarrisonPrincipal`）
/// 从 `Authorization: Bearer <token>` header 提取并填充。
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

/// 上下文 trait，提供请求访问入口（对应 `SaTokenContext`），各 Web 框架适配需实现此 trait。
///
/// 仅暴露 `request()` 方法获取请求对象；响应数据写入由具体适配器
/// （如 `AxumContext::raw_response_mut()` / `into_response()`）提供，避免 trait 方法返回新实例破坏状态共享。
pub trait GarrisonContext {
    /// 获取当前请求对象。
    fn request(&self) -> GarrisonResult<Box<dyn GarrisonRequest>>;
}

/// 请求抽象 trait，提供 HTTP 请求数据访问（对应 `SaTokenRequest`）。
pub trait GarrisonRequest {
    /// 获取请求路径。
    fn path(&self) -> GarrisonResult<String>;

    /// 获取请求方法（GET / POST 等）。
    fn method(&self) -> GarrisonResult<String>;

    /// 获取请求头；头部不存在返回 `None`。
    fn header(&self, name: &str) -> GarrisonResult<Option<String>>;

    /// 获取 Cookie 值；Cookie 不存在返回 `None`。
    fn cookie(&self, name: &str) -> GarrisonResult<Option<String>>;

    /// 从请求中提取 Token。
    ///
    /// 提取顺序依据 `GarrisonConfig`：`is_read_header` 为 true 时从
    /// `Authorization: Bearer <token>` 或自定义 header 提取，`is_read_cookie` 为 true 时
    /// 从 cookie `token_name` 提取；返回首个命中的 token，header 优先于 cookie，均无则 `None`。
    fn get_token(&self, config: &crate::config::GarrisonConfig) -> GarrisonResult<Option<String>>;
}

/// 响应抽象 trait，提供 HTTP 响应数据写入（对应 `SaTokenResponse`）。
pub trait GarrisonResponse {
    /// 设置响应状态码（如 401 未登录、403 无权限）。
    fn set_status(&mut self, code: u16) -> GarrisonResult<()>;

    /// 设置响应头。
    fn set_header(&mut self, name: &str, value: &str) -> GarrisonResult<()>;

    /// 设置响应 Cookie（默认带 `HttpOnly; Secure; SameSite=Lax; Path=/` 安全属性，无需额外参数）。
    ///
    /// 本便捷方法无 `config` 参数，`frontend_separation` 检查基于 `GarrisonConfig::default_config()`
    /// （对齐 [`GarrisonResponse::set_cookie_with_frontend_check`]）；需要 per-request 配置时改用
    /// `set_cookie_with_frontend_check(name, value, &config)`。
    ///
    /// **写读错配警告**：兜底走共享默认配置（`cookie_secure=true`，进程级缓存，确定性可复用）。
    /// 若业务配置为 `cookie_secure=false`，production 构建下本方法按默认配置写入 `__Host-` 前缀
    /// cookie 名，而读侧按业务配置解析裸名，客户端回传的 cookie 读不到。生产代码必须用
    /// `set_cookie_with_config` 传入真实配置，不得依赖本方法兜底。
    fn set_cookie(&mut self, name: &str, value: &str) -> GarrisonResult<()> {
        self.set_cookie_with_frontend_check(name, value, helpers::shared_default_config())
    }

    /// 设置响应 Cookie，读取 `config.cookie_secure` / `cookie_same_site`。
    ///
    /// 经 Set-Cookie 单一构建点（[`CookieType::session`] + [`build_set_cookie_value`]）产出：
    /// 注入防护、SameSite 白名单 fail-fast、None→Lax 降级与 production 前缀全部在构建点强制，
    /// 实现方无需自行拼接属性串。
    fn set_cookie_with_config(
        &mut self,
        name: &str,
        value: &str,
        config: &crate::config::GarrisonConfig,
    ) -> GarrisonResult<()> {
        let cookie = CookieType::session(name, config)?;
        let cookie_value = build_set_cookie_value(&cookie, value, config.cookie_secure)?;
        self.set_header("Set-Cookie", &cookie_value)
    }

    /// 设置响应 Cookie（受 `frontend_separation` 控制）：`true` 时跳过设置直接返回 `Ok(())`，
    /// 否则委托 `set_cookie_with_config`。
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

/// 存储抽象 trait，提供请求级临时数据存储（对应 `SaTokenStorage`）。
///
/// 用于单次请求范围内传递数据（如 trace_id、用户上下文）。
pub trait GarrisonStorage {
    /// 存储键值对。
    fn set(&mut self, key: &str, value: &str) -> GarrisonResult<()>;

    /// 获取存储值；键不存在返回 `None`。
    fn get(&self, key: &str) -> GarrisonResult<Option<String>>;

    /// 删除存储值。
    fn delete(&mut self, key: &str) -> GarrisonResult<()>;
}

// 前后端分离模式辅助函数
mod helpers;
pub use helpers::{effective_is_read_cookie, effective_is_read_header};

// Set-Cookie 注入防护（供各框架适配器共用）
/// 校验 Set-Cookie 的 name/value 合法性，防止 Cookie 头注入。
///
/// `Set-Cookie` 按 `name=value; attr1; attr2` 拼接：name/value 含 `;`、控制字符或空格等
/// 分隔符时，攻击者可注入 `Domain=` / 移除 `HttpOnly` 等恶意属性或破坏头部结构。
/// 规则：`name` 非空且仅允许 RFC 6265 `token` 字符，拒绝 `=`、`;`、空格与控制字符；
/// `value` 允许空串（用于清除 cookie），但拒绝控制字符（< 0x21 或 0x7F）、空格、`;`、`,`、`\`、`"`。
/// 不引入 percent-encoding 依赖，非法输入直接返回 `GarrisonError::Context`。
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

#[cfg(feature = "web-axum")]
pub mod axum_adapter;

#[cfg(feature = "web-axum")]
pub use axum_adapter::{AxumContext, AxumRequest, AxumResponse, AxumStorage};

#[cfg(feature = "web-actix")]
pub mod actix_adapter;

#[cfg(feature = "web-actix")]
pub use actix_adapter::{ActixContext, ActixRequest, ActixResponse, ActixStorage};

#[cfg(feature = "web-warp")]
pub mod warp_adapter;

#[cfg(feature = "web-warp")]
pub use warp_adapter::{WarpContext, WarpRequest, WarpResponse, WarpStorage};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
