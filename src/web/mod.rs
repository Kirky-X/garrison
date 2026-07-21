//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Web 安全中间件模块，提供 WAF / CORS / CSRF 等请求内容校验能力。
//!
//! 各子模块独立 feature-gated：
//! - `web-waf`：WAF 请求内容校验（路径/方法/危险字符检测）
//! - `web-cors`：CORS 跨域资源共享中间件
//! - `web-csrf`：CSRF 跨站请求伪造防护（Double-Submit Cookie 模式）
//!
//! 此外，本模块提供前后端分离模式（`frontend_separation`）的 CORS 头部应用函数，
//! 供 Web 框架适配器在响应阶段调用。

use crate::context::GarrisonResponse;
use crate::error::GarrisonResult;

/// 前后端分离模式 CORS `Allow-Origin` 头部名。
pub const CORS_ALLOW_ORIGIN: &str = "Access-Control-Allow-Origin";

/// 前后端分离模式 CORS `Allow-Headers` 头部名。
pub const CORS_ALLOW_HEADERS: &str = "Access-Control-Allow-Headers";

/// 前后端分离模式 CORS `Allow-Methods` 头部名。
pub const CORS_ALLOW_METHODS: &str = "Access-Control-Allow-Methods";

/// 前后端分离模式 CORS `Allow-Origin` 默认值（`*` 允许所有来源）。
pub const DEFAULT_CORS_ALLOW_ORIGIN: &str = "*";

/// 前后端分离模式 CORS `Allow-Headers` 默认值（含 Authorization 与 Content-Type）。
pub const DEFAULT_CORS_ALLOW_HEADERS: &str = "Authorization, Content-Type";

/// 前后端分离模式 CORS `Allow-Methods` 默认值。
pub const DEFAULT_CORS_ALLOW_METHODS: &str = "GET, POST, PUT, DELETE, OPTIONS";

/// WAF 请求内容校验模块。
#[cfg(feature = "web-waf")]
pub mod waf;

/// CORS 跨域资源共享中间件模块。
#[cfg(feature = "web-cors")]
pub mod cors;

/// CSRF 跨站请求伪造防护模块。
#[cfg(feature = "web-csrf")]
pub mod csrf;

/// axum 框架适配子模块（firewall-waf middleware 等）。
#[cfg(feature = "firewall-waf")]
pub mod axum;

/// 应用前后端分离模式的 CORS 头部。
///
/// `frontend_separation=true` 时设置 `Access-Control-Allow-Origin/Headers/Methods` 头部，
/// 允许前端跨域携带 `Authorization` Header 访问后端 API；
/// `frontend_separation=false` 时不设置任何头部（保持原有行为）。
///
/// # 参数
///
/// - `response`: 响应对象，需实现 [`GarrisonResponse`] trait。
/// - `config`: 全局配置，读取 `frontend_separation` 字段。
pub fn apply_frontend_separation_cors<R: GarrisonResponse>(
    response: &mut R,
    config: &crate::config::GarrisonConfig,
) -> GarrisonResult<()> {
    if config.frontend_separation {
        response.set_header(CORS_ALLOW_ORIGIN, DEFAULT_CORS_ALLOW_ORIGIN)?;
        response.set_header(CORS_ALLOW_HEADERS, DEFAULT_CORS_ALLOW_HEADERS)?;
        response.set_header(CORS_ALLOW_METHODS, DEFAULT_CORS_ALLOW_METHODS)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Web 模块测试用的 Mock 响应（仅记录 header 写入，不关心 cookie/status）。
    struct WebMockResponse {
        headers: HashMap<String, String>,
    }

    impl WebMockResponse {
        fn new() -> Self {
            Self {
                headers: HashMap::new(),
            }
        }
    }

    impl GarrisonResponse for WebMockResponse {
        fn set_status(&mut self, _code: u16) -> GarrisonResult<()> {
            Ok(())
        }

        fn set_header(&mut self, name: &str, value: &str) -> GarrisonResult<()> {
            self.headers.insert(name.to_string(), value.to_string());
            Ok(())
        }

        fn set_cookie_with_config(
            &mut self,
            _name: &str,
            _value: &str,
            _config: &crate::config::GarrisonConfig,
        ) -> GarrisonResult<()> {
            Ok(())
        }
    }

    /// 验证 frontend_separation=true 时 apply_frontend_separation_cors 设置 CORS 头。
    #[test]
    fn t011_apply_cors_separation_adds_headers() {
        let mut resp = WebMockResponse::new();
        let mut config = crate::config::GarrisonConfig::default_config();
        config.frontend_separation = true;
        let result = apply_frontend_separation_cors(&mut resp, &config);
        assert!(result.is_ok());
        assert_eq!(
            resp.headers.get(CORS_ALLOW_ORIGIN),
            Some(&DEFAULT_CORS_ALLOW_ORIGIN.to_string())
        );
        assert_eq!(
            resp.headers.get(CORS_ALLOW_HEADERS),
            Some(&DEFAULT_CORS_ALLOW_HEADERS.to_string())
        );
        assert_eq!(
            resp.headers.get(CORS_ALLOW_METHODS),
            Some(&DEFAULT_CORS_ALLOW_METHODS.to_string())
        );
    }

    /// 验证 frontend_separation=false 时 apply_frontend_separation_cors 不设置 CORS 头。
    #[test]
    fn t011_apply_cors_no_separation_no_headers() {
        let mut resp = WebMockResponse::new();
        let mut config = crate::config::GarrisonConfig::default_config();
        config.frontend_separation = false;
        let result = apply_frontend_separation_cors(&mut resp, &config);
        assert!(result.is_ok());
        assert!(resp.headers.is_empty());
    }
}
