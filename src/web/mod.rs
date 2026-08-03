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

/// 前后端分离模式 CORS `Allow-Origin` 回退默认值。
///
/// 仅在请求无 `Origin` header 时作为回退值使用。
/// 正常 CORS 请求应通过 [`apply_frontend_separation_cors_with_origin`] 动态回显请求 Origin，
/// 因为 wildcard `*` + `Authorization` header 会被浏览器拒绝（CORS credentials 限制）。
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

/// 应用前后端分离模式的 CORS 头部（动态回显请求 Origin）。
///
/// `frontend_separation=true` 时设置 `Access-Control-Allow-Origin/Headers/Methods` 头部。
/// 根据 `request_origin` 参数决定 `Allow-Origin` 值：
///
/// - `Some(origin)`：回显请求的 `Origin`（推荐，兼容 credentials）。
/// - `None`：不设置 `Allow-Origin` header（安全默认，避免 wildcard + credentials 冲突）。
///
/// `frontend_separation=false` 时不设置任何头部。
///
/// # 参数
///
/// - `response`: 响应对象，需实现 [`GarrisonResponse`] trait。
/// - `config`: 全局配置，读取 `frontend_separation` 字段。
/// - `request_origin`: 请求的 `Origin` header 值（从请求上下文提取）。
///
/// # 使用
///
/// Web 框架适配器应在响应阶段调用此函数，传入从请求中提取的 Origin：
/// ```ignore
/// let origin = request.headers().get("Origin").and_then(|v| v.to_str().ok());
/// apply_frontend_separation_cors_with_origin(&mut response, &config, origin)?;
/// ```
pub fn apply_frontend_separation_cors_with_origin<R: GarrisonResponse>(
    response: &mut R,
    config: &crate::config::GarrisonConfig,
    request_origin: Option<&str>,
) -> GarrisonResult<()> {
    if config.frontend_separation {
        // 动态回显请求 Origin（替代 wildcard `*`），兼容 credentials 场景。
        // 无 Origin 时不设置 Allow-Origin（安全默认，非 CORS 请求无需此 header）。
        if let Some(origin) = request_origin {
            response.set_header(CORS_ALLOW_ORIGIN, origin)?;
        }
        response.set_header(CORS_ALLOW_HEADERS, DEFAULT_CORS_ALLOW_HEADERS)?;
        response.set_header(CORS_ALLOW_METHODS, DEFAULT_CORS_ALLOW_METHODS)?;
        // 添加 Vary: Origin 确保缓存层按 Origin 区分响应
        response.set_header("Vary", "Origin")?;
    }
    Ok(())
}

/// 应用前后端分离模式的 CORS 头部（无 Origin 上下文时的简化版本）。
///
/// 不设置 `Allow-Origin` header（避免 wildcard `*` + `Authorization` 被浏览器拒绝）。
/// 若需设置 `Allow-Origin`，请使用 [`apply_frontend_separation_cors_with_origin`] 并传入请求 Origin。
///
/// `frontend_separation=false` 时不设置任何头部。
pub fn apply_frontend_separation_cors<R: GarrisonResponse>(
    response: &mut R,
    config: &crate::config::GarrisonConfig,
) -> GarrisonResult<()> {
    // 无请求 Origin 上下文，仅设置 Allow-Headers/Methods 和 Vary。
    // Allow-Origin 需调用方通过 apply_frontend_separation_cors_with_origin 设置。
    if config.frontend_separation {
        response.set_header(CORS_ALLOW_HEADERS, DEFAULT_CORS_ALLOW_HEADERS)?;
        response.set_header(CORS_ALLOW_METHODS, DEFAULT_CORS_ALLOW_METHODS)?;
        response.set_header("Vary", "Origin")?;
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

    /// 验证 frontend_separation=true 时 apply_frontend_separation_cors 设置 CORS 头（不含 Allow-Origin）。
    #[test]
    fn t011_apply_cors_separation_adds_headers() {
        let mut resp = WebMockResponse::new();
        let mut config = crate::config::GarrisonConfig::default_config();
        config.frontend_separation = true;
        let result = apply_frontend_separation_cors(&mut resp, &config);
        assert!(result.is_ok());
        // 无 Origin 上下文时不设置 Allow-Origin（避免 wildcard）
        assert!(resp.headers.get(CORS_ALLOW_ORIGIN).is_none());
        assert_eq!(
            resp.headers.get(CORS_ALLOW_HEADERS),
            Some(&DEFAULT_CORS_ALLOW_HEADERS.to_string())
        );
        assert_eq!(
            resp.headers.get(CORS_ALLOW_METHODS),
            Some(&DEFAULT_CORS_ALLOW_METHODS.to_string())
        );
    }

    /// 验证 `apply_frontend_separation_cors_with_origin` 动态回显请求 Origin。
    #[test]
    fn cors_with_origin_echoes_request_origin() {
        let mut resp = WebMockResponse::new();
        let mut config = crate::config::GarrisonConfig::default_config();
        config.frontend_separation = true;
        let result = apply_frontend_separation_cors_with_origin(
            &mut resp,
            &config,
            Some("https://example.com"),
        );
        assert!(result.is_ok());
        assert_eq!(
            resp.headers.get(CORS_ALLOW_ORIGIN),
            Some(&"https://example.com".to_string()),
            "应回显请求 Origin 而非 wildcard *"
        );
        assert_eq!(resp.headers.get("Vary"), Some(&"Origin".to_string()));
    }

    /// 验证 `apply_frontend_separation_cors_with_origin` 无 Origin 时不设置 Allow-Origin。
    #[test]
    fn cors_without_origin_skips_allow_origin() {
        let mut resp = WebMockResponse::new();
        let mut config = crate::config::GarrisonConfig::default_config();
        config.frontend_separation = true;
        let result = apply_frontend_separation_cors_with_origin(&mut resp, &config, None);
        assert!(result.is_ok());
        assert!(
            resp.headers.get(CORS_ALLOW_ORIGIN).is_none(),
            "无 Origin 时不应设置 Allow-Origin"
        );
        // Allow-Headers/Methods 和 Vary 仍应设置
        assert_eq!(
            resp.headers.get(CORS_ALLOW_HEADERS),
            Some(&DEFAULT_CORS_ALLOW_HEADERS.to_string())
        );
    }

    /// 验证不同 Origin 回显不同值（防止缓存混用）。
    #[test]
    fn cors_with_different_origins_echoes_differently() {
        let mut config = crate::config::GarrisonConfig::default_config();
        config.frontend_separation = true;

        let mut resp1 = WebMockResponse::new();
        apply_frontend_separation_cors_with_origin(&mut resp1, &config, Some("https://a.com"))
            .unwrap();
        let mut resp2 = WebMockResponse::new();
        apply_frontend_separation_cors_with_origin(&mut resp2, &config, Some("https://b.com"))
            .unwrap();

        assert_eq!(
            resp1.headers.get(CORS_ALLOW_ORIGIN),
            Some(&"https://a.com".to_string())
        );
        assert_eq!(
            resp2.headers.get(CORS_ALLOW_ORIGIN),
            Some(&"https://b.com".to_string())
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

    /// CRITICAL-8: frontend_separation=true 时应设置 `Vary: Origin` header。
    ///
    /// 确保缓存层按 Origin 区分响应，避免不同 Origin 的响应被缓存混用。
    #[test]
    fn cors_sets_vary_origin_header() {
        let mut resp = WebMockResponse::new();
        let mut config = crate::config::GarrisonConfig::default_config();
        config.frontend_separation = true;
        let result = apply_frontend_separation_cors(&mut resp, &config);
        assert!(result.is_ok());
        assert_eq!(
            resp.headers.get("Vary"),
            Some(&"Origin".to_string()),
            "应设置 Vary: Origin 确保缓存正确性"
        );
    }
}
