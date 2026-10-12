// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Web 安全中间件模块：CORS / CSRF 等请求内容校验，各子模块独立 feature 门控（`web-cors`、`web-csrf`、
//! `web-security-headers`、`web-axum`、`firewall-waf`）；另提供前后端分离模式的 CORS 头部应用函数，
//! 供框架适配器在响应阶段调用。

use crate::context::GarrisonResponse;
use crate::error::GarrisonResult;

/// 前后端分离模式 CORS `Allow-Origin` 头部名。
pub const CORS_ALLOW_ORIGIN: &str = "Access-Control-Allow-Origin";

/// 前后端分离模式 CORS `Allow-Headers` 头部名。
pub const CORS_ALLOW_HEADERS: &str = "Access-Control-Allow-Headers";

/// 前后端分离模式 CORS `Allow-Methods` 头部名。
pub const CORS_ALLOW_METHODS: &str = "Access-Control-Allow-Methods";

/// 前后端分离模式 CORS `Allow-Origin` 回退默认值（`*`），仅在请求无 `Origin` 时使用。
///
/// 正常请求应经 [`apply_frontend_separation_cors_with_origin`] 动态回显 Origin——wildcard `*` +
/// `Authorization` 会被浏览器拒绝（CORS credentials 限制）。
pub const DEFAULT_CORS_ALLOW_ORIGIN: &str = "*";

/// 前后端分离模式 CORS `Allow-Headers` 默认值（含 Authorization 与 Content-Type）。
pub const DEFAULT_CORS_ALLOW_HEADERS: &str = "Authorization, Content-Type";

/// 前后端分离模式 CORS `Allow-Methods` 默认值。
pub const DEFAULT_CORS_ALLOW_METHODS: &str = "GET, POST, PUT, DELETE, OPTIONS";

/// CORS 跨域资源共享中间件模块。
#[cfg(feature = "web-cors")]
pub mod cors;

/// CSRF 跨站请求伪造防护模块。
#[cfg(feature = "web-csrf")]
pub mod csrf;

/// HTTP 安全响应头中间件模块（X-Content-Type-Options / X-Frame-Options / HSTS / Cache-Control）。
#[cfg(feature = "web-security-headers")]
pub mod security_headers;

/// X-Request-ID 请求标识中间件模块（提取 / 生成 / 回传，错误体携带 request_id）。
#[cfg(feature = "web-axum")]
pub mod request_id;

/// axum 框架适配子模块（firewall-waf middleware 等）。
#[cfg(feature = "firewall-waf")]
pub mod axum;

/// 允许列表未配置时的一次性告警（防日志刷屏）。
#[cfg(feature = "web-cors")]
fn warn_missing_allowlist_once() {
    static WARN: std::sync::Once = std::sync::Once::new();
    WARN.call_once(|| {
        tracing::warn!(
            "{}",
            crate::i18n::translate_detail("logs-cors-allowlist-not-configured", &[])
        );
    });
}

/// web-cors feature 未启用时的一次性告警（防日志刷屏）。
#[cfg(not(feature = "web-cors"))]
fn warn_no_cors_feature_once() {
    static WARN: std::sync::Once = std::sync::Once::new();
    WARN.call_once(|| {
        tracing::warn!(
            "{}",
            crate::i18n::translate_detail("logs-cors-feature-disabled", &[])
        );
    });
}

/// 应用前后端分离模式的 CORS 头部（动态回显请求 Origin；`frontend_separation=false` 时不设任何头部）。
///
/// `Some(origin)`：回显请求 Origin（推荐，兼容 credentials）；`web-cors` 启用且
/// `cors_config.allowed_origins` 非空时仅回显命中允许列表的 Origin，未命中不设 `Allow-Origin`
/// （fail-closed）；允许列表为空时保持回显任意 Origin 的旧行为并 warn。
/// `None`：不设 `Allow-Origin`（安全默认，避免 wildcard + credentials 冲突）。
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
        // 动态回显请求 Origin（替代 wildcard `*`，兼容 credentials）；无 Origin 时不设 Allow-Origin。
        if let Some(origin) = request_origin {
            // 允许列表非空时仅回显命中 Origin（fail-closed；cors_config 字段仅 web-cors 下存在）
            #[cfg(feature = "web-cors")]
            {
                let allowed = &config.cors_config.allowed_origins;
                if allowed.is_empty() {
                    warn_missing_allowlist_once();
                } else if !crate::web::cors::origin_matches(origin, allowed) {
                    tracing::debug!(
                        origin = %origin,
                        "{}",
                        crate::i18n::translate_detail("logs-cors-origin-not-allowed", &[])
                    );
                    response.set_header(CORS_ALLOW_HEADERS, DEFAULT_CORS_ALLOW_HEADERS)?;
                    response.set_header(CORS_ALLOW_METHODS, DEFAULT_CORS_ALLOW_METHODS)?;
                    response.set_header("Vary", "Origin")?;
                    return Ok(());
                }
            }
            #[cfg(not(feature = "web-cors"))]
            {
                warn_no_cors_feature_once();
            }
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
    // 无 Origin 上下文：仅设 Allow-Headers/Methods/Vary，Allow-Origin 由调用方用 _with_origin 设置。
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
        assert!(!resp.headers.contains_key(CORS_ALLOW_ORIGIN));
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
            !resp.headers.contains_key(CORS_ALLOW_ORIGIN),
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

    /// frontend_separation=true 时设置 `Vary: Origin`，确保缓存层按 Origin 区分响应。
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
