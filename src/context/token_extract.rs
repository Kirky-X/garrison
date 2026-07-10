//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Token 提取公共模块。
//!
//! 提供 `strip_bearer_prefix` 和 `extract_token_from_headers` 两个函数，
//! 供 web 框架适配器（`web_actix` / `web_warp`）和 context 适配器
//! （`axum_adapter` / `actix_adapter` / `warp_adapter`）共用，
//! 消除跨文件重复实现（Rule 8：先读再写，不重复造轮子）。
//!
//! ## 设计
//!
//! - `strip_bearer_prefix`：大小写不敏感地剥离 `Bearer ` 前缀（RFC 7235）
//! - `extract_token_from_headers`：依据 `BulwarkConfig` 从 `http::HeaderMap` 提取 token
//!   （Authorization: Bearer → 自定义 token_name header → cookie）
//!
//! `http` crate 是必需依赖（Cargo.toml L43），故本模块无需 feature gate。
//! `warp::http::HeaderMap` / `axum::http::HeaderMap` 是 `http::HeaderMap` 的 re-export，
//! 可直接传入本模块函数。`actix_web::http::header::HeaderMap` 是 `actix_http::header::HeaderMap`
//! （独立类型，非 `http::HeaderMap` 的 re-export），通过 [`HeaderLookup`] trait 适配。

use crate::config::BulwarkConfig;
use crate::error::BulwarkError;
use http::HeaderMap;

// ============================================================================
// HeaderLookup trait：抽象 HeaderMap 类型差异
// ============================================================================

/// Header 查找抽象 trait，用于 `extract_token_from_headers` 泛型约束。
///
/// **为什么需要这个 trait**：`http::HeaderMap`（v1.x）和 `actix_http::header::HeaderMap`
/// 是两个不同的类型。actix-web 4.x 依赖 `http` v0.2，而 bulwark 依赖 `http` v1.x，
/// 两者的 `HeaderName` / `HeaderValue` 也是不同类型。本 trait 用纯字符串接口
/// (`&str` → `Option<&str>`) 彻底规避版本冲突，使 `extract_token_from_headers`
/// 可同时接受两种 HeaderMap。
///
/// `http::HeaderMap` 的实现在本模块中提供；`actix_web::http::header::HeaderMap`
/// 的实现在 `web_actix/mod.rs` 中提供（需要 `web-actix` feature）。
pub trait HeaderLookup {
    /// 按 header name（小写字符串）查找值，返回 header 值的字符串切片。
    fn get_header(&self, name: &str) -> Option<&str>;
}

impl HeaderLookup for HeaderMap {
    fn get_header(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|v| v.to_str().ok())
    }
}

// ============================================================================
// 公共函数
// ============================================================================

/// 大小写不敏感地剥离 `Bearer ` 前缀（RFC 7235）。
///
/// 支持 `Bearer xxx`、`bearer xxx`、`BEARER xxx` 等任意大小写组合。
///
/// # 参数
/// - `auth_str`: Authorization header 值（如 `"Bearer my_token"`）。
///
/// # 返回
/// - `Some(token)`: 成功剥离前缀后的 token 字符串切片。
/// - `None`: 前缀不匹配或字符串过短。
pub fn strip_bearer_prefix(auth_str: &str) -> Option<&str> {
    let prefix = "bearer ";
    // 用 get(..n) 而非 auth_str[..n]：当 n 落在多字节 UTF-8 字符中间时
    // get 返回 None（而非 panic），避免恶意非 ASCII header 触发 DoS（T117）。
    let head = auth_str.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        Some(&auth_str[prefix.len()..])
    } else {
        None
    }
}

/// 从 `HeaderMap` 提取 token。
///
/// 提取顺序：
/// 1. `Authorization: Bearer <token>`（仅当 `is_read_header` 为 true）
/// 2. 自定义 `token_name` header（仅当 `is_read_header` 为 true）
/// 3. `Cookie: token_name=<token>`（仅当 `is_read_cookie` 为 true）
///
/// 返回第一个找到的 token，若都不存在返回 `Ok(None)`。
///
/// # 泛型参数
///
/// 泛型 `H: HeaderLookup` 使本函数可同时接受 `http::HeaderMap`（warp/axum 使用）
/// 和 `actix_http::header::HeaderMap`（actix-web 使用）。两种 HeaderMap 是不同的类型，
/// 通过 [`HeaderLookup`] trait 统一抽象。
///
/// # 参数
/// - `headers`: 任何实现 `HeaderLookup` 的 header 容器。
/// - `config`: 全局配置，决定从 header 还是 cookie 提取。
pub fn extract_token_from_headers<H: HeaderLookup>(
    headers: &H,
    config: &BulwarkConfig,
) -> Result<Option<String>, BulwarkError> {
    if config.is_read_header {
        // 1. Authorization: Bearer <token>
        if let Some(auth) = headers.get_header("authorization") {
            if let Some(token) = strip_bearer_prefix(auth) {
                return Ok(Some(token.to_string()));
            }
        }
        // 2. 自定义 token_name header
        if let Some(token) = headers.get_header(&config.token_name) {
            return Ok(Some(token.to_string()));
        }
    }
    if config.is_read_cookie {
        // 3. Cookie: token_name=<token>
        let cookie_header = headers.get_header("cookie").unwrap_or("");
        if !cookie_header.is_empty() {
            for cookie in cookie_header.split(';') {
                let cookie = cookie.trim();
                if let Some(eq_pos) = cookie.find('=') {
                    let (k, v) = cookie.split_at(eq_pos);
                    if k == config.token_name {
                        return Ok(Some(v[1..].to_string()));
                    }
                }
            }
        }
    }
    Ok(None)
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use http::header;
    use http::HeaderValue;

    // ========================================================================
    // strip_bearer_prefix 测试
    // ========================================================================

    /// `Bearer ` 前缀标准大小写。
    #[test]
    fn strip_bearer_prefix_standard() {
        assert_eq!(strip_bearer_prefix("Bearer my_token"), Some("my_token"));
    }

    /// `bearer ` 前缀小写。
    #[test]
    fn strip_bearer_prefix_lowercase() {
        assert_eq!(strip_bearer_prefix("bearer my_token"), Some("my_token"));
    }

    /// `BEARER ` 前缀大写。
    #[test]
    fn strip_bearer_prefix_uppercase() {
        assert_eq!(strip_bearer_prefix("BEARER my_token"), Some("my_token"));
    }

    /// `BeArEr ` 混合大小写。
    #[test]
    fn strip_bearer_prefix_mixed_case() {
        assert_eq!(strip_bearer_prefix("BeArEr my_token"), Some("my_token"));
    }

    /// 无 Bearer 前缀返回 None。
    #[test]
    fn strip_bearer_prefix_no_prefix() {
        assert_eq!(strip_bearer_prefix("my_token"), None);
        assert_eq!(strip_bearer_prefix("Basic abc123"), None);
    }

    /// 空字符串返回 None。
    #[test]
    fn strip_bearer_prefix_empty() {
        assert_eq!(strip_bearer_prefix(""), None);
    }

    /// 字符串短于 `"bearer "` 返回 None。
    #[test]
    fn strip_bearer_prefix_shorter_than_prefix() {
        assert_eq!(strip_bearer_prefix("Bear"), None);
        assert_eq!(strip_bearer_prefix("bearer"), None);
    }

    /// 多字节 UTF-8 header 值不应 panic（边界安全，T117 回归测试）。
    ///
    /// 构造 4 个 `é`（每个 2 字节，共 8 字节），`prefix.len()=7` 落在
    /// 最后一个 `é` 中间（字节 7 是 0xA9，非字符起始边界）。
    /// 修复前：`auth_str[..prefix.len()]` 触发 panic（byte index 7 is not a char boundary），
    /// 攻击者可发送非 ASCII Authorization header 远程 DoS。
    /// 修复后：`get(..prefix.len())` 返回 None，函数返回 None。
    #[test]
    fn strip_bearer_prefix_multibyte_no_panic() {
        let auth_str = "éééé"; // 0xC3 0xA9 × 4 = 8 字节
        assert_eq!(strip_bearer_prefix(auth_str), None);
    }

    /// 仅前缀无 token 返回空切片。
    #[test]
    fn strip_bearer_prefix_only_prefix() {
        assert_eq!(strip_bearer_prefix("Bearer "), Some(""));
    }

    // ========================================================================
    // extract_token_from_headers 测试
    // ========================================================================

    /// 从 Authorization: Bearer 提取 token。
    #[test]
    fn extract_token_from_bearer_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my_token_123"),
        );
        let config = BulwarkConfig::default_config();
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("my_token_123".to_string()));
    }

    /// Bearer 前缀大小写不敏感（RFC 7235）。
    #[test]
    fn extract_token_bearer_case_insensitive() {
        let config = BulwarkConfig::default_config();
        for prefix in &["Bearer", "bearer", "BEARER", "BeArEr"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("{} tok_{}", prefix, prefix)).unwrap(),
            );
            let token = extract_token_from_headers(&headers, &config).unwrap();
            assert_eq!(
                token,
                Some(format!("tok_{}", prefix)),
                "前缀 '{}' 应能提取 token",
                prefix
            );
        }
    }

    /// 从自定义 token_name header 提取 token（非 Authorization）。
    #[test]
    fn extract_token_from_custom_token_name_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "bulwark_token",
            HeaderValue::from_static("custom_header_tok"),
        );
        let config = BulwarkConfig::default_config();
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("custom_header_tok".to_string()));
    }

    /// 从 cookie 提取 token。
    #[test]
    fn extract_token_from_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("bulwark_token=cookie_tok_456"),
        );
        let config = BulwarkConfig::default_config();
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("cookie_tok_456".to_string()));
    }

    /// 无 token 时返回 None。
    #[test]
    fn extract_token_returns_none_when_missing() {
        let headers = HeaderMap::new();
        let config = BulwarkConfig::default_config();
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, None);
    }

    /// Authorization Bearer 优先级高于 cookie。
    #[test]
    fn extract_token_bearer_priority_over_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header_tok"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("bulwark_token=cookie_tok"),
        );
        let config = BulwarkConfig::default_config();
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("header_tok".to_string()));
    }

    /// 自定义 token_name header 优先级高于 cookie。
    #[test]
    fn extract_token_custom_header_priority_over_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "bulwark_token",
            HeaderValue::from_static("custom_header_tok"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("bulwark_token=cookie_tok"),
        );
        let config = BulwarkConfig::default_config();
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("custom_header_tok".to_string()));
    }

    /// is_read_header=false 时不从 header 提取，但仍可从 cookie 提取。
    #[test]
    fn extract_token_skips_header_when_disabled() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header_tok"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("bulwark_token=cookie_tok"),
        );
        let mut config = BulwarkConfig::default_config();
        config.is_read_header = false;
        // header 关闭，应走 cookie 路径
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("cookie_tok".to_string()));
    }

    /// is_read_cookie=false 时不从 cookie 提取，但仍可从 header 提取。
    #[test]
    fn extract_token_skips_cookie_when_disabled() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header_tok"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("bulwark_token=cookie_tok"),
        );
        let mut config = BulwarkConfig::default_config();
        config.is_read_cookie = false;
        // cookie 关闭，应走 header 路径
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("header_tok".to_string()));
    }

    /// is_read_header=false + is_read_cookie=false 时返回 None。
    #[test]
    fn extract_token_returns_none_when_both_disabled() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header_tok"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("bulwark_token=cookie_tok"),
        );
        let mut config = BulwarkConfig::default_config();
        config.is_read_header = false;
        config.is_read_cookie = false;
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, None);
    }

    /// Cookie 中有多项时正确提取目标 token_name。
    #[test]
    fn extract_token_from_cookie_with_multiple_pairs() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("session=abc; bulwark_token=target_tok; other=val"),
        );
        let config = BulwarkConfig::default_config();
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("target_tok".to_string()));
    }

    /// Authorization header 存在但无 Bearer 前缀时，回退到自定义 header / cookie。
    #[test]
    fn extract_token_falls_back_when_no_bearer_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic abc123"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("bulwark_token=cookie_tok"),
        );
        let config = BulwarkConfig::default_config();
        // Authorization 无 Bearer 前缀，应回退到 cookie
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(token, Some("cookie_tok".to_string()));
    }
}
