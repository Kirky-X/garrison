//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! WAF 请求内容校验模块。
//!
//! 提供 [`WafRule`] trait 与 5 个内置规则，通过 `bulwark_waf_middleware` 集成到 axum 路由。
//!
//! # 内置规则
//!
//! - [`DangerousCharacter`]：检测路径中的危险字符（`//`、`\`、`%2e`、`%2f`、`;`、`\0`、`\n`、`\r`）
//! - [`DirectoryTraversal`]：检测目录遍历攻击（`./`、`../`、`..%2f`、`..%5c`）
//! - [`PathWhitelist`]：路径白名单前缀匹配
//! - [`PathBlacklist`]：路径黑名单前缀匹配
//! - [`HttpMethodWhitelist`]：HTTP 方法白名单
//!
//! # 配置
//!
//! 通过 [`WafConfig`] 控制是否启用 WAF 校验及各规则参数，集成到 [`crate::config::BulwarkConfig`]。

use crate::error::BulwarkResult;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

/// WAF 校验上下文，携带请求路径、方法和 headers。
#[derive(Debug, Clone)]
pub struct WafContext {
    /// 请求路径（如 `/api/users/1`）。
    pub path: String,
    /// HTTP 方法（如 `GET`、`POST`）。
    pub method: String,
    /// 请求 headers。
    pub headers: HeaderMap,
}

/// WAF 规则 trait，定义请求校验契约。
///
/// 实现者返回 `Ok(())` 放行请求，`Err(BulwarkError)` 拒绝请求。
///
/// # 示例
///
/// ```ignore
/// use bulwark::web::waf::{WafRule, WafContext};
/// use bulwark::BulwarkResult;
///
/// struct CustomRule;
///
/// #[async_trait::async_trait]
/// impl WafRule for CustomRule {
///     async fn check(&self, ctx: &WafContext) -> BulwarkResult<()> {
///         if ctx.path.contains("forbidden") {
///             Err(bulwark::BulwarkError::Config("forbidden path".into()))
///         } else {
///             Ok(())
///         }
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait WafRule: Send + Sync {
    /// 校验请求，返回 `Ok(())` 放行，`Err` 拒绝。
    async fn check(&self, ctx: &WafContext) -> BulwarkResult<()>;
}

/// WAF 配置。
///
/// 控制是否启用 WAF 校验以及各规则的配置。
///
/// # 默认值
///
/// - `enabled`: `false`（不启用，向后兼容）
/// - `check_dangerous_chars`: `true`
/// - `check_directory_traversal`: `true`
/// - `path_whitelist` / `path_blacklist` / `allowed_methods`: 空列表（不限制）
///
/// # 配置示例
///
/// ```toml
/// [waf_config]
/// enabled = true
/// path_blacklist = ["/admin"]
/// check_dangerous_chars = true
/// allowed_methods = ["GET", "POST"]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WafConfig {
    /// 是否启用 WAF 校验。
    pub enabled: bool,
    /// 路径白名单前缀列表（空时不启用白名单校验）。
    pub path_whitelist: Vec<String>,
    /// 路径黑名单前缀列表（空时不启用黑名单校验）。
    pub path_blacklist: Vec<String>,
    /// 是否检测危险字符。
    pub check_dangerous_chars: bool,
    /// 是否检测目录遍历。
    pub check_directory_traversal: bool,
    /// 允许的 HTTP 方法列表（空时不限制方法）。
    pub allowed_methods: Vec<String>,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path_whitelist: Vec::new(),
            path_blacklist: Vec::new(),
            check_dangerous_chars: true,
            check_directory_traversal: true,
            allowed_methods: Vec::new(),
        }
    }
}
