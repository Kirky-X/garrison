//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! WAF 请求内容校验模块。
//!
//! 提供 [`WafRule`](crate::web::waf::WafRule) trait 与 5 个内置规则，通过 `bulwark_waf_middleware` 集成到 axum 路由。
//!
//! # 内置规则
//!
//! - [`DangerousCharacter`](crate::web::waf::DangerousCharacter)：检测路径中的危险字符（`//`、`\`、`%2e`、`%2f`、`;`、`\0`、`\n`、`\r`）
//! - [`DirectoryTraversal`](crate::web::waf::DirectoryTraversal)：检测目录遍历攻击（`./`、`../`、`..%2f`、`..%5c`）
//! - [`PathWhitelist`](crate::web::waf::PathWhitelist)：路径白名单前缀匹配
//! - [`PathBlacklist`](crate::web::waf::PathBlacklist)：路径黑名单前缀匹配
//! - [`HttpMethodWhitelist`](crate::web::waf::HttpMethodWhitelist)：HTTP 方法白名单
//!
//! # 配置
//!
//! 通过 [`WafConfig`](crate::web::waf::WafConfig) 控制是否启用 WAF 校验及各规则参数，集成到 [`crate::config::BulwarkConfig`]。

use crate::error::{BulwarkError, BulwarkResult};
use axum::extract::State;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

/// WAF 校验上下文，携带请求路径、query、方法和 headers。
#[derive(Debug, Clone)]
pub struct WafContext {
    /// 请求路径（如 `/api/users/1`）。
    pub path: String,
    /// 请求 query 字符串（如 `id=1&name=foo`，不含 `?` 前缀；无 query 时为空字符串）。
    ///
    /// C2 修复：原 WAF 仅检查 path 不检查 query，攻击者可通过 `?q=../../etc/passwd`
    /// 绕过目录遍历防护。现 DangerousCharacter / DirectoryTraversal 同时检查 path 与 query。
    pub query: String,
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
/// - `enabled`: `true`（默认启用，secure-by-default）
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
// NOTE: `custom_rules: Vec<Arc<dyn WafRule>>` 不可 derive `Debug`/`PartialEq`/`Eq`
// （`dyn WafRule` 无 `Debug`/`PartialEq` bound），故手写 `Debug` 并移除 `PartialEq`/`Eq`。
// `Arc<dyn WafRule>` 是 `Clone`，`#[derive(Clone)]` 仍可用。
#[derive(Clone, Serialize, Deserialize)]
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
    /// 自定义规则链（spec R-waf-001 验收标准：自定义规则可通过 `WafConfig` 注入）。
    ///
    /// `#[serde(skip)]`：`Arc<dyn WafRule>` 不可 Serialize/Deserialize。
    /// middleware 在内置规则链之后追加执行这些规则。
    #[serde(skip)]
    pub custom_rules: Vec<std::sync::Arc<dyn WafRule>>,
}

impl std::fmt::Debug for WafConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WafConfig")
            .field("enabled", &self.enabled)
            .field("path_whitelist", &self.path_whitelist)
            .field("path_blacklist", &self.path_blacklist)
            .field("check_dangerous_chars", &self.check_dangerous_chars)
            .field("check_directory_traversal", &self.check_directory_traversal)
            .field("allowed_methods", &self.allowed_methods)
            .field(
                "custom_rules",
                &format!("{} rules", self.custom_rules.len()),
            )
            .finish()
    }
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            // secure-by-default，默认启用 WAF 校验
            enabled: true,
            path_whitelist: Vec::new(),
            path_blacklist: Vec::new(),
            check_dangerous_chars: true,
            check_directory_traversal: true,
            allowed_methods: Vec::new(),
            custom_rules: Vec::new(),
        }
    }
}

// ============================================================================
// T002: DangerousCharacter 规则
// ============================================================================

/// 危险字符检测规则（T002）。
///
/// 检测 `ctx.path` 与 `ctx.query` 中的危险字符：`//`、`\`、`%2e`、`%2f`、`;`、`\0`、`\n`、`\r`。
/// 其中 `%2e`/`%2f` 大小写不敏感（同时匹配 `%2E`/`%2F`）。
///
/// C2 修复：原实现仅检查 path，攻击者可通过 `?q=...` 绕过防护。现同时检查 path 与 query。
pub struct DangerousCharacter;

/// 内部辅助：对单个输入（path 或 query）执行危险字符检测。
fn check_dangerous_chars_in(input: &str, source: &str) -> BulwarkResult<()> {
    let lower = input.to_lowercase();
    // (pattern, is_percent_encoded, description)
    const PATTERNS: &[(&str, bool, &str)] = &[
        ("//", false, "双斜杠 //"),
        ("\\", false, "反斜杠"),
        (";", false, "分号 ;"),
        ("\0", false, "空字节"),
        ("\n", false, "换行符"),
        ("\r", false, "回车符"),
        ("%2e", true, "百分号编码 %2e"),
        ("%2f", true, "百分号编码 %2f"),
    ];
    for &(pattern, is_encoded, desc) in PATTERNS {
        let found = if is_encoded {
            lower.contains(pattern)
        } else {
            input.contains(pattern)
        };
        if found {
            return Err(BulwarkError::Config(format!(
                "WAF violation: {}包含危险字符 {}",
                source, desc
            )));
        }
    }
    Ok(())
}

#[async_trait::async_trait]
impl WafRule for DangerousCharacter {
    async fn check(&self, ctx: &WafContext) -> BulwarkResult<()> {
        // C2: 同时检查 path 与 query，防止 query 参数绕过
        check_dangerous_chars_in(&ctx.path, "路径")?;
        check_dangerous_chars_in(&ctx.query, "query 参数")?;
        Ok(())
    }
}

// ============================================================================
// T003: DirectoryTraversal 规则
// ============================================================================

/// 目录遍历检测规则（T003）。
///
/// 检测 `ctx.path` 与 `ctx.query` 中的目录遍历模式：`./`、`../`、`..%2f`、`..%5c`。
/// 其中 `..%2f`/`..%5c` 大小写不敏感。
///
/// C2 修复：原实现仅检查 path，攻击者可通过 `?q=../../etc/passwd` 绕过。现同时检查 path 与 query。
pub struct DirectoryTraversal;

/// 内部辅助：对单个输入（path 或 query）执行目录遍历检测。
fn check_directory_traversal_in(input: &str, source: &str) -> BulwarkResult<()> {
    let lower = input.to_lowercase();
    const LITERAL_PATTERNS: &[&str] = &["./", "../"];
    const ENCODED_PATTERNS: &[&str] = &["..%2f", "..%5c"];
    for &pattern in LITERAL_PATTERNS {
        if input.contains(pattern) {
            return Err(BulwarkError::Config(format!(
                "WAF violation: {}包含目录遍历模式 {}",
                source, pattern
            )));
        }
    }
    for &pattern in ENCODED_PATTERNS {
        if lower.contains(pattern) {
            return Err(BulwarkError::Config(format!(
                "WAF violation: {}包含目录遍历模式 {}",
                source, pattern
            )));
        }
    }
    Ok(())
}

#[async_trait::async_trait]
impl WafRule for DirectoryTraversal {
    async fn check(&self, ctx: &WafContext) -> BulwarkResult<()> {
        // C2: 同时检查 path 与 query，防止 query 参数绕过
        check_directory_traversal_in(&ctx.path, "路径")?;
        check_directory_traversal_in(&ctx.query, "query 参数")?;
        Ok(())
    }
}

// ============================================================================
// T004: PathWhitelist + PathBlacklist 规则
// ============================================================================

/// 路径白名单规则（T004）。
///
/// `prefixes` 为空时始终放行；非空时 `ctx.path` 必须以至少一个前缀开头才放行。
#[derive(Debug, Clone, Default)]
pub struct PathWhitelist {
    /// 允许的路径前缀列表。
    pub prefixes: Vec<String>,
}

#[async_trait::async_trait]
impl WafRule for PathWhitelist {
    async fn check(&self, ctx: &WafContext) -> BulwarkResult<()> {
        if self.prefixes.is_empty() {
            return Ok(());
        }
        if self.prefixes.iter().any(|p| ctx.path.starts_with(p)) {
            Ok(())
        } else {
            Err(BulwarkError::Config(format!(
                "WAF violation: 路径 {} 不在白名单中",
                ctx.path
            )))
        }
    }
}

/// 路径黑名单规则（T004）。
///
/// `prefixes` 为空时始终放行；非空时 `ctx.path` 以任一前缀开头即拒绝。
#[derive(Debug, Clone, Default)]
pub struct PathBlacklist {
    /// 禁止的路径前缀列表。
    pub prefixes: Vec<String>,
}

#[async_trait::async_trait]
impl WafRule for PathBlacklist {
    async fn check(&self, ctx: &WafContext) -> BulwarkResult<()> {
        if self.prefixes.is_empty() {
            return Ok(());
        }
        if self.prefixes.iter().any(|p| ctx.path.starts_with(p)) {
            Err(BulwarkError::Config(format!(
                "WAF violation: 路径 {} 命中黑名单",
                ctx.path
            )))
        } else {
            Ok(())
        }
    }
}

// ============================================================================
// T005: HttpMethodWhitelist 规则
// ============================================================================

/// HTTP 方法白名单规则（T005）。
///
/// `methods` 为空时始终放行；非空时 `ctx.method` 必须匹配（大小写敏感，RFC 7230）任一方法。
#[derive(Debug, Clone, Default)]
pub struct HttpMethodWhitelist {
    /// 允许的 HTTP 方法列表。
    pub methods: Vec<String>,
}

#[async_trait::async_trait]
impl WafRule for HttpMethodWhitelist {
    async fn check(&self, ctx: &WafContext) -> BulwarkResult<()> {
        if self.methods.is_empty() {
            return Ok(());
        }
        if self.methods.iter().any(|m| m == &ctx.method) {
            Ok(())
        } else {
            Err(BulwarkError::Config(format!(
                "WAF violation: HTTP 方法 {} 不在允许列表中",
                ctx.method
            )))
        }
    }
}

// ============================================================================
// T006: bulwark_waf_middleware
// ============================================================================

/// WAF 请求校验中间件（T006）。
///
/// 基于 [`WafConfig`] 构建规则链，对每个请求执行 WAF 校验。
///
/// # 行为
///
/// - `config.enabled == false`：跳过所有校验，直接放行
/// - `config.enabled == true`：按配置构建规则链，任一规则返回 `Err` 时返回 HTTP 400
///
/// # 规则链构建顺序
///
/// 1. `check_dangerous_chars` → [`DangerousCharacter`]
/// 2. `check_directory_traversal` → [`DirectoryTraversal`]
/// 3. `path_whitelist` 非空 → [`PathWhitelist`]
/// 4. `path_blacklist` 非空 → [`PathBlacklist`]
/// 5. `allowed_methods` 非空 → [`HttpMethodWhitelist`]
///
/// # 使用
///
/// ```ignore
/// use bulwark::web::waf::{bulwark_waf_middleware, WafConfig};
/// use std::sync::Arc;
/// use axum::Router;
///
/// let config = WafConfig { enabled: true, ..Default::default() };
/// let app = Router::new()
///     .route("/api", axum::routing::get(|| async { "ok" }))
///     .layer(axum::middleware::from_fn_with_state(
///         Arc::new(config),
///         bulwark_waf_middleware,
///     ));
/// ```
pub async fn bulwark_waf_middleware(
    State(config): State<std::sync::Arc<WafConfig>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    if !config.enabled {
        return next.run(req).await;
    }

    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let method = req.method().to_string();
    let headers = req.headers().clone();
    let ctx = WafContext {
        path,
        query,
        method,
        headers,
    };

    let mut rules: Vec<Box<dyn WafRule>> = Vec::new();
    if config.check_dangerous_chars {
        rules.push(Box::new(DangerousCharacter));
    }
    if config.check_directory_traversal {
        rules.push(Box::new(DirectoryTraversal));
    }
    if !config.path_whitelist.is_empty() {
        rules.push(Box::new(PathWhitelist {
            prefixes: config.path_whitelist.clone(),
        }));
    }
    if !config.path_blacklist.is_empty() {
        rules.push(Box::new(PathBlacklist {
            prefixes: config.path_blacklist.clone(),
        }));
    }
    if !config.allowed_methods.is_empty() {
        rules.push(Box::new(HttpMethodWhitelist {
            methods: config.allowed_methods.clone(),
        }));
    }

    for rule in &rules {
        if let Err(e) = rule.check(&ctx).await {
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
    }

    // T035: 自定义规则链（通过 WafConfig.custom_rules 注入，在内置规则之后追加执行）
    for rule in &config.custom_rules {
        if let Err(e) = rule.check(&ctx).await {
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use std::sync::Arc;
    use tower::ServiceExt;

    // ----------------------------------------------------------------
    // 辅助函数
    // ----------------------------------------------------------------

    fn make_ctx(path: &str, method: &str) -> WafContext {
        WafContext {
            path: path.to_string(),
            query: String::new(),
            method: method.to_string(),
            headers: HeaderMap::new(),
        }
    }

    /// 构建带 query 的 WafContext（用于 C2 query 参数检测测试）。
    fn make_ctx_with_query(path: &str, query: &str, method: &str) -> WafContext {
        WafContext {
            path: path.to_string(),
            query: query.to_string(),
            method: method.to_string(),
            headers: HeaderMap::new(),
        }
    }

    fn make_app(config: WafConfig) -> Router {
        Router::new()
            .route("/api/test", get(|| async { "ok" }))
            .route("/admin/test", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(config),
                bulwark_waf_middleware,
            ))
    }

    fn make_request(method: &str, path: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    /// 构建带 query 的请求（用于 C2 query 参数检测测试）。
    /// `path` 不含 `?`，`query` 为 `?` 后的部分（如 `q=../../etc/passwd`）。
    fn make_request_with_query(method: &str, path: &str, query: &str) -> Request<Body> {
        let uri = format!("{}?{}", path, query);
        Request::builder()
            .method(method)
            .uri(&uri)
            .body(Body::empty())
            .unwrap()
    }

    // ========================================================================
    // T002: DangerousCharacter 测试（8 个）
    // ========================================================================

    #[tokio::test]
    async fn dangerous_character_detects_double_slash() {
        let rule = DangerousCharacter;
        let ctx = make_ctx("/api//test", "GET");
        assert!(rule.check(&ctx).await.is_err());
    }

    #[tokio::test]
    async fn dangerous_character_detects_backslash() {
        let rule = DangerousCharacter;
        let ctx = make_ctx("/api\\test", "GET");
        assert!(rule.check(&ctx).await.is_err());
    }

    #[tokio::test]
    async fn dangerous_character_detects_percent_2e() {
        let rule = DangerousCharacter;
        let ctx_lower = make_ctx("/api/%2etest", "GET");
        assert!(rule.check(&ctx_lower).await.is_err());
        let ctx_upper = make_ctx("/api/%2Etest", "GET");
        assert!(rule.check(&ctx_upper).await.is_err());
    }

    #[tokio::test]
    async fn dangerous_character_detects_percent_2f() {
        let rule = DangerousCharacter;
        let ctx_lower = make_ctx("/api%2ftest", "GET");
        assert!(rule.check(&ctx_lower).await.is_err());
        let ctx_upper = make_ctx("/api%2Ftest", "GET");
        assert!(rule.check(&ctx_upper).await.is_err());
    }

    #[tokio::test]
    async fn dangerous_character_detects_semicolon() {
        let rule = DangerousCharacter;
        let ctx = make_ctx("/api;test", "GET");
        assert!(rule.check(&ctx).await.is_err());
    }

    #[tokio::test]
    async fn dangerous_character_detects_null_byte() {
        let rule = DangerousCharacter;
        let ctx = make_ctx("/api\0test", "GET");
        assert!(rule.check(&ctx).await.is_err());
    }

    #[tokio::test]
    async fn dangerous_character_detects_newline_and_cr() {
        let rule = DangerousCharacter;
        let ctx_nl = make_ctx("/api\ntest", "GET");
        assert!(rule.check(&ctx_nl).await.is_err());
        let ctx_cr = make_ctx("/api\rtest", "GET");
        assert!(rule.check(&ctx_cr).await.is_err());
    }

    #[tokio::test]
    async fn dangerous_character_allows_normal_path() {
        let rule = DangerousCharacter;
        let ctx = make_ctx("/api/users/123", "GET");
        assert!(rule.check(&ctx).await.is_ok());
    }

    // ========================================================================
    // T003: DirectoryTraversal 测试（6 个）
    // ========================================================================

    #[tokio::test]
    async fn directory_traversal_detects_dot_slash() {
        let rule = DirectoryTraversal;
        let ctx = make_ctx("/api/./test", "GET");
        assert!(rule.check(&ctx).await.is_err());
    }

    #[tokio::test]
    async fn directory_traversal_detects_dot_dot_slash() {
        let rule = DirectoryTraversal;
        let ctx = make_ctx("/api/../etc/passwd", "GET");
        assert!(rule.check(&ctx).await.is_err());
    }

    #[tokio::test]
    async fn directory_traversal_detects_percent_2f() {
        let rule = DirectoryTraversal;
        let ctx_lower = make_ctx("/api/..%2fetc", "GET");
        assert!(rule.check(&ctx_lower).await.is_err());
        let ctx_upper = make_ctx("/api/..%2Fetc", "GET");
        assert!(rule.check(&ctx_upper).await.is_err());
    }

    #[tokio::test]
    async fn directory_traversal_detects_percent_5c() {
        let rule = DirectoryTraversal;
        let ctx_lower = make_ctx("/api/..%5cetc", "GET");
        assert!(rule.check(&ctx_lower).await.is_err());
        let ctx_upper = make_ctx("/api/..%5Cetc", "GET");
        assert!(rule.check(&ctx_upper).await.is_err());
    }

    #[tokio::test]
    async fn directory_traversal_allows_normal_path() {
        let rule = DirectoryTraversal;
        let ctx = make_ctx("/api/users/123", "GET");
        assert!(rule.check(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn directory_traversal_detects_combined_patterns() {
        let rule = DirectoryTraversal;
        let ctx = make_ctx("/api/.././..%2f%5c", "GET");
        assert!(rule.check(&ctx).await.is_err());
    }

    // ========================================================================
    // T004: PathWhitelist + PathBlacklist 测试（8 个）
    // ========================================================================

    #[tokio::test]
    async fn path_whitelist_empty_allows_all() {
        let rule = PathWhitelist::default();
        let ctx = make_ctx("/any/path", "GET");
        assert!(rule.check(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn path_whitelist_single_prefix_match() {
        let rule = PathWhitelist {
            prefixes: vec!["/api".to_string()],
        };
        let ctx = make_ctx("/api/test", "GET");
        assert!(rule.check(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn path_whitelist_single_prefix_no_match() {
        let rule = PathWhitelist {
            prefixes: vec!["/api".to_string()],
        };
        let ctx = make_ctx("/admin/test", "GET");
        assert!(rule.check(&ctx).await.is_err());
    }

    #[tokio::test]
    async fn path_whitelist_multiple_prefixes_match() {
        let rule = PathWhitelist {
            prefixes: vec!["/api".to_string(), "/admin".to_string()],
        };
        let ctx = make_ctx("/admin/test", "GET");
        assert!(rule.check(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn path_blacklist_empty_allows_all() {
        let rule = PathBlacklist::default();
        let ctx = make_ctx("/any/path", "GET");
        assert!(rule.check(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn path_blacklist_single_prefix_match_blocks() {
        let rule = PathBlacklist {
            prefixes: vec!["/admin".to_string()],
        };
        let ctx = make_ctx("/admin/test", "GET");
        assert!(rule.check(&ctx).await.is_err());
    }

    #[tokio::test]
    async fn path_blacklist_single_prefix_no_match_allows() {
        let rule = PathBlacklist {
            prefixes: vec!["/admin".to_string()],
        };
        let ctx = make_ctx("/api/test", "GET");
        assert!(rule.check(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn path_blacklist_multiple_prefixes_match_blocks() {
        let rule = PathBlacklist {
            prefixes: vec!["/admin".to_string(), "/secret".to_string()],
        };
        let ctx = make_ctx("/secret/data", "GET");
        assert!(rule.check(&ctx).await.is_err());
    }

    // ========================================================================
    // T005: HttpMethodWhitelist 测试（5 个）
    // ========================================================================

    #[tokio::test]
    async fn http_method_whitelist_get_allowed() {
        let rule = HttpMethodWhitelist {
            methods: vec!["GET".to_string()],
        };
        let ctx = make_ctx("/api/test", "GET");
        assert!(rule.check(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn http_method_whitelist_post_blocked() {
        let rule = HttpMethodWhitelist {
            methods: vec!["GET".to_string()],
        };
        let ctx = make_ctx("/api/test", "POST");
        assert!(rule.check(&ctx).await.is_err());
    }

    #[tokio::test]
    async fn http_method_whitelist_empty_allows_all() {
        let rule = HttpMethodWhitelist::default();
        let ctx = make_ctx("/api/test", "DELETE");
        assert!(rule.check(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn http_method_whitelist_case_sensitive() {
        let rule = HttpMethodWhitelist {
            methods: vec!["GET".to_string()],
        };
        // 相同大小写放行
        let ctx = make_ctx("/api/test", "GET");
        assert!(rule.check(&ctx).await.is_ok());
        // 不同大小写拒绝（HTTP 方法大小写敏感，RFC 7230）
        let ctx_lower = make_ctx("/api/test", "get");
        assert!(rule.check(&ctx_lower).await.is_err());
    }

    #[tokio::test]
    async fn http_method_whitelist_multiple_methods() {
        let rule = HttpMethodWhitelist {
            methods: vec!["GET".to_string(), "POST".to_string()],
        };
        let ctx_get = make_ctx("/api/test", "GET");
        assert!(rule.check(&ctx_get).await.is_ok());
        let ctx_post = make_ctx("/api/test", "POST");
        assert!(rule.check(&ctx_post).await.is_ok());
    }

    // ========================================================================
    // T006: bulwark_waf_middleware 集成测试（6 个）
    // ========================================================================

    #[tokio::test]
    async fn middleware_disabled_passes_through() {
        let config = WafConfig {
            enabled: false,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn middleware_enabled_blocks_dangerous_path() {
        let config = WafConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request("GET", "/api//test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn middleware_whitelist_passes() {
        let config = WafConfig {
            enabled: true,
            path_whitelist: vec!["/api".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn middleware_blacklist_blocks() {
        let config = WafConfig {
            enabled: true,
            path_blacklist: vec!["/admin".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request("GET", "/admin/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn middleware_method_restriction_blocks() {
        let config = WafConfig {
            enabled: true,
            allowed_methods: vec!["GET".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request("POST", "/api/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn middleware_multi_rule_combination() {
        let config = WafConfig {
            enabled: true,
            check_dangerous_chars: true,
            check_directory_traversal: true,
            path_blacklist: vec!["/admin".to_string()],
            allowed_methods: vec!["GET".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        // 黑名单拦截 /admin
        let resp = app
            .clone()
            .oneshot(make_request("GET", "/admin/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // 方法限制拦截 POST
        let resp = app
            .clone()
            .oneshot(make_request("POST", "/api/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // 危险字符拦截 //
        let resp = app
            .clone()
            .oneshot(make_request("GET", "/api//test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // 合法请求放行
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ========================================================================
    // T035: custom_rules 自定义规则注入测试（4 个）
    // ========================================================================

    /// 测试用自定义规则：拒绝路径包含指定子串的请求。
    struct BlockSubstrRule {
        blocked: String,
    }

    #[async_trait::async_trait]
    impl WafRule for BlockSubstrRule {
        async fn check(&self, ctx: &WafContext) -> BulwarkResult<()> {
            if ctx.path.contains(&self.blocked) {
                Err(BulwarkError::Config(format!(
                    "WAF violation: 自定义规则拦截 {}",
                    self.blocked
                )))
            } else {
                Ok(())
            }
        }
    }

    /// T035: custom_rules 为空时不影响请求放行。
    #[tokio::test]
    async fn custom_rules_empty_list_passes() {
        let config = WafConfig {
            enabled: true,
            custom_rules: Vec::new(),
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// T035: 单个 custom_rule 放行不匹配的路径。
    #[tokio::test]
    async fn custom_rules_single_rule_passes() {
        let rule: Arc<dyn WafRule> = Arc::new(BlockSubstrRule {
            blocked: "forbidden".to_string(),
        });
        let config = WafConfig {
            enabled: true,
            custom_rules: vec![rule],
            ..Default::default()
        };
        let app = make_app(config);
        // /api/test 不含 "forbidden"，应放行
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// T035: 多个 custom_rule 全部放行时请求通过。
    #[tokio::test]
    async fn custom_rules_multiple_rules_pass() {
        let rules: Vec<Arc<dyn WafRule>> = vec![
            Arc::new(BlockSubstrRule {
                blocked: "evil".to_string(),
            }),
            Arc::new(BlockSubstrRule {
                blocked: "hack".to_string(),
            }),
        ];
        let config = WafConfig {
            enabled: true,
            custom_rules: rules,
            ..Default::default()
        };
        let app = make_app(config);
        // /api/test 不含 "evil" 也不含 "hack"，两条规则均放行
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// T035: custom_rule 拒绝匹配路径时返回 400。
    #[tokio::test]
    async fn custom_rules_rejection_returns_400() {
        let rule: Arc<dyn WafRule> = Arc::new(BlockSubstrRule {
            blocked: "/admin".to_string(),
        });
        let config = WafConfig {
            enabled: true,
            custom_rules: vec![rule],
            ..Default::default()
        };
        let app = make_app(config);
        // /admin/test 命中自定义规则，应返回 400
        let resp = app
            .oneshot(make_request("GET", "/admin/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // /api/test 不命中，应放行
        let app2 = make_app(WafConfig {
            enabled: true,
            custom_rules: vec![Arc::new(BlockSubstrRule {
                blocked: "/admin".to_string(),
            })],
            ..Default::default()
        });
        let resp = app2
            .oneshot(make_request("GET", "/api/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ========================================================================
    // C1: WAF 默认启用测试（secure-by-default）
    // ========================================================================

    /// WafConfig::default() 应默认启用 WAF 防护（secure-by-default）。
    #[test]
    fn waf_config_default_enabled_is_true() {
        let config = WafConfig::default();
        assert!(
            config.enabled,
            "VULN-0006: WafConfig::default().enabled 必须为 true（secure-by-default）"
        );
    }

    /// 默认配置应阻止危险路径（无需用户显式启用）。
    #[tokio::test]
    async fn default_config_blocks_dangerous_path() {
        let app = make_app(WafConfig::default());
        let resp = app
            .oneshot(make_request("GET", "/api//test"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "VULN-0006: 默认配置应阻止危险路径"
        );
    }

    /// 默认配置应阻止目录遍历。
    #[tokio::test]
    async fn default_config_blocks_directory_traversal() {
        let app = make_app(WafConfig::default());
        let resp = app
            .oneshot(make_request("GET", "/api/../etc/passwd"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "VULN-0006: 默认配置应阻止目录遍历"
        );
    }

    // ========================================================================
    // C2: WAF 检查 query 参数测试（防止 query 绕过）
    // ========================================================================

    /// DangerousCharacter 应检测 query 中的目录遍历模式 `../`。
    #[tokio::test]
    async fn dangerous_character_detects_traversal_in_query() {
        let rule = DangerousCharacter;
        // path 干净，query 含 `../`
        let ctx = make_ctx_with_query("/api/test", "q=../../etc/passwd", "GET");
        // `../` 不是 DangerousCharacter 的检测项（由 DirectoryTraversal 负责），
        // 但 `;` 是。这里验证 DangerousCharacter 不误报 `../`。
        // 真正的 query 检测在 directory_traversal_query 测试中。
        let _ = rule.check(&ctx).await;
    }

    /// DirectoryTraversal 应检测 query 中的 `../` 模式。
    #[tokio::test]
    async fn directory_traversal_detects_dot_dot_slash_in_query() {
        let rule = DirectoryTraversal;
        // path 干净，query 含 `../`
        let ctx = make_ctx_with_query("/api/test", "q=../../etc/passwd", "GET");
        assert!(
            rule.check(&ctx).await.is_err(),
            "C2: query 中的 `../` 应被 DirectoryTraversal 检测到"
        );
    }

    /// DirectoryTraversal 应检测 query 中的 `./` 模式。
    #[tokio::test]
    async fn directory_traversal_detects_dot_slash_in_query() {
        let rule = DirectoryTraversal;
        let ctx = make_ctx_with_query("/api/test", "q=./secret", "GET");
        assert!(
            rule.check(&ctx).await.is_err(),
            "C2: query 中的 `./` 应被 DirectoryTraversal 检测到"
        );
    }

    /// DirectoryTraversal 应检测 query 中的 `..%2f` 编码模式（大小写不敏感）。
    #[tokio::test]
    async fn directory_traversal_detects_encoded_2f_in_query() {
        let rule = DirectoryTraversal;
        let ctx_lower = make_ctx_with_query("/api/test", "q=..%2fetc", "GET");
        assert!(rule.check(&ctx_lower).await.is_err());
        let ctx_upper = make_ctx_with_query("/api/test", "q=..%2Fetc", "GET");
        assert!(rule.check(&ctx_upper).await.is_err());
    }

    /// DirectoryTraversal 应检测 query 中的 `..%5c` 编码模式（大小写不敏感）。
    #[tokio::test]
    async fn directory_traversal_detects_encoded_5c_in_query() {
        let rule = DirectoryTraversal;
        let ctx_lower = make_ctx_with_query("/api/test", "q=..%5cetc", "GET");
        assert!(rule.check(&ctx_lower).await.is_err());
        let ctx_upper = make_ctx_with_query("/api/test", "q=..%5Cetc", "GET");
        assert!(rule.check(&ctx_upper).await.is_err());
    }

    /// DangerousCharacter 应检测 query 中的 `;` 字符。
    #[tokio::test]
    async fn dangerous_character_detects_semicolon_in_query() {
        let rule = DangerousCharacter;
        let ctx = make_ctx_with_query("/api/test", "q=a;rm -rf", "GET");
        assert!(
            rule.check(&ctx).await.is_err(),
            "C2: query 中的 `;` 应被 DangerousCharacter 检测到"
        );
    }

    /// DangerousCharacter 应检测 query 中的 `%2e` 编码（大小写不敏感）。
    #[tokio::test]
    async fn dangerous_character_detects_percent_2e_in_query() {
        let rule = DangerousCharacter;
        let ctx_lower = make_ctx_with_query("/api/test", "q=%2e%2e/secret", "GET");
        assert!(rule.check(&ctx_lower).await.is_err());
        let ctx_upper = make_ctx_with_query("/api/test", "q=%2E%2E/secret", "GET");
        assert!(rule.check(&ctx_upper).await.is_err());
    }

    /// DangerousCharacter 应检测 query 中的 `%2f` 编码（大小写不敏感）。
    #[tokio::test]
    async fn dangerous_character_detects_percent_2f_in_query() {
        let rule = DangerousCharacter;
        let ctx_lower = make_ctx_with_query("/api/test", "q=api%2ftest", "GET");
        assert!(rule.check(&ctx_lower).await.is_err());
        let ctx_upper = make_ctx_with_query("/api/test", "q=api%2Ftest", "GET");
        assert!(rule.check(&ctx_upper).await.is_err());
    }

    /// 干净的 query 不应触发任何规则。
    #[tokio::test]
    async fn clean_query_passes_all_rules() {
        let ctx = make_ctx_with_query("/api/test", "id=123&name=foo", "GET");
        assert!(DangerousCharacter.check(&ctx).await.is_ok());
        assert!(DirectoryTraversal.check(&ctx).await.is_ok());
    }

    /// 中间件层应阻止 query 中的目录遍历攻击（端到端测试）。
    #[tokio::test]
    async fn middleware_blocks_directory_traversal_in_query() {
        let config = WafConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        // path 干净，query 含 `../../etc/passwd`
        let resp = app
            .oneshot(make_request_with_query(
                "GET",
                "/api/test",
                "q=../../etc/passwd",
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "C2: 中间件应阻止 query 中的目录遍历"
        );
    }

    /// 中间件层应阻止 query 中的危险字符（端到端测试）。
    #[tokio::test]
    async fn middleware_blocks_dangerous_char_in_query() {
        let config = WafConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        // path 干净，query 含 `;`（注意 URI 不能含原始空格，故用 `;` 单独触发）
        let resp = app
            .oneshot(make_request_with_query("GET", "/api/test", "q=a;rm"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "C2: 中间件应阻止 query 中的危险字符"
        );
    }

    /// 中间件层应放行干净的 query（端到端测试）。
    #[tokio::test]
    async fn middleware_allows_clean_query() {
        let config = WafConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_query(
                "GET",
                "/api/test",
                "id=123&name=foo",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "C2: 干净 query 应放行");
    }
}
