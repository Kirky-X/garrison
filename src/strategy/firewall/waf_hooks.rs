//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! WAF Hook 实现（9 个内置 Hook）。
//!
//! 每个 Hook 实现 [`WafHook`](crate::strategy::firewall::waf::WafHook) trait，
//! 通过 [`WafHookChain`](crate::strategy::firewall::waf::WafHookChain) 按注册顺序执行。
//!
//! # 9 个 Hook
//!
//! | Hook | name() | 校验内容 |
//! |------|--------|----------|
//! | `WhitePathHook` | `white_path` | 路径前缀白名单（始终 Allow） |
//! | `BlackPathHook` | `black_path` | 路径前缀黑名单 |
//! | `DangerCharacterHook` | `danger_char` | 危险字符（`//`、`\`、`%2e` 等） |
//! | `BannedCharacterHook` | `banned_char` | 不可打印 ASCII 字符 |
//! | `DirectoryTraversalHook` | `dir_traversal` | 目录遍历（`./`、`../`、`//`） |
//! | `HostHook` | `host` | Host 头白名单 |
//! | `HttpMethodHook` | `http_method` | HTTP 方法白名单 |
//! | `HeaderHook` | `header` | 禁止请求头黑名单 |
//! | `ParameterHook` | `parameter` | 禁止参数黑名单 |

use crate::strategy::firewall::waf::{WafContext, WafHook, WafVerdict};
use async_trait::async_trait;

// ============================================================================
// 1. WhitePathHook — 路径前缀白名单
// ============================================================================

/// 路径前缀白名单 Hook。
///
/// 语义：白名单匹配时不拦截（Allow），不匹配时也不拦截（Allow）。
/// 白名单的目的是"标记安全路径"，在当前短路链模型中始终返回 Allow。
pub struct WhitePathHook;

impl WhitePathHook {
    /// 创建白名单 Hook，传入允许的路径前缀列表。
    ///
    /// 注意：当前短路链模型中 WhitePathHook 始终返回 Allow，
    /// `paths` 参数保留用于未来扩展（如日志记录或条件短路）。
    pub fn new(_paths: Vec<String>) -> Self {
        Self
    }
}

#[async_trait]
impl WafHook for WhitePathHook {
    fn name(&self) -> &'static str {
        "white_path"
    }

    async fn check(&self, _ctx: &WafContext<'_>) -> WafVerdict {
        WafVerdict::Allow
    }
}

// ============================================================================
// 2. BlackPathHook — 路径前缀黑名单
// ============================================================================

/// 路径前缀黑名单 Hook。
///
/// 匹配任一黑名单前缀时返回 Deny，否则 Allow。空列表始终 Allow。
pub struct BlackPathHook {
    paths: Vec<String>,
}

impl BlackPathHook {
    /// 创建黑名单 Hook，传入禁止的路径前缀列表。
    pub fn new(paths: Vec<String>) -> Self {
        Self { paths }
    }
}

#[async_trait]
impl WafHook for BlackPathHook {
    fn name(&self) -> &'static str {
        "black_path"
    }

    async fn check(&self, ctx: &WafContext<'_>) -> WafVerdict {
        if self.paths.is_empty() {
            return WafVerdict::Allow;
        }
        if self.paths.iter().any(|p| ctx.path.starts_with(p)) {
            return WafVerdict::Deny {
                reason: format!("路径 {} 命中黑名单", ctx.path),
                hook: "black_path",
            };
        }
        WafVerdict::Allow
    }
}

// ============================================================================
// 3. DangerCharacterHook — 危险字符检测
// ============================================================================

/// 危险字符检测 Hook。
///
/// 检测 path 中的危险字符：`//`、`\`、`%2e`、`%2f`、`;`、`\0`、`\n`、`\r`。
/// 其中 `%2e`/`%2f` 大小写不敏感。
pub struct DangerCharacterHook;

impl DangerCharacterHook {
    /// 创建危险字符检测 Hook。
    pub fn new() -> Self {
        Self
    }
}

impl Default for DangerCharacterHook {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WafHook for DangerCharacterHook {
    fn name(&self) -> &'static str {
        "danger_char"
    }

    async fn check(&self, ctx: &WafContext<'_>) -> WafVerdict {
        let path = ctx.path;
        let lower = path.to_lowercase();
        // (pattern, is_percent_encoded, description)
        const PATTERNS: &[(&str, bool, &str)] = &[
            ("//", false, "双斜杠 //"),
            ("\\", false, "反斜杠 \\"),
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
                path.contains(pattern)
            };
            if found {
                return WafVerdict::Deny {
                    reason: format!("路径包含危险字符 {}", desc),
                    hook: "danger_char",
                };
            }
        }
        WafVerdict::Allow
    }
}

// ============================================================================
// 4. BannedCharacterHook — 不可打印 ASCII 字符检测
// ============================================================================

/// 不可打印 ASCII 字符检测 Hook。
///
/// 检测 path 中的不可打印字符（ASCII < 0x20 或 > 0x7E）。
pub struct BannedCharacterHook;

impl BannedCharacterHook {
    /// 创建不可打印字符检测 Hook。
    pub fn new() -> Self {
        Self
    }
}

impl Default for BannedCharacterHook {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WafHook for BannedCharacterHook {
    fn name(&self) -> &'static str {
        "banned_char"
    }

    async fn check(&self, ctx: &WafContext<'_>) -> WafVerdict {
        for &b in ctx.path.as_bytes() {
            if !(0x20..=0x7E).contains(&b) {
                return WafVerdict::Deny {
                    reason: format!("路径包含不可打印字符 (0x{:02X})", b),
                    hook: "banned_char",
                };
            }
        }
        WafVerdict::Allow
    }
}

// ============================================================================
// 5. DirectoryTraversalHook — 目录遍历检测
// ============================================================================

/// 目录遍历检测 Hook。
///
/// 检测 path 中的目录遍历模式：`./`、`../`、`//`。
pub struct DirectoryTraversalHook;

impl DirectoryTraversalHook {
    /// 创建目录遍历检测 Hook。
    pub fn new() -> Self {
        Self
    }
}

impl Default for DirectoryTraversalHook {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WafHook for DirectoryTraversalHook {
    fn name(&self) -> &'static str {
        "dir_traversal"
    }

    async fn check(&self, ctx: &WafContext<'_>) -> WafVerdict {
        const PATTERNS: &[&str] = &["../", "./", "//"];
        for &pattern in PATTERNS {
            if ctx.path.contains(pattern) {
                return WafVerdict::Deny {
                    reason: format!("路径包含目录遍历模式 {}", pattern),
                    hook: "dir_traversal",
                };
            }
        }
        WafVerdict::Allow
    }
}

// ============================================================================
// 6. HostHook — Host 头白名单
// ============================================================================

/// Host 头白名单 Hook。
///
/// 空列表始终 Allow。非空时 Host 头必须在白名单中。
/// 无 Host 头时 Allow（不校验）。
pub struct HostHook {
    hosts: Vec<String>,
}

impl HostHook {
    /// 创建 Host 白名单 Hook，传入允许的 Host 列表。
    pub fn new(hosts: Vec<String>) -> Self {
        Self { hosts }
    }
}

#[async_trait]
impl WafHook for HostHook {
    fn name(&self) -> &'static str {
        "host"
    }

    async fn check(&self, ctx: &WafContext<'_>) -> WafVerdict {
        if self.hosts.is_empty() {
            return WafVerdict::Allow;
        }
        match ctx.host {
            None => WafVerdict::Allow,
            Some(host) => {
                if self.hosts.iter().any(|h| h == host) {
                    WafVerdict::Allow
                } else {
                    WafVerdict::Deny {
                        reason: format!("Host {} 不在白名单中", host),
                        hook: "host",
                    }
                }
            },
        }
    }
}

// ============================================================================
// 7. HttpMethodHook — HTTP 方法白名单
// ============================================================================

/// HTTP 方法白名单 Hook。
///
/// 空列表始终 Allow。非空时方法必须在列表中（大小写敏感，RFC 7230）。
pub struct HttpMethodHook {
    methods: Vec<String>,
}

impl HttpMethodHook {
    /// 创建 HTTP 方法白名单 Hook，传入允许的方法列表。
    pub fn new(methods: Vec<String>) -> Self {
        Self { methods }
    }
}

#[async_trait]
impl WafHook for HttpMethodHook {
    fn name(&self) -> &'static str {
        "http_method"
    }

    async fn check(&self, ctx: &WafContext<'_>) -> WafVerdict {
        if self.methods.is_empty() {
            return WafVerdict::Allow;
        }
        if self.methods.iter().any(|m| m == ctx.method) {
            WafVerdict::Allow
        } else {
            WafVerdict::Deny {
                reason: format!("HTTP 方法 {} 不在允许列表中", ctx.method),
                hook: "http_method",
            }
        }
    }
}

// ============================================================================
// 8. HeaderHook — 禁止请求头黑名单
// ============================================================================

/// 禁止请求头黑名单 Hook。
///
/// 空列表始终 Allow。非空时请求头中含黑名单 header 则 Deny。
/// header 名称比较大小写不敏感。
pub struct HeaderHook {
    headers: Vec<String>,
}

impl HeaderHook {
    /// 创建禁止 Header 黑名单 Hook，传入禁止的 header 名称列表。
    pub fn new(headers: Vec<String>) -> Self {
        Self { headers }
    }
}

#[async_trait]
impl WafHook for HeaderHook {
    fn name(&self) -> &'static str {
        "header"
    }

    async fn check(&self, ctx: &WafContext<'_>) -> WafVerdict {
        if self.headers.is_empty() {
            return WafVerdict::Allow;
        }
        for banned in &self.headers {
            let banned_lower = banned.to_lowercase();
            for (name, _) in ctx.headers {
                if name.to_lowercase() == banned_lower {
                    return WafVerdict::Deny {
                        reason: format!("请求头 {} 在禁止列表中", name),
                        hook: "header",
                    };
                }
            }
        }
        WafVerdict::Allow
    }
}

// ============================================================================
// 9. ParameterHook — 禁止参数黑名单
// ============================================================================

/// 禁止参数黑名单 Hook。
///
/// 空列表始终 Allow。非空时请求参数中含黑名单参数则 Deny。
pub struct ParameterHook {
    params: Vec<String>,
}

impl ParameterHook {
    /// 创建禁止参数黑名单 Hook，传入禁止的参数名称列表。
    pub fn new(params: Vec<String>) -> Self {
        Self { params }
    }
}

#[async_trait]
impl WafHook for ParameterHook {
    fn name(&self) -> &'static str {
        "parameter"
    }

    async fn check(&self, ctx: &WafContext<'_>) -> WafVerdict {
        if self.params.is_empty() {
            return WafVerdict::Allow;
        }
        for banned in &self.params {
            for (name, _) in ctx.params {
                if name == banned {
                    return WafVerdict::Deny {
                        reason: format!("参数 {} 在禁止列表中", name),
                        hook: "parameter",
                    };
                }
            }
        }
        WafVerdict::Allow
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造测试用 WafContext。
    fn make_ctx<'a>(
        path: &'a str,
        method: &'a str,
        host: Option<&'a str>,
        headers: &'a [(String, String)],
        params: &'a [(String, String)],
    ) -> WafContext<'a> {
        WafContext {
            path,
            method,
            host,
            headers,
            params,
        }
    }

    /// 默认上下文（/api/test, GET, example.com, 无 headers/params）。
    fn default_ctx<'a>() -> WafContext<'a> {
        make_ctx("/api/test", "GET", Some("example.com"), &[], &[])
    }

    // ========================================================================
    // 1. WhitePathHook 测试（3 个）
    // ========================================================================

    /// 验证匹配白名单路径返回 Allow。
    #[tokio::test]
    async fn white_path_match_returns_allow() {
        let hook = WhitePathHook::new(vec!["/api".to_string()]);
        let ctx = default_ctx();
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    /// 验证不匹配白名单路径也返回 Allow。
    #[tokio::test]
    async fn white_path_no_match_returns_allow() {
        let hook = WhitePathHook::new(vec!["/admin".to_string()]);
        let ctx = default_ctx();
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    /// 验证空白名单返回 Allow。
    #[tokio::test]
    async fn white_path_empty_returns_allow() {
        let hook = WhitePathHook::new(vec![]);
        let ctx = default_ctx();
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    // ========================================================================
    // 2. BlackPathHook 测试（3 个）
    // ========================================================================

    /// 验证匹配黑名单路径返回 Deny。
    #[tokio::test]
    async fn black_path_match_returns_deny() {
        let hook = BlackPathHook::new(vec!["/admin".to_string()]);
        let ctx = make_ctx("/admin/secret", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Deny { .. }));
    }

    /// 验证不匹配黑名单路径返回 Allow。
    #[tokio::test]
    async fn black_path_no_match_returns_allow() {
        let hook = BlackPathHook::new(vec!["/admin".to_string()]);
        let ctx = default_ctx();
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    /// 验证空黑名单返回 Allow。
    #[tokio::test]
    async fn black_path_empty_returns_allow() {
        let hook = BlackPathHook::new(vec![]);
        let ctx = default_ctx();
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    // ========================================================================
    // 3. DangerCharacterHook 测试（3 个）
    // ========================================================================

    /// 验证含 `//` 返回 Deny。
    #[tokio::test]
    async fn danger_char_double_slash_returns_deny() {
        let hook = DangerCharacterHook::new();
        let ctx = make_ctx("/api//test", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Deny { .. }));
    }

    /// 验证含 `\` 返回 Deny。
    #[tokio::test]
    async fn danger_char_backslash_returns_deny() {
        let hook = DangerCharacterHook::new();
        let ctx = make_ctx("/api\\test", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Deny { .. }));
    }

    /// 验证正常路径返回 Allow。
    #[tokio::test]
    async fn danger_char_normal_path_returns_allow() {
        let hook = DangerCharacterHook::new();
        let ctx = default_ctx();
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    // ========================================================================
    // 4. BannedCharacterHook 测试（2 个）
    // ========================================================================

    /// 验证含不可打印字符返回 Deny。
    #[tokio::test]
    async fn banned_char_non_printable_returns_deny() {
        let hook = BannedCharacterHook::new();
        // 0x01 (SOH) 是不可打印字符
        let ctx = make_ctx("/api\x01test", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Deny { .. }));
    }

    /// 验证正常路径返回 Allow。
    #[tokio::test]
    async fn banned_char_normal_path_returns_allow() {
        let hook = BannedCharacterHook::new();
        let ctx = default_ctx();
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    // ========================================================================
    // 5. DirectoryTraversalHook 测试（3 个）
    // ========================================================================

    /// 验证含 `../` 返回 Deny。
    #[tokio::test]
    async fn dir_traversal_dot_dot_slash_returns_deny() {
        let hook = DirectoryTraversalHook::new();
        let ctx = make_ctx("/api/../etc/passwd", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Deny { .. }));
    }

    /// 验证含 `./` 返回 Deny。
    #[tokio::test]
    async fn dir_traversal_dot_slash_returns_deny() {
        let hook = DirectoryTraversalHook::new();
        let ctx = make_ctx("/api/./test", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Deny { .. }));
    }

    /// 验证正常路径返回 Allow。
    #[tokio::test]
    async fn dir_traversal_normal_path_returns_allow() {
        let hook = DirectoryTraversalHook::new();
        let ctx = default_ctx();
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    // ========================================================================
    // 6. HostHook 测试（3 个）
    // ========================================================================

    /// 验证 Host 不在白名单返回 Deny。
    #[tokio::test]
    async fn host_not_in_whitelist_returns_deny() {
        let hook = HostHook::new(vec!["allowed.com".to_string()]);
        let ctx = make_ctx("/api/test", "GET", Some("evil.com"), &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Deny { .. }));
    }

    /// 验证 Host 在白名单返回 Allow。
    #[tokio::test]
    async fn host_in_whitelist_returns_allow() {
        let hook = HostHook::new(vec!["example.com".to_string()]);
        let ctx = default_ctx();
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    /// 验证无 Host 返回 Allow。
    #[tokio::test]
    async fn host_none_returns_allow() {
        let hook = HostHook::new(vec!["example.com".to_string()]);
        let ctx = make_ctx("/api/test", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    // ========================================================================
    // 7. HttpMethodHook 测试（2 个）
    // ========================================================================

    /// 验证 Method 不在允许列表返回 Deny。
    #[tokio::test]
    async fn http_method_not_allowed_returns_deny() {
        let hook = HttpMethodHook::new(vec!["GET".to_string()]);
        let ctx = make_ctx("/api/test", "POST", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Deny { .. }));
    }

    /// 验证 Method 在允许列表返回 Allow。
    #[tokio::test]
    async fn http_method_allowed_returns_allow() {
        let hook = HttpMethodHook::new(vec!["GET".to_string(), "POST".to_string()]);
        let ctx = default_ctx();
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    // ========================================================================
    // 8. HeaderHook 测试（2 个）
    // ========================================================================

    /// 验证含黑名单 Header 返回 Deny。
    #[tokio::test]
    async fn header_banned_returns_deny() {
        let hook = HeaderHook::new(vec!["X-Forbidden".to_string()]);
        let headers = vec![("X-Forbidden".to_string(), "value".to_string())];
        let ctx = make_ctx("/api/test", "GET", None, &headers, &[]);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Deny { .. }));
    }

    /// 验证不含黑名单 Header 返回 Allow。
    #[tokio::test]
    async fn header_not_banned_returns_allow() {
        let hook = HeaderHook::new(vec!["X-Forbidden".to_string()]);
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        let ctx = make_ctx("/api/test", "GET", None, &headers, &[]);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }

    // ========================================================================
    // 9. ParameterHook 测试（2 个）
    // ========================================================================

    /// 验证含黑名单参数返回 Deny。
    #[tokio::test]
    async fn parameter_banned_returns_deny() {
        let hook = ParameterHook::new(vec!["password".to_string()]);
        let params = vec![("password".to_string(), "secret".to_string())];
        let ctx = make_ctx("/api/test", "GET", None, &[], &params);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Deny { .. }));
    }

    /// 验证不含黑名单参数返回 Allow。
    #[tokio::test]
    async fn parameter_not_banned_returns_allow() {
        let hook = ParameterHook::new(vec!["password".to_string()]);
        let params = vec![("username".to_string(), "admin".to_string())];
        let ctx = make_ctx("/api/test", "GET", None, &[], &params);
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::Allow));
    }
}
