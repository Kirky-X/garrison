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
//! | `WhitePathHook` | `white_path` | 路径前缀白名单（匹配返回 AllowAndSkip） |
//! | `BlackPathHook` | `black_path` | 路径前缀黑名单 |
//! | `DangerCharacterHook` | `danger_char` | 危险字符（`//`、`\`、`%2e`、`%00` 等，校验 path/param/header 值） |
//! | `BannedCharacterHook` | `banned_char` | 不可打印 ASCII 字符 |
//! | `DirectoryTraversalHook` | `dir_traversal` | 目录遍历（`./`、`../`、`//`） |
//! | `HostHook` | `host` | Host 头白名单 |
//! | `HttpMethodHook` | `http_method` | HTTP 方法白名单 |
//! | `HeaderHook` | `header` | 禁止请求头黑名单 |
//! | `ParameterHook` | `parameter` | 禁止参数黑名单 |

use super::waf::{WafContext, WafHook, WafVerdict};
use async_trait::async_trait;

// ============================================================================
// 1. WhitePathHook — 路径前缀白名单
// ============================================================================

/// 路径前缀白名单 Hook。
///
/// 语义：白名单匹配时返回 `AllowAndSkip`（放行并跳过后续 Hook），
/// 不匹配时返回 `Allow`（继续执行后续 Hook）。
///
/// # 注册顺序约束（MED-001）
///
/// **警告**：WhitePathHook 必须注册在所有安全关键 Hook（如
/// [`DirectoryTraversalHook`] / [`DangerCharacterHook`]）**之后**。
///
/// 若注册在安全 Hook 之前，白名单匹配会短路跳过安全校验，导致
/// `/api/../admin` 等路径遍历攻击绕过。为防止上述绕过，本 Hook 在匹配白名单前
/// 会先检查 path 是否含可疑模式（`..` 或 `//`），若含可疑模式则不短路，
/// 返回 `Allow` 交给后续安全 Hook 处理。但这只是兜底防御，正确的注册顺序
/// 仍是强约束。
///
/// [`DirectoryTraversalHook`]: DirectoryTraversalHook
/// [`DangerCharacterHook`]: DangerCharacterHook
pub struct WhitePathHook {
    paths: Vec<String>,
}

impl WhitePathHook {
    /// 创建白名单 Hook，传入允许的路径前缀列表。
    ///
    /// 匹配任一前缀时返回 `AllowAndSkip`，短路后续 Hook。
    ///
    /// # 注册顺序约束（MED-001）
    ///
    /// **警告**：WhitePathHook 必须注册在所有安全关键 Hook（如
    /// [`DirectoryTraversalHook`] / [`DangerCharacterHook`]）**之后**。
    /// 若注册在安全 Hook 之前，白名单匹配会短路跳过安全校验，导致路径遍历攻击绕过。
    ///
    /// [`DirectoryTraversalHook`]: DirectoryTraversalHook
    /// [`DangerCharacterHook`]: DangerCharacterHook
    pub fn new(paths: Vec<String>) -> Self {
        Self { paths }
    }
}

/// 精确路径段匹配：`path == prefix` 或 `path` 以 `prefix/` 开头。
///
/// 避免 `starts_with` 的前缀混淆问题（如 `/api` 误匹配 `/api-v2/secret`）。
fn path_matches(prefix: &str, path: &str) -> bool {
    path == prefix || path.starts_with(&format!("{}/", prefix))
}

#[async_trait]
impl WafHook for WhitePathHook {
    fn name(&self) -> &'static str {
        "white_path"
    }

    /// 校验请求上下文。
    ///
    /// # 注册顺序约束（MED-001）
    ///
    /// **警告**：本 Hook 必须注册在所有安全关键 Hook（如
    /// [`DirectoryTraversalHook`] / [`DangerCharacterHook`]）**之后**。
    ///
    /// 实现细节：匹配白名单前先检查 path 是否含可疑模式（字面量 `..`/`//` 或
    /// URL 编码形式 `%2e`/`%2f`/`%5c`），若含可疑模式则返回 `Allow`（不短路），
    /// 交给后续安全 Hook 处理。
    ///
    /// [`DirectoryTraversalHook`]: DirectoryTraversalHook
    /// [`DangerCharacterHook`]: DangerCharacterHook
    async fn check(&self, ctx: &WafContext<'_>) -> WafVerdict {
        // 安全兜底：含可疑模式（字面量或 URL 编码）时不短路，返回 Allow 交给后续安全 Hook 处理。
        // 防止 `/api/../admin` 或 `/api/%2e%2e/admin` 通过 `starts_with("/api")` 绕过安全 Hook。
        let lower = ctx.path.to_lowercase();
        if lower.contains("..")
            || lower.contains("//")
            || lower.contains("%2e")
            || lower.contains("%2f")
            || lower.contains("%5c")
        {
            return WafVerdict::Allow;
        }
        if self.paths.iter().any(|p| path_matches(p, ctx.path)) {
            return WafVerdict::AllowAndSkip;
        }
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
/// 检测 path、参数值、请求头值中的危险字符：`//`、`\`、`;`、`\0`、`\n`、`\r`，
/// 以及百分号编码 `%2e`、`%2f`、`%00`、`%5c`、`%3b`、`%0a`、`%0d`（大小写不敏感）。
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

/// 检测字符串中的危险字符，返回命中的模式描述。
///
/// 所有模式均大小写不敏感，统一在 `lower`（小写形式）中检测。
/// 非编码模式（`//`、`\`、`;`、`\0`、`\n`、`\r`）为符号和控制字符，无大小写之分，
/// 百分号编码模式（`%2e`、`%2f` 等）通过小写形式统一匹配。
fn check_danger_chars(lower: &str) -> Option<&'static str> {
    // (pattern, description) — 所有模式均大小写不敏感，统一用 lower.contains(pattern) 检测
    const PATTERNS: &[(&str, &str)] = &[
        ("//", "双斜杠 //"),
        ("\\", "反斜杠 \\"),
        (";", "分号 ;"),
        ("\0", "空字节"),
        ("\n", "换行符"),
        ("\r", "回车符"),
        ("%2e", "百分号编码 %2e"),
        ("%2f", "百分号编码 %2f"),
        ("%00", "百分号编码 %00"),
        ("%5c", "百分号编码 %5c"),
        ("%3b", "百分号编码 %3b"),
        ("%0a", "百分号编码 %0a"),
        ("%0d", "百分号编码 %0d"),
    ];
    for &(pattern, desc) in PATTERNS {
        if lower.contains(pattern) {
            return Some(desc);
        }
    }
    // 双重编码检测：将 %25 解码为 % 后重新校验
    // 防止 %252e（→ %2e → .）等双重 % 编码绕过
    if lower.contains("%25") {
        let decoded = lower.replace("%25", "%");
        for &(pattern, desc) in PATTERNS {
            if decoded.contains(pattern) {
                return Some(desc);
            }
        }
    }
    None
}

#[async_trait]
impl WafHook for DangerCharacterHook {
    fn name(&self) -> &'static str {
        "danger_char"
    }

    async fn check(&self, ctx: &WafContext<'_>) -> WafVerdict {
        let path = ctx.path;
        let lower = path.to_lowercase();
        if let Some(desc) = check_danger_chars(&lower) {
            return WafVerdict::Deny {
                reason: format!("路径包含危险字符 {}", desc),
                hook: "danger_char",
            };
        }
        for (_, value) in ctx.params {
            let lower = value.to_lowercase();
            if let Some(desc) = check_danger_chars(&lower) {
                return WafVerdict::Deny {
                    reason: format!("参数值包含危险字符 {}", desc),
                    hook: "danger_char",
                };
            }
        }
        for (_, value) in ctx.headers {
            let lower = value.to_lowercase();
            if let Some(desc) = check_danger_chars(&lower) {
                return WafVerdict::Deny {
                    reason: format!("请求头值包含危险字符 {}", desc),
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
    use crate::strategy::firewall::WafHookChain;
    use std::sync::{Arc, Mutex};

    /// 记录执行顺序的 Mock Hook（用于验证链短路行为）。
    struct RecordingHook {
        hook_name: &'static str,
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl WafHook for RecordingHook {
        fn name(&self) -> &'static str {
            self.hook_name
        }
        async fn check(&self, _ctx: &WafContext<'_>) -> WafVerdict {
            self.log.lock().unwrap().push(self.hook_name);
            WafVerdict::Allow
        }
    }

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

    /// 验证匹配白名单路径返回 AllowAndSkip。
    #[tokio::test]
    async fn white_path_match_returns_allow_and_skip() {
        let hook = WhitePathHook::new(vec!["/api".to_string()]);
        let ctx = default_ctx();
        let verdict = hook.check(&ctx).await;
        assert!(matches!(verdict, WafVerdict::AllowAndSkip));
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

    // ========================================================================
    // 10. WAF 绕过场景测试（HIGH-004，10 个）
    // ========================================================================

    /// 验证 path 含 `%00` 编码返回 Deny（HIGH-001）。
    #[tokio::test]
    async fn danger_char_percent_00_encoded_returns_deny() {
        let hook = DangerCharacterHook::new();
        let ctx = make_ctx("/api/%00test", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(
            matches!(verdict, WafVerdict::Deny { .. }),
            "path 含 %00 应被拦截"
        );
    }

    /// 验证 path 含 `%5c` 编码返回 Deny（HIGH-001）。
    #[tokio::test]
    async fn danger_char_percent_5c_encoded_returns_deny() {
        let hook = DangerCharacterHook::new();
        let ctx = make_ctx("/api/%5ctest", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(
            matches!(verdict, WafVerdict::Deny { .. }),
            "path 含 %5c 应被拦截"
        );
    }

    /// 验证 path 含 `%3b` 编码返回 Deny（HIGH-001）。
    #[tokio::test]
    async fn danger_char_percent_3b_encoded_returns_deny() {
        let hook = DangerCharacterHook::new();
        let ctx = make_ctx("/api/%3btest", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(
            matches!(verdict, WafVerdict::Deny { .. }),
            "path 含 %3b 应被拦截"
        );
    }

    /// 验证 path 含 `%0a` 编码返回 Deny（HIGH-001）。
    #[tokio::test]
    async fn danger_char_percent_0a_encoded_returns_deny() {
        let hook = DangerCharacterHook::new();
        let ctx = make_ctx("/api/%0atest", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(
            matches!(verdict, WafVerdict::Deny { .. }),
            "path 含 %0a 应被拦截"
        );
    }

    /// 验证 path 含 `%0d` 编码返回 Deny（HIGH-001）。
    #[tokio::test]
    async fn danger_char_percent_0d_encoded_returns_deny() {
        let hook = DangerCharacterHook::new();
        let ctx = make_ctx("/api/%0dtest", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(
            matches!(verdict, WafVerdict::Deny { .. }),
            "path 含 %0d 应被拦截"
        );
    }

    /// 验证大写百分号编码返回 Deny（大小写不敏感，HIGH-001）。
    #[tokio::test]
    async fn danger_char_uppercase_percent_encoded_returns_deny() {
        let hook = DangerCharacterHook::new();
        // %2E（大写 %2e）
        let ctx = make_ctx("/api/%2Etest", "GET", None, &[], &[]);
        assert!(
            matches!(hook.check(&ctx).await, WafVerdict::Deny { .. }),
            "path 含 %2E 应被拦截"
        );
        // %2F（大写 %2f）
        let ctx = make_ctx("/api/%2Ftest", "GET", None, &[], &[]);
        assert!(
            matches!(hook.check(&ctx).await, WafVerdict::Deny { .. }),
            "path 含 %2F 应被拦截"
        );
        // %00（大写 %00）
        let ctx = make_ctx("/api/%00test", "GET", None, &[], &[]);
        assert!(
            matches!(hook.check(&ctx).await, WafVerdict::Deny { .. }),
            "path 含 %00 应被拦截"
        );
    }

    /// 验证 query 参数值含 `//` 返回 Deny（HIGH-003）。
    #[tokio::test]
    async fn danger_char_query_param_value_returns_deny() {
        let hook = DangerCharacterHook::new();
        let params = vec![("q".to_string(), "a//b".to_string())];
        let ctx = make_ctx("/api/test", "GET", None, &[], &params);
        let verdict = hook.check(&ctx).await;
        assert!(
            matches!(verdict, WafVerdict::Deny { .. }),
            "参数值含 // 应被拦截"
        );
    }

    /// 验证 header 值含 `\` 返回 Deny（HIGH-003）。
    #[tokio::test]
    async fn danger_char_header_value_returns_deny() {
        let hook = DangerCharacterHook::new();
        let headers = vec![("X-Custom".to_string(), "a\\b".to_string())];
        let ctx = make_ctx("/api/test", "GET", None, &headers, &[]);
        let verdict = hook.check(&ctx).await;
        assert!(
            matches!(verdict, WafVerdict::Deny { .. }),
            "header 值含 \\ 应被拦截"
        );
    }

    /// 验证 WhitePathHook 匹配时短路，后续 Hook 不执行（HIGH-002）。
    #[tokio::test]
    async fn white_path_match_short_circuits_chain() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = WafHookChain::new();
        chain.register(Box::new(WhitePathHook::new(vec!["/api".to_string()])));
        chain.register(Box::new(RecordingHook {
            hook_name: "recorder",
            log: log.clone(),
        }));
        let ctx = default_ctx(); // path = /api/test 匹配 /api
        let result = chain.check(&ctx).await;
        assert!(result.is_ok(), "WhitePathHook 匹配时应放行");
        let executed = log.lock().unwrap();
        assert!(
            executed.is_empty(),
            "WhitePathHook 匹配时应短路，后续 Hook 不应执行，实际执行: {:?}",
            executed
        );
    }

    /// 验证 WhitePathHook 不匹配时后续 Hook 继续执行（HIGH-002）。
    #[tokio::test]
    async fn white_path_no_match_continues_chain() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = WafHookChain::new();
        chain.register(Box::new(WhitePathHook::new(vec!["/admin".to_string()])));
        chain.register(Box::new(RecordingHook {
            hook_name: "recorder",
            log: log.clone(),
        }));
        let ctx = default_ctx(); // path = /api/test 不匹配 /admin
        let result = chain.check(&ctx).await;
        assert!(result.is_ok());
        let executed = log.lock().unwrap();
        assert_eq!(
            executed.len(),
            1,
            "WhitePathHook 不匹配时后续 Hook 应执行，实际执行: {:?}",
            executed
        );
    }

    // ========================================================================
    // 11. HIGH-001 修复测试（5 个）
    // ========================================================================

    /// 验证 path 含 `..` 时 WhitePathHook 不短路（HIGH-001 修复）。
    ///
    /// `/api/../admin` 虽然以 `/api` 开头，但含 `..` 可疑模式，
    /// 应返回 Allow 交给后续安全 Hook（如 DirectoryTraversalHook）处理。
    #[tokio::test]
    async fn white_path_traversal_not_short_circuited() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = WafHookChain::new();
        chain.register(Box::new(WhitePathHook::new(vec!["/api".to_string()])));
        chain.register(Box::new(RecordingHook {
            hook_name: "recorder",
            log: log.clone(),
        }));
        let ctx = make_ctx("/api/../admin", "GET", None, &[], &[]);
        let result = chain.check(&ctx).await;
        assert!(result.is_ok(), "含 .. 的路径应放行（不短路）");
        let executed = log.lock().unwrap();
        assert!(
            !executed.is_empty(),
            "含 .. 的路径不应短路，后续 Hook 应执行，实际执行: {:?}",
            executed
        );
    }

    /// 验证 path 含 `//` 时 WhitePathHook 不短路（HIGH-001 修复）。
    #[tokio::test]
    async fn white_path_double_slash_not_short_circuited() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = WafHookChain::new();
        chain.register(Box::new(WhitePathHook::new(vec!["/api".to_string()])));
        chain.register(Box::new(RecordingHook {
            hook_name: "recorder",
            log: log.clone(),
        }));
        let ctx = make_ctx("/api//test", "GET", None, &[], &[]);
        let result = chain.check(&ctx).await;
        assert!(result.is_ok(), "含 // 的路径应放行（不短路）");
        let executed = log.lock().unwrap();
        assert!(
            !executed.is_empty(),
            "含 // 的路径不应短路，后续 Hook 应执行，实际执行: {:?}",
            executed
        );
    }

    /// 验证 path 含 URL 编码 `..`（`%2e%2e`）时 WhitePathHook 不短路（FM-013 修复）。
    #[tokio::test]
    async fn white_path_url_encoded_traversal_not_short_circuited() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = WafHookChain::new();
        chain.register(Box::new(WhitePathHook::new(vec!["/api".to_string()])));
        chain.register(Box::new(RecordingHook {
            hook_name: "recorder",
            log: log.clone(),
        }));
        let ctx = make_ctx("/api/%2e%2e/admin", "GET", None, &[], &[]);
        let result = chain.check(&ctx).await;
        assert!(result.is_ok(), "含 %2e%2e 的路径应放行（不短路）");
        let executed = log.lock().unwrap();
        assert!(
            !executed.is_empty(),
            "含 %2e%2e 的路径不应短路，后续 Hook 应执行，实际执行: {:?}",
            executed
        );
    }

    /// 验证 path 含 URL 编码 `/`（`%2f`）时 WhitePathHook 不短路（FM-013 修复）。
    #[tokio::test]
    async fn white_path_url_encoded_slash_not_short_circuited() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = WafHookChain::new();
        chain.register(Box::new(WhitePathHook::new(vec!["/api".to_string()])));
        chain.register(Box::new(RecordingHook {
            hook_name: "recorder",
            log: log.clone(),
        }));
        let ctx = make_ctx("/api%2ftest", "GET", None, &[], &[]);
        let result = chain.check(&ctx).await;
        assert!(result.is_ok(), "含 %2f 的路径应放行（不短路）");
        let executed = log.lock().unwrap();
        assert!(
            !executed.is_empty(),
            "含 %2f 的路径不应短路，后续 Hook 应执行，实际执行: {:?}",
            executed
        );
    }

    /// 验证精确匹配白名单路径返回 AllowAndSkip（HIGH-001 修复）。
    #[tokio::test]
    async fn white_path_exact_match_returns_allow_and_skip() {
        let hook = WhitePathHook::new(vec!["/api".to_string()]);
        let ctx = make_ctx("/api", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(
            matches!(verdict, WafVerdict::AllowAndSkip),
            "精确匹配 /api 应返回 AllowAndSkip"
        );
    }

    /// 验证段前缀匹配白名单路径返回 AllowAndSkip（HIGH-001 修复）。
    #[tokio::test]
    async fn white_path_segment_match_returns_allow_and_skip() {
        let hook = WhitePathHook::new(vec!["/api".to_string()]);
        let ctx = make_ctx("/api/test", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(
            matches!(verdict, WafVerdict::AllowAndSkip),
            "段前缀匹配 /api/test 应返回 AllowAndSkip"
        );
    }

    /// 验证前缀混淆路径不匹配白名单（HIGH-001 修复）。
    ///
    /// `/api-v2/secret` 虽然以 `/api` 开头，但不是精确匹配也不是段前缀匹配，
    /// 应返回 Allow（不命中白名单）。
    #[tokio::test]
    async fn white_path_prefix_confusion_not_matched() {
        let hook = WhitePathHook::new(vec!["/api".to_string()]);
        let ctx = make_ctx("/api-v2/secret", "GET", None, &[], &[]);
        let verdict = hook.check(&ctx).await;
        assert!(
            matches!(verdict, WafVerdict::Allow),
            "前缀混淆 /api-v2/secret 不应命中 /api 白名单"
        );
    }

    // ========================================================================
    // 12. T-CONV-002: 双重编码边界测试（%252e）
    // ========================================================================

    /// 验证 `%252e` 双重编码被检测到。
    ///
    /// 当前实现检测 `%2e`（子串匹配）而非解码后检测，
    /// `%252e` 被捕获是子串匹配的副作用。
    #[tokio::test]
    async fn double_encoding_percent_252e_detected() {
        let mut chain = WafHookChain::new();
        chain.register(Box::new(DangerCharacterHook::new()));

        let ctx = crate::strategy::firewall::WafContext {
            path: "/api/%252e%252e/admin",
            method: "GET",
            host: Some("example.com"),
            headers: &[],
            params: &[],
        };

        let result = chain.check(&ctx).await;
        assert!(result.is_err(), "%252e 双重编码应被拦截");
    }
}
