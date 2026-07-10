//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! XSS 防护子模块。
//!
//! 提供 [`XssProtector`] 对 HTML 输入进行转义/白名单过滤，防止 XSS 攻击。零外部依赖。
//!
//! ## 设计
//!
//! - [`XssMode::EscapeAll`]：转义所有 HTML 特殊字符（`<` / `>` / `&` / `"` / `'`）
//! - [`XssMode::Whitelist`]：白名单内的标签保留原样（属性值中的特殊字符仍转义），
//!   非白名单标签全部转义，纯文本内容中的特殊字符也转义
//! - 转义顺序：`&` 必须最先转义，避免二次转义

/// XSS 防护模式枚举。
///
/// - [`EscapeAll`](Self::EscapeAll)：全量转义所有 HTML 特殊字符
/// - [`Whitelist`](Self::Whitelist)：仅保留白名单内的标签，其余转义
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XssMode {
    /// 全量转义模式：转义 `<` / `>` / `&` / `"` / `'`。
    EscapeAll,
    /// 白名单模式：保留指定的标签名，其余标签全部转义。
    ///
    /// 白名单标签的属性值中的特殊字符仍会转义。
    Whitelist(Vec<&'static str>),
}

/// XSS 防护器。
///
/// 持有 [`XssMode`] 配置，通过 [`sanitize`](Self::sanitize) 对 HTML 输入进行转义/过滤。
///
/// # 示例
///
/// ```ignore
/// use bulwark::secure::xss::{XssMode, XssProtector};
///
/// let p = XssProtector::new(XssMode::EscapeAll);
/// assert_eq!(p.sanitize("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;");
/// ```
pub struct XssProtector {
    /// 防护模式。
    mode: XssMode,
}

impl XssProtector {
    /// 创建 XSS 防护器。
    ///
    /// # 参数
    /// - `mode`: 防护模式（[`XssMode::EscapeAll`] 或 [`XssMode::Whitelist`]）。
    pub fn new(mode: XssMode) -> Self {
        Self { mode }
    }

    /// 对输入字符串进行 XSS 防护处理。
    ///
    /// 根据 [`XssMode`] 执行全量转义或白名单过滤，返回处理后的字符串。
    ///
    /// # 参数
    /// - `input`: 待处理的 HTML 输入。
    ///
    /// # 返回
    /// 处理后的安全字符串。
    pub fn sanitize(&self, input: &str) -> String {
        match &self.mode {
            XssMode::EscapeAll => {
                let mut out = String::with_capacity(input.len());
                escape_into(&mut out, input);
                out
            },
            XssMode::Whitelist(allowed) => sanitize_whitelist(input, allowed),
        }
    }
}

/// 将字符串中的 HTML 特殊字符转义并追加到 `out`。
///
/// 转义映射：`&`→`&amp;`、`<`→`&lt;`、`>`→`&gt;`、`"`→`&quot;`、`'`→`&#x27;`。
/// `&` 最先转义以避免二次转义。
fn escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
}

/// 解析从 `rest` 开头的 HTML 标签，返回 `(标签名, 是否闭合标签, 属性文本, 标签后的剩余字符串)`。
///
/// `rest` 必须以 `<` 开头。若无法解析为有效标签（无标签名或无闭合 `>`）返回 `None`。
fn parse_tag(rest: &str) -> Option<(&str, bool, &str, &str)> {
    let bytes = rest.as_bytes();
    if bytes.is_empty() || bytes[0] != b'<' {
        return None;
    }

    let mut pos = 1;
    let mut is_closing = false;
    if pos < bytes.len() && bytes[pos] == b'/' {
        is_closing = true;
        pos += 1;
    }

    let name_start = pos;
    if pos >= bytes.len() || !bytes[pos].is_ascii_alphabetic() {
        return None;
    }
    pos += 1;
    while pos < bytes.len() && bytes[pos].is_ascii_alphanumeric() {
        pos += 1;
    }
    let name = &rest[name_start..pos];

    let attrs_start = pos;
    while pos < bytes.len() && bytes[pos] != b'>' {
        pos += 1;
    }
    if pos >= bytes.len() {
        return None;
    }
    let attrs = &rest[attrs_start..pos];
    let after = &rest[pos + 1..];

    Some((name, is_closing, attrs, after))
}

/// 白名单模式：保留白名单内的标签（属性值仍转义），其余标签和纯文本中的特殊字符全部转义。
fn sanitize_whitelist(input: &str, allowed: &[&'static str]) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    while !rest.is_empty() {
        if rest.starts_with('<') {
            if let Some((name, is_closing, attrs, after)) = parse_tag(rest) {
                if allowed.contains(&name) {
                    out.push('<');
                    if is_closing {
                        out.push('/');
                    }
                    out.push_str(name);
                    escape_into(&mut out, attrs);
                    out.push('>');
                    rest = after;
                } else {
                    out.push_str("&lt;");
                    rest = &rest[1..];
                }
            } else {
                out.push_str("&lt;");
                rest = &rest[1..];
            }
        } else {
            let chunk_end = rest.find('<').unwrap_or(rest.len());
            escape_into(&mut out, &rest[..chunk_end]);
            rest = &rest[chunk_end..];
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // EscapeAll 模式测试（T007）
    // ========================================================================

    /// T007-1: EscapeAll 转义尖括号：`<script>alert(1)</script>` → `&lt;script&gt;alert(1)&lt;/script&gt;`。
    #[test]
    fn escape_all_replaces_angle_brackets() {
        let p = XssProtector::new(XssMode::EscapeAll);
        assert_eq!(
            p.sanitize("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
    }

    /// T007-2: EscapeAll 转义 & 符号：`a & b` → `a &amp; b`。
    #[test]
    fn escape_all_replaces_ampersand() {
        let p = XssProtector::new(XssMode::EscapeAll);
        assert_eq!(p.sanitize("a & b"), "a &amp; b");
    }

    /// T007-3: EscapeAll 转义双引号：`"quote"` → `&quot;quote&quot;`。
    #[test]
    fn escape_all_replaces_double_quote() {
        let p = XssProtector::new(XssMode::EscapeAll);
        assert_eq!(p.sanitize("\"quote\""), "&quot;quote&quot;");
    }

    /// T007-4: EscapeAll 转义单引号：`'single'` → `&#x27;single&#x27;`。
    #[test]
    fn escape_all_replaces_single_quote() {
        let p = XssProtector::new(XssMode::EscapeAll);
        assert_eq!(p.sanitize("'single'"), "&#x27;single&#x27;");
    }

    /// T007-5: EscapeAll 处理空输入：`` → ``。
    #[test]
    fn escape_all_handles_empty_input() {
        let p = XssProtector::new(XssMode::EscapeAll);
        assert_eq!(p.sanitize(""), "");
    }

    // ========================================================================
    // Whitelist 模式测试（T008）
    // ========================================================================

    /// T008-1: 白名单保留允许的标签，转义非白名单标签。
    /// 白名单 `["b","i"]`，输入 `<b>bold</b><script>x</script>`
    /// → `<b>bold</b>&lt;script&gt;x&lt;/script&gt;`。
    #[test]
    fn whitelist_keeps_allowed_tags() {
        let p = XssProtector::new(XssMode::Whitelist(vec!["b", "i"]));
        assert_eq!(
            p.sanitize("<b>bold</b><script>x</script>"),
            "<b>bold</b>&lt;script&gt;x&lt;/script&gt;"
        );
    }

    /// T008-2: 白名单标签的属性值中的特殊字符也要转义。
    /// 白名单 `["b"]`，输入 `<b onclick="x">text</b>`
    /// → `<b onclick=&quot;x&quot;>text</b>`。
    #[test]
    fn whitelist_escapes_attributes() {
        let p = XssProtector::new(XssMode::Whitelist(vec!["b"]));
        assert_eq!(
            p.sanitize("<b onclick=\"x\">text</b>"),
            "<b onclick=&quot;x&quot;>text</b>"
        );
    }

    /// T008-3: 白名单标签内的纯文本内容中的特殊字符也要转义。
    /// 白名单 `["b"]`，输入 `<b>a & b</b>` → `<b>a &amp; b</b>`。
    #[test]
    fn whitelist_escapes_text_content() {
        let p = XssProtector::new(XssMode::Whitelist(vec!["b"]));
        assert_eq!(p.sanitize("<b>a & b</b>"), "<b>a &amp; b</b>");
    }

    /// T008-4: 白名单模式处理空输入：`` → ``。
    #[test]
    fn whitelist_empty_returns_empty() {
        let p = XssProtector::new(XssMode::Whitelist(vec!["b"]));
        assert_eq!(p.sanitize(""), "");
    }
}
