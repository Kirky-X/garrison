//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! XSS 防护子模块。
//!
//! 提供 [`XssProtector`](crate::secure::xss::XssProtector) 对 HTML 输入进行转义/白名单过滤，防止 XSS 攻击。零外部依赖。
//!
//! ## 设计
//!
//! - [`XssMode::EscapeAll`](crate::secure::xss::XssMode::EscapeAll)：转义所有 HTML 特殊字符（`<` / `>` / `&` / `"` / `'`）
//! - [`XssMode::Whitelist`](crate::secure::xss::XssMode::Whitelist)：白名单内的标签保留原样（属性值中的特殊字符仍转义），
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
/// use garrison::secure::xss::{XssMode, XssProtector};
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

    /// 对 Owned 字符串进行 XSS 防护处理（避免重复分配）。
    ///
    /// 若输入不包含 HTML 特殊字符（`<` / `>` / `&` / `"` / `'`），直接返回原 String。
    /// 否则调用 `sanitize` 重新分配。
    ///
    /// # 参数
    /// - `input`: 待处理的 HTML 输入（Owned String）。
    ///
    /// # 返回
    /// 处理后的安全字符串。
    pub fn sanitize_owned(&self, input: String) -> String {
        let needs_escape = input
            .chars()
            .any(|c| matches!(c, '<' | '>' | '&' | '"' | '\''));
        if !needs_escape {
            return input;
        }
        self.sanitize(&input)
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

/// 从属性段中移除 `on*` 事件处理器属性。
///
/// 扫描属性字符串，识别 `on` 开头后跟字母数字再跟 `=` 的属性名，移除整个
/// `name=value` 片段。支持三种值形式：双引号、单引号、无引号（到空白为止）。
///
/// 不引入 regex crate，使用字节扫描实现。
fn strip_event_handlers(attrs: &str) -> String {
    let bytes = attrs.as_bytes();
    let mut out = String::with_capacity(attrs.len());
    let mut i = 0;
    let mut last_copy = 0;

    while i < bytes.len() {
        let is_attr_start = i == 0 || bytes[i - 1].is_ascii_whitespace();
        if is_attr_start
            && i + 2 <= bytes.len()
            && bytes[i].eq_ignore_ascii_case(&b'o')
            && bytes[i + 1].eq_ignore_ascii_case(&b'n')
        {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_alphanumeric() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' {
                out.push_str(&attrs[last_copy..i]);
                j += 1;
                if j < bytes.len() {
                    match bytes[j] {
                        b'"' => {
                            j += 1;
                            while j < bytes.len() && bytes[j] != b'"' {
                                j += 1;
                            }
                            if j < bytes.len() {
                                j += 1;
                            }
                        },
                        b'\'' => {
                            j += 1;
                            while j < bytes.len() && bytes[j] != b'\'' {
                                j += 1;
                            }
                            if j < bytes.len() {
                                j += 1;
                            }
                        },
                        _ => {
                            while j < bytes.len() && !bytes[j].is_ascii_whitespace() {
                                j += 1;
                            }
                        },
                    }
                }
                last_copy = j;
                i = j;
                continue;
            }
        }
        i += 1;
    }

    out.push_str(&attrs[last_copy..]);
    out
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
                    // 先 strip event handlers，再 strip dangerous URI（顺序保证 on* 属性
                    // 被移除后，剩余 href/src/xlink:href 中的危险 scheme 被替换为 #）
                    let cleaned = strip_event_handlers(attrs);
                    let cleaned = strip_dangerous_uri(&cleaned);
                    escape_into(&mut out, &cleaned);
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

/// 从属性段中移除危险 URI scheme。
///
/// 扫描 `href=`/`src=`/`xlink:href=` 属性值，若 scheme 不在安全白名单
/// （`http`/`https`/`mailto`/`#`/`/`/`./`/`../`/相对路径无 scheme）则将值替换为 `#`。
/// 防止 `javascript:`/`data:`/`vbscript:` 等 URI scheme 执行 XSS。
///
/// # 安全白名单（大小写不敏感）
///
/// - `http://` / `https://`：标准 HTTP(S) URL
/// - `mailto:`：邮件协议
/// - `#`：锚点
/// - `/`：绝对路径
/// - `./` / `../`：相对路径
/// - 无 scheme（不以 `scheme:` 开头）：相对路径或无 scheme 的 URL
///
/// # 处理的绕过场景
///
/// - 大小写绕过：`JavaScript:`/`JAVASCRIPT:`/`java\tscript:`（前导空白和控制字符）
/// - 前导空白：` javascript:alert(1)`
/// - 三种引号形式：双引号、单引号、无引号
///
/// # 实现策略
///
/// 参照 `strip_event_handlers` 的字节扫描模式，识别属性名后跟 `=`，提取属性值，
/// strip 前导空白和控制字符后检查 scheme。
fn strip_dangerous_uri(attrs: &str) -> String {
    let bytes = attrs.as_bytes();
    let mut out = String::with_capacity(attrs.len());
    let mut i = 0;
    let mut last_copy = 0;

    /// 检查从 `bytes[i..]` 开始是否匹配目标属性名（大小写不敏感），后跟 `=` 或空白+`=`。
    /// 返回匹配后的位置（指向 `=` 之后）或 `None`。
    fn match_attr_name(bytes: &[u8], i: usize, target: &[u8]) -> Option<usize> {
        if i + target.len() > bytes.len() {
            return None;
        }
        for (k, &c) in target.iter().enumerate() {
            if !bytes[i + k].eq_ignore_ascii_case(&c) {
                return None;
            }
        }
        // target 匹配后，跳过空白，然后期望 `=`
        let mut j = i + target.len();
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'=' {
            Some(j + 1) // 指向 `=` 之后
        } else {
            None
        }
    }

    /// 判断 URI scheme 是否安全（白名单内）。
    /// `value` 是 strip 前导空白和控制字符后的属性值。
    fn is_safe_uri(value: &str) -> bool {
        let lower = value.to_ascii_lowercase();
        // 锚点、绝对路径、相对路径
        if lower.starts_with('#')
            || lower.starts_with('/')
            || lower.starts_with("./")
            || lower.starts_with("../")
        {
            return true;
        }
        // 标准 scheme 白名单
        if lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("mailto:")
        {
            return true;
        }
        // 无 scheme（不含 `:`）视为相对路径，安全
        // 注意：`javascript:`/`data:`/`vbscript:` 等含 `:` 且非白名单 scheme → 不安全
        if let Some(colon_pos) = lower.find(':') {
            // 检查 `:` 前是否有 `/`（若有 `/` 在前则是相对路径如 `/path:to`，安全）
            if let Some(slash_pos) = lower.find('/') {
                if slash_pos < colon_pos {
                    return true; // `/` 在 `:` 前，相对路径
                }
            }
            // `:` 在前且非白名单 scheme → 不安全
            false
        } else {
            true // 无 `:`，相对路径或 fragment
        }
    }

    while i < bytes.len() {
        let is_attr_start = i == 0 || bytes[i - 1].is_ascii_whitespace();
        if is_attr_start {
            // 尝试匹配 href= / src= / xlink:href=
            let target_pos = match_attr_name(bytes, i, b"href")
                .or_else(|| match_attr_name(bytes, i, b"src"))
                .or_else(|| match_attr_name(bytes, i, b"xlink:href"));
            if let Some(value_start) = target_pos {
                // 找到属性值，提取值范围
                out.push_str(&attrs[last_copy..value_start]);
                let (value_end, value_str) = extract_attr_value(bytes, value_start);
                // strip 前导空白和控制字符（0x00-0x1F + 0x7F），再 strip 引号
                // 注意：value_str 可能带引号（如 `"https://example.com"`），
                // is_safe_uri 需要检查不带引号的纯 URI
                let stripped = value_str
                    .trim_start_matches(|c: char| c.is_ascii_whitespace() || c.is_ascii_control());
                let stripped = stripped.trim_matches(|c| c == '"' || c == '\'');
                if is_safe_uri(stripped) {
                    // 安全：保留原值（包含引号）
                    out.push_str(&attrs[value_start..value_end]);
                } else {
                    // 不安全：替换值为 `#`（保留引号形式）
                    // 根据原始引号形式决定输出
                    if value_start < bytes.len() && bytes[value_start] == b'"' {
                        out.push_str("\"#\"");
                    } else if value_start < bytes.len() && bytes[value_start] == b'\'' {
                        out.push_str("'#'");
                    } else {
                        out.push('#');
                    }
                }
                last_copy = value_end;
                i = value_end;
                continue;
            }
        }
        i += 1;
    }

    out.push_str(&attrs[last_copy..]);
    out
}

/// 从 `bytes[start..]` 开始提取属性值，返回 `(值结束位置, 值字符串)`。
///
/// 支持三种形式：
/// - 双引号：`"value"` → 返回 `"value"` 全长（含引号）
/// - 单引号：`'value'` → 返回 `'value'` 全长（含引号）
/// - 无引号：`value` → 到空白为止
fn extract_attr_value(bytes: &[u8], start: usize) -> (usize, &str) {
    if start >= bytes.len() {
        return (start, "");
    }
    match bytes[start] {
        b'"' => {
            let mut j = start + 1;
            while j < bytes.len() && bytes[j] != b'"' {
                j += 1;
            }
            if j < bytes.len() {
                j += 1; // 包含闭合引号
            }
            (j, std::str::from_utf8(&bytes[start..j]).unwrap_or(""))
        },
        b'\'' => {
            let mut j = start + 1;
            while j < bytes.len() && bytes[j] != b'\'' {
                j += 1;
            }
            if j < bytes.len() {
                j += 1;
            }
            (j, std::str::from_utf8(&bytes[start..j]).unwrap_or(""))
        },
        _ => {
            let mut j = start;
            while j < bytes.len() && !bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            (j, std::str::from_utf8(&bytes[start..j]).unwrap_or(""))
        },
    }
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
    /// 白名单 `["b"]`，输入 `<b class="x">text</b>`
    /// → `<b class=&quot;x&quot;>text</b>`。
    #[test]
    fn whitelist_escapes_attributes() {
        let p = XssProtector::new(XssMode::Whitelist(vec!["b"]));
        assert_eq!(
            p.sanitize("<b class=\"x\">text</b>"),
            "<b class=&quot;x&quot;>text</b>"
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

    /// T008-5: 白名单标签的事件处理器属性（on*）应被移除。
    /// 输入 `<b onclick=alert(1)>text</b>`，onclick 不应出现在输出中。
    #[test]
    fn whitelist_strips_event_handler_attributes() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["b"]));
        let result = protector.sanitize(r#"<b onclick=alert(1)>text</b>"#);
        assert!(
            !result.contains("onclick"),
            "event handler attribute should be stripped, got: {}",
            result
        );
    }

    /// T008-6: 白名单标签的双引号包裹事件处理器属性也应被移除。
    #[test]
    fn whitelist_strips_quoted_event_handler_attributes() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["b"]));
        let result = protector.sanitize(r#"<b onclick="alert(1)">text</b>"#);
        assert!(
            !result.contains("onclick"),
            "quoted event handler attribute should be stripped, got: {}",
            result
        );
    }

    /// T008-7: 白名单标签的单引号包裹事件处理器属性也应被移除。
    #[test]
    fn whitelist_strips_single_quoted_event_handler_attributes() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["b"]));
        let result = protector.sanitize(r#"<b onclick='alert(1)'>text</b>"#);
        assert!(
            !result.contains("onclick"),
            "single-quoted event handler attribute should be stripped, got: {}",
            result
        );
    }

    /// 大写 ONCLICK 事件处理器应被移除。
    #[test]
    fn whitelist_strips_uppercase_event_handler() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["b"]));
        let result = protector.sanitize(r#"<b ONCLICK=alert(1)>text</b>"#);
        assert!(
            !result.to_lowercase().contains("onclick"),
            "uppercase ONCLICK should be stripped, got: {}",
            result
        );
    }

    /// 混合大小写 OnClick 事件处理器应被移除。
    #[test]
    fn whitelist_strips_mixedcase_event_handler() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["b"]));
        let result = protector.sanitize(r#"<b OnClick=alert(1)>text</b>"#);
        assert!(
            !result.to_lowercase().contains("onclick"),
            "mixed-case OnClick should be stripped, got: {}",
            result
        );
    }

    /// 混合大小写 oNsUbMiT 事件处理器应被移除。
    #[test]
    fn whitelist_strips_mixedcase_onsubmit() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["b"]));
        let result = protector.sanitize(r#"<b oNsUbMiT=alert(1)>text</b>"#);
        assert!(
            !result.to_lowercase().contains("onsubmit"),
            "mixed-case oNsUbMiT should be stripped, got: {}",
            result
        );
    }

    // ========================================================================
    // sanitize_owned 测试
    // ========================================================================

    /// sanitize_owned 无特殊字符直接返回原 String（零分配）。
    #[test]
    fn sanitize_owned_no_escape_returns_original() {
        let p = XssProtector::new(XssMode::EscapeAll);
        let input = String::from("hello world");
        let result = p.sanitize_owned(input);
        assert_eq!(result, "hello world");
    }

    /// sanitize_owned 有特殊字符转义。
    #[test]
    fn sanitize_owned_escapes_special_chars() {
        let p = XssProtector::new(XssMode::EscapeAll);
        let result = p.sanitize_owned(String::from("<script>alert(1)</script>"));
        assert_eq!(result, "&lt;script&gt;alert(1)&lt;/script&gt;");
    }

    /// sanitize_owned 空字符串返回空字符串。
    #[test]
    fn sanitize_owned_empty_string() {
        let p = XssProtector::new(XssMode::EscapeAll);
        let result = p.sanitize_owned(String::new());
        assert_eq!(result, "");
    }

    // ========================================================================
    // strip_dangerous_uri 测试
    // ========================================================================

    /// `javascript:` URI scheme 在 href 中应被替换为 `#`。
    #[test]
    fn whitelist_strips_javascript_uri_in_href() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a href="javascript:alert(1)">click</a>"#);
        assert!(
            !result.to_lowercase().contains("javascript"),
            "javascript: scheme 应被替换为 #，实际: {}",
            result
        );
        // escape_into 会将 " 转义为 &quot;，故 href 值为 &quot;#&quot;
        assert!(result.contains("#"), "href 值应含 #，实际: {}", result);
    }

    /// `JavaScript:` 大小写绕过应被替换为 `#`。
    #[test]
    fn whitelist_strips_mixedcase_javascript_uri() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a href="JavaScript:alert(1)">click</a>"#);
        assert!(
            !result.to_lowercase().contains("javascript"),
            "JavaScript: 大小写绕过应被替换为 #，实际: {}",
            result
        );
    }

    /// `JAVASCRIPT:` 全大写绕过应被替换为 `#`。
    #[test]
    fn whitelist_strips_uppercase_javascript_uri() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a href="JAVASCRIPT:alert(1)">click</a>"#);
        assert!(
            !result.to_lowercase().contains("javascript"),
            "JAVASCRIPT: 全大写应被替换为 #，实际: {}",
            result
        );
    }

    /// 前导空白的 `javascript:` 应被替换为 `#`。
    #[test]
    fn whitelist_strips_javascript_uri_with_leading_whitespace() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a href=" javascript:alert(1)">click</a>"#);
        assert!(
            !result.to_lowercase().contains("javascript"),
            "前导空白的 javascript: 应被替换为 #，实际: {}",
            result
        );
    }

    /// `data:` URI scheme 应被替换为 `#`。
    #[test]
    fn whitelist_strips_data_uri_scheme() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result =
            protector.sanitize(r#"<a href="data:text/html,<script>alert(1)</script>">click</a>"#);
        assert!(
            !result.to_lowercase().contains("data:"),
            "data: scheme 应被替换为 #，实际: {}",
            result
        );
    }

    /// `vbscript:` URI scheme 应被替换为 `#`。
    #[test]
    fn whitelist_strips_vbscript_uri_scheme() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a href="vbscript:msgbox(1)">click</a>"#);
        assert!(
            !result.to_lowercase().contains("vbscript"),
            "vbscript: scheme 应被替换为 #，实际: {}",
            result
        );
    }

    /// 合法的 `https://` URL 应保留原样。
    #[test]
    fn whitelist_keeps_https_url() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a href="https://example.com">click</a>"#);
        assert!(
            result.contains("https://example.com"),
            "合法 https:// URL 应保留，实际: {}",
            result
        );
    }

    /// 合法的 `http://` URL 应保留原样。
    #[test]
    fn whitelist_keeps_http_url() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a href="http://example.com">click</a>"#);
        assert!(
            result.contains("http://example.com"),
            "合法 http:// URL 应保留，实际: {}",
            result
        );
    }

    /// 合法的 `mailto:` 应保留原样。
    #[test]
    fn whitelist_keeps_mailto_uri() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a href="mailto:user@example.com">email</a>"#);
        assert!(
            result.contains("mailto:user@example.com"),
            "合法 mailto: 应保留，实际: {}",
            result
        );
    }

    /// 锚点 `#section` 应保留原样。
    #[test]
    fn whitelist_keeps_anchor_uri() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r##"<a href="#section">jump</a>"##);
        // escape_into 会将 " 转义为 &quot;，故 href 值为 &quot;#section&quot;
        assert!(
            result.contains("#section"),
            "锚点 #section 应保留，实际: {}",
            result
        );
    }

    /// 绝对路径 `/path/to/resource` 应保留原样。
    #[test]
    fn whitelist_keeps_absolute_path() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a href="/path/to/resource">link</a>"#);
        assert!(
            result.contains("/path/to/resource"),
            "绝对路径应保留，实际: {}",
            result
        );
    }

    /// 相对路径 `./relative` 应保留原样。
    #[test]
    fn whitelist_keeps_relative_path() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a href="./relative">link</a>"#);
        assert!(
            result.contains("./relative"),
            "相对路径 ./relative 应保留，实际: {}",
            result
        );
    }

    /// `<img src="javascript:alert(1)">` 的 src 也应被替换为 `#`。
    #[test]
    fn whitelist_strips_javascript_uri_in_src() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["img"]));
        let result = protector.sanitize(r#"<img src="javascript:alert(1)">"#);
        assert!(
            !result.to_lowercase().contains("javascript"),
            "src 中的 javascript: 应被替换为 #，实际: {}",
            result
        );
    }

    /// 单引号包裹的 `javascript:` 也应被替换为 `#`。
    #[test]
    fn whitelist_strips_javascript_uri_single_quoted() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a href='javascript:alert(1)'>click</a>"#);
        assert!(
            !result.to_lowercase().contains("javascript"),
            "单引号 javascript: 应被替换为 #，实际: {}",
            result
        );
    }

    /// 无引号包裹的 `javascript:` 也应被替换为 `#`。
    #[test]
    fn whitelist_strips_javascript_uri_unquoted() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a href=javascript:alert(1)>click</a>"#);
        assert!(
            !result.to_lowercase().contains("javascript"),
            "无引号 javascript: 应被替换为 #，实际: {}",
            result
        );
    }

    /// 大写 HREF 属性名也应被识别。
    #[test]
    fn whitelist_strips_javascript_uri_uppercase_attr() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a HREF="javascript:alert(1)">click</a>"#);
        assert!(
            !result.to_lowercase().contains("javascript"),
            "大写 HREF 中的 javascript: 应被替换为 #，实际: {}",
            result
        );
    }

    /// 混合大小写 `Href` 属性名也应被识别。
    #[test]
    fn whitelist_strips_javascript_uri_mixedcase_attr() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector.sanitize(r#"<a Href="javascript:alert(1)">click</a>"#);
        assert!(
            !result.to_lowercase().contains("javascript"),
            "混合大小写 Href 中的 javascript: 应被替换为 #，实际: {}",
            result
        );
    }

    /// 多个属性中混合危险 URI，仅危险 URI 被替换，其他属性保留。
    #[test]
    fn whitelist_strips_only_dangerous_uri_keeps_safe_attrs() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["a"]));
        let result = protector
            .sanitize(r#"<a href="javascript:alert(1)" title="click me" class="link">text</a>"#);
        assert!(
            !result.to_lowercase().contains("javascript"),
            "javascript: 应被替换，实际: {}",
            result
        );
        assert!(
            result.contains("click me"),
            "title 属性应保留，实际: {}",
            result
        );
        assert!(
            result.contains("link"),
            "class 属性应保留，实际: {}",
            result
        );
    }

    /// 同一标签中同时有安全和不安全 URI，仅不安全 URI 被替换。
    /// 注意：HTML 规范中同名属性只取第一个，但这里测试 src（安全）和 href（不安全）共存。
    #[test]
    fn whitelist_strips_only_dangerous_uri_keeps_safe_uri() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["img"]));
        let result = protector
            .sanitize(r#"<img src="https://safe.com/img.png" data-href="javascript:alert(1)">"#);
        // src 是安全 URL，应保留
        assert!(
            result.contains("https://safe.com/img.png"),
            "安全 src 应保留，实际: {}",
            result
        );
        // data-href 不是 href/src/xlink:href，不会被 strip_dangerous_uri 处理
        // 但 javascript: 在 data-href 中，不应触发 strip（因为不是目标属性）
        // 这个测试验证 strip_dangerous_uri 只处理 href/src/xlink:href
    }

    /// `xlink:href` 属性（SVG 中使用）的危险 URI 也应被替换。
    #[test]
    fn whitelist_strips_javascript_uri_in_xlink_href() {
        let protector = XssProtector::new(XssMode::Whitelist(vec!["use"]));
        let result = protector.sanitize(r#"<use xlink:href="javascript:alert(1)">"#);
        assert!(
            !result.to_lowercase().contains("javascript"),
            "xlink:href 中的 javascript: 应被替换为 #，实际: {}",
            result
        );
    }
}
