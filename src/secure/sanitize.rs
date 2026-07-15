//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 通用输入消毒子模块。
//!
//! 提供 `sanitize_input` 对用户输入进行通用消毒：
//! - 移除 null 字节（`\0`）防止 C 字符串截断攻击
//! - 移除控制字符（保留 `\n` / `\r` / `\t` 以支持多行文本）
//! - 长度限制（防 DoS）
//! - 前后空白 trim
//!
//! 与 [`XssProtector`](crate::secure::xss::XssProtector) 的区别：
//! - `XssProtector` 针对 HTML 输入进行转义/白名单过滤（XSS 专用）
//! - `sanitize_input` 针对任意文本输入进行通用消毒（非 HTML 专用）
//!
//! # 示例
//!
//! ```ignore
//! use bulwark::secure::sanitize::sanitize_input;
//!
//! let cleaned = sanitize_input("  hello\0world  ", 100).unwrap();
//! assert_eq!(cleaned, "helloworld");
//! ```

use crate::error::{BulwarkError, BulwarkResult};

/// 检测 Unicode 格式字符（Cf 类）和分隔符字符（Zl/Zp 类）。
///
/// 这些字符在大多数渲染环境中不可见，但会影响字符串比较、数据库查询和日志渲染，
/// 可被用于钓鱼、显示欺骗和日志注入攻击。
///
/// 覆盖范围：
/// - Cf（Format）：U+00AD, U+0600-0605, U+061C, U+06DD, U+070F, U+180E,
///   U+200B-200F, U+202A-202E, U+2060-206F, U+FEFF, U+FFF9-FFFB
/// - Zl（Line Separator）：U+2028
/// - Zp（Paragraph Separator）：U+2029
fn is_unicode_format_or_separator(c: char) -> bool {
    let cp = c as u32;
    // Zl: Line Separator
    if cp == 0x2028 {
        return true;
    }
    // Zp: Paragraph Separator
    if cp == 0x2029 {
        return true;
    }
    // Cf: Format characters（安全相关的高频子集）
    matches!(cp,
        0x00AD |        // Soft Hyphen
        0x0600..=0x0605 | // Arabic number signs
        0x061C |         // Arabic Letter Mark
        0x06DD |         // Arabic End of Ayah
        0x070F |         // Syriac Abbreviation Mark
        0x180E |         // Mongolian Vowel Separator
        0x200B..=0x200F | // Zero Width Space/Non-Joiner/Joiner, LRM, RLM
        0x202A..=0x202E | // Bidi controls (LRE, RLE, PDF, LRO, RLO)
        0x2060..=0x206F | // Word Joiner, Invisible operators, deprecated format chars
        0xFEFF |         // BOM / Zero Width No-Break Space
        0xFFF9..=0xFFFB   // Interlinear annotation
    )
}

/// 通用输入消毒：移除 null 字节、控制字符，trim 前后空白，限制长度。
///
/// # 参数
/// - `input`: 待消毒的用户输入
/// - `max_len`: 最大允许长度（按 char count，非字节）
///
/// # 返回
/// - `Ok(String)`: 消毒后的字符串
/// - `Err(BulwarkError::InvalidParam)`: 输入长度超过 `max_len`
///
/// # 消毒规则
/// 1. 移除 null 字节（`\0`）— 防止 C 字符串截断
/// 2. 移除控制字符（U+0000..=U+001F 除 `\t` `\n` `\r`，及 U+007F DEL）
/// 3. 移除 Unicode 格式字符（Cf 类）和分隔符字符（Zl/Zp 类）— 防止零宽字符绕过、BOM 绕过、日志注入
/// 4. trim 前后空白
/// 5. 长度检查（按 char count）
///
/// # 示例
///
/// ```ignore
/// use bulwark::secure::sanitize::sanitize_input;
///
/// // 移除 null 字节
/// assert_eq!(sanitize_input("ab\0cd", 100).unwrap(), "abcd");
///
/// // 移除控制字符（保留 \n \r \t）
/// assert_eq!(sanitize_input("a\x01b\x02c", 100).unwrap(), "abc");
///
/// // trim 前后空白
/// assert_eq!(sanitize_input("  hello  ", 100).unwrap(), "hello");
///
/// // 长度超限返回错误
/// assert!(sanitize_input("hello world", 5).is_err());
/// ```
pub fn sanitize_input(input: &str, max_len: usize) -> BulwarkResult<String> {
    // 预分配容量（最坏情况：全部保留）
    let mut cleaned = String::with_capacity(input.len());

    for c in input.chars() {
        // 移除 null 字节
        if c == '\0' {
            continue;
        }
        // 移除控制字符（保留 \t \n \r）
        if c.is_control() && c != '\t' && c != '\n' && c != '\r' {
            continue;
        }
        // 移除 Unicode 格式字符（Cf）和分隔符字符（Zl/Zp）
        // 防止零宽字符绕过比较、BOM 绕过前缀检查、行分隔符注入日志
        if is_unicode_format_or_separator(c) {
            continue;
        }
        cleaned.push(c);
    }

    // trim 前后空白
    let trimmed = cleaned.trim();

    // 长度检查（按 char count）
    let char_count = trimmed.chars().count();
    if char_count > max_len {
        return Err(BulwarkError::InvalidParam(format!(
            "输入长度 {} 超过最大限制 {}",
            char_count, max_len
        )));
    }

    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // 正常用例（T235）
    // ========================================================================

    /// T235-1: 普通字符串原样返回（trim 后）。
    #[test]
    fn sanitize_normal_string() {
        let result = sanitize_input("hello world", 100).unwrap();
        assert_eq!(result, "hello world");
    }

    /// T235-2: trim 前后空白。
    #[test]
    fn sanitize_trims_whitespace() {
        let result = sanitize_input("  hello  ", 100).unwrap();
        assert_eq!(result, "hello");
    }

    /// T235-3: 移除 null 字节。
    #[test]
    fn sanitize_removes_null_bytes() {
        let result = sanitize_input("ab\0cd", 100).unwrap();
        assert_eq!(result, "abcd");
    }

    /// T235-4: 移除控制字符（除 \t \n \r）。
    #[test]
    fn sanitize_removes_control_chars() {
        let input = "a\x01b\x02c\x03d";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "abcd");
    }

    /// T235-5: 保留 \t \n \r。
    #[test]
    fn sanitize_keeps_tab_newline_carriage_return() {
        let input = "line1\nline2\r\n\ttabbed";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "line1\nline2\r\n\ttabbed");
    }

    /// T235-6: 移除 DEL 字符（U+007F）。
    #[test]
    fn sanitize_removes_del_char() {
        let input = "ab\x7Fcd";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "abcd");
    }

    /// VULN-0017 修复: 移除零宽空格（U+200B）。
    #[test]
    fn sanitize_removes_zero_width_space() {
        let input = "admin\u{200B}@example.com";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "admin@example.com", "U+200B 应被移除");
    }

    /// VULN-0017 修复: 移除 BOM（U+FEFF）。
    #[test]
    fn sanitize_removes_bom() {
        let input = "\u{FEFF}admin";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "admin", "U+FEFF BOM 应被移除");
    }

    /// VULN-0017 修复: 移除行分隔符（U+2028）防止日志注入。
    #[test]
    fn sanitize_removes_line_separator() {
        let input = "log entry\u{2028}injected entry";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "log entryinjected entry", "U+2028 应被移除");
    }

    /// VULN-0017 修复: 移除段落分隔符（U+2029）。
    #[test]
    fn sanitize_removes_paragraph_separator() {
        let input = "para1\u{2029}para2";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "para1para2", "U+2029 应被移除");
    }

    /// VULN-0017 修复: 移除零宽连接符（U+200D）和非连接符（U+200C）。
    #[test]
    fn sanitize_removes_zero_width_joiners() {
        let input = "a\u{200C}b\u{200D}c";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "abc", "U+200C 和 U+200D 应被移除");
    }

    /// VULN-0017 修复: 移除双向格式控制字符（U+202A-202E）。
    #[test]
    fn sanitize_removes_bidi_controls() {
        let input = "hello\u{202E}world";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "helloworld", "U+202E (RLO) 应被移除");
    }

    /// T235-7: 空输入返回空字符串。
    #[test]
    fn sanitize_empty_input() {
        let result = sanitize_input("", 100).unwrap();
        assert_eq!(result, "");
    }

    /// T235-8: 全空白输入返回空字符串。
    #[test]
    fn sanitize_all_whitespace_returns_empty() {
        let result = sanitize_input("   \t  \n  ", 100).unwrap();
        assert_eq!(result, "");
    }

    // ========================================================================
    // 长度限制（T235）
    // ========================================================================

    /// T235-9: 长度等于 max_len 通过。
    #[test]
    fn sanitize_len_equal_max_passes() {
        let result = sanitize_input("hello", 5).unwrap();
        assert_eq!(result, "hello");
    }

    /// T235-10: 长度超过 max_len 返回 InvalidParam 错误。
    #[test]
    fn sanitize_len_exceeds_max_returns_error() {
        let result = sanitize_input("hello world", 5);
        assert!(matches!(result, Err(BulwarkError::InvalidParam(_))));
    }

    /// T235-11: 长度按 char count 计算（非字节），多字节字符正确处理。
    #[test]
    fn sanitize_len_counts_chars_not_bytes() {
        // 3 个中文字符 = 9 字节，但 char count = 3
        let result = sanitize_input("你好吗", 3).unwrap();
        assert_eq!(result, "你好吗");
    }

    /// T235-12: max_len = 0 只允许空字符串。
    #[test]
    fn sanitize_max_len_zero_only_empty() {
        let result = sanitize_input("", 0).unwrap();
        assert_eq!(result, "");
    }

    /// T235-13: max_len = 0 拒绝非空输入。
    #[test]
    fn sanitize_max_len_zero_rejects_nonempty() {
        let result = sanitize_input("a", 0);
        assert!(matches!(result, Err(BulwarkError::InvalidParam(_))));
    }

    // ========================================================================
    // 边界用例（T235）
    // ========================================================================

    /// T235-14: 消毒后再检查长度（null 字节移除后不超限）。
    #[test]
    fn sanitize_then_length_check() {
        // 输入 6 个字符（含 1 个 null），消毒后 5 个字符，max_len=5 通过
        let result = sanitize_input("abcd\0e", 5).unwrap();
        assert_eq!(result, "abcde");
    }

    /// T235-15: 消毒后超限仍返回错误（trim 后仍超长）。
    #[test]
    fn sanitize_after_trim_exceeds_returns_error() {
        let result = sanitize_input("  hello world  ", 5);
        assert!(matches!(result, Err(BulwarkError::InvalidParam(_))));
    }

    /// T235-16: Unicode 控制字符 U+0085 (NEL) 被移除。
    #[test]
    fn sanitize_removes_unicode_control_nel() {
        let input = "ab\u{0085}cd";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "abcd");
    }

    /// T235-17: VULN-0017 修复后，U+200B (ZERO WIDTH SPACE) 作为 Cf 类字符被移除。
    /// 旧行为保留 ZWSP，新行为移除以防止 Unicode 同形/绕过攻击。
    #[test]
    fn sanitize_keeps_zero_width_space() {
        let input = "ab\u{200B}cd";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "abcd");
    }

    /// T235-18: 混合攻击 payload（null + 控制字符 + 前后空白）。
    #[test]
    fn sanitize_mixed_attack_payload() {
        let input = "  \0\x01admin\x02\0  ";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "admin");
    }
}
