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
/// 3. trim 前后空白
/// 4. 长度检查（按 char count）
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

    /// T235-17: Unicode 控制字符 U+200B (ZERO WIDTH SPACE) 不被 is_control() 识别，保留。
    /// 注：ZWSP 是 format 字符非 control，此测试验证 is_control 的行为边界。
    #[test]
    fn sanitize_keeps_zero_width_space() {
        let input = "ab\u{200B}cd";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "ab\u{200B}cd");
    }

    /// T235-18: 混合攻击 payload（null + 控制字符 + 前后空白）。
    #[test]
    fn sanitize_mixed_attack_payload() {
        let input = "  \0\x01admin\x02\0  ";
        let result = sanitize_input(input, 100).unwrap();
        assert_eq!(result, "admin");
    }
}
