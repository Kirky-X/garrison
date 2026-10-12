// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 社交登录 URL 编码工具：对查询参数值做百分号编码，保留 RFC 3986 unreserved 字符（字母、数字、`-`、`_`、`.`、`~`）。
//!
//! 独立于 `percent-encoding` crate 的最小实现，避免 `utf8_percent_encode` + `AsciiSet` 配置复杂度；
//! `protocol::oauth2` 则直接使用 `percent-encoding`。

/// 对查询参数值进行百分号编码。
///
/// 保留 RFC 3986 unreserved 字符（字母、数字、`-`、`_`、`.`、`~`），其他字节按 `%XX`（大写十六进制）编码。
///
/// # 示例
///
/// ```ignore
/// use garrison::protocol::social::urlencoding::encode;
///
/// assert_eq!(encode("abc123"), "abc123");
/// assert_eq!(encode("a b"), "a%20b");
/// assert_eq!(encode("微信"), "%E5%BE%AE%E4%BF%A1");
/// ```
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    // write! 直接写入预分配缓冲区，避免逐字节 format! 产生的临时 String（热路径）。
    use std::fmt::Write as _;
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            // String 的 fmt::Write 不会失败，忽略返回值
            let _ = write!(out, "%{:02X}", b);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_alphanumeric_no_change() {
        assert_eq!(encode("abc123"), "abc123");
    }

    #[test]
    fn encode_reserved_chars_no_change() {
        assert_eq!(encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn encode_space_to_percent_20() {
        assert_eq!(encode("a b"), "a%20b");
    }

    #[test]
    fn encode_special_chars_encoded() {
        let encoded = encode("a&b=c?d#e");
        assert!(!encoded.contains('&'), "& 应被编码");
        assert!(!encoded.contains('='), "= 应被编码");
        assert!(!encoded.contains('?'), "? 应被编码");
        assert!(!encoded.contains('#'), "# 应被编码");
    }

    #[test]
    fn encode_empty_string_returns_empty() {
        assert_eq!(encode(""), "");
    }

    #[test]
    fn encode_chinese_chars_encoded() {
        let encoded = encode("微信");
        assert!(encoded.starts_with('%'), "中文字符应被百分号编码");
        assert!(!encoded.contains('微'), "不应包含原始中文字符");
        // 微 = E5 BE AE，信 = E4 BF A1
        assert_eq!(encoded, "%E5%BE%AE%E4%BF%A1");
    }
}
