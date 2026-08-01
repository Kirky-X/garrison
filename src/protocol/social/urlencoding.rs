//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 社交登录 URL 编码工具。
//!
//! 提供对查询参数值的百分号编码，保留字母、数字、`-`、`_`、`.`、`~`（RFC 3986 unreserved）。
//!
//! ## 设计
//!
//! 独立于 `percent-encoding` crate，对社交登录 provider 查询参数的简单编码场景做最小实现，
//! 避免 `percent-encoding::utf8_percent_encode` + `AsciiSet` 配置复杂度。
//!
//! ## 使用场景
//!
//! - `WechatProvider::get_authorization_url` 拼接 `appid` / `redirect_uri` / `state` query 参数
//! - `WechatProvider::exchange_token` 拼接 `code` / `secret` query 参数
//! - `WechatProvider::get_user_info` 拼接 `access_token` / `openid` query 参数
//! - `WechatMiniAppProvider::get_user_info` 拼接 `js_code` query 参数
//! - `AlipayProvider::get_authorization_url` / `exchange_token` 拼接 query 参数
//! - 外部 crate（如 sinnan `HuaweiProvider`）自定义 provider 拼接 query 参数
//!
//! ## 与 `protocol::oauth2` 的关系
//!
//! `protocol::oauth2` 直接使用 `percent-encoding` crate（依赖 `AsciiSet` 配置），
//! 本模块针对社交登录场景提供简化版，避免社交 provider 重复实现编码逻辑。

/// 对查询参数值进行百分号编码。
///
/// 保留 RFC 3986 unreserved 字符（字母、数字、`-`、`_`、`.`、`~`），
/// 其他字节按 `%XX`（大写十六进制）编码。
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
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 纯字母数字不编码。
    #[test]
    fn encode_alphanumeric_no_change() {
        assert_eq!(encode("abc123"), "abc123");
    }

    /// 保留字符 -.~_ 不编码。
    #[test]
    fn encode_reserved_chars_no_change() {
        assert_eq!(encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    /// 空格编码为 %20。
    #[test]
    fn encode_space_to_percent_20() {
        assert_eq!(encode("a b"), "a%20b");
    }

    /// 特殊字符 &=?# 编码。
    #[test]
    fn encode_special_chars_encoded() {
        let encoded = encode("a&b=c?d#e");
        assert!(!encoded.contains('&'), "& 应被编码");
        assert!(!encoded.contains('='), "= 应被编码");
        assert!(!encoded.contains('?'), "? 应被编码");
        assert!(!encoded.contains('#'), "# 应被编码");
    }

    /// 空字符串返回空字符串。
    #[test]
    fn encode_empty_string_returns_empty() {
        assert_eq!(encode(""), "");
    }

    /// 中文字符按 UTF-8 字节编码。
    #[test]
    fn encode_chinese_chars_encoded() {
        let encoded = encode("微信");
        // 中文字符应全部被编码（每个字节为 %XX）
        assert!(encoded.starts_with('%'), "中文字符应被百分号编码");
        assert!(!encoded.contains('微'), "不应包含原始中文字符");
        // 验证具体编码值：微 = E5 BE AE，信 = E4 BF A1
        assert_eq!(encoded, "%E5%BE%AE%E4%BF%A1");
    }
}
