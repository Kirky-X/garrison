//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! HTTP Basic 认证子模块（RFC 7617）。
//!
//! 对应 Basic 认证能力，
//! 基于 `base64` crate 实现用户名密码的编解码。
//!
//! 所有方法均为关联函数，`HttpBasicAuth` struct 不持有任何状态。

use crate::error::{BulwarkError, BulwarkResult};
use base64::{engine::general_purpose::STANDARD, Engine};

/// Basic 认证凭证，承载解码后的用户名与密码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// 用户名。
    pub user: String,
    /// 密码。
    pub pass: String,
}

/// HTTP Basic 认证工具，封装 RFC 7617 编解码逻辑。
///
/// 所有方法为关联函数，无需实例化即可调用：
///
/// ```
/// #[cfg(feature = "secure-httpbasic")]
/// # {
/// use bulwark::secure::httpbasic::HttpBasicAuth;
/// let encoded = HttpBasicAuth::encode("alice", "secret");
/// let cred = HttpBasicAuth::decode(&encoded).unwrap();
/// assert_eq!(cred.user, "alice");
/// assert_eq!(cred.pass, "secret");
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpBasicAuth;

impl HttpBasicAuth {
    /// 编码用户名密码为 Base64 凭证字符串。
    ///
    /// 将 `"user:pass"` 进行 Base64 编码，返回值可直接作为 `Authorization: Basic <encoded>` 中的凭证部分。
    ///
    /// # 参数
    /// - `user`: 用户名。
    /// - `pass`: 密码。
    ///
    /// # 返回
    /// Base64 编码字符串（不含 `Basic ` 前缀）。
    pub fn encode(user: &str, pass: &str) -> String {
        let credentials = format!("{}:{}", user, pass);
        STANDARD.encode(credentials.as_bytes())
    }

    /// 解码 Base64 凭证为 `Credential`。
    ///
    /// # 参数
    /// - `header_value`: Base64 编码的凭证字符串（不含 `Basic ` 前缀）。
    ///
    /// # 返回
    /// - `Ok(Credential)`: 解码成功。
    /// - `Err(BulwarkError::Internal)`: Base64 非法 / UTF-8 解码失败 / 缺失冒号分隔符。
    pub fn decode(header_value: &str) -> BulwarkResult<Credential> {
        let decoded = STANDARD
            .decode(header_value)
            .map_err(|e| BulwarkError::Internal(format!("Base64 解码失败: {}", e)))?;
        let decoded_str = String::from_utf8(decoded)
            .map_err(|e| BulwarkError::Internal(format!("UTF-8 解码失败: {}", e)))?;
        let (user, pass) = decoded_str
            .split_once(':')
            .ok_or_else(|| BulwarkError::Internal("凭证格式错误：缺失冒号分隔符".to_string()))?;
        Ok(Credential {
            user: user.to_string(),
            pass: pass.to_string(),
        })
    }

    /// 从完整 `Authorization` header 解析 Basic 凭证。
    ///
    /// 依据 RFC 7235，认证方案 `Basic` 大小写不敏感。
    ///
    /// # 参数
    /// - `header`: 完整的 Authorization header 值（如 `"Basic YWxpY2U6c2VjcmV0"`）。
    ///
    /// # 返回
    /// - `Ok(Credential)`: 解析成功。
    /// - `Err(BulwarkError::Internal)`: 方案非 Basic / 缺少凭证 / Base64 解码失败。
    pub fn parse_authorization_header(header: &str) -> BulwarkResult<Credential> {
        let header = header.trim();
        let (scheme, credentials) = header.split_once(char::is_whitespace).ok_or_else(|| {
            BulwarkError::Internal("Authorization header 格式错误：缺少凭证部分".to_string())
        })?;

        if !scheme.eq_ignore_ascii_case("basic") {
            return Err(BulwarkError::Internal(format!(
                "认证方案不支持: {}，仅支持 Basic",
                scheme
            )));
        }

        let credentials = credentials.trim();
        if credentials.is_empty() {
            return Err(BulwarkError::Internal(
                "Authorization header 缺少凭证部分".to_string(),
            ));
        }

        Self::decode(credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // encode 测试
    // ========================================================================

    /// 编码用户名密码为 Base64，解码后等于 "user:pass"。
    #[test]
    fn encode_produces_valid_base64() {
        let encoded = HttpBasicAuth::encode("alice", "secret");
        let decoded = STANDARD.decode(&encoded).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert_eq!(decoded_str, "alice:secret");
    }

    /// encode/decode 往返一致。
    #[test]
    fn encode_decode_roundtrip() {
        let encoded = HttpBasicAuth::encode("bob", "p@ss");
        let cred = HttpBasicAuth::decode(&encoded).unwrap();
        assert_eq!(cred.user, "bob");
        assert_eq!(cred.pass, "p@ss");
    }

    /// 空用户名编码解码。
    #[test]
    fn encode_decode_empty_user() {
        let encoded = HttpBasicAuth::encode("", "pass");
        let cred = HttpBasicAuth::decode(&encoded).unwrap();
        assert_eq!(cred.user, "");
        assert_eq!(cred.pass, "pass");
    }

    /// 含特殊字符的凭证。
    #[test]
    fn encode_decode_special_characters() {
        let encoded = HttpBasicAuth::encode("用户", "密码!@#");
        let cred = HttpBasicAuth::decode(&encoded).unwrap();
        assert_eq!(cred.user, "用户");
        assert_eq!(cred.pass, "密码!@#");
    }

    // ========================================================================
    // decode 测试
    // ========================================================================

    /// 解码合法 Base64 凭证（spec Scenario）。
    #[test]
    fn decode_valid_base64_credential() {
        // "alice:secret" 的 Base64
        let cred = HttpBasicAuth::decode("YWxpY2U6c2VjcmV0").unwrap();
        assert_eq!(cred.user, "alice");
        assert_eq!(cred.pass, "secret");
    }

    /// 解码非法 Base64 字符串失败（spec Scenario）。
    #[test]
    fn decode_invalid_base64_errors() {
        let result = HttpBasicAuth::decode("!!!not-base64!!!");
        assert!(result.is_err());
    }

    /// 解码后缺失冒号分隔符失败（spec Scenario）。
    #[test]
    fn decode_missing_colon_errors() {
        // "usernocolon" 的 Base64
        let result = HttpBasicAuth::decode("dXNlcm5hbWVub2NvbG9u");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("冒号分隔符"));
    }

    // ========================================================================
    // parse_authorization_header 测试
    // ========================================================================

    /// 解析完整 Authorization Header（spec Scenario）。
    #[test]
    fn parse_full_authorization_header() {
        let cred = HttpBasicAuth::parse_authorization_header("Basic YWxpY2U6c2VjcmV0").unwrap();
        assert_eq!(cred.user, "alice");
        assert_eq!(cred.pass, "secret");
    }

    /// Header 前缀非 Basic 失败（spec Scenario）。
    #[test]
    fn parse_non_basic_scheme_errors() {
        let result = HttpBasicAuth::parse_authorization_header("Bearer some.token.value");
        assert!(result.is_err());
    }

    /// Header 缺少凭证部分失败（spec Scenario）。
    #[test]
    fn parse_missing_credentials_errors() {
        let result = HttpBasicAuth::parse_authorization_header("Basic");
        assert!(result.is_err());
    }

    /// Basic 方案大小写不敏感（RFC 7235）。
    #[test]
    fn parse_basic_scheme_case_insensitive() {
        let cred = HttpBasicAuth::parse_authorization_header("BASIC YWxpY2U6c2VjcmV0").unwrap();
        assert_eq!(cred.user, "alice");
    }
}
