//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `HttpBasicAuth` 实现块，封装 RFC 7617 编解码逻辑。

use super::{Credential, HttpBasicAuth};
use crate::error::{BulwarkError, BulwarkResult};
use base64::{engine::general_purpose::STANDARD, Engine};

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
            .map_err(|e| BulwarkError::Internal(format!("secure-base64-decode::{}", e)))?;
        let decoded_str = String::from_utf8(decoded)
            .map_err(|e| BulwarkError::Internal(format!("secure-utf8-decode::{}", e)))?;
        let (user, pass) = decoded_str
            .split_once(':')
            .ok_or_else(|| BulwarkError::Internal("secure-cred-missing-colon::".to_string()))?;
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
        let (scheme, credentials) = header
            .split_once(char::is_whitespace)
            .ok_or_else(|| BulwarkError::Internal("secure-auth-header-no-cred::".to_string()))?;

        if !scheme.eq_ignore_ascii_case("basic") {
            return Err(BulwarkError::Internal(format!(
                "secure-httpbasic-unsupported-scheme::{}",
                scheme
            )));
        }

        let credentials = credentials.trim();
        if credentials.is_empty() {
            return Err(BulwarkError::Internal(
                "secure-auth-header-no-cred::".to_string(),
            ));
        }

        Self::decode(credentials)
    }
}
