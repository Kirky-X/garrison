//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! `HttpBasicAuth` 实现块，封装 RFC 7617 编解码逻辑。

use super::{Credential, HttpBasicAuth};
use crate::error::{GarrisonError, GarrisonResult};
use base64::{engine::general_purpose::STANDARD, Engine};

/// Base64 凭证输入最大长度（字节）。
///
/// 4KB 覆盖所有合法 Basic 凭证（RFC 7617 用户名密码通常 < 256 字节），
/// 防止恶意超长 Base64 输入在解码时按比例分配内存（DoS 向量）。
const MAX_CREDENTIAL_LEN: usize = 4 * 1024;

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
    ///
    /// # 注意
    /// 本函数不限制 `user`/`pass` 长度（调用方输入为已信任的服务端凭证）；
    /// 解码侧 [`decode`](Self::decode) 强制 `MAX_CREDENTIAL_LEN`（4KB）上限。
    pub fn encode(user: &str, pass: &str) -> String {
        let credentials = format!("{}:{}", user, pass);
        STANDARD.encode(credentials.as_bytes())
    }

    /// 解码 Base64 凭证为 `Credential`。
    ///
    /// # 参数
    /// - `header_value`: Base64 编码的凭证字符串（不含 `Basic ` 前缀），长度 ≤ 4KB。
    ///
    /// # 返回
    /// - `Ok(Credential)`: 解码成功。
    /// - `Err(GarrisonError::InvalidParam)`: 输入超长 / Base64 非法 / UTF-8 解码失败 /
    /// 缺失冒号分隔符（均为客户端输入错误，映射 HTTP 400，而非 500 Internal）。
    pub fn decode(header_value: &str) -> GarrisonResult<Credential> {
        if header_value.len() > MAX_CREDENTIAL_LEN {
            return Err(GarrisonError::InvalidParam(
                "secure-cred-too-long::".to_string(),
            ));
        }
        let decoded = STANDARD
            .decode(header_value)
            .map_err(|e| GarrisonError::InvalidParam(format!("secure-base64-decode::{}", e)))?;
        let decoded_str = String::from_utf8(decoded)
            .map_err(|e| GarrisonError::InvalidParam(format!("secure-utf8-decode::{}", e)))?;
        let (user, pass) = decoded_str.split_once(':').ok_or_else(|| {
            GarrisonError::InvalidParam("secure-cred-missing-colon::".to_string())
        })?;
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
    /// - `Err(GarrisonError::InvalidParam)`: 方案非 Basic / 缺少凭证 / Base64 解码失败
    /// （客户端输入错误，映射 HTTP 400，由下游中间件决定是否升级为 401）。
    pub fn parse_authorization_header(header: &str) -> GarrisonResult<Credential> {
        if header.len() > MAX_CREDENTIAL_LEN {
            return Err(GarrisonError::InvalidParam(
                "secure-cred-too-long::".to_string(),
            ));
        }
        let header = header.trim();
        let (scheme, credentials) = header.split_once(char::is_whitespace).ok_or_else(|| {
            GarrisonError::InvalidParam("secure-auth-header-no-cred::".to_string())
        })?;

        if !scheme.eq_ignore_ascii_case("basic") {
            return Err(GarrisonError::InvalidParam(format!(
                "secure-httpbasic-unsupported-scheme::{}",
                scheme
            )));
        }

        let credentials = credentials.trim();
        if credentials.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "secure-auth-header-no-cred::".to_string(),
            ));
        }

        Self::decode(credentials)
    }
}
