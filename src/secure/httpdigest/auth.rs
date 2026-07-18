//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `HttpDigestAuth` 实现块，封装 RFC 7616 质询生成与响应校验。

use super::{DigestAlgorithm, HttpDigestAuth};
use crate::error::{BulwarkError, BulwarkResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// 默认 nonce 有效期（秒），RFC 7616 §3.2.1 建议 nonce 应有合理 TTL。
const DEFAULT_NONCE_TTL_SECONDS: u64 = 300;

impl HttpDigestAuth {
    /// 创建新的 Digest 认证工具。
    ///
    /// # 参数
    /// - `realm`: 认证域。
    /// - `algorithm`: 算法字符串（"MD5" / "SHA256"，大小写不敏感）。
    ///
    /// # 返回
    /// - `Ok(Self)`: 构造成功。
    /// - `Err(BulwarkError::Internal)`: 不支持的算法。
    pub fn new(realm: &str, algorithm: &str) -> BulwarkResult<Self> {
        Ok(Self {
            realm: realm.to_string(),
            algorithm: algorithm.parse()?,
            nonce_ttl: DEFAULT_NONCE_TTL_SECONDS,
        })
    }

    /// 设置 nonce 有效期（秒），默认 300 秒。
    pub fn with_nonce_ttl(mut self, ttl_seconds: u64) -> Self {
        self.nonce_ttl = ttl_seconds;
        self
    }

    /// 获取 nonce 有效期（秒）。
    pub fn nonce_ttl(&self) -> u64 {
        self.nonce_ttl
    }

    /// 获取当前算法。
    pub fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// 生成 WWW-Authenticate 质询头。
    ///
    /// # 返回
    /// 形如 `Digest realm="...", nonce="...", qop="auth,auth-int", algorithm=SHA256` 的字符串。
    /// nonce 为 `base64(timestamp:random_uuid)` 格式，validate 时校验时间戳。
    pub fn challenge(&self) -> String {
        let nonce = self.generate_nonce();
        format!(
            r#"Digest realm="{}", nonce="{}", qop="auth,auth-int", algorithm={}"#,
            self.realm,
            nonce,
            self.algorithm.as_str()
        )
    }

    /// 生成带时间戳的 nonce。
    ///
    /// 格式：`base64("{timestamp}:{random_uuid}")`
    /// - timestamp: 当前 Unix 秒
    /// - random_uuid: UUID v4（保证唯一性）
    fn generate_nonce(&self) -> String {
        let timestamp = current_unix_seconds();
        let random = Uuid::new_v4().simple().to_string();
        let raw = format!("{}:{}", timestamp, random);
        STANDARD.encode(raw.as_bytes())
    }

    /// 校验 nonce 是否有效（格式正确且未过期）。
    ///
    /// nonce 格式: `base64("{timestamp}:{random}")`
    /// - 解码失败 → 无效
    /// - timestamp 非数字 → 无效
    /// - timestamp 在未来 → 无效（防止客户端伪造未来 nonce）
    /// - 已超过 TTL → 无效（过期）
    pub(super) fn is_nonce_valid(&self, nonce: &str) -> bool {
        let decoded = match STANDARD.decode(nonce) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let raw = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let parts: Vec<&str> = raw.splitn(2, ':').collect();
        if parts.len() != 2 {
            return false;
        }
        let timestamp: u64 = match parts[0].parse() {
            Ok(t) => t,
            Err(_) => return false,
        };
        let now = current_unix_seconds();
        // 防止未来时间戳（允许 5 秒时钟漂移）
        if timestamp > now + 5 {
            return false;
        }
        // 检查是否过期
        if timestamp + self.nonce_ttl < now {
            return false;
        }
        true
    }

    /// 计算 HA1 = H(username:realm:password)。
    ///
    /// HA1 为预先计算的摘要，避免框架持有明文密码。
    /// 算法依据实例配置（MD5 或 SHA256）。
    ///
    /// # 参数
    /// - `username`: 用户名。
    /// - `password`: 密码。
    pub fn compute_ha1(&self, username: &str, password: &str) -> String {
        let data = format!("{}:{}:{}", username, self.realm, password);
        self.algorithm.hash(data.as_bytes())
    }

    /// 校验客户端 Authorization header（仅支持 qop=auth）。
    ///
    /// # 参数
    /// - `authorization_header`: 客户端发送的 Authorization header 值。
    /// - `method`: HTTP method（如 "GET" / "POST"）。
    /// - `uri`: 请求 URI。
    /// - `ha1`: 预先计算的 HA1 = H(user:realm:pass)。
    ///
    /// # 返回
    /// - `true`: 校验通过。
    /// - `false`: 校验失败（密码错误 / method 不匹配 / qop 不支持 / nonce 过期 / 格式错误）。
    pub fn validate(&self, authorization_header: &str, method: &str, uri: &str, ha1: &str) -> bool {
        self.validate_inner(authorization_header, method, uri, None, ha1)
    }

    /// 校验客户端 Authorization header（支持 qop=auth 和 qop=auth-int）。
    ///
    /// qop=auth-int 时，HA2 = H(method:uri:H(body))，需传入请求体。
    /// qop=auth 时，HA2 = H(method:uri)，body 参数被忽略。
    ///
    /// # 参数
    /// - `authorization_header`: 客户端 Authorization header。
    /// - `method`: HTTP method。
    /// - `uri`: 请求 URI。
    /// - `body`: 请求体字节（用于 auth-int 计算 HA2）。
    /// - `ha1`: 预先计算的 HA1。
    pub fn validate_with_body(
        &self,
        authorization_header: &str,
        method: &str,
        uri: &str,
        body: &[u8],
        ha1: &str,
    ) -> bool {
        self.validate_inner(authorization_header, method, uri, Some(body), ha1)
    }

    /// 内部校验逻辑，统一处理 qop=auth 和 qop=auth-int。
    fn validate_inner(
        &self,
        authorization_header: &str,
        method: &str,
        uri: &str,
        body: Option<&[u8]>,
        ha1: &str,
    ) -> bool {
        match self.parse_authorization(authorization_header) {
            Ok(resp) => {
                // 检查 nonce 是否有效（格式 + 过期）
                if !self.is_nonce_valid(&resp.nonce) {
                    return false;
                }
                let qop = resp.qop.as_deref();
                // 根据 qop 计算 HA2
                let ha2 = match qop {
                    Some("auth") => {
                        let ha2_input = format!("{}:{}", method, uri);
                        self.algorithm.hash(ha2_input.as_bytes())
                    },
                    Some("auth-int") => {
                        // auth-int 需要 body，HA2 = H(method:uri:H(body))
                        let body_bytes = body.unwrap_or(&[]);
                        let body_hash = self.algorithm.hash(body_bytes);
                        let ha2_input = format!("{}:{}:{}", method, uri, body_hash);
                        self.algorithm.hash(ha2_input.as_bytes())
                    },
                    _ => return false,
                };
                // 计算 response = H(HA1:nonce:nc:cnonce:qop:HA2)
                let response_input = format!(
                    "{}:{}:{}:{}:{}:{}",
                    ha1,
                    resp.nonce,
                    resp.nc,
                    resp.cnonce,
                    qop.unwrap(),
                    ha2
                );
                let expected = self.algorithm.hash(response_input.as_bytes());
                // 常量时间比较，避免时序攻击
                constant_time_eq(expected.as_bytes(), resp.response.as_bytes())
            },
            Err(_) => false,
        }
    }

    /// 解析 Authorization header 为 DigestResponse。
    fn parse_authorization(&self, header: &str) -> BulwarkResult<DigestResponse> {
        let header = header.trim();
        let (scheme, params) = header
            .split_once(char::is_whitespace)
            .ok_or_else(|| BulwarkError::Internal("secure-http-digest-no-params::".to_string()))?;

        if !scheme.eq_ignore_ascii_case("digest") {
            return Err(BulwarkError::Internal(format!(
                "secure-httpdigest-unsupported-scheme::{}",
                scheme
            )));
        }

        let mut nonce = None;
        let mut response = None;
        let mut qop = None;
        let mut nc = None;
        let mut cnonce = None;

        for (key, value) in parse_digest_params(params) {
            match key.as_str() {
                // username/realm/uri 由 RFC 7616 要求存在，但 validate() 不使用，仅校验存在性
                "username" | "realm" | "uri" => {},
                "nonce" => nonce = Some(value),
                "response" => response = Some(value),
                "qop" => qop = Some(value),
                "nc" => nc = Some(value),
                "cnonce" => cnonce = Some(value),
                _ => {},
            }
        }

        Ok(DigestResponse {
            nonce: nonce.ok_or_else(|| {
                BulwarkError::Internal("secure-http-digest-missing-nonce::".to_string())
            })?,
            response: response.ok_or_else(|| {
                BulwarkError::Internal("secure-http-digest-missing-response::".to_string())
            })?,
            qop,
            nc: nc.ok_or_else(|| {
                BulwarkError::Internal("secure-http-digest-missing-nc::".to_string())
            })?,
            cnonce: cnonce.ok_or_else(|| {
                BulwarkError::Internal("secure-http-digest-missing-cnonce::".to_string())
            })?,
        })
    }
}

/// Digest 响应参数（解析自客户端 Authorization header）。
///
/// 仅保留 `validate()` 实际使用的字段；username/realm/uri 虽由 RFC 7616 要求且
/// 在 `parse_authorization` 中校验存在性，但不存储（避免死字段）。
#[derive(Debug, Clone)]
struct DigestResponse {
    nonce: String,
    response: String,
    qop: Option<String>,
    nc: String,
    cnonce: String,
}

/// 解析 Digest 参数串（key=value 或 key="quoted value" 形式，依据 RFC 7616）。
fn parse_digest_params(s: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();

    while chars.peek().is_some() {
        // 跳过空白与逗号分隔符
        while matches!(chars.peek(), Some(c) if c.is_whitespace() || *c == ',') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        // 读取 key
        let mut key = String::new();
        while let Some(c) = chars.peek() {
            if c.is_whitespace() || *c == '=' {
                break;
            }
            key.push(chars.next().unwrap());
        }
        // 跳过空白
        while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
            chars.next();
        }
        // 期望 '='
        if chars.peek() != Some(&'=') {
            break;
        }
        chars.next(); // 消费 '='
                      // 跳过空白
        while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
            chars.next();
        }
        // 读取 value（带引号或不带引号）
        let mut value = String::new();
        if chars.peek() == Some(&'"') {
            chars.next(); // 消费开引号
            while let Some(c) = chars.next() {
                if c == '"' {
                    break;
                }
                if c == '\\' {
                    if let Some(escaped) = chars.next() {
                        value.push(escaped);
                    }
                } else {
                    value.push(c);
                }
            }
        } else {
            while let Some(c) = chars.peek() {
                if c.is_whitespace() || *c == ',' {
                    break;
                }
                value.push(chars.next().unwrap());
            }
        }
        if !key.is_empty() {
            result.push((key, value));
        }
    }
    result
}

/// 常量时间字符串比较，避免时序攻击。
pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 获取当前 Unix 时间戳（秒）。
pub(super) fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
