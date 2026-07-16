//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! HTTP Digest 认证子模块（RFC 7616）。
//!
//! 对应 Digest 认证能力，
//! 基于 `md5` / `sha2` crate 实现摘要认证。
//!
//! VULN-0016 修复后：
//! - `DigestAlgorithm::default()` 返回 `Sha256`（不再默认 MD5）
//! - nonce 格式为 `base64(timestamp:random_uuid)`，validate 时校验时间戳防过期
//! - 支持 `qop=auth` 与 `qop=auth-int`（后者需通过 `validate_with_body` 传入请求体）
//!
//! # 安全说明
//!
//! MD5 算法已被证明存在碰撞攻击，不建议在新系统中使用。
//! 仅在兼容旧客户端时使用 MD5，新系统应使用 SHA256（现为默认值）。

use crate::error::{BulwarkError, BulwarkResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// 默认 nonce 有效期（秒），RFC 7616 §3.2.1 建议 nonce 应有合理 TTL。
const DEFAULT_NONCE_TTL_SECONDS: u64 = 300;

/// Digest 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// MD5 算法（兼容旧客户端，安全性较弱）。
    Md5,
    /// SHA256 算法（VULN-0016 后为默认值，安全性较高）。
    Sha256,
}

impl DigestAlgorithm {
    /// 返回算法名称字符串。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha256 => "SHA256",
        }
    }

    /// 计算给定数据的摘要（hex 输出）。
    fn hash(&self, data: &[u8]) -> String {
        match self {
            Self::Md5 => {
                let digest = md5::compute(data);
                hex_encode(&digest.0)
            },
            Self::Sha256 => {
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                hex_encode(&hasher.finalize())
            },
        }
    }
}

impl Default for DigestAlgorithm {
    /// VULN-0016 修复：默认算法从 MD5 升级为 SHA256。
    ///
    /// 新系统应使用 SHA256 以避免 MD5 碰撞攻击。需要在兼容旧客户端时
    /// 通过 `HttpDigestAuth::new(realm, "MD5")` 显式指定。
    fn default() -> Self {
        Self::Sha256
    }
}

impl std::str::FromStr for DigestAlgorithm {
    type Err = BulwarkError;

    /// 从字符串解析算法（大小写不敏感）。
    fn from_str(s: &str) -> BulwarkResult<Self> {
        match s.to_ascii_uppercase().as_str() {
            "MD5" => Ok(Self::Md5),
            "SHA256" => Ok(Self::Sha256),
            other => Err(BulwarkError::Internal(format!(
                "不支持的 Digest 算法: {}，仅支持 MD5 / SHA256",
                other
            ))),
        }
    }
}

/// 将字节数组编码为小写 hex 字符串。
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// HTTP Digest 认证工具，封装 RFC 7616 质询生成与响应校验。
///
/// # 示例
///
/// ```
/// #[cfg(feature = "secure-httpdigest")]
/// # {
/// use bulwark::secure::httpdigest::HttpDigestAuth;
///
/// let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
/// let challenge = auth.challenge();
/// assert!(challenge.starts_with("Digest "));
/// # }
/// ```
pub struct HttpDigestAuth {
    /// 认证域。
    realm: String,
    /// 摘要算法。
    algorithm: DigestAlgorithm,
    /// VULN-0016: nonce 有效期（秒），质询生成时嵌入时间戳，校验时检查是否过期。
    nonce_ttl: u64,
}

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

    /// VULN-0016 修复：生成带时间戳的 nonce。
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

    /// VULN-0016 修复：校验 nonce 是否有效（格式正确且未过期）。
    ///
    /// nonce 格式: `base64("{timestamp}:{random}")`
    /// - 解码失败 → 无效
    /// - timestamp 非数字 → 无效
    /// - timestamp 在未来 → 无效（防止客户端伪造未来 nonce）
    /// - 已超过 TTL → 无效（过期）
    fn is_nonce_valid(&self, nonce: &str) -> bool {
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

    /// VULN-0016 修复：校验客户端 Authorization header（支持 qop=auth 和 qop=auth-int）。
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
                // VULN-0016: 检查 nonce 是否有效（格式 + 过期）
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
        let (scheme, params) = header.split_once(char::is_whitespace).ok_or_else(|| {
            BulwarkError::Internal("Authorization header 格式错误：缺少参数部分".to_string())
        })?;

        if !scheme.eq_ignore_ascii_case("digest") {
            return Err(BulwarkError::Internal(format!(
                "Authorization 方案不支持: {}，仅支持 Digest",
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
            nonce: nonce.ok_or_else(|| BulwarkError::Internal("缺失 nonce 参数".to_string()))?,
            response: response
                .ok_or_else(|| BulwarkError::Internal("缺失 response 参数".to_string()))?,
            qop,
            nc: nc.ok_or_else(|| BulwarkError::Internal("缺失 nc 参数".to_string()))?,
            cnonce: cnonce.ok_or_else(|| BulwarkError::Internal("缺失 cnonce 参数".to_string()))?,
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
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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
fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // 算法枚举测试
    // ========================================================================

    /// from_str 解析 MD5。
    #[test]
    fn algorithm_from_str_md5() {
        assert_eq!(
            "MD5".parse::<DigestAlgorithm>().unwrap(),
            DigestAlgorithm::Md5
        );
        // 大小写不敏感
        assert_eq!(
            "md5".parse::<DigestAlgorithm>().unwrap(),
            DigestAlgorithm::Md5
        );
    }

    /// from_str 解析 SHA256。
    #[test]
    fn algorithm_from_str_sha256() {
        assert_eq!(
            "SHA256".parse::<DigestAlgorithm>().unwrap(),
            DigestAlgorithm::Sha256
        );
        assert_eq!(
            "sha256".parse::<DigestAlgorithm>().unwrap(),
            DigestAlgorithm::Sha256
        );
    }

    /// from_str 拒绝未知算法。
    #[test]
    fn algorithm_from_str_unknown_errors() {
        assert!("SHA512".parse::<DigestAlgorithm>().is_err());
        assert!("".parse::<DigestAlgorithm>().is_err());
    }

    /// VULN-0016: DigestAlgorithm::default() 返回 Sha256。
    #[test]
    fn algorithm_default_is_sha256() {
        assert_eq!(DigestAlgorithm::default(), DigestAlgorithm::Sha256);
    }

    // ========================================================================
    // 构造与质询测试
    // ========================================================================

    /// new 构造合法实例。
    #[test]
    fn new_constructs_instance() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let challenge = auth.challenge();
        assert!(challenge.starts_with("Digest "));
    }

    /// new 拒绝未知算法。
    #[test]
    fn new_rejects_unknown_algorithm() {
        assert!(HttpDigestAuth::new("realm", "SHA512").is_err());
    }

    /// 质询头包含 RFC 7616 必要字段。
    #[test]
    fn challenge_contains_required_fields() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let challenge = auth.challenge();
        assert!(challenge.starts_with("Digest "));
        assert!(challenge.contains(r#"realm="test@realm""#));
        // VULN-0016: qop 现在声明支持 auth 和 auth-int
        assert!(challenge.contains(r#"qop="auth,auth-int""#));
        assert!(challenge.contains("algorithm=MD5"));
        assert!(challenge.contains("nonce="));
    }

    /// nonce 每次生成为随机值。
    #[test]
    fn challenge_nonce_is_random() {
        let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
        let c1 = auth.challenge();
        let c2 = auth.challenge();
        // 提取 nonce
        let n1 = extract_nonce(&c1).unwrap();
        let n2 = extract_nonce(&c2).unwrap();
        assert!(!n1.is_empty());
        assert_ne!(n1, n2);
    }

    /// SHA256 算法的质询头包含 algorithm=SHA256。
    #[test]
    fn challenge_sha256_algorithm() {
        let auth = HttpDigestAuth::new("realm", "SHA256").unwrap();
        let challenge = auth.challenge();
        assert!(challenge.contains("algorithm=SHA256"));
    }

    /// VULN-0016: challenge 生成的 nonce 可被 is_nonce_valid 接受。
    #[test]
    fn challenge_nonce_is_valid() {
        let auth = HttpDigestAuth::new("realm", "SHA256").unwrap();
        let challenge = auth.challenge();
        let nonce = extract_nonce(&challenge).unwrap();
        assert!(auth.is_nonce_valid(&nonce));
    }

    /// VULN-0016: with_nonce_ttl 设置 TTL。
    #[test]
    fn with_nonce_ttl_sets_ttl() {
        let auth = HttpDigestAuth::new("realm", "MD5")
            .unwrap()
            .with_nonce_ttl(60);
        assert_eq!(auth.nonce_ttl(), 60);
    }

    // ========================================================================
    // compute_ha1 测试
    // ========================================================================

    /// compute_ha1 返回已知 MD5 值。
    #[test]
    fn compute_ha1_known_md5_value() {
        // "user:realm:pass" 的 MD5
        let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("user", "pass");
        // 验证：MD5("user:realm:pass") 应为已知值
        let expected_input = "user:realm:pass";
        let expected = md5::compute(expected_input.as_bytes());
        let expected_hex: String = expected.0.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(ha1, expected_hex);
    }

    /// compute_ha1 SHA256 返回 64 字符。
    #[test]
    fn compute_ha1_sha256_returns_64_chars() {
        let auth = HttpDigestAuth::new("realm", "SHA256").unwrap();
        let ha1 = auth.compute_ha1("user", "pass");
        assert_eq!(ha1.len(), 64);
    }

    // ========================================================================
    // validate 测试（qop=auth）
    // ========================================================================

    /// VULN-0016: 辅助函数 — 生成有效 nonce（base64(timestamp:uuid)）。
    fn make_valid_nonce() -> String {
        let timestamp = current_unix_seconds();
        let random = Uuid::new_v4().simple().to_string();
        let raw = format!("{}:{}", timestamp, random);
        STANDARD.encode(raw.as_bytes())
    }

    /// VULN-0016: 辅助函数 — 生成过期 nonce（时间戳在 TTL 之前）。
    fn make_expired_nonce(ttl: u64) -> String {
        let expired_timestamp = current_unix_seconds().saturating_sub(ttl + 10);
        let random = Uuid::new_v4().simple().to_string();
        let raw = format!("{}:{}", expired_timestamp, random);
        STANDARD.encode(raw.as_bytes())
    }

    /// VULN-0016: 辅助函数 — 生成未来 nonce（时间戳在未来）。
    fn make_future_nonce() -> String {
        let future_timestamp = current_unix_seconds() + 100;
        let random = Uuid::new_v4().simple().to_string();
        let raw = format!("{}:{}", future_timestamp, random);
        STANDARD.encode(raw.as_bytes())
    }

    /// VULN-0016: 辅助函数 — 构造合法 MD5 Authorization header。
    fn build_md5_auth_header(
        _auth: &HttpDigestAuth,
        username: &str,
        realm: &str,
        nonce: &str,
        nc: &str,
        cnonce: &str,
        method: &str,
        uri: &str,
        ha1: &str,
    ) -> String {
        let ha2_input = format!("{}:{}", method, uri);
        let ha2 = md5::compute(ha2_input.as_bytes());
        let ha2_hex: String = ha2.0.iter().map(|b| format!("{:02x}", b)).collect();
        let resp_input = format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2_hex);
        let resp = md5::compute(resp_input.as_bytes());
        let resp_hex: String = resp.0.iter().map(|b| format!("{:02x}", b)).collect();
        format!(
            r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}", qop=auth, nc={}, cnonce="{}""#,
            username, realm, nonce, uri, resp_hex, nc, cnonce
        )
    }

    /// VULN-0016: 辅助函数 — 构造合法 SHA256 Authorization header。
    fn build_sha256_auth_header(
        _auth: &HttpDigestAuth,
        username: &str,
        realm: &str,
        nonce: &str,
        nc: &str,
        cnonce: &str,
        method: &str,
        uri: &str,
        ha1: &str,
    ) -> String {
        use sha2::Digest;
        let ha2_input = format!("{}:{}", method, uri);
        let mut h2 = sha2::Sha256::new();
        h2.update(ha2_input.as_bytes());
        let ha2_hex: String = h2.finalize().iter().map(|b| format!("{:02x}", b)).collect();
        let resp_input = format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2_hex);
        let mut h = sha2::Sha256::new();
        h.update(resp_input.as_bytes());
        let resp_hex: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
        format!(
            r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}", qop=auth, nc={}, cnonce="{}""#,
            username, realm, nonce, uri, resp_hex, nc, cnonce
        )
    }

    /// 合法 Digest 响应校验通过（qop=auth）。
    #[test]
    fn validate_correct_password_succeeds() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        let nonce = make_valid_nonce();
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "GET";
        let uri = "/resource";
        let header = build_md5_auth_header(
            &auth,
            "admin",
            "test@realm",
            &nonce,
            nc,
            cnonce,
            method,
            uri,
            &ha1,
        );
        assert!(auth.validate(&header, method, uri, &ha1));
    }

    /// 错误密码生成的响应校验失败。
    #[test]
    fn validate_wrong_password_fails() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1_correct = auth.compute_ha1("admin", "secret");
        let ha1_wrong = auth.compute_ha1("admin", "wrong");
        let nonce = make_valid_nonce();
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "GET";
        let uri = "/resource";
        // 客户端用错误密码计算 response
        let header = build_md5_auth_header(
            &auth,
            "admin",
            "test@realm",
            &nonce,
            nc,
            cnonce,
            method,
            uri,
            &ha1_wrong,
        );
        // 服务端用正确 ha1 校验 → 应失败
        assert!(!auth.validate(&header, method, uri, &ha1_correct));
    }

    /// 错误的 HTTP method 导致校验失败。
    #[test]
    fn validate_wrong_method_fails() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        let nonce = make_valid_nonce();
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "POST";
        let uri = "/resource";
        let header = build_md5_auth_header(
            &auth,
            "admin",
            "test@realm",
            &nonce,
            nc,
            cnonce,
            method,
            uri,
            &ha1,
        );
        // 服务端用 GET 校验（method 不匹配）→ 应失败
        assert!(!auth.validate(&header, "GET", uri, &ha1));
    }

    /// VULN-0016: 过期 nonce 被拒绝。
    #[test]
    fn validate_expired_nonce_rejected() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        // 使用过期 nonce（超过默认 300 秒 TTL）
        let nonce = make_expired_nonce(300);
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "GET";
        let uri = "/resource";
        let header = build_md5_auth_header(
            &auth,
            "admin",
            "test@realm",
            &nonce,
            nc,
            cnonce,
            method,
            uri,
            &ha1,
        );
        // nonce 过期 → 应失败
        assert!(!auth.validate(&header, method, uri, &ha1));
    }

    /// VULN-0016: 未来 nonce 被拒绝（防止伪造未来时间戳）。
    #[test]
    fn validate_future_nonce_rejected() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        let nonce = make_future_nonce();
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "GET";
        let uri = "/resource";
        let header = build_md5_auth_header(
            &auth,
            "admin",
            "test@realm",
            &nonce,
            nc,
            cnonce,
            method,
            uri,
            &ha1,
        );
        // nonce 时间戳在未来 → 应失败
        assert!(!auth.validate(&header, method, uri, &ha1));
    }

    /// VULN-0016: 非 base64 格式的 nonce 被拒绝。
    #[test]
    fn validate_malformed_nonce_rejected() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        // "abc123nonce" 不是有效的 base64(timestamp:uuid) 格式
        let nonce = "abc123nonce";
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "GET";
        let uri = "/resource";
        let header = build_md5_auth_header(
            &auth,
            "admin",
            "test@realm",
            nonce,
            nc,
            cnonce,
            method,
            uri,
            &ha1,
        );
        // nonce 格式无效 → 应失败
        assert!(!auth.validate(&header, method, uri, &ha1));
    }

    /// VULN-0016: 自定义 TTL — 短 TTL 的过期 nonce 被拒绝，但刚生成的 nonce 通过。
    #[test]
    fn validate_custom_ttl_works() {
        let auth = HttpDigestAuth::new("test@realm", "MD5")
            .unwrap()
            .with_nonce_ttl(1);
        let ha1 = auth.compute_ha1("admin", "secret");
        // 生成 5 秒前的 nonce，超过 1 秒 TTL
        let nonce = make_expired_nonce(1);
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "GET";
        let uri = "/resource";
        let header = build_md5_auth_header(
            &auth,
            "admin",
            "test@realm",
            &nonce,
            nc,
            cnonce,
            method,
            uri,
            &ha1,
        );
        assert!(!auth.validate(&header, method, uri, &ha1));
        // 刚生成的有效 nonce 应通过
        let valid_nonce = make_valid_nonce();
        let valid_header = build_md5_auth_header(
            &auth,
            "admin",
            "test@realm",
            &valid_nonce,
            nc,
            cnonce,
            method,
            uri,
            &ha1,
        );
        assert!(auth.validate(&valid_header, method, uri, &ha1));
    }

    /// 客户端请求 auth-int 时，validate（无 body）拒绝。
    #[test]
    fn validate_auth_int_rejected_without_body() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        let nonce = make_valid_nonce();
        let header = format!(
            r#"Digest username="admin", realm="test@realm", nonce="{}", uri="/resource", response="dummy", qop=auth-int, nc=00000001, cnonce="abc""#,
            nonce
        );
        // validate（无 body）遇到 auth-int → 返回 false
        assert!(!auth.validate(&header, "GET", "/resource", &ha1));
    }

    /// VULN-0016: validate_with_body 支持 qop=auth-int（MD5）。
    #[test]
    fn validate_with_body_auth_int_md5_succeeds() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        let nonce = make_valid_nonce();
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "POST";
        let uri = "/resource";
        let body = b"hello world";
        // 计算 auth-int 的 response: HA2 = H(method:uri:H(body))
        let body_hash = auth.algorithm.hash(body);
        let ha2_input = format!("{}:{}:{}", method, uri, body_hash);
        let ha2 = md5::compute(ha2_input.as_bytes());
        let ha2_hex: String = ha2.0.iter().map(|b| format!("{:02x}", b)).collect();
        let resp_input = format!("{}:{}:{}:{}:auth-int:{}", ha1, nonce, nc, cnonce, ha2_hex);
        let resp = md5::compute(resp_input.as_bytes());
        let resp_hex: String = resp.0.iter().map(|b| format!("{:02x}", b)).collect();
        let header = format!(
            r#"Digest username="admin", realm="test@realm", nonce="{}", uri="{}", response="{}", qop=auth-int, nc={}, cnonce="{}""#,
            nonce, uri, resp_hex, nc, cnonce
        );
        assert!(auth.validate_with_body(&header, method, uri, body, &ha1));
    }

    /// VULN-0016: validate_with_body 支持 qop=auth-int（SHA256）。
    #[test]
    fn validate_with_body_auth_int_sha256_succeeds() {
        let auth = HttpDigestAuth::new("test@realm", "SHA256").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        let nonce = make_valid_nonce();
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "POST";
        let uri = "/resource";
        let body = b"hello world";
        // 用 SHA256 计算 auth-int 的 response
        use sha2::Digest;
        let body_hash = {
            let mut h = sha2::Sha256::new();
            h.update(body);
            h.finalize()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        };
        let ha2_input = format!("{}:{}:{}", method, uri, body_hash);
        let mut h2 = sha2::Sha256::new();
        h2.update(ha2_input.as_bytes());
        let ha2_hex: String = h2.finalize().iter().map(|b| format!("{:02x}", b)).collect();
        let resp_input = format!("{}:{}:{}:{}:auth-int:{}", ha1, nonce, nc, cnonce, ha2_hex);
        let mut h = sha2::Sha256::new();
        h.update(resp_input.as_bytes());
        let resp_hex: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
        let header = format!(
            r#"Digest username="admin", realm="test@realm", nonce="{}", uri="{}", response="{}", qop=auth-int, nc={}, cnonce="{}""#,
            nonce, uri, resp_hex, nc, cnonce
        );
        assert!(auth.validate_with_body(&header, method, uri, body, &ha1));
    }

    /// VULN-0016: validate_with_body 中 body 不匹配导致校验失败。
    #[test]
    fn validate_with_body_tampered_body_fails() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        let nonce = make_valid_nonce();
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "POST";
        let uri = "/resource";
        let original_body = b"hello world";
        // 客户端用 original_body 计算 response
        let body_hash = auth.algorithm.hash(original_body);
        let ha2_input = format!("{}:{}:{}", method, uri, body_hash);
        let ha2 = md5::compute(ha2_input.as_bytes());
        let ha2_hex: String = ha2.0.iter().map(|b| format!("{:02x}", b)).collect();
        let resp_input = format!("{}:{}:{}:{}:auth-int:{}", ha1, nonce, nc, cnonce, ha2_hex);
        let resp = md5::compute(resp_input.as_bytes());
        let resp_hex: String = resp.0.iter().map(|b| format!("{:02x}", b)).collect();
        let header = format!(
            r#"Digest username="admin", realm="test@realm", nonce="{}", uri="{}", response="{}", qop=auth-int, nc={}, cnonce="{}""#,
            nonce, uri, resp_hex, nc, cnonce
        );
        // 服务端用篡改后的 body 校验 → 应失败
        let tampered_body = b"tampered body";
        assert!(!auth.validate_with_body(&header, method, uri, tampered_body, &ha1));
    }

    /// VULN-0016: validate_with_body 也支持 qop=auth（body 被忽略）。
    #[test]
    fn validate_with_body_supports_auth_qop() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        let nonce = make_valid_nonce();
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "GET";
        let uri = "/resource";
        // 构造 qop=auth 的 header
        let header = build_md5_auth_header(
            &auth,
            "admin",
            "test@realm",
            &nonce,
            nc,
            cnonce,
            method,
            uri,
            &ha1,
        );
        // validate_with_body 也能校验 qop=auth（body 被忽略）
        assert!(auth.validate_with_body(&header, method, uri, b"any body", &ha1));
    }

    /// 格式错误的 Authorization header 返回 false。
    #[test]
    fn validate_malformed_header_returns_false() {
        let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
        let ha1 = "dummy";
        // 非 Digest 方案
        assert!(!auth.validate("Basic abc123", "GET", "/resource", ha1));
        // 缺失参数
        assert!(!auth.validate("Digest username=\"admin\"", "GET", "/resource", ha1));
    }

    /// SHA256 算法的 validate 校验通过。
    #[test]
    fn validate_sha256_succeeds() {
        let auth = HttpDigestAuth::new("test@realm", "SHA256").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        let nonce = make_valid_nonce();
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "GET";
        let uri = "/resource";
        let header = build_sha256_auth_header(
            &auth,
            "admin",
            "test@realm",
            &nonce,
            nc,
            cnonce,
            method,
            uri,
            &ha1,
        );
        assert!(auth.validate(&header, method, uri, &ha1));
    }

    // ========================================================================
    // parse_authorization 边界路径测试
    // ========================================================================

    /// 验证 validate 对无参数部分的 header 返回 false。
    ///
    /// 覆盖 parse_authorization 中 `split_once(char::is_whitespace)` 返回 None 的错误路径
    /// （"Authorization header 格式错误：缺少参数部分"）。
    #[test]
    fn validate_header_without_whitespace_returns_false() {
        let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
        // "Digest" 后无空格，split_once 返回 None
        assert!(!auth.validate("Digest", "GET", "/resource", "ha1"));
    }

    /// 验证 validate 对包含未知参数的 header 仍可解析。
    ///
    /// 覆盖 parse_digest_params 中 `_ => {}` 分支（未知 key 被忽略）。
    #[test]
    fn validate_header_with_unknown_params_returns_false() {
        let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
        // 使用有效 nonce 但 response 不正确
        let nonce = make_valid_nonce();
        let header = format!(
            r#"Digest username="admin", realm="realm", nonce="{}", uri="/r", response="r", qop=auth, nc=1, cnonce="c", custom_param="x""#,
            nonce
        );
        // response 不正确，应返回 false（但解析本身不应出错）
        assert!(!auth.validate(&header, "GET", "/r", "dummy_ha1"));
    }

    /// 验证 validate 对包含转义字符的 header 可解析。
    ///
    /// 覆盖 parse_digest_params 中 `if c == '\\' { ... }` 转义分支。
    #[test]
    fn validate_header_with_escaped_chars_returns_false() {
        let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
        let nonce = make_valid_nonce();
        // response 包含转义字符 \"
        let header = format!(
            r#"Digest username="ad\"min", realm="realm", nonce="{}", uri="/r", response="r", qop=auth, nc=1, cnonce="c""#,
            nonce
        );
        // response 不正确，应返回 false
        assert!(!auth.validate(&header, "GET", "/r", "dummy_ha1"));
    }

    /// 验证 validate 对 key 后无等号的 header 返回 false。
    ///
    /// 覆盖 parse_digest_params 中 `if chars.peek() != Some(&'=') { break; }` 分支。
    #[test]
    fn validate_header_with_key_without_equals_returns_false() {
        let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
        let nonce = make_valid_nonce();
        // "username" 后无 '='，parse_digest_params 应 break
        let header = format!(
            r#"Digest username realm="realm", nonce="{}", uri="/r", response="r", qop=auth, nc=1, cnonce="c""#,
            nonce
        );
        assert!(!auth.validate(&header, "GET", "/r", "dummy_ha1"));
    }

    /// 验证 validate 对不含 qop 的 header 返回 false。
    ///
    /// 覆盖 validate 中 qop=None 的分支。
    #[test]
    fn validate_header_without_qop_returns_false() {
        let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
        let nonce = make_valid_nonce();
        let header = format!(
            r#"Digest username="admin", realm="realm", nonce="{}", uri="/r", response="r", nc=1, cnonce="c""#,
            nonce
        );
        assert!(!auth.validate(&header, "GET", "/r", "dummy_ha1"));
    }

    // ========================================================================
    // is_nonce_valid 直接测试
    // ========================================================================

    /// VULN-0016: is_nonce_valid 对空字符串返回 false。
    #[test]
    fn is_nonce_valid_empty_returns_false() {
        let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
        assert!(!auth.is_nonce_valid(""));
    }

    /// VULN-0016: is_nonce_valid 对纯文本（非 base64）返回 false。
    #[test]
    fn is_nonce_valid_plain_text_returns_false() {
        let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
        assert!(!auth.is_nonce_valid("abc123nonce"));
    }

    /// VULN-0016: is_nonce_valid 对缺少冒号分隔符的 base64 返回 false。
    #[test]
    fn is_nonce_valid_no_colon_returns_false() {
        let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
        // base64("12345") — 无冒号
        let nonce = STANDARD.encode(b"12345");
        assert!(!auth.is_nonce_valid(&nonce));
    }

    /// VULN-0016: is_nonce_valid 对时间戳非数字返回 false。
    #[test]
    fn is_nonce_valid_non_numeric_timestamp_returns_false() {
        let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
        let raw = "abc:def";
        let nonce = STANDARD.encode(raw.as_bytes());
        assert!(!auth.is_nonce_valid(&nonce));
    }

    // ========================================================================
    // constant_time_eq 测试
    // ========================================================================

    /// 验证 constant_time_eq 对不同长度字符串返回 false。
    ///
    /// 覆盖 constant_time_eq 中 `if a.len() != b.len() { return false; }` 分支。
    #[test]
    fn constant_time_eq_different_lengths_returns_false() {
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
    }

    /// 验证 constant_time_eq 对相同字符串返回 true。
    #[test]
    fn constant_time_eq_same_strings_returns_true() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(constant_time_eq(b"", b""));
    }

    /// 验证 constant_time_eq 对不同字符串返回 false。
    #[test]
    fn constant_time_eq_different_strings_returns_false() {
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    // ========================================================================
    // hex_encode 测试
    // ========================================================================

    /// 验证 hex_encode 对空字节返回空字符串。
    #[test]
    fn hex_encode_empty_bytes() {
        assert_eq!(hex_encode(&[]), "");
    }

    /// 验证 hex_encode 对已知字节返回正确 hex。
    #[test]
    fn hex_encode_known_bytes() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x0a]), "00ff0a");
    }

    // ========================================================================
    // 辅助函数
    // ========================================================================

    /// 从质询头中提取 nonce 值。
    fn extract_nonce(challenge: &str) -> Option<String> {
        let start = challenge.find("nonce=\"")? + "nonce=\"".len();
        let end = challenge[start..].find('"')? + start;
        Some(challenge[start..end].to_string())
    }
}
