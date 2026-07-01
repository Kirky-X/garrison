//! HTTP Digest 认证子模块（RFC 7616）。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 Digest 认证能力，
//! 基于 `md5` / `sha2` crate 实现摘要认证。
//!
//! 仅支持 qop=auth（不支持 auth-int，因需要计算 entity-body 摘要，
//! 与 axum body 读取模型冲突）。
//!
//! # 安全警告
//!
//! MD5 算法已被证明存在碰撞攻击，不建议在新系统中使用。
//! 仅在兼容旧客户端时使用 MD5，新系统应使用 SHA256。

use crate::error::{BulwarkError, BulwarkResult};
use uuid::Uuid;

/// Digest 算法枚举（依据 spec secure-httpdigest）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// MD5 算法（默认，兼容旧客户端，安全性较弱）。
    Md5,
    /// SHA256 算法（推荐，安全性较高）。
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

/// HTTP Digest 认证工具，封装 RFC 7616 质询生成与响应校验（依据 spec secure-httpdigest）。
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
}

impl HttpDigestAuth {
    /// 创建新的 Digest 认证工具（依据 spec secure-httpdigest）。
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
        })
    }

    /// 生成 WWW-Authenticate 质询头（依据 RFC 7616）。
    ///
    /// # 返回
    /// 形如 `Digest realm="...", nonce="...", qop="auth", algorithm=MD5` 的字符串。
    /// nonce 每次调用均为随机值。
    pub fn challenge(&self) -> String {
        let nonce = Uuid::new_v4().simple().to_string();
        format!(
            r#"Digest realm="{}", nonce="{}", qop="auth", algorithm={}"#,
            self.realm,
            nonce,
            self.algorithm.as_str()
        )
    }

    /// 计算 HA1 = H(username:realm:password)（依据 RFC 7616）。
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

    /// 校验客户端 Authorization header（依据 RFC 7616 qop=auth 流程）。
    ///
    /// # 参数
    /// - `authorization_header`: 客户端发送的 Authorization header 值。
    /// - `method`: HTTP method（如 "GET" / "POST"）。
    /// - `uri`: 请求 URI。
    /// - `ha1`: 预先计算的 HA1 = H(user:realm:pass)。
    ///
    /// # 返回
    /// - `true`: 校验通过。
    /// - `false`: 校验失败（密码错误 / method 不匹配 / qop 不支持 / 格式错误）。
    pub fn validate(&self, authorization_header: &str, method: &str, uri: &str, ha1: &str) -> bool {
        match self.parse_authorization(authorization_header) {
            Ok(resp) => {
                // qop 必须为 auth，不支持 auth-int
                if resp.qop.as_deref() != Some("auth") {
                    return false;
                }
                // 计算 HA2 = H(method:uri)
                let ha2_input = format!("{}:{}", method, uri);
                let ha2 = self.algorithm.hash(ha2_input.as_bytes());
                // 计算 response = H(HA1:nonce:nc:cnonce:qop:HA2)
                let response_input = format!(
                    "{}:{}:{}:{}:auth:{}",
                    ha1, resp.nonce, resp.nc, resp.cnonce, ha2
                );
                let expected = self.algorithm.hash(response_input.as_bytes());
                // 常量时间比较，避免时序攻击
                constant_time_eq(expected.as_bytes(), resp.response.as_bytes())
            },
            Err(_) => false,
        }
    }

    /// 解析 Authorization header 为 DigestResponse（依据 RFC 7616）。
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

        let mut username = None;
        let mut realm = None;
        let mut nonce = None;
        let mut uri = None;
        let mut response = None;
        let mut qop = None;
        let mut nc = None;
        let mut cnonce = None;

        for (key, value) in parse_digest_params(params) {
            match key.as_str() {
                "username" => username = Some(value),
                "realm" => realm = Some(value),
                "nonce" => nonce = Some(value),
                "uri" => uri = Some(value),
                "response" => response = Some(value),
                "qop" => qop = Some(value),
                "nc" => nc = Some(value),
                "cnonce" => cnonce = Some(value),
                _ => {},
            }
        }

        Ok(DigestResponse {
            username: username
                .ok_or_else(|| BulwarkError::Internal("缺失 username 参数".to_string()))?,
            realm: realm.ok_or_else(|| BulwarkError::Internal("缺失 realm 参数".to_string()))?,
            nonce: nonce.ok_or_else(|| BulwarkError::Internal("缺失 nonce 参数".to_string()))?,
            uri: uri.ok_or_else(|| BulwarkError::Internal("缺失 uri 参数".to_string()))?,
            response: response
                .ok_or_else(|| BulwarkError::Internal("缺失 response 参数".to_string()))?,
            qop,
            nc: nc.ok_or_else(|| BulwarkError::Internal("缺失 nc 参数".to_string()))?,
            cnonce: cnonce.ok_or_else(|| BulwarkError::Internal("缺失 cnonce 参数".to_string()))?,
        })
    }
}

/// Digest 响应参数（解析自客户端 Authorization header）。
#[derive(Debug, Clone)]
struct DigestResponse {
    #[allow(dead_code)]
    username: String,
    #[allow(dead_code)]
    realm: String,
    nonce: String,
    #[allow(dead_code)]
    uri: String,
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

    // ========================================================================
    // 构造与质询测试（依据 spec secure-httpdigest）
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

    /// 质询头包含 RFC 7616 必要字段（spec Scenario）。
    #[test]
    fn challenge_contains_required_fields() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let challenge = auth.challenge();
        assert!(challenge.starts_with("Digest "));
        assert!(challenge.contains(r#"realm="test@realm""#));
        assert!(challenge.contains(r#"qop="auth""#));
        assert!(challenge.contains("algorithm=MD5"));
        assert!(challenge.contains("nonce="));
    }

    /// nonce 每次生成为随机值（spec Scenario）。
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

    /// SHA256 算法的质询头包含 algorithm=SHA256（spec Scenario）。
    #[test]
    fn challenge_sha256_algorithm() {
        let auth = HttpDigestAuth::new("realm", "SHA256").unwrap();
        let challenge = auth.challenge();
        assert!(challenge.contains("algorithm=SHA256"));
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
    // validate 测试（依据 spec secure-httpdigest）
    // ========================================================================

    /// 合法 Digest 响应校验通过（spec Scenario）。
    #[test]
    fn validate_correct_password_succeeds() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        let nonce = "abc123nonce";
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "GET";
        let uri = "/resource";

        // 计算 HA2 = MD5(method:uri)
        let ha2_input = format!("{}:{}", method, uri);
        let ha2 = md5::compute(ha2_input.as_bytes());
        let ha2_hex: String = ha2.0.iter().map(|b| format!("{:02x}", b)).collect();

        // 计算 response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
        let resp_input = format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2_hex);
        let resp = md5::compute(resp_input.as_bytes());
        let resp_hex: String = resp.0.iter().map(|b| format!("{:02x}", b)).collect();

        let header = format!(
            r#"Digest username="admin", realm="test@realm", nonce="{}", uri="{}", response="{}", qop=auth, nc={}, cnonce="{}""#,
            nonce, uri, resp_hex, nc, cnonce
        );

        assert!(auth.validate(&header, method, uri, &ha1));
    }

    /// 错误密码生成的响应校验失败（spec Scenario）。
    #[test]
    fn validate_wrong_password_fails() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1_correct = auth.compute_ha1("admin", "secret");
        let ha1_wrong = auth.compute_ha1("admin", "wrong");

        let nonce = "abc123nonce";
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "GET";
        let uri = "/resource";

        // 客户端用错误密码计算 response
        let ha2_input = format!("{}:{}", method, uri);
        let ha2 = md5::compute(ha2_input.as_bytes());
        let ha2_hex: String = ha2.0.iter().map(|b| format!("{:02x}", b)).collect();
        let resp_input = format!("{}:{}:{}:{}:auth:{}", ha1_wrong, nonce, nc, cnonce, ha2_hex);
        let resp = md5::compute(resp_input.as_bytes());
        let resp_hex: String = resp.0.iter().map(|b| format!("{:02x}", b)).collect();

        let header = format!(
            r#"Digest username="admin", realm="test@realm", nonce="{}", uri="{}", response="{}", qop=auth, nc={}, cnonce="{}""#,
            nonce, uri, resp_hex, nc, cnonce
        );

        // 服务端用正确 ha1 校验 → 应失败
        assert!(!auth.validate(&header, method, uri, &ha1_correct));
    }

    /// 错误的 HTTP method 导致校验失败（spec Scenario）。
    #[test]
    fn validate_wrong_method_fails() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");
        let nonce = "abc123nonce";
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "POST";
        let uri = "/resource";

        let ha2_input = format!("{}:{}", method, uri);
        let ha2 = md5::compute(ha2_input.as_bytes());
        let ha2_hex: String = ha2.0.iter().map(|b| format!("{:02x}", b)).collect();
        let resp_input = format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2_hex);
        let resp = md5::compute(resp_input.as_bytes());
        let resp_hex: String = resp.0.iter().map(|b| format!("{:02x}", b)).collect();

        let header = format!(
            r#"Digest username="admin", realm="test@realm", nonce="{}", uri="{}", response="{}", qop=auth, nc={}, cnonce="{}""#,
            nonce, uri, resp_hex, nc, cnonce
        );

        // 服务端用 GET 校验（method 不匹配）→ 应失败
        assert!(!auth.validate(&header, "GET", uri, &ha1));
    }

    /// 客户端请求 auth-int 时拒绝（spec Scenario）。
    #[test]
    fn validate_auth_int_rejected() {
        let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
        let ha1 = auth.compute_ha1("admin", "secret");

        let header = r#"Digest username="admin", realm="test@realm", nonce="abc", uri="/resource", response="dummy", qop=auth-int, nc=00000001, cnonce="abc""#;
        assert!(!auth.validate(header, "GET", "/resource", &ha1));
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
        let nonce = "abc123nonce";
        let nc = "00000001";
        let cnonce = "0a4f113c";
        let method = "GET";
        let uri = "/resource";

        // 用 SHA256 计算 response
        use sha2::Digest;
        let ha2_input = format!("{}:{}", method, uri);
        let mut h2 = sha2::Sha256::new();
        h2.update(ha2_input.as_bytes());
        let ha2_hex: String = h2.finalize().iter().map(|b| format!("{:02x}", b)).collect();

        let resp_input = format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2_hex);
        let mut h = sha2::Sha256::new();
        h.update(resp_input.as_bytes());
        let resp_hex: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();

        let header = format!(
            r#"Digest username="admin", realm="test@realm", nonce="{}", uri="{}", response="{}", qop=auth, nc={}, cnonce="{}""#,
            nonce, uri, resp_hex, nc, cnonce
        );

        assert!(auth.validate(&header, method, uri, &ha1));
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
