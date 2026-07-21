//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `httpdigest` 模块单元测试。

use super::algorithm::hex_encode;
use super::auth::{constant_time_eq, current_unix_seconds};
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::sync::Arc;
use uuid::Uuid;

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

/// DigestAlgorithm::default() 返回 Sha256。
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
    // qop 现在声明支持 auth 和 auth-int
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

/// challenge 生成的 nonce 可被 is_nonce_valid 接受。
#[test]
fn challenge_nonce_is_valid() {
    let auth = HttpDigestAuth::new("realm", "SHA256").unwrap();
    let challenge = auth.challenge();
    let nonce = extract_nonce(&challenge).unwrap();
    assert!(auth.is_nonce_valid(&nonce));
}

/// with_nonce_ttl 设置 TTL。
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

/// 辅助函数 — 生成有效 nonce（base64(timestamp:uuid)）。
fn make_valid_nonce() -> String {
    let timestamp = current_unix_seconds();
    let random = Uuid::new_v4().simple().to_string();
    let raw = format!("{}:{}", timestamp, random);
    STANDARD.encode(raw.as_bytes())
}

/// 辅助函数 — 生成过期 nonce（时间戳在 TTL 之前）。
fn make_expired_nonce(ttl: u64) -> String {
    let expired_timestamp = current_unix_seconds().saturating_sub(ttl + 10);
    let random = Uuid::new_v4().simple().to_string();
    let raw = format!("{}:{}", expired_timestamp, random);
    STANDARD.encode(raw.as_bytes())
}

/// 辅助函数 — 生成未来 nonce（时间戳在未来）。
fn make_future_nonce() -> String {
    let future_timestamp = current_unix_seconds() + 100;
    let random = Uuid::new_v4().simple().to_string();
    let raw = format!("{}:{}", future_timestamp, random);
    STANDARD.encode(raw.as_bytes())
}

/// 辅助函数 — 构造合法 MD5 Authorization header。
#[allow(clippy::too_many_arguments)]
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

/// 辅助函数 — 构造合法 SHA256 Authorization header。
#[allow(clippy::too_many_arguments)]
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

/// 过期 nonce 被拒绝。
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

/// 未来 nonce 被拒绝（防止伪造未来时间戳）。
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

/// 非 base64 格式的 nonce 被拒绝。
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

/// 自定义 TTL — 短 TTL 的过期 nonce 被拒绝，但刚生成的 nonce 通过。
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

/// validate_with_body 支持 qop=auth-int（MD5）。
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

/// validate_with_body 支持 qop=auth-int（SHA256）。
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

/// validate_with_body 中 body 不匹配导致校验失败。
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

/// validate_with_body 也支持 qop=auth（body 被忽略）。
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

/// is_nonce_valid 对空字符串返回 false。
#[test]
fn is_nonce_valid_empty_returns_false() {
    let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
    assert!(!auth.is_nonce_valid(""));
}

/// is_nonce_valid 对纯文本（非 base64）返回 false。
#[test]
fn is_nonce_valid_plain_text_returns_false() {
    let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
    assert!(!auth.is_nonce_valid("abc123nonce"));
}

/// is_nonce_valid 对缺少冒号分隔符的 base64 返回 false。
#[test]
fn is_nonce_valid_no_colon_returns_false() {
    let auth = HttpDigestAuth::new("realm", "MD5").unwrap();
    // base64("12345") — 无冒号
    let nonce = STANDARD.encode(b"12345");
    assert!(!auth.is_nonce_valid(&nonce));
}

/// is_nonce_valid 对时间戳非数字返回 false。
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
// vuln-0008: nc 单调性校验测试（RFC 7616 §3.4.6 重放防护）
// ========================================================================

/// `validate_nc` 首次使用 nonce 时接受任意 nc（with DAO）。
///
/// 场景：注入 DAO，首次请求 nc=00000001 应通过。
#[tokio::test(flavor = "multi_thread")]
async fn validate_nc_first_use_accepted_with_dao() {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(crate::dao::MockDao::new());
    let auth = HttpDigestAuth::new("test@realm", "MD5")
        .unwrap()
        .with_dao(dao);
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
    assert!(
        auth.validate(&header, method, uri, &ha1),
        "vuln-0008: 首次使用 nonce 应通过 nc 校验"
    );
}

/// `validate_nc` 拒绝同一 nonce 的 nc 重复（重放攻击，with DAO）。
///
/// 场景：注入 DAO，第一次 nc=00000001 通过，第二次相同 nc=00000001 应被拒绝。
#[tokio::test(flavor = "multi_thread")]
async fn validate_nc_replay_rejected_with_dao() {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(crate::dao::MockDao::new());
    let auth = HttpDigestAuth::new("test@realm", "MD5")
        .unwrap()
        .with_dao(dao);
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
    // 第一次：通过
    assert!(
        auth.validate(&header, method, uri, &ha1),
        "vuln-0008: 首次请求应通过"
    );
    // 第二次相同 nc：应被拒绝（重放）
    assert!(
        !auth.validate(&header, method, uri, &ha1),
        "vuln-0008: 相同 nc 重放应被拒绝"
    );
}

/// `validate_nc` 拒绝 nc 回退（with DAO）。
///
/// 场景：注入 DAO，第一次 nc=00000003 通过，第二次 nc=00000002 应被拒绝（nc 回退）。
#[tokio::test(flavor = "multi_thread")]
async fn validate_nc_decrease_rejected_with_dao() {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(crate::dao::MockDao::new());
    let auth = HttpDigestAuth::new("test@realm", "MD5")
        .unwrap()
        .with_dao(dao);
    let ha1 = auth.compute_ha1("admin", "secret");
    let nonce = make_valid_nonce();
    let cnonce = "0a4f113c";
    let method = "GET";
    let uri = "/resource";
    // 第一次 nc=00000003
    let header1 = build_md5_auth_header(
        &auth,
        "admin",
        "test@realm",
        &nonce,
        "00000003",
        cnonce,
        method,
        uri,
        &ha1,
    );
    assert!(
        auth.validate(&header1, method, uri, &ha1),
        "vuln-0008: nc=3 应通过"
    );
    // 第二次 nc=00000002（回退）应被拒绝
    let header2 = build_md5_auth_header(
        &auth,
        "admin",
        "test@realm",
        &nonce,
        "00000002",
        cnonce,
        method,
        uri,
        &ha1,
    );
    assert!(
        !auth.validate(&header2, method, uri, &ha1),
        "vuln-0008: nc 回退（3→2）应被拒绝"
    );
}

/// `validate_nc` 接受 nc 单调递增（with DAO）。
///
/// 场景：注入 DAO，nc=1→2→3 连续递增，每次都应通过。
#[tokio::test(flavor = "multi_thread")]
async fn validate_nc_increasing_accepted_with_dao() {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(crate::dao::MockDao::new());
    let auth = HttpDigestAuth::new("test@realm", "MD5")
        .unwrap()
        .with_dao(dao);
    let ha1 = auth.compute_ha1("admin", "secret");
    let nonce = make_valid_nonce();
    let cnonce = "0a4f113c";
    let method = "GET";
    let uri = "/resource";
    for i in 1..=3u64 {
        let nc = format!("{:08x}", i);
        let header = build_md5_auth_header(
            &auth,
            "admin",
            "test@realm",
            &nonce,
            &nc,
            cnonce,
            method,
            uri,
            &ha1,
        );
        assert!(
            auth.validate(&header, method, uri, &ha1),
            "vuln-0008: nc={} 应通过（单调递增）",
            nc
        );
    }
}

/// 未注入 DAO 时跳过 nc 校验（向后兼容）。
///
/// 场景：不注入 DAO（dao=None），相同 nc 重放仍被接受（仅依赖 nonce TTL 防重放）。
#[tokio::test(flavor = "multi_thread")]
async fn validate_nc_skipped_without_dao() {
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
    // 第一次：通过
    assert!(
        auth.validate(&header, method, uri, &ha1),
        "vuln-0008: 无 DAO 时首次请求应通过"
    );
    // 第二次相同 nc：仍通过（无 DAO 跳过 nc 校验，向后兼容）
    assert!(
        auth.validate(&header, method, uri, &ha1),
        "vuln-0008: 无 DAO 时相同 nc 重放仍通过（向后兼容）"
    );
}

/// 不同 nonce 的 nc 计数独立（with DAO）。
///
/// 场景：注入 DAO，nonce-A nc=1 通过，nonce-B nc=1 也应通过（不同 nonce 独立计数）。
#[tokio::test(flavor = "multi_thread")]
async fn validate_nc_isolates_nonces_with_dao() {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(crate::dao::MockDao::new());
    let auth = HttpDigestAuth::new("test@realm", "MD5")
        .unwrap()
        .with_dao(dao);
    let ha1 = auth.compute_ha1("admin", "secret");
    let cnonce = "0a4f113c";
    let method = "GET";
    let uri = "/resource";
    let nc = "00000001";
    // nonce-A nc=1
    let nonce_a = make_valid_nonce();
    let header_a = build_md5_auth_header(
        &auth,
        "admin",
        "test@realm",
        &nonce_a,
        nc,
        cnonce,
        method,
        uri,
        &ha1,
    );
    assert!(
        auth.validate(&header_a, method, uri, &ha1),
        "vuln-0008: nonce-A nc=1 应通过"
    );
    // nonce-B nc=1（不同 nonce，应独立计数，通过）
    let nonce_b = make_valid_nonce();
    let header_b = build_md5_auth_header(
        &auth,
        "admin",
        "test@realm",
        &nonce_b,
        nc,
        cnonce,
        method,
        uri,
        &ha1,
    );
    assert!(
        auth.validate(&header_b, method, uri, &ha1),
        "vuln-0008: nonce-B nc=1 应通过（不同 nonce 独立计数）"
    );
}

// ========================================================================
// vuln-0008 三维度审查修复验证测试
// ========================================================================

/// `validate_nc` 在 current_thread runtime 下 fail-closed（vuln-0012 修复验证）。
///
/// 场景：注入 DAO，但在 current_thread tokio runtime 下调用 validate()。
/// validate_nc 检测到 current_thread runtime 后应 fail-closed（不调用 block_in_place，
/// 否则会 panic "Cannot block the current thread from within a runtime"），
/// 返回 false 拒绝请求，避免允许重放攻击。
///
/// vuln-0012 修复：原 fail-open 允许重放，违背 RFC 7616 §3.4.6。
/// 注意：使用 `#[tokio::test]`（不带 `flavor = "multi_thread"`）创建 current_thread runtime。
#[tokio::test]
async fn validate_nc_current_thread_runtime_fail_closed() {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(crate::dao::MockDao::new());
    let auth = HttpDigestAuth::new("test@realm", "MD5")
        .unwrap()
        .with_dao(dao);
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
    // 第一次：current_thread runtime 下 fail-closed，应拒绝（不 panic，但拒绝重放风险）
    assert!(
        !auth.validate(&header, method, uri, &ha1),
        "vuln-0012: current_thread runtime 下 validate_nc 应 fail-closed，首次请求拒绝"
    );
    // 第二次相同 nc：仍 fail-closed，应拒绝
    assert!(
        !auth.validate(&header, method, uri, &ha1),
        "vuln-0012: current_thread runtime 下相同 nc 重放仍拒绝（fail-closed）"
    );
}

/// 始终返回 DAO 错误的 mock DAO。
///
/// 用于触发 `validate_nc` 的 fail-closed 路径（vuln-0012 修复：DAO 错误时拒绝请求）。
struct FailingDao;

#[async_trait::async_trait]
impl crate::dao::GarrisonDao for FailingDao {
    async fn get(&self, key: &str) -> crate::error::GarrisonResult<Option<String>> {
        Err(crate::error::GarrisonError::Dao(format!(
            "vuln-0012-failing-dao-get::{}",
            key
        )))
    }
    async fn set(
        &self,
        key: &str,
        _value: &str,
        _ttl_seconds: u64,
    ) -> crate::error::GarrisonResult<()> {
        Err(crate::error::GarrisonError::Dao(format!(
            "vuln-0012-failing-dao-set::{}",
            key
        )))
    }
    async fn update(&self, key: &str, _value: &str) -> crate::error::GarrisonResult<()> {
        Err(crate::error::GarrisonError::Dao(format!(
            "vuln-0012-failing-dao-update::{}",
            key
        )))
    }
    async fn expire(&self, key: &str, _seconds: u64) -> crate::error::GarrisonResult<()> {
        Err(crate::error::GarrisonError::Dao(format!(
            "vuln-0012-failing-dao-expire::{}",
            key
        )))
    }
    async fn delete(&self, key: &str) -> crate::error::GarrisonResult<()> {
        Err(crate::error::GarrisonError::Dao(format!(
            "vuln-0012-failing-dao-delete::{}",
            key
        )))
    }
}

/// `validate_nc` 在 DAO 错误时 fail-closed（vuln-0012 修复验证）。
///
/// 场景：注入始终返回错误的 FailingDao，validate_nc 内部 compare_and_update_if_greater
/// 调用 DAO 失败后应 fail-closed（返回 false），拒绝请求防止重放攻击。
///
/// vuln-0012 修复：原 fail-open 允许重放（接受请求），违背 RFC 7616 §3.4.6。
/// nonce TTL（300s）不足以防重放（窗口内仍可重放），必须 fail-closed。
#[tokio::test(flavor = "multi_thread")]
async fn validate_nc_dao_error_fail_closed() {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(FailingDao);
    let auth = HttpDigestAuth::new("test@realm", "MD5")
        .unwrap()
        .with_dao(dao);
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
    // DAO 错误时 fail-closed，应拒绝
    assert!(
        !auth.validate(&header, method, uri, &ha1),
        "vuln-0012: DAO 错误时 validate_nc 应 fail-closed（拒绝请求）"
    );
    // 再次调用，DAO 仍错误，仍 fail-closed（拒绝重放）
    assert!(
        !auth.validate(&header, method, uri, &ha1),
        "vuln-0012: DAO 错误时相同 nc 重放仍拒绝（fail-closed）"
    );
}

/// `validate_nc` 在无 tokio runtime 时 fail-closed（vuln-0012 修复验证，LOW-sec 补充）。
///
/// 场景：注入 DAO，但 `validate()` 在非 async 上下文中调用（无 tokio runtime）。
/// `Handle::try_current()` 返回 `Err`，validate_nc 应 fail-closed（返回 false），
/// 拒绝请求防止重放攻击，而不是 fail-open 允许重放。
///
/// vuln-0012 修复：原 fail-open 允许重放，违背 RFC 7616 §3.4.6。
/// 注意：使用普通 `#[test]`（不引入 tokio runtime），与 `#[tokio::test]` 区分。
#[test]
fn validate_nc_no_runtime_fail_closed() {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(crate::dao::MockDao::new());
    let auth = HttpDigestAuth::new("test@realm", "MD5")
        .unwrap()
        .with_dao(dao);
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
    // 无 tokio runtime 时 fail-closed，应拒绝（不 panic，但拒绝重放风险）
    assert!(
        !auth.validate(&header, method, uri, &ha1),
        "vuln-0012: 无 tokio runtime 时 validate_nc 应 fail-closed，拒绝请求"
    );
    // 第二次相同 nc：仍 fail-closed，应拒绝
    assert!(
        !auth.validate(&header, method, uri, &ha1),
        "vuln-0012: 无 tokio runtime 时相同 nc 重放仍拒绝（fail-closed）"
    );
}

/// `validate_nc` 拒绝非 hex 格式的 nc（LOW-2 修复验证）。
///
/// 场景：nc="gggggggg"（非 hex 字符），`u64::from_str_radix(_, 16)` 解析失败，
/// validate_nc 返回 false（拒绝畸形请求，不是 fail-open）。
#[tokio::test(flavor = "multi_thread")]
async fn validate_nc_malformed_hex_rejected() {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(crate::dao::MockDao::new());
    let auth = HttpDigestAuth::new("test@realm", "MD5")
        .unwrap()
        .with_dao(dao);
    let ha1 = auth.compute_ha1("admin", "secret");
    let nonce = make_valid_nonce();
    // "gggggggg" 不是有效的 hex 字符
    let nc = "gggggggg";
    let cnonce = "0a4f113c";
    let method = "GET";
    let uri = "/resource";
    // 构造 header 时 nc 字段直接放入（parse_authorization 仅提取字符串，不校验格式）
    let header = format!(
        r#"Digest username="admin", realm="test@realm", nonce="{}", uri="{}", response="dummy", qop=auth, nc={}, cnonce="{}""#,
        nonce, uri, nc, cnonce
    );
    // nc 非 hex 格式 → validate_nc 返回 false → validate 返回 false
    assert!(
        !auth.validate(&header, method, uri, &ha1),
        "LOW-2: 非 hex 格式的 nc 应被拒绝（不是 fail-open）"
    );
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
