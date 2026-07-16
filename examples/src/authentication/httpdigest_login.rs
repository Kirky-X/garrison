//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! HTTP Digest 认证示例：演示 RFC 7616 质询生成、HA1 预计算与响应校验。
//!
//! 对应模块：`src/secure/httpdigest/mod.rs`（feature: secure-httpdigest）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin httpdigest_login --features secure-httpdigest
//! ```

use bulwark::error::BulwarkResult;
use bulwark::secure::httpdigest::HttpDigestAuth;

/// 运行 HTTP Digest 认证示例。
///
/// 演示 HttpDigestAuth 构造、WWW-Authenticate 质询头生成、
/// compute_ha1 预计算摘要、validate 校验客户端 Authorization header。
pub fn run() -> BulwarkResult<()> {
    println!("=== Bulwark HTTP Digest 认证示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 构造 Digest 认证工具并生成质询头
    // ----------------------------------------------------------------
    // VULN-0016 修复后：默认算法为 SHA256（更安全），qop 声明支持 auth 和 auth-int，
    // nonce 格式为 base64(timestamp:uuid)，validate 时校验时间戳防过期。
    let auth = HttpDigestAuth::new("bulwark@realm", "SHA256")?;
    let challenge = auth.challenge();
    println!("[1] WWW-Authenticate 质询头:");
    println!("    {}\n", challenge);
    assert!(challenge.starts_with("Digest "));
    assert!(challenge.contains(r#"realm="bulwark@realm""#));
    assert!(challenge.contains(r#"qop="auth,auth-int""#));
    assert!(challenge.contains("algorithm=SHA256"));

    // ----------------------------------------------------------------
    // 2. 预计算 HA1 = H(username:realm:password)
    // ----------------------------------------------------------------
    let username = "admin";
    let password = "secret";
    let ha1 = auth.compute_ha1(username, password);
    println!("[2] compute_ha1（预计算摘要，避免持有明文密码）:");
    println!("    username = {}", username);
    println!("    realm    = bulwark@realm");
    println!("    HA1      = {}\n", ha1);

    // ----------------------------------------------------------------
    // 3. 模拟客户端构造 Authorization header 并由服务端 validate
    // ----------------------------------------------------------------
    // VULN-0016: 客户端从质询头提取 nonce（base64(timestamp:uuid) 格式），
    // 使用 HA1 + nonce + method + uri 计算 response。
    let nonce = extract_nonce_from_challenge(&challenge)
        .ok_or_else(|| bulwark::error::BulwarkError::Internal("无法提取 nonce".into()))?;
    let nc = "00000001";
    let cnonce = "0a4f113c";
    let method = "GET";
    let uri = "/protected/resource";

    // 计算 HA2 = H(method:uri)（使用 SHA256）
    use sha2::Digest;
    let ha2_input = format!("{}:{}", method, uri);
    let mut h2 = sha2::Sha256::new();
    h2.update(ha2_input.as_bytes());
    let ha2_hex: String = h2.finalize().iter().map(|b| format!("{:02x}", b)).collect();

    // 计算 response = H(HA1:nonce:nc:cnonce:qop:HA2)
    let resp_input = format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2_hex);
    let mut h = sha2::Sha256::new();
    h.update(resp_input.as_bytes());
    let resp_hex: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();

    // 构造客户端 Authorization header
    let client_header = format!(
        r#"Digest username="{}", realm="bulwark@realm", nonce="{}", uri="{}", response="{}", qop=auth, nc={}, cnonce="{}""#,
        username, nonce, uri, resp_hex, nc, cnonce
    );
    println!("[3] 客户端构造的 Authorization header:");
    println!("    {}\n", client_header);

    // 服务端校验（使用预计算的 HA1）
    let valid = auth.validate(&client_header, method, uri, &ha1);
    println!("    validate 结果 = {}\n", valid);
    assert!(valid, "合法凭证应校验通过");

    // ----------------------------------------------------------------
    // 4. 错误密码校验失败
    // ----------------------------------------------------------------
    let ha1_wrong = auth.compute_ha1(username, "wrong-password");
    let invalid = auth.validate(&client_header, method, uri, &ha1_wrong);
    println!("[4] 错误密码校验:");
    println!("    validate 结果 = {}（应为 false）\n", invalid);
    assert!(!invalid, "错误密码应校验失败");

    // ----------------------------------------------------------------
    // 5. auth-int 模式（带请求体校验）
    // ----------------------------------------------------------------
    println!("[5] auth-int 模式（带请求体校验）:");
    let auth_int = HttpDigestAuth::new("secure@realm", "SHA256")?;
    let ha1_int = auth_int.compute_ha1(username, password);
    let challenge_int = auth_int.challenge();
    let nonce_int = extract_nonce_from_challenge(&challenge_int)
        .ok_or_else(|| bulwark::error::BulwarkError::Internal("无法提取 nonce".into()))?;
    let body = b"request-body-content";
    let method_int = "POST";
    let uri_int = "/api/data";

    // HA2 = H(method:uri:H(body))
    let body_hash = {
        let mut bh = sha2::Sha256::new();
        bh.update(body);
        bh.finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    };
    let ha2_int_input = format!("{}:{}:{}", method_int, uri_int, body_hash);
    let mut h2i = sha2::Sha256::new();
    h2i.update(ha2_int_input.as_bytes());
    let ha2_int_hex: String = h2i
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let resp_int_input = format!(
        "{}:{}:{}:{}:auth-int:{}",
        ha1_int, nonce_int, nc, cnonce, ha2_int_hex
    );
    let mut hi = sha2::Sha256::new();
    hi.update(resp_int_input.as_bytes());
    let resp_int_hex: String = hi.finalize().iter().map(|b| format!("{:02x}", b)).collect();

    let header_int = format!(
        r#"Digest username="{}", realm="secure@realm", nonce="{}", uri="{}", response="{}", qop=auth-int, nc={}, cnonce="{}""#,
        username, nonce_int, uri_int, resp_int_hex, nc, cnonce
    );
    let valid_int = auth_int.validate_with_body(&header_int, method_int, uri_int, body, &ha1_int);
    println!("    validate_with_body 结果 = {}\n", valid_int);
    assert!(valid_int, "auth-int 合法凭证应校验通过");

    println!("=== 示例执行完成 ===");
    Ok(())
}

/// 从质询头中提取 nonce 值。
fn extract_nonce_from_challenge(challenge: &str) -> Option<String> {
    let start = challenge.find("nonce=\"")? + "nonce=\"".len();
    let end = challenge[start..].find('"')? + start;
    Some(challenge[start..end].to_string())
}
