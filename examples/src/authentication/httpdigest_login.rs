//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
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
    let auth = HttpDigestAuth::new("bulwark@realm", "MD5")?;
    let challenge = auth.challenge();
    println!("[1] WWW-Authenticate 质询头:");
    println!("    {}\n", challenge);
    assert!(challenge.starts_with("Digest "));
    assert!(challenge.contains(r#"realm="bulwark@realm""#));
    assert!(challenge.contains(r#"qop="auth""#));
    assert!(challenge.contains("algorithm=MD5"));

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
    // 客户端收到质询后，使用 HA1 + nonce + method + uri 计算 response
    let nonce = "abc123nonce";
    let nc = "00000001";
    let cnonce = "0a4f113c";
    let method = "GET";
    let uri = "/protected/resource";

    // 计算 HA2 = H(method:uri)
    let ha2_input = format!("{}:{}", method, uri);
    let ha2 = md5::compute(ha2_input.as_bytes());
    let ha2_hex: String = ha2.0.iter().map(|b| format!("{:02x}", b)).collect();

    // 计算 response = H(HA1:nonce:nc:cnonce:qop:HA2)
    let resp_input = format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2_hex);
    let resp = md5::compute(resp_input.as_bytes());
    let resp_hex: String = resp.0.iter().map(|b| format!("{:02x}", b)).collect();

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
    // 5. SHA256 算法支持
    // ----------------------------------------------------------------
    let auth_sha256 = HttpDigestAuth::new("secure@realm", "SHA256")?;
    let challenge_sha256 = auth_sha256.challenge();
    println!("[5] SHA256 算法质询头:");
    println!("    {}\n", challenge_sha256);
    assert!(challenge_sha256.contains("algorithm=SHA256"));

    let ha1_sha256 = auth_sha256.compute_ha1(username, password);
    println!("    SHA256 HA1 长度 = {} 字符\n", ha1_sha256.len());
    assert_eq!(ha1_sha256.len(), 64);

    println!("=== 示例执行完成 ===");
    Ok(())
}
