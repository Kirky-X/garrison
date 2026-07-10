//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OIDC（OpenID Connect）处理器示例（依据 spec oauth2-oidc，0.4.0 新增）。
//!
//! 演示 `OidcHandler` 完整流程：
//! 1. 创建 OidcHandler（issuer / audience / secret）
//! 2. `sign_id_token` 签发 id_token（JWT 格式，含 iss/sub/aud/exp/iat/nonce claims）
//! 3. `verify_id_token` 校验 id_token 并提取 claims
//! 4. `discovery_metadata` 生成 OIDC discovery endpoint JSON
//! 5. nonce 不匹配时校验失败
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin oidc_handler --features protocol-oidc
//! ```

use bulwark::error::BulwarkError;
use bulwark::protocol::oauth2::oidc::OidcHandler;

/// 运行 OIDC 处理器示例。
///
/// 演示 OidcHandler 的 sign_id_token / verify_id_token / discovery_metadata 完整流程，
/// 包括 nonce 不匹配时返回 OAuth2 错误的场景。
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark OIDC 处理器示例 ===\n");

    // 1. 创建 OidcHandler（issuer / audience / secret）
    let handler = OidcHandler::new(
        "https://auth.example.com",
        "my-client-id",
        "super-secret-key",
    )?;
    println!("[配置] issuer: https://auth.example.com");
    println!("[配置] audience: my-client-id");
    println!("[配置] 算法: HS256（默认）\n");

    // 2. 签发 id_token
    let login_id = "1001";
    let nonce = "random-nonce-abc123";
    let id_token = handler.sign_id_token(login_id, nonce, "openid profile", 3600)?;
    println!("[签发] id_token（前 40 字符）: {}...", &id_token[..40]);
    println!(
        "       login_id={}, nonce={}, scope=openid profile, timeout=3600s\n",
        login_id, nonce
    );

    // 3. 校验 id_token（nonce 匹配 → 成功）
    let claims = handler.verify_id_token(&id_token, nonce)?;
    println!("[校验] 校验成功，提取 claims:");
    println!("    iss     = {}", claims.iss);
    println!("    sub     = {}", claims.sub);
    println!("    aud     = {}", claims.aud);
    println!("    login_id = {}", claims.login_id);
    println!("    nonce   = {}", claims.nonce);
    println!("    iat     = {}", claims.iat);
    println!("    exp     = {}（iat + 3600）\n", claims.exp);
    assert_eq!(claims.login_id, login_id);
    assert_eq!(claims.nonce, nonce);
    assert_eq!(claims.iss, "https://auth.example.com");
    assert_eq!(claims.aud, "my-client-id");
    assert!(claims.exp > claims.iat);

    // 4. 生成 OIDC discovery endpoint 元数据
    let metadata = handler.discovery_metadata();
    println!("[Discovery] OIDC discovery metadata:");
    println!(
        "    {}",
        serde_json::to_string_pretty(&metadata).expect("序列化 metadata 失败")
    );
    assert_eq!(metadata["issuer"], "https://auth.example.com");
    assert!(metadata["authorization_endpoint"]
        .as_str()
        .expect("authorization_endpoint 应为字符串")
        .ends_with("/authorize"));
    assert!(metadata["id_token_signing_alg_values_supported"]
        .as_array()
        .expect("id_token_signing_alg_values_supported 应为数组")
        .contains(&serde_json::json!("HS256")));
    println!();

    // 5. nonce 不匹配时校验失败（防重放保护）
    println!("[校验] nonce 不匹配场景（防重放保护）:");
    match handler.verify_id_token(&id_token, "wrong-nonce") {
        Err(BulwarkError::OAuth2(msg)) => {
            println!("    校验失败（预期）: {}", msg);
            assert!(msg.contains("nonce mismatch"));
        },
        other => panic!("期望 OAuth2 错误（nonce mismatch），实际: {:?}", other),
    }
    println!();

    println!("=== 示例完成 ===");
    Ok(())
}
