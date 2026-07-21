//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth 2.1 PKCE 示例（v0.4.2 新增，依据 spec oauth-2-1-upgrade R-oauth-2-1-001）。
//!
//! 演示 `OAuth2Client` 的 PKCE 流程：
//! - `generate_pkce_challenge`：从 code_verifier 计算 code_challenge（S256）
//! - `get_auth_url_with_pkce`：构造带 PKCE 的授权 URL
//! - `exchange_code_with_pkce`：用授权码 + code_verifier 换取令牌
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin oauth2_pkce --features protocol-oauth2
//! ```
//!
//! 本示例仅展示客户端构造与 URL 生成，不实际发起 HTTP 请求。
//! 端到端测试见 `tests/protocol_oauth2_integration.rs`（使用 wiremock mock server）。

use garrison::error::GarrisonError;
use garrison::protocol::oauth2::OAuth2Client;

/// 运行 OAuth 2.1 PKCE 示例。
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Garrison OAuth 2.1 PKCE 示例 ===\n");

    // 1. 构造 OAuth2Client
    let client = OAuth2Client::new(
        "my-client-id",
        "my-client-secret",
        "https://myapp.example.com/callback",
        "https://auth.example.com/oauth2/authorize",
        "https://auth.example.com/oauth2/token",
    )?;
    println!("[1] OAuth2Client 构造完成");
    println!("    client_id:    my-client-id");
    println!("    redirect_uri: https://myapp.example.com/callback");
    println!("    auth_url:     https://auth.example.com/oauth2/authorize");
    println!("    token_url:    https://auth.example.com/oauth2/token\n");

    // 2. 生成 code_verifier（RFC 7636 §4.1：43-128 字符，[A-Z]/[a-z]/[0-9]/-./_/~）
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    println!("[2] 生成 code_verifier");
    println!("    code_verifier: {}", code_verifier);
    println!("    长度: {}（合法范围 43-128）", code_verifier.len());

    // 3. 计算 code_challenge（S256 = base64url_no_pad(sha256(code_verifier))）
    let code_challenge = OAuth2Client::generate_pkce_challenge(code_verifier)?;
    println!("\n[3] 计算 code_challenge（S256）");
    println!("    code_challenge: {}", code_challenge);
    // RFC 7636 Appendix B 测试向量
    assert_eq!(
        code_challenge,
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    println!("    ✓ 与 RFC 7636 Appendix B 测试向量一致\n");

    // 4. 构造带 PKCE 的授权 URL
    let state = "csrf-random-state-12345";
    let (auth_url, returned_challenge) = client.get_auth_url_with_pkce(state, code_verifier)?;
    println!("[4] 构造带 PKCE 的授权 URL");
    println!("    auth_url: {}", auth_url);
    assert!(auth_url.contains("response_type=code"));
    assert!(auth_url.contains("client_id=my-client-id"));
    assert!(auth_url.contains("state=csrf-random-state-12345"));
    assert!(auth_url.contains("code_challenge_method=S256"));
    assert!(auth_url.contains("code_challenge="));
    assert_eq!(returned_challenge, code_challenge);
    println!("    ✓ 包含 response_type=code");
    println!("    ✓ 包含 client_id + redirect_uri + state");
    println!("    ✓ 包含 code_challenge + code_challenge_method=S256\n");

    // 5. 展示 exchange_code_with_pkce 的调用方式（不实际发起 HTTP）
    println!("[5] exchange_code_with_pkce 调用方式");
    println!("    // 用户在授权服务器登录并同意授权后，浏览器重定向到：");
    println!(
        "    //   https://myapp.example.com/callback?code=AUTH_CODE&state={}",
        state
    );
    println!("    // 业务方校验 state 一致后，用 code + code_verifier 换取 token：");
    println!("    let token_response = client");
    println!(
        "        .exchange_code_with_pkce(\"AUTH_CODE\", \"{}\", \"ACTUAL_STATE\", \"{}\")",
        state, code_verifier
    );
    println!("        .await?;");
    println!("    // 返回 TokenResponse：");
    println!("    //   access_token  — 访问令牌");
    println!("    //   token_type    — 通常为 \"Bearer\"");
    println!("    //   expires_in    — 有效期（秒）");
    println!("    //   refresh_token — 刷新令牌（可选）");
    println!("    //   scope         — 实际授权 scope");
    println!();
    println!("    端到端测试见 tests/protocol_oauth2_integration.rs\n");

    // 6. 演示 code_verifier 校验失败
    println!("[6] code_verifier 校验失败（预期）");
    let short_verifier = "too-short";
    let result = OAuth2Client::generate_pkce_challenge(short_verifier);
    assert!(result.is_err(), "长度不足 43 应失败");
    match result.unwrap_err() {
        GarrisonError::InvalidParam(msg) => {
            println!("    generate_pkce_challenge(\"{}\") → Err", short_verifier);
            println!("    错误：{}", msg);
            println!("    ✓ 长度 < 43 正确拒绝");
        },
        other => {
            return Err(format!("期望 InvalidParam，实际: {:?}", other).into());
        },
    }

    let invalid_chars = "contains spaces and special!chars<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<";
    let result = OAuth2Client::generate_pkce_challenge(invalid_chars);
    assert!(result.is_err(), "非法字符应失败");
    match result.unwrap_err() {
        GarrisonError::InvalidParam(msg) => {
            println!("\n    generate_pkce_challenge(\"contains spaces...\") → Err");
            println!("    错误：{}", msg);
            println!("    ✓ 非法字符正确拒绝");
        },
        other => {
            return Err(format!("期望 InvalidParam，实际: {:?}", other).into());
        },
    }

    println!("\n=== 示例完成 ===");
    println!("\nPKCE 安全收益：");
    println!("  - 防止授权码注入攻击（攻击者无法构造合法 code_verifier）");
    println!("  - 防止授权码截获攻击（即使截获 code 也无法换取 token）");
    println!("  - OAuth 2.1 强制要求所有 Authorization Code 流程使用 PKCE");
    Ok(())
}
