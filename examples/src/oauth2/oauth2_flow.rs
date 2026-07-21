//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 Authorization Code 流程示例（依据 spec protocol-oauth2）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin oauth2_flow --features protocol-oauth2
//! ```
//!
//! 本示例演示：
//! 1. 构造 `OAuth2Client`
//! 2. 生成授权 URL（引导用户跳转到授权服务器）
//! 3. 使用授权码换取令牌（`exchange_code`，需要真实授权服务器，此处仅展示调用方式）
//! 4. `refresh_access_token` 刷新令牌（仅展示调用方式，不实际发起 HTTP 请求）
//!
//! `exchange_code` / `get_client_credentials_token` / `get_password_token` /
//! `refresh_access_token` 会发起真实 HTTP 请求，本示例不实际调用以避免依赖外部服务；
//! 如需端到端测试参见 `tests/protocol_oauth2_integration.rs`（使用 wiremock mock server）。

use garrison::protocol::oauth2::OAuth2Client;

/// 运行 OAuth2 流程示例。
///
/// 构造 OAuth2Client、生成授权 URL，并展示 exchange_code 的调用方式。
/// 不实际发起 HTTP 请求（避免依赖外部授权服务器）。
#[allow(deprecated)]
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Garrison OAuth2 Authorization Code 流程示例 ===\n");

    // 1. 构造 OAuth2Client（参数来自你在授权服务器的应用注册）
    let client = OAuth2Client::new(
        "my-client-id",
        "my-client-secret",
        "https://myapp.example.com/callback",
        "https://auth.example.com/oauth2/authorize",
        "https://auth.example.com/oauth2/token",
    )?
    .with_user_info_url("https://auth.example.com/oauth2/userinfo");

    println!("[配置] 授权端点：{}", client.auth_url());
    println!("[配置] 令牌端点：{}", client.token_url());
    println!("[配置] 用户信息端点：{:?}", client.user_info_url());

    // 2. 生成授权 URL（引导用户浏览器跳转至此 URL 完成授权）
    let state = "random-csrf-state-12345";
    let auth_url = client.get_auth_url(state);
    println!("\n[授权 URL]\n{}", auth_url);
    assert!(auth_url.contains("client_id=my-client-id"));
    assert!(auth_url.contains("response_type=code"));
    assert!(auth_url.contains("state=random-csrf-state-12345"));
    println!(
        "\n（用户在授权服务器登录并同意授权后，会被重定向到 redirect_uri，附带 code 与 state）"
    );

    println!("\n[说明] exchange_code 需真实授权服务器，本示例不实际调用。");
    println!("       端到端测试见 tests/protocol_oauth2_integration.rs。");

    // 3. 演示 refresh_access_token 的调用方式（access_token 过期后用 refresh_token 刷新）
    //
    // 与 exchange_code 一样，refresh_access_token 会发起真实 HTTP 请求，
    // 本示例不实际调用，仅展示调用方式与返回值结构。
    println!("\n[刷新令牌] refresh_access_token 调用方式:");
    println!("    // access_token 过期后，使用 refresh_token 换取新的 access_token");
    println!("    // 参数：refresh_token（必填，非空）、scope（可选，仅能缩小原 scope）");
    println!("    let token = client");
    println!("        .refresh_access_token(\"old-refresh-token\", None)");
    println!("        .await?;");
    println!("    // 返回 TokenResponse：");
    println!("    //   access_token  — 新的访问令牌");
    println!("    //   token_type    — 通常为 \"Bearer\"");
    println!("    //   expires_in    — 有效期（秒）");
    println!("    //   refresh_token — 可能返回新的 refresh_token（可选，取决于授权服务器策略）");
    println!("    //   scope         — 实际授权 scope（可选）");
    println!();
    println!("    // 也可在刷新时显式指定 scope（仅能缩小原 scope，不能扩大）:");
    println!("    let token = client");
    println!("        .refresh_access_token(\"old-refresh-token\", Some(\"openid profile\"))");
    println!("        .await?;");
    println!();
    println!("    // refresh_token 为空时返回 InvalidParam 错误（Fail Loud）:");
    println!("    //   client.refresh_access_token(\"\", None).await");
    println!("    //   → Err(GarrisonError::InvalidParam(\"refresh_token 不可为空\"))");
    println!("\n[说明] refresh_access_token 需真实 token 端点，本示例不实际调用。");
    println!(
        "       端到端测试见 src/protocol/oauth2/mod.rs 的 refresh_access_token_success 测试。"
    );

    println!("\n=== 示例完成 ===");
    Ok(())
}
