//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 授权服务器完整流程示例：客户端注册 → 授权码 → Token 交换 → 内省 → 吊销。
//!
//! 演示 Garrison OAuth2 Server 模块（AS 角色）的完整业务链路：
//! 1. 客户端注册（OAuth2Client + Argon2id 密钥哈希存储）
//! 2. 授权码流程（/authorize + PKCE S256）
//! 3. Token 交换（/token，authorization_code grant）
//! 4. Token 内省（/introspect，RFC 7662）
//! 5. Token 吊销（/revoke，RFC 7009）
//! 6. Client Credentials 流程（服务间调用）
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin oauth2_server_flow --features "oauth2-server cache-memory"
//! ```
//!
//! 本示例使用 oxcache 内存 DAO，无需外部依赖即可运行。

use async_trait::async_trait;
use garrison::dao::{GarrisonDao, GarrisonDaoOxcache};
use garrison::error::GarrisonResult;
use garrison::oauth2_server::authorize::{
    generate_code_challenge, AuthorizeHandler, AuthorizeRequest, AuthorizeResponse,
};
use garrison::oauth2_server::client::{
    DaoOAuth2ClientStore, GrantType, OAuth2Client, OAuth2ClientStore,
};
use garrison::oauth2_server::introspect::{IntrospectHandler, IntrospectRequest};
use garrison::oauth2_server::revoke::{RevokeHandler, RevokeRequest};
use garrison::oauth2_server::token::{PasswordVerifier, TokenHandler, TokenRequest};
use std::sync::Arc;

/// Mock 密码验证器（示例用，业务方应实现真实密码校验逻辑）。
struct MockPasswordVerifier;

#[async_trait]
impl PasswordVerifier for MockPasswordVerifier {
    async fn verify(&self, username: &str, password: &str) -> GarrisonResult<Option<i64>> {
        if username == "admin" && password == "secret" {
            Ok(Some(1001))
        } else {
            Ok(None)
        }
    }
}

/// 运行 OAuth2 授权服务器完整流程。
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Garrison OAuth2 授权服务器完整流程 ===\n");

    // 基础设施初始化
    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await?);
    let store = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));

    // ================================================================
    // 步骤 1：注册 OAuth2 客户端
    // ================================================================
    println!("--- 步骤 1：注册 OAuth2 客户端 ---");

    let client = OAuth2Client::new(
        "my-app",
        "my-secret-123",
        vec!["https://app.example.com/callback".into()],
        vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            GrantType::Password,
        ],
        vec!["read".into(), "write".into()],
    )?;
    store.create(client).await?;
    println!("[1] 客户端已注册：client_id=my-app");
    println!("    client_secret 以 Argon2id 哈希存储（不明文）");
    println!("    redirect_uris: [https://app.example.com/callback]");
    println!("    grant_types: [authorization_code, refresh_token, client_credentials, password]");
    println!("    scopes: [read, write]\n");

    // 构建 handler 链
    let authorize_handler = Arc::new(AuthorizeHandler::new(
        store.clone(),
        dao.clone(),
        "https://auth.example.com/login".into(),
    ));
    let token_handler = Arc::new(
        TokenHandler::new(store.clone(), dao.clone(), authorize_handler.clone())
            .with_password_verifier(Arc::new(MockPasswordVerifier)),
    );
    let introspect_handler = Arc::new(IntrospectHandler::new(store.clone(), token_handler.clone()));
    let revoke_handler = Arc::new(RevokeHandler::new(store.clone(), token_handler.clone()));

    // ================================================================
    // 步骤 2：授权码流程（Authorization Code + PKCE）
    // ================================================================
    println!("--- 步骤 2：授权码流程（PKCE S256）---");

    // 2a. 客户端生成 PKCE code_verifier + code_challenge
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = generate_code_challenge(code_verifier);
    println!("[2a] PKCE 参数生成：");
    println!("    code_verifier: {}...", &code_verifier[..20]);
    println!("    code_challenge: {}...", &code_challenge[..20]);

    // 2b. 用户已登录，请求授权
    let auth_req = AuthorizeRequest {
        response_type: "code".into(),
        client_id: "my-app".into(),
        redirect_uri: "https://app.example.com/callback".into(),
        scope: Some("read write".into()),
        state: Some("random-state-xyz".into()),
        code_challenge: code_challenge.clone(),
        code_challenge_method: "S256".into(),
    };
    let auth_resp = authorize_handler.authorize(&auth_req, Some(1001)).await?;

    let code = match auth_resp {
        AuthorizeResponse::Redirect { location } => {
            let code = location
                .split("code=")
                .nth(1)
                .and_then(|s| s.split('&').next())
                .unwrap_or("")
                .to_string();
            println!("[2b] 授权成功，重定向到：{}", location);
            println!(
                "    提取授权码: {}...",
                &code[..std::cmp::min(20, code.len())]
            );
            code
        },
        _ => return Err("预期 Redirect 响应".into()),
    };

    // ================================================================
    // 步骤 3：授权码交换 Token
    // ================================================================
    println!("\n--- 步骤 3：授权码交换 Token ---");

    let token_req = TokenRequest {
        grant_type: "authorization_code".into(),
        client_id: "my-app".into(),
        client_secret: "my-secret-123".into(),
        code: Some(code.clone()),
        redirect_uri: Some("https://app.example.com/callback".into()),
        code_verifier: Some(code_verifier.to_string()),
        refresh_token: None,
        scope: None,
        username: None,
        password: None,
    };
    let token_resp = token_handler.handle(&token_req).await?;
    println!("[3] Token 交换成功：");
    println!("    access_token: {}...", &token_resp.access_token[..20]);
    println!("    token_type: {}", token_resp.token_type);
    println!("    expires_in: {}s", token_resp.expires_in);
    if let Some(ref rt) = token_resp.refresh_token {
        println!(
            "    refresh_token: {}...",
            &rt[..std::cmp::min(20, rt.len())]
        );
    }
    if let Some(ref scope) = token_resp.scope {
        println!("    scope: {}", scope);
    }

    // ================================================================
    // 步骤 4：Token 内省（RFC 7662）
    // ================================================================
    println!("\n--- 步骤 4：Token 内省（RFC 7662）---");

    let introspect_req = IntrospectRequest {
        token: token_resp.access_token.clone(),
        token_type_hint: Some("access_token".into()),
        client_id: "my-app".into(),
        client_secret: "my-secret-123".into(),
    };
    let introspect_resp = introspect_handler.handle(&introspect_req).await?;
    println!("[4] 内省结果：");
    println!("    active: {}", introspect_resp.active);
    if let Some(ref scope) = introspect_resp.scope {
        println!("    scope: {}", scope);
    }
    if let Some(ref client_id) = introspect_resp.client_id {
        println!("    client_id: {}", client_id);
    }
    assert!(introspect_resp.active, "有效 token 内省应返回 active=true");

    // ================================================================
    // 步骤 5：Token 吊销（RFC 7009）
    // ================================================================
    println!("\n--- 步骤 5：Token 吊销（RFC 7009）---");

    let revoke_req = RevokeRequest {
        token: token_resp.access_token.clone(),
        token_type_hint: Some("access_token".into()),
        client_id: "my-app".into(),
        client_secret: "my-secret-123".into(),
    };
    revoke_handler.handle(&revoke_req).await?;
    println!("[5] Token 已吊销");

    // 吊销后内省应返回 active=false
    let introspect_after = introspect_handler.handle(&introspect_req).await?;
    assert!(!introspect_after.active, "吊销后内省应返回 active=false");
    println!("    ✓ 吊销后内省验证：active=false");

    // ================================================================
    // 步骤 6：Client Credentials 流程（服务间调用）
    // ================================================================
    println!("\n--- 步骤 6：Client Credentials 流程（服务间调用）---");

    let cc_req = TokenRequest {
        grant_type: "client_credentials".into(),
        client_id: "my-app".into(),
        client_secret: "my-secret-123".into(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: Some("read".into()),
        username: None,
        password: None,
    };
    let cc_resp = token_handler.handle(&cc_req).await?;
    println!("[6] Client Credentials Token：");
    println!("    access_token: {}...", &cc_resp.access_token[..20]);
    println!("    token_type: {}", cc_resp.token_type);
    assert!(
        cc_resp.refresh_token.is_none(),
        "client_credentials 不返回 refresh_token"
    );
    println!("    ✓ 无 refresh_token（client_credentials 规范行为）");

    // ================================================================
    // 步骤 7：Password 流程（遗留兼容）
    // ================================================================
    println!("\n--- 步骤 7：Password 流程（遗留兼容）---");

    let pw_req = TokenRequest {
        grant_type: "password".into(),
        client_id: "my-app".into(),
        client_secret: "my-secret-123".into(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: Some("read".into()),
        username: Some("admin".into()),
        password: Some("secret".into()),
    };
    let pw_resp = token_handler.handle(&pw_req).await?;
    println!("[7] Password Grant Token：");
    println!("    access_token: {}...", &pw_resp.access_token[..20]);

    // 错误密码验证
    let bad_pw_req = TokenRequest {
        password: Some("wrong".into()),
        ..pw_req.clone()
    };
    let bad_result = token_handler.handle(&bad_pw_req).await;
    assert!(bad_result.is_err(), "错误密码应返回错误");
    println!("    ✓ 错误密码拒绝（统一返回 OAuth2 error，防用户枚举）");

    // ================================================================
    // 步骤 8：授权码一次性使用验证
    // ================================================================
    println!("\n--- 步骤 8：安全验证 ---");

    let replay_req = TokenRequest {
        grant_type: "authorization_code".into(),
        code: Some(code),
        ..token_req.clone()
    };
    let replay_result = token_handler.handle(&replay_req).await;
    assert!(replay_result.is_err(), "授权码应只能使用一次");
    println!("    ✓ 授权码一次性使用（重放攻击被阻止）");

    println!("\n=== OAuth2 授权服务器流程演示完成 ===");
    println!("已展示功能：");
    println!("  • 客户端注册（Argon2id 密钥哈希）");
    println!("  • 授权码流程（PKCE S256 强制）");
    println!("  • Token 交换（authorization_code grant）");
    println!("  • Token 内省（RFC 7662）");
    println!("  • Token 吊销（RFC 7009）");
    println!("  • Client Credentials（服务间调用）");
    println!("  • Password Grant（遗留兼容）");
    println!("  • 安全验证（授权码一次性使用）");

    Ok(())
}
