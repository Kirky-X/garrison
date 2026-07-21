//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Token Introspection (RFC 7662) 示例（v0.4.2 新增，依据 spec token-introspection）。
//!
//! 演示 `OAuth2Client::introspect_token` 查询 token 状态：
//! - `with_introspect_url`：显式设置 introspection 端点
//! - `introspect_token`：远程查询 token 状态
//! - URL 推导规则：未设置时从 token_url 推导
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin token_introspection --features protocol-oauth2
//! ```
//!
//! 本示例展示客户端构造与 URL 推导，不实际发起 HTTP 请求。
//! 端到端测试见 `tests/protocol_oauth2_integration.rs`。

use garrison::protocol::oauth2::{OAuth2Client, TokenIntrospectionResponse};

/// 运行 Token Introspection 示例。
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Garrison Token Introspection (RFC 7662) 示例 ===\n");

    // 1. 构造 OAuth2Client，显式设置 introspect_url
    let _client = OAuth2Client::new(
        "my-client-id",
        "my-client-secret",
        "https://myapp.example.com/callback",
        "https://auth.example.com/oauth2/authorize",
        "https://auth.example.com/oauth2/token",
    )?
    .with_introspect_url("https://auth.example.com/oauth2/introspect");
    println!("[1] OAuth2Client 构造完成（显式 introspect_url）");
    println!("    token_url:      https://auth.example.com/oauth2/token");
    println!("    introspect_url: https://auth.example.com/oauth2/introspect\n");

    // 2. URL 推导规则演示（未设置 introspect_url 时）
    println!("[2] URL 推导规则（未设置 introspect_url 时）");
    let client_default = OAuth2Client::new(
        "cid",
        "secret",
        "https://redirect",
        "https://auth.example.com/oauth2/authorize",
        "https://auth.example.com/oauth2/token",
    )?;
    println!("    场景 A：token_url 末尾为 /token → 替换为 /introspect");
    println!("      token_url:      https://auth.example.com/oauth2/token");
    println!("      introspect_url: https://auth.example.com/oauth2/introspect（自动推导）");

    let _client_no_token_suffix = OAuth2Client::new(
        "cid",
        "secret",
        "https://redirect",
        "https://auth.example.com/oauth2/authorize",
        "https://auth.example.com/oauth2/issues",
    )?;
    println!("    场景 B：token_url 末尾非 /token → 末尾追加 /introspect");
    println!("      token_url:      https://auth.example.com/oauth2/issues");
    println!(
        "      introspect_url: https://auth.example.com/oauth2/issues/introspect（自动推导）\n"
    );

    // 3. 展示 introspect_token 调用方式
    println!("[3] introspect_token 调用方式");
    println!("    // 查询 access_token 或 refresh_token 的当前状态");
    println!("    let response: TokenIntrospectionResponse = client");
    println!("        .introspect_token(\"some-access-token\")");
    println!("        .await?;");
    println!();
    println!("    // 响应字段（RFC 7662 §2.2）：");
    println!("    //   active   — 必填，token 是否有效");
    println!("    //   scope    — 可选，授权 scope");
    println!("    //   client_id — 可选，签发该 token 的客户端 ID");
    println!("    //   username  — 可选，资源所有者用户名");
    println!("    //   token_type — 可选，通常为 \"Bearer\"");
    println!("    //   exp      — 可选，过期时间（Unix 秒）");
    println!("    //   iat      — 可选，签发时间");
    println!("    //   nbf      — 可选，生效时间");
    println!("    //   sub      — 可选，主体标识");
    println!("    //   aud      — 可选，受众");
    println!("    //   iss      — 可选，签发者");
    println!("    //   jti      — 可选，token ID");
    println!();

    // 4. 演示 TokenIntrospectionResponse 的反序列化
    println!("[4] TokenIntrospectionResponse 反序列化示例");
    let active_json = r#"{
        "active": true,
        "scope": "read write",
        "client_id": "my-client-id",
        "username": "alice",
        "token_type": "Bearer",
        "exp": 1700000000,
        "iat": 1699996400,
        "sub": "1001",
        "aud": "resource-server-1",
        "iss": "https://auth.example.com"
    }"#;
    let resp: TokenIntrospectionResponse = serde_json::from_str(active_json)?;
    println!("    反序列化 active=true 响应:");
    println!("      active:    {}", resp.active);
    println!("      scope:     {:?}", resp.scope);
    println!("      client_id: {:?}", resp.client_id);
    println!("      username:  {:?}", resp.username);
    println!("      exp:       {:?}", resp.exp);
    println!("      sub:       {:?}", resp.sub);
    println!("      iss:       {:?}", resp.iss);
    assert!(resp.active);
    assert_eq!(resp.scope.as_deref(), Some("read write"));
    assert_eq!(resp.client_id.as_deref(), Some("my-client-id"));
    assert_eq!(resp.sub.as_deref(), Some("1001"));

    let inactive_json = r#"{"active": false}"#;
    let resp_inactive: TokenIntrospectionResponse = serde_json::from_str(inactive_json)?;
    println!("\n    反序列化 active=false 响应:");
    println!("      active:    {}", resp_inactive.active);
    println!("      其他字段:  全部为 None");
    assert!(!resp_inactive.active);
    assert!(resp_inactive.scope.is_none());
    println!("    ✓ 反序列化正确\n");

    // 5. 业务决策示例
    println!("[5] 业务决策示例");
    println!("    // 根据 active 字段决定是否允许访问资源");
    println!("    match client.introspect_token(&token).await {{");
    println!("        Ok(resp) if resp.active => {{");
    println!("            // token 有效，检查 scope/aud/iss 等字段");
    println!("            if let Some(scope) = &resp.scope {{");
    println!("                if !scope.contains(\"required-scope\") {{");
    println!("                    return Err(\"insufficient_scope\".into());");
    println!("                }}");
    println!("            }}");
    println!("            // 允许访问");
    println!("        }}");
    println!("        Ok(_) => return Err(\"token inactive\".into()),");
    println!("        Err(e) => return Err(format!(\"introspection failed: {{}}\", e).into()),");
    println!("    }}");
    println!();

    // 6. 不缓存说明
    println!("[6] 不缓存约束（依据 spec Constraints）");
    println!("    introspect_token 每次调用都请求授权服务器，不缓存结果。");
    println!("    业务方如需缓存可自行封装（注意 TTL 不应超过 token 剩余有效期）。\n");

    // 7. 客户端演示（使用推导 URL）
    println!("[7] 使用推导 URL 的客户端");
    println!("    // 场景：授权服务器 token_url 末尾为 /token");
    println!("    //       introspect_url 自动推导为 /introspect");
    let _client_derived = client_default;
    println!("    // client.introspect_token(\"token\").await?");
    println!("    // → POST https://auth.example.com/oauth2/introspect");

    println!("\n=== 示例完成 ===");
    println!("\nIntrospection 适用场景：");
    println!("  - 资源服务器（RS）验证 access_token 有效性");
    println!("  - 撤销检测（token 在 introspection 端点被撤销后立即失效）");
    println!("  - token 元数据查询（scope/aud/iss 等字段）");
    println!("  - 与 JWT 无状态校验互补：高敏感操作走 introspection，普通操作走本地 JWT 校验");
    Ok(())
}
