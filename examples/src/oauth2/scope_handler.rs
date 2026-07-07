//! OAuth2 Scope Handler 示例（依据 spec oauth2-scope-handler，0.4.0 新增）。
//!
//! 演示 `ScopeHandler` trait + `ScopeRegistry` + `OAuth2Client::with_scope_registry`：
//! 1. 自定义实现 `ScopeHandler` trait（`AdminScopeHandler`）
//! 2. 创建 `ScopeRegistry`，注册 handler
//! 3. `OAuth2Client::new(...).with_scope_registry(registry)` 注入
//! 4. 演示 `validate_scope` 在 token 请求前被调用（成功 / 拒绝 / 未注册三种场景）
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin scope_handler --features oauth2-scope-handler
//! ```

use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::protocol::oauth2::scope::{ScopeHandler, ScopeRegistry};
use bulwark::protocol::oauth2::OAuth2Client;
use std::sync::Arc;

/// 管理员 scope handler：根据 scope 名称与 login_id 决定是否允许。
///
/// - `openid` / `profile`：所有用户均允许（公共 scope）
/// - `admin`：仅 login_id > 1000 的用户允许
/// - 其他 scope：拒绝
struct AdminScopeHandler;

impl ScopeHandler for AdminScopeHandler {
    fn validate(&self, scope: &str, login_id: i64) -> BulwarkResult<bool> {
        match scope {
            "openid" | "profile" => Ok(true),
            "admin" => Ok(login_id > 1000),
            _ => Ok(false),
        }
    }
}

/// 运行 OAuth2 Scope Handler 示例。
///
/// 演示 ScopeRegistry 直接校验 + OAuth2Client 注入后 token 请求前的 scope 校验。
/// 使用 wiremock MockServer mock token 端点，验证校验通过时 HTTP 请求被发送。
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark OAuth2 Scope Handler 示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 创建 ScopeRegistry 并注册 handler
    // ----------------------------------------------------------------
    let registry = Arc::new(ScopeRegistry::new());
    registry.register("openid", Arc::new(AdminScopeHandler));
    registry.register("profile", Arc::new(AdminScopeHandler));
    registry.register("admin", Arc::new(AdminScopeHandler));
    println!("[注册] 已注册 3 个 scope handler: openid / profile / admin\n");

    // ----------------------------------------------------------------
    // 2. 直接通过 ScopeRegistry 校验（三种场景）
    // ----------------------------------------------------------------
    println!("[校验] 直接通过 ScopeRegistry 校验:");

    // 成功：openid 公共 scope
    let ok = registry.validate("openid", 0)?;
    println!("    validate(\"openid\", 0)   → {}（公共 scope 允许）", ok);
    assert!(ok);

    // 拒绝：admin scope，login_id=500 < 1000
    let denied = registry.validate("admin", 500)?;
    println!(
        "    validate(\"admin\", 500)  → {}（login_id 不足）",
        denied
    );
    assert!(!denied);

    // 未注册的 scope 返回 OAuth2 错误
    match registry.validate("unregistered", 0) {
        Err(BulwarkError::OAuth2(msg)) => {
            println!("    validate(\"unregistered\", 0) → Err（未注册）");
            assert!(msg.contains("not registered"));
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
    println!();

    // ----------------------------------------------------------------
    // 3. 注入 OAuth2Client 并通过 wiremock mock token 端点
    // ----------------------------------------------------------------
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/token"))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-token-from-mock",
                "token_type": "Bearer",
                "expires_in": 3600
            })),
        )
        .mount(&server)
        .await;

    let base = server.uri();
    let client = OAuth2Client::new(
        "client-id",
        "client-secret",
        "https://example.com/callback",
        format!("{}/auth", base),
        format!("{}/token", base),
    )?
    .with_scope_registry(registry);

    println!("[集成] OAuth2Client 注入 ScopeRegistry，token 端点已 mock\n");

    // ----------------------------------------------------------------
    // 4. 通过 OAuth2Client 验证 validate_scope 在 HTTP 请求前被调用
    // ----------------------------------------------------------------
    println!("[集成] token 请求前的 scope 校验:");

    // 成功：openid scope 校验通过，HTTP 请求发送，获取 token
    let token = client.get_client_credentials_token(Some("openid")).await?;
    println!(
        "    get_client_credentials_token(\"openid\") → Ok（access_token={}）",
        token.access_token
    );
    assert_eq!(token.access_token, "new-token-from-mock");

    // 拒绝：admin scope 被 handler 拒绝（login_id=0 < 1000），不发送 HTTP
    match client.get_client_credentials_token(Some("admin")).await {
        Err(BulwarkError::OAuth2(msg)) => {
            println!("    get_client_credentials_token(\"admin\")  → Err（scope 被拒）");
            assert!(msg.contains("scope validation failed"));
        },
        other => panic!("期望 OAuth2 错误（scope 被拒），实际: {:?}", other),
    }

    // 未注册：scope 未注册，不发送 HTTP
    match client
        .get_client_credentials_token(Some("unknown-scope"))
        .await
    {
        Err(BulwarkError::OAuth2(msg)) => {
            println!("    get_client_credentials_token(\"unknown\") → Err（未注册）");
            assert!(msg.contains("not registered"));
        },
        other => panic!("期望 OAuth2 错误（未注册），实际: {:?}", other),
    }

    println!("\n=== 示例完成 ===");
    Ok(())
}
