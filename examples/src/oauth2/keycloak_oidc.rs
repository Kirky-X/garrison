//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Keycloak OIDC RP 示例：演示 KeycloakConfig / KeycloakProvider 配置与使用。
//!
//! 对应模块：`src/protocol/oauth2/keycloak.rs`（`keycloak-oidc` feature 开启时可用）。
//!
//! Keycloak OIDC RP 角色：Garrison 作为 Relying Party，向 Keycloak 授权服务器请求 token。
//! 与 `oauth2-server`（Garrison 本身作为授权服务器）互补。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin keycloak_oidc --features "keycloak-oidc"
//! ```

use garrison::error::GarrisonResult;
use garrison::{KeycloakConfig, KeycloakProvider};

/// 运行 Keycloak OIDC RP 示例。
///
/// 演示 KeycloakConfig 构造 + KeycloakProvider 使用方式。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison Keycloak OIDC RP 示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 构造 KeycloakConfig
    // ----------------------------------------------------------------
    println!("[1] 构造 KeycloakConfig:");
    // 占位值，生产环境必须从环境变量/KMS 加载
    let kc_config = KeycloakConfig {
        base_url: "https://kc.example.com:8443/realms/myrealm".into(),
        client_id: "garrison-rp".into(),
        client_secret: Some("client-secret-123".into()),
        redirect_uri: "https://app.example.com/cb".into(),
        expected_iss: "https://kc.example.com:8443/realms/myrealm".into(),
    };
    println!("    ✓ KeycloakConfig 已构造");
    println!("    base_url: {}", kc_config.base_url);
    println!("    discovery_url: {}", kc_config.discovery_url());
    println!("    client_id: {}", kc_config.client_id);
    println!("    redirect_uri: {}", kc_config.redirect_uri);
    println!();

    // ----------------------------------------------------------------
    // 2. 构造 KeycloakProvider
    // ----------------------------------------------------------------
    println!("[2] 构造 KeycloakProvider:");
    let _provider = KeycloakProvider::new(kc_config)?;
    println!("    ✓ KeycloakProvider 已构造");
    println!("    可用方法:");
    println!("    • discover() → 获取 OIDC Discovery 文档");
    println!("    • exchange_code(code, state) → Authorization Code 换 token");
    println!("    • verify_id_token(id_token) → 验证 id_token 签名 + claims");
    println!();

    // ----------------------------------------------------------------
    // 3. KeycloakClaims 结构
    // ----------------------------------------------------------------
    println!("[3] KeycloakClaims（id_token 中的 claims）:");
    println!("    • sub: 用户唯一标识");
    println!("    • exp: token 过期时间");
    println!("    • realm_access: realm 级角色列表");
    println!("    • resource_access: 资源级角色列表");
    println!("    • tenant_id: 租户 ID（Garrison 扩展 claim）");
    println!();

    // ----------------------------------------------------------------
    // 4. 与其他 OIDC Provider 的关系
    // ----------------------------------------------------------------
    println!("[4] OIDC 集成方式对比:");
    println!("    • KeycloakProvider: 内置 Keycloak OIDC RP（keycloak-oidc feature）");
    println!("    • protocol-oidc: 通用 OIDC id_token 签发/验证（protocol-oidc feature）");
    println!("    • oauth2-server: Garrison 本身作为授权服务器（oauth2-server feature）");
    println!();

    println!("=== 示例执行完成 ===");
    Ok(())
}
