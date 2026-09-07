//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! keycloak_oidc 示例测试（keycloak-oidc feature）。
//!
//! 验证 run() 完整执行（仅构造 KeycloakConfig/KeycloakProvider，不实际调用 discover，无外部网络依赖）。

#![cfg(feature = "keycloak-oidc")]

use garrison_examples::oauth2::keycloak_oidc;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    keycloak_oidc::run().await.unwrap();
}
