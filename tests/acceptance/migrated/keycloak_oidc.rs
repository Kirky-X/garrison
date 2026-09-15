//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! Keycloak OIDC RP 完整流程端到端集成测试。
//!
//! 打真实 Keycloak 26（docker-compose.e2e.yml + scripts/keycloak_provision.py
//! 幂等供给 realm=garrison），验证 garrison 作为 OIDC RP 的完整授权码流程：
//! discover → 真实登录表单流获取授权码（tests/acceptance/keycloak_fixture.rs）→
//! exchange_code → verify_id_token（真实 JWKS RS256 验签）。
//!
//! 运行：
//! ```bash
//! GARRISON_TEST_KEYCLOAK_URL=http://127.0.0.1:18090 \
//!   cargo test --features "full,keycloak-oidc" --test acceptance keycloak_oidc
//! ```
//!
//! # production-mock-purge（2026-09 二次裁定）
//!
//! 原 wiremock 模拟 Keycloak 端点的实现（曾在 2026-09 早期裁定豁免保留），
//! 依用户最新裁定「仅单元测试可 mock，验收/集成一律打真实服务」移除；Keycloak
//! 不可达时经 tests/acceptance/keycloak_fixture.rs 门控 `[SKIP]`。id_token 的
//! sub / preferred_username / email / realm_access.roles / resource_access /
//! tenant_id claims 均由真实 realm 数据产生（用户 alice + tenant_id mapper）。

#[cfg(all(
    feature = "keycloak-oidc",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
mod keycloak_e2e {
    use crate::keycloak_fixture::{KeycloakFixture, CLIENT_ID, CLIENT_SECRET, REDIRECT_HTTPS};
    use garrison::dao::GarrisonDaoOxcache;
    use garrison::{KeycloakConfig, KeycloakProvider};
    use serial_test::serial;
    use std::sync::Arc;

    /// 验证 Keycloak OIDC RP 完整流程：discover → exchange_code → verify_id_token。
    ///
    /// 断言：
    /// 1. `discover()` 返回正确的 OIDC discovery metadata（真实 realm）
    /// 2. 真实登录表单流授权码经 `exchange_code` 换取 KeycloakTokenSet 三 token
    /// 3. `verify_id_token(id_token)` 经真实 JWKS 验签并解析 KeycloakClaims
    ///    （sub / preferred_username / email / realm_access.roles / resource_access /
    ///    tenant_id）
    // multi_thread flavor 必需：oxcache memory 后端的 sync API 通过
    // `block_in_place` 复用 runtime，current-thread runtime 下会 panic
    //（"Cannot start a runtime from within a runtime"）。
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn keycloak_oidc_rp_full_flow_e2e() {
        let fx = KeycloakFixture::new();
        if !fx.available_or_skip("keycloak_oidc").await {
            return;
        }

        let config = KeycloakConfig {
            base_url: crate::keycloak_fixture::realm_base(),
            client_id: CLIENT_ID.to_string(),
            client_secret: Some(CLIENT_SECRET.to_string()),
            redirect_uri: REDIRECT_HTTPS.to_string(),
            expected_iss: crate::keycloak_fixture::realm_base(),
        };
        let provider = KeycloakProvider::new(config)
            .expect("KeycloakProvider::new 应成功")
            .with_dao(Arc::new(
                GarrisonDaoOxcache::new()
                    .await
                    .expect("构造 GarrisonDaoOxcache 应成功"),
            ));

        // Step 1: discover（真实 discovery 端点）
        let metadata = provider.discover().await.expect("discover 应成功");
        assert_eq!(
            metadata.issuer,
            crate::keycloak_fixture::realm_base(),
            "issuer 应为真实 realm URL"
        );
        assert_eq!(
            metadata.token_endpoint,
            format!("{}/token", crate::keycloak_fixture::oidc_base())
        );
        assert_eq!(
            metadata.jwks_uri,
            format!(
                "{}/protocol/openid-connect/certs",
                crate::keycloak_fixture::realm_base()
            )
        );

        // Step 2: 真实登录表单流获取授权码 → 换取 token set
        let (code, state) = fx
            .obtain_auth_code(Some("openid"), REDIRECT_HTTPS, "e2e-state", None)
            .await
            .expect("真实登录表单流应成功");
        assert_eq!(state, "e2e-state", "回调 state 应与授权请求一致");
        let token_set = provider
            .exchange_code(&code)
            .await
            .expect("exchange_code 应成功");
        assert!(!token_set.access_token.is_empty(), "access_token 应非空");
        assert!(!token_set.refresh_token.is_empty(), "refresh_token 应非空");
        assert!(!token_set.id_token.is_empty(), "id_token 应非空");
        assert!(token_set.expires_in > 0, "expires_in 应为正数");

        // Step 3: verify_id_token（真实 JWKS RS256 验签 + claims 解析）
        let keycloak_claims = provider
            .verify_id_token(&token_set.id_token)
            .await
            .expect("verify_id_token 应成功");
        assert!(
            !keycloak_claims.sub.is_empty(),
            "claims.sub 应为真实主体标识"
        );
        assert_eq!(
            keycloak_claims.preferred_username.as_deref(),
            Some(crate::keycloak_fixture::USERNAME),
            "preferred_username 应匹配"
        );
        assert_eq!(
            keycloak_claims.email.as_deref(),
            Some("alice@garrison.test"),
            "email 应匹配"
        );
        assert!(
            keycloak_claims
                .realm_access
                .roles
                .contains(&"admin".to_string())
                && keycloak_claims
                    .realm_access
                    .roles
                    .contains(&"user".to_string()),
            "realm_access.roles 应含 admin/user，实际: {:?}",
            keycloak_claims.realm_access.roles
        );
        assert_eq!(
            keycloak_claims.tenant_id,
            Some(42),
            "tenant_id claim 应正确解析"
        );
        assert!(
            keycloak_claims.resource_access.contains_key("account"),
            "resource_access 应包含 account，实际: {:?}",
            keycloak_claims.resource_access
        );
    }
}
