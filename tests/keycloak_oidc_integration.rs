//! Keycloak OIDC RP 完整流程端到端集成测试。
//!
//! 使用 wiremock 模拟 Keycloak 的 discovery/JWKS/token endpoints，
//! 验证 bulwark 作为 OIDC RP 的完整授权码流程：discover → exchange_code → verify_id_token。
//!
//! 运行：
//! ```bash
//! cargo test --features "keycloak-oidc db-sqlite" --test keycloak_oidc_integration
//! ```

#[cfg(all(feature = "keycloak-oidc", feature = "db-sqlite"))]
mod keycloak_e2e {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use bulwark::protocol::jwt::JwtHandler;
    use bulwark::{KeycloakConfig, KeycloakProvider};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use rand::rngs::OsRng;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sha256_hex(s: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[derive(Serialize)]
    struct TestIdTokenClaims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
        iat: i64,
        preferred_username: String,
        email: String,
        realm_access: serde_json::Value,
        resource_access: serde_json::Value,
        tenant_id: i64,
    }

    /// 验证 Keycloak OIDC RP 完整流程：discover → exchange_code → verify_id_token。
    ///
    /// 使用 wiremock 模拟 Keycloak 的 discovery/JWKS/token endpoints，
    /// 验证 bulwark 作为 OIDC RP 的完整授权码流程。
    ///
    /// 断言：
    /// 1. `discover()` 返回正确的 OIDC discovery metadata
    /// 2. `exchange_code("auth_code")` 返回 KeycloakTokenSet 含三个 token
    /// 3. `verify_id_token(id_token)` 返回 KeycloakClaims 含 sub/realm_access.roles
    #[tokio::test]
    async fn keycloak_oidc_rp_full_flow_e2e() {
        let server = MockServer::start().await;

        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let n_bytes = public_key.n().to_bytes_be();
        let e_bytes = public_key.e().to_bytes_be();
        let n_b64 = URL_SAFE_NO_PAD.encode(n_bytes);
        let e_b64 = URL_SAFE_NO_PAD.encode(e_bytes);
        let kid = "key1";

        let issuer = server.uri();
        let token_endpoint = format!("{}/protocol/openid-connect/token", server.uri());
        let jwks_uri = format!("{}/protocol/openid-connect/certs", server.uri());

        // Mock: discovery endpoint
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{}/protocol/openid-connect/auth", server.uri()),
                "token_endpoint": token_endpoint,
                "jwks_uri": jwks_uri,
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })))
            .mount(&server)
            .await;

        // Mock: JWKS endpoint
        Mock::given(method("GET"))
            .and(path("/protocol/openid-connect/certs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [{
                    "kid": kid,
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": n_b64,
                    "e": e_b64
                }]
            })))
            .mount(&server)
            .await;

        // 生成 id_token
        let sub = "user-123";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = TestIdTokenClaims {
            iss: issuer.clone(),
            sub: sub.into(),
            aud: "bulwark-rp".into(),
            exp: now + 3600,
            iat: now,
            preferred_username: "testuser".into(),
            email: "test@example.com".into(),
            realm_access: serde_json::json!({ "roles": ["admin", "user"] }),
            resource_access: serde_json::json!({
                "account": { "roles": ["manage-account"] }
            }),
            tenant_id: 42,
        };

        let der = private_key.to_pkcs1_der().expect("转 PKCS#1 DER 应成功");
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let id_token = encode(&header, &claims, &encoding_key).expect("签发 JWT 应成功");

        // Mock: token endpoint
        Mock::given(method("POST"))
            .and(path("/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "access-token-abc",
                "refresh_token": "refresh-token-xyz",
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid profile email"
            })))
            .mount(&server)
            .await;

        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "bulwark-rp".into(),
            client_secret: Some("client-secret-123".into()),
            redirect_uri: "https://app.example.com/cb".into(),
        };
        let provider = KeycloakProvider::new(config).expect("KeycloakProvider::new 应成功");

        // Step 1: discover
        let metadata = provider.discover().await.expect("discover 应成功");
        assert_eq!(metadata.issuer, issuer);
        assert_eq!(metadata.token_endpoint, token_endpoint);
        assert_eq!(metadata.jwks_uri, jwks_uri);

        // Step 2: exchange_code
        let token_set = provider
            .exchange_code("auth-code-xyz")
            .await
            .expect("exchange_code 应成功");
        assert!(!token_set.access_token.is_empty(), "access_token 应非空");
        assert!(!token_set.refresh_token.is_empty(), "refresh_token 应非空");
        assert!(!token_set.id_token.is_empty(), "id_token 应非空");
        assert_eq!(token_set.expires_in, 3600);

        // Step 3: verify_id_token
        let keycloak_claims = provider
            .verify_id_token(&token_set.id_token)
            .await
            .expect("verify_id_token 应成功");
        assert_eq!(keycloak_claims.sub, sub, "claims.sub 应匹配");
        assert_eq!(
            keycloak_claims.preferred_username.as_deref(),
            Some("testuser"),
            "preferred_username 应匹配"
        );
        assert_eq!(
            keycloak_claims.email.as_deref(),
            Some("test@example.com"),
            "email 应匹配"
        );
        assert_eq!(
            keycloak_claims.realm_access.roles,
            vec!["admin", "user"],
            "realm_access.roles 应匹配"
        );
        assert_eq!(
            keycloak_claims.tenant_id,
            Some(42),
            "tenant_id claim 应正确解析"
        );
        assert!(
            keycloak_claims.resource_access.contains_key("account"),
            "resource_access 应包含 account"
        );

        // 验证 JwtHandler 可以独立工作（确认 JWT 模块可用）
        let _ = JwtHandler::new("test-secret");

        // 验证 sha256_hex 辅助函数工作正常
        let hash = sha256_hex("test");
        assert_eq!(hash.len(), 64, "SHA-256 hex 长度应为 64");
    }
}
