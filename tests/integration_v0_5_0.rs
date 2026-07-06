//! v0.5.0 集成测试：多租户隔离 + 审计日志 + 决策溯源 + Keycloak OIDC + RefreshToken Rotation 端到端验证。
//!
//! 包含测试：
//! - T141: `tenant_isolation_with_audit_log_and_decision_trace_e2e`
//! - T143: `keycloak_oidc_rp_full_flow_e2e`
//! - T145: `refresh_token_rotation_reuse_detection_e2e`
//!
//! 运行全部：
//! ```bash
//! cargo test --features "tenant-isolation audit-log db-sqlite decision-trace cache-memory keycloak-oidc protocol-jwt" --test integration_v0_5_0
//! ```

// ============================================================================
// T141: 多租户隔离 + 审计日志 + 决策溯源端到端集成测试
// ============================================================================

#[cfg(all(
    feature = "tenant-isolation",
    feature = "audit-log",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
mod tenant_audit_decision_e2e {
    use async_trait::async_trait;
    use bulwark::context::tenant::{TenantContext, TenantSource, TENANT};
    use bulwark::core::permission::{
        AuthRequest, DecisionReason, PermissionChecker, PermissionCheckerDefault,
    };
    use bulwark::dao::{init_dbnexus, BulwarkDao, BulwarkDaoOxcache, BulwarkMigration};
    use bulwark::error::BulwarkResult;
    use bulwark::listener::audit::{AuditConfig, AuditQuery};
    use bulwark::listener::{BulwarkListener, BulwarkListenerManager};
    use bulwark::session::BulwarkSession;
    use bulwark::stp::{with_current_token, BulwarkInterface, BulwarkLogic, BulwarkLogicDefault};
    use bulwark::AuditLogListener;
    use serial_test::serial;
    use std::path::PathBuf;
    use std::sync::Arc;

    struct MockInterface;

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
            if login_id == 1001 {
                Ok(vec!["user:read".to_string()])
            } else {
                Ok(vec![])
            }
        }

        async fn get_role_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
    }

    fn project_migrations_dir() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .join("migrations")
            .join("sqlite")
    }

    async fn setup_db() -> dbnexus::DbPool {
        let pool = init_dbnexus("sqlite::memory:")
            .await
            .expect("init_dbnexus 应成功");
        let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());
        let applied = migration.migrate_core().await.expect("migrate_core 应成功");
        assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
        pool
    }

    /// 验证租户 42 用户 1001 的权限校验全链路：
    /// `check_permission` → `authorize` → `Decision` → 广播 `PermissionCheck` → `AuditLogListener` 写入。
    ///
    /// 断言：
    /// 1. `check_permission("user:read")` 返回 `Ok(())`
    /// 2. `authorize()` 返回 `Decision { allowed: true, reason: ExplicitAllow }`
    /// 3. `audit_logs` 表存在 `tenant_id=42, event_type="permission_check"` 的记录
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn tenant_isolation_with_audit_log_and_decision_trace_e2e() {
        let pool = setup_db().await;

        let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
        let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));

        let mut config = bulwark::config::BulwarkConfig::default_config();
        config.token_style = "uuid".to_string();
        config.timeout = 3600;
        config.throw_on_not_login = true;

        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
        let pc: Arc<dyn PermissionChecker> =
            Arc::new(PermissionCheckerDefault::new(interface.clone()));

        let firewall = Arc::new(bulwark::strategy::BulwarkPermissionStrategyDefault::new(
            interface,
        ));

        let lm = Arc::new(BulwarkListenerManager::new());
        let audit_config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
        };
        let audit_listener = Arc::new(AuditLogListener::new(pool.clone(), audit_config));
        lm.register(audit_listener.clone() as Arc<dyn BulwarkListener>);

        let logic = Arc::new(
            BulwarkLogicDefault::new(session, Arc::new(config), firewall)
                .with_permission_checker(pc.clone())
                .with_listener_manager(lm),
        );

        let tenant_ctx = TenantContext {
            tenant_id: 42,
            resolved_from: TenantSource::Header,
        };

        let token = TENANT
            .scope(tenant_ctx.clone(), async {
                logic.login(1001).await.expect("login 应成功")
            })
            .await;
        assert!(!token.is_empty(), "token 不应为空");

        let check_result = TENANT
            .scope(
                tenant_ctx,
                with_current_token(token.clone(), async {
                    logic.check_permission("user:read").await
                }),
            )
            .await;

        assert!(
            check_result.is_ok(),
            "check_permission 应成功: {:?}",
            check_result.err()
        );

        let auth_request = AuthRequest {
            login_id: 1001,
            tenant_id: 42,
            action: "user:read".to_string(),
            resource: None,
            context: serde_json::Value::Null,
        };
        let decision = pc.authorize(&auth_request).await.expect("authorize 应成功");
        assert!(decision.allowed, "Decision.allowed 应为 true");
        assert_eq!(
            decision.reason,
            DecisionReason::ExplicitAllow,
            "Decision.reason 应为 ExplicitAllow"
        );

        let query = AuditQuery {
            tenant_id: Some(42),
            event_type: Some("permission_check".to_string()),
            ..Default::default()
        };
        let logs = audit_listener
            .query_audit_logs(query)
            .await
            .expect("query_audit_logs 应成功");

        assert!(
            !logs.is_empty(),
            "audit_logs 应存在 tenant_id=42, event_type=permission_check 的记录"
        );
        let entry = &logs[0];
        assert_eq!(entry.tenant_id, 42, "audit_logs tenant_id 应为 42");
        assert_eq!(
            entry.event_type, "permission_check",
            "audit_logs event_type 应为 permission_check"
        );
        assert_eq!(entry.login_id, Some(1001), "audit_logs login_id 应为 1001");
    }
}

// ============================================================================
// T143: Keycloak OIDC RP 完整流程端到端集成测试
// ============================================================================

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

// ============================================================================
// T145: RefreshToken Rotation + Reuse Detection 端到端集成测试
// ============================================================================

#[cfg(all(feature = "protocol-jwt", feature = "db-sqlite"))]
mod refresh_token_e2e {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use bulwark::dao::{init_dbnexus, BulwarkMigration};
    use bulwark::protocol::jwt::JwtHandler;
    use bulwark::RefreshTokenRotation;
    use dbnexus::DbPool;
    use rand::rngs::OsRng;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};

    fn project_migrations_dir() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .join("migrations")
            .join("sqlite")
    }

    async fn setup_db() -> DbPool {
        let pool = init_dbnexus("sqlite::memory:")
            .await
            .expect("init_dbnexus 应成功");
        let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());
        let applied = migration.migrate_core().await.expect("migrate_core 应成功");
        assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
        pool
    }

    fn sha256_hex(s: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    async fn insert_refresh_token(
        pool: &DbPool,
        token_hash: &str,
        parent_token_hash: Option<&str>,
        login_id: i64,
        tenant_id: i64,
        key_version: u32,
        expires_at: i64,
        revoked: i64,
    ) {
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO refresh_tokens (token_hash, parent_token_hash, login_id, tenant_id, key_version, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                Value::String(Some(token_hash.to_string())),
                Value::String(parent_token_hash.map(|s| s.to_string())),
                Value::BigInt(Some(login_id)),
                Value::BigInt(Some(tenant_id)),
                Value::BigInt(Some(key_version as i64)),
                Value::BigInt(Some(expires_at)),
                Value::BigInt(Some(revoked)),
                Value::BigInt(Some(0)),
            ],
        );
        conn.execute_raw(stmt).await.expect("INSERT 应成功");
    }

    async fn query_revoked(pool: &DbPool, token_hash: &str) -> i64 {
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT revoked FROM refresh_tokens WHERE token_hash = ?",
            vec![Value::String(Some(token_hash.to_string()))],
        );
        let row = conn
            .query_one_raw(stmt)
            .await
            .unwrap()
            .expect("record 应存在");
        row.try_get::<i64>("", "revoked").unwrap()
    }

    /// 验证 RefreshToken Rotation + Reuse Detection 完整流程。
    ///
    /// 流程：
    /// 1. 插入初始 refresh token (t1)
    /// 2. 调用 `rotate(t1)` 得到 t2 → t1 标记为 revoked，t2 插入且 parent=t1
    /// 3. 再次调用 `rotate(t1)`（重用）→ 应返回 InvalidToken 且 t1/t2 全被吊销
    ///
    /// 断言：
    /// 1. 首次 rotate 返回新 access + 新 refresh token
    /// 2. 首次 rotate 后旧 token revoked=1
    /// 3. 重用旧 token 触发 BulwarkError::InvalidToken
    /// 4. 重用检测后整条链（t1 + t2）revoked=1
    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_token_rotation_reuse_detection_e2e() {
        let pool = setup_db().await;

        let jwt_handler = Arc::new(JwtHandler::new("test_secret_key"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let t1 = "initial-refresh-token-t1";
        let t1_hash = sha256_hex(t1);
        let expires = now_unix() + 7 * 24 * 3600;

        insert_refresh_token(&pool, &t1_hash, None, 1001, 0, 1, expires, 0).await;

        // Step 1: 首次 rotate(t1) → 得到 t2
        let (access_1, t2) = rotation.rotate(t1).await.expect("首次 rotate 应成功");
        assert!(!access_1.is_empty(), "access_token 应非空");
        assert!(!t2.is_empty(), "新 refresh_token 应非空");
        assert_ne!(t1, t2, "新 token 不应与旧 token 相同");

        // 验证 t1 已 revoked
        let t1_revoked = query_revoked(&pool, &t1_hash).await;
        assert_eq!(t1_revoked, 1, "旧 token t1 应标记为 revoked");

        // 验证 t2 已插入且未 revoked
        let t2_hash = sha256_hex(&t2);
        let t2_revoked = query_revoked(&pool, &t2_hash).await;
        assert_eq!(t2_revoked, 0, "新 token t2 应未 revoked");

        // Step 2: 重用 t1 → 应触发 reuse detection，返回 InvalidToken，且整条链被吊销
        let reuse_result = rotation.rotate(t1).await;
        assert!(reuse_result.is_err(), "重用已消费的 token 应返回错误");
        let err_msg = format!("{}", reuse_result.unwrap_err());
        assert!(
            err_msg.contains("reuse"),
            "错误信息应包含 'reuse': {}",
            err_msg
        );

        // 验证 t1 仍 revoked
        let t1_revoked_after = query_revoked(&pool, &t1_hash).await;
        assert_eq!(t1_revoked_after, 1, "重用后 t1 应仍 revoked");

        // 验证 t2 也被吊销（整条链被撤销）
        let t2_revoked_after = query_revoked(&pool, &t2_hash).await;
        assert_eq!(t2_revoked_after, 1, "重用检测后 t2 也应被吊销（链级撤销）");
    }

    /// 生成 RSA 密钥对 smoke 测试：验证 rsa 依赖可用且能生成 2048 位密钥。
    #[test]
    fn generate_test_rsa_keys_smoke() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 密钥失败");
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let n_bytes = public_key.n().to_bytes_be();
        let e_bytes = public_key.e().to_bytes_be();

        let n_b64 = URL_SAFE_NO_PAD.encode(n_bytes);
        let e_b64 = URL_SAFE_NO_PAD.encode(e_bytes);
        assert!(!n_b64.is_empty(), "n_b64 应非空");
        assert!(!e_b64.is_empty(), "e_b64 应非空");

        let pem = private_key.to_pkcs1_der().expect("导出 PKCS#1 DER 失败");
        assert!(!pem.as_bytes().is_empty(), "DER 应非空");
    }
}
