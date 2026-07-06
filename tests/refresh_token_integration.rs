//! RefreshToken Rotation + Reuse Detection 端到端集成测试。
//!
//! 验证 RefreshToken 轮换、重用检测和链级撤销完整流程：
//! 1. `rotate(t1)` 得到 t2 → t1 标记为 revoked，t2 插入且 parent=t1
//! 2. 再次 `rotate(t1)`（重用）→ 返回 InvalidToken 且整条链被吊销
//!
//! 运行：
//! ```bash
//! cargo test --features "protocol-jwt db-sqlite" --test refresh_token_integration
//! ```

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
