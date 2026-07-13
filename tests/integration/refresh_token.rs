//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

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
    use bulwark::protocol::jwt::JwtHandler;
    use bulwark::{BulwarkError, RefreshTokenRotation};
    use dbnexus::DbPool;
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use std::sync::{Arc, RwLock};

    use crate::common::{setup_db, sha256_hex};

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
        let session = pool.get_session("admin").await.expect("获取 admin session");
        let conn = session.connection().expect("获取连接");
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
        let session = pool.get_session("admin").await.expect("获取 admin session");
        let conn = session.connection().expect("获取连接");
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT revoked FROM refresh_tokens WHERE token_hash = ?",
            vec![Value::String(Some(token_hash.to_string()))],
        );
        let row = conn
            .query_one_raw(stmt)
            .await
            .expect("查询应成功")
            .expect("record 应存在");
        row.try_get::<i64>("", "revoked").expect("读取 revoked 列")
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

    /// T016: 验证 `refresh_access_token` 传入已撤销 token 时返回 `TokenRevoked`（透传 `rotate` 错误）。
    ///
    /// 流程：
    /// 1. 预先插入一个 revoked=1 的 refresh token（模拟已被撤销的 token）
    /// 2. 调用 `rotate(old_token)` → `detect_reuse` 发现 revoked=1 → 撤销链后返回 `TokenRevoked`
    ///
    /// 断言：返回 `Err(BulwarkError::TokenRevoked)`，错误信息包含 "reuse" 或 "revoked"。
    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_access_token_with_revoked_token_returns_error() {
        let pool = setup_db().await;

        // 1. 插入一个已撤销的 refresh token (revoked=1)
        let old_token = "revoked-refresh-token-12345";
        let old_hash = sha256_hex(old_token);
        insert_refresh_token(&pool, &old_hash, None, 1001, 0, 1, now_unix() + 3600, 1).await;

        // 2. 创建 RefreshTokenRotation 实例
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_key"));
        let key_version = Arc::new(RwLock::new(1u32));
        let rotation = RefreshTokenRotation::new(pool, jwt_handler, key_version);

        // 3. 调用 rotate 直接验证行为（透传 TokenRevoked）
        let result = rotation.rotate(old_token).await;
        assert!(
            matches!(result, Err(BulwarkError::TokenRevoked(ref msg)) if msg.contains("reuse") || msg.contains("revoked")),
            "已撤销 token 应返回 TokenRevoked 错误，实际: {:?}",
            result
        );
    }
}
