//! JWT RefreshToken Rotation 模块（v0.5.0 新增，依据 proposal H4）。
//!
//! 基于 hash chain 的 RefreshToken 轮换：每次 `rotate` 时，新 token 的
//! `parent_token_hash` 指向旧 token 的 `token_hash`，形成链式结构。
//! 旧 token 标记为 `revoked`，防止重放攻击。
//!
//! ## 核心抽象
//!
//! - [`RefreshTokenRecord`]：`refresh_tokens` 表行结构（hash chain 字段）
//! - `RefreshTokenRotation`：rotate 服务（T057-T066 实现）
//!
//! ## 表结构
//!
//! ```sql
//! CREATE TABLE refresh_tokens (
//!     token_hash TEXT PRIMARY KEY,
//!     parent_token_hash TEXT,
//!     login_id INTEGER NOT NULL,
//!     tenant_id INTEGER NOT NULL DEFAULT 0,
//!     key_version INTEGER NOT NULL,
//!     expires_at INTEGER NOT NULL,
//!     revoked INTEGER NOT NULL DEFAULT 0,
//!     created_at INTEGER NOT NULL
//! );
//! ```

// ============================================================================
// RefreshTokenRecord 定义（T054 Green）
// ============================================================================

/// `refresh_tokens` 表行结构（T054 Green）。
///
/// 基于 hash chain 的 RefreshToken 记录：每次 `rotate` 时，新 token 的
/// `parent_token_hash` 指向旧 token 的 `token_hash`，形成链式结构。
/// 旧 token 标记为 `revoked`，防止重放攻击。
///
/// # 字段
///
/// - `token_hash`: 当前 token 的 SHA-256 哈希（主键）
/// - `parent_token_hash`: 旧 token 的哈希（首次签发为 `None`）
/// - `login_id`: 关联用户 ID
/// - `tenant_id`: 租户 ID（多租户隔离）
/// - `key_version`: 密钥轮换版本号（支持密钥轮换时区分）
/// - `expires_at`: 过期时间（Unix 秒）
/// - `revoked`: 是否已撤销（rotate 后旧 token 标记为 true）
/// - `created_at`: 创建时间（Unix 秒）
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefreshTokenRecord {
    /// 当前 token 的 SHA-256 哈希（主键）。
    pub token_hash: String,
    /// 旧 token 的哈希（首次签发为 `None`）。
    pub parent_token_hash: Option<String>,
    /// 关联用户 ID。
    pub login_id: i64,
    /// 租户 ID（多租户隔离）。
    pub tenant_id: i64,
    /// 密钥轮换版本号。
    pub key_version: u32,
    /// 过期时间（Unix 秒）。
    pub expires_at: i64,
    /// 是否已撤销（rotate 后旧 token 标记为 true）。
    pub revoked: bool,
    /// 创建时间（Unix 秒）。
    pub created_at: i64,
}

// ============================================================================
// RefreshTokenRotation 服务（T057-T064：db-sqlite gated）
// ============================================================================

#[cfg(feature = "db-sqlite")]
mod service {
    use crate::error::{BulwarkError, BulwarkResult};
    use crate::protocol::jwt::JwtHandler;
    use dbnexus::DbPool;
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, RwLock};
    use uuid::Uuid;

    /// RefreshToken Rotation 服务（hash chain + rotate + reuse detection）。
    ///
    /// 完整实现在 T057-T066 逐步构建：
    /// - T057-T058: `rotate` 基础实现（SHA-256 hash + INSERT new + UPDATE old revoked=1）
    /// - T059-T060: `detect_reuse` 查表 revoked=1
    /// - T061-T062: `revoke_chain` 递归 UPDATE parent_token_hash 链
    /// - T063-T064: `rotate` 追加 reuse detection（重用则 revoke_chain 后返回 InvalidToken）
    ///
    /// # 字段
    ///
    /// - `pool`: SQLite 连接池（查 `refresh_tokens` 表）
    /// - `jwt_handler`: JWT 处理器（签发新 access token）
    /// - `key_version`: 密钥轮换版本号（写入新 record 的 key_version 字段）
    ///
    /// # Rule 7 冲突暴露
    ///
    /// tasks.md T058 原描述 `pub dao: Arc<dyn BulwarkDao>` 不够——
    /// `rotate` 需查 SQL（DbPool）+ 签发 access token（JwtHandler）+ 读 key_version。
    /// 决策：struct 持有 `pool: DbPool` + `jwt_handler: Arc<JwtHandler>` + `key_version: Arc<RwLock<u32>>`，
    /// 不持有 `dao`（BulwarkDao 是缓存层抽象，不支持 SQL 查询）。
    pub struct RefreshTokenRotation {
        /// SQLite 连接池（查 `refresh_tokens` 表）。
        pub pool: DbPool,
        /// JWT 处理器（签发新 access token）。
        pub jwt_handler: Arc<JwtHandler>,
        /// 密钥轮换版本号（写入新 record 的 key_version 字段）。
        pub key_version: Arc<RwLock<u32>>,
    }

    impl RefreshTokenRotation {
        /// 创建 RefreshTokenRotation 实例。
        ///
        /// # 参数
        /// - `pool`: SQLite 连接池（用于查 `refresh_tokens` 表）
        /// - `jwt_handler`: JWT 处理器（签发新 access token）
        /// - `key_version`: 密钥轮换版本号（写入新 record 的 key_version 字段）
        pub fn new(
            pool: DbPool,
            jwt_handler: Arc<JwtHandler>,
            key_version: Arc<RwLock<u32>>,
        ) -> Self {
            Self {
                pool,
                jwt_handler,
                key_version,
            }
        }

        /// 计算 SHA-256 并返回 hex 字符串。
        fn sha256_hex(s: &str) -> String {
            let mut hasher = Sha256::new();
            hasher.update(s.as_bytes());
            let result = hasher.finalize();
            result.iter().map(|b| format!("{:02x}", b)).collect()
        }

        /// 获取当前 Unix 时间戳（秒）。
        fn now_unix() -> i64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        }

        /// T058 Green: rotate 旧 refresh token 为新 access + 新 refresh。
        ///
        /// 流程：
        /// 1. 计算 `old_hash = SHA-256(old_token)`
        /// 2. 查表验证 `old_hash` 存在且 `revoked=0`，读取 login_id / tenant_id
        /// 3. 生成新 refresh token（UUID v4）+ 签发新 access token（JwtHandler，1 小时有效期）
        /// 4. 计算 `new_hash = SHA-256(new_refresh)`
        /// 5. INSERT new record（`parent_token_hash = old_hash`, `revoked=0`，7 天过期）
        /// 6. UPDATE old record `revoked=1`
        /// 7. 返回 `(new_access, new_refresh)`
        ///
        /// # 错误
        /// - `BulwarkError::InvalidToken`: old_token 不存在或已 revoked
        /// - `BulwarkError::Dao`: SQL 查询/INSERT/UPDATE 失败
        /// - `BulwarkError::Internal`: JwtHandler 签发失败（由 sign 透传）
        pub async fn rotate(&self, old_token: &str) -> BulwarkResult<(String, String)> {
            let old_hash = Self::sha256_hex(old_token);

            // 查表验证 old_hash 存在且 revoked=0
            let session = self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 session 失败: {}", e))
            })?;
            let conn = session.connection().map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 connection 失败: {}", e))
            })?;

            let select_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT login_id, tenant_id FROM refresh_tokens WHERE token_hash = ? AND revoked = 0",
                vec![Value::String(Some(old_hash.clone()))],
            );
            let row = conn
                .query_one_raw(select_stmt)
                .await
                .map_err(|e| BulwarkError::Dao(format!("refresh_tokens 查询失败: {}", e)))?
                .ok_or_else(|| {
                    BulwarkError::InvalidToken(
                        "refresh token not found or already consumed".to_string(),
                    )
                })?;

            let login_id: i64 = row
                .try_get("", "login_id")
                .map_err(|e| BulwarkError::Dao(format!("login_id 读取失败: {}", e)))?;
            let tenant_id: i64 = row
                .try_get("", "tenant_id")
                .map_err(|e| BulwarkError::Dao(format!("tenant_id 读取失败: {}", e)))?;

            // 生成新 refresh token + 签发新 access token
            let new_refresh = Uuid::new_v4().to_string();
            let new_access = self.jwt_handler.sign(login_id, 3600)?;
            let new_hash = Self::sha256_hex(&new_refresh);
            let now = Self::now_unix();
            let kv = *self
                .key_version
                .read()
                .expect("key_version RwLock 不应 poisoned");

            // INSERT new record（parent_token_hash = old_hash, revoked=0, 7 天过期）
            let insert_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO refresh_tokens (token_hash, parent_token_hash, login_id, tenant_id, key_version, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    Value::String(Some(new_hash.clone())),
                    Value::String(Some(old_hash.clone())),
                    Value::BigInt(Some(login_id)),
                    Value::BigInt(Some(tenant_id)),
                    Value::BigInt(Some(kv as i64)),
                    Value::BigInt(Some(now + 86400 * 7)),
                    Value::BigInt(Some(0)),
                    Value::BigInt(Some(now)),
                ],
            );
            conn.execute_raw(insert_stmt)
                .await
                .map_err(|e| BulwarkError::Dao(format!("refresh_tokens INSERT 失败: {}", e)))?;

            // UPDATE old record revoked=1
            let update_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
                vec![Value::String(Some(old_hash))],
            );
            conn.execute_raw(update_stmt)
                .await
                .map_err(|e| BulwarkError::Dao(format!("refresh_tokens UPDATE 失败: {}", e)))?;

            Ok((new_access, new_refresh))
        }

        /// T060 Green: 检测 token 是否已被消费（revoked=1 即 reuse）。
        ///
        /// # 参数
        /// - `token_hash`: 已 SHA-256 哈希的 token hash（非原始 token）
        ///
        /// # 返回
        /// - `Ok(true)`: token 已 revoked（reuse 检测命中）
        /// - `Ok(false)`: token 未 revoked 或不存在
        /// - `Err(BulwarkError::Dao)`: SQL 查询失败
        ///
        /// # 语义
        /// 不存在与 revoked=0 同等对待（均返回 false）——
        /// 只有已 revoked 才视为 reuse。不存在视为"未签发"，由调用方决定如何处理。
        pub async fn detect_reuse(&self, token_hash: &str) -> BulwarkResult<bool> {
            let session = self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 session 失败: {}", e))
            })?;
            let conn = session.connection().map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 connection 失败: {}", e))
            })?;

            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT revoked FROM refresh_tokens WHERE token_hash = ?",
                vec![Value::String(Some(token_hash.to_string()))],
            );
            let row = conn
                .query_one_raw(stmt)
                .await
                .map_err(|e| BulwarkError::Dao(format!("refresh_tokens 查询失败: {}", e)))?;

            // 不存在 → false（未签发，不算 reuse）；存在且 revoked=1 → true
            let revoked = match row {
                Some(row) => row
                    .try_get::<i64>("", "revoked")
                    .map_err(|e| BulwarkError::Dao(format!("revoked 读取失败: {}", e)))?,
                None => return Ok(false),
            };
            Ok(revoked == 1)
        }

        /// T062 Green: 撤销给定 token 及其所有子代（沿 parent_token_hash 反向递归）。
        ///
        /// 语义：reuse detection 命中 old_token 后，old_token 之后签发的所有
        /// 后代 token（即 parent_token_hash 链上以 old_token 为根的子树）
        /// 都应被吊销，防止攻击者继续使用被盗链。
        ///
        /// # 参数
        /// - `token_hash`: 起点 token hash（已 SHA-256 哈希）
        ///
        /// # 算法（迭代 + 栈，避免 async 递归 Box::pin 复杂度）
        /// 1. 把 `token_hash` 入栈
        /// 2. 出栈一个 hash，UPDATE 它 revoked=1
        /// 3. 查所有 `parent_token_hash == hash` 的 record（子代），入栈
        /// 4. 重复直到栈空
        ///
        /// # 错误
        /// - `BulwarkError::Dao`: SQL 查询/UPDATE 失败
        pub async fn revoke_chain(&self, token_hash: &str) -> BulwarkResult<()> {
            let session = self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 session 失败: {}", e))
            })?;
            let conn = session.connection().map_err(|e| {
                BulwarkError::Dao(format!("refresh_tokens 获取 connection 失败: {}", e))
            })?;

            let mut stack = vec![token_hash.to_string()];
            while let Some(hash) = stack.pop() {
                // UPDATE current revoked=1
                let update_stmt = Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
                    vec![Value::String(Some(hash.clone()))],
                );
                conn.execute_raw(update_stmt)
                    .await
                    .map_err(|e| BulwarkError::Dao(format!("refresh_tokens UPDATE 失败: {}", e)))?;

                // 查子代（parent_token_hash == hash）
                let select_stmt = Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "SELECT token_hash FROM refresh_tokens WHERE parent_token_hash = ?",
                    vec![Value::String(Some(hash))],
                );
                let rows = conn.query_all_raw(select_stmt).await.map_err(|e| {
                    BulwarkError::Dao(format!("refresh_tokens 查询子代失败: {}", e))
                })?;
                for row in rows {
                    let child_hash: String = row
                        .try_get("", "token_hash")
                        .map_err(|e| BulwarkError::Dao(format!("token_hash 读取失败: {}", e)))?;
                    stack.push(child_hash);
                }
            }
            Ok(())
        }
    }
}

#[cfg(feature = "db-sqlite")]
pub use service::RefreshTokenRotation;

// ============================================================================
// 测试模块
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// T053 Red: `RefreshTokenRecord` 构造测试（hash chain 字段可读）。
    ///
    /// 断言所有字段可正确初始化与读取，包括：
    /// - `token_hash`: 新 token 的 SHA-256 哈希
    /// - `parent_token_hash`: 旧 token 的哈希（首次签发为 None）
    /// - `login_id` / `tenant_id`: 多租户隔离
    /// - `key_version`: 密钥轮换版本号
    /// - `expires_at` / `created_at`: 时间戳
    /// - `revoked`: 是否已撤销（防重放）
    #[test]
    fn refresh_token_record_constructs_with_hash_chain_fields() {
        let record = RefreshTokenRecord {
            token_hash: "abc".to_string(),
            parent_token_hash: Some("def".to_string()),
            login_id: 1,
            tenant_id: 0,
            key_version: 1,
            expires_at: 9999,
            revoked: false,
            created_at: 0,
        };
        assert_eq!(record.token_hash, "abc");
        assert_eq!(record.parent_token_hash, Some("def".to_string()));
        assert_eq!(record.login_id, 1);
        assert_eq!(record.tenant_id, 0);
        assert_eq!(record.key_version, 1);
        assert_eq!(record.expires_at, 9999);
        assert!(!record.revoked);
        assert_eq!(record.created_at, 0);
    }
}

// ============================================================================
// db-sqlite 集成测试（T055-T066: refresh_tokens 表迁移 + rotate 服务）
// ============================================================================

#[cfg(all(test, feature = "protocol-jwt", feature = "db-sqlite"))]
mod db_sqlite_tests {
    use super::RefreshTokenRotation;
    use crate::dao::{init_dbnexus, BulwarkMigration};
    use crate::protocol::jwt::JwtHandler;
    use dbnexus::DbPool;
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};

    /// 定位项目根目录的 migrations/sqlite/ 目录。
    fn project_migrations_dir() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .join("migrations")
            .join("sqlite")
    }

    /// 创建并初始化 SQLite in-memory 数据库（迁移 + 返回 pool）。
    async fn setup_db() -> DbPool {
        let pool = init_dbnexus("sqlite::memory:")
            .await
            .expect("init_dbnexus 应成功");
        let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());
        let applied = migration.migrate_core().await.expect("migrate_core 应成功");
        assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
        pool
    }

    // ========================================================================
    // T055-T056: refresh_tokens 表迁移验证
    // ========================================================================

    /// T055-T056 Green: 验证 SQLite 迁移加载 `003_refresh_tokens.sql` 后
    /// `refresh_tokens` 表存在。
    ///
    /// Rule 11（惯例优先）：SQL 文件放 `migrations/sqlite/core/003_refresh_tokens.sql`，
    /// 复用现有 `migrate_core()` 自动加载机制（与 002_role_hierarchy.sql 同惯例），
    /// 而非 tasks.md 原描述的 `src/dao/repository/sqlite/refresh_tokens.sql`。
    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_tokens_table_exists_after_migration() {
        let pool = setup_db().await;
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type='table' AND name='refresh_tokens'",
            vec![],
        );
        let rows = conn.query_all_raw(stmt).await.expect("query_all 应成功");
        assert_eq!(
            rows.len(),
            1,
            "refresh_tokens 表应存在（迁移后 sqlite_master 应有 1 行记录）"
        );
    }

    // ========================================================================
    // 辅助函数（T057+ rotate 测试用）
    // ========================================================================

    /// 计算 SHA-256 并返回 hex 字符串。
    fn sha256_hex(s: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// 向 refresh_tokens 表插入一条记录。
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

    /// 查询 record 的 revoked 字段。
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

    /// 查询 record 的 (parent_token_hash, revoked)。
    async fn query_record(pool: &DbPool, token_hash: &str) -> (Option<String>, i64) {
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT parent_token_hash, revoked FROM refresh_tokens WHERE token_hash = ?",
            vec![Value::String(Some(token_hash.to_string()))],
        );
        let row = conn
            .query_one_raw(stmt)
            .await
            .unwrap()
            .expect("record 应存在");
        let parent: Option<String> = row.try_get("", "parent_token_hash").ok();
        let revoked: i64 = row.try_get("", "revoked").unwrap();
        (parent, revoked)
    }

    // ========================================================================
    // T057-T058: rotate 测试
    // ========================================================================

    /// T057 Red: `rotate` 插入新 token 并标记旧 token 已消费。
    ///
    /// 流程：
    /// 1. 预先 INSERT old_token record（模拟已签发的 refresh token）
    /// 2. 调用 `rotate(old_token)` 返回 (new_access, new_refresh)
    /// 3. 断言 old_token 的 record revoked=1
    /// 4. 断言 new_refresh 的 record 已插入，parent_token_hash == SHA-256(old_token)
    #[tokio::test(flavor = "multi_thread")]
    async fn rotate_inserts_new_token_and_marks_old_consumed() {
        let pool = setup_db().await;

        // 预先 INSERT old_token record
        let old_token = "old_token_value";
        let old_hash = sha256_hex(old_token);
        insert_refresh_token(&pool, &old_hash, None, 1, 0, 1, 9999, 0).await;

        // 构造 RefreshTokenRotation（Rule 7：持有 pool + jwt_handler + key_version）
        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // rotate
        let (new_access, new_refresh) = rotation.rotate(old_token).await.expect("rotate 应成功");
        assert!(!new_access.is_empty(), "new_access 应非空");
        assert!(!new_refresh.is_empty(), "new_refresh 应非空");

        // 断言 old_token revoked=1
        let old_revoked = query_revoked(&pool, &old_hash).await;
        assert_eq!(old_revoked, 1, "old_token 应标记为 revoked");

        // 断言 new_refresh 的 record 已插入，parent_token_hash == old_hash
        let new_hash = sha256_hex(&new_refresh);
        let (parent, revoked) = query_record(&pool, &new_hash).await;
        assert_eq!(
            parent,
            Some(old_hash),
            "new record 的 parent_token_hash 应等于 old_hash"
        );
        assert_eq!(revoked, 0, "new record 应未 revoked");
    }

    // ========================================================================
    // T059-T060: detect_reuse 测试
    // ========================================================================

    /// T059 Red: `detect_reuse` 在 token 已被消费（revoked=1）时返回 true。
    ///
    /// 流程：
    /// 1. 预先 INSERT old_token record（revoked=0）
    /// 2. 调用 `rotate(old_token)` → old_token 标记为 revoked=1
    /// 3. 调用 `detect_reuse(SHA-256(old_token))` → 断言返回 `true`（已消费）
    /// 4. 用 new_refresh 的 hash 调用 `detect_reuse` → 断言返回 `false`（未消费）
    #[tokio::test(flavor = "multi_thread")]
    async fn detect_reuse_returns_true_when_token_already_consumed() {
        let pool = setup_db().await;

        let old_token = "old_token_value";
        let old_hash = sha256_hex(old_token);
        insert_refresh_token(&pool, &old_hash, None, 1, 0, 1, 9999, 0).await;

        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // rotate 后 old_token 应 revoked=1
        let (_, new_refresh) = rotation.rotate(old_token).await.expect("rotate 应成功");

        // detect_reuse(old_hash) → true（已被消费）
        let reused = rotation
            .detect_reuse(&old_hash)
            .await
            .expect("detect_reuse 应成功");
        assert!(reused, "已 revoked 的 token 应检测为 reuse");

        // detect_reuse(new_hash) → false（未消费）
        let new_hash = sha256_hex(&new_refresh);
        let new_reused = rotation
            .detect_reuse(&new_hash)
            .await
            .expect("detect_reuse 应成功");
        assert!(!new_reused, "未 revoked 的 token 不应检测为 reuse");
    }

    // ========================================================================
    // T061-T062: revoke_chain 测试
    // ========================================================================

    /// T061 Red: `revoke_chain` 撤销给定 token 及其所有子代（沿 parent_token_hash 反向递归）。
    ///
    /// 构造链：t1 (parent=None) ← t2 (parent=t1) ← t3 (parent=t2)
    /// （t3 是最新，t1 是最老）
    ///
    /// 调用 `revoke_chain(SHA-256(t1))` → 应撤销 t1 及其所有子代（t2, t3）
    ///
    /// 断言：t1/t2/t3 的 revoked 字段全为 1
    ///
    /// **Rule 7 命名说明**：tasks.md 原测试名 `revoke_chain_revokes_all_parent_tokens`
    /// 与实际语义有歧义——实际撤销的是 t1 及其所有"子代"（descendant），
    /// 而非"父代"（parent）。此处沿用 tasks.md 命名以保持一致（Rule 11），
    /// 但语义以 doc comment 为准。
    #[tokio::test(flavor = "multi_thread")]
    async fn revoke_chain_revokes_all_parent_tokens() {
        let pool = setup_db().await;

        // 构造链 t1 ← t2 ← t3（t3 最新）
        let t1_hash = sha256_hex("t1");
        let t2_hash = sha256_hex("t2");
        let t3_hash = sha256_hex("t3");
        insert_refresh_token(&pool, &t1_hash, None, 1, 0, 1, 9999, 0).await;
        insert_refresh_token(&pool, &t2_hash, Some(&t1_hash), 1, 0, 1, 9999, 0).await;
        insert_refresh_token(&pool, &t3_hash, Some(&t2_hash), 1, 0, 1, 9999, 0).await;

        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // revoke_chain(t1_hash) → t1 + 所有子代（t2, t3）全 revoked
        rotation
            .revoke_chain(&t1_hash)
            .await
            .expect("revoke_chain 应成功");

        assert_eq!(query_revoked(&pool, &t1_hash).await, 1, "t1 应 revoked");
        assert_eq!(
            query_revoked(&pool, &t2_hash).await,
            1,
            "t2 应 revoked（子代）"
        );
        assert_eq!(
            query_revoked(&pool, &t3_hash).await,
            1,
            "t3 应 revoked（孙代）"
        );
    }
}
