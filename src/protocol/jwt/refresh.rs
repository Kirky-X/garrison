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
    use crate::dao::{init_dbnexus, BulwarkMigration};
    use dbnexus::DbPool;
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    use std::path::PathBuf;

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
}
