//! 审计日志模块（v0.5.0 新增，依据 proposal H3）。
//!
//! 提供 `AuditLogListener` 实现，将 `BulwarkEvent` 持久化到 `audit_logs` 表，
//! 支持字段掩码（如 password）与异步写入。
//!
//! ## 核心抽象
//!
//! - [`AuditConfig`]：审计日志配置（掩码字段 + 保留天数 + 异步写入开关）
//! - `AuditLogListener`：实现 `BulwarkListener`，将事件转换为 `AuditEntry` 持久化（T071-T078 实现）
//! - `AuditEntry`：`audit_logs` 表行结构（T071-T072 实现）
//! - `AuditQuery`：审计日志查询条件（T079-T080 实现）
//!
//! ## 表结构
//!
//! ```sql
//! CREATE TABLE audit_logs (
//!     id INTEGER PRIMARY KEY AUTOINCREMENT,
//!     tenant_id INTEGER NOT NULL DEFAULT 0,
//!     event_type TEXT NOT NULL,
//!     login_id INTEGER,
//!     token TEXT,
//!     ip TEXT,
//!     user_agent TEXT,
//!     metadata TEXT,
//!     success INTEGER NOT NULL,
//!     created_at INTEGER NOT NULL
//! );
//! ```

// ============================================================================
// AuditConfig 定义（T068 Green）
// ============================================================================

/// 审计日志配置（T068 Green）。
///
/// 控制 `AuditLogListener` 的行为：字段掩码、保留天数、异步写入。
///
/// # 字段
///
/// - `mask_fields`: 需掩码的字段列表（如 `password`），metadata JSON 中对应字段值替换为 `"***"`
/// - `retain_days`: 日志保留天数（过期自动清理，0 表示永不清理）
/// - `async_write`: 是否异步写入（true 时不阻塞主流程，失败仅 `tracing::warn`）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    /// 需掩码的字段列表（如 `password`），metadata JSON 中对应字段值替换为 `"***"`。
    pub mask_fields: Vec<String>,
    /// 日志保留天数（过期自动清理，0 表示永不清理）。
    pub retain_days: u32,
    /// 是否异步写入（true 时不阻塞主流程，失败仅 `tracing::warn`）。
    pub async_write: bool,
}

// ============================================================================
// 测试模块
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// T067 Red: `AuditConfig` 构造测试（掩码字段 + 保留天数 + 异步写入开关）。
    ///
    /// 断言所有字段可正确初始化与读取：
    /// - `mask_fields`: 需掩码的字段列表（如 `password`）
    /// - `retain_days`: 日志保留天数（过期自动清理）
    /// - `async_write`: 是否异步写入（不阻塞主流程）
    #[test]
    fn audit_config_constructs_with_mask_fields_and_retain_days() {
        let config = AuditConfig {
            mask_fields: vec!["password".to_string()],
            retain_days: 30,
            async_write: true,
        };
        assert_eq!(config.mask_fields, vec!["password".to_string()]);
        assert_eq!(config.retain_days, 30);
        assert!(config.async_write);
    }
}

// ============================================================================
// db-sqlite 集成测试（T069-T082: audit_logs 表迁移 + AuditLogListener）
// ============================================================================

#[cfg(all(test, feature = "audit-log", feature = "db-sqlite"))]
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
    // T069-T070: audit_logs 表迁移验证
    // ========================================================================

    /// T069-T070 Green: 验证 SQLite 迁移加载 `004_audit_logs.sql` 后
    /// `audit_logs` 表存在。
    ///
    /// Rule 11（惯例优先）：SQL 文件放 `migrations/sqlite/core/004_audit_logs.sql`，
    /// 复用现有 `migrate_core()` 自动加载机制（与 002_role_hierarchy.sql / 003_refresh_tokens.sql 同惯例），
    /// 而非 tasks.md 原描述的 `src/dao/repository/sqlite/audit_logs.sql`。
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_logs_table_exists_after_migration() {
        let pool = setup_db().await;
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'",
            vec![],
        );
        let rows = conn.query_all_raw(stmt).await.expect("query_all 应成功");
        assert_eq!(
            rows.len(),
            1,
            "audit_logs 表应存在（迁移后 sqlite_master 应有 1 行记录）"
        );
    }
}
