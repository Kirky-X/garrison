//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Dbnexus Repository 实现。
//!
//! 基于 dbnexus DbPool + sea-orm Statement 参数化查询。
//! 通过 [`make_statement`] 实现 backend-agnostic：传入 `?` 占位符的 SQL，
//! PostgreSQL 后端运行时自动转换为 `$1`, `$2`, ...
//!
//! ## 设计要点
//!
//! - **参数化查询**：所有 WHERE 条件用 `?` 占位符，防 SQL 注入。
//! - **多租户过滤**（R-004）：有 tenant_id 的表自动注入 `WHERE tenant_id = ?`；
//!   `app_permission` 表无 tenant_id（全局表）。
//! - **find_by_\*** 返回 `Option<Row>`，不存在返回 `Ok(None)`。
//! - **create** 返回 `NewXxx.id`（调用方生成的 UUID），不依赖数据库自增 ID。
//! - **delete** 幂等，不存在返回 `Ok(())`。
//! - **bool 字段**：SQLite 用 INTEGER 0/1 存储，Row struct 用 bool，读取时 i64→bool 转换。
//! - **时间字段**：SQLite 用 CURRENT_TIMESTAMP 默认生成，读取为 String。

use dbnexus::DbPool;
use sea_orm::{QueryResult, Value};

// ============================================================================
// 子模块声明（impl 块拆分到独立文件，遵循 mod.rs 加固规则 D1）
// ============================================================================

mod auth_method_repo;
mod login_log_repo;
mod permission_repo;
mod role_permission_repo;
mod role_repo;
mod session_repo;
mod user_device_repo;
mod user_ext_repo;
mod user_repo;
mod user_role_repo;

// ============================================================================
// 内部辅助函数
// ============================================================================

/// 构造字符串 Value 参数。
fn v_str(s: &str) -> Value {
    Value::String(Some(s.to_string()))
}

/// 构造可选字符串 Value 参数（None → SQL NULL）。
fn v_opt_str(s: &Option<String>) -> Value {
    Value::String(s.clone())
}

/// 构造 i64 Value 参数（用于 offset/limit 等）。
fn v_i64(n: i64) -> Value {
    Value::BigInt(Some(n))
}

/// 构造布尔 Value 参数（SQLite 用 0/1 存储）。
fn v_bool(b: bool) -> Value {
    Value::BigInt(Some(if b { 1 } else { 0 }))
}

/// 读取 bool 列（SQLite INTEGER 0/1 → bool）。
fn read_bool(row: &QueryResult, col: &str) -> bool {
    row.try_get::<i64>("", col).map(|v| v != 0).unwrap_or(false)
}

// ============================================================================
// Repository struct 定义（impl 见各 _repo.rs 子模块）
// ============================================================================

/// SQLite 用户表 Repository 实现。
pub struct DbnexusUserRepository {
    pool: DbPool,
}

/// SQLite 角色表 Repository 实现。
pub struct DbnexusRoleRepository {
    pool: DbPool,
}

/// SQLite 权限表 Repository 实现（全局表，无 tenant_id）。
pub struct DbnexusPermissionRepository {
    pool: DbPool,
}

/// SQLite 用户-角色关联表 Repository 实现。
pub struct DbnexusUserRoleRepository {
    pool: DbPool,
}

/// SQLite 角色-权限关联表 Repository 实现。
pub struct DbnexusRolePermissionRepository {
    pool: DbPool,
}

/// SQLite 认证方式表 Repository 实现。
pub struct DbnexusAuthMethodRepository {
    pool: DbPool,
}

/// SQLite 会话表 Repository 实现。
pub struct DbnexusSessionRepository {
    pool: DbPool,
}

/// SQLite 登录日志表 Repository 实现。
pub struct DbnexusLoginLogRepository {
    pool: DbPool,
}

/// SQLite 用户扩展字段表 Repository 实现。
pub struct DbnexusUserExtRepository {
    pool: DbPool,
}

/// SQLite 用户设备表 Repository 实现。
///
/// UA 解析当前用简单字符串启发式（提取 Browser/OS 关键字）。
/// 完整 `ua-parser` regex 集需启用 `ua-parser-precompiled` feature（设计 A4 决策延后）。
pub struct DbnexusUserDeviceRepository {
    pool: DbPool,
}

// ============================================================================
// 测试模块
// ============================================================================

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::*;
    use crate::dao::repository::*;
    use crate::dao::{init_dbnexus, BulwarkMigration};
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

    /// R-tenant-isolation-004: Repository SQL 强制 tenant_id 过滤。
    ///
    /// 验证 v0.4.2 已无条件实现的 `WHERE tenant_id = ?` 过滤行为：
    /// - 构造 tenant_id=42 与 tenant_id=1 的用户
    /// - 跨租户查询应返回 None（SQL 含 `WHERE tenant_id = ?` 过滤）
    /// - list 按 tenant 隔离
    ///
    /// 注：v0.5.0 决策（Rule 7 暴露冲突后用户选择"保留 v0.4.2 无条件过滤"）：
    /// SQL 过滤不门控 `tenant-isolation` feature，始终生效——因 tenant_id 已是所有表必需字段，
    /// 不过滤会导致跨租户数据泄露（安全优先）。
    #[tokio::test(flavor = "multi_thread")]
    async fn repository_filters_by_tenant_id_when_tenant_isolation_enabled() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        // 在 tenant 42 创建用户
        let user_42 = repo
            .create(
                42,
                NewUser {
                    username: "tenant-42-user".to_string(),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("create tenant 42 用户应成功");

        // 在 tenant 1 创建用户
        let user_1 = repo
            .create(
                1,
                NewUser {
                    username: "tenant-1-user".to_string(),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("create tenant 1 用户应成功");

        // 跨租户 find_by_id：tenant 42 查不到 tenant 1 的用户（SQL 含 WHERE tenant_id = ?）
        let cross = repo.find_by_id(42, &user_1).await.unwrap();
        assert!(
            cross.is_none(),
            "tenant 42 不应查到 tenant 1 的用户（SQL 过滤生效）"
        );

        // 跨租户 find_by_id：tenant 1 查不到 tenant 42 的用户
        let cross = repo.find_by_id(1, &user_42).await.unwrap();
        assert!(
            cross.is_none(),
            "tenant 1 不应查到 tenant 42 的用户（SQL 过滤生效）"
        );

        // 跨租户 find_by_username：tenant 42 查不到 tenant 1 的 username
        let cross = repo.find_by_username(42, "tenant-1-user").await.unwrap();
        assert!(
            cross.is_none(),
            "tenant 42 不应查到 tenant 1 的 username（SQL 过滤生效）"
        );

        // list 按 tenant 隔离
        let list_42 = repo.list(42, 0, 100).await.unwrap();
        let list_1 = repo.list(1, 0, 100).await.unwrap();
        let ids_42: Vec<_> = list_42.iter().map(|u| u.id.clone()).collect();
        let ids_1: Vec<_> = list_1.iter().map(|u| u.id.clone()).collect();
        assert!(
            ids_42.contains(&user_42) && !ids_42.contains(&user_1),
            "tenant 42 list 应仅含本租户用户"
        );
        assert!(
            ids_1.contains(&user_1) && !ids_1.contains(&user_42),
            "tenant 1 list 应仅含本租户用户"
        );

        // 验证返回行的 tenant_id 字段正确
        let row_42 = repo.find_by_id(42, &user_42).await.unwrap().unwrap();
        assert_eq!(row_42.tenant_id, 42, "返回行 tenant_id 应为 42");
    }

    /// create 内部生成合法 UUID v4。
    ///
    /// 验证 Repository 内部生成 UUID v4 的行为：
    /// - 调用 create 不传 id
    /// - 返回值应为合法 UUID v4（parse_str 成功 + version == Random）
    #[tokio::test(flavor = "multi_thread")]
    async fn create_generates_valid_uuid_v4() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        let id = repo
            .create(
                42,
                NewUser {
                    username: "uuid-test".to_string(),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("create 应成功并返回 UUID v4");

        let parsed = uuid::Uuid::parse_str(&id).expect("返回的 id 应为合法 UUID");
        assert_eq!(
            parsed.get_version(),
            Some(uuid::Version::Random),
            "返回的 id 应为 UUID v4，实际: {}",
            id
        );
    }
}
