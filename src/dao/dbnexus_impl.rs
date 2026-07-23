//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! dbnexus 集成模块。
//!
//! 对应 二级持久化层（DB），
//! 通过 dbnexus 0.2 提供 SQLite/PostgreSQL/MySQL 连接池、Session、迁移能力。
//!
//! Garrison 不定义 `GarrisonDb` trait，直接复用 `dbnexus::DbPool`：
//! - dbnexus 本身就是 DB 适配库，通过特性切换后端
//! - `init_dbnexus(url)` 返回 `dbnexus::DbPool`，业务代码直接调用其方法
//! - `GarrisonMigration` 包装 `DbPool::run_migrations`，按 spec 分层管理迁移脚本

use crate::error::{GarrisonError, GarrisonResult};
use dbnexus::DbPool;
use std::path::{Path, PathBuf};

/// 编译时嵌入的 postgres 迁移文件目录。
///
/// 用 `include_dir::include_dir!` 宏在编译期将 `migrations/postgres/` 目录树
/// 完整嵌入二进制产物。启用 `embedded-migrations` feature 时可用，
/// 配合 [`GarrisonMigration::run_embedded_postgres`] 供 crates.io 消费者
/// 在运行时无需访问 garrison 源码目录即可执行 postgres schema 迁移。
#[cfg(feature = "embedded-migrations")]
static POSTGRES_MIGRATIONS: include_dir::Dir<'_> = include_dir::include_dir!("migrations/postgres");

/// 初始化 dbnexus 连接池（最常用入口）。
///
/// 对应 tasks.md 3.4：封装 dbnexus 初始化逻辑。
///
/// # 参数
/// - `url`: 数据库连接 URL。
///   - SQLite 内存：`sqlite::memory:`
///   - SQLite 文件：`sqlite:///path/to/db.sqlite`
///
/// # 示例
/// ```ignore
/// use garrison::dao::init_dbnexus;
/// let pool = init_dbnexus("sqlite::memory:").await?;
/// ```
pub async fn init_dbnexus(url: &str) -> GarrisonResult<DbPool> {
    DbPool::new(url)
        .await
        .map_err(|e| GarrisonError::Dao(format!("dao-dbnexus-init::{}", e)))
}

/// Garrison schema 迁移管理器。
///
/// 包装 `dbnexus::DbPool::run_migrations`，按 extensible-schema spec 分层管理：
/// - `migrate_core`: 执行 `migrations/sqlite/core/*.sql`（8 张核心表 + app_user_ext）
/// - `migrate_extensions`: 执行 `migrations/sqlite/extensions/*.sql`（用户自定义扩展表）
/// - `migrate_tenant`: 执行 `migrations/sqlite/tenant/*.sql`（多租户特定表）
///
/// 调用 `run_all()` 一次性按 core→extensions→tenant 顺序执行。
///
/// 迁移文件命名约定：`{version}_{description}.sql`（如 `001_init.sql`）
/// 内容格式：用 `-- UP:` 与 `-- DOWN:` 分隔（参见 dbnexus MigrationExecutor::extract_up_sql）
///
/// # 版本号全局唯一约束
/// dbnexus 的 `dbnexus_migrations` 历史表按 version 全局去重（不区分目录）。
/// 因此跨目录的版本号必须互不冲突，建议约定：
/// - `core/`: 1–999（核心表迁移，随版本发布）
/// - `extensions/`: 1000+（用户自定义扩展，从 1000 开始避免冲突）
/// - `tenant/`: 2000+（多租户特定表，从 2000 开始）
pub struct GarrisonMigration {
    pool: DbPool,
    base_dir: PathBuf,
}

impl GarrisonMigration {
    /// 创建迁移管理器，使用默认 `migrations/sqlite/` 基目录。
    pub fn new(pool: DbPool) -> Self {
        Self::with_base_dir(pool, PathBuf::from("migrations/sqlite"))
    }

    /// 创建迁移管理器，指定基目录（用于测试或自定义路径）。
    pub fn with_base_dir(pool: DbPool, base_dir: PathBuf) -> Self {
        Self { pool, base_dir }
    }

    /// 获取底层 `DbPool` 引用（用于查询、Session 等操作）。
    pub fn pool(&self) -> &DbPool {
        &self.pool
    }

    /// 执行核心表迁移（`{base_dir}/core/*.sql`）。
    ///
    /// 对应 extensible-schema spec：8 张核心表 + app_user_ext。
    pub async fn migrate_core(&self) -> GarrisonResult<u32> {
        self.run_dir(&self.base_dir.join("core")).await
    }

    /// 执行扩展表迁移（`{base_dir}/extensions/*.sql`）。
    ///
    /// 对应 extensible-schema spec：用户自定义扩展表（如表名以 `app_` 前缀）。
    pub async fn migrate_extensions(&self) -> GarrisonResult<u32> {
        self.run_dir(&self.base_dir.join("extensions")).await
    }

    /// 执行多租户表迁移（`{base_dir}/tenant/*.sql`）。
    ///
    /// 对应 extensible-schema spec：多租户特定表。
    pub async fn migrate_tenant(&self) -> GarrisonResult<u32> {
        self.run_dir(&self.base_dir.join("tenant")).await
    }

    /// 一次性按 core→extensions→tenant 顺序执行所有迁移。
    ///
    /// 任一阶段失败立即返回错误（不继续后续阶段）。
    pub async fn run_all(&self) -> GarrisonResult<u32> {
        let mut total = 0;
        total += self.migrate_core().await?;
        total += self.migrate_extensions().await?;
        total += self.migrate_tenant().await?;
        Ok(total)
    }

    /// 执行嵌入的 postgres 迁移文件（不需文件系统访问）。
    ///
    /// 将编译时 `include_dir!` 嵌入的 `migrations/postgres/` 目录内容
    /// 写到 `tempfile::tempdir()` 临时目录，再调用 `DbPool::run_migrations`
    /// 执行迁移。完全复用 dbnexus 的迁移历史记录、版本过滤、事务逻辑。
    ///
    /// 适用于 crates.io 消费者：运行时无需访问 garrison crate 源码目录
    /// （如 sinnan 作为 crates.io 依赖消费 garrison 时，工作目录没有
    /// `migrations/postgres/` 子目录）。
    ///
    /// # 子目录遍历
    ///
    /// dbnexus `scan_migrations` 只扫描指定目录顶层的 `.sql` 文件，**不递归子目录**。
    /// garrison postgres 迁移按 `core/`/`extensions/`/`tenant/` 分层组织
    /// （版本号全局唯一，参见 [`GarrisonMigration`] 文档），`copy_embedded_dir`
    /// 会保留子目录结构（如 `temp_dir/core/001_init.sql`）。
    /// 因此本方法遍历 `temp_dir` 的所有子目录，对每个子目录独立调用
    /// [`GarrisonMigration::run_dir`]，累积应用迁移数。未来新增 `extensions/`
    /// 或 `tenant/` 子目录时无需修改本方法。
    ///
    /// # Errors
    ///
    /// 返回 [`GarrisonError::Dao`] 的场景：
    /// - 临时目录创建失败
    /// - 嵌入文件写入失败
    /// - 临时目录读取失败（权限不足、路径无效等）
    /// - dbnexus 迁移执行失败（SQL 语法错误、版本冲突等）
    #[cfg(feature = "embedded-migrations")]
    pub async fn run_embedded_postgres(&self) -> GarrisonResult<u32> {
        let temp_dir = tempfile::tempdir()
            .map_err(|e| GarrisonError::Dao(format!("embedded-migrations-tempdir::{e}")))?;

        // 将嵌入的 postgres 迁移文件写到临时目录（保留 core/ 等子目录结构）
        copy_embedded_dir(&POSTGRES_MIGRATIONS, temp_dir.path())
            .map_err(|e| GarrisonError::Dao(format!("embedded-migrations-write::{e}")))?;

        // dbnexus scan_migrations 不递归子目录，需遍历 temp_dir 的子目录逐个执行。
        // garrison postgres 迁移按 core/extensions/tenant 分层（版本号全局唯一），
        // 对每个子目录独立调用 run_dir，累积应用迁移数。
        let mut total = 0;
        let entries = std::fs::read_dir(temp_dir.path())
            .map_err(|e| GarrisonError::Dao(format!("embedded-migrations-readdir::{e}")))?;
        for entry in entries {
            let entry = entry
                .map_err(|e| GarrisonError::Dao(format!("embedded-migrations-direntry::{e}")))?;
            let path = entry.path();
            if path.is_dir() {
                total += self.run_dir(&path).await?;
            }
        }
        Ok(total)
    }

    /// 执行指定目录的迁移文件。
    ///
    /// 不存在的目录返回 0（不报错，符合 dbnexus scan_migrations 行为）。
    async fn run_dir(&self, dir: &Path) -> GarrisonResult<u32> {
        self.pool.run_migrations(dir).await.map_err(|e| {
            GarrisonError::Dao(format!("dao-dbnexus-migrate::{}::{}", dir.display(), e))
        })
    }
}

/// 递归复制 `include_dir::Dir` 到文件系统目标目录。
///
/// 供 [`GarrisonMigration::run_embedded_postgres`] 使用：将编译时嵌入的
/// `migrations/postgres/` 目录树（含 `core/` 等子目录）展开到临时目录，
/// 以便复用 `DbPool::run_migrations` 从文件系统读取迁移文件。
///
/// 注意：`include_dir::DirEntry::File::path()` 返回相对于**根嵌入目录**的路径
/// （如 `core/001_init.sql`），递归处理子目录时必须只取 `file_name()`，
/// 否则会重复创建 `core/core/` 嵌套目录。
///
/// # Errors
///
/// 返回 `std::io::Error` 的场景：
/// - 创建目录失败（权限不足、路径无效等）
/// - 写入文件失败（磁盘满、路径无效等）
#[cfg(feature = "embedded-migrations")]
fn copy_embedded_dir(dir: &include_dir::Dir, dest: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in dir.entries() {
        match entry {
            include_dir::DirEntry::Dir(sub_dir) => {
                let sub_dest = dest.join(sub_dir.path().file_name().unwrap_or_else(|| {
                    panic!("embedded migration subdirectory must have valid name")
                }));
                copy_embedded_dir(sub_dir, &sub_dest)?;
            },
            include_dir::DirEntry::File(file) => {
                // file.path() 返回相对于根的路径（如 "core/001_init.sql"），
                // 递归到子目录时只取 file_name 避免 core/core/ 嵌套
                let file_name = file
                    .path()
                    .file_name()
                    .expect("embedded migration file must have valid name");
                let file_dest = dest.join(file_name);
                std::fs::write(&file_dest, file.contents())?;
            },
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::*;
    use sea_orm::{ConnectionTrait, DbBackend, Statement};

    // ========================================================================
    // init_dbnexus 辅助函数测试
    // ========================================================================

    /// 验证 init_dbnexus 用 sqlite::memory: 创建池成功。
    #[tokio::test]
    async fn init_dbnexus_sqlite_memory() {
        let pool = init_dbnexus("sqlite::memory:").await;
        assert!(
            pool.is_ok(),
            "init_dbnexus sqlite::memory: 应成功: {:?}",
            pool.err()
        );
    }

    /// 验证 init_dbnexus 用无效 URL 返回错误（Fail Loud 原则）。
    #[tokio::test]
    async fn init_dbnexus_invalid_url_errors() {
        let result = init_dbnexus("not-a-valid-url").await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(_))),
            "无效 URL 应返回 Dao 错误，实际: {:?}",
            result.map(|_| ())
        );
    }

    // ========================================================================
    // GarrisonMigration 测试（使用临时目录 + sqlite::memory:）
    // ========================================================================

    /// 验证 migrate_core 在空目录上返回 0。
    #[tokio::test]
    async fn migrate_core_empty_dir_returns_zero() {
        let pool = init_dbnexus("sqlite::memory:").await.unwrap();
        let tmp = tempfile::tempdir().unwrap();
        // 不创建 core/ 目录，run_dir 应返回 0
        let migration = GarrisonMigration::with_base_dir(pool, tmp.path().to_path_buf());
        let result = migration.migrate_core().await;
        assert!(result.is_ok(), "空目录迁移应成功: {:?}", result.err());
        assert_eq!(result.unwrap(), 0);
    }

    /// 验证 migrate_core 执行单个 SQL 文件后返回 1。
    #[tokio::test]
    async fn migrate_core_single_file() {
        let pool = init_dbnexus("sqlite::memory:").await.unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let core_dir = tmp.path().join("core");
        std::fs::create_dir_all(&core_dir).unwrap();
        std::fs::write(
            core_dir.join("001_init.sql"),
            "-- UP:\nCREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT);\n-- DOWN:\nDROP TABLE test_table;\n",
        )
        .unwrap();

        let migration = GarrisonMigration::with_base_dir(pool, tmp.path().to_path_buf());
        let applied = migration.migrate_core().await.unwrap();
        assert_eq!(applied, 1, "应执行 1 个迁移文件");

        // 再次执行应返回 0（幂等性）
        // 注意：内存数据库每次 run_migrations 会重新扫描，但 dbnexus_migrations 表记录了已应用版本
        // 此处不重复执行（避免复杂化），由后续集成测试覆盖幂等性
    }

    /// 验证 run_all 按顺序执行 core/extensions/tenant。
    ///
    /// 注意：dbnexus 版本号全局唯一（不区分目录），三个目录用不同版本号避免冲突：
    /// - core/001_init.sql → version=1
    /// - extensions/1000_ext.sql → version=1000
    /// - tenant/2000_tenant.sql → version=2000
    #[tokio::test]
    async fn run_all_executes_in_order() {
        let pool = init_dbnexus("sqlite::memory:").await.unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        // core: 001_init.sql (version=1)
        let core_dir = base.join("core");
        std::fs::create_dir_all(&core_dir).unwrap();
        std::fs::write(
            core_dir.join("001_init.sql"),
            "-- UP:\nCREATE TABLE core_t (id INTEGER PRIMARY KEY);\n",
        )
        .unwrap();

        // extensions: 1000_ext.sql (version=1000)
        let ext_dir = base.join("extensions");
        std::fs::create_dir_all(&ext_dir).unwrap();
        std::fs::write(
            ext_dir.join("1000_ext.sql"),
            "-- UP:\nCREATE TABLE ext_t (id INTEGER PRIMARY KEY);\n",
        )
        .unwrap();

        // tenant: 2000_tenant.sql (version=2000)
        let tenant_dir = base.join("tenant");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(
            tenant_dir.join("2000_tenant.sql"),
            "-- UP:\nCREATE TABLE tenant_t (id INTEGER PRIMARY KEY);\n",
        )
        .unwrap();

        let migration = GarrisonMigration::with_base_dir(pool, base.to_path_buf());
        let total = migration.run_all().await.unwrap();
        assert_eq!(total, 3, "run_all 应执行 3 个迁移文件");
    }

    /// 验证 GarrisonMigration::new 使用默认 base_dir。
    #[tokio::test]
    async fn new_uses_default_base_dir() {
        let pool = init_dbnexus("sqlite::memory:").await.unwrap();
        let migration = GarrisonMigration::new(pool);
        assert_eq!(migration.base_dir, PathBuf::from("migrations/sqlite"));
    }

    // ========================================================================
    // CRUD 测试：验证 Session execute_raw_ddl / execute_raw / query
    // ========================================================================

    /// 辅助函数：查询单行单列字符串值。
    async fn query_one_string(session: &dbnexus::Session, sql: &str) -> String {
        let conn = session
            .connection()
            .expect("connection should be available");
        let stmt = Statement::from_sql_and_values(DbBackend::Sqlite, sql, vec![]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .expect("query_one should succeed")
            .expect("row should exist");
        row.try_get::<String>("", "val")
            .expect("column 'val' should be present")
    }

    /// 辅助函数：查询 count(*) 结果。
    async fn query_count(session: &dbnexus::Session, sql: &str) -> i64 {
        let conn = session
            .connection()
            .expect("connection should be available");
        let stmt = Statement::from_sql_and_values(DbBackend::Sqlite, sql, vec![]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .expect("query_one should succeed")
            .expect("row should exist");
        row.try_get::<i64>("", "cnt")
            .expect("column 'cnt' should be present")
    }

    /// Scenario: CRUD 完整流程。
    /// WHEN CREATE TABLE → INSERT → SELECT → UPDATE → SELECT → DELETE → SELECT
    /// THEN 各步骤的 rows_affected 与查询结果符合预期
    #[tokio::test]
    async fn dbnexus_crud_full_cycle() {
        let pool = init_dbnexus("sqlite::memory:").await.unwrap();
        let session = pool.get_session("admin").await.unwrap();

        // CREATE TABLE（DDL 用 execute_raw_ddl，execute_raw 会拒绝 DDL）
        session
            .execute_raw_ddl("CREATE TABLE test_crud (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
            .await
            .expect("CREATE TABLE 应成功");

        // INSERT
        let result = session
            .execute_raw("INSERT INTO test_crud (id, name) VALUES (1, 'alice')")
            .await
            .expect("INSERT 应成功");
        assert_eq!(result.rows_affected(), 1, "INSERT 应影响 1 行");

        // SELECT 验证
        let name =
            query_one_string(&session, "SELECT name AS val FROM test_crud WHERE id = 1").await;
        assert_eq!(name, "alice", "INSERT 后应查到 alice");

        // UPDATE
        let result = session
            .execute_raw("UPDATE test_crud SET name = 'bob' WHERE id = 1")
            .await
            .expect("UPDATE 应成功");
        assert_eq!(result.rows_affected(), 1, "UPDATE 应影响 1 行");

        // 验证 UPDATE
        let name =
            query_one_string(&session, "SELECT name AS val FROM test_crud WHERE id = 1").await;
        assert_eq!(name, "bob", "UPDATE 后应查到 bob");

        // DELETE
        let result = session
            .execute_raw("DELETE FROM test_crud WHERE id = 1")
            .await
            .expect("DELETE 应成功");
        assert_eq!(result.rows_affected(), 1, "DELETE 应影响 1 行");

        // 验证 DELETE
        let count = query_count(&session, "SELECT count(*) AS cnt FROM test_crud").await;
        assert_eq!(count, 0, "DELETE 后表应为空");
    }

    // ========================================================================
    // 事务测试：验证 begin/commit/rollback
    // ========================================================================

    /// Scenario: 事务回滚后未提交的数据不可见。
    /// WHEN begin → INSERT → rollback → SELECT count(*)
    /// THEN count == 0（回滚清除未提交的 INSERT）
    #[tokio::test]
    async fn dbnexus_transaction_rollback() {
        let pool = init_dbnexus("sqlite::memory:").await.unwrap();
        let session = pool.get_session("admin").await.unwrap();

        session
            .execute_raw_ddl("CREATE TABLE test_txn (id INTEGER PRIMARY KEY, name TEXT)")
            .await
            .unwrap();

        // 开始事务
        session.begin_transaction().await.expect("begin 应成功");

        // 在事务中 INSERT
        session
            .execute_raw("INSERT INTO test_txn (id, name) VALUES (1, 'temp')")
            .await
            .expect("事务内 INSERT 应成功");

        // 回滚
        session.rollback().await.expect("rollback 应成功");

        // 验证表为空
        let count = query_count(&session, "SELECT count(*) AS cnt FROM test_txn").await;
        assert_eq!(count, 0, "回滚后表应为空");
    }

    /// Scenario: 事务提交后数据持久化。
    /// WHEN begin → INSERT → commit → SELECT count(*)
    /// THEN count == 1（提交后数据可见）
    #[tokio::test]
    async fn dbnexus_transaction_commit() {
        let pool = init_dbnexus("sqlite::memory:").await.unwrap();
        let session = pool.get_session("admin").await.unwrap();

        session
            .execute_raw_ddl("CREATE TABLE test_txn_c (id INTEGER PRIMARY KEY, name TEXT)")
            .await
            .unwrap();

        session.begin_transaction().await.unwrap();
        session
            .execute_raw("INSERT INTO test_txn_c (id, name) VALUES (1, 'committed')")
            .await
            .unwrap();
        session.commit().await.expect("commit 应成功");

        let count = query_count(&session, "SELECT count(*) AS cnt FROM test_txn_c").await;
        assert_eq!(count, 1, "提交后应有 1 条记录");
    }

    // ========================================================================
    // 8 表验证测试：用项目根目录的 migrations/sqlite/core/001_init.sql
    // ========================================================================

    /// Scenario: migrate_core 创建 8 张核心表 + app_user_ext。
    /// WHEN GarrisonMigration::migrate_core() 执行 001_init.sql
    /// THEN sqlite_master 中应包含 10 张表：
    ///   app_user / app_role / app_permission / app_user_role / app_role_permission
    ///   / app_auth_method / app_session / app_login_log / app_user_ext / app_user_device
    #[tokio::test]
    async fn migrate_core_creates_all_core_tables() {
        let pool = init_dbnexus("sqlite::memory:").await.unwrap();

        // 用 CARGO_MANIFEST_DIR 定位项目根目录的 migrations/sqlite/
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR 应可用");
        let base_dir = PathBuf::from(manifest_dir).join("migrations/sqlite");

        let migration = GarrisonMigration::with_base_dir(pool, base_dir);
        let applied = migration.migrate_core().await.expect("migrate_core 应成功");
        // 001_init.sql + 002_role_hierarchy.sql + 003_refresh_tokens.sql + 004_audit_logs.sql = 4 个文件
        assert!(
            applied >= 4,
            "应至少执行 4 个迁移文件（001-004），实际: {}",
            applied
        );

        // 查询 sqlite_master 验证 10 张表存在
        let pool = migration.pool();
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
            vec![],
        );
        let rows = conn.query_all_raw(stmt).await.expect("query_all 应成功");
        let table_names: Vec<String> = rows
            .iter()
            .map(|row| row.try_get::<String>("", "name").unwrap_or_default())
            .collect();

        // 8 张核心表 + app_user_ext + app_user_device = 10 张表
        // （不含 dbnexus_migrations / role_hierarchy / refresh_tokens / audit_logs）
        let expected_tables = [
            "app_auth_method",
            "app_login_log",
            "app_permission",
            "app_role",
            "app_role_permission",
            "app_session",
            "app_user",
            "app_user_device",
            "app_user_ext",
            "app_user_role",
        ];
        for expected in &expected_tables {
            assert!(
                table_names.contains(&expected.to_string()),
                "核心表 {} 应存在于 sqlite_master，实际表: {:?}",
                expected,
                table_names
            );
        }
        assert_eq!(
            expected_tables.len(),
            10,
            "应有 10 张核心表（8 核心 + app_user_ext + app_user_device）"
        );
    }

    /// Scenario: 迁移幂等性——重复执行 migrate_core 不重复建表。
    /// WHEN migrate_core() → migrate_core() 再次执行
    /// THEN 第二次返回 0（无新增迁移），10 张表仍存在
    #[tokio::test]
    async fn migrate_core_idempotent() {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let base_dir = PathBuf::from(manifest_dir).join("migrations/sqlite");

        let pool = init_dbnexus("sqlite::memory:").await.unwrap();
        let migration = GarrisonMigration::with_base_dir(pool, base_dir);

        // 第一次：应用迁移（001-006 共 6 个文件）
        let first = migration
            .migrate_core()
            .await
            .expect("第一次 migrate 应成功");
        assert!(
            first >= 4,
            "第一次应至少执行 4 个迁移（001-006），实际: {}",
            first
        );

        // 第二次：应跳过（已应用）
        let second = migration
            .migrate_core()
            .await
            .expect("第二次 migrate 应成功");
        assert_eq!(second, 0, "第二次应跳过已应用的迁移");

        // 验证表仍存在
        let pool = migration.pool();
        let session = pool.get_session("admin").await.unwrap();
        let count = query_count(
            &session,
            "SELECT count(*) AS cnt FROM sqlite_master WHERE type='table' AND name LIKE 'app_%'",
        )
        .await;
        assert_eq!(count, 10, "应有 10 张 app_ 前缀的表");
    }

    /// Scenario: 迁移后 app_user 表可正常 CRUD（端到端验证）。
    /// WHEN migrate_core() → INSERT INTO app_user → SELECT
    /// THEN 数据可正常写入与读取
    #[tokio::test]
    async fn app_user_table_crud_after_migration() {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let base_dir = PathBuf::from(manifest_dir).join("migrations/sqlite");

        let pool = init_dbnexus("sqlite::memory:").await.unwrap();
        let migration = GarrisonMigration::with_base_dir(pool, base_dir);
        migration.migrate_core().await.expect("migrate 应成功");

        let pool = migration.pool();
        let session = pool.get_session("admin").await.unwrap();

        // INSERT
        session
            .execute_raw(
                "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
                 VALUES ('u-001', 'alice', 'argon2$hash', 'active', 0)",
            )
            .await
            .expect("INSERT app_user 应成功");

        // SELECT 验证
        let username = query_one_string(
            &session,
            "SELECT username AS val FROM app_user WHERE id = 'u-001'",
        )
        .await;
        assert_eq!(username, "alice", "应查到 alice");

        let status = query_one_string(
            &session,
            "SELECT status AS val FROM app_user WHERE id = 'u-001'",
        )
        .await;
        assert_eq!(status, "active", "status 应为 active");
    }
}

/// 嵌入式 postgres 迁移测试模块。
///
/// 独立于 `tests` 模块（`#[cfg(all(test, feature = "db-sqlite"))]`），
/// 因为 embedded-migrations 由 `db-postgres` 透传启用，
/// 验证标准 `cargo test --features db-postgres` 不一定启用 `db-sqlite`。
/// 两个模块各自独立门控，避免 feature cfg 冲突（规则 4：不混合两种模式）。
#[cfg(all(test, feature = "embedded-migrations"))]
mod embedded_migrations_tests {
    use super::*;

    // ========================================================================
    // 单元测试（不需数据库，验证 include_dir! 嵌入与文件写入逻辑）
    // ========================================================================

    /// 验证 POSTGRES_MIGRATIONS 嵌入了 7 个 postgres core SQL 文件。
    ///
    /// Scenario: 编译时 include_dir!("migrations/postgres") 嵌入成功。
    /// WHEN POSTGRES_MIGRATIONS.get_dir("core")
    /// THEN core 目录存在且包含 7 个 .sql 文件（001_init ~ 007_refresh_tokens_oauth2_fields）
    #[test]
    fn embedded_postgres_migrations_contain_7_core_files() {
        let core_dir = POSTGRES_MIGRATIONS
            .get_dir("core")
            .expect("migrations/postgres/core 必须被嵌入");
        let sql_files: Vec<_> = core_dir
            .files()
            .filter(|f| f.path().extension().map_or(false, |ext| ext == "sql"))
            .collect();
        assert_eq!(
            sql_files.len(),
            7,
            "postgres core 迁移必须有 7 个 SQL 文件，实际: {sql_files:?}"
        );
        // 验证文件名边界（按版本号约定）
        let names: Vec<String> = sql_files
            .iter()
            .filter_map(|f| {
                f.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(String::from)
            })
            .collect();
        assert!(
            names.iter().any(|n| n.starts_with("001_")),
            "必须包含 001_init.sql，实际: {names:?}"
        );
        assert!(
            names.iter().any(|n| n.starts_with("006_")),
            "必须包含 006_user_devices.sql，实际: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("007_refresh_tokens_oauth2_fields")),
            "必须包含 007_refresh_tokens_oauth2_fields.sql，实际: {names:?}"
        );
    }

    /// 验证 copy_embedded_dir 将嵌入目录正确写入临时目录。
    ///
    /// Scenario: 递归复制 include_dir::Dir 到文件系统。
    /// WHEN copy_embedded_dir(&POSTGRES_MIGRATIONS, tempdir)
    /// THEN tempdir/core/ 包含 7 个 .sql 文件，内容与嵌入文件一致
    #[test]
    fn copy_embedded_dir_writes_files_to_tempdir() {
        let temp_dir = tempfile::tempdir().expect("创建临时目录应成功");
        copy_embedded_dir(&POSTGRES_MIGRATIONS, temp_dir.path()).expect("复制嵌入目录应成功");

        let core_dir = temp_dir.path().join("core");
        assert!(core_dir.exists(), "core 子目录必须被创建");

        let entries: Vec<_> = std::fs::read_dir(&core_dir)
            .expect("读取 core 目录应成功")
            .collect();
        assert_eq!(entries.len(), 7, "core 目录必须包含 7 个 SQL 文件");

        // 验证文件内容非空（写入的是真实 SQL，不是空字节）
        for entry in entries {
            let entry = entry.expect("读取目录项应成功");
            let path = entry.path();
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("读取 {} 应成功: {e}", path.display()));
            assert!(
                !content.trim().is_empty(),
                "文件 {} 内容不应为空",
                path.display()
            );
        }
    }

    /// 验证 copy_embedded_dir 是幂等的——重复写入同一目录不报错且文件数不变。
    ///
    /// Scenario: 多次复制同一嵌入目录到同一目标。
    /// WHEN copy_embedded_dir → copy_embedded_dir（再次）
    /// THEN 第二次成功，core 目录仍为 6 个文件（覆盖写入）
    #[test]
    fn copy_embedded_dir_is_idempotent() {
        let temp_dir = tempfile::tempdir().expect("创建临时目录应成功");
        copy_embedded_dir(&POSTGRES_MIGRATIONS, temp_dir.path()).expect("第一次复制应成功");
        copy_embedded_dir(&POSTGRES_MIGRATIONS, temp_dir.path()).expect("第二次复制应成功");

        let core_dir = temp_dir.path().join("core");
        let count = std::fs::read_dir(&core_dir)
            .expect("读取 core 目录应成功")
            .count();
        assert_eq!(count, 7, "重复写入后仍应为 7 个文件");
    }

    // ========================================================================
    // 集成测试（需要 postgres DATABASE_URL，用 #[ignore] 标记）
    // ========================================================================

    /// Scenario: run_embedded_postgres 在真实 postgres 上执行迁移。
    /// WHEN GarrisonMigration::run_embedded_postgres()
    /// THEN 返回值 > 0（至少一个迁移被应用），且 dbnexus_migrations 表有记录
    #[tokio::test]
    #[ignore = "requires postgres DATABASE_URL (set SINNAN_TEST_DATABASE_URL to run)"]
    async fn run_embedded_postgres_creates_tables() {
        let db_url = std::env::var("DATABASE_URL")
            .or_else(|_| std::env::var("SINNAN_TEST_DATABASE_URL"))
            .expect("DATABASE_URL 或 SINNAN_TEST_DATABASE_URL 必须设置才能运行此测试");
        let pool = init_dbnexus(&db_url)
            .await
            .expect("init_dbnexus 应成功（数据库可达）");
        let migration = GarrisonMigration::new(pool);
        let count = migration
            .run_embedded_postgres()
            .await
            .expect("run_embedded_postgres 应成功");
        assert!(count > 0, "至少应应用一个迁移，实际: {count}");
    }
}
