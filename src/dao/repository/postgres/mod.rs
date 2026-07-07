//! PostgreSQL Repository 实现（v0.5.1 新增，依据 tasks.md T111-T114 / D8）。
//!
//! 复用 `sqlite` 模块的 backend-agnostic Repository 实现（通过 [`make_statement`](crate::dao::repository::make_statement)
//! 自动转换 `?` → `$1, $2` 占位符）。本模块仅提供 postgres 命名空间下的类型别名，
//! 实际逻辑见 `sqlite` 模块——`DbPool` 后端为 PostgreSQL 时，同一份代码自动走 PG 方言。
//!
//! ## 设计偏离说明（Rule 7 暴露冲突）
//!
//! - **design.md L376-377 + L431-432**：PostgreSQL 后端 D8 明确"延后到 v0.5.2+ 评估"，
//!   **无完整 PostgresRepository 设计**。
//! - **tasks.md T111-T114**：要求"探测 dbnexus postgres feature 可用则本版本（v0.5.1）实施"。
//! - **冲突**：design.md 说延后，tasks.md 说本版本实施。
//! - **决策**：用户在本会话中明确决策"本版本实施"。本实现参考 SqliteRepository 模式，
//!   schema 类型映射 SQLite→Postgres（`INTEGER`→`BIGINT`, `AUTOINCREMENT`→`BIGSERIAL`,
//!   `TEXT`→`TEXT` 保持以兼容 `try_get::<String>`）。Repository 代码零重复复用 sqlite 模块
//!   （该模块通过 `make_statement` 已是 backend-agnostic）。
//!
//! ## 6 个 Repository
//!
//! | 类型别名 | 原 SQLite 类型 | trait |
//! |:---|:---|:---|
//! | `DbnexusPostgresUserRepository` | `DbnexusUserRepository` | [`UserRepository`](crate::dao::repository::UserRepository) |
//! | `DbnexusPostgresRoleRepository` | `DbnexusRoleRepository` | [`RoleRepository`](crate::dao::repository::RoleRepository) |
//! | `DbnexusPostgresPermissionRepository` | `DbnexusPermissionRepository` | [`PermissionRepository`](crate::dao::repository::PermissionRepository) |
//! | `DbnexusPostgresUserRoleRepository` | `DbnexusUserRoleRepository` | [`UserRoleRepository`](crate::dao::repository::UserRoleRepository) |
//! | `DbnexusPostgresRolePermissionRepository` | `DbnexusRolePermissionRepository` | [`RolePermissionRepository`](crate::dao::repository::RolePermissionRepository) |
//! | `DbnexusPostgresUserDeviceRepository` | `DbnexusUserDeviceRepository` | [`UserDeviceRepository`](crate::dao::repository::UserDeviceRepository) |
//!
//! ## 使用示例
//!
//! ```ignore
//! use bulwark::dao::init_dbnexus;
//! use bulwark::dao::repository::postgres::DbnexusPostgresUserRepository;
//! use bulwark::dao::repository::{UserRepository, NewUser};
//!
//! # async fn demo() -> bulwark::error::BulwarkResult<()> {
//! let pool = init_dbnexus("postgres://bulwark:bulwark@localhost:5432/bulwark_test").await?;
//! let repo = DbnexusPostgresUserRepository::new(pool);
//! let user_id = uuid::Uuid::new_v4().to_string();
//! repo.create(1, NewUser {
//!     id: user_id.clone(),
//!     username: "alice".to_string(),
//!     password_hash: "hashed".to_string(),
//!     status: "active".to_string(),
//! }).await?;
//! # Ok(())
//! # }
//! ```

// 复用 sqlite 模块的 backend-agnostic Repository 实现。
// sqlite 模块通过 make_statement(conn, sql, values) 在运行时根据 conn.get_database_backend()
// 自动转换占位符（SQLite ? / PostgreSQL $1,$2），因此同一份代码两种后端通用。
// 此处仅以 Postgres 命名空间 re-export，避免代码重复（Rule 8：不重复造轮子）。
pub use crate::dao::repository::sqlite::{
    DbnexusPermissionRepository as DbnexusPostgresPermissionRepository,
    DbnexusRolePermissionRepository as DbnexusPostgresRolePermissionRepository,
    DbnexusRoleRepository as DbnexusPostgresRoleRepository,
    DbnexusUserDeviceRepository as DbnexusPostgresUserDeviceRepository,
    DbnexusUserRepository as DbnexusPostgresUserRepository,
    DbnexusUserRoleRepository as DbnexusPostgresUserRoleRepository,
};
