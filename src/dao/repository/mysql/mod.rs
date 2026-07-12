//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! MySQL Repository 实现。
//!
//! 复用 `sqlite` 模块的 backend-agnostic Repository 实现（通过 [`make_statement`](crate::dao::repository::make_statement)
//! 自动转换 `?` 占位符）。本模块仅提供 mysql 命名空间下的类型别名，
//! 实际逻辑见 `sqlite` 模块——`DbPool` 后端为 MySQL 时，同一份代码自动走 MySQL 方言。
//!
//! ## 10 个 Repository
//!
//! | 类型别名 | 原 SQLite 类型 | trait |
//! |:---|:---|:---|
//! | `DbnexusMysqlUserRepository` | `DbnexusUserRepository` | [`UserRepository`](crate::dao::repository::UserRepository) |
//! | `DbnexusMysqlRoleRepository` | `DbnexusRoleRepository` | [`RoleRepository`](crate::dao::repository::RoleRepository) |
//! | `DbnexusMysqlPermissionRepository` | `DbnexusPermissionRepository` | [`PermissionRepository`](crate::dao::repository::PermissionRepository) |
//! | `DbnexusMysqlUserRoleRepository` | `DbnexusUserRoleRepository` | [`UserRoleRepository`](crate::dao::repository::UserRoleRepository) |
//! | `DbnexusMysqlRolePermissionRepository` | `DbnexusRolePermissionRepository` | [`RolePermissionRepository`](crate::dao::repository::RolePermissionRepository) |
//! | `DbnexusMysqlAuthMethodRepository` | `DbnexusAuthMethodRepository` | [`AuthMethodRepository`](crate::dao::repository::AuthMethodRepository) |
//! | `DbnexusMysqlSessionRepository` | `DbnexusSessionRepository` | [`SessionRepository`](crate::dao::repository::SessionRepository) |
//! | `DbnexusMysqlLoginLogRepository` | `DbnexusLoginLogRepository` | [`LoginLogRepository`](crate::dao::repository::LoginLogRepository) |
//! | `DbnexusMysqlUserExtRepository` | `DbnexusUserExtRepository` | [`UserExtRepository`](crate::dao::repository::UserExtRepository) |
//! | `DbnexusMysqlUserDeviceRepository` | `DbnexusUserDeviceRepository` | [`UserDeviceRepository`](crate::dao::repository::UserDeviceRepository) |
//!
//! ## 使用示例
//!
//! ```ignore
//! use bulwark::dao::init_dbnexus;
//! use bulwark::dao::repository::mysql::DbnexusMysqlUserRepository;
//! use bulwark::dao::repository::{UserRepository, NewUser};
//!
//! # async fn demo() -> bulwark::error::BulwarkResult<()> {
//! let pool = init_dbnexus("mysql://root:root@localhost:3306/bulwark_test").await?;
//! let repo = DbnexusMysqlUserRepository::new(pool);
//! let user_id = repo.create(1, NewUser {
//!     username: "alice".to_string(),
//!     password_hash: "hashed".to_string(),
//!     status: "active".to_string(),
//! }).await?;
//! # Ok(())
//! # }
//! ```
// 复用 sqlite 模块的 backend-agnostic Repository 实现。
// sqlite 模块通过 make_statement(conn, sql, values) 在运行时根据 conn.get_database_backend()
// 自动转换占位符（SQLite ? / MySQL ? / PostgreSQL $1,$2），因此同一份代码三种后端通用。
// 此处仅以 MySQL 命名空间 re-export，避免代码重复（Rule 8：不重复造轮子）。
pub use crate::dao::repository::sqlite::{
    DbnexusAuthMethodRepository as DbnexusMysqlAuthMethodRepository,
    DbnexusLoginLogRepository as DbnexusMysqlLoginLogRepository,
    DbnexusPermissionRepository as DbnexusMysqlPermissionRepository,
    DbnexusRolePermissionRepository as DbnexusMysqlRolePermissionRepository,
    DbnexusRoleRepository as DbnexusMysqlRoleRepository,
    DbnexusSessionRepository as DbnexusMysqlSessionRepository,
    DbnexusUserDeviceRepository as DbnexusMysqlUserDeviceRepository,
    DbnexusUserExtRepository as DbnexusMysqlUserExtRepository,
    DbnexusUserRepository as DbnexusMysqlUserRepository,
    DbnexusUserRoleRepository as DbnexusMysqlUserRoleRepository,
};
