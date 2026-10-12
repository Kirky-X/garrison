// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL Repository 实现。
//!
//! 复用 `sqlite` 模块的 backend-agnostic Repository 实现（通过 [`make_statement`](crate::dao::repository::make_statement)
//! 自动转换 `?` → `$1, $2` 占位符）；本模块仅提供 postgres 命名空间下的 10 个 Repository 类型别名，
//! 实际逻辑见 `sqlite` 模块——`DbPool` 后端为 PostgreSQL 时，同一份代码自动走 PG 方言；
//! schema 类型映射 SQLite→Postgres（`INTEGER`→`BIGINT`、`AUTOINCREMENT`→`BIGSERIAL`、`TEXT`→`TEXT` 保持以兼容 `try_get::<String>`）。
//!
//! ## 使用示例
//!
//! ```ignore
//! use garrison::dao::init_dbnexus;
//! use garrison::dao::repository::postgres::DbnexusPostgresUserRepository;
//! use garrison::dao::repository::{UserRepository, NewUser};
//!
//! # async fn demo() -> garrison::error::GarrisonResult<()> {
//! let pool = init_dbnexus("postgres://garrison:garrison@localhost:5432/garrison_test").await?;
//! let repo = DbnexusPostgresUserRepository::new(pool);
//! let user_id = repo.create(1, NewUser {
//! username: "alice".to_string(),
//! password_hash: "hashed".to_string(),
//! status: "active".to_string(),
//! }).await?;
//! # Ok(())
//! # }
//! ```
pub use crate::dao::repository::sqlite::{
    DbnexusAuthMethodRepository as DbnexusPostgresAuthMethodRepository,
    DbnexusLoginLogRepository as DbnexusPostgresLoginLogRepository,
    DbnexusPermissionRepository as DbnexusPostgresPermissionRepository,
    DbnexusRolePermissionRepository as DbnexusPostgresRolePermissionRepository,
    DbnexusRoleRepository as DbnexusPostgresRoleRepository,
    DbnexusSessionRepository as DbnexusPostgresSessionRepository,
    DbnexusUserDeviceRepository as DbnexusPostgresUserDeviceRepository,
    DbnexusUserExtRepository as DbnexusPostgresUserExtRepository,
    DbnexusUserRepository as DbnexusPostgresUserRepository,
    DbnexusUserRoleRepository as DbnexusPostgresUserRoleRepository,
};
