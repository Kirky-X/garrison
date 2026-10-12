// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! MySQL Repository 实现。
//!
//! 复用 `sqlite` 模块的 backend-agnostic Repository 实现（通过 [`make_statement`](crate::dao::repository::make_statement)
//! 自动转换 `?` 占位符）；本模块仅提供 mysql 命名空间下的 10 个 Repository 类型别名，
//! 实际逻辑见 `sqlite` 模块——`DbPool` 后端为 MySQL 时，同一份代码自动走 MySQL 方言。
//!
//! ## 使用示例
//!
//! ```ignore
//! use garrison::dao::init_dbnexus;
//! use garrison::dao::repository::mysql::DbnexusMysqlUserRepository;
//! use garrison::dao::repository::{UserRepository, NewUser};
//!
//! # async fn demo() -> garrison::error::GarrisonResult<()> {
//! let pool = init_dbnexus("mysql://root:root@localhost:3306/garrison_test").await?;
//! let repo = DbnexusMysqlUserRepository::new(pool);
//! let user_id = repo.create(1, NewUser {
//! username: "alice".to_string(),
//! password_hash: "hashed".to_string(),
//! status: "active".to_string(),
//! }).await?;
//! # Ok(())
//! # }
//! ```
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
