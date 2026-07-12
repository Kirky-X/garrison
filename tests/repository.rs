//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 仓储层集成测试入口——SQLite / PostgreSQL / dbnexus CRUD 与错误路径验证。

#[path = "repository/dbnexus_integration.rs"]
mod dbnexus_integration;
#[path = "repository/error_paths.rs"]
mod error_paths;
#[path = "repository/integration.rs"]
mod integration;
#[path = "repository/postgres_integration.rs"]
mod postgres_integration;
