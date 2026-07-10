//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 集成测试共享辅助函数。
//!
//! 各测试文件通过 `mod common;` 引入，避免跨文件重复。
//! 允许 dead_code：不同测试二进制可能只使用部分函数。

#![allow(dead_code)]

use bulwark::dao::{init_dbnexus, BulwarkMigration};
use dbnexus::DbPool;
use std::path::PathBuf;

/// 返回项目 migrations/sqlite 目录的绝对路径。
pub fn project_migrations_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("migrations")
        .join("sqlite")
}

/// 初始化 SQLite in-memory 数据库并执行 core 迁移。
pub async fn setup_db() -> DbPool {
    let pool = init_dbnexus("sqlite::memory:")
        .await
        .expect("init_dbnexus 应成功");
    let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
    pool
}

/// 计算 SHA-256 十六进制摘要。
#[cfg(any(feature = "keycloak-oidc", feature = "protocol-jwt"))]
pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}
