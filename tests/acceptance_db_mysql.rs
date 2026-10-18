// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! MySQL 真实服务专用验收 target（testcontainers）。
//!
//! # 为什么独立成 target
//! `full` 聚合含 `db-sqlite`（embedded），dbnexus 禁止与 server-side 驱动共存——
//! environment.rs 中 `#[cfg(feature = "db-mysql")]` 门控的 MySQL 场景在 full 面下不可达。
//! 本 target 以 `--no-default-features --features db-mysql` 单独编译运行；docker 不可达
//! 时场景按约定 `[SKIP]`（fail-open 于探活、fail-closed 于断言）。
//!
//! 运行（scripts/e2e_matrix.sh S3 自动执行）：
//! ```bash
//! cargo test --test acceptance_db_mysql \
//! --no-default-features --features db-mysql,testing -- --test-threads=1
//! ```

#[cfg(feature = "db-mysql")]
#[path = "acceptance/environment.rs"]
mod environment;
