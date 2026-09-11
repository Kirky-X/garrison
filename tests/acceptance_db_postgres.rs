//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! PostgreSQL 真实服务专用验收 target（ACC-ENV-005..006）。
//!
//! # 为什么独立成 target
//! dbnexus 以 `compile_error!` 禁止 embedded（sqlite）与 server-side
//! （postgres/mysql）驱动共存，而 `full` 聚合含 `db-sqlite`——因此
//! `tests/acceptance/environment.rs` 中 `#[cfg(feature = "db-postgres")]`
//! 门控的 Postgres 真实服务场景在 `--features full` 下被整体剥离，
//! 历史上从未在任何 CI/本地面执行过。本 target 以
//! `--no-default-features --features db-postgres` 单独编译运行，
//! 配合 `docker-compose.e2e.yml`（15432 端口）或本地 Postgres。
//!
//! 运行（scripts/e2e_matrix.sh S3 自动执行）：
//! ```bash
//! cargo test --test acceptance_db_postgres \
//!   --no-default-features --features db-postgres -- --test-threads=1
//! ```
//!
//! 地址覆盖：`GARRISON_TEST_POSTGRES_ADDR` / `GARRISON_TEST_POSTGRES_URL`
//! （默认 `127.0.0.1:5432`，见 environment.rs）。

#[cfg(feature = "db-postgres")]
#[path = "acceptance/environment.rs"]
mod environment;
