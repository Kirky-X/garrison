//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 验收矩阵入口（specmark change `acceptance-overhaul` / spec `acceptance-matrix`）。
//!
//! 按域组织 `tests/acceptance/*.rs`，每域「正常路径 + 异常路径」成对覆盖，
//! 场景编号 `ACC-<域>-NNN` 可追溯。本 target 需 `full` + `testing` feature
//! （Cargo.toml `required-features`，与 `e2e` target 同一惯例，避免门禁漏跑）。
//!
//! 域模块按 feature 逐个门控；无相关 feature 时对应域不参与构建。

#[cfg(feature = "db-sqlite")]
#[path = "common/mod.rs"]
mod common;

#[path = "acceptance/harness.rs"]
mod harness;

#[path = "acceptance/web_smoke.rs"]
mod web_smoke;

#[path = "acceptance/storage.rs"]
mod storage;

#[path = "acceptance/authentication.rs"]
mod authentication;

#[path = "acceptance/session.rs"]
mod session;

#[path = "acceptance/rbac.rs"]
mod rbac;

#[path = "acceptance/protocol_jwt.rs"]
mod protocol_jwt;

#[path = "acceptance/protocol_oauth2.rs"]
mod protocol_oauth2;

#[path = "acceptance/protocol_mixed.rs"]
mod protocol_mixed;

#[path = "acceptance/security.rs"]
mod security;

#[path = "acceptance/web_axum.rs"]
mod web_axum;

#[path = "acceptance/web_actix.rs"]
mod web_actix;

#[path = "acceptance/web_warp.rs"]
mod web_warp;

#[path = "acceptance/resilience.rs"]
mod resilience;

#[path = "acceptance/concurrency.rs"]
mod concurrency;

#[path = "acceptance/server.rs"]
mod server;

#[path = "acceptance/repository.rs"]
mod repository;

#[path = "acceptance/environment.rs"]
mod environment;
