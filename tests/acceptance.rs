// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 验收矩阵入口。
//!
//! 按域组织 `tests/acceptance/*.rs`，每域「正常路径 + 异常路径」成对覆盖，
//! 本 target 需 `full` + `testing` feature
//! （Cargo.toml `required-features`，与 `e2e` target 同一惯例，避免门禁漏跑）。
//!
//! 域模块按 feature 逐个门控；无相关 feature 时对应域不参与构建。

#[cfg(feature = "db-sqlite")]
#[path = "common/mod.rs"]
mod common;

#[path = "acceptance/harness.rs"]
mod harness;

// 真实 Keycloak 夹具（OAuth2/OIDC 协议验收共享；登录表单流自动化 + 探活门控）
#[cfg(feature = "protocol-oauth2")]
#[path = "acceptance/keycloak_fixture.rs"]
mod keycloak_fixture;

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

#[path = "acceptance/bw_ac.rs"]
mod bw_ac;

#[path = "acceptance/migrated/mod.rs"]
mod migrated;
