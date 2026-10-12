// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Garrison 官方示例集库模块。
//!
//! 每个 bin 的核心逻辑提取为 `pub fn run()`（或 `pub async fn run()`），
//! 由 `src/bin/<name>.rs` 作为 thin wrapper 调用，并由 `tests/<name>.rs` 进行测试。
//!
//! # 模块分类
//!
//! authentication（登录认证）、oauth2（OAuth2/OIDC/SSO）、apikey、authorization（授权/策略）、sign（签名协议）、web（Web 框架集成）、infrastructure（基础设施）、extension（扩展能力）、demo（综合演示）。
//!
//! # 运行示例
//!
//! ```sh
//! cargo run -p garrison-examples --bin <name> --features full
//! ```

pub mod apikey;
pub mod authentication;
pub mod authorization;
pub mod demo;
pub mod extension;
pub mod infrastructure;
pub mod oauth2;
pub mod security;
pub mod sign;
pub mod web;
