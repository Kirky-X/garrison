//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Bulwark 官方示例集库模块。
//!
//! 每个 bin 的核心逻辑提取为 `pub fn run()`（或 `pub async fn run()`），
//! 由 `src/bin/<name>.rs` 作为 thin wrapper 调用，并由 `tests/<name>.rs` 进行测试。
//!
//! # 模块分类（模块化重构后）
//!
//! - **authentication**：登录认证示例（basic/password/jwt/httpbasic/httpdigest/totp）
//! - **oauth2**：OAuth2/OIDC/SSO 示例
//! - **apikey**：API Key 示例
//! - **authorization**：授权/权限/策略示例
//! - **sign**：签名协议示例
//! - **web**：Web 框架集成示例（axum/actix/warp/grpc）
//! - **infrastructure**：基础设施示例（cache/config/dao/i18n/observability）
//! - **extension**：扩展能力示例（plugin/listener/macro/manager/session）
//! - **demo**：综合演示
//!
//! # 运行示例
//!
//! ```sh
//! cargo run -p bulwark-examples --bin <name> --features full
//! ```

pub mod apikey;
pub mod authentication;
pub mod authorization;
pub mod demo;
pub mod extension;
pub mod infrastructure;
pub mod oauth2;
pub mod sign;
pub mod web;
