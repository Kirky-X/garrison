// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Context 模块辅助函数（从 mod.rs 迁移）。
//!
//! # ⚠️ 现状说明
//!
//! 以下 `effective_is_read_header` / `effective_is_read_cookie` 目前**未接入任何适配器
//! 的 token 提取路径**：`context::token_extract` 的 `extract_token_from_headers` /
//! `extract_token_from_request_parts` 直接读取 `config.is_read_header` /
//! `config.is_read_cookie`。这意味着 `frontend_separation=true` 仅在**响应写入侧**
//! （`set_cookie_with_frontend_check`）生效，token 提取行为不受其影响。
//! 本函数作为前后端分离语义的参考实现保留并导出（crate 内测试与潜在调用方使用），
//! 适配器若后续接入，应改用这两个函数作为有效开关。

/// 前后端分离模式下有效的 Header 读取开关。
///
/// `frontend_separation=true` 时强制返回 `true`（必须从 Authorization Header 读取 Token），
/// 忽略 `is_read_header` 配置。
///
/// # ⚠️ 未接入说明
///
/// 当前 `token_extract.rs` 的提取路径直接使用 `config.is_read_header`，
/// 本函数**未在任何适配器运行路径中调用**，仅作语义参考实现保留。
pub fn effective_is_read_header(config: &crate::config::GarrisonConfig) -> bool {
    config.is_read_header || config.frontend_separation
}

/// 前后端分离模式下有效的 Cookie 读取开关。
///
/// `frontend_separation=true` 时强制返回 `false`（不读 Cookie），
/// 忽略 `is_read_cookie` 配置。
///
/// # ⚠️ 未接入说明
///
/// 当前 `token_extract.rs` 的提取路径直接使用 `config.is_read_cookie`，
/// 本函数**未在任何适配器运行路径中调用**，仅作语义参考实现保留。
pub fn effective_is_read_cookie(config: &crate::config::GarrisonConfig) -> bool {
    config.is_read_cookie && !config.frontend_separation
}
