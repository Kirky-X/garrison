// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 状态机模块，定义 [`TokenState`] 与 [`UserStatus`] 显式状态机；转换路径以本模块定义为准，不混合其他文档。
//!
//! 以下集成项已定义、尚未接入运行路径（接线计划见 `docs/ROADMAP.md`）：与 Session / User 模块集成、状态机事件触发、状态持久化到 dbnexus。

use crate::error::{GarrisonError, GarrisonResult};

// TokenState

/// Token 生命周期状态（5 个）：Issued → Active（可续期），Active → Expired（TTL 到达）/ Revoked（logout / kickout）/ Refreshed（refresh_token），Refreshed → Revoked（旧 Token 立即作废）；Expired 与 Revoked 为终态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenState {
    /// 已签发，客户端尚未首次使用。
    Issued,
    /// 活跃中，每次访问续期 30min TTL。
    Active,
    /// 已过期（TTL 到达 / exp 字段过期）。终态。
    Expired,
    /// 已撤销（logout / kickout / 账号封禁）。终态。
    Revoked,
    /// 已刷新（refresh_token 调用后旧 Token 状态）。
    Refreshed,
}

// UserStatus

/// 用户账号状态（5 个）：Pending → Active / Suspended；Active → Suspended / Inactive / Deleted；Suspended 与 Inactive → Active / Deleted；Deleted 为终态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserStatus {
    /// 待激活（注册 / 第三方首次登录）。
    Pending,
    /// 活跃。
    Active,
    /// 已封禁。
    Suspended,
    /// 长期未登录休眠。
    Inactive,
    /// 已删除。终态。
    Deleted,
}

mod impls;

#[cfg(test)]
mod tests;
