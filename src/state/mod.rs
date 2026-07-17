//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 状态机模块，定义 Token 与 User 的显式状态机。
//! 以 FRD §4.2 / §4.3 为权威来源。
//!
//! ## 设计
//!
//! - [`TokenState`]：Token 生命周期状态（5 个状态 + 6 条合法转换路径）
//! - [`UserStatus`]：用户账号状态（5 个状态 + 9 条合法转换路径）
//!
//! 状态转换路径严格遵循 FRD，不混合 ADD 文档的路径（规则7 冲突以 FRD 为准）。
//!
//! ## 不在范围内
//!
//! - 与现有 Session / User 模块的集成（推迟到 v0.7.0）
//! - 状态机事件触发（推迟到 v0.7.0）
//! - 状态持久化到 dbnexus（推迟到 v0.7.0）

use crate::error::{BulwarkError, BulwarkResult};

// ============================================================================
// TokenState（FRD §4.3）
// ============================================================================

/// Token 生命周期状态（5 个状态）。
///
/// 依据 FRD §4.3，状态转换路径如下：
///
/// ```text
/// Issued → Active → Active（续期）
///                → Expired（TTL 到达）
///                → Revoked（logout / kickout）
///                → Refreshed（refresh_token）
/// Refreshed → Revoked（旧 Token 立即作废）
/// ```
///
/// `Expired` 与 `Revoked` 为终态，不可转换。
/// `Refreshed` 仅可转换到 `Revoked`（旧 Token 立即作废）。
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

// ============================================================================
// UserStatus（FRD §4.1 / §4.2）
// ============================================================================

/// 用户账号状态（5 个状态）。
///
/// 依据 FRD §4.2 状态转换规则表，转换路径如下：
///
/// ```text
/// Pending → Active / Suspended
/// Active → Suspended / Inactive / Deleted
/// Suspended → Active / Deleted
/// Inactive → Active / Deleted
/// Deleted（终态）
/// ```
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
