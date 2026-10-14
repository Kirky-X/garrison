// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 异常模块，提供细化异常类型与统一错误枚举。

use std::collections::HashMap;

pub use crate::error::GarrisonError;

/// 未登录异常，表示请求缺少有效登录态。
#[derive(Debug, Clone)]
pub struct NotLoginException {
    /// 异常消息。
    pub message: String,

    /// 关联的登录类型（如 account / wechat 等）。
    pub login_type: String,
}

/// 携带上下文的业务可恢复异常。
///
/// 与 `GarrisonError` enum 解耦，提供 token / login_id / extras 上下文；经 `new(code, msg).with_*(..).build()` 链式构造，`Into<GarrisonError>` 转为 `GarrisonError::Exception` 上抛。
///
/// # ⚠️ 安全说明
///
/// 手动 `Debug` 实现：`token_value` 脱敏为前 8 字符 + `***`，防 `{:?}` 泄露到日志；字段保持 `pub`（pre-1.0 兼容），但后改字段仍走脱敏（`mask_preview`），`extras` 在日志与 HTTP 响应体均经 `sanitize_extras` 过滤；需不可变保证场景用链式构造且不暴露 `&mut`。
#[derive(Clone)]
pub struct GarrisonException {
    /// 业务错误码（如 -1 表示未登录）。
    pub code: i32,

    /// 异常消息。
    pub message: String,

    /// 登录类型（如 1 表示账号登录）。
    pub login_type: i32,

    /// 关联的 token（可能为 `None`）。
    pub token_value: Option<String>,

    /// 关联的登录主体（与全局 login_id 一致为 `String`，可能为 `None`）。
    pub login_id: Option<String>,

    /// 额外键值对上下文。
    pub extras: HashMap<String, String>,
}

mod impls;

#[cfg(test)]
mod tests;
