//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 异常模块，定义框架异常类型。
//!
//! 对应 异常体系，
//! 提供细化异常类型与统一错误枚举。

use std::collections::HashMap;

/// 重导出 `crate::error::GarrisonError`，便于从异常模块统一访问。
pub use crate::error::GarrisonError;

/// 未登录异常，表示请求缺少有效登录态。
///
/// 对应 `NotLoginException`。
#[derive(Debug, Clone)]
pub struct NotLoginException {
    /// 异常消息。
    pub message: String,

    /// 关联的登录类型（如 account / wechat 等）。
    pub login_type: String,
}

/// 携带上下文的业务可恢复异常（）。
///
/// 与 `GarrisonError` enum 解耦，提供更丰富的异常上下文（token / login_id / extras）。
/// 业务方可通过 `GarrisonException::new(code, msg).with_token(t).build()` 链式构造，
/// 并通过 `Into<GarrisonError>` 转换为 `GarrisonError::Exception` 上抛。
///
/// 对应 SaTokenException 的"携带上下文"语义。
#[derive(Debug, Clone)]
pub struct GarrisonException {
    /// 业务错误码（如 -1 表示未登录）。
    pub code: i32,

    /// 异常消息。
    pub message: String,

    /// 登录类型（如 1 表示账号登录）。
    pub login_type: i32,

    /// 关联的 token（可能为 `None`）。
    pub token_value: Option<String>,

    /// 关联的登录主体（可能为 `None`）。
    pub login_id: Option<i64>,

    /// 额外键值对上下文。
    pub extras: HashMap<String, String>,
}

mod impls;

#[cfg(test)]
mod tests;
