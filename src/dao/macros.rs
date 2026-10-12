// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! DAO 层内部宏，消除 session+connection 获取样板。

/// 获取 dbnexus session + connection，封装 map_err 样板。
///
/// 把每个 DAO 方法重复的 `get_session` + `connection` + `map_err` 样板：
///
/// ```ignore
/// let session = self.pool.get_session("admin").await.map_err(|e| {
/// GarrisonError::Dao(format!("PREFIX-session::{}", e))
/// })?;
/// let conn = session.connection().map_err(|e| {
/// GarrisonError::Dao(format!("PREFIX-connection::{}", e))
/// })?;
/// ```
///
/// 宏化为 1 行：
///
/// ```ignore
/// dao_session!(self.pool, "PREFIX", session, conn);
/// ```
///
/// 展开后在当前作用域创建 `session`（owned）与 `conn`（借用 `session`）两个变量；
/// 变量名由调用方通过 `$session` / `$conn` 参数显式提供，绕开 `macro_rules!` 的 hygiene 约束（宏内 `let` 默认不暴露给调用方）。
///
/// `$prefix` 遵循 `dao-{table}-{operation}` 格式，错误消息为 `"{prefix}-session::{e}"` / `"{prefix}-connection::{e}"`。
/// 仅用于 DAO 层 SQLite Repository（`src/dao/repository/sqlite/*.rs`）；其他层前缀格式与宏不兼容，不应使用。
macro_rules! dao_session {
    ($pool:expr, $prefix:literal, $session:ident, $conn:ident) => {
        let $session = $pool.get_session("admin").await.map_err(|e| {
            $crate::error::GarrisonError::Dao(format!("{}-session::{}", $prefix, e))
        })?;
        let $conn = $session.connection().map_err(|e| {
            $crate::error::GarrisonError::Dao(format!("{}-connection::{}", $prefix, e))
        })?;
    };
}

pub(crate) use dao_session;
