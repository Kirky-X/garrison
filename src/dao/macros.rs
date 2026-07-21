//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DAO 层内部宏，消除 session+connection 获取样板。

/// 获取 dbnexus session + connection，封装 map_err 样板。
///
/// # 消除的样板
///
/// 每个 DAO 方法重复以下 7 行：
///
/// ```ignore
/// let session = self.pool.get_session("admin").await.map_err(|e| {
///     GarrisonError::Dao(format!("PREFIX-session::{}", e))
/// })?;
/// let conn = session.connection().map_err(|e| {
///     GarrisonError::Dao(format!("PREFIX-connection::{}", e))
/// })?;
/// ```
///
/// 宏化为 1 行：
///
/// ```ignore
/// dao_session!(self.pool, "PREFIX", session, conn);
/// ```
///
/// 展开后在当前作用域创建 `session` 与 `conn` 两个变量。
/// 变量名由调用方通过 `$session` / `$conn` 参数显式提供，
/// 绕开 `macro_rules!` 的 hygiene 约束（宏内 `let` 默认不暴露给调用方）。
///
/// # 参数
/// - `$pool`: `DbPool` 引用（如 `self.pool`）
/// - `$prefix`: 错误前缀字面量（如 `"dao-app-session-find-by-session-id"`）
/// - `$session`: 调用方作用域中接收 `DbnexusSession` 的 ident
/// - `$conn`: 调用方作用域中接收 `&DatabaseConnection` 的 ident
///
/// # 展开行为
///
/// 宏展开为两条 `let` 语句，使用调用方提供的 ident：
/// - `$session`: `DbnexusSession`（owned，需保持存活因为 `$conn` 借用它）
/// - `$conn`: `&DatabaseConnection`（借用 `$session`）
///
/// 错误消息格式与原样板完全一致：`"{prefix}-session::{e}"` / `"{prefix}-connection::{e}"`。
///
/// # 适用范围
///
/// 仅用于 DAO 层 SQLite Repository（`src/dao/repository/sqlite/*.rs`）的样板消除。
/// 其他层（如 `listener/`、`protocol/`）的 `pool.get_session + session.connection` 调用
/// 错误前缀格式与宏不兼容（前缀已含 `-session` 后缀，或用 `-get-conn` 而非 `-connection`），
/// 不应使用此宏。
///
/// # 命名约定
///
/// `$prefix` 应遵循 `dao-{table}-{operation}` 格式
/// （如 `"dao-app-session-find-by-session-id"`、`"dao-app-user-create"`），
/// 与现有 sqlite repo 调用点保持一致，便于日志中按表名 / 操作定位故障点。
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
