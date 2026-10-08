// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! SQL 方言适配（backend-agnostic 辅助函数，自 `repository/mod.rs` 迁出）。
//!
//! mod 接口隔离收口：实现函数不写在 `mod.rs`，此处承载占位符方言转换
//! （SQLite `?` / PostgreSQL `$1,$2`）与 backend-agnostic Statement 构造；
//! 公共路径经 `repository::{convert_placeholders, make_statement}` re-export 保持不变。

/// 转换 SQL 占位符为指定后端的方言。
///
/// - `DbBackend::Sqlite`：保留 `?` 占位符
/// - `DbBackend::Postgres`：将第 n 个 `?` 替换为 `$n`
/// - 其他后端：保留 `?`（由调用方确保兼容性）
///
/// # 跳过的上下文
///
/// 以下上下文中的 `?` 不被替换（避免参数序号错位）：
/// - 单引号字符串字面量（含 `''` 转义）
/// - `--` 行注释（至行尾）
/// - `/* */` 块注释（支持嵌套，与 PostgreSQL 语义一致）
///
/// # 示例
///
/// ```
/// use dbnexus::sea_orm::DbBackend;
/// use garrison::dao::repository::convert_placeholders;
///
/// let sql = "WHERE id = ? AND name = ?";
/// assert_eq!(convert_placeholders(sql, DbBackend::Sqlite), "WHERE id = ? AND name = ?");
/// assert_eq!(convert_placeholders(sql, DbBackend::Postgres), "WHERE id = $1 AND name = $2");
/// ```
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub fn convert_placeholders(sql: &str, backend: dbnexus::sea_orm::DbBackend) -> String {
    use dbnexus::sea_orm::DbBackend;
    use std::fmt::Write as _;
    if backend != DbBackend::Postgres {
        return sql.to_string();
    }
    let mut result = String::with_capacity(sql.len() + 16);
    let mut n = 0u32;
    // 主循环只识别三种词法上下文起点（行注释 `--`、块注释 `/*`、字符串 `'`），
    // 上下文整体交给对应 helper 原样复制；`?` 在 helper 内天然不被替换，
    // 参数序号不会错位。
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '-' if chars.peek() == Some(&'-') => {
                result.push_str("--");
                chars.next();
                copy_until_line_end(&mut chars, &mut result);
            },
            '/' if chars.peek() == Some(&'*') => {
                result.push_str("/*");
                chars.next();
                copy_block_comment(&mut chars, &mut result);
            },
            '\'' => {
                result.push('\'');
                copy_string_literal(&mut chars, &mut result);
            },
            '?' => {
                n += 1;
                // write! 直写避免 to_string() 的临时小字符串分配（热路径：每占位符一次）
                let _ = write!(result, "${n}");
            },
            c => result.push(c),
        }
    }
    result
}

/// 行注释剩余部分原样复制至行尾（含换行符；无换行则复制至串尾）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
fn copy_until_line_end(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, out: &mut String) {
    for c in chars.by_ref() {
        out.push(c);
        if c == '\n' {
            return;
        }
    }
}

/// 块注释剩余部分原样复制；支持嵌套（PostgreSQL 语义），
/// 与首个未配对的 `*/` 一同结束。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
fn copy_block_comment(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, out: &mut String) {
    let mut depth = 1usize;
    while let Some(c) = chars.next() {
        if c == '/' && chars.peek() == Some(&'*') {
            out.push_str("/*");
            chars.next();
            depth += 1;
        } else if c == '*' && chars.peek() == Some(&'/') {
            out.push_str("*/");
            chars.next();
            depth -= 1;
            if depth == 0 {
                return;
            }
        } else {
            out.push(c);
        }
    }
}

/// 字符串字面量剩余部分原样复制至结束引号；
/// `''` 为 SQL 标准的字面转义（一个 `'`），复制两个引号并留在字面量内。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
fn copy_string_literal(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, out: &mut String) {
    while let Some(c) = chars.next() {
        out.push(c);
        if c == '\'' {
            if chars.peek() == Some(&'\'') {
                out.push('\'');
                chars.next();
            } else {
                return;
            }
        }
    }
}

/// 构造 backend-agnostic 的 [`dbnexus::sea_orm::Statement`]，根据 conn 的 backend 自动转换占位符。
///
/// 封装 [`convert_placeholders`] + [`dbnexus::sea_orm::Statement::from_sql_and_values`]，
/// 让 Repository 实现无需关心后端差异——传入 `?` 占位符的 SQL 即可，
/// Postgres backend 会自动转换为 `$1`, `$2`, ...
///
/// # 示例
///
/// ```ignore
/// use garrison::dao::repository::make_statement;
/// use dbnexus::sea_orm::Value;
///
/// // 实际使用时传入真实的 DatabaseConnection（Sqlite 或 Postgres 后端）
/// let stmt = make_statement(&conn, "WHERE id = ?", vec![Value::Int(Some(1))]);
/// ```
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub fn make_statement(
    conn: &impl dbnexus::sea_orm::ConnectionTrait,
    sql: &str,
    values: Vec<dbnexus::sea_orm::Value>,
) -> dbnexus::sea_orm::Statement {
    let backend = conn.get_database_backend();
    let sql = convert_placeholders(sql, backend);
    dbnexus::sea_orm::Statement::from_sql_and_values(backend, sql, values)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // convert_placeholders 测试（依据 P3 重构决策）
    // ========================================================================

    /// SQLite 后端保留 `?` 占位符不变。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_sqlite_keeps_question_mark() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "WHERE id = ? AND name = ?";
        let result = convert_placeholders(sql, DbBackend::Sqlite);
        assert_eq!(result, "WHERE id = ? AND name = ?");
    }

    /// PostgreSQL 后端将 `?` 替换为 `$1`, `$2`, ...
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_postgres_replaces_with_dollar_n() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "WHERE id = ? AND name = ?";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(result, "WHERE id = $1 AND name = $2");
    }

    /// 单个占位符也能正确转换。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_postgres_single_placeholder() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "WHERE id = ?";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(result, "WHERE id = $1");
    }

    /// 无占位符的 SQL 不受影响。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_no_placeholder_unchanged() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT 1";
        assert_eq!(convert_placeholders(sql, DbBackend::Postgres), "SELECT 1");
        assert_eq!(convert_placeholders(sql, DbBackend::Sqlite), "SELECT 1");
    }

    /// 多个占位符（5 个）能正确编号。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_postgres_five_placeholders() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "VALUES (?, ?, ?, ?, ?)";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(result, "VALUES ($1, $2, $3, $4, $5)");
    }

    /// Postgres 后端跳过单引号字符串字面量内的 `?`，引号外仍替换为 `$n`。
    ///
    /// 场景：SQL 注释/字面量中的 `?`（如 `note = '?'`）不应被当作占位符替换，
    /// 否则参数序号错位导致后续 `$n` 与绑定参数不匹配。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_skips_question_mark_inside_string_literal() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT * FROM t WHERE note = '?' AND id = ?";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT * FROM t WHERE note = '?' AND id = $1",
            "引号内 ? 不应替换，引号外 ? 应替换为 $1"
        );
    }

    /// Postgres 后端处理连续 `''` 转义单引号后仍正确替换占位符。
    ///
    /// 场景：SQL 字面量 `''` 表示一个字面单引号字符（不结束字符串），
    /// 因此 `'' AS empty` 之后 `?` 仍在字符串外，应被替换为 `$1`。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_handles_escaped_single_quote() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT '' AS empty, ? AS v";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT '' AS empty, $1 AS v",
            "连续 '' 转义单引号后 ? 仍应替换为 $1"
        );
    }

    /// 覆盖 SQL 字符串字面量内的 `''` 转义分支。
    ///
    /// 场景：SQL 标准中字符串字面量内的 `''` 表示一个字面单引号字符
    /// （不结束字符串），如 `'a''b'` 表示字符串 `a'b`。状态机应保持
    /// `in_string=true`，使转义后的 `?` 在字符串外被替换为 `$1`。
    /// 仅覆盖独立 `''`（空字符串字面量），未触发字符串内转义分支。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_handles_escaped_quote_inside_string_literal() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT 'a''b' AS s, ? AS v";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT 'a''b' AS s, $1 AS v",
            "字符串字面量内 '' 转义分支：状态机应保持 in_string=true，转义后 ? 应替换为 $1"
        );
    }

    /// `--` 行注释内的 `?` 不被替换，注释后的 `?` 正常编号。
    ///
    /// 场景：`SELECT ? -- comment with ?` 若注释内 `?` 被替换，
    /// 会导致参数序号错位（绑定值与占位符不匹配）。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_skips_question_mark_in_line_comment() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT ? -- comment with ? here\nWHERE id = ?";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT $1 -- comment with ? here\nWHERE id = $2",
            "行注释内 ? 不应替换，注释结束后 ? 应继续编号为 $2"
        );
    }

    /// `/* */` 块注释内的 `?` 不被替换。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_skips_question_mark_in_block_comment() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT ?, /* hint: ? not a placeholder */ ? AS b";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT $1, /* hint: ? not a placeholder */ $2 AS b",
            "块注释内 ? 不应替换，注释外 ? 正常编号"
        );
    }

    /// 嵌套块注释（PostgreSQL 语义）内层的 `?` 也不替换。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_handles_nested_block_comments() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT ? /* outer /* inner ? */ still comment ? */ , ? AS b";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT $1 /* outer /* inner ? */ still comment ? */ , $2 AS b",
            "嵌套块注释内的 ? 均不应替换，第一个未匹配 */ 结束内层、第二个结束外层"
        );
    }

    /// 字符串字面量内的 `--` / `/*` 不应被误判为注释开始。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_comment_markers_inside_string_are_literal() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT '-- not a comment /* neither */ ?' AS s, ? AS v";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT '-- not a comment /* neither */ ?' AS s, $1 AS v",
            "字符串字面量内的注释标记应按字面量处理，其中 ? 不替换也不计数"
        );
    }

    // ========================================================================
    // make_statement 测试（依据 P3 重构决策）
    // ========================================================================

    /// Mock 连接，仅用于测试 `make_statement` 的 backend 检测逻辑。
    /// 其他方法未实现（`make_statement` 仅调用 `get_database_backend`）。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    struct MockConn {
        backend: dbnexus::sea_orm::DbBackend,
    }

    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[async_trait::async_trait]
    impl dbnexus::sea_orm::ConnectionTrait for MockConn {
        fn get_database_backend(&self) -> dbnexus::sea_orm::DbBackend {
            self.backend
        }

        async fn execute_raw(
            &self,
            _stmt: dbnexus::sea_orm::Statement,
        ) -> Result<dbnexus::sea_orm::ExecResult, dbnexus::sea_orm::DbErr> {
            Err(dbnexus::sea_orm::DbErr::Custom(
                "MockConn only supports get_database_backend".into(),
            ))
        }

        async fn execute_unprepared(
            &self,
            _sql: &str,
        ) -> Result<dbnexus::sea_orm::ExecResult, dbnexus::sea_orm::DbErr> {
            Err(dbnexus::sea_orm::DbErr::Custom(
                "MockConn only supports get_database_backend".into(),
            ))
        }

        async fn query_one_raw(
            &self,
            _stmt: dbnexus::sea_orm::Statement,
        ) -> Result<Option<dbnexus::sea_orm::QueryResult>, dbnexus::sea_orm::DbErr> {
            Err(dbnexus::sea_orm::DbErr::Custom(
                "MockConn only supports get_database_backend".into(),
            ))
        }

        async fn query_all_raw(
            &self,
            _stmt: dbnexus::sea_orm::Statement,
        ) -> Result<Vec<dbnexus::sea_orm::QueryResult>, dbnexus::sea_orm::DbErr> {
            Err(dbnexus::sea_orm::DbErr::Custom(
                "MockConn only supports get_database_backend".into(),
            ))
        }
    }

    /// SQLite backend：`make_statement` 保留 `?` 占位符。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn make_statement_sqlite_uses_question_mark() {
        let conn = MockConn {
            backend: dbnexus::sea_orm::DbBackend::Sqlite,
        };
        let stmt = make_statement(
            &conn,
            "WHERE id = ? AND name = ?",
            vec![
                dbnexus::sea_orm::Value::Int(Some(1)),
                dbnexus::sea_orm::Value::String(Some("alice".into())),
            ],
        );
        assert_eq!(stmt.sql, "WHERE id = ? AND name = ?");
    }

    /// Postgres backend：`make_statement` 将 `?` 替换为 `$1`, `$2`。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn make_statement_postgres_uses_dollar_n() {
        let conn = MockConn {
            backend: dbnexus::sea_orm::DbBackend::Postgres,
        };
        let stmt = make_statement(
            &conn,
            "WHERE id = ? AND name = ?",
            vec![
                dbnexus::sea_orm::Value::Int(Some(1)),
                dbnexus::sea_orm::Value::String(Some("alice".into())),
            ],
        );
        assert_eq!(stmt.sql, "WHERE id = $1 AND name = $2");
    }
}
