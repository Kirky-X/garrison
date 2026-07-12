//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 会话搜索模块。
//!
//! 启用 `session-search` feature 后编译。提供按关键字搜索 Token-Session / Account-Session，
//! 支持分页与排序（创建时间 / 最后活跃时间）。
//!
//! ## 搜索方法
//!
//! - [`search_token_value`]: 按 token 值搜索 Token-Session（排除匿名 Session）。
//! - [`search_session_id`]: 按 login_id 搜索 Account-Session。
//! - [`search_token_session_id`]: 按 TokenSession.login_id 搜索 token（排除匿名 Session）。

use super::{AccountSession, BulwarkSession, TokenSession};
use crate::error::{BulwarkError, BulwarkResult};
use serde::{Deserialize, Serialize};

/// 搜索排序类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchSortType {
    /// 按创建时间升序。
    CreatedAsc,
    /// 按创建时间降序。
    CreatedDesc,
    /// 按最后活跃时间升序。
    LastActiveAsc,
    /// 按最后活跃时间降序。
    LastActiveDesc,
}

/// Token-Session key 前缀。
const TOKEN_SESSION_PREFIX: &str = "token:session:";

/// 匿名 Session key 前缀（搜索时需排除）。
const ANON_SESSION_PREFIX: &str = "token:session:anon:";

/// Account-Session key 前缀。
const ACCOUNT_SESSION_PREFIX: &str = "account:session:";

/// 按 sort_type 排序 `(id, created_at, last_active_at)` 元组列表。
///
/// 升序使用 `sort_by_key`，降序使用 `sort_by_key` + `Reverse`。
fn sort_entries(entries: &mut [(String, i64, i64)], sort_type: SearchSortType) {
    use std::cmp::Reverse;
    match sort_type {
        SearchSortType::CreatedAsc => entries.sort_by_key(|a| a.1),
        SearchSortType::CreatedDesc => entries.sort_by_key(|a| Reverse(a.1)),
        SearchSortType::LastActiveAsc => entries.sort_by_key(|a| a.2),
        SearchSortType::LastActiveDesc => entries.sort_by_key(|a| Reverse(a.2)),
    }
}

/// 按 token 值搜索 Token-Session。
///
/// 搜索 token 值包含 `keyword` 的登录 Session（排除匿名 Session）。空 `keyword` 匹配所有。
///
/// # 参数
/// - `session`: BulwarkSession 引用。
/// - `keyword`: 搜索关键字（空字符串匹配所有）。
/// - `start`: 分页偏移量（0-based，超出范围返回空 Vec）。
/// - `size`: 返回数量上限（0 返回空 Vec）。
/// - `sort_type`: 排序方式。
///
/// # 返回
/// 匹配的 token 值列表。
///
/// # 错误
/// - 反序列化 TokenSession 失败：`BulwarkError::Session`。
/// - DAO 操作失败：透传 `BulwarkError`。
pub async fn search_token_value(
    session: &BulwarkSession,
    keyword: &str,
    start: usize,
    size: usize,
    sort_type: SearchSortType,
) -> BulwarkResult<Vec<String>> {
    let keys = session
        .dao
        .keys(&format!("{}*", TOKEN_SESSION_PREFIX))
        .await?;

    let mut entries: Vec<(String, i64, i64)> = Vec::new();
    for key in keys {
        // 排除匿名 Session
        if key.starts_with(ANON_SESSION_PREFIX) {
            continue;
        }
        let token = match key.strip_prefix(TOKEN_SESSION_PREFIX) {
            Some(t) => t,
            None => continue,
        };
        // keyword 过滤（空 keyword 匹配所有）
        if !keyword.is_empty() && !token.contains(keyword) {
            continue;
        }
        // 读取 TokenSession 获取排序时间戳
        let json = match session.dao.get(&key).await? {
            Some(j) => j,
            None => continue,
        };
        let ts: TokenSession = serde_json::from_str(&json)
            .map_err(|e| BulwarkError::Session(format!("反序列化 TokenSession 失败: {}", e)))?;
        entries.push((token.to_string(), ts.created_at, ts.last_active_at));
    }

    sort_entries(&mut entries, sort_type);

    Ok(entries
        .into_iter()
        .skip(start)
        .take(size)
        .map(|(id, _, _)| id)
        .collect())
}

/// 按 login_id 搜索 Account-Session。
///
/// 搜索 login_id 包含 `keyword` 的 Account-Session。空 `keyword` 匹配所有。
///
/// # 参数
/// - `session`: BulwarkSession 引用。
/// - `keyword`: 搜索关键字（空字符串匹配所有）。
/// - `start`: 分页偏移量（0-based，超出范围返回空 Vec）。
/// - `size`: 返回数量上限（0 返回空 Vec）。
/// - `sort_type`: 排序方式。
///
/// # 返回
/// 匹配的 login_id 列表。
///
/// # 错误
/// - 反序列化 AccountSession 失败：`BulwarkError::Session`。
/// - DAO 操作失败：透传 `BulwarkError`。
pub async fn search_session_id(
    session: &BulwarkSession,
    keyword: &str,
    start: usize,
    size: usize,
    sort_type: SearchSortType,
) -> BulwarkResult<Vec<String>> {
    let keys = session
        .dao
        .keys(&format!("{}*", ACCOUNT_SESSION_PREFIX))
        .await?;

    let mut entries: Vec<(String, i64, i64)> = Vec::new();
    for key in keys {
        let login_id = match key.strip_prefix(ACCOUNT_SESSION_PREFIX) {
            Some(t) => t,
            None => continue,
        };
        // keyword 过滤（空 keyword 匹配所有）
        if !keyword.is_empty() && !login_id.contains(keyword) {
            continue;
        }
        // 读取 AccountSession 获取排序时间戳
        let json = match session.dao.get(&key).await? {
            Some(j) => j,
            None => continue,
        };
        let as_: AccountSession = serde_json::from_str(&json)
            .map_err(|e| BulwarkError::Session(format!("反序列化 AccountSession 失败: {}", e)))?;
        entries.push((login_id.to_string(), as_.created_at, as_.last_active_at));
    }

    sort_entries(&mut entries, sort_type);

    Ok(entries
        .into_iter()
        .skip(start)
        .take(size)
        .map(|(id, _, _)| id)
        .collect())
}

/// 按 login_id 搜索 Token-Session 的 token。
///
/// 搜索 TokenSession 中 `login_id` 包含 `keyword` 的 token（排除匿名 Session）。
/// 空 `keyword` 匹配所有。
///
/// # 参数
/// - `session`: BulwarkSession 引用。
/// - `keyword`: 搜索关键字（空字符串匹配所有）。
/// - `start`: 分页偏移量（0-based，超出范围返回空 Vec）。
/// - `size`: 返回数量上限（0 返回空 Vec）。
/// - `sort_type`: 排序方式。
///
/// # 返回
/// 匹配的 token 值列表。
///
/// # 错误
/// - 反序列化 TokenSession 失败：`BulwarkError::Session`。
/// - DAO 操作失败：透传 `BulwarkError`。
pub async fn search_token_session_id(
    session: &BulwarkSession,
    keyword: &str,
    start: usize,
    size: usize,
    sort_type: SearchSortType,
) -> BulwarkResult<Vec<String>> {
    let keys = session
        .dao
        .keys(&format!("{}*", TOKEN_SESSION_PREFIX))
        .await?;

    let mut entries: Vec<(String, i64, i64)> = Vec::new();
    for key in keys {
        // 排除匿名 Session
        if key.starts_with(ANON_SESSION_PREFIX) {
            continue;
        }
        let token = match key.strip_prefix(TOKEN_SESSION_PREFIX) {
            Some(t) => t,
            None => continue,
        };
        // 读取 TokenSession 获取 login_id 与排序时间戳
        let json = match session.dao.get(&key).await? {
            Some(j) => j,
            None => continue,
        };
        let ts: TokenSession = serde_json::from_str(&json)
            .map_err(|e| BulwarkError::Session(format!("反序列化 TokenSession 失败: {}", e)))?;
        // keyword 过滤（空 keyword 匹配所有）
        if !keyword.is_empty() && !ts.login_id.contains(keyword) {
            continue;
        }
        entries.push((token.to_string(), ts.created_at, ts.last_active_at));
    }

    sort_entries(&mut entries, sort_type);

    Ok(entries
        .into_iter()
        .skip(start)
        .take(size)
        .map(|(id, _, _)| id)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::dao::BulwarkDao;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// 辅助函数：创建带 MockDao 的 BulwarkSession。
    fn make_session(timeout: u64, active_timeout: u64) -> (Arc<MockDao>, BulwarkSession) {
        let dao = Arc::new(MockDao::new());
        let session = BulwarkSession::new(dao.clone(), timeout, active_timeout);
        (dao, session)
    }

    /// 辅助函数：直接写入 TokenSession 到 DAO，使用指定的 created_at / last_active_at。
    async fn put_token_session(
        dao: &Arc<MockDao>,
        token: &str,
        login_id: &str,
        created_at: i64,
        last_active_at: i64,
    ) {
        let key = format!("{}{}", TOKEN_SESSION_PREFIX, token);
        let ts = TokenSession {
            token: token.to_string(),
            login_id: login_id.to_string(),
            created_at,
            last_active_at,
            attrs: HashMap::new(),
            device: None,
            ip: None,
            user_agent: None,
            safe_services: HashMap::new(),
            #[cfg(feature = "dynamic-active-timeout")]
            dynamic_active_timeout: None,
            #[cfg(feature = "anonymous-session")]
            is_anon: false,
        };
        let json = serde_json::to_string(&ts).unwrap();
        dao.set(&key, &json, 3600).await.unwrap();
    }

    // ========================================================================
    // T024: SearchSortType 枚举
    // ========================================================================

    /// T024: CreatedAsc 序列化为 "created_asc"。
    #[test]
    fn search_sort_type_serialization() {
        let json = serde_json::to_string(&SearchSortType::CreatedAsc).unwrap();
        assert_eq!(json, "\"created_asc\"");
    }

    // ========================================================================
    // T025: search_token_value
    // ========================================================================

    /// T025: keyword 匹配 — 搜索 "alpha" 返回 2 个（alpha-1, alpha-2）。
    #[tokio::test]
    async fn search_token_value_keyword_match() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("u1", "alpha-1").await.unwrap();
        session.create("u2", "alpha-2").await.unwrap();
        session.create("u3", "beta-1").await.unwrap();

        let result = session
            .search_token_value("alpha", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains(&"alpha-1".to_string()));
        assert!(result.contains(&"alpha-2".to_string()));
    }

    /// T025: 分页 — start=1, size=2 返回第 2、3 个。
    #[tokio::test]
    async fn search_token_value_pagination() {
        let (dao, session) = make_session(3600, 86400);
        // 使用不同 created_at 确保排序确定性
        put_token_session(&dao, "tok-1", "u1", 100, 100).await;
        put_token_session(&dao, "tok-2", "u2", 200, 200).await;
        put_token_session(&dao, "tok-3", "u3", 300, 300).await;
        put_token_session(&dao, "tok-4", "u4", 400, 400).await;
        put_token_session(&dao, "tok-5", "u5", 500, 500).await;

        let result = session
            .search_token_value("", 1, 2, SearchSortType::CreatedAsc)
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "tok-2");
        assert_eq!(result[1], "tok-3");
    }

    /// T025: 排序 — 验证 CreatedDesc 和 CreatedAsc 顺序正确。
    #[tokio::test]
    async fn search_token_value_sort_order() {
        let (dao, session) = make_session(3600, 86400);
        put_token_session(&dao, "tok-a", "u1", 100, 150).await;
        put_token_session(&dao, "tok-b", "u2", 200, 100).await;
        put_token_session(&dao, "tok-c", "u3", 300, 250).await;

        let asc = session
            .search_token_value("", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        assert_eq!(asc, vec!["tok-a", "tok-b", "tok-c"]);

        let desc = session
            .search_token_value("", 0, 100, SearchSortType::CreatedDesc)
            .await
            .unwrap();
        assert_eq!(desc, vec!["tok-c", "tok-b", "tok-a"]);
    }

    // ========================================================================
    // T026: search_session_id
    // ========================================================================

    /// T026: keyword 匹配 — 搜索 "user" 返回 2 个（user1, user2）。
    #[tokio::test]
    async fn search_session_id_keyword_match() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("user1", "t1").await.unwrap();
        session.create("user2", "t2").await.unwrap();
        session.create("admin1", "t3").await.unwrap();

        let result = session
            .search_session_id("user", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains(&"user1".to_string()));
        assert!(result.contains(&"user2".to_string()));
    }

    /// T026: 空结果 — 搜索不存在的 keyword 返回空 Vec。
    #[tokio::test]
    async fn search_session_id_empty_result() {
        let (_dao, session) = make_session(3600, 86400);
        session.create("user1", "t1").await.unwrap();

        let result = session
            .search_session_id("nonexistent", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();

        assert!(result.is_empty());
    }

    // ========================================================================
    // T027: search_token_session_id
    // ========================================================================

    /// T027: 验证 search_token_session_id 按 login_id 过滤，并与 search_token_value 对比。
    #[tokio::test]
    async fn search_token_session_id_filters_by_login_id() {
        let (dao, session) = make_session(3600, 86400);

        // login_id 包含 "user" 的 session
        put_token_session(&dao, "tok-1", "user-1", 100, 100).await;
        put_token_session(&dao, "tok-2", "user-2", 200, 200).await;
        // login_id 不包含 "user"
        put_token_session(&dao, "tok-3", "admin-1", 300, 300).await;

        // search_token_session_id("user") 按 login_id 过滤
        let result = session
            .search_token_session_id("user", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"tok-1".to_string()));
        assert!(result.contains(&"tok-2".to_string()));

        // 对比：search_token_value("user") 按 token 过滤，返回空
        let result2 = session
            .search_token_value("user", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        assert!(
            result2.is_empty(),
            "search_token_value('user') 应返回空，因为没有 token 包含 'user'"
        );

        // 当 keyword 同时出现在 token 和 login_id 中时，两个方法返回相同结果
        put_token_session(&dao, "shared-1", "shared-a", 400, 400).await;
        put_token_session(&dao, "shared-2", "shared-b", 500, 500).await;

        let by_token = session
            .search_token_value("shared", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        let by_login = session
            .search_token_session_id("shared", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        assert_eq!(
            by_token, by_login,
            "当 keyword 同时出现在 token 和 login_id 中时，两个方法应返回相同结果"
        );
    }
}
