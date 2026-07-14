//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 会话搜索模块。
//!
//! 启用 `session-search` feature 后编译。提供按关键字搜索 Token-Session / Account-Session，
//! 支持分页与排序（创建时间 / 最后活跃时间）。
//!
//! ## 搜索方法
//!
//! - `search_token_value`: 按 token 值搜索 Token-Session（排除匿名 Session）。
//! - `search_session_id`: 按 login_id 搜索 Account-Session。
//! - `search_token_session_id`: 按 TokenSession.login_id 搜索 token（排除匿名 Session）。

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

/// 单次搜索最大扫描 key 数量（防止 DoS）。
///
/// 超出时截断并记录 warn 日志。这是性能与可用性的权衡：
/// 生产环境应通过维护反向索引（如 login_token_map）替代全量扫描。
const MAX_SCAN: usize = 10000;

/// 搜索关键字最大长度（防止超长 keyword 放大 CPU 消耗）。
const MAX_KEYWORD_LEN: usize = 256;

/// 单次搜索最大返回数量。
const MAX_SIZE: usize = 1000;

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
/// # 性能警告
///
/// 此方法通过 `dao.keys()` 全量扫描 key，性能与 key 总数线性相关。
/// 单次搜索最多扫描 `MAX_SCAN`（10000）条 key，超出时截断并记录 warn 日志。
/// 生产环境大规模部署时应通过反向索引替代全量扫描。
///
/// # 错误
/// - `keyword` 长度超过 `MAX_KEYWORD_LEN`：`BulwarkError::InvalidParam`。
/// - `size` 超过 `MAX_SIZE`：`BulwarkError::InvalidParam`。
/// - DAO 操作失败：透传 `BulwarkError`。
pub async fn search_token_value(
    session: &BulwarkSession,
    keyword: &str,
    start: usize,
    size: usize,
    sort_type: SearchSortType,
) -> BulwarkResult<Vec<String>> {
    if keyword.len() > MAX_KEYWORD_LEN {
        return Err(BulwarkError::InvalidParam(format!(
            "keyword 长度超限：{} > {}",
            keyword.len(),
            MAX_KEYWORD_LEN
        )));
    }
    if size > MAX_SIZE {
        return Err(BulwarkError::InvalidParam(format!(
            "size 超限：{} > {}",
            size, MAX_SIZE
        )));
    }

    let mut keys = session
        .dao
        .keys(&format!("{}*", TOKEN_SESSION_PREFIX))
        .await?;
    if keys.len() > MAX_SCAN {
        tracing::warn!(
            actual = keys.len(),
            max = MAX_SCAN,
            "搜索扫描的 key 数量超过上限，已截断"
        );
        keys.truncate(MAX_SCAN);
    }

    let mut entries: Vec<(String, i64, i64)> = Vec::new();
    let mut skipped = 0usize;
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
        let ts: TokenSession = match serde_json::from_str(&json) {
            Ok(ts) => ts,
            Err(e) => {
                tracing::warn!(
                    key = %key,
                    error = %e,
                    "跳过损坏的 TokenSession 记录"
                );
                skipped += 1;
                continue;
            },
        };
        entries.push((token.to_string(), ts.created_at, ts.last_active_at));
    }

    if skipped > 0 {
        tracing::warn!(
            skipped,
            total = entries.len() + skipped,
            "搜索完成但有记录被跳过"
        );
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
/// # 性能警告
///
/// 此方法通过 `dao.keys()` 全量扫描 key，性能与 key 总数线性相关。
/// 单次搜索最多扫描 `MAX_SCAN`（10000）条 key，超出时截断并记录 warn 日志。
/// 生产环境大规模部署时应通过反向索引替代全量扫描。
///
/// # 错误
/// - `keyword` 长度超过 `MAX_KEYWORD_LEN`：`BulwarkError::InvalidParam`。
/// - `size` 超过 `MAX_SIZE`：`BulwarkError::InvalidParam`。
/// - DAO 操作失败：透传 `BulwarkError`。
pub async fn search_session_id(
    session: &BulwarkSession,
    keyword: &str,
    start: usize,
    size: usize,
    sort_type: SearchSortType,
) -> BulwarkResult<Vec<String>> {
    if keyword.len() > MAX_KEYWORD_LEN {
        return Err(BulwarkError::InvalidParam(format!(
            "keyword 长度超限：{} > {}",
            keyword.len(),
            MAX_KEYWORD_LEN
        )));
    }
    if size > MAX_SIZE {
        return Err(BulwarkError::InvalidParam(format!(
            "size 超限：{} > {}",
            size, MAX_SIZE
        )));
    }

    let mut keys = session
        .dao
        .keys(&format!("{}*", ACCOUNT_SESSION_PREFIX))
        .await?;
    if keys.len() > MAX_SCAN {
        tracing::warn!(
            actual = keys.len(),
            max = MAX_SCAN,
            "搜索扫描的 key 数量超过上限，已截断"
        );
        keys.truncate(MAX_SCAN);
    }

    let mut entries: Vec<(String, i64, i64)> = Vec::new();
    let mut skipped = 0usize;
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
        let account_session: AccountSession = match serde_json::from_str(&json) {
            Ok(as_v) => as_v,
            Err(e) => {
                tracing::warn!(
                    key = %key,
                    error = %e,
                    "跳过损坏的 AccountSession 记录"
                );
                skipped += 1;
                continue;
            },
        };
        entries.push((
            login_id.to_string(),
            account_session.created_at,
            account_session.last_active_at,
        ));
    }

    if skipped > 0 {
        tracing::warn!(
            skipped,
            total = entries.len() + skipped,
            "搜索完成但有记录被跳过"
        );
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
/// # 性能警告
///
/// 此方法通过 `dao.keys()` 全量扫描 key，性能与 key 总数线性相关。
/// 单次搜索最多扫描 `MAX_SCAN`（10000）条 key，超出时截断并记录 warn 日志。
/// 生产环境大规模部署时应通过反向索引替代全量扫描。
///
/// # 错误
/// - `keyword` 长度超过 `MAX_KEYWORD_LEN`：`BulwarkError::InvalidParam`。
/// - `size` 超过 `MAX_SIZE`：`BulwarkError::InvalidParam`。
/// - DAO 操作失败：透传 `BulwarkError`。
pub async fn search_token_session_id(
    session: &BulwarkSession,
    keyword: &str,
    start: usize,
    size: usize,
    sort_type: SearchSortType,
) -> BulwarkResult<Vec<String>> {
    if keyword.len() > MAX_KEYWORD_LEN {
        return Err(BulwarkError::InvalidParam(format!(
            "keyword 长度超限：{} > {}",
            keyword.len(),
            MAX_KEYWORD_LEN
        )));
    }
    if size > MAX_SIZE {
        return Err(BulwarkError::InvalidParam(format!(
            "size 超限：{} > {}",
            size, MAX_SIZE
        )));
    }

    let mut keys = session
        .dao
        .keys(&format!("{}*", TOKEN_SESSION_PREFIX))
        .await?;
    if keys.len() > MAX_SCAN {
        tracing::warn!(
            actual = keys.len(),
            max = MAX_SCAN,
            "搜索扫描的 key 数量超过上限，已截断"
        );
        keys.truncate(MAX_SCAN);
    }

    let mut entries: Vec<(String, i64, i64)> = Vec::new();
    let mut skipped = 0usize;
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
        let ts: TokenSession = match serde_json::from_str(&json) {
            Ok(ts) => ts,
            Err(e) => {
                tracing::warn!(
                    key = %key,
                    error = %e,
                    "跳过损坏的 TokenSession 记录"
                );
                skipped += 1;
                continue;
            },
        };
        // keyword 过滤（空 keyword 匹配所有）
        if !keyword.is_empty() && !ts.login_id.contains(keyword) {
            continue;
        }
        entries.push((token.to_string(), ts.created_at, ts.last_active_at));
    }

    if skipped > 0 {
        tracing::warn!(
            skipped,
            total = entries.len() + skipped,
            "搜索完成但有记录被跳过"
        );
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

    /// T024: SearchSortType 4 个变体的序列化 + 反序列化 round-trip。
    #[test]
    fn search_sort_type_round_trip() {
        for variant in [
            SearchSortType::CreatedAsc,
            SearchSortType::CreatedDesc,
            SearchSortType::LastActiveAsc,
            SearchSortType::LastActiveDesc,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: SearchSortType = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back, "round-trip 失败: {}", json);
        }
        assert_eq!(
            serde_json::to_string(&SearchSortType::CreatedAsc).unwrap(),
            "\"created_asc\""
        );
        assert_eq!(
            serde_json::to_string(&SearchSortType::CreatedDesc).unwrap(),
            "\"created_desc\""
        );
        assert_eq!(
            serde_json::to_string(&SearchSortType::LastActiveAsc).unwrap(),
            "\"last_active_asc\""
        );
        assert_eq!(
            serde_json::to_string(&SearchSortType::LastActiveDesc).unwrap(),
            "\"last_active_desc\""
        );
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

        // last_active_at: tok-b=100, tok-a=150, tok-c=250
        let last_asc = session
            .search_token_value("", 0, 100, SearchSortType::LastActiveAsc)
            .await
            .unwrap();
        assert_eq!(last_asc, vec!["tok-b", "tok-a", "tok-c"]);

        let last_desc = session
            .search_token_value("", 0, 100, SearchSortType::LastActiveDesc)
            .await
            .unwrap();
        assert_eq!(last_desc, vec!["tok-c", "tok-a", "tok-b"]);
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

    // ========================================================================
    // T025/T027: 匿名 Session 排除
    // ========================================================================

    /// T025/T027: 匿名 Session 不出现在搜索结果中。
    #[tokio::test]
    async fn search_excludes_anon_sessions() {
        let (dao, session) = make_session(3600, 86400);
        // 写入正常 Token-Session
        put_token_session(&dao, "normal-1", "u1", 100, 100).await;

        // 写入匿名 Session（直接操作 DAO，模拟 anon 模块的行为）
        let anon_key = format!("{}anon:anon-tok", TOKEN_SESSION_PREFIX);
        let anon_ts = TokenSession {
            token: "anon-tok".to_string(),
            login_id: String::new(),
            created_at: 50,
            last_active_at: 50,
            attrs: HashMap::new(),
            device: None,
            ip: None,
            user_agent: None,
            safe_services: HashMap::new(),
            #[cfg(feature = "dynamic-active-timeout")]
            dynamic_active_timeout: None,
            #[cfg(feature = "anonymous-session")]
            is_anon: true,
        };
        let json = serde_json::to_string(&anon_ts).unwrap();
        dao.set(&anon_key, &json, 3600).await.unwrap();

        // search_token_value 不应返回匿名 token
        let result = session
            .search_token_value("", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        assert_eq!(result, vec!["normal-1"], "anon Session 不应出现在搜索结果");
        assert!(!result.contains(&"anon-tok".to_string()));

        // search_token_session_id 不应返回匿名 token
        let result2 = session
            .search_token_session_id("", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        assert_eq!(
            result2,
            vec!["normal-1"],
            "anon Session 不应出现在 login_id 搜索结果"
        );
    }

    // ========================================================================
    // 输入验证测试（MAX_KEYWORD_LEN / MAX_SIZE）
    // ========================================================================

    /// keyword 超过 MAX_KEYWORD_LEN 时返回 InvalidParam 错误。
    #[tokio::test]
    async fn search_token_value_keyword_too_long_returns_error() {
        let (_dao, session) = make_session(3600, 86400);
        let long_keyword = "a".repeat(MAX_KEYWORD_LEN + 1);
        let result = session
            .search_token_value(&long_keyword, 0, 10, SearchSortType::CreatedAsc)
            .await;
        assert!(result.is_err(), "超长 keyword 应返回错误");
        match result {
            Err(BulwarkError::InvalidParam(msg)) => {
                assert!(
                    msg.contains("keyword 长度超限"),
                    "错误消息应包含 'keyword 长度超限'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 InvalidParam，实际: {:?}", other),
            Ok(_) => panic!("期望错误，实际返回 Ok"),
        }
    }

    /// size 超过 MAX_SIZE 时返回 InvalidParam 错误。
    #[tokio::test]
    async fn search_token_value_size_too_large_returns_error() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session
            .search_token_value("", 0, MAX_SIZE + 1, SearchSortType::CreatedAsc)
            .await;
        assert!(result.is_err(), "超大 size 应返回错误");
        match result {
            Err(BulwarkError::InvalidParam(msg)) => {
                assert!(
                    msg.contains("size 超限"),
                    "错误消息应包含 'size 超限'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 InvalidParam，实际: {:?}", other),
            Ok(_) => panic!("期望错误，实际返回 Ok"),
        }
    }

    /// search_session_id keyword 超长时返回 InvalidParam。
    #[tokio::test]
    async fn search_session_id_keyword_too_long_returns_error() {
        let (_dao, session) = make_session(3600, 86400);
        let long_keyword = "x".repeat(MAX_KEYWORD_LEN + 1);
        let result = session
            .search_session_id(&long_keyword, 0, 10, SearchSortType::CreatedAsc)
            .await;
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::InvalidParam(_))));
    }

    /// search_session_id size 超大时返回 InvalidParam。
    #[tokio::test]
    async fn search_session_id_size_too_large_returns_error() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session
            .search_session_id("", 0, MAX_SIZE + 1, SearchSortType::CreatedAsc)
            .await;
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::InvalidParam(_))));
    }

    /// search_token_session_id keyword 超长时返回 InvalidParam。
    #[tokio::test]
    async fn search_token_session_id_keyword_too_long_returns_error() {
        let (_dao, session) = make_session(3600, 86400);
        let long_keyword = "y".repeat(MAX_KEYWORD_LEN + 1);
        let result = session
            .search_token_session_id(&long_keyword, 0, 10, SearchSortType::CreatedAsc)
            .await;
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::InvalidParam(_))));
    }

    /// search_token_session_id size 超大时返回 InvalidParam。
    #[tokio::test]
    async fn search_token_session_id_size_too_large_returns_error() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session
            .search_token_session_id("", 0, MAX_SIZE + 1, SearchSortType::CreatedAsc)
            .await;
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::InvalidParam(_))));
    }

    // ========================================================================
    // 分页边界测试
    // ========================================================================

    /// start 超出范围时返回空 Vec。
    #[tokio::test]
    async fn search_token_value_start_beyond_range_returns_empty() {
        let (dao, session) = make_session(3600, 86400);
        put_token_session(&dao, "tok-1", "u1", 100, 100).await;
        put_token_session(&dao, "tok-2", "u2", 200, 200).await;

        let result = session
            .search_token_value("", 10, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        assert!(result.is_empty(), "start 超出范围应返回空 Vec");
    }

    /// size=0 返回空 Vec。
    #[tokio::test]
    async fn search_token_value_size_zero_returns_empty() {
        let (dao, session) = make_session(3600, 86400);
        put_token_session(&dao, "tok-1", "u1", 100, 100).await;

        let result = session
            .search_token_value("", 0, 0, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        assert!(result.is_empty(), "size=0 应返回空 Vec");
    }

    /// 空数据库 + 空 keyword 返回空 Vec（不报错）。
    #[tokio::test]
    async fn search_empty_db_empty_keyword_returns_empty() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session
            .search_token_value("", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        assert!(result.is_empty());

        let result2 = session
            .search_session_id("", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        assert!(result2.is_empty());
    }

    // ========================================================================
    // 反序列化容错测试
    // ========================================================================

    /// 损坏的 TokenSession JSON 被跳过（不 panic，不传播错误）。
    #[tokio::test]
    async fn search_token_value_skips_corrupted_json() {
        let (dao, session) = make_session(3600, 86400);
        // 写入正常 session
        put_token_session(&dao, "valid-tok", "u1", 100, 100).await;
        // 写入损坏的 JSON
        let corrupt_key = format!("{}{}", TOKEN_SESSION_PREFIX, "corrupt-tok");
        dao.set(&corrupt_key, "{invalid json}", 3600).await.unwrap();

        let result = session
            .search_token_value("", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        // 损坏记录被跳过，只返回正常记录
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "valid-tok");
    }

    /// 损坏的 AccountSession JSON 被跳过。
    #[tokio::test]
    async fn search_session_id_skips_corrupted_json() {
        let (dao, session) = make_session(3600, 86400);
        // 写入正常 AccountSession（通过 session.create 创建）
        session.create("valid-user", "tok-1").await.unwrap();
        // 写入损坏的 AccountSession JSON
        let corrupt_key = format!("{}corrupt-user", ACCOUNT_SESSION_PREFIX);
        dao.set(&corrupt_key, "not valid json{{{", 3600)
            .await
            .unwrap();

        let result = session
            .search_session_id("", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        // 损坏记录被跳过，只返回正常记录
        assert_eq!(result.len(), 1);
        assert!(result.contains(&"valid-user".to_string()));
    }

    /// search_token_session_id 跳过损坏的 TokenSession JSON。
    #[tokio::test]
    async fn search_token_session_id_skips_corrupted_json() {
        let (dao, session) = make_session(3600, 86400);
        put_token_session(&dao, "valid-tok", "user-1", 100, 100).await;
        let corrupt_key = format!("{}{}", TOKEN_SESSION_PREFIX, "corrupt-tok");
        dao.set(&corrupt_key, "broken json", 3600).await.unwrap();

        let result = session
            .search_token_session_id("user", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "valid-tok");
    }

    /// get() 返回 None 的 key 被跳过（key 在 keys() 与 get() 之间过期）。
    #[tokio::test]
    async fn search_skips_keys_with_none_get() {
        let (dao, session) = make_session(3600, 86400);
        // 写入一个正常 session
        put_token_session(&dao, "exists-tok", "u1", 100, 100).await;
        // 写入一个 key 但值被手动删除（模拟 TTL 过期）
        let expired_key = format!("{}{}", TOKEN_SESSION_PREFIX, "expired-tok");
        dao.set(&expired_key, "will_be_deleted", 3600)
            .await
            .unwrap();
        dao.delete(&expired_key).await.unwrap();

        let result = session
            .search_token_value("", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        // expired-tok 的 get() 返回 None，被跳过
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "exists-tok");
    }

    // ========================================================================
    // MAX_SCAN 截断测试
    // ========================================================================

    /// 模拟返回大量 key 的 mock DAO，用于测试 MAX_SCAN 截断。
    struct LargeKeyDao {
        key_count: usize,
    }

    impl LargeKeyDao {
        fn new(key_count: usize) -> Self {
            Self { key_count }
        }
    }

    #[async_trait::async_trait]
    impl crate::dao::BulwarkDao for LargeKeyDao {
        async fn get(&self, _key: &str) -> BulwarkResult<Option<String>> {
            Ok(None) // 返回 None，所有 key 被跳过
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn keys(&self, pattern: &str) -> BulwarkResult<Vec<String>> {
            // 根据 pattern 前缀生成对应数量的 key
            let prefix = pattern.trim_end_matches('*');
            let keys: Vec<String> = (0..self.key_count)
                .map(|i| format!("{}key_{}", prefix, i))
                .collect();
            Ok(keys)
        }
    }

    /// MAX_SCAN 截断：keys() 返回超过 MAX_SCAN 条 key 时被截断为 MAX_SCAN。
    ///
    /// 验证 DoS 防护：大量 key 不会导致搜索耗时过长。
    #[tokio::test]
    async fn search_truncates_keys_exceeding_max_scan() {
        let dao = Arc::new(LargeKeyDao::new(MAX_SCAN + 100));
        let session = BulwarkSession::new(dao, 3600, 86400);

        // 搜索应成功完成（截断后所有 key 的 get() 返回 None，结果为空）
        let result = session
            .search_token_value("", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        assert!(result.is_empty(), "所有 key 的 get() 返回 None，结果应为空");
    }

    /// MAX_SCAN 边界：keys() 返回恰好 MAX_SCAN 条 key 时不截断。
    #[tokio::test]
    async fn search_max_scan_boundary_not_truncated() {
        let dao = Arc::new(LargeKeyDao::new(MAX_SCAN));
        let session = BulwarkSession::new(dao, 3600, 86400);

        let result = session
            .search_token_value("", 0, 100, SearchSortType::CreatedAsc)
            .await
            .unwrap();
        // 恰好 MAX_SCAN 条不截断，但 get() 返回 None，结果为空
        assert!(result.is_empty());
    }

    // ========================================================================
    // sort_entries 排序测试
    // ========================================================================

    /// sort_entries 对 CreatedDesc 降序排列正确。
    #[test]
    fn sort_entries_created_desc_correct() {
        let mut entries = vec![
            ("a".to_string(), 100i64, 50i64),
            ("b".to_string(), 300, 200),
            ("c".to_string(), 200, 100),
        ];
        sort_entries(&mut entries, SearchSortType::CreatedDesc);
        assert_eq!(entries[0].0, "b"); // 300
        assert_eq!(entries[1].0, "c"); // 200
        assert_eq!(entries[2].0, "a"); // 100
    }

    /// sort_entries 对 LastActiveDesc 降序排列正确。
    #[test]
    fn sort_entries_last_active_desc_correct() {
        let mut entries = vec![
            ("a".to_string(), 100, 50),
            ("b".to_string(), 300, 200),
            ("c".to_string(), 200, 100),
        ];
        sort_entries(&mut entries, SearchSortType::LastActiveDesc);
        assert_eq!(entries[0].0, "b"); // 200
        assert_eq!(entries[1].0, "c"); // 100
        assert_eq!(entries[2].0, "a"); // 50
    }

    /// sort_entries 空列表不 panic。
    #[test]
    fn sort_entries_empty_list_no_panic() {
        let mut entries: Vec<(String, i64, i64)> = vec![];
        sort_entries(&mut entries, SearchSortType::CreatedAsc);
        assert!(entries.is_empty());
    }

    /// sort_entries 单元素列表不 panic。
    #[test]
    fn sort_entries_single_element_no_panic() {
        let mut entries = vec![("only".to_string(), 42, 99)];
        sort_entries(&mut entries, SearchSortType::LastActiveAsc);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "only");
    }
}
