//! 匿名 Session 模块。
//!
//! 启用 `anonymous-session` feature 后编译。提供未登录用户的匿名会话支持，
//! 适用于购物车、访客浏览等场景。
//!
//! ## Key 空间隔离
//!
//! 匿名 Session 使用独立的 key 空间，与登录 Session 隔离：
//! - 登录 Session: `token:session:{token}`
//! - 匿名 Session: `token:session:anon:{token}`
//!
//! 匿名 Session 的 `login_id` 为空字符串 `""`，`is_anon` 为 `true`。
//! 不参与 `login_token_map`（因为 login_id 为空）。

use super::{BulwarkSession, TokenSession};
use crate::constants::DaoKeyPrefix;
use crate::error::{BulwarkError, BulwarkResult};
use chrono::Utc;
use std::collections::HashMap;

/// 生成匿名 Token-Session 的存储 key。
///
/// 格式: `token:session:anon:{token}`
fn anon_token_key(token: &str) -> String {
    format!("{}session:anon:{}", DaoKeyPrefix::Token, token)
}

/// 校验匿名 token 输入。
///
/// 拒绝空字符串和超长 token（>128 字节），防止 DoS 和语义混淆。
fn validate_anon_token(token: &str) -> BulwarkResult<()> {
    if token.is_empty() {
        return Err(BulwarkError::InvalidParam(
            "session-token-empty::".to_string(),
        ));
    }
    if token.len() > 128 {
        return Err(BulwarkError::InvalidParam(
            "session-token-too-long::".to_string(),
        ));
    }
    Ok(())
}

/// 获取匿名 Token-Session，不存在则创建。
///
/// 首次调用时创建新的匿名 Session（`login_id = ""`, `is_anon = true`）并存储到 DAO，
/// 后续调用返回已存在的 Session。TTL 由 `anon_session_timeout` 控制。
///
/// # 参数
/// - `session`: BulwarkSession 引用。
/// - `token`: token 字符串。
///
/// # 返回
/// 匿名 TokenSession。
///
/// # 错误
/// - 序列化/反序列化失败：`BulwarkError::Session`。
/// - DAO 操作失败：透传 `BulwarkError`。
pub async fn get_anon_token_session(
    session: &BulwarkSession,
    token: &str,
) -> BulwarkResult<TokenSession> {
    validate_anon_token(token)?;
    let key = anon_token_key(token);

    // 使用 per-token 锁保护 check-then-set 序列，避免并发 lost update
    session
        .with_token_session_lock(token, async {
            // 已存在则返回
            if let Some(json) = session.dao.get(&key).await? {
                let ts: TokenSession = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Session(format!("session-sim-anon-deserialize::{}", e))
                })?;
                return Ok(ts);
            }

            // 不存在则创建
            let now = Utc::now().timestamp();
            let ts = TokenSession {
                token: token.to_string(),
                login_id: String::new(),
                created_at: now,
                last_active_at: now,
                attrs: HashMap::new(),
                device: None,
                ip: None,
                user_agent: None,
                safe_services: HashMap::new(),
                #[cfg(feature = "dynamic-active-timeout")]
                dynamic_active_timeout: None,
                is_anon: true,
            };

            let json = serde_json::to_string(&ts)
                .map_err(|e| BulwarkError::Session(format!("session-sim-anon-serialize::{}", e)))?;
            session
                .dao
                .set(&key, &json, session.anon_session_timeout)
                .await?;

            Ok(ts)
        })
        .await
}

/// 判断 token 是否为匿名 Session。
///
/// 检查 `token:session:anon:{token}` 是否存在：
/// - 存在 → `true`（匿名 Session）
/// - 不存在 → `false`（登录 Session 或不存在的 token）
///
/// # 参数
/// - `session`: BulwarkSession 引用。
/// - `token`: token 字符串。
///
/// # 返回
/// `true` 表示匿名 Session，`false` 表示非匿名。
///
/// # 错误
/// DAO 读取失败时透传 `BulwarkError`。
pub async fn is_anon(session: &BulwarkSession, token: &str) -> BulwarkResult<bool> {
    validate_anon_token(token)?;
    let key = anon_token_key(token);
    Ok(session.dao.get(&key).await?.is_some())
}

/// 注销匿名 Session。
///
/// 删除 `token:session:anon:{token}` 键。不存在的 anon token 返回 `Ok(())`（幂等）。
///
/// # 参数
/// - `session`: BulwarkSession 引用。
/// - `token`: token 字符串。
///
/// # 返回
/// 成功返回 `Ok(())`。
///
/// # 错误
/// DAO 删除失败时透传 `BulwarkError`。
pub async fn logout_anon(session: &BulwarkSession, token: &str) -> BulwarkResult<()> {
    validate_anon_token(token)?;
    let key = anon_token_key(token);
    session.dao.delete(&key).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use std::sync::Arc;
    use std::time::Duration;

    /// 辅助函数：创建带 MockDao + 自定义 anon_session_timeout 的 BulwarkSession。
    fn make_anon_session(
        timeout: u64,
        active_timeout: u64,
        anon_timeout: u64,
    ) -> (Arc<MockDao>, BulwarkSession) {
        let dao = Arc::new(MockDao::new());
        let session = BulwarkSession::new(dao.clone(), timeout, active_timeout)
            .with_anon_session_timeout(anon_timeout);
        (dao, session)
    }

    // ========================================================================
    // T019: get_anon_token_session
    // ========================================================================

    /// T019: 首次调用创建匿名 Session，login_id 为空，is_anon 为 true。
    #[tokio::test]
    async fn get_anon_token_session_creates_new_on_first_call() {
        let (_dao, session) = make_anon_session(3600, 86400, 1800);

        let ts = session.get_anon_token_session("anon-1").await.unwrap();

        assert_eq!(ts.token, "anon-1");
        assert!(
            ts.login_id.is_empty(),
            "匿名 Session 的 login_id 应为空字符串"
        );
        assert!(ts.is_anon, "匿名 Session 的 is_anon 应为 true");
        assert!(ts.created_at > 0, "created_at 应为有效时间戳");
        assert_eq!(ts.created_at, ts.last_active_at);
    }

    /// T019: 二次获取返回同一个 Session（created_at 不变）。
    #[tokio::test]
    async fn get_anon_token_session_returns_same_on_second_call() {
        let (_dao, session) = make_anon_session(3600, 86400, 1800);

        let ts1 = session.get_anon_token_session("anon-1").await.unwrap();
        let ts2 = session.get_anon_token_session("anon-1").await.unwrap();

        assert_eq!(
            ts1.created_at, ts2.created_at,
            "二次获取应返回同一个 Session（created_at 不变）"
        );
        assert_eq!(ts1.token, ts2.token);
        assert!(ts2.is_anon);
    }

    /// T019: 超时后重新调用创建新 Session（created_at 不同）。
    #[tokio::test]
    async fn get_anon_token_session_recreates_after_timeout() {
        // anon TTL = 2 秒
        let (_dao, session) = make_anon_session(3600, 86400, 2);

        let ts1 = session.get_anon_token_session("anon-1").await.unwrap();

        // 等待超时（TTL=2，sleep 3 秒确保过期）
        tokio::time::sleep(Duration::from_secs(3)).await;

        let ts2 = session.get_anon_token_session("anon-1").await.unwrap();

        assert!(
            ts2.created_at > ts1.created_at,
            "超时后应创建新 Session（created_at 应大于首次）"
        );
        assert!(ts2.is_anon, "新 Session 的 is_anon 应为 true");
        assert!(ts2.login_id.is_empty(), "新 Session 的 login_id 应为空");
    }

    // ========================================================================
    // T020: is_anon
    // ========================================================================

    /// T020: 匿名 token 的 is_anon 返回 true。
    #[tokio::test]
    async fn is_anon_returns_true_for_anon_token() {
        let (_dao, session) = make_anon_session(3600, 86400, 1800);

        // 先创建匿名 Session
        session.get_anon_token_session("anon-1").await.unwrap();

        let result = session.is_anon("anon-1").await.unwrap();
        assert!(result, "匿名 token 的 is_anon 应返回 true");
    }

    /// T020: 登录 token 的 is_anon 返回 false。
    #[tokio::test]
    async fn is_anon_returns_false_for_login_token() {
        let (_dao, session) = make_anon_session(3600, 86400, 1800);

        // 创建登录 Session
        session.create("1001", "T1").await.unwrap();

        let result = session.is_anon("T1").await.unwrap();
        assert!(!result, "登录 token 的 is_anon 应返回 false");
    }

    // ========================================================================
    // T021: logout_anon
    // ========================================================================

    /// T021: 注销后再获取创建新 Session。
    #[tokio::test]
    async fn logout_anon_then_get_creates_new_session() {
        let (_dao, session) = make_anon_session(3600, 86400, 1800);

        // 首次创建
        session.get_anon_token_session("anon-1").await.unwrap();
        assert!(
            session.is_anon("anon-1").await.unwrap(),
            "首次创建后 is_anon 应为 true"
        );

        // 注销
        session.logout_anon("anon-1").await.unwrap();
        assert!(
            !session.is_anon("anon-1").await.unwrap(),
            "注销后 is_anon 应为 false"
        );

        // 再次获取应创建新 Session
        let ts2 = session.get_anon_token_session("anon-1").await.unwrap();
        assert!(
            session.is_anon("anon-1").await.unwrap(),
            "重新获取后 is_anon 应为 true"
        );
        assert!(ts2.is_anon, "新 Session 的 is_anon 应为 true");
        assert!(ts2.login_id.is_empty(), "新 Session 的 login_id 应为空");
    }

    /// T021: 注销不存在的 anon token 返回 Ok(())（幂等）。
    #[tokio::test]
    async fn logout_anon_nonexistent_returns_ok() {
        let (_dao, session) = make_anon_session(3600, 86400, 1800);

        let result = session.logout_anon("nonexistent-anon").await;
        assert!(
            result.is_ok(),
            "注销不存在的 anon token 应返回 Ok(())（幂等）"
        );
    }

    /// logout 对空 token 保持幂等契约（anonymous-session feature 下不因 InvalidParam 报错）。
    #[tokio::test]
    async fn logout_empty_token_remains_idempotent_with_anon_feature() {
        let (_dao, session) = make_anon_session(3600, 86400, 1800);

        let result = session.logout("").await;
        assert!(
            result.is_ok(),
            "logout(\"\") 应保持幂等契约返回 Ok(())，而非因 is_anon 校验返回 Err"
        );
    }

    /// logout 对超长 token 保持幂等契约。
    #[tokio::test]
    async fn logout_oversized_token_remains_idempotent_with_anon_feature() {
        let (_dao, session) = make_anon_session(3600, 86400, 1800);

        let oversized = "a".repeat(200);
        let result = session.logout(&oversized).await;
        assert!(
            result.is_ok(),
            "logout 对超长 token 应保持幂等契约返回 Ok(())"
        );
    }
}
