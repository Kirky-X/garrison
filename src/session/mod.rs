//! 会话模块，提供双模会话管理（Account-Session + Token-Session）。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaSession`，
//! 提供会话级数据存储与 Token 列表管理。
//!
//! ## 双模会话（依据 spec session-management）
//!
//! 1. **Account-Session**：以 login_id 为 key，存储该账号所有 token 列表与最后活跃时间
//!    - key: `session:account:{login_id}`
//!    - TTL: `active_timeout`（账号级 activity 超时）
//! 2. **Token-Session**：以 token 为 key，存储 login_id/创建时间/自定义属性
//!    - key: `session:token:{token}`
//!    - TTL: `timeout`（token 级超时）
//!
//! ## 过期机制
//!
//! - **token 级过期**：由 oxcache TTL 自动管理，过期后 get 返回 None
//! - **Account-Session 级过期**：由 oxcache TTL 自动管理 + `is_valid` 惰性检查
//! - **活跃续期**：`touch(token)` 更新 last_active_at 并重置 TTL
//! - **主动续期**：`renew(token)` 重置过期时间为完整 timeout
//!
//! ## 存储委托
//!
//! 会话数据通过 `BulwarkDao` 持久化（oxcache / dbnexus），不自行实现缓存逻辑。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Account-Session 的 token 信息条目。
///
/// 存储 token 字符串、创建时间与最后活跃时间。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// token 字符串。
    pub token: String,
    /// 创建时间戳（Unix 秒）。
    pub created_at: i64,
    /// 最后活跃时间戳（Unix 秒）。
    pub last_active_at: i64,
}

/// Account-Session 数据（以 login_id 为 key）。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的 Account-Session，
/// 存储账号所有 token 列表与最后活跃时间。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSession {
    /// 登录主体标识。
    pub login_id: i64,
    /// 该账号的所有 token 信息列表。
    pub tokens: Vec<TokenInfo>,
    /// Account-Session 创建时间戳（Unix 秒）。
    pub created_at: i64,
    /// Account-Session 最后活跃时间戳（Unix 秒）。
    pub last_active_at: i64,
}

/// Token-Session 数据（以 token 为 key）。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的 Token-Session，
/// 存储 token 关联的 login_id、创建时间与自定义属性。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSession {
    /// token 字符串。
    pub token: String,
    /// 关联的登录主体标识。
    pub login_id: i64,
    /// 创建时间戳（Unix 秒）。
    pub created_at: i64,
    /// 最后活跃时间戳（Unix 秒）。
    pub last_active_at: i64,
    /// 自定义属性（键值对）。
    pub attrs: HashMap<String, String>,
}

/// 会话管理器，封装 `BulwarkDao` 提供双模会话操作。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的 `SaSession` 管理逻辑，
/// 持有 DAO 引用与超时配置，提供会话 CRUD / 过期检查 / 续期 / 登出。
///
/// # 存储格式
///
/// - `session:account:{login_id}` → `AccountSession`（JSON）
/// - `session:token:{token}` → `TokenSession`（JSON）
pub struct BulwarkSession {
    /// DAO 引用（oxcache / dbnexus 实现）。
    dao: Arc<dyn BulwarkDao>,
    /// token 级超时（秒）。
    timeout: u64,
    /// Account-Session 级 activity 超时（秒）。
    active_timeout: u64,
}

/// 生成 Account-Session 的存储 key。
fn account_key(login_id: i64) -> String {
    format!("session:account:{}", login_id)
}

/// 生成 Token-Session 的存储 key。
fn token_key(token: &str) -> String {
    format!("session:token:{}", token)
}

impl BulwarkSession {
    /// 创建会话管理器实例。
    ///
    /// # 参数
    /// - `dao`: DAO 引用（oxcache / dbnexus）。
    /// - `timeout`: token 级超时秒数（0 表示永久驻留）。
    /// - `active_timeout`: Account-Session 级 activity 超时秒数。
    ///
    /// # 返回
    /// 新建的 `BulwarkSession` 实例。
    pub fn new(dao: Arc<dyn BulwarkDao>, timeout: u64, active_timeout: u64) -> Self {
        Self {
            dao,
            timeout,
            active_timeout,
        }
    }

    /// 创建会话（login 时调用）：双写 Account-Session + Token-Session。
    ///
    /// 对应 spec scenario "创建 Account-Session" 与 "创建 Token-Session"。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `token`: 新创建的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 序列化 `TokenSession` / `AccountSession` 失败：`BulwarkError::Session`。
    /// - DAO 写入失败：透传 `BulwarkError`。
    pub async fn create(&self, login_id: i64, token: &str) -> BulwarkResult<()> {
        let now = Utc::now().timestamp();

        // 创建 Token-Session
        let token_session = TokenSession {
            token: token.to_string(),
            login_id,
            created_at: now,
            last_active_at: now,
            attrs: HashMap::new(),
        };
        let token_json = serde_json::to_string(&token_session)
            .map_err(|e| BulwarkError::Session(format!("序列化 TokenSession 失败: {}", e)))?;
        self.dao
            .set(&token_key(token), &token_json, self.timeout)
            .await?;

        // 读取或创建 Account-Session
        let mut account = self
            .get_account_session(login_id)
            .await?
            .unwrap_or_else(|| AccountSession {
                login_id,
                tokens: vec![],
                created_at: now,
                last_active_at: now,
            });

        // 添加 token 信息（spec scenario "Account-Session 记录多 token"）
        account.tokens.push(TokenInfo {
            token: token.to_string(),
            created_at: now,
            last_active_at: now,
        });
        account.last_active_at = now;

        let account_json = serde_json::to_string(&account)
            .map_err(|e| BulwarkError::Session(format!("序列化 AccountSession 失败: {}", e)))?;
        self.dao
            .set(&account_key(login_id), &account_json, self.active_timeout)
            .await?;

        Ok(())
    }

    /// 获取 Token-Session。
    ///
    /// 对应 spec scenario "创建 Token-Session"（读取验证）。
    ///
    /// # 参数
    /// - `token`: token 字符串。
    ///
    /// # 返回
    /// - `Some(TokenSession)`: token 存在。
    /// - `None`: token 不存在或已过期。
    ///
    /// # 错误
    /// - 反序列化失败：`BulwarkError::Session`。
    /// - DAO 读取失败：透传 `BulwarkError`。
    pub async fn get_token_session(&self, token: &str) -> BulwarkResult<Option<TokenSession>> {
        match self.dao.get(&token_key(token)).await? {
            Some(json) => {
                let ts: TokenSession = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Session(format!("反序列化 TokenSession 失败: {}", e))
                })?;
                Ok(Some(ts))
            },
            None => Ok(None),
        }
    }

    /// 获取 Account-Session。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// - `Some(AccountSession)`: 账号会话存在。
    /// - `None`: 账号会话不存在或已过期。
    ///
    /// # 错误
    /// - 反序列化失败：`BulwarkError::Session`。
    /// - DAO 读取失败：透传 `BulwarkError`。
    pub async fn get_account_session(
        &self,
        login_id: i64,
    ) -> BulwarkResult<Option<AccountSession>> {
        match self.dao.get(&account_key(login_id)).await? {
            Some(json) => {
                let as_: AccountSession = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Session(format!("反序列化 AccountSession 失败: {}", e))
                })?;
                Ok(Some(as_))
            },
            None => Ok(None),
        }
    }

    /// 设置 Token-Session 自定义属性。
    ///
    /// 对应 spec scenario "Token-Session 存储自定义属性"。
    ///
    /// # 参数
    /// - `token`: token 字符串。
    /// - `key`: 属性键。
    /// - `value`: 属性值。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 若 token 不存在，返回 `BulwarkError::InvalidToken`。
    pub async fn set(&self, token: &str, key: &str, value: &str) -> BulwarkResult<()> {
        let mut ts = self
            .get_token_session(token)
            .await?
            .ok_or_else(|| BulwarkError::InvalidToken("token 不存在".to_string()))?;
        ts.attrs.insert(key.to_string(), value.to_string());
        ts.last_active_at = Utc::now().timestamp();
        let json = serde_json::to_string(&ts)
            .map_err(|e| BulwarkError::Session(format!("序列化 TokenSession 失败: {}", e)))?;
        // 用 update 保留原 TTL（不重置过期时间）
        self.dao.update(&token_key(token), &json).await?;
        Ok(())
    }

    /// 获取 Token-Session 自定义属性。
    ///
    /// 对应 spec scenario "Token-Session 存储自定义属性"（读取验证）。
    ///
    /// # 参数
    /// - `token`: token 字符串。
    /// - `key`: 属性键。
    ///
    /// # 返回
    /// - `Some(String)`: 属性存在。
    /// - `None`: token 不存在或属性不存在。
    ///
    /// # 错误
    /// - DAO 读取失败：透传 `BulwarkError`。
    pub async fn get(&self, token: &str, key: &str) -> BulwarkResult<Option<String>> {
        match self.get_token_session(token).await? {
            Some(ts) => Ok(ts.attrs.get(key).cloned()),
            None => Ok(None),
        }
    }

    /// 关联 SSO ticket 到 token 会话（0.2.0 新增，依据 spec session-management）。
    ///
    /// 将 SSO ticket 存入 Token-Session 的 `sso_ticket` 属性，
    /// 便于 logout 时联动销毁 SSO ticket。
    pub async fn link_sso_ticket(&self, token: &str, ticket: &str) -> BulwarkResult<()> {
        self.set(token, "sso_ticket", ticket).await
    }

    /// 查询 token 关联的 SSO ticket（0.2.0 新增，依据 spec session-management）。
    pub async fn get_sso_ticket(&self, token: &str) -> BulwarkResult<Option<String>> {
        self.get(token, "sso_ticket").await
    }

    /// 关联 OAuth2 access_token 到 token 会话（0.2.0 新增，依据 spec session-management）。
    ///
    /// 将 OAuth2 access_token 存入 Token-Session 的 `oauth2_access_token` 属性，
    /// 便于业务方在持有内部 token 时访问 OAuth2 资源服务器。
    pub async fn link_oauth2_token(&self, token: &str, access_token: &str) -> BulwarkResult<()> {
        self.set(token, "oauth2_access_token", access_token).await
    }

    /// 查询 token 关联的 OAuth2 access_token（0.2.0 新增，依据 spec session-management）。
    pub async fn get_oauth2_token(&self, token: &str) -> BulwarkResult<Option<String>> {
        self.get(token, "oauth2_access_token").await
    }

    /// 关联临时凭证 key 到 token 会话（0.2.0 新增，依据 spec session-management）。
    ///
    /// 将临时凭证的完整 dao key 存入 Token-Session 的 `temp_credential_key` 属性。
    /// `is_valid` 会检查该 key 是否仍存在于 dao，若已被删除则会话失效。
    pub async fn link_temp_credential(&self, token: &str, temp_key: &str) -> BulwarkResult<()> {
        self.set(token, "temp_credential_key", temp_key).await
    }

    /// 查询 token 关联的临时凭证 key（0.2.0 新增）。
    pub async fn get_temp_credential(&self, token: &str) -> BulwarkResult<Option<String>> {
        self.get(token, "temp_credential_key").await
    }

    /// 检查 token 是否有效（Token-Session 存在且 Account-Session 未过期）。
    ///
    /// 惰性检查 Account-Session 是否存在——若 Account-Session 已被 oxcache TTL 清理，
    /// 即使 Token-Session 仍存在，也视为无效（spec scenario "Activity 超时"）。
    ///
    /// 注意：此方法只读，不更新 last_active_at。活跃续期请调用 `touch`。
    ///
    /// # 参数
    /// - `token`: 待校验的 token 字符串。
    ///
    /// # 返回
    /// - `true`: Token-Session 存在且 Account-Session 未过期。
    /// - `false`: token 不存在或 Account-Session 已过期。
    ///
    /// # 错误
    /// - DAO 读取失败：透传 `BulwarkError`。
    pub async fn is_valid(&self, token: &str) -> BulwarkResult<bool> {
        let ts = match self.get_token_session(token).await? {
            Some(ts) => ts,
            None => return Ok(false),
        };
        // 惰性检查 Account-Session 是否存在
        if self.get_account_session(ts.login_id).await?.is_none() {
            return Ok(false);
        }
        // 0.2.0 新增：临时凭证过期联动（依据 spec session-management "临时凭证关联会话的自定义过期"）。
        // 若 Token-Session 含 temp_credential_key 属性，检查该 key 是否仍存在于 dao；
        // 临时凭证过期后 token 立即失效，不论 token 自身 timeout 是否到期。
        if let Some(temp_key) = ts.attrs.get("temp_credential_key") {
            if self.dao.get(temp_key).await?.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 活跃续期：更新 last_active_at 并重置 TTL。
    ///
    /// 对应 spec scenario "活跃续期"。
    /// 同时更新 Token-Session 与 Account-Session 的 last_active_at 和 TTL。
    ///
    /// # 参数
    /// - `token`: 待续期的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 若 token 不存在，返回 `BulwarkError::InvalidToken`。
    pub async fn touch(&self, token: &str) -> BulwarkResult<()> {
        let mut ts = self
            .get_token_session(token)
            .await?
            .ok_or_else(|| BulwarkError::InvalidToken(format!("token 不存在: {}", token)))?;
        let now = Utc::now().timestamp();
        ts.last_active_at = now;
        let json = serde_json::to_string(&ts)
            .map_err(|e| BulwarkError::Session(format!("序列化 TokenSession 失败: {}", e)))?;
        // 更新值 + 重置 TTL（用 set 覆盖，重置 TTL）
        self.dao.set(&token_key(token), &json, self.timeout).await?;

        // 同时更新 Account-Session 的 last_active_at + 对应 TokenInfo + 重置 TTL
        if let Some(mut account) = self.get_account_session(ts.login_id).await? {
            account.last_active_at = now;
            for ti in &mut account.tokens {
                if ti.token == token {
                    ti.last_active_at = now;
                }
            }
            let account_json = serde_json::to_string(&account)
                .map_err(|e| BulwarkError::Session(format!("序列化 AccountSession 失败: {}", e)))?;
            self.dao
                .set(
                    &account_key(ts.login_id),
                    &account_json,
                    self.active_timeout,
                )
                .await?;
        }
        Ok(())
    }

    /// 主动续期：重置过期时间为完整 timeout。
    ///
    /// 对应 spec scenario "主动续期重置过期时间"。
    ///
    /// # 参数
    /// - `token`: 待续期的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 若 token 不存在，返回 `BulwarkError::InvalidToken`（spec scenario "续期不存在的 token"）。
    pub async fn renew(&self, token: &str) -> BulwarkResult<()> {
        // 检查 token 存在（Fail Loud）
        if self.get_token_session(token).await?.is_none() {
            return Err(BulwarkError::InvalidToken(format!(
                "token 不存在: {}",
                token
            )));
        }
        // renew 等同于 touch：重置 TTL + 更新 last_active_at
        self.touch(token).await
    }

    /// 登出指定 token。
    ///
    /// 对应 spec scenario "Account-Session 随登出更新"。
    ///
    /// 删除 Token-Session，并从 Account-Session 的 token 列表移除该 token。
    /// 若列表为空，Account-Session 保留（不删除，保留历史）。
    ///
    /// # 参数
    /// - `token`: 待登出的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；token 不存在时幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - 序列化 `AccountSession` 失败：`BulwarkError::Session`。
    /// - DAO 删除/更新失败：透传 `BulwarkError`。
    pub async fn logout(&self, token: &str) -> BulwarkResult<()> {
        let ts = self.get_token_session(token).await?;
        // 删除 Token-Session
        self.dao.delete(&token_key(token)).await?;

        // 从 Account-Session 移除该 token
        if let Some(ts) = ts {
            // 0.2.0 新增：SSO ticket 销毁联动（依据 spec session-management "SSO 会话集成"）。
            // 若 Token-Session 含 sso_ticket 属性，删除 dao 中的 `bulwark:sso:ticket:<ticket>` key。
            // 失败仅记录不中断主流程（依据 design Decision 6: plugin/listener/集成失败不中断主流程）。
            if let Some(ticket) = ts.attrs.get("sso_ticket") {
                let sso_key = format!("bulwark:sso:ticket:{}", ticket);
                if let Err(e) = self.dao.delete(&sso_key).await {
                    tracing::warn!("logout 联动删除 SSO ticket 失败 (key={}): {}", sso_key, e);
                }
            }

            if let Some(mut account) = self.get_account_session(ts.login_id).await? {
                account.tokens.retain(|ti| ti.token != token);
                // spec: 若列表为空，Account-Session 标记为空（但不删除，保留历史）
                let account_json = serde_json::to_string(&account).map_err(|e| {
                    BulwarkError::Session(format!("序列化 AccountSession 失败: {}", e))
                })?;
                // 用 update 保留原 TTL（不重置 Account-Session 的过期时间）
                self.dao
                    .update(&account_key(ts.login_id), &account_json)
                    .await?;
            }
        }
        Ok(())
    }

    /// 按账号登出：删除所有关联 token + Account-Session。
    ///
    /// 对应 Sa-Token 的 `logout(login_id)` 语义。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - DAO 删除失败：透传 `BulwarkError`。
    pub async fn logout_by_login_id(&self, login_id: i64) -> BulwarkResult<()> {
        if let Some(account) = self.get_account_session(login_id).await? {
            for ti in &account.tokens {
                self.dao.delete(&token_key(&ti.token)).await?;
            }
        }
        self.dao.delete(&account_key(login_id)).await?;
        Ok(())
    }
}

// ============================================================================
// 测试（依据 spec session-management 所有 scenario）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::time::{Duration, Instant};

    // ------------------------------------------------------------------------
    // MockDao：基于 HashMap + Instant 模拟 TTL，用于验证 session 业务逻辑
    // ------------------------------------------------------------------------

    /// 测试用 mock DAO，模拟 oxcache 的 TTL 行为。
    struct MockDao {
        store: Mutex<HashMap<String, (String, Option<Instant>)>>,
    }

    impl MockDao {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BulwarkDao for MockDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            let mut store = self.store.lock();
            match store.get(key) {
                Some((value, expire_at)) => {
                    if let Some(deadline) = expire_at {
                        if Instant::now() >= *deadline {
                            store.remove(key);
                            return Ok(None);
                        }
                    }
                    Ok(Some(value.clone()))
                },
                None => Ok(None),
            }
        }

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            let expire_at = if ttl_seconds == 0 {
                None
            } else {
                Some(Instant::now() + Duration::from_secs(ttl_seconds))
            };
            self.store
                .lock()
                .insert(key.to_string(), (value.to_string(), expire_at));
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((existing, _)) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((_, expire_at)) => {
                    *expire_at = if seconds == 0 {
                        None
                    } else {
                        Some(Instant::now() + Duration::from_secs(seconds))
                    };
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.store.lock().remove(key);
            Ok(())
        }
    }

    /// 辅助函数：创建带 MockDao 的 BulwarkSession。
    fn make_session(timeout: u64, active_timeout: u64) -> (Arc<MockDao>, BulwarkSession) {
        let dao = Arc::new(MockDao::new());
        let session = BulwarkSession::new(dao.clone(), timeout, active_timeout);
        (dao, session)
    }

    // ------------------------------------------------------------------------
    // spec scenario: 创建 Account-Session / 创建 Token-Session
    // ------------------------------------------------------------------------

    /// 验证 create 双写 Account-Session 与 Token-Session。
    #[tokio::test]
    async fn create_writes_both_sessions() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        // Token-Session 存在
        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert_eq!(ts.login_id, 1001);
        assert_eq!(ts.token, "T1");
        assert!(ts.created_at > 0);
        assert_eq!(ts.created_at, ts.last_active_at);

        // Account-Session 存在，包含 T1
        let as_ = session.get_account_session(1001).await.unwrap().unwrap();
        assert_eq!(as_.login_id, 1001);
        assert_eq!(as_.tokens.len(), 1);
        assert_eq!(as_.tokens[0].token, "T1");
    }

    /// 验证 BulwarkDao 直接读取 key 格式正确。
    #[tokio::test]
    async fn dao_key_format_matches_spec() {
        let (dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        // spec: BulwarkDao::get("session:account:1001") 返回 Account-Session 数据
        let account_json = dao.get("session:account:1001").await.unwrap();
        assert!(account_json.is_some());
        let account: AccountSession = serde_json::from_str(&account_json.unwrap()).unwrap();
        assert_eq!(account.login_id, 1001);

        // spec: BulwarkDao::get("session:token:T1") 返回 Token-Session 数据
        let token_json = dao.get("session:token:T1").await.unwrap();
        assert!(token_json.is_some());
        let ts: TokenSession = serde_json::from_str(&token_json.unwrap()).unwrap();
        assert_eq!(ts.login_id, 1001);
    }

    // ------------------------------------------------------------------------
    // spec scenario: Account-Session 记录多 token
    // ------------------------------------------------------------------------

    /// 验证同一账号登录两次后 token 列表包含两个 token。
    #[tokio::test]
    async fn account_session_records_multiple_tokens() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();
        session.create(1001, "T2").await.unwrap();

        let as_ = session.get_account_session(1001).await.unwrap().unwrap();
        assert_eq!(as_.tokens.len(), 2);
        assert_eq!(as_.tokens[0].token, "T1");
        assert_eq!(as_.tokens[1].token, "T2");
    }

    // ------------------------------------------------------------------------
    // spec scenario: Account-Session 随登出更新
    // ------------------------------------------------------------------------

    /// 验证登出 T1 后 Account-Session 移除 T1 但保留 T2。
    #[tokio::test]
    async fn account_session_removes_token_on_logout() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();
        session.create(1001, "T2").await.unwrap();

        session.logout("T1").await.unwrap();

        let as_ = session.get_account_session(1001).await.unwrap().unwrap();
        assert_eq!(as_.tokens.len(), 1);
        assert_eq!(as_.tokens[0].token, "T2");
    }

    /// 验证登出最后一个 token 后 Account-Session 保留（不删除，保留历史）。
    #[tokio::test]
    async fn account_session_keeps_history_when_empty() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();
        session.logout("T1").await.unwrap();

        // spec: 若列表为空，Account-Session 标记为空（但不删除，保留历史）
        let as_ = session.get_account_session(1001).await.unwrap();
        assert!(as_.is_some(), "Account-Session 应保留（保留历史）");
        assert!(as_.unwrap().tokens.is_empty());
    }

    // ------------------------------------------------------------------------
    // spec scenario: Token-Session 存储自定义属性
    // ------------------------------------------------------------------------

    /// 验证 set/get Token-Session 自定义属性。
    #[tokio::test]
    async fn token_session_stores_custom_attrs() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        session.set("T1", "ip", "192.168.1.1").await.unwrap();
        let ip = session.get("T1", "ip").await.unwrap();
        assert_eq!(ip, Some("192.168.1.1".to_string()));
    }

    /// 验证 set 不存在的 token 抛 InvalidToken。
    #[tokio::test]
    async fn set_attr_nonexistent_token_errors() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session.set("nonexistent", "ip", "1.2.3.4").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "set 不存在的 token 应返回 InvalidToken"
        );
    }

    // ------------------------------------------------------------------------
    // spec scenario: token 过期自动失效 / Activity 超时
    // ------------------------------------------------------------------------

    /// 验证 token 不存在时 is_valid 返回 false。
    #[tokio::test]
    async fn is_valid_returns_false_for_nonexistent_token() {
        let (_dao, session) = make_session(3600, 86400);
        let valid = session.is_valid("nonexistent").await.unwrap();
        assert!(!valid);
    }

    /// 验证 token 有效时 is_valid 返回 true。
    #[tokio::test]
    async fn is_valid_returns_true_for_active_token() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();
        let valid = session.is_valid("T1").await.unwrap();
        assert!(valid);
    }

    /// 验证 Account-Session 过期后 token 视为无效（惰性检查）。
    ///
    /// spec scenario "Activity 超时（Account-Session 级别）"：
    /// Account-Session 过期后，所有关联 token 失效。
    #[tokio::test]
    async fn is_valid_returns_false_when_account_session_expired() {
        let (dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        // 模拟 Account-Session 过期（oxcache TTL 到期自动删除）
        dao.delete(&account_key(1001)).await.unwrap();

        // Token-Session 仍存在，但 Account-Session 已过期 → is_valid 返回 false
        let token_exists = session.get_token_session("T1").await.unwrap();
        assert!(token_exists.is_some(), "Token-Session 仍应存在");
        let valid = session.is_valid("T1").await.unwrap();
        assert!(!valid, "Account-Session 过期后 token 应视为无效");
    }

    // ------------------------------------------------------------------------
    // spec scenario: 活跃续期 / 主动续期
    // ------------------------------------------------------------------------

    /// 验证 touch 更新 last_active_at 并重置 TTL。
    #[tokio::test]
    async fn touch_updates_last_active_and_renews_ttl() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        // 等待一小段时间，确保 touch 后 last_active_at 变化
        tokio::time::sleep(Duration::from_millis(1100)).await;

        session.touch("T1").await.unwrap();

        let ts = session.get_token_session("T1").await.unwrap().unwrap();
        assert!(
            ts.last_active_at > ts.created_at,
            "touch 后 last_active_at 应大于 created_at"
        );

        // Account-Session 的对应 TokenInfo 也应更新
        let as_ = session.get_account_session(1001).await.unwrap().unwrap();
        assert_eq!(as_.last_active_at, ts.last_active_at);
        let ti = as_.tokens.iter().find(|t| t.token == "T1").unwrap();
        assert_eq!(ti.last_active_at, ts.last_active_at);
    }

    /// 验证 renew 重置过期时间（token 短 TTL + renew 后仍有效）。
    ///
    /// spec scenario "主动续期重置过期时间"。
    #[tokio::test]
    async fn renew_resets_ttl() {
        // token TTL=3 秒，留足 margin 避免 sleep 精度问题
        let (_dao, session) = make_session(3, 86400);
        session.create(1001, "T1").await.unwrap();

        // 在过期前 renew（已过 1 秒，剩余 2 秒）
        tokio::time::sleep(Duration::from_secs(1)).await;
        session.renew("T1").await.unwrap();

        // renew 重置 TTL 为 3 秒；再 sleep 2 秒，距过期还有 1 秒 margin
        tokio::time::sleep(Duration::from_secs(2)).await;
        let valid = session.is_valid("T1").await.unwrap();
        assert!(
            valid,
            "renew 后 token 应仍有效（TTL 已重置，还有 1 秒 margin）"
        );
    }

    /// 验证 renew 不存在的 token 抛 InvalidToken。
    ///
    /// spec scenario "续期不存在的 token"。
    #[tokio::test]
    async fn renew_nonexistent_token_errors() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session.renew("nonexistent").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "renew 不存在的 token 应返回 InvalidToken"
        );
    }

    // ------------------------------------------------------------------------
    // spec scenario: 登出
    // ------------------------------------------------------------------------

    /// 验证 logout 删除 Token-Session。
    #[tokio::test]
    async fn logout_removes_token_session() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();
        session.logout("T1").await.unwrap();

        let ts = session.get_token_session("T1").await.unwrap();
        assert!(ts.is_none(), "logout 后 Token-Session 应删除");
    }

    /// 验证 logout_by_login_id 删除所有关联 token + Account-Session。
    #[tokio::test]
    async fn logout_by_login_id_removes_all() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();
        session.create(1001, "T2").await.unwrap();

        session.logout_by_login_id(1001).await.unwrap();

        // 两个 token 都删除
        assert!(session.get_token_session("T1").await.unwrap().is_none());
        assert!(session.get_token_session("T2").await.unwrap().is_none());
        // Account-Session 也删除
        assert!(session.get_account_session(1001).await.unwrap().is_none());
    }

    /// 验证 logout 不存在的 token 不报错（幂等）。
    #[tokio::test]
    async fn logout_nonexistent_token_is_noop() {
        let (_dao, session) = make_session(3600, 86400);
        // logout 不存在的 token 不应报错
        let result = session.logout("nonexistent").await;
        assert!(result.is_ok());
    }

    // ------------------------------------------------------------------------
    // 错误分支补充测试：反序列化失败 / touch 不存在的 token
    // ------------------------------------------------------------------------

    /// 验证 get_token_session 在 DAO 中存储了非法 JSON 时返回 Session 错误。
    ///
    /// 覆盖 `get_token_session` 中 `serde_json::from_str(&json).map_err(...)` 错误路径。
    #[tokio::test]
    async fn get_token_session_corrupt_json_errors() {
        let (dao, session) = make_session(3600, 86400);
        // 直接写入非法 JSON 到 token key
        dao.set(&token_key("corrupt"), "not-a-valid-json", 3600)
            .await
            .unwrap();
        let result = session.get_token_session("corrupt").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("反序列化 TokenSession 失败")),
            "非法 JSON 应返回 '反序列化 TokenSession 失败' 错误，实际: {:?}",
            result
        );
    }

    /// 验证 get_account_session 在 DAO 中存储了非法 JSON 时返回 Session 错误。
    ///
    /// 覆盖 `get_account_session` 中 `serde_json::from_str(&json).map_err(...)` 错误路径。
    #[tokio::test]
    async fn get_account_session_corrupt_json_errors() {
        let (dao, session) = make_session(3600, 86400);
        // 直接写入非法 JSON 到 account key
        dao.set(&account_key(2001), "{invalid-json", 3600)
            .await
            .unwrap();
        let result = session.get_account_session(2001).await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("反序列化 AccountSession 失败")),
            "非法 JSON 应返回 '反序列化 AccountSession 失败' 错误，实际: {:?}",
            result
        );
    }

    /// 验证 touch 不存在的 token 返回 InvalidToken 错误。
    ///
    /// 覆盖 `touch` 方法中 `ok_or_else(|| BulwarkError::InvalidToken(...))` 错误路径。
    #[tokio::test]
    async fn touch_nonexistent_token_errors() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session.touch("nonexistent").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "touch 不存在的 token 应返回 InvalidToken 错误"
        );
    }

    /// 验证 get 在 token 不存在时返回 None（不抛错）。
    ///
    /// 覆盖 `get` 方法中 `None => Ok(None)` 分支。
    #[tokio::test]
    async fn get_attr_nonexistent_token_returns_none() {
        let (_dao, session) = make_session(3600, 86400);
        let result = session.get("nonexistent", "key").await.unwrap();
        assert!(result.is_none(), "token 不存在时 get 属性应返回 None");
    }

    /// 验证 create 在已存在 Account-Session 时追加 token 而非覆盖。
    ///
    /// 覆盖 `create` 中 `unwrap_or_else` 的 Some 分支（读取已存在的 account）。
    /// 此场景实际已被 account_session_records_multiple_tokens 覆盖，
    /// 但此处显式断言已存在的 token 列表被保留。
    #[tokio::test]
    async fn create_appends_to_existing_account_session() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();
        session.create(1001, "T2").await.unwrap();
        session.create(1001, "T3").await.unwrap();

        let as_ = session.get_account_session(1001).await.unwrap().unwrap();
        assert_eq!(as_.tokens.len(), 3, "三次 login 后应有 3 个 token");
        assert_eq!(as_.tokens[0].token, "T1");
        assert_eq!(as_.tokens[1].token, "T2");
        assert_eq!(as_.tokens[2].token, "T3");
    }

    // ------------------------------------------------------------------------
    // 0.2.0 新增 spec scenario: Token-Session 存储 SSO ticket 引用
    // ------------------------------------------------------------------------

    /// 验证 link_sso_ticket / get_sso_ticket 往返。
    ///
    /// 对应 spec scenario "Token-Session 存储 SSO ticket 引用 (NEW - 0.2.0)"。
    #[tokio::test]
    async fn link_sso_ticket_stores_ticket_in_token_session() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        session
            .link_sso_ticket("T1", "ticket-abc-123")
            .await
            .unwrap();
        let ticket = session.get_sso_ticket("T1").await.unwrap();
        assert_eq!(ticket, Some("ticket-abc-123".to_string()));
    }

    /// 验证 get_sso_ticket 对未关联 ticket 的 token 返回 None。
    ///
    /// 对应 spec scenario "查询未关联 ticket 的 token"。
    #[tokio::test]
    async fn get_sso_ticket_returns_none_when_not_linked() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        let ticket = session.get_sso_ticket("T1").await.unwrap();
        assert!(ticket.is_none(), "未关联 ticket 时应返回 None");
    }

    /// 验证 get_sso_ticket 对不存在的 token 返回 None。
    #[tokio::test]
    async fn get_sso_ticket_returns_none_for_nonexistent_token() {
        let (_dao, session) = make_session(3600, 86400);
        let ticket = session.get_sso_ticket("nonexistent").await.unwrap();
        assert!(ticket.is_none(), "token 不存在时应返回 None");
    }

    // ------------------------------------------------------------------------
    // 0.2.0 新增 spec scenario: Token-Session 存储 OAuth2 access_token
    // ------------------------------------------------------------------------

    /// 验证 link_oauth2_token / get_oauth2_token 往返。
    ///
    /// 对应 spec scenario "Token-Session 存储 OAuth2 access_token (NEW - 0.2.0)"。
    #[tokio::test]
    async fn link_oauth2_token_stores_access_token_in_token_session() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        session
            .link_oauth2_token("T1", "access-token-xyz")
            .await
            .unwrap();
        let access_token = session.get_oauth2_token("T1").await.unwrap();
        assert_eq!(access_token, Some("access-token-xyz".to_string()));
    }

    /// 验证 get_oauth2_token 对未关联 access_token 的 token 返回 None。
    ///
    /// 对应 spec scenario "查询未关联 access_token 的 token"。
    #[tokio::test]
    async fn get_oauth2_token_returns_none_when_not_linked() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        let access_token = session.get_oauth2_token("T1").await.unwrap();
        assert!(access_token.is_none(), "未关联 access_token 时应返回 None");
    }

    /// 验证 get_oauth2_token 对不存在的 token 返回 None。
    #[tokio::test]
    async fn get_oauth2_token_returns_none_for_nonexistent_token() {
        let (_dao, session) = make_session(3600, 86400);
        let access_token = session.get_oauth2_token("nonexistent").await.unwrap();
        assert!(access_token.is_none(), "token 不存在时应返回 None");
    }

    // ------------------------------------------------------------------------
    // 0.2.0 新增 spec scenario: 临时凭证关联会话
    // ------------------------------------------------------------------------

    /// 验证 link_temp_credential / get_temp_credential 往返。
    #[tokio::test]
    async fn link_temp_credential_stores_key_in_token_session() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        let temp_key = "bulwark:temp:order:abc123";
        session.link_temp_credential("T1", temp_key).await.unwrap();
        let stored = session.get_temp_credential("T1").await.unwrap();
        assert_eq!(stored, Some(temp_key.to_string()));
    }

    /// 验证 get_temp_credential 对未关联的 token 返回 None。
    #[tokio::test]
    async fn get_temp_credential_returns_none_when_not_linked() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        let stored = session.get_temp_credential("T1").await.unwrap();
        assert!(stored.is_none(), "未关联临时凭证时应返回 None");
    }

    /// 验证 get_temp_credential 对不存在的 token 返回 None。
    #[tokio::test]
    async fn get_temp_credential_returns_none_for_nonexistent_token() {
        let (_dao, session) = make_session(3600, 86400);
        let stored = session.get_temp_credential("nonexistent").await.unwrap();
        assert!(stored.is_none(), "token 不存在时应返回 None");
    }

    // ------------------------------------------------------------------------
    // 0.2.0 新增 spec scenario: link 方法对不存在的 token 报错
    // ------------------------------------------------------------------------

    /// 验证 link_sso_ticket / link_oauth2_token / link_temp_credential
    /// 对不存在的 token 返回 InvalidToken 错误。
    #[tokio::test]
    async fn link_methods_return_error_for_nonexistent_token() {
        let (_dao, session) = make_session(3600, 86400);

        let r1 = session.link_sso_ticket("nonexistent", "ticket").await;
        assert!(
            matches!(r1, Err(BulwarkError::InvalidToken(_))),
            "link_sso_ticket 不存在的 token 应返回 InvalidToken"
        );

        let r2 = session
            .link_oauth2_token("nonexistent", "access-token")
            .await;
        assert!(
            matches!(r2, Err(BulwarkError::InvalidToken(_))),
            "link_oauth2_token 不存在的 token 应返回 InvalidToken"
        );

        let r3 = session
            .link_temp_credential("nonexistent", "temp-key")
            .await;
        assert!(
            matches!(r3, Err(BulwarkError::InvalidToken(_))),
            "link_temp_credential 不存在的 token 应返回 InvalidToken"
        );
    }

    // ------------------------------------------------------------------------
    // 0.2.0 新增 spec scenario: SSO ticket 销毁联动（logout 联动）
    // ------------------------------------------------------------------------

    /// 验证 logout 时联动删除 Token-Session 关联的 SSO ticket。
    ///
    /// 对应 spec scenario "SSO 会话集成"：logout 应销毁关联的 SSO ticket。
    #[tokio::test]
    async fn logout_destroys_linked_sso_ticket() {
        let (dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        // 在 dao 中预置 SSO ticket
        let sso_key = "bulwark:sso:ticket:ticket-abc-123";
        dao.set(sso_key, r#"{"login_id":1001,"client_id":1}"#, 60)
            .await
            .unwrap();
        // 关联 ticket 到 token
        session
            .link_sso_ticket("T1", "ticket-abc-123")
            .await
            .unwrap();
        // 确认 ticket 存在
        assert!(dao.get(sso_key).await.unwrap().is_some());

        // logout 应联动删除 SSO ticket
        session.logout("T1").await.unwrap();

        // SSO ticket 应已被删除
        assert!(
            dao.get(sso_key).await.unwrap().is_none(),
            "logout 后关联的 SSO ticket 应被删除"
        );
        // Token-Session 也应被删除
        assert!(session.get_token_session("T1").await.unwrap().is_none());
    }

    /// 验证 logout 未关联 SSO ticket 的 token 时，不影响 dao 中的 SSO keys。
    #[tokio::test]
    async fn logout_without_sso_ticket_does_not_affect_sso_keys() {
        let (dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        // 在 dao 中预置一个不相关的 SSO ticket
        let unrelated_sso_key = "bulwark:sso:ticket:other-ticket";
        dao.set(unrelated_sso_key, r#"{"login_id":2002,"client_id":2}"#, 60)
            .await
            .unwrap();

        // logout T1（未关联 sso_ticket）
        session.logout("T1").await.unwrap();

        // 不相关的 SSO ticket 应仍然存在
        assert!(
            dao.get(unrelated_sso_key).await.unwrap().is_some(),
            "logout 未关联 SSO ticket 的 token 不应影响其他 SSO keys"
        );
    }

    // ------------------------------------------------------------------------
    // 0.2.0 新增 spec scenario: 临时凭证过期联动（is_valid 联动）
    // ------------------------------------------------------------------------

    /// 验证 is_valid 在 token 关联的临时凭证仍存在时返回 true。
    ///
    /// 对应 spec scenario "临时凭证关联会话的自定义过期 (NEW - 0.2.0)"。
    #[tokio::test]
    async fn is_valid_returns_true_when_temp_credential_exists() {
        let (dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        // 在 dao 中预置临时凭证
        let temp_key = "bulwark:temp:order:abc123";
        dao.set(temp_key, "secret-value", 300).await.unwrap();
        // 关联临时凭证到 token
        session.link_temp_credential("T1", temp_key).await.unwrap();

        // 临时凭证仍存在，token 应有效
        let valid = session.is_valid("T1").await.unwrap();
        assert!(valid, "临时凭证存在时 token 应有效");
    }

    /// 验证 is_valid 在 token 关联的临时凭证已被删除时返回 false。
    ///
    /// 对应 spec scenario "临时凭证关联会话的自定义过期 (NEW - 0.2.0)"：
    /// "临时凭证过期后 T1 立即失效，不论 token 自身 timeout 是否到期"。
    #[tokio::test]
    async fn is_valid_returns_false_when_temp_credential_expired() {
        let (dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        // 在 dao 中预置临时凭证
        let temp_key = "bulwark:temp:order:abc123";
        dao.set(temp_key, "secret-value", 300).await.unwrap();
        session.link_temp_credential("T1", temp_key).await.unwrap();

        // 模拟临时凭证过期/被删除
        dao.delete(temp_key).await.unwrap();

        // 临时凭证已失效，token 应立即失效（即使 token 自身 timeout 未到期）
        let valid = session.is_valid("T1").await.unwrap();
        assert!(
            !valid,
            "临时凭证过期后 token 应立即失效，不论 token 自身 timeout 是否到期"
        );
    }

    /// 验证 is_valid 在 token 未关联临时凭证时返回 true（向后兼容）。
    #[tokio::test]
    async fn is_valid_returns_true_when_no_temp_credential_linked() {
        let (_dao, session) = make_session(3600, 86400);
        session.create(1001, "T1").await.unwrap();

        // 未关联临时凭证，token 应有效（0.1.0 既有行为不变）
        let valid = session.is_valid("T1").await.unwrap();
        assert!(valid, "未关联临时凭证时 token 有效性应遵循 0.1.0 既有行为");
    }
}
