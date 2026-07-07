//! 认证逻辑模块，定义以 token 为入参的登录/登出核心抽象。
//!
//! [借鉴 Sa-Token] 登录认证核心逻辑，对应 Sa-Token 的 `StpLogic.login / logout` 方法。
//!
//! 0.2.0 将 API 改为 token-as-input，与 0.1.0 的 `BulwarkLogic`（依赖 task_local 上下文）解耦，
//! 便于 `protocol-jwt` 等协议层模块干净复用。

use async_trait::async_trait;
use std::sync::Arc;

use crate::core::token::Token;
use crate::error::{BulwarkError, BulwarkResult};
use crate::session::BulwarkSession;

/// 认证逻辑 trait，定义以 token 为入参的认证抽象（依据 spec core-auth）。
///
/// 所有方法 MUST 使用 `async_trait` 标注，trait 绑定 `Send + Sync`。
/// 与 0.1.0 的 `BulwarkLogic` 解耦：不读取 `tokio::task_local`，所有方法显式接收 `token: &str`。
#[async_trait]
pub trait AuthLogic: Send + Sync {
    /// 执行登录操作，生成 token 并建立会话（依据 spec core-auth）。
    ///
    /// # 参数
    /// - `id`: 登录主体标识（如用户 ID）。
    /// - `params`: 可选参数（如 device、timeout 等，由实现方解析）。
    ///
    /// # 返回
    /// - `Ok(String)`: 非空 token 字符串。
    async fn login(&self, id: &str, params: Option<&str>) -> BulwarkResult<String>;

    /// 执行登出操作，销毁指定 token 对应的会话（依据 spec core-auth）。
    ///
    /// 幂等处理：不存在的 token 返回 `Ok(())`。
    async fn logout(&self, token: &str) -> BulwarkResult<()>;

    /// 检查 token 是否存在且未过期（依据 spec core-auth）。
    async fn is_login(&self, token: &str) -> BulwarkResult<bool>;

    /// 获取 token 关联的登录主体标识（依据 spec core-auth）。
    ///
    /// # 返回
    /// - `Ok(Some(id))`: token 有效且关联登录 ID。
    /// - `Ok(None)`: token 无效或已过期。
    async fn get_login_id(&self, token: &str) -> BulwarkResult<Option<String>>;

    /// 校验 token 有效性并返回关联的 login_id（依据 spec core-auth）。
    ///
    /// 与 `get_login_id` 的区别：校验失败时抛错而非返回 `None`，适用于必须登录的场景。
    ///
    /// # 返回
    /// - `Ok(id)`: token 有效，返回关联 login_id。
    /// - `Err(BulwarkError::InvalidToken)`: token 无效或已过期。
    async fn verify_token(&self, token: &str) -> BulwarkResult<String>;
}

/// `AuthLogic` 的默认实现，委托 `BulwarkSession`（会话管理）与 `core-token::Token`（token 生成与校验）（依据 spec core-auth）。
///
/// 协议层模块无需自行实现会话存储逻辑，直接复用此默认实现。
pub struct AuthLogicDefault {
    /// 会话管理器。
    session: Arc<BulwarkSession>,
    /// Token 生成与校验处理器。
    token_handler: Arc<dyn Token>,
    /// 默认 token 有效期（秒）。
    timeout: i64,
}

impl AuthLogicDefault {
    /// 创建新的 `AuthLogicDefault` 实例。
    ///
    /// # 参数
    /// - `session`: 会话管理器。
    /// - `token_handler`: Token 生成与校验处理器。
    /// - `timeout`: 默认 token 有效期（秒）。
    pub fn new(session: Arc<BulwarkSession>, token_handler: Arc<dyn Token>, timeout: i64) -> Self {
        Self {
            session,
            token_handler,
            timeout,
        }
    }
}

#[async_trait]
impl AuthLogic for AuthLogicDefault {
    async fn login(&self, id: &str, _params: Option<&str>) -> BulwarkResult<String> {
        let token = self.token_handler.generate(id, self.timeout)?;
        self.session.create(id, &token).await?;
        Ok(token)
    }

    async fn logout(&self, token: &str) -> BulwarkResult<()> {
        // 幂等处理：logout 不存在的 token 返回 Ok(())
        // session.logout 内部对不存在的 token 返回 Ok(())，直接委托
        self.session.logout(token).await
    }

    async fn is_login(&self, token: &str) -> BulwarkResult<bool> {
        self.session.is_valid(token).await
    }

    async fn get_login_id(&self, token: &str) -> BulwarkResult<Option<String>> {
        match self.session.get_token_session(token).await? {
            Some(ts) => Ok(Some(ts.login_id)),
            None => Ok(None),
        }
    }

    async fn verify_token(&self, token: &str) -> BulwarkResult<String> {
        match self.get_login_id(token).await? {
            Some(id) => Ok(id),
            None => Err(BulwarkError::InvalidToken("token 无效或已过期".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::token::UuidTokenStyle;
    use crate::dao::BulwarkDao;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use tokio::sync::Mutex;

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
            let mut store = self.store.lock().await;
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
                .await
                .insert(key.to_string(), (value.to_string(), expire_at));
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            let mut store = self.store.lock().await;
            match store.get_mut(key) {
                Some((existing, _)) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            let mut store = self.store.lock().await;
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
            self.store.lock().await.remove(key);
            Ok(())
        }
    }

    /// 辅助函数：创建 AuthLogicDefault 实例（使用 UuidTokenStyle + MockDao）。
    fn make_auth_logic(timeout: u64, active_timeout: u64) -> AuthLogicDefault {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao, timeout, active_timeout));
        let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
        AuthLogicDefault::new(session, token_handler, timeout as i64)
    }

    // ========================================================================
    // login 测试（依据 spec core-auth）
    // ========================================================================

    /// login 生成非空 token 并建立会话（spec Scenario）。
    #[tokio::test]
    async fn login_generates_token_and_session() {
        let auth = make_auth_logic(3600, 86400);
        let token = auth.login("1001", None).await.unwrap();
        assert!(!token.is_empty());
        // is_login 应返回 true
        assert!(auth.is_login(&token).await.unwrap());
    }

    /// login 后 get_login_id 返回关联 ID（spec Scenario）。
    #[tokio::test]
    async fn login_associates_login_id() {
        let auth = make_auth_logic(3600, 86400);
        let token = auth.login("2002", None).await.unwrap();
        let login_id = auth.get_login_id(&token).await.unwrap();
        assert_eq!(login_id, Some("2002".to_string()));
    }

    /// login 多次生成不同 token。
    #[tokio::test]
    async fn login_generates_unique_tokens() {
        let auth = make_auth_logic(3600, 86400);
        let t1 = auth.login("1001", None).await.unwrap();
        let t2 = auth.login("1001", None).await.unwrap();
        assert_ne!(t1, t2);
    }

    // ========================================================================
    // logout 测试（依据 spec core-auth）
    // ========================================================================

    /// logout 销毁指定 token 会话（spec Scenario）。
    #[tokio::test]
    async fn logout_destroys_session() {
        let auth = make_auth_logic(3600, 86400);
        let token = auth.login("1001", None).await.unwrap();
        assert!(auth.is_login(&token).await.unwrap());
        auth.logout(&token).await.unwrap();
        assert!(!auth.is_login(&token).await.unwrap());
    }

    /// logout 幂等处理无效 token（spec Scenario）。
    #[tokio::test]
    async fn logout_idempotent_for_invalid_token() {
        let auth = make_auth_logic(3600, 86400);
        // 不存在的 token 应返回 Ok(())
        let result = auth.logout("non-existent-token").await;
        assert!(result.is_ok());
    }

    /// logout 不影响同账号的其他 token（spec Scenario）。
    #[tokio::test]
    async fn logout_preserves_other_tokens() {
        let auth = make_auth_logic(3600, 86400);
        let t1 = auth.login("1001", None).await.unwrap();
        let t2 = auth.login("1001", None).await.unwrap();
        auth.logout(&t1).await.unwrap();
        // t2 仍应有效
        assert!(auth.is_login(&t2).await.unwrap());
        assert!(!auth.is_login(&t1).await.unwrap());
    }

    // ========================================================================
    // is_login 测试（依据 spec core-auth）
    // ========================================================================

    /// is_login 有效 token 返回 true（spec Scenario）。
    #[tokio::test]
    async fn is_login_valid_token_returns_true() {
        let auth = make_auth_logic(3600, 86400);
        let token = auth.login("1001", None).await.unwrap();
        assert!(auth.is_login(&token).await.unwrap());
    }

    /// is_login 无效 token 返回 false（spec Scenario）。
    #[tokio::test]
    async fn is_login_invalid_token_returns_false() {
        let auth = make_auth_logic(3600, 86400);
        assert!(!auth.is_login("invalid-token").await.unwrap());
    }

    // ========================================================================
    // get_login_id 测试（依据 spec core-auth）
    // ========================================================================

    /// get_login_id 有效 token 返回 Some(id)（spec Scenario）。
    #[tokio::test]
    async fn get_login_id_valid_token_returns_some() {
        let auth = make_auth_logic(3600, 86400);
        let token = auth.login("3003", None).await.unwrap();
        assert_eq!(
            auth.get_login_id(&token).await.unwrap(),
            Some("3003".to_string())
        );
    }

    /// get_login_id 无效 token 返回 None（spec Scenario）。
    #[tokio::test]
    async fn get_login_id_invalid_token_returns_none() {
        let auth = make_auth_logic(3600, 86400);
        assert_eq!(auth.get_login_id("invalid").await.unwrap(), None);
    }

    // ========================================================================
    // verify_token 测试（依据 spec core-auth）
    // ========================================================================

    /// verify_token 有效 token 返回 login_id（spec Scenario）。
    #[tokio::test]
    async fn verify_token_valid_returns_login_id() {
        let auth = make_auth_logic(3600, 86400);
        let token = auth.login("4004", None).await.unwrap();
        assert_eq!(auth.verify_token(&token).await.unwrap(), "4004".to_string());
    }

    /// verify_token 无效 token 返回 InvalidToken 错误（spec Scenario）。
    #[tokio::test]
    async fn verify_token_invalid_returns_error() {
        let auth = make_auth_logic(3600, 86400);
        let result = auth.verify_token("invalid-token").await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidToken(_)) => {},
            other => panic!("期望 InvalidToken，实际: {:?}", other),
        }
    }

    /// verify_token 已过期 token 返回错误（spec Scenario）。
    #[tokio::test]
    async fn verify_token_expired_returns_error() {
        let auth = make_auth_logic(1, 1);
        let token = auth.login("5005", None).await.unwrap();
        // 等待 token 过期（timeout=1s + active_timeout=1s）
        tokio::time::sleep(Duration::from_secs(2)).await;
        let result = auth.verify_token(&token).await;
        assert!(result.is_err());
    }
}
