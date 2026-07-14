//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! PasswordLogic trait — 密码登录契约。
//! 从 v0.5.2 起，从 `BulwarkLogic` 上帝 trait 拆分；本 trait 承接密码登录 1 个方法。
//! super-trait 为 [`SessionLogic`]（密码校验通过后调用
//! [`login`](SessionLogic::login) 签发 token）。
//!
//! # v0.5.2 LoginId 迁移：删除 LoginId newtype，全栈使用 String/&str
//!
//! `login_id` 参数从 `i64` 迁移为 `&str`（字符串形式，对象安全）。

use super::BulwarkLogicDefault;
#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
use super::LoginParams;
#[cfg(all(
    feature = "listener",
    feature = "account-credential",
    feature = "db-sqlite"
))]
use crate::constants::EventReason;
use crate::error::{BulwarkError, BulwarkResult};
#[cfg(all(
    feature = "listener",
    feature = "account-credential",
    feature = "db-sqlite"
))]
use crate::listener::BulwarkEvent;
use crate::stp::session::SessionLogic;
use async_trait::async_trait;

/// 密码逻辑 trait，定义密码登录契约。
///
/// # 默认实现
///
/// [`login_with_password`](Self::login_with_password) 默认返回 `NotImplemented`
/// （未启用 `account-credential` + `db-sqlite` feature）。
/// 由 `BulwarkLogicDefault` 的 impl 覆写为：
/// 1) `UserRepository::find_by_username` 查询用户
/// 2) `PasswordHasher::verify` 校验密码
/// 3) 调用 [`SessionLogic::login`] 签发 token
///
/// # 安全约束
///
/// 用户不存在与密码错误统一返回 `InvalidParam("invalid password")`，
/// 日志和事件 reason 统一为 "invalid_credentials"（v0.4.2 安全审计 A-014），
/// 防止攻击者通过返回值或日志差异进行用户枚举。
#[async_trait]
pub trait PasswordLogic: SessionLogic {
    /// 密码登录：校验密码后签发 token。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识引用（字符串形式，作为 username 查询 `UserRepository`）。
    /// - `password`: 明文密码（仅校验时临时持有，不存储）。
    ///
    /// # 返回
    /// - `Ok(token)`: 密码校验通过，返回新签发的 token 字符串。
    ///
    /// # 错误
    /// - 未启用 `account-credential` + `db-sqlite` feature：`BulwarkError::NotImplemented`。
    /// - 未注入 `password_hasher`：`BulwarkError::Config("password hasher not configured")`。
    /// - 未注入 `user_repository`：`BulwarkError::Config("user repository not configured")`。
    /// - 用户不存在 / 密码错误：`BulwarkError::InvalidParam("invalid password")`
    ///   （不泄露具体原因，防止用户枚举）。
    /// - 哈希格式不支持：`BulwarkError::InvalidParam("unsupported hash format")`。
    /// - DAO 查询失败：透传 `BulwarkError::Dao`。
    async fn login_with_password(&self, _login_id: &str, _password: &str) -> BulwarkResult<String> {
        Err(BulwarkError::NotImplemented(
            "login_with_password 未实现：需启用 account-credential + db-sqlite feature".to_string(),
        ))
    }
}

// ============================================================================
// BulwarkLogicDefault impl
// ============================================================================

#[async_trait]
impl PasswordLogic for BulwarkLogicDefault {
    /// 密码登录实现：校验密码后调用 [`login`](Self::login) 签发 token。
    ///
    /// R-002：1) UserRepository 查询 2) PasswordHasher 校验 3) login 签发。
    /// 安全约束：用户不存在与密码错误统一返回 `InvalidParam("invalid password")`，真实原因记录在 tracing 日志。
    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    async fn login_with_password(&self, login_id: &str, password: &str) -> BulwarkResult<String> {
        let hasher = self
            .password_hasher
            .as_ref()
            .ok_or_else(|| BulwarkError::Config("password hasher not configured".to_string()))?;
        let repo = self
            .user_repository
            .as_ref()
            .ok_or_else(|| BulwarkError::Config("user repository not configured".to_string()))?;

        // 1. 查询用户（login_id 转字符串作为 username 查询）
        let username = login_id.to_string();
        let user = repo
            .find_by_username(0, &username)
            .await
            .map_err(|e| BulwarkError::Dao(format!("login_with_password 查询用户失败: {}", e)))?;

        let user = match user {
            Some(u) => u,
            None => {
                // v0.4.2 安全审计 A-014: 日志和事件统一为 "invalid_credentials"，
                // 不区分 user_not_found/wrong_password，防止日志泄露用户存在性
                tracing::warn!(
                    login_id = login_id,
                    reason = "invalid_credentials",
                    "login_with_password 失败"
                );
                // 广播 LoginFailure 事件
                #[cfg(feature = "listener")]
                if let Some(lm) = &self.listener_manager {
                    lm.broadcast(&BulwarkEvent::LoginFailure {
                        login_id: login_id.to_string(),
                        reason: EventReason::InvalidCredentials.to_string(),
                        request_context: None,
                    })
                    .await;
                }
                return Err(BulwarkError::InvalidParam("invalid password".to_string()));
            },
        };

        // 2. 校验密码（哈希格式不支持返回 "unsupported hash format"，可泄露）
        let verified = hasher.verify(password, &user.password_hash).map_err(|e| {
            tracing::warn!(
                login_id = login_id,
                reason = "hash_format_error",
                error = %e,
                "login_with_password 密码哈希格式不支持"
            );
            BulwarkError::InvalidParam("unsupported hash format".to_string())
        })?;

        if !verified {
            // v0.4.2 安全审计 A-014: 日志和事件统一为 "invalid_credentials"，
            // 不区分 user_not_found/wrong_password，防止日志泄露用户存在性
            tracing::warn!(
                login_id = login_id,
                reason = "invalid_credentials",
                "login_with_password 失败"
            );
            // 广播 LoginFailure 事件
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                lm.broadcast(&BulwarkEvent::LoginFailure {
                    login_id: login_id.to_string(),
                    reason: EventReason::InvalidCredentials.to_string(),
                    request_context: None,
                })
                .await;
            }
            return Err(BulwarkError::InvalidParam("invalid password".to_string()));
        }

        // 3. 调用 login 签发 token（触发 plugin/listener auto-wire）
        self.login(login_id, &LoginParams::default()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BulwarkConfig;
    use crate::error::BulwarkResult;
    use crate::stp::core::BulwarkCore;
    use crate::stp::session::SessionLogic;
    use std::sync::Arc;

    /// 最小 mock：实现 `BulwarkCore` + `SessionLogic`（9 必需方法）。
    /// `PasswordLogic` 1 个方法有默认实现，空 impl 即可获得默认行为。
    struct MockPassword {
        config: Arc<BulwarkConfig>,
    }

    impl BulwarkCore for MockPassword {
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockPassword {
        async fn login(
            &self,
            _login_id: &str,
            _params: &crate::stp::LoginParams,
        ) -> BulwarkResult<String> {
            Ok("mock-token".to_string())
        }
        async fn login_with_token(&self, _login_id: &str, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout(&self) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout_by_login_id(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout_by_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn revoke_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> BulwarkResult<bool> {
            Ok(true)
        }
        async fn get_login_id(&self) -> BulwarkResult<Option<String>> {
            Ok(Some("42".to_string()))
        }
    }

    #[async_trait]
    impl PasswordLogic for MockPassword {}

    #[tokio::test]
    async fn login_with_password_default_returns_not_implemented() {
        let mock = MockPassword {
            config: Arc::new(BulwarkConfig::default()),
        };
        let id = "alice";
        let result = mock.login_with_password(id, "secret").await;
        assert!(matches!(result, Err(BulwarkError::NotImplemented(_))));
    }

    // ========================================================================
    // BulwarkLogicDefault impl 覆盖测试（cfg-gated: account-credential + db-sqlite）
    // 覆盖 hasher/repo 未注入 + listener_manager 广播 LoginFailure 路径
    // ========================================================================

    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    mod default_impl_coverage {
        use super::*;
        use crate::account::credential::{Argon2Hasher, PasswordHasher};
        use crate::config::BulwarkConfig;
        use crate::dao::repository::{UserRepository, UserRow};
        use crate::dao::BulwarkDao;
        use crate::listener::{BulwarkEvent, BulwarkListener, BulwarkListenerManager};
        use crate::session::BulwarkSession;
        use crate::stp::mock::{MockDao, MockFirewall, MockUserRepository};
        use crate::strategy::BulwarkPermissionStrategy;
        use async_trait::async_trait;
        use parking_lot::Mutex;
        use std::sync::Arc;

        /// 记录事件监听器，捕获广播的 BulwarkEvent 用于断言。
        struct RecordingListener {
            events: Mutex<Vec<BulwarkEvent>>,
        }

        impl RecordingListener {
            fn new() -> Self {
                Self {
                    events: Mutex::new(Vec::new()),
                }
            }

            fn captured(&self) -> Vec<BulwarkEvent> {
                self.events.lock().clone()
            }
        }

        #[async_trait]
        impl BulwarkListener for RecordingListener {
            async fn on_event(&self, event: &BulwarkEvent) -> crate::error::BulwarkResult<()> {
                self.events.lock().push(event.clone());
                Ok(())
            }
        }

        fn make_user_row(login_id: &str, password_hash: &str) -> UserRow {
            UserRow {
                id: format!("u-{}", login_id),
                username: login_id.to_string(),
                password_hash: password_hash.to_string(),
                status: "active".to_string(),
                tenant_id: 0,
                created_at: "2026-07-04T00:00:00Z".to_string(),
                updated_at: "2026-07-04T00:00:00Z".to_string(),
                last_login_at: None,
            }
        }

        /// 构造 BulwarkLogicDefault（不注入 hasher/repo，测试 Config 错误路径）。
        fn make_logic_without_creds() -> BulwarkLogicDefault {
            let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
            let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
            let mut config = BulwarkConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            BulwarkLogicDefault::new(session, Arc::new(config), firewall)
        }

        /// 未注入 password_hasher 时返回 Config("password hasher not configured")。
        ///
        /// 覆盖 password.rs 第 86-89 行 `hasher.as_ref().ok_or_else(...)` 路径。
        #[tokio::test]
        async fn login_with_password_missing_hasher_returns_config_error() {
            let logic = make_logic_without_creds();
            // 注入 repo 但不注入 hasher
            let repo: Arc<dyn UserRepository> = Arc::new(MockUserRepository::new());
            let logic = logic.with_user_repository(repo);

            let result = logic.login_with_password("alice", "any").await;
            assert!(
                matches!(result, Err(BulwarkError::Config(ref msg)) if msg == "password hasher not configured"),
                "未注入 hasher 应返回 Config(\"password hasher not configured\")，实际: {:?}",
                result
            );
        }

        /// 未注入 user_repository 时返回 Config("user repository not configured")。
        ///
        /// 覆盖 password.rs 第 90-93 行 `repo.as_ref().ok_or_else(...)` 路径。
        #[tokio::test]
        async fn login_with_password_missing_repo_returns_config_error() {
            let logic = make_logic_without_creds();
            // 注入 hasher 但不注入 repo
            let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());
            let logic = logic.with_password_hasher(hasher);

            let result = logic.login_with_password("alice", "any").await;
            assert!(
                matches!(result, Err(BulwarkError::Config(ref msg)) if msg == "user repository not configured"),
                "未注入 repo 应返回 Config(\"user repository not configured\")，实际: {:?}",
                result
            );
        }

        /// 用户不存在 + listener_manager 注入 → 广播 LoginFailure 事件。
        ///
        /// 覆盖 password.rs 第 113-121 行 `#[cfg(feature = "listener")] lm.broadcast(LoginFailure)` 路径。
        #[cfg(feature = "listener")]
        #[tokio::test]
        async fn login_with_password_user_not_found_broadcasts_login_failure() {
            let logic = make_logic_without_creds();
            let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());
            let repo: Arc<dyn UserRepository> = Arc::new(MockUserRepository::new()); // 空仓库
            let recorder = Arc::new(RecordingListener::new());
            let lm = Arc::new(BulwarkListenerManager::new());
            lm.register(recorder.clone() as Arc<dyn BulwarkListener>);

            let logic = logic
                .with_password_hasher(hasher)
                .with_user_repository(repo)
                .with_listener_manager(lm);

            let result = logic.login_with_password("missing-user", "any").await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidParam(ref msg)) if msg == "invalid password"),
                "用户不存在应返回 InvalidParam(\"invalid password\")，实际: {:?}",
                result
            );

            // 验证广播了 LoginFailure 事件
            let events = recorder.captured();
            let failure_count = events
                .iter()
                .filter(|e| matches!(e, BulwarkEvent::LoginFailure { .. }))
                .count();
            assert_eq!(
                failure_count, 1,
                "应广播 1 次 LoginFailure 事件，实际广播: {} 次",
                failure_count
            );
            // 验证事件 reason 为 "invalid_credentials"（防用户枚举）
            if let Some(BulwarkEvent::LoginFailure {
                login_id, reason, ..
            }) = events.first()
            {
                assert_eq!(login_id, "missing-user");
                assert_eq!(
                    reason, "invalid_credentials",
                    "reason 应为 'invalid_credentials'（防用户枚举），实际: {}",
                    reason
                );
            }
        }

        /// 密码错误 + listener_manager 注入 → 广播 LoginFailure 事件。
        ///
        /// 覆盖 password.rs 第 145-153 行 `#[cfg(feature = "listener")] lm.broadcast(LoginFailure)` 路径。
        #[cfg(feature = "listener")]
        #[tokio::test]
        async fn login_with_password_wrong_password_broadcasts_login_failure() {
            let logic = make_logic_without_creds();
            let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());
            let hash = hasher.hash("correct-password").unwrap();
            let mock_repo = MockUserRepository::new();
            mock_repo.insert(make_user_row("1001", &hash));
            let repo: Arc<dyn UserRepository> = Arc::new(mock_repo);
            let recorder = Arc::new(RecordingListener::new());
            let lm = Arc::new(BulwarkListenerManager::new());
            lm.register(recorder.clone() as Arc<dyn BulwarkListener>);

            let logic = logic
                .with_password_hasher(hasher)
                .with_user_repository(repo)
                .with_listener_manager(lm);

            let result = logic.login_with_password("1001", "wrong-password").await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidParam(ref msg)) if msg == "invalid password"),
                "错误密码应返回 InvalidParam(\"invalid password\")，实际: {:?}",
                result
            );

            // 验证广播了 LoginFailure 事件，reason 为 "invalid_credentials"
            let events = recorder.captured();
            if let Some(BulwarkEvent::LoginFailure {
                login_id, reason, ..
            }) = events.first()
            {
                assert_eq!(login_id, "1001");
                assert_eq!(
                    reason, "invalid_credentials",
                    "reason 应为 'invalid_credentials'，实际: {}",
                    reason
                );
            } else {
                panic!("应广播 LoginFailure 事件，实际捕获: {:?}", events);
            }
        }

        /// 哈希格式不支持 → 返回 InvalidParam("unsupported hash format")。
        ///
        /// 覆盖 password.rs 第 127-135 行 `hasher.verify(...).map_err(...)` 返回 Err 路径。
        #[tokio::test]
        async fn login_with_password_unsupported_hash_format_returns_error() {
            let logic = make_logic_without_creds();
            let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());
            let mock_repo = MockUserRepository::new();
            // 插入格式非法的 password_hash（非 Argon2/Bcrypt 格式）
            mock_repo.insert(make_user_row("1002", "not-a-valid-hash-format"));
            let repo: Arc<dyn UserRepository> = Arc::new(mock_repo);

            let logic = logic
                .with_password_hasher(hasher)
                .with_user_repository(repo);

            let result = logic.login_with_password("1002", "any-password").await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidParam(ref msg)) if msg == "unsupported hash format"),
                "哈希格式不支持应返回 InvalidParam(\"unsupported hash format\")，实际: {:?}",
                result
            );
        }

        /// 用户存在 + 密码正确 → 返回 Ok(token)。
        ///
        /// 覆盖 password.rs 第 158-160 行成功登录路径（调用 login 签发 token）。
        #[tokio::test]
        async fn login_with_password_correct_credentials_returns_token() {
            let logic = make_logic_without_creds();
            let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());
            let hash = hasher.hash("correct-password").unwrap();
            let mock_repo = MockUserRepository::new();
            mock_repo.insert(make_user_row("1003", &hash));
            let repo: Arc<dyn UserRepository> = Arc::new(mock_repo);

            let logic = logic
                .with_password_hasher(hasher)
                .with_user_repository(repo);

            let result = logic.login_with_password("1003", "correct-password").await;
            assert!(
                result.is_ok(),
                "用户存在 + 密码正确应返回 Ok(token)，实际: {:?}",
                result
            );
            let token = result.unwrap();
            assert!(!token.is_empty(), "返回的 token 不应为空字符串");
        }
    }
}
