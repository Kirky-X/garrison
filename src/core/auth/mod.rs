//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 认证逻辑模块，定义以 token 为入参的登录/登出核心抽象。
//!
//! [借鉴 Sa-Token] 登录认证核心逻辑，对应 Sa-Token 的 `StpLogic.login / logout` 方法。
//!
//! 0.2.0 将 API 改为 token-as-input，与 0.1.0 的 `BulwarkLogic`（依赖 task_local 上下文）解耦，
//! 便于 `protocol-jwt` 等协议层模块干净复用。

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;

use crate::core::token::Token;
use crate::error::{BulwarkError, BulwarkResult};
use crate::session::{BulwarkSession, TokenSession};

/// 身份切换权限校验 trait（L4 修复，依据安全审计 L4）。
///
/// `switch_to` 执行前调用 [`SwitchToGuard::check`] 校验是否允许切换。
/// 默认实现 [`DenyAllSwitchToGuard`] 拒绝所有切换（fail-closed 安全默认），
/// 调用方通过 [`AuthLogicDefault::with_switch_to_guard`] 注入自定义规则。
///
/// # 设计理由
///
/// 审计 L4 指出 `switch_to` 无权限校验，普通用户可切换到管理员身份。
/// 采用 guard trait 模式（而非硬编码权限规则）让调用方灵活定义授权策略，
/// 如基于角色、基于 PermissionChecker、或基于配置白名单。
///
/// # 示例
///
/// ```ignore
/// use std::sync::Arc;
/// use bulwark::core::auth::{AuthLogicDefault, SwitchToGuard, AllowAllSwitchToGuard};
/// use bulwark::error::BulwarkResult;
///
/// // 仅允许 admin 切换
/// struct AdminOnlyGuard;
/// #[async_trait::async_trait]
/// impl SwitchToGuard for AdminOnlyGuard {
///     async fn check(&self, original: &str, target: &str) -> BulwarkResult<()> {
///         if original.starts_with("admin:") {
///             Ok(())
///         } else {
///             Err(bulwark::error::BulwarkError::NotPermission(
///                 format!("{} 无权切换到 {}", original, target)
///             ))
///         }
///     }
/// }
///
/// let auth = AuthLogicDefault::new(session, token_handler, 3600)
///     .with_switch_to_guard(Arc::new(AdminOnlyGuard));
/// ```
#[async_trait]
pub trait SwitchToGuard: Send + Sync {
    /// 校验是否允许从 `original_login_id` 切换到 `target_login_id`。
    ///
    /// # 返回
    /// - `Ok(())`: 允许切换。
    /// - `Err(BulwarkError::NotPermission)`: 权限不足，拒绝切换。
    async fn check(&self, original_login_id: &str, target_login_id: &str) -> BulwarkResult<()>;
}

/// 拒绝所有切换的默认 guard（L4 修复，fail-closed 安全默认）。
///
/// 未通过 [`AuthLogicDefault::with_switch_to_guard`] 注入自定义 guard 时，
/// 所有 `switch_to` 调用都被拒绝。强制调用方显式配置权限规则。
pub struct DenyAllSwitchToGuard;

#[async_trait]
impl SwitchToGuard for DenyAllSwitchToGuard {
    async fn check(&self, _original: &str, _target: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotPermission(
            "switch_to 被拒绝：未配置 SwitchToGuard，默认 deny-all".to_string(),
        ))
    }
}

/// 允许所有切换的 guard（仅用于测试，生产环境禁止使用）。
///
/// L4 修复后现有测试通过此 guard 保持向后兼容行为。
#[cfg(test)]
pub struct AllowAllSwitchToGuard;

#[cfg(test)]
#[async_trait]
impl SwitchToGuard for AllowAllSwitchToGuard {
    async fn check(&self, _original: &str, _target: &str) -> BulwarkResult<()> {
        Ok(())
    }
}

/// 认证逻辑 trait，定义以 token 为入参的认证抽象。
///
/// 所有方法 MUST 使用 `async_trait` 标注，trait 绑定 `Send + Sync`。
/// 与 0.1.0 的 `BulwarkLogic` 解耦：不读取 `tokio::task_local`，所有方法显式接收 `token: &str`。
#[async_trait]
pub trait AuthLogic: Send + Sync {
    /// 执行登录操作，生成 token 并建立会话。
    ///
    /// # 参数
    /// - `id`: 登录主体标识（如用户 ID）。
    /// - `params`: 可选参数（如 device、timeout 等，由实现方解析）。
    ///
    /// # 返回
    /// - `Ok(String)`: 非空 token 字符串。
    async fn login(&self, id: &str, params: Option<&str>) -> BulwarkResult<String>;

    /// 执行登出操作，销毁指定 token 对应的会话。
    ///
    /// 幂等处理：不存在的 token 返回 `Ok(())`。
    async fn logout(&self, token: &str) -> BulwarkResult<()>;

    /// 检查 token 是否存在且未过期。
    async fn is_login(&self, token: &str) -> BulwarkResult<bool>;

    /// 获取 token 关联的登录主体标识。
    ///
    /// # 返回
    /// - `Ok(Some(id))`: token 有效且关联登录 ID。
    /// - `Ok(None)`: token 无效或已过期。
    async fn get_login_id(&self, token: &str) -> BulwarkResult<Option<String>>;

    /// 校验 token 有效性并返回关联的 login_id。
    ///
    /// 与 `get_login_id` 的区别：校验失败时抛错而非返回 `None`，适用于必须登录的场景。
    ///
    /// # 返回
    /// - `Ok(id)`: token 有效，返回关联 login_id。
    /// - `Err(BulwarkError::InvalidToken)`: token 无效或已过期。
    async fn verify_token(&self, token: &str) -> BulwarkResult<String>;

    /// 身份切换：在当前会话中切换到另一个 login_id。
    ///
    /// 验证当前 token 有效后，将 TokenSession 的 `login_id` 更新为 `target_login_id`，
    /// 同时将原始 `login_id` 存储到 `attrs["switched_from"]` 供审计追溯。
    ///
    /// # 参数
    /// - `token`: 当前有效的 token 字符串。
    /// - `target_login_id`: 要切换到的目标登录主体标识。
    ///
    /// # 错误
    /// - `BulwarkError::NotLogin`: token 无效或已过期。
    /// - `BulwarkError::InvalidParam`: `target_login_id` 为空字符串。
    ///
    /// # 默认实现
    /// 返回 `BulwarkError::NotImplemented`，由 `AuthLogicDefault` 覆盖。
    async fn switch_to(&self, _token: &str, _target_login_id: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(format!(
            "switch_to 未实现: {} 不支持身份切换",
            std::any::type_name::<Self>()
        )))
    }

    /// Token 置换：生成等价的新 token 替换旧 token。
    ///
    /// 新 token 与旧 token 具有相同的 `login_id`、`session attrs`、`剩余 TTL`，
    /// 但 token 字符串不同。旧 token 的 session 在新 session 创建成功后被删除。
    ///
    /// # 参数
    /// - `token`: 当前有效的 token 字符串。
    ///
    /// # 返回
    /// - `Ok(new_token)`: 新生成的等价 token。
    ///
    /// # 错误
    /// - `BulwarkError::NotLogin`: token 无效或已过期。
    ///
    /// # 默认实现
    /// 返回 `BulwarkError::NotImplemented`，由 `AuthLogicDefault` 覆盖。
    async fn renew_to_equivalent(&self, _token: &str) -> BulwarkResult<String> {
        Err(BulwarkError::NotImplemented(format!(
            "renew_to_equivalent 未实现: {} 不支持 token 置换",
            std::any::type_name::<Self>()
        )))
    }
}

/// `AuthLogic` 的默认实现，委托 `BulwarkSession`（会话管理）与 `core-token::Token`（token 生成与校验）。
///
/// 协议层模块无需自行实现会话存储逻辑，直接复用此默认实现。
pub struct AuthLogicDefault {
    /// 会话管理器。
    session: Arc<BulwarkSession>,
    /// Token 生成与校验处理器。
    token_handler: Arc<dyn Token>,
    /// 默认 token 有效期（秒）。
    timeout: i64,
    /// 是否启用 remember_me 扩展超时。
    remember_me_enabled: bool,
    /// remember_me 扩展超时秒数（默认 7776000 = 90 天）。
    remember_me_timeout: i64,
    /// 身份切换权限校验 guard（L4 修复，默认 DenyAllSwitchToGuard fail-closed）。
    switch_to_guard: Arc<dyn SwitchToGuard>,
}

impl AuthLogicDefault {
    /// 创建新的 `AuthLogicDefault` 实例。
    ///
    /// remember_me 默认禁用。使用 `with_remember_me` 启用扩展超时。
    ///
    /// # 安全默认（L4 修复）
    ///
    /// `switch_to_guard` 默认为 `DenyAllSwitchToGuard`（拒绝所有切换）。
    /// 调用方必须通过 [`with_switch_to_guard`](Self::with_switch_to_guard)
    /// 注入自定义 guard 才能启用 `switch_to` 功能。
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
            remember_me_enabled: false,
            remember_me_timeout: 7_776_000,
            switch_to_guard: Arc::new(DenyAllSwitchToGuard),
        }
    }

    /// 配置 remember_me 扩展超时。
    ///
    /// 启用后，`login` 时 params 含 `remember_me=true` 将使用 `remember_me_timeout` 作为
    /// Token-Session 的 TTL，否则使用默认 `timeout`。
    ///
    /// # 参数
    /// - `enabled`: 是否启用 remember_me。
    /// - `timeout`: remember_me 扩展超时秒数（应大于 `timeout`）。
    pub fn with_remember_me(mut self, enabled: bool, timeout: i64) -> Self {
        self.remember_me_enabled = enabled;
        self.remember_me_timeout = timeout;
        self
    }

    /// 注入身份切换权限校验 guard（L4 修复，依据安全审计 L4）。
    ///
    /// 默认为 `DenyAllSwitchToGuard`（拒绝所有切换）。调用方必须注入自定义 guard
    /// 才能启用 `switch_to` 功能。
    ///
    /// # 参数
    /// - `guard`: 实现 [`SwitchToGuard`] trait 的权限校验实例。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use bulwark::core::auth::{AuthLogicDefault, SwitchToGuard};
    /// use bulwark::error::{BulwarkError, BulwarkResult};
    ///
    /// struct AdminOnlyGuard;
    /// #[async_trait::async_trait]
    /// impl SwitchToGuard for AdminOnlyGuard {
    ///     async fn check(&self, original: &str, target: &str) -> BulwarkResult<()> {
    ///         if original.starts_with("admin:") {
    ///             Ok(())
    ///         } else {
    ///             Err(BulwarkError::NotPermission(format!("{} 无权切换", original)))
    ///         }
    ///     }
    /// }
    ///
    /// let auth = AuthLogicDefault::new(session, token_handler, 3600)
    ///     .with_switch_to_guard(Arc::new(AdminOnlyGuard));
    /// ```
    pub fn with_switch_to_guard(mut self, guard: Arc<dyn SwitchToGuard>) -> Self {
        self.switch_to_guard = guard;
        self
    }
}

/// 解析 params 中的 remember_me 参数。
///
/// params 格式为 URL query string（`key=value&key2=value2`）。
/// 仅当存在 `remember_me=true` 时返回 `true`，其他值或格式错误时静默返回 `false`（容错）。
fn parse_remember_me_param(params: Option<&str>) -> bool {
    match params {
        Some(p) if !p.is_empty() => {
            for pair in p.split('&') {
                let mut kv = pair.splitn(2, '=');
                if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                    if k.trim() == "remember_me" && v.trim() == "true" {
                        return true;
                    }
                }
            }
            false
        },
        _ => false,
    }
}

#[async_trait]
impl AuthLogic for AuthLogicDefault {
    async fn login(&self, id: &str, params: Option<&str>) -> BulwarkResult<String> {
        // R-session-lifecycle-005: 解析 remember_me 参数
        let remember_me = parse_remember_me_param(params);
        let effective_timeout = if remember_me && self.remember_me_enabled {
            self.remember_me_timeout
        } else {
            self.timeout
        };
        let token = self.token_handler.generate(id, effective_timeout)?;
        self.session.create(id, &token).await?;
        // R-session-lifecycle-005: remember_me 扩展 Token-Session TTL
        if effective_timeout != self.timeout {
            self.session
                .set_token_session_ttl(&token, effective_timeout as u64)
                .await?;
        }
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

    async fn switch_to(&self, token: &str, target_login_id: &str) -> BulwarkResult<()> {
        // 验证 target_login_id 非空
        if target_login_id.is_empty() {
            return Err(BulwarkError::InvalidParam(
                "target_login_id 不能为空".to_string(),
            ));
        }

        // 获取当前 TokenSession
        let mut ts = self
            .session
            .get_token_session(token)
            .await?
            .ok_or_else(|| BulwarkError::NotLogin("token 无效或已过期".to_string()))?;

        // L4 修复：执行权限校验（guard 默认 DenyAllSwitchToGuard，fail-closed）
        // 在修改 session 前校验，确保无权限时不产生任何副作用
        let original_login_id = ts.login_id.clone();
        self.switch_to_guard
            .check(&original_login_id, target_login_id)
            .await?;

        // 存储原始 login_id 到 attrs["switched_from"]
        ts.attrs
            .insert("switched_from".to_string(), original_login_id.clone());

        // 更新 login_id 为 target_login_id
        ts.login_id = target_login_id.to_string();
        ts.last_active_at = Utc::now().timestamp();

        // 保存更新后的 session 到 DAO（保留原 TTL）
        self.session.save_token_session(token, &ts).await?;

        // 确保 token 存在于目标 login_id 的 Account-Session 中
        //（否则 is_valid 检查会因 Account-Session 不存在而返回 false）
        self.session
            .ensure_token_in_account_session(target_login_id, token)
            .await?;

        // 审计日志
        // token 脱敏：仅记录前 8 字符
        let token_prefix = if token.len() >= 8 { &token[..8] } else { token };
        tracing::info!(
            original_login_id = %original_login_id,
            target_login_id = %target_login_id,
            token_prefix = %token_prefix,
            "身份切换: {} -> {}",
            original_login_id,
            target_login_id
        );

        Ok(())
    }

    async fn renew_to_equivalent(&self, token: &str) -> BulwarkResult<String> {
        // 1. 获取旧 TokenSession
        let old_ts = self
            .session
            .get_token_session(token)
            .await?
            .ok_or_else(|| BulwarkError::NotLogin("token 无效或已过期".to_string()))?;

        // 2. 查询剩余 TTL
        //    None 表示永久键（无 TTL），用 0 表示永久驻留
        let remaining_ttl = self.session.get_token_timeout(token).await?;
        let ttl_secs = remaining_ttl.map(|d| d.as_secs()).unwrap_or(0);

        // 3. 生成新 token（同 token_style + 同 login_id）
        let new_token = self
            .token_handler
            .generate(&old_ts.login_id, self.timeout)?;

        // 4. 构建新 TokenSession（复制 attrs + device + ip + user_agent + safe_services）
        let now = Utc::now().timestamp();
        let new_ts = TokenSession {
            token: new_token.clone(),
            login_id: old_ts.login_id.clone(),
            created_at: now,
            last_active_at: now,
            attrs: old_ts.attrs.clone(),
            device: old_ts.device.clone(),
            ip: old_ts.ip.clone(),
            user_agent: old_ts.user_agent.clone(),
            safe_services: old_ts.safe_services.clone(),
            #[cfg(feature = "dynamic-active-timeout")]
            dynamic_active_timeout: old_ts.dynamic_active_timeout,
        };

        // 5. 保存新 Token-Session with remaining TTL
        //    若此步失败，旧 session 保持不变
        self.session
            .create_token_session_with_ttl(&new_token, &new_ts, ttl_secs)
            .await?;

        // 6. 添加新 token 到 Account-Session
        //    若此步失败，旧 session 保持不变
        self.session
            .ensure_token_in_account_session(&old_ts.login_id, &new_token)
            .await?;

        // 7. 删除旧 token
        //    若删除失败，回滚新 token（防止双 token 共存），返回错误
        if let Err(e) = self.session.logout(token).await {
            let old_prefix = if token.len() >= 8 { &token[..8] } else { token };
            let new_prefix = if new_token.len() >= 8 {
                &new_token[..8]
            } else {
                &new_token
            };
            // 回滚：删除新创建的 token session，防止新旧 token 同时有效
            if let Err(rb_err) = self.session.logout(&new_token).await {
                tracing::error!(
                    error = %e,
                    rollback_error = %rb_err,
                    old_token_prefix = %old_prefix,
                    new_token_prefix = %new_prefix,
                    "renew_to_equivalent 删除旧 token 失败且回滚新 token 也失败，可能存在双 token 共存"
                );
            }
            return Err(BulwarkError::Internal(format!(
                "token 置换失败：删除旧 token session 出错，已回滚新 token（old_prefix={}...）",
                old_prefix
            )));
        }

        Ok(new_token)
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

        /// 查询 key 的剩余 TTL（供 renew_to_equivalent 测试使用）。
        ///
        /// - `Some(remaining)`: 键存在且设置了 TTL（expire_at - now）
        /// - `None`: 键不存在，或永久键（expire_at = None）
        async fn get_timeout(&self, key: &str) -> BulwarkResult<Option<Duration>> {
            let store = self.store.lock().await;
            match store.get(key) {
                Some((_, Some(deadline))) => {
                    let now = Instant::now();
                    if *deadline <= now {
                        Ok(None)
                    } else {
                        Ok(Some(*deadline - now))
                    }
                },
                _ => Ok(None),
            }
        }
    }

    /// 辅助函数：创建 AuthLogicDefault 实例（使用 UuidTokenStyle + MockDao）。
    /// 默认使用 DenyAllSwitchToGuard（L4 安全默认）。
    fn make_auth_logic(timeout: u64, active_timeout: u64) -> AuthLogicDefault {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao, timeout, active_timeout));
        let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
        AuthLogicDefault::new(session, token_handler, timeout as i64)
    }

    /// 辅助函数：创建 AuthLogicDefault 实例，注入 AllowAllSwitchToGuard（L4 测试用）。
    /// 生产环境禁止使用此函数，应注入自定义权限 guard。
    fn make_auth_logic_allow_switch(timeout: u64, active_timeout: u64) -> AuthLogicDefault {
        make_auth_logic(timeout, active_timeout)
            .with_switch_to_guard(Arc::new(AllowAllSwitchToGuard))
    }

    // ========================================================================
    // login 测试
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
    // logout 测试
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
    // is_login 测试
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
    // get_login_id 测试
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
    // verify_token 测试
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

    // ========================================================================
    // switch_to 测试
    // ========================================================================

    /// R-001: switch_to 更新 login_id 并存储 switched_from（使用 AllowAll guard）。
    #[tokio::test]
    async fn switch_to_updates_login_id_and_stores_switched_from() {
        let auth = make_auth_logic_allow_switch(3600, 86400);
        let token = auth.login("1001", None).await.unwrap();
        auth.switch_to(&token, "2002").await.unwrap();
        // get_login_id 应返回新的 login_id
        assert_eq!(
            auth.get_login_id(&token).await.unwrap(),
            Some("2002".to_string())
        );
        // attrs["switched_from"] 应存储原始 login_id
        let switched_from = auth.session.get(&token, "switched_from").await.unwrap();
        assert_eq!(switched_from, Some("1001".to_string()));
    }

    /// R-001: switch_to 后 token 仍然有效（is_login 返回 true）。
    #[tokio::test]
    async fn switch_to_preserves_token_validity() {
        let auth = make_auth_logic_allow_switch(3600, 86400);
        let token = auth.login("1001", None).await.unwrap();
        auth.switch_to(&token, "2002").await.unwrap();
        assert!(auth.is_login(&token).await.unwrap());
    }

    /// R-001: switch_to 无效 token 返回 NotLogin 错误。
    #[tokio::test]
    async fn switch_to_invalid_token_returns_not_login() {
        let auth = make_auth_logic_allow_switch(3600, 86400);
        let result = auth.switch_to("invalid-token", "2002").await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(_))),
            "无效 token 应返回 NotLogin，实际: {:?}",
            result
        );
    }

    /// R-001: switch_to 空 target_login_id 返回 InvalidParam 错误。
    #[tokio::test]
    async fn switch_to_empty_target_returns_invalid_param() {
        let auth = make_auth_logic_allow_switch(3600, 86400);
        let token = auth.login("1001", None).await.unwrap();
        let result = auth.switch_to(&token, "").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "空 target_login_id 应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// R-001: switch_to 后 verify_token 返回新的 login_id。
    #[tokio::test]
    async fn switch_to_verify_token_returns_new_login_id() {
        let auth = make_auth_logic_allow_switch(3600, 86400);
        let token = auth.login("1001", None).await.unwrap();
        auth.switch_to(&token, "9999").await.unwrap();
        assert_eq!(auth.verify_token(&token).await.unwrap(), "9999");
    }

    /// R-001: switch_to 多次切换，switched_from 记录最近一次的原始 login_id。
    #[tokio::test]
    async fn switch_to_multiple_times_updates_switched_from() {
        let auth = make_auth_logic_allow_switch(3600, 86400);
        let token = auth.login("1001", None).await.unwrap();
        // 第一次切换：1001 -> 2002
        auth.switch_to(&token, "2002").await.unwrap();
        assert_eq!(
            auth.session.get(&token, "switched_from").await.unwrap(),
            Some("1001".to_string())
        );
        // 第二次切换：2002 -> 3003
        auth.switch_to(&token, "3003").await.unwrap();
        assert_eq!(
            auth.get_login_id(&token).await.unwrap(),
            Some("3003".to_string())
        );
        // switched_from 应记录最近一次切换前的 login_id（2002）
        assert_eq!(
            auth.session.get(&token, "switched_from").await.unwrap(),
            Some("2002".to_string())
        );
    }

    /// R-001: switch_to 保留 TokenSession 的其他 attrs（不丢失已有属性）。
    #[tokio::test]
    async fn switch_to_preserves_existing_attrs() {
        let auth = make_auth_logic_allow_switch(3600, 86400);
        let token = auth.login("1001", None).await.unwrap();
        // 设置一个自定义 attr
        auth.session.set(&token, "device", "web").await.unwrap();
        // 执行 switch_to
        auth.switch_to(&token, "2002").await.unwrap();
        // 原有 attr 应保留
        let device = auth.session.get(&token, "device").await.unwrap();
        assert_eq!(device, Some("web".to_string()));
        // switched_from 应也存在
        let switched_from = auth.session.get(&token, "switched_from").await.unwrap();
        assert_eq!(switched_from, Some("1001".to_string()));
    }

    /// R-001: switch_to 默认实现返回 NotImplemented。
    #[tokio::test]
    async fn switch_to_default_impl_returns_not_implemented() {
        struct NoSwitchAuth;
        #[async_trait]
        impl AuthLogic for NoSwitchAuth {
            async fn login(&self, _id: &str, _params: Option<&str>) -> BulwarkResult<String> {
                Ok("token".to_string())
            }
            async fn logout(&self, _token: &str) -> BulwarkResult<()> {
                Ok(())
            }
            async fn is_login(&self, _token: &str) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn get_login_id(&self, _token: &str) -> BulwarkResult<Option<String>> {
                Ok(Some("id".to_string()))
            }
            async fn verify_token(&self, _token: &str) -> BulwarkResult<String> {
                Ok("id".to_string())
            }
        }
        let auth = NoSwitchAuth;
        let result = auth.switch_to("token", "target").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(_))),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    // ========================================================================
    // L4 新增：switch_to 权限校验测试（依据安全审计 L4）
    // ========================================================================

    /// L4: 默认 DenyAllSwitchToGuard 应拒绝所有 switch_to 调用（fail-closed）。
    #[tokio::test]
    async fn switch_to_default_guard_denies_all_switches() {
        let auth = make_auth_logic(3600, 86400); // 默认 DenyAllSwitchToGuard
        let token = auth.login("1001", None).await.unwrap();
        let result = auth.switch_to(&token, "2002").await;
        assert!(
            matches!(result, Err(BulwarkError::NotPermission(ref msg)) if msg.contains("deny-all")),
            "默认 guard 应拒绝切换并返回 NotPermission，实际: {:?}",
            result
        );
        // 验证 session 未被修改（login_id 仍为原值）
        assert_eq!(
            auth.get_login_id(&token).await.unwrap(),
            Some("1001".to_string())
        );
    }

    /// L4: 自定义 guard 拒绝时返回 NotPermission 且不修改 session。
    #[tokio::test]
    async fn switch_to_custom_guard_denies_preserves_session() {
        struct DenyTargetGuard;
        #[async_trait]
        impl SwitchToGuard for DenyTargetGuard {
            async fn check(&self, _original: &str, target: &str) -> BulwarkResult<()> {
                if target == "admin" {
                    return Err(BulwarkError::NotPermission(format!(
                        "禁止切换到管理员身份: {}",
                        target
                    )));
                }
                Ok(())
            }
        }
        let auth = make_auth_logic(3600, 86400).with_switch_to_guard(Arc::new(DenyTargetGuard));
        let token = auth.login("1001", None).await.unwrap();

        // 切换到 admin 应被拒绝
        let result = auth.switch_to(&token, "admin").await;
        assert!(
            matches!(result, Err(BulwarkError::NotPermission(ref msg)) if msg.contains("禁止切换")),
            "切换到 admin 应被拒绝，实际: {:?}",
            result
        );
        // session 未被修改
        assert_eq!(
            auth.get_login_id(&token).await.unwrap(),
            Some("1001".to_string())
        );

        // 切换到 普通用户 应成功
        auth.switch_to(&token, "user-2002").await.unwrap();
        assert_eq!(
            auth.get_login_id(&token).await.unwrap(),
            Some("user-2002".to_string())
        );
    }

    // ========================================================================
    // renew_to_equivalent 测试
    // ========================================================================

    /// R-003: renew_to_equivalent 返回新 token，新 token 有效且 login_id 相同。
    #[tokio::test]
    async fn renew_to_equivalent_returns_new_valid_token_with_same_login_id() {
        let auth = make_auth_logic(3600, 86400);
        let old_token = auth.login("1001", None).await.unwrap();
        let new_token = auth.renew_to_equivalent(&old_token).await.unwrap();
        // 新 token 非空
        assert!(!new_token.is_empty());
        // 新 token 有效
        assert!(auth.is_login(&new_token).await.unwrap());
        // login_id 相同
        assert_eq!(
            auth.get_login_id(&new_token).await.unwrap(),
            Some("1001".to_string())
        );
    }

    /// R-003: renew_to_equivalent 生成与旧 token 不同的字符串。
    #[tokio::test]
    async fn renew_to_equivalent_generates_different_token_string() {
        let auth = make_auth_logic(3600, 86400);
        let old_token = auth.login("1001", None).await.unwrap();
        let new_token = auth.renew_to_equivalent(&old_token).await.unwrap();
        assert_ne!(old_token, new_token);
    }

    /// R-004: renew_to_equivalent 后旧 token 失效（session 已删除）。
    #[tokio::test]
    async fn renew_to_equivalent_invalidates_old_token() {
        let auth = make_auth_logic(3600, 86400);
        let old_token = auth.login("1001", None).await.unwrap();
        assert!(auth.is_login(&old_token).await.unwrap());
        let _new_token = auth.renew_to_equivalent(&old_token).await.unwrap();
        // 旧 token 应已失效
        assert!(!auth.is_login(&old_token).await.unwrap());
    }

    /// R-003: renew_to_equivalent 保留旧 session 的 attrs。
    #[tokio::test]
    async fn renew_to_equivalent_preserves_attrs() {
        let auth = make_auth_logic(3600, 86400);
        let old_token = auth.login("1001", None).await.unwrap();
        // 设置自定义 attr
        auth.session
            .set(&old_token, "device", "web-chrome")
            .await
            .unwrap();
        auth.session.set(&old_token, "role", "admin").await.unwrap();
        // 置换
        let new_token = auth.renew_to_equivalent(&old_token).await.unwrap();
        // 新 token 应保留 attrs
        let device = auth.session.get(&new_token, "device").await.unwrap();
        assert_eq!(device, Some("web-chrome".to_string()));
        let role = auth.session.get(&new_token, "role").await.unwrap();
        assert_eq!(role, Some("admin".to_string()));
    }

    /// R-003: renew_to_equivalent 保留旧 session 的 device 字段。
    #[tokio::test]
    async fn renew_to_equivalent_preserves_device() {
        let auth = make_auth_logic(3600, 86400);
        let old_token = auth.login("1001", None).await.unwrap();
        // 设置 device
        auth.session
            .set_device(&old_token, "mobile-ios")
            .await
            .unwrap();
        // 置换
        let new_token = auth.renew_to_equivalent(&old_token).await.unwrap();
        // 新 token 应保留 device
        let ts = auth.session.get_token_session(&new_token).await.unwrap();
        assert!(ts.is_some(), "新 token session 应存在");
        assert_eq!(ts.unwrap().device, Some("mobile-ios".to_string()));
    }

    /// R-003: renew_to_equivalent 无效 token 返回 NotLogin 错误。
    #[tokio::test]
    async fn renew_to_equivalent_invalid_token_returns_not_login() {
        let auth = make_auth_logic(3600, 86400);
        let result = auth.renew_to_equivalent("invalid-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(_))),
            "无效 token 应返回 NotLogin，实际: {:?}",
            result
        );
    }

    /// R-003: renew_to_equivalent 继承剩余 TTL（不重置为原始 timeout）。
    #[tokio::test]
    async fn renew_to_equivalent_preserves_remaining_ttl() {
        // 手动构建 auth + dao，以便直接操作 DAO 的 TTL
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao.clone(), 3600, 86400));
        let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
        let auth = AuthLogicDefault::new(session, token_handler, 3600);

        let old_token = auth.login("1001", None).await.unwrap();

        // 手动缩短旧 token 的 TTL 到 100s（模拟部分过期）
        let token_session_key = format!("token:session:{}", old_token);
        dao.expire(&token_session_key, 100).await.unwrap();

        // 验证旧 token 剩余 TTL ≈ 100s
        let old_ttl = auth.session.get_token_timeout(&old_token).await.unwrap();
        assert!(old_ttl.is_some(), "旧 token 应有 TTL");
        let old_secs = old_ttl.unwrap().as_secs();
        assert!(old_secs <= 100, "旧 TTL 应 ≤ 100s，实际: {}", old_secs);

        // 置换
        let new_token = auth.renew_to_equivalent(&old_token).await.unwrap();

        // 新 token 的 TTL 应继承剩余 TTL（≈100s），而非重置为 3600s
        let new_ttl = auth.session.get_token_timeout(&new_token).await.unwrap();
        assert!(new_ttl.is_some(), "新 token 应有 TTL");
        let new_secs = new_ttl.unwrap().as_secs();
        assert!(
            new_secs <= 100,
            "新 TTL 应继承剩余 TTL (≤100s)，实际: {}（可能被重置为 3600s）",
            new_secs
        );
    }

    /// R-003: renew_to_equivalent 默认实现返回 NotImplemented。
    #[tokio::test]
    async fn renew_to_equivalent_default_impl_returns_not_implemented() {
        struct NoRenewAuth;
        #[async_trait]
        impl AuthLogic for NoRenewAuth {
            async fn login(&self, _id: &str, _params: Option<&str>) -> BulwarkResult<String> {
                Ok("token".to_string())
            }
            async fn logout(&self, _token: &str) -> BulwarkResult<()> {
                Ok(())
            }
            async fn is_login(&self, _token: &str) -> BulwarkResult<bool> {
                Ok(true)
            }
            async fn get_login_id(&self, _token: &str) -> BulwarkResult<Option<String>> {
                Ok(Some("id".to_string()))
            }
            async fn verify_token(&self, _token: &str) -> BulwarkResult<String> {
                Ok("id".to_string())
            }
        }
        let auth = NoRenewAuth;
        let result = auth.renew_to_equivalent("token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(_))),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    // ========================================================================
    // remember_me 测试
    // ========================================================================

    /// 辅助函数：创建带 remember_me 配置的 AuthLogicDefault 实例。
    fn make_auth_logic_with_remember_me(
        timeout: u64,
        active_timeout: u64,
        rm_enabled: bool,
        rm_timeout: i64,
    ) -> AuthLogicDefault {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao, timeout, active_timeout));
        let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
        AuthLogicDefault::new(session, token_handler, timeout as i64)
            .with_remember_me(rm_enabled, rm_timeout)
    }

    /// R-005: login with remember_me=true 且 enabled 时使用扩展超时。
    #[tokio::test]
    async fn login_with_remember_me_true_uses_extended_timeout() {
        let auth = make_auth_logic_with_remember_me(3600, 86400, true, 7_776_000);
        let token = auth.login("1001", Some("remember_me=true")).await.unwrap();
        // token 有效
        assert!(auth.is_login(&token).await.unwrap());
        // TTL 应接近 7776000s
        let ttl = auth.session.get_token_timeout(&token).await.unwrap();
        assert!(ttl.is_some(), "Token-Session 应有 TTL");
        let secs = ttl.unwrap().as_secs();
        assert!(
            secs > 3_600 && secs <= 7_776_000,
            "remember_me TTL 应接近 7776000s，实际: {}s",
            secs
        );
    }

    /// R-005: login with remember_me=true 但 disabled 时使用默认超时。
    #[tokio::test]
    async fn login_with_remember_me_true_but_disabled_uses_default_timeout() {
        let auth = make_auth_logic_with_remember_me(3600, 86400, false, 7_776_000);
        let token = auth.login("1001", Some("remember_me=true")).await.unwrap();
        let ttl = auth.session.get_token_timeout(&token).await.unwrap();
        assert!(ttl.is_some());
        let secs = ttl.unwrap().as_secs();
        assert!(
            secs <= 3600,
            "disabled 时 TTL 应为默认 3600s，实际: {}s",
            secs
        );
    }

    /// R-005: login with remember_me=false 使用默认超时。
    #[tokio::test]
    async fn login_with_remember_me_false_uses_default_timeout() {
        let auth = make_auth_logic_with_remember_me(3600, 86400, true, 7_776_000);
        let token = auth.login("1001", Some("remember_me=false")).await.unwrap();
        let ttl = auth.session.get_token_timeout(&token).await.unwrap();
        assert!(ttl.is_some());
        let secs = ttl.unwrap().as_secs();
        assert!(
            secs <= 3600,
            "remember_me=false 时 TTL 应为默认 3600s，实际: {}s",
            secs
        );
    }

    /// R-005: login with None params 使用默认超时。
    #[tokio::test]
    async fn login_with_none_params_uses_default_timeout() {
        let auth = make_auth_logic_with_remember_me(3600, 86400, true, 7_776_000);
        let token = auth.login("1001", None).await.unwrap();
        let ttl = auth.session.get_token_timeout(&token).await.unwrap();
        assert!(ttl.is_some());
        let secs = ttl.unwrap().as_secs();
        assert!(
            secs <= 3600,
            "None params 时 TTL 应为默认 3600s，实际: {}s",
            secs
        );
    }

    /// R-005: login with empty params 使用默认超时。
    #[tokio::test]
    async fn login_with_empty_params_uses_default_timeout() {
        let auth = make_auth_logic_with_remember_me(3600, 86400, true, 7_776_000);
        let token = auth.login("1001", Some("")).await.unwrap();
        let ttl = auth.session.get_token_timeout(&token).await.unwrap();
        assert!(ttl.is_some());
        let secs = ttl.unwrap().as_secs();
        assert!(
            secs <= 3600,
            "empty params 时 TTL 应为默认 3600s，实际: {}s",
            secs
        );
    }

    /// R-005: login with remember_me=true 与其他参数组合仍检测到 remember_me。
    #[tokio::test]
    async fn login_with_remember_me_and_other_params() {
        let auth = make_auth_logic_with_remember_me(3600, 86400, true, 7_776_000);
        let token = auth
            .login("1001", Some("remember_me=true&device=web"))
            .await
            .unwrap();
        let ttl = auth.session.get_token_timeout(&token).await.unwrap();
        assert!(ttl.is_some());
        let secs = ttl.unwrap().as_secs();
        assert!(
            secs > 3_600 && secs <= 7_776_000,
            "组合参数中 remember_me=true 应使用扩展 TTL，实际: {}s",
            secs
        );
    }

    /// R-005: login with malformed params 使用默认超时（容错）。
    #[tokio::test]
    async fn login_with_malformed_params_uses_default_timeout() {
        let auth = make_auth_logic_with_remember_me(3600, 86400, true, 7_776_000);
        let token = auth.login("1001", Some("malformed")).await.unwrap();
        let ttl = auth.session.get_token_timeout(&token).await.unwrap();
        assert!(ttl.is_some());
        let secs = ttl.unwrap().as_secs();
        assert!(
            secs <= 3600,
            "malformed params 时 TTL 应为默认 3600s，实际: {}s",
            secs
        );
    }

    /// R-005: parse_remember_me_param 各种输入解析正确。
    #[test]
    fn parse_remember_me_param_various_inputs() {
        assert!(parse_remember_me_param(Some("remember_me=true")));
        assert!(!parse_remember_me_param(Some("remember_me=false")));
        assert!(parse_remember_me_param(Some("remember_me=true&device=web")));
        assert!(parse_remember_me_param(Some("device=web&remember_me=true")));
        assert!(!parse_remember_me_param(Some("")));
        assert!(!parse_remember_me_param(None));
        assert!(!parse_remember_me_param(Some("remember_me=1")));
        assert!(!parse_remember_me_param(Some("malformed")));
    }
}
