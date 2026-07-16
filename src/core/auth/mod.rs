//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 认证逻辑模块，定义以 token 为入参的登录/登出核心抽象。
//!
//! 登录认证核心逻辑，对应 `StpLogic.login / logout` 方法。
//!
//! 0.2.0 将 API 改为 token-as-input，与 0.1.0 的 `BulwarkLogic`（依赖 task_local 上下文）解耦，
//! 便于 `protocol-jwt` 等协议层模块干净复用。

use async_trait::async_trait;
use std::sync::Arc;

use crate::core::token::Token;
use crate::error::{BulwarkError, BulwarkResult};
use crate::session::BulwarkSession;

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
/// # Security Warning
///
/// `switch_to` 是高风险操作：若 [`SwitchToGuard::check`] 直接返回 `Ok(())`，
/// 任何身份都可切换到任意目标身份（含管理员），造成**垂直越权**。
/// 实现方必须校验至少以下三项：
///
/// 1. **original 权限**：调用方是否具备 `switch_to` 权限（如 `admin:switch`）
/// 2. **target 可切换范围**：target 是否在允许切换的集合内（如同一租户、下级账号）
/// 3. **审计日志**：每次 switch_to 记录 `original / target / timestamp / request_context`，
///    便于事后追溯
///
/// 推荐参考 [`AdminOnlyGuard`] 示例实现，而非裸用 [`AllowAllSwitchToGuard`]。
///
/// # 示例
///
/// ```ignore
/// use std::sync::Arc;
/// use bulwark::core::auth::{AuthLogicDefault, SwitchToGuard};
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
/// # Deprecated
///
/// 裸用此 guard 等价于关闭 switch_to 权限校验，任何身份可切换到任意
/// 目标身份（含管理员），构成垂直越权风险。测试代码也应实现自定义 guard，参考
/// [`AdminOnlyGuard`] doctest 示例。
///
/// 若必须使用（如遗留测试），需在调用处加 `#[allow(deprecated)]` 抑制警告，例如：
///
/// ```ignore
/// # use bulwark::core::auth::AllowAllSwitchToGuard;
/// # use std::sync::Arc;
/// # #[allow(deprecated)]
/// let _guard = Arc::new(AllowAllSwitchToGuard);
/// ```
#[cfg(test)]
#[deprecated(
    since = "0.7.0",
    note = "测试代码也应实现自定义 guard，禁止裸用 AllowAllSwitchToGuard；参考 SwitchToGuard trait 的 AdminOnlyGuard doctest 示例"
)]
pub struct AllowAllSwitchToGuard;

#[cfg(test)]
#[allow(deprecated)]
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

mod default;

#[cfg(test)]
pub(super) use default::parse_remember_me_param;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests {
    use super::mock::MockDao;
    use super::*;
    use crate::core::token::UuidTokenStyle;
    use crate::dao::BulwarkDao;
    use async_trait::async_trait;
    use std::time::Duration;

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
    /// `#[allow(deprecated)]` 抑制 deprecated 警告（测试专用）。
    #[allow(deprecated)]
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
        // ensure_token_in_account_session 拒绝创建新 Account-Session，
        // 需预先 login target 以确保其 Account-Session 存在。
        let _ = auth.login("2002", None).await.unwrap();
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
        // 需预先创建 target Account-Session。
        let _ = auth.login("2002", None).await.unwrap();
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
        // 需预先创建 target Account-Session。
        let _ = auth.login("9999", None).await.unwrap();
        auth.switch_to(&token, "9999").await.unwrap();
        assert_eq!(auth.verify_token(&token).await.unwrap(), "9999");
    }

    /// R-001: switch_to 多次切换，switched_from 记录最近一次的原始 login_id。
    #[tokio::test]
    async fn switch_to_multiple_times_updates_switched_from() {
        let auth = make_auth_logic_allow_switch(3600, 86400);
        let token = auth.login("1001", None).await.unwrap();
        // 需预先创建 target Account-Session（2002 + 3003）。
        let _ = auth.login("2002", None).await.unwrap();
        let _ = auth.login("3003", None).await.unwrap();
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
        // 需预先创建 target Account-Session。
        let _ = auth.login("2002", None).await.unwrap();
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
        // 需预先创建 target Account-Session（user-2002）。
        let _ = auth.login("user-2002", None).await.unwrap();

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
    // renew_to_equivalent 原子化测试（先失效旧 token，再创建新 token）
    // ========================================================================

    /// 追踪 DAO 操作顺序的 wrapper。
    ///
    /// 包装 `MockDao`，在 `set("token:session:*")` 时检测旧 token 是否已被 `delete`。
    /// 若旧 token 未先失效就创建新 token，标记 `violation_detected = true`。
    struct OrderTrackingDao {
        inner: MockDao,
        tracking_state: std::sync::Mutex<OrderTrackingState>,
    }

    struct OrderTrackingState {
        /// 是否开始追踪（仅在 renew_to_equivalent 期间启用）。
        enabled: bool,
        /// 旧 token（用于检测 delete("token:session:{old_token}") 是否已调用）。
        old_token: String,
        /// 旧 token 的 session key 是否已被 delete。
        old_token_deleted: bool,
        /// 是否检测到违规（set(new) 在 delete(old) 之前）。
        violation_detected: bool,
    }

    impl OrderTrackingDao {
        fn new() -> Self {
            Self {
                inner: MockDao::new(),
                tracking_state: std::sync::Mutex::new(OrderTrackingState {
                    enabled: false,
                    old_token: String::new(),
                    old_token_deleted: false,
                    violation_detected: false,
                }),
            }
        }

        /// 开始追踪 renew 操作顺序（login 完成后调用）。
        fn start_tracking(&self, old_token: String) {
            let mut state = self.tracking_state.lock().unwrap();
            state.enabled = true;
            state.old_token = old_token;
            state.old_token_deleted = false;
            state.violation_detected = false;
        }

        /// 是否检测到违规（新 token session 在旧 token session 删除前被创建）。
        fn was_violation_detected(&self) -> bool {
            self.tracking_state.lock().unwrap().violation_detected
        }
    }

    #[async_trait]
    impl BulwarkDao for OrderTrackingDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            self.inner.get(key).await
        }

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            // 若正在追踪且 key 是 token:session:*，
            // 检查旧 token 是否已被 delete
            {
                let mut state = self.tracking_state.lock().unwrap();
                if state.enabled && key.starts_with("token:session:") && !state.old_token_deleted {
                    state.violation_detected = true;
                }
            }
            self.inner.set(key, value, ttl_seconds).await
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            self.inner.update(key, value).await
        }

        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            self.inner.expire(key, seconds).await
        }

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            // 标记旧 token 已被 delete
            {
                let mut state = self.tracking_state.lock().unwrap();
                if state.enabled && key == format!("token:session:{}", state.old_token) {
                    state.old_token_deleted = true;
                }
            }
            self.inner.delete(key).await
        }

        async fn get_timeout(&self, key: &str) -> BulwarkResult<Option<Duration>> {
            self.inner.get_timeout(key).await
        }
    }

    /// renew_to_equivalent 必须先失效旧 token，再创建新 token（原子化）。
    ///
    /// 顺序为"先 delete 后 create"，消除窗口期双 token 同时有效的风险。
    #[tokio::test]
    async fn renew_to_equivalent_deletes_old_token_before_creating_new() {
        let tracking_dao = Arc::new(OrderTrackingDao::new());
        let session = Arc::new(BulwarkSession::new(
            tracking_dao.clone() as Arc<dyn BulwarkDao>,
            3600,
            86400,
        ));
        let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
        let auth = AuthLogicDefault::new(session, token_handler, 3600);

        let old_token = auth.login("1001", None).await.unwrap();

        // 开始追踪 renew 操作的顺序
        tracking_dao.start_tracking(old_token.clone());

        // renew_to_equivalent 应成功
        let new_token = auth.renew_to_equivalent(&old_token).await;
        assert!(
            new_token.is_ok(),
            "renew 应成功，实际: {:?}",
            new_token.err()
        );

        // 验证：新 token session 不应在旧 token session 删除前被创建
        assert!(
            !tracking_dao.was_violation_detected(),
            "VULN-0020 违规：新 token session 在旧 token session 删除前被创建（双 token 窗口期）"
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
