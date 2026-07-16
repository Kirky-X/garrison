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
mod guards;

#[cfg(test)]
pub(super) use default::parse_remember_me_param;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
