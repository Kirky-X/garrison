//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! GarrisonUtil 静态方法入口 + JwtMode 校验模式枚举 + AuthBackend 全局桥接。
use crate::config::GarrisonConfig;
use crate::error::GarrisonResult;
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
use crate::loc;
use crate::session::GarrisonSession;
use crate::stp::core::GarrisonCore;
use crate::stp::mfa::MfaLogic;
use crate::stp::permission::PermissionLogic;
use crate::stp::session::SessionLogic;
use crate::stp::token::TokenLogic;
use crate::stp::LoginParams;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::task;
use tokio::task::JoinHandle;

// ============================================================================
// AuthBackend 全局桥接（R-msa-005）
// ============================================================================
//
// 设计冲突说明（规则 7 — 暴露冲突）：
//
// design.md §3.5 原设计使用 `CURRENT_BACKEND.get().expect("Backend not initialized")`，
// 要求用户必须显式调用 `init_backend()`，否则 panic。
//
// spec R-msa-005 约束："backend-embedded 模式下 GarrisonUtil 行为与 v0.6.7 一致" +
// Constraints："backend-embedded 模式必须与 v0.6.7 行为完全一致（zero-break）"。
//
// 两者冲突：design.md 要求显式初始化（breaking change），spec 要求 zero-break。
//
// 决策：采取 fallback 策略，优先满足 spec 的 zero-break 约束。
// - 启用 backend feature 且已 `init_backend()`：委托 `AuthBackend` trait
// - 启用 `backend-embedded` 但未 `init_backend()`：fallback 到 `GarrisonManager`（v0.6.7 兼容）
// - 仅启用 `backend-remote` 但未 `init_backend()`：返回 `GarrisonError::Config`
// - 未启用任何 backend feature：直接走 `GarrisonManager` 路径（v0.6.7 兼容）
//
// 实现说明：使用 `Mutex<Option<...>>` 而非 design.md 的 `OnceLock`，以支持测试重置。
// 生产环境中 `init_backend()` 只应调用一次，Mutex 无竞争开销可忽略。

/// 全局认证后端实例。
///
/// 通过 [`init_backend`] 初始化。未初始化时根据 feature flag 决定 fallback 行为。
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
static CURRENT_BACKEND: std::sync::Mutex<Option<Arc<dyn crate::backend::AuthBackend>>> =
    std::sync::Mutex::new(None);

/// 初始化全局认证后端。
///
/// 必须在使用 `GarrisonUtil` 之前调用一次。重复调用返回 `GarrisonError::Config`。
///
/// # 参数
/// - `backend`: `Arc<dyn AuthBackend>` 实例（`BackendEmbedded` 或 `BackendRemote`）
///
/// # 示例
///
/// ```ignore
/// use std::sync::Arc;
/// use garrison::backend::{AuthBackend, BackendEmbedded};
/// use garrison::stp::init_backend;
///
/// // Embedded 模式（v0.6.7 兼容）
/// init_backend(Arc::new(BackendEmbedded::new())).unwrap();
///
/// // Remote 模式
/// // init_backend(Arc::new(BackendRemote::new("https://auth:8443", "key", Duration::from_secs(5)).unwrap())).unwrap();
/// ```
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
pub fn init_backend(backend: Arc<dyn crate::backend::AuthBackend>) -> GarrisonResult<()> {
    let mut guard = CURRENT_BACKEND
        .lock()
        .map_err(|_| crate::error::GarrisonError::Config("stp-backend-lock-poisoned::".into()))?;
    if guard.is_some() {
        return Err(crate::error::GarrisonError::Config(
            "stp-backend-already-init::".into(),
        ));
    }
    *guard = Some(backend);
    Ok(())
}

/// 获取已初始化的认证后端。
///
/// # 返回
/// - `Ok(Some(backend))`: 已通过 [`init_backend`] 初始化
/// - `Ok(None)`: 未初始化，且 `backend-embedded` feature 启用（调用方应 fallback 到 GarrisonManager）
/// - `Err(_)`: 未初始化，且 `backend-embedded` feature 未启用
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
fn get_backend() -> GarrisonResult<Option<Arc<dyn crate::backend::AuthBackend>>> {
    let guard = CURRENT_BACKEND
        .lock()
        .map_err(|_| crate::error::GarrisonError::Config("stp-backend-lock-poisoned::".into()))?;
    if let Some(backend) = guard.as_ref() {
        return Ok(Some(backend.clone()));
    }
    #[cfg(not(feature = "backend-embedded"))]
    {
        Err(crate::error::GarrisonError::Config(
            "stp-backend-not-init::".into(),
        ))
    }
    #[cfg(feature = "backend-embedded")]
    {
        Ok(None)
    }
}

/// 重置全局认证后端（仅测试用）。
///
/// 用于单元测试中重置 `CURRENT_BACKEND`，以便测试不同的 backend 配置。
/// 生产代码中严禁调用此函数。
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
#[cfg(test)]
pub(crate) fn reset_backend_for_test() {
    if let Ok(mut guard) = CURRENT_BACKEND.lock() {
        *guard = None;
    }
}

// ============================================================================
// JwtMode：JWT 校验模式
// ============================================================================

/// JWT 校验模式。
///
/// 控制 `check_login` 在 JWT verify 与 oxcache session 查询之间的组合策略。
/// 不依赖 `jsonwebtoken` crate，作为配置选项总是编译（即使未启用 `protocol-jwt`）。
///
/// # 变体
///
/// - `Stateless`：仅 JWT verify，不查询 oxcache session。适用于高可用场景
///   （DAO 故障时仍可校验），要求启用 `protocol-jwt` feature 且 `token_style=jwt`。
/// - `Mixin`（默认）：JWT verify + session 二级校验。推荐的平衡模式——
///   JWT 提供无状态校验，session 提供主动注销能力。
/// - `Simple`：仅 session 校验，JWT 仅作为 token 字符串载体（不验证签名）。
///   适用于 token 已由网关层校验过的场景。
///
/// # feature 依赖
///
/// `jwt_mode` 字段本身不 feature gate，但 `Stateless`/`Mixin` 中的 JWT verify
/// 调用需 `protocol-jwt` feature。未启用时 `Stateless` 返回 `Config` 错误，
/// `Mixin` 退化为仅查 session（向后兼容 0.4.1 行为）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JwtMode {
    /// 仅 JWT verify，不查询 oxcache session（高可用场景）。
    Stateless,
    /// JWT verify + session 二级校验（推荐，默认）。
    #[default]
    Mixin,
    /// 仅 session，JWT 仅作为 token 载体（不验证签名）。
    Simple,
}

// ============================================================================
// GarrisonUtil：静态方法入口（委托全局 GarrisonManager 单例）
// ============================================================================

/// 工具结构体，提供静态方法入口。
///
/// 对应 `StpUtil`，是面向使用者的便捷入口。
/// 内部委托给 `GarrisonManager::logic()` 全局单例。
///
/// # 使用前提
///
/// 调用前必须先执行 `GarrisonManager::builder().dao(dao).config(config).interface(interface).build().await`，
/// 否则返回 `GarrisonError::Session("GarrisonManager 未初始化")`。
pub struct GarrisonUtil;

impl GarrisonUtil {
    /// 执行登录：生成 token + 创建会话。
    ///
    /// # 参数
    /// - `id`: 登录主体标识（支持 `String`、`&str` 等 `Into<String>` 类型）。
    ///
    /// # 返回
    /// 生成的 token 字符串。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - token 生成或会话创建失败：透传 `GarrisonError`。
    pub async fn login(id: impl Into<String>, params: &LoginParams) -> GarrisonResult<String> {
        let id: String = id.into();
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                return backend.login(&id, params).await;
            }
        }
        crate::manager::GarrisonManager::logic()?
            .login(&id, params)
            .await
    }

    /// 便捷登录：使用默认 `LoginParams`（无设备/IP/UA/remember_me）。
    ///
    /// 等价于 `login(id, &LoginParams::default())`，向后兼容 0.6.2 前的 `login(id)` 调用。
    pub async fn login_simple(id: impl Into<String>) -> GarrisonResult<String> {
        Self::login(id, &LoginParams::default()).await
    }

    /// 执行登出：从 task_local 获取当前 token 并销毁。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；未设置 token 时幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 会话销毁失败：透传 `GarrisonError`。
    pub async fn logout() -> GarrisonResult<()> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                return backend.logout(&token).await;
            }
        }
        crate::manager::GarrisonManager::logic()?.logout().await
    }

    /// 按账号登出：销毁指定 login_id 的所有会话。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（支持 `String`、`&str` 等 `Into<String>` 类型）。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 会话销毁失败：透传 `GarrisonError`。
    pub async fn logout_by_login_id(login_id: impl Into<String>) -> GarrisonResult<()> {
        let login_id: String = login_id.into();
        crate::manager::GarrisonManager::logic()?
            .logout_by_login_id(&login_id)
            .await
    }

    /// 踢出用户：按账号踢出（语义等同 logout_by_login_id）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（支持 `String`、`&str` 等 `Into<String>` 类型）。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 会话销毁失败：透传 `GarrisonError`。
    pub async fn kickout(login_id: impl Into<String>) -> GarrisonResult<()> {
        let login_id: String = login_id.into();
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                return backend.kickout(&login_id).await;
            }
        }
        crate::manager::GarrisonManager::logic()?
            .kickout(&login_id)
            .await
    }

    /// 踢出会话：按 token 踢出。
    ///
    /// # 参数
    /// - `token`: 待踢出的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 会话销毁失败：透传 `GarrisonError`。
    pub async fn kickout_by_token(token: &str) -> GarrisonResult<()> {
        crate::manager::GarrisonManager::logic()?
            .kickout_by_token(token)
            .await
    }

    /// 密码修改后失效用户所有会话（H-7 修复）。
    ///
    /// 清除指定 `login_id` 的所有 Token-Session 和 Account-Session，
    /// 并广播 `GarrisonEvent::Kickout` 事件（reason: "password-changed"）。
    ///
    /// 应用层在密码修改成功后应调用此方法，确保已签发的会话立即失效，
    /// 缩小凭证泄露后的攻击窗口。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（支持 `String`、`&str` 等 `Into<String>` 类型）。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 会话销毁失败：透传 `GarrisonError`。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// // 应用层密码修改成功后调用
    /// GarrisonUtil::invalidate_sessions_after_password_change("user-001").await?;
    /// ```
    pub async fn invalidate_sessions_after_password_change(
        login_id: impl Into<String>,
    ) -> GarrisonResult<()> {
        let login_id: String = login_id.into();
        let logic = crate::manager::GarrisonManager::logic()?;
        // 销毁该用户所有会话
        logic.session.logout_by_login_id(&login_id).await?;
        // 广播 Kickout 事件（reason: "password-changed"）
        #[cfg(feature = "listener")]
        if let Some(lm) = &logic.listener_manager {
            lm.broadcast(&crate::listener::GarrisonEvent::Kickout {
                login_id: login_id.clone(),
                token: String::new(),
                reason: loc!("session-kickout-password-changed", "password-changed"),
                request_context: None,
            })
            .await;
        }
        Ok(())
    }

    /// 主动吊销 token：销毁指定 token 的会话。
    ///
    /// 与 [`kickout_by_token`](Self::kickout_by_token) 的区别：
    /// - `revoke_token` 广播 `RevokeToken` 事件（仅携带 token，语义为"token 失效"）
    /// - `kickout_by_token` 不广播事件（语义为"管理员强制下线"，无对应 listener 事件）
    ///
    /// # 参数
    /// - `token`: 待吊销的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；token 不存在时幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 会话销毁失败：透传 `GarrisonError`。
    pub async fn revoke_token(token: &str) -> GarrisonResult<()> {
        crate::manager::GarrisonManager::logic()?
            .revoke_token(token)
            .await
    }

    /// 检查登录状态。
    ///
    /// # 返回
    /// - `Ok(true)`: 当前已登录且 token 有效。
    /// - `Ok(false)`: 未登录或 token 无效（`throw_on_not_login=false`）。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未登录且 `throw_on_not_login=true`：`GarrisonError::Session`。
    pub async fn check_login() -> GarrisonResult<bool> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                return backend.check_login(&token).await;
            }
        }
        crate::manager::GarrisonManager::logic()?
            .check_login()
            .await
    }

    /// 获取当前登录 ID。
    ///
    /// # 返回
    /// - `Some(login_id)`: 已登录，返回关联的 login_id。
    /// - `None`: 未登录或 token 无效。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - DAO 读取失败：透传 `GarrisonError`。
    pub async fn get_login_id() -> GarrisonResult<Option<String>> {
        crate::manager::GarrisonManager::logic()?
            .get_login_id()
            .await
    }

    /// 通过指定 token 获取关联的登录 ID。
    ///
    /// 与 [`get_login_id`] 的区别：本方法显式接收 token 参数，内部通过
    /// [`with_current_token`] 将 token 设置到 task_local 上下文后再查询，
    /// 适用于 web extractor 场景（从请求 header 提取 token 后解析 login_id）。
    ///
    /// # 参数
    /// - `token`: 待解析的 token 字符串。
    ///
    /// # 返回
    /// - `Some(login_id)`: token 有效，返回关联的 login_id。
    /// - `None`: token 无效或会话不存在。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - DAO 读取失败：透传 `GarrisonError`。
    ///
    /// [`get_login_id`]: Self::get_login_id
    /// [`with_current_token`]: crate::stp::with_current_token
    pub async fn get_login_id_by_token(token: &str) -> GarrisonResult<Option<String>> {
        super::with_current_token(token.to_string(), async { Self::get_login_id().await }).await
    }

    /// 校验权限。
    ///
    /// # 参数
    /// - `permission`: 权限标识字符串。
    ///
    /// # 返回
    /// 成功（持有权限）返回 `Ok(())`。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未登录：`GarrisonError::NotLogin` 或降级为 `GarrisonError::NotPermission`。
    /// - 未持有权限：`GarrisonError::NotPermission`。
    pub async fn check_permission(permission: &str) -> GarrisonResult<()> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                return backend.check_permission(&token, permission).await;
            }
        }
        crate::manager::GarrisonManager::logic()?
            .check_permission(permission)
            .await
    }

    /// 校验角色。
    ///
    /// # 参数
    /// - `role`: 角色标识字符串。
    ///
    /// # 返回
    /// 成功（持有角色）返回 `Ok(())`。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未登录：`GarrisonError::NotLogin` 或降级为 `GarrisonError::NotRole`。
    /// - 未持有角色：`GarrisonError::NotRole`。
    pub async fn check_role(role: &str) -> GarrisonResult<()> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                return backend.check_role(&token, role).await;
            }
        }
        crate::manager::GarrisonManager::logic()?
            .check_role(role)
            .await
    }

    /// 检查当前会话是否持有指定权限。
    ///
    /// 与 [`check_permission`](Self::check_permission) 的区别：本方法返回布尔值而非抛出异常。
    /// 未登录或未持有权限均返回 `Ok(false)`，适用于条件分支场景（如 UI 元素显隐控制）。
    ///
    /// # 参数
    /// - `permission`: 权限标识字符串。
    ///
    /// # 返回
    /// - `Ok(true)`: 当前会话持有该权限。
    /// - `Ok(false)`: 当前会话未持有该权限或未登录。
    ///
    /// # 错误
    /// - `permission` 为空字符串：`GarrisonError::InvalidParam`。
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - DAO 层错误等非权限性错误：透传 `GarrisonError`。
    pub async fn has_permission(permission: &str) -> GarrisonResult<bool> {
        if permission.is_empty() {
            return Err(crate::error::GarrisonError::InvalidParam(
                "stp-permission-empty::".to_string(),
            ));
        }
        crate::manager::GarrisonManager::logic()?
            .has_permission(permission)
            .await
    }

    /// 检查当前会话是否持有指定角色。
    ///
    /// 与 [`check_role`](Self::check_role) 的区别：本方法返回布尔值而非抛出异常。
    /// 未登录或未持有角色均返回 `Ok(false)`，适用于条件分支场景。
    ///
    /// # 参数
    /// - `role`: 角色标识字符串。
    ///
    /// # 返回
    /// - `Ok(true)`: 当前会话持有该角色。
    /// - `Ok(false)`: 当前会话未持有该角色或未登录。
    ///
    /// # 错误
    /// - `role` 为空字符串：`GarrisonError::InvalidParam`。
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - DAO 层错误等非角色性错误：透传 `GarrisonError`。
    pub async fn has_role(role: &str) -> GarrisonResult<bool> {
        if role.is_empty() {
            return Err(crate::error::GarrisonError::InvalidParam(
                "stp-role-empty::".to_string(),
            ));
        }
        crate::manager::GarrisonManager::logic()?
            .has_role(role)
            .await
    }

    /// 获取当前登录主体的权限列表。
    ///
    /// 从当前会话上下文获取 login_id 后委托 `GarrisonPermissionStrategy` 查询权限数据。
    /// 未登录时返回 `Ok(vec![])`（非抛出异常）。
    ///
    /// # 返回
    /// - `Ok(permissions)`: 权限标识字符串列表（如 `["user:read", "user:write"]`），可为空。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 数据源访问失败：透传 `GarrisonError`。
    pub async fn get_permission_list() -> GarrisonResult<Vec<String>> {
        crate::manager::GarrisonManager::logic()?
            .get_permission_list()
            .await
    }

    /// 获取当前登录主体的角色列表。
    ///
    /// 从当前会话上下文获取 login_id 后委托 `GarrisonPermissionStrategy` 查询角色数据。
    /// 未登录时返回 `Ok(vec![])`。
    ///
    /// # 返回
    /// - `Ok(roles)`: 角色标识字符串列表（如 `["admin", "user"]`），可为空。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 数据源访问失败：透传 `GarrisonError`。
    pub async fn get_role_list() -> GarrisonResult<Vec<String>> {
        crate::manager::GarrisonManager::logic()?
            .get_role_list()
            .await
    }

    /// 校验 access_token 类型会话。
    ///
    /// 委托 `TokenLogic::check_access_token()`，默认实现委托 `check_login`。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未登录：`GarrisonError::NotLogin`。
    pub async fn check_access_token() -> GarrisonResult<()> {
        crate::manager::GarrisonManager::logic()?
            .check_access_token()
            .await
    }

    /// 校验 client_token 类型会话。
    ///
    /// 委托 `TokenLogic::check_client_token()`，默认实现委托 `check_login`。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未登录：`GarrisonError::NotLogin`。
    pub async fn check_client_token() -> GarrisonResult<()> {
        crate::manager::GarrisonManager::logic()?
            .check_client_token()
            .await
    }

    /// 校验 temp_token 类型会话。
    ///
    /// 委托 `TokenLogic::check_temp_token()`，默认实现委托 `check_login`。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未登录：`GarrisonError::NotLogin`。
    pub async fn check_temp_token() -> GarrisonResult<()> {
        crate::manager::GarrisonManager::logic()?
            .check_temp_token()
            .await
    }

    /// 检查二级认证（MFA）状态。
    ///
    /// 委托 `MfaLogic::check_safe()`，默认实现返回 `Ok(())`（未启用 MFA）。
    ///
    /// # 返回
    /// - `Ok(())`: 已通过二级认证或未启用 MFA。
    /// - `Err(GarrisonError::Session)`: 未通过二级认证。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    pub async fn check_safe() -> GarrisonResult<()> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                let is_safe = backend.check_safe(&token).await?;
                if is_safe {
                    return Ok(());
                }
                return Err(crate::error::GarrisonError::NotSafe {
                    reason: loc!("stp-mfa-not-passed", ""),
                });
            }
        }
        crate::manager::GarrisonManager::logic()?.check_safe().await
    }

    /// 检查账号是否被禁用。
    ///
    /// 委托 `MfaLogic::check_disable()`，默认实现返回 `Ok(())`（未实现禁用账号库）。
    ///
    /// # 返回
    /// - `Ok(())`: 账号未禁用。
    /// - `Err(GarrisonError::Session)`: 账号已禁用。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    pub async fn check_disable() -> GarrisonResult<()> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                let is_disabled = backend.check_disable(&token).await?;
                if is_disabled {
                    return Err(crate::error::GarrisonError::DisableService {
                        service: "default".to_string(),
                        until: None,
                    });
                }
                return Ok(());
            }
        }
        crate::manager::GarrisonManager::logic()?
            .check_disable()
            .await
    }

    /// 校验 API Key。
    ///
    /// 从当前请求上下文（task_local `CURRENT_TOKEN`）获取 API Key，
    /// 委托 `GarrisonLogicDefault::check_api_key(namespace)` 校验。
    ///
    /// # 参数
    /// - `namespace`: 命名空间标识，用于隔离不同业务的 API Key。
    ///
    /// # 返回
    /// - `Ok(())`: API Key 有效。
    /// - `Err(GarrisonError::Session)`: `GarrisonManager` 未初始化 或 未设置当前请求上下文。
    /// - `Err(GarrisonError::InvalidToken)`: API Key 不存在或已吊销。
    /// - `Err(GarrisonError::ExpiredToken)`: API Key 已过期。
    ///
    /// # 兼容性
    ///
    /// `protocol-apikey` feature 关闭时，本方法返回 `Ok(())`（兼容 0.6.0 未启用 API Key 场景）。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use garrison::stp::GarrisonUtil;
    /// use garrison::stp::with_current_token;
    ///
    /// // 在 axum handler 中（middleware 已设置 CURRENT_TOKEN）
    /// GarrisonUtil::check_api_key("default").await?;
    ///
    /// // 或手动设置 token 作用域
    /// with_current_token("my-api-key".to_string(), async {
    ///     GarrisonUtil::check_api_key("internal").await
    /// }).await?;
    /// ```
    pub async fn check_api_key(namespace: &str) -> GarrisonResult<()> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                return backend.check_api_key(&token, namespace).await;
            }
        }
        crate::manager::GarrisonManager::logic()?
            .check_api_key(namespace)
            .await
    }

    /// 通过外部 token 反向建立会话。
    ///
    /// 用于 OAuth2/SSO 场景：外部 token 已通过协议层校验后，
    /// 调用此方法在当前上下文建立内部会话。
    ///
    /// # 参数
    /// - `token`: 外部 token 字符串。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未启用协议层 feature：`GarrisonError::NotImplemented`。
    pub async fn login_by_token(token: &str) -> GarrisonResult<()> {
        crate::manager::GarrisonManager::logic()?
            .login_by_token(token)
            .await
    }

    /// 验证显式传入的 token 并返回关联的 login_id。
    ///
    /// # 参数
    /// - `token`: 待验证的 token 字符串。
    ///
    /// # 返回
    /// - `Ok(login_id)`: token 有效，返回关联的 login_id。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - token 无效：`GarrisonError::InvalidToken`。
    pub async fn verify_token(token: &str) -> GarrisonResult<String> {
        crate::manager::GarrisonManager::logic()?
            .verify_token(token)
            .await
    }

    /// 刷新 token。
    ///
    /// # 参数
    /// - `token`: 待刷新的旧 token 字符串。
    ///
    /// # 返回
    /// - `Ok(new_token)`: 刷新后的新 token 字符串。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未启用 protocol-jwt：`GarrisonError::NotImplemented`。
    /// - token 已过期：`GarrisonError::InvalidToken`。
    pub async fn refresh_token(token: &str) -> GarrisonResult<String> {
        crate::manager::GarrisonManager::logic()?
            .refresh_token(token)
            .await
    }

    // ========================================================================
    // 同步版本（check_*_sync）：通过 block_in_place + Handle::current().block_on
    // 包装 async 版本，供 sync fn 宏 wrapper 调用（v0.6.1 sync fn 支持）。
    //
    // 设计约束：
    // - 必须在 tokio multi_thread runtime 上下文内调用（block_in_place 要求）
    // - task_local `CURRENT_TOKEN` 自动继承（同 task 内）
    // - 参数 `&str` 需 `.to_string()` 后 move 进 block_on future（'static 约束）
    // ========================================================================

    /// 同步版 [`check_login`](Self::check_login)。
    ///
    /// 在当前 tokio runtime 上阻塞执行 async `check_login`。
    ///
    /// # 返回
    /// - `Ok(true)`: 当前已登录且 token 有效。
    /// - `Ok(false)`: 未登录或 token 无效（`throw_on_not_login=false`）。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未登录且 `throw_on_not_login=true`：`GarrisonError::Session`。
    /// - 不在 tokio multi_thread runtime 上下文：panic（`block_in_place` 要求）。
    pub fn check_login_sync() -> GarrisonResult<bool> {
        task::block_in_place(|| Handle::current().block_on(Self::check_login()))
    }

    /// 同步版 [`check_permission`](Self::check_permission)。
    ///
    /// # 参数
    /// - `perm`: 权限标识字符串。
    ///
    /// # 返回
    /// 成功（持有权限）返回 `Ok(())`。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未登录：`GarrisonError::NotLogin` 或降级为 `GarrisonError::NotPermission`。
    /// - 未持有权限：`GarrisonError::NotPermission`。
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_permission_sync(perm: &str) -> GarrisonResult<()> {
        let perm = perm.to_string();
        task::block_in_place(|| Handle::current().block_on(Self::check_permission(&perm)))
    }

    /// 同步版 [`check_role`](Self::check_role)。
    ///
    /// # 参数
    /// - `role`: 角色标识字符串。
    ///
    /// # 返回
    /// 成功（持有角色）返回 `Ok(())`。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未登录：`GarrisonError::NotLogin` 或降级为 `GarrisonError::NotRole`。
    /// - 未持有角色：`GarrisonError::NotRole`。
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_role_sync(role: &str) -> GarrisonResult<()> {
        let role = role.to_string();
        task::block_in_place(|| Handle::current().block_on(Self::check_role(&role)))
    }

    /// 同步版 [`check_access_token`](Self::check_access_token)。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未登录：`GarrisonError::NotLogin`。
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_access_token_sync() -> GarrisonResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_access_token()))
    }

    /// 同步版 [`check_client_token`](Self::check_client_token)。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未登录：`GarrisonError::NotLogin`。
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_client_token_sync() -> GarrisonResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_client_token()))
    }

    /// 同步版 [`check_temp_token`](Self::check_temp_token)。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未登录：`GarrisonError::NotLogin`。
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_temp_token_sync() -> GarrisonResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_temp_token()))
    }

    /// 同步版 [`check_api_key`](Self::check_api_key)。
    ///
    /// # 参数
    /// - `namespace`: 命名空间标识，用于隔离不同业务的 API Key。
    ///
    /// # 返回
    /// - `Ok(())`: API Key 有效。
    /// - `Err(GarrisonError::Session)`: `GarrisonManager` 未初始化 或 未设置当前请求上下文。
    /// - `Err(GarrisonError::InvalidToken)`: API Key 不存在或已吊销。
    /// - `Err(GarrisonError::ExpiredToken)`: API Key 已过期。
    ///
    /// # 兼容性
    ///
    /// `protocol-apikey` feature 关闭时，本方法返回 `Ok(())`。
    ///
    /// # 错误（runtime）
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_api_key_sync(namespace: &str) -> GarrisonResult<()> {
        let namespace = namespace.to_string();
        task::block_in_place(|| Handle::current().block_on(Self::check_api_key(&namespace)))
    }

    /// 同步版 [`check_safe`](Self::check_safe)。
    ///
    /// 在当前 tokio runtime 上阻塞执行 async `check_safe`。
    ///
    /// # 返回
    /// - `Ok(())`: 已通过二级认证或未启用 MFA。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 未通过二级认证：`GarrisonError::NotSafe`。
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_safe_sync() -> GarrisonResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_safe()))
    }

    /// 同步版 [`check_disable`](Self::check_disable)。
    ///
    /// 在当前 tokio runtime 上阻塞执行 async `check_disable`。
    ///
    /// # 返回
    /// - `Ok(())`: 账号未禁用。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    /// - 账号已禁用：`GarrisonError::DisableService`。
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_disable_sync() -> GarrisonResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_disable()))
    }

    /// 获取当前 `GarrisonConfig` 引用（用于 extractor / middleware 等需要配置的场景）。
    ///
    /// # 返回
    /// 全局配置的 `Arc` 引用。
    ///
    /// # 错误
    /// - `GarrisonManager` 未初始化：`GarrisonError::Session`。
    pub fn config() -> GarrisonResult<Arc<GarrisonConfig>> {
        Ok(crate::manager::GarrisonManager::logic()?.config())
    }
}

// ============================================================================
// spawn_cleanup_task：后台定期清理过期 token
// ============================================================================

/// 启动后台 task 定期清理 `login_token_map` 中的过期/已注销 token。
///
/// 每 `interval_secs` 秒调用一次 [`GarrisonSession::cleanup_expired_tokens`]。
/// 清理失败时仅记录 `tracing::warn!`，不中断 task（规则12：错误显性化但不阻断后台清理）。
///
/// # 参数
/// - `session`: `GarrisonSession` 的 `Arc` 引用。
/// - `interval_secs`: 清理间隔秒数。`<= 0` 时返回 `None`（不启动 task）。
///
/// # 返回
/// - `Some(JoinHandle)`: task 已启动，调用方可通过 `abort()` 取消或 `await` 等待结束。
/// - `None`: `interval_secs <= 0`，未启动 task。
pub fn spawn_cleanup_task(
    session: Arc<GarrisonSession>,
    interval_secs: i64,
) -> Option<JoinHandle<()>> {
    if interval_secs <= 0 {
        return None;
    }
    let interval_duration = Duration::from_secs(interval_secs as u64);
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval_duration);
        loop {
            interval.tick().await;
            if let Err(e) = session.cleanup_expired_tokens().await {
                tracing::warn!("cleanup_expired_tokens failed: {}", e);
            }
        }
    });
    Some(handle)
}

#[cfg(test)]
mod tests;
