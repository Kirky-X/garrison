//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BulwarkUtil 静态方法入口 + JwtMode 校验模式枚举 + AuthBackend 全局桥接。
use crate::config::BulwarkConfig;
use crate::error::BulwarkResult;
use crate::session::BulwarkSession;
use crate::stp::core::BulwarkCore;
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
// spec R-msa-005 约束："backend-embedded 模式下 BulwarkUtil 行为与 v0.6.7 一致" +
// Constraints："backend-embedded 模式必须与 v0.6.7 行为完全一致（zero-break）"。
//
// 两者冲突：design.md 要求显式初始化（breaking change），spec 要求 zero-break。
//
// 决策：采取 fallback 策略，优先满足 spec 的 zero-break 约束。
// - 启用 backend feature 且已 `init_backend()`：委托 `AuthBackend` trait
// - 启用 `backend-embedded` 但未 `init_backend()`：fallback 到 `BulwarkManager`（v0.6.7 兼容）
// - 仅启用 `backend-remote` 但未 `init_backend()`：返回 `BulwarkError::Config`
// - 未启用任何 backend feature：直接走 `BulwarkManager` 路径（v0.6.7 兼容）
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
/// 必须在使用 `BulwarkUtil` 之前调用一次。重复调用返回 `BulwarkError::Config`。
///
/// # 参数
/// - `backend`: `Arc<dyn AuthBackend>` 实例（`BackendEmbedded` 或 `BackendRemote`）
///
/// # 示例
///
/// ```ignore
/// use std::sync::Arc;
/// use bulwark::backend::{AuthBackend, BackendEmbedded};
/// use bulwark::stp::init_backend;
///
/// // Embedded 模式（v0.6.7 兼容）
/// init_backend(Arc::new(BackendEmbedded::new())).unwrap();
///
/// // Remote 模式
/// // init_backend(Arc::new(BackendRemote::new("https://auth:8443", "key", Duration::from_secs(5)).unwrap())).unwrap();
/// ```
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
pub fn init_backend(backend: Arc<dyn crate::backend::AuthBackend>) -> BulwarkResult<()> {
    let mut guard = CURRENT_BACKEND
        .lock()
        .map_err(|_| crate::error::BulwarkError::Config("CURRENT_BACKEND lock poisoned".into()))?;
    if guard.is_some() {
        return Err(crate::error::BulwarkError::Config(
            "Backend already initialized".into(),
        ));
    }
    *guard = Some(backend);
    Ok(())
}

/// 获取已初始化的认证后端。
///
/// # 返回
/// - `Ok(Some(backend))`: 已通过 [`init_backend`] 初始化
/// - `Ok(None)`: 未初始化，且 `backend-embedded` feature 启用（调用方应 fallback 到 BulwarkManager）
/// - `Err(_)`: 未初始化，且 `backend-embedded` feature 未启用
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
fn get_backend() -> BulwarkResult<Option<Arc<dyn crate::backend::AuthBackend>>> {
    let guard = CURRENT_BACKEND
        .lock()
        .map_err(|_| crate::error::BulwarkError::Config("CURRENT_BACKEND lock poisoned".into()))?;
    if let Some(backend) = guard.as_ref() {
        return Ok(Some(backend.clone()));
    }
    #[cfg(not(feature = "backend-embedded"))]
    {
        Err(crate::error::BulwarkError::Config(
            "Backend not initialized. Call init_backend() first.".into(),
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
// BulwarkUtil：静态方法入口（委托全局 BulwarkManager 单例）
// ============================================================================

/// 工具结构体，提供静态方法入口。
///
/// [借鉴 Sa-Token] 对应 `StpUtil`，是面向使用者的便捷入口。
/// 内部委托给 `BulwarkManager::logic()` 全局单例。
///
/// # 使用前提
///
/// 调用前必须先执行 `BulwarkManager::init(dao, config, interface)`，
/// 否则返回 `BulwarkError::Session("BulwarkManager 未初始化")`。
pub struct BulwarkUtil;

impl BulwarkUtil {
    /// 执行登录：生成 token + 创建会话。
    ///
    /// # 参数
    /// - `id`: 登录主体标识（支持 `String`、`&str` 等 `Into<String>` 类型）。
    ///
    /// # 返回
    /// 生成的 token 字符串。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - token 生成或会话创建失败：透传 `BulwarkError`。
    pub async fn login(id: impl Into<String>, params: &LoginParams) -> BulwarkResult<String> {
        let id: String = id.into();
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                return backend.login(&id, params).await;
            }
        }
        crate::manager::BulwarkManager::logic()?
            .login(&id, params)
            .await
    }

    /// 便捷登录：使用默认 `LoginParams`（无设备/IP/UA/remember_me）。
    ///
    /// 等价于 `login(id, &LoginParams::default())`，向后兼容 0.6.2 前的 `login(id)` 调用。
    pub async fn login_simple(id: impl Into<String>) -> BulwarkResult<String> {
        Self::login(id, &LoginParams::default()).await
    }

    /// 执行登出：从 task_local 获取当前 token 并销毁。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；未设置 token 时幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn logout() -> BulwarkResult<()> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                return backend.logout(&token).await;
            }
        }
        crate::manager::BulwarkManager::logic()?.logout().await
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn logout_by_login_id(login_id: impl Into<String>) -> BulwarkResult<()> {
        let login_id: String = login_id.into();
        crate::manager::BulwarkManager::logic()?
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn kickout(login_id: impl Into<String>) -> BulwarkResult<()> {
        let login_id: String = login_id.into();
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                return backend.kickout(&login_id).await;
            }
        }
        crate::manager::BulwarkManager::logic()?
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn kickout_by_token(token: &str) -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .kickout_by_token(token)
            .await
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn revoke_token(token: &str) -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录且 `throw_on_not_login=true`：`BulwarkError::Session`。
    pub async fn check_login() -> BulwarkResult<bool> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                return backend.check_login(&token).await;
            }
        }
        crate::manager::BulwarkManager::logic()?.check_login().await
    }

    /// 获取当前登录 ID。
    ///
    /// # 返回
    /// - `Some(login_id)`: 已登录，返回关联的 login_id。
    /// - `None`: 未登录或 token 无效。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - DAO 读取失败：透传 `BulwarkError`。
    pub async fn get_login_id() -> BulwarkResult<Option<String>> {
        crate::manager::BulwarkManager::logic()?
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - DAO 读取失败：透传 `BulwarkError`。
    ///
    /// [`get_login_id`]: Self::get_login_id
    /// [`with_current_token`]: crate::stp::with_current_token
    pub async fn get_login_id_by_token(token: &str) -> BulwarkResult<Option<String>> {
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin` 或降级为 `BulwarkError::NotPermission`。
    /// - 未持有权限：`BulwarkError::NotPermission`。
    pub async fn check_permission(permission: &str) -> BulwarkResult<()> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                return backend.check_permission(&token, permission).await;
            }
        }
        crate::manager::BulwarkManager::logic()?
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin` 或降级为 `BulwarkError::NotRole`。
    /// - 未持有角色：`BulwarkError::NotRole`。
    pub async fn check_role(role: &str) -> BulwarkResult<()> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                return backend.check_role(&token, role).await;
            }
        }
        crate::manager::BulwarkManager::logic()?
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
    /// - `permission` 为空字符串：`BulwarkError::InvalidParam`。
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - DAO 层错误等非权限性错误：透传 `BulwarkError`。
    pub async fn has_permission(permission: &str) -> BulwarkResult<bool> {
        if permission.is_empty() {
            return Err(crate::error::BulwarkError::InvalidParam(
                "permission 不能为空".to_string(),
            ));
        }
        crate::manager::BulwarkManager::logic()?
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
    /// - `role` 为空字符串：`BulwarkError::InvalidParam`。
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - DAO 层错误等非角色性错误：透传 `BulwarkError`。
    pub async fn has_role(role: &str) -> BulwarkResult<bool> {
        if role.is_empty() {
            return Err(crate::error::BulwarkError::InvalidParam(
                "role 不能为空".to_string(),
            ));
        }
        crate::manager::BulwarkManager::logic()?
            .has_role(role)
            .await
    }

    /// 获取当前登录主体的权限列表。
    ///
    /// 从当前会话上下文获取 login_id 后委托 `BulwarkPermissionStrategy` 查询权限数据。
    /// 未登录时返回 `Ok(vec![])`（非抛出异常）。
    ///
    /// # 返回
    /// - `Ok(permissions)`: 权限标识字符串列表（如 `["user:read", "user:write"]`），可为空。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 数据源访问失败：透传 `BulwarkError`。
    pub async fn get_permission_list() -> BulwarkResult<Vec<String>> {
        crate::manager::BulwarkManager::logic()?
            .get_permission_list()
            .await
    }

    /// 获取当前登录主体的角色列表。
    ///
    /// 从当前会话上下文获取 login_id 后委托 `BulwarkPermissionStrategy` 查询角色数据。
    /// 未登录时返回 `Ok(vec![])`。
    ///
    /// # 返回
    /// - `Ok(roles)`: 角色标识字符串列表（如 `["admin", "user"]`），可为空。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 数据源访问失败：透传 `BulwarkError`。
    pub async fn get_role_list() -> BulwarkResult<Vec<String>> {
        crate::manager::BulwarkManager::logic()?
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin`。
    pub async fn check_access_token() -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin`。
    pub async fn check_client_token() -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin`。
    pub async fn check_temp_token() -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .check_temp_token()
            .await
    }

    /// 检查二级认证（MFA）状态。
    ///
    /// 委托 `MfaLogic::check_safe()`，默认实现返回 `Ok(())`（未启用 MFA）。
    ///
    /// # 返回
    /// - `Ok(())`: 已通过二级认证或未启用 MFA。
    /// - `Err(BulwarkError::Session)`: 未通过二级认证。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    pub async fn check_safe() -> BulwarkResult<()> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                let is_safe = backend.check_safe(&token).await?;
                if is_safe {
                    return Ok(());
                }
                return Err(crate::error::BulwarkError::NotSafe {
                    reason: "二级认证未通过".to_string(),
                });
            }
        }
        crate::manager::BulwarkManager::logic()?.check_safe().await
    }

    /// 检查账号是否被禁用。
    ///
    /// 委托 `MfaLogic::check_disable()`，默认实现返回 `Ok(())`（未实现禁用账号库）。
    ///
    /// # 返回
    /// - `Ok(())`: 账号未禁用。
    /// - `Err(BulwarkError::Session)`: 账号已禁用。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    pub async fn check_disable() -> BulwarkResult<()> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                let is_disabled = backend.check_disable(&token).await?;
                if is_disabled {
                    return Err(crate::error::BulwarkError::DisableService {
                        service: "default".to_string(),
                        until: None,
                    });
                }
                return Ok(());
            }
        }
        crate::manager::BulwarkManager::logic()?
            .check_disable()
            .await
    }

    /// 校验 API Key。
    ///
    /// 从当前请求上下文（task_local `CURRENT_TOKEN`）获取 API Key，
    /// 委托 `BulwarkLogicDefault::check_api_key(namespace)` 校验。
    ///
    /// # 参数
    /// - `namespace`: 命名空间标识，用于隔离不同业务的 API Key。
    ///
    /// # 返回
    /// - `Ok(())`: API Key 有效。
    /// - `Err(BulwarkError::Session)`: `BulwarkManager` 未初始化 或 未设置当前请求上下文。
    /// - `Err(BulwarkError::InvalidToken)`: API Key 不存在或已吊销。
    /// - `Err(BulwarkError::ExpiredToken)`: API Key 已过期。
    ///
    /// # 兼容性
    ///
    /// `protocol-apikey` feature 关闭时，本方法返回 `Ok(())`（兼容 0.6.0 未启用 API Key 场景）。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use bulwark::stp::BulwarkUtil;
    /// use bulwark::stp::with_current_token;
    ///
    /// // 在 axum handler 中（middleware 已设置 CURRENT_TOKEN）
    /// BulwarkUtil::check_api_key("default").await?;
    ///
    /// // 或手动设置 token 作用域
    /// with_current_token("my-api-key".to_string(), async {
    ///     BulwarkUtil::check_api_key("internal").await
    /// }).await?;
    /// ```
    pub async fn check_api_key(namespace: &str) -> BulwarkResult<()> {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                let token = super::current_token()?;
                return backend.check_api_key(&token, namespace).await;
            }
        }
        crate::manager::BulwarkManager::logic()?
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未启用协议层 feature：`BulwarkError::NotImplemented`。
    pub async fn login_by_token(token: &str) -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - token 无效：`BulwarkError::InvalidToken`。
    pub async fn verify_token(token: &str) -> BulwarkResult<String> {
        crate::manager::BulwarkManager::logic()?
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未启用 protocol-jwt：`BulwarkError::NotImplemented`。
    /// - token 已过期：`BulwarkError::InvalidToken`。
    pub async fn refresh_token(token: &str) -> BulwarkResult<String> {
        crate::manager::BulwarkManager::logic()?
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录且 `throw_on_not_login=true`：`BulwarkError::Session`。
    /// - 不在 tokio multi_thread runtime 上下文：panic（`block_in_place` 要求）。
    pub fn check_login_sync() -> BulwarkResult<bool> {
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin` 或降级为 `BulwarkError::NotPermission`。
    /// - 未持有权限：`BulwarkError::NotPermission`。
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_permission_sync(perm: &str) -> BulwarkResult<()> {
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
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin` 或降级为 `BulwarkError::NotRole`。
    /// - 未持有角色：`BulwarkError::NotRole`。
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_role_sync(role: &str) -> BulwarkResult<()> {
        let role = role.to_string();
        task::block_in_place(|| Handle::current().block_on(Self::check_role(&role)))
    }

    /// 同步版 [`check_access_token`](Self::check_access_token)。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin`。
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_access_token_sync() -> BulwarkResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_access_token()))
    }

    /// 同步版 [`check_client_token`](Self::check_client_token)。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin`。
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_client_token_sync() -> BulwarkResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_client_token()))
    }

    /// 同步版 [`check_temp_token`](Self::check_temp_token)。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin`。
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_temp_token_sync() -> BulwarkResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_temp_token()))
    }

    /// 同步版 [`check_api_key`](Self::check_api_key)。
    ///
    /// # 参数
    /// - `namespace`: 命名空间标识，用于隔离不同业务的 API Key。
    ///
    /// # 返回
    /// - `Ok(())`: API Key 有效。
    /// - `Err(BulwarkError::Session)`: `BulwarkManager` 未初始化 或 未设置当前请求上下文。
    /// - `Err(BulwarkError::InvalidToken)`: API Key 不存在或已吊销。
    /// - `Err(BulwarkError::ExpiredToken)`: API Key 已过期。
    ///
    /// # 兼容性
    ///
    /// `protocol-apikey` feature 关闭时，本方法返回 `Ok(())`。
    ///
    /// # 错误（runtime）
    /// - 不在 tokio multi_thread runtime 上下文：panic。
    pub fn check_api_key_sync(namespace: &str) -> BulwarkResult<()> {
        let namespace = namespace.to_string();
        task::block_in_place(|| Handle::current().block_on(Self::check_api_key(&namespace)))
    }

    /// 获取当前 `BulwarkConfig` 引用（用于 extractor / middleware 等需要配置的场景）。
    ///
    /// # 返回
    /// 全局配置的 `Arc` 引用。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    pub fn config() -> BulwarkResult<Arc<BulwarkConfig>> {
        Ok(crate::manager::BulwarkManager::logic()?.config())
    }
}

// ============================================================================
// spawn_cleanup_task：后台定期清理过期 token
// ============================================================================

/// 启动后台 task 定期清理 `login_token_map` 中的过期/已注销 token。
///
/// 每 `interval_secs` 秒调用一次 [`BulwarkSession::cleanup_expired_tokens`]。
/// 清理失败时仅记录 `tracing::warn!`，不中断 task（规则12：错误显性化但不阻断后台清理）。
///
/// # 参数
/// - `session`: `BulwarkSession` 的 `Arc` 引用。
/// - `interval_secs`: 清理间隔秒数。`<= 0` 时返回 `None`（不启动 task）。
///
/// # 返回
/// - `Some(JoinHandle)`: task 已启动，调用方可通过 `abort()` 取消或 `await` 等待结束。
/// - `None`: `interval_secs <= 0`，未启动 task。
pub fn spawn_cleanup_task(
    session: Arc<BulwarkSession>,
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
                tracing::warn!("cleanup_expired_tokens 失败: {}", e);
            }
        }
    });
    Some(handle)
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::dao::BulwarkDao;
    use crate::error::{BulwarkError, BulwarkResult};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 辅助函数：创建带 MockDao 的 Arc<BulwarkSession>。
    fn make_session(timeout: u64, active_timeout: u64) -> (Arc<MockDao>, Arc<BulwarkSession>) {
        let dao = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao.clone(), timeout, active_timeout));
        (dao, session)
    }

    // ----------------------------------------------------------------
    // 测试 1：interval <= 0 返回 None 不启动 task
    // ----------------------------------------------------------------

    /// 验证 interval < 0 时返回 None 不启动 task。
    /// 同时验证 interval == 0 也返回 None（0 秒间隔无实际意义，与 < 0 一致）。
    #[tokio::test]
    async fn spawn_cleanup_task_negative_interval_returns_none() {
        let (_dao, session) = make_session(3600, 86400);
        let handle = spawn_cleanup_task(session, -1);
        assert!(handle.is_none(), "interval=-1 应返回 None");

        let (_dao, session) = make_session(3600, 86400);
        let handle = spawn_cleanup_task(session, 0);
        assert!(handle.is_none(), "interval=0 应返回 None");
    }

    // ----------------------------------------------------------------
    // 测试 2：interval > 0 启动 task 并执行清理
    // ----------------------------------------------------------------

    /// 验证 interval > 0 时启动 task，且 task 定期执行 cleanup_expired_tokens。
    ///
    /// 策略：创建 TTL=1 秒的 token，启动间隔=1 秒的清理 task，
    /// 等待 3 秒后验证 token 已从 login_token_map 中清理。
    #[tokio::test]
    async fn spawn_cleanup_task_positive_interval_starts_and_cleans() {
        let (_dao, session) = make_session(1, 86400);
        // 创建 token（TTL=1 秒，1 秒后 MockDao 自动过期）
        session.create("1001", "T1").await.unwrap();
        assert!(
            session.get_token_by_login_id("1001").is_some(),
            "清理前 token 应存在于 login_token_map"
        );

        // 启动清理 task，间隔 1 秒
        let handle = spawn_cleanup_task(session.clone(), 1);
        assert!(handle.is_some(), "interval=1 应返回 Some");

        // 等待 token TTL 过期 + 至少 2 次清理周期
        tokio::time::sleep(Duration::from_secs(3)).await;

        // 验证 token 已被清理（cleanup_expired_tokens 检测到 DAO 返回 None 后移除）
        assert!(
            session.get_token_by_login_id("1001").is_none(),
            "清理后 token 应从 login_token_map 移除"
        );

        // 清理 task
        if let Some(h) = handle {
            h.abort();
        }
    }

    // ----------------------------------------------------------------
    // 测试 3：task 可通过 abort 取消
    // ----------------------------------------------------------------

    /// 验证 task 可通过 JoinHandle::abort() 取消。
    ///
    /// abort 后 await 应返回 Err(JoinError)，且 JoinError::is_cancelled() 为 true。
    #[tokio::test]
    async fn spawn_cleanup_task_can_be_cancelled() {
        let (_dao, session) = make_session(3600, 86400);
        let handle = spawn_cleanup_task(session, 1).unwrap();

        // 等待一小段时间确保 task 已启动并被 runtime 调度
        tokio::time::sleep(Duration::from_millis(100)).await;

        // abort 后 await 应返回 Err（JoinError::is_cancelled）
        handle.abort();
        let result = handle.await;
        assert!(
            result.is_err(),
            "abort 后 await 应返回 Err，实际: {:?}",
            result
        );
        assert!(
            result.unwrap_err().is_cancelled(),
            "JoinError 应为 cancelled"
        );
    }

    // ----------------------------------------------------------------
    // 测试 4：清理失败只 warn 不中断 task
    // ----------------------------------------------------------------

    /// DAO wrapper：get 始终返回错误，用于测试清理失败不中断 task。
    ///
    /// 通过 AtomicUsize 计数 get 调用次数，验证 task 在首次清理失败后仍继续运行。
    struct FailingGetDao {
        get_call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BulwarkDao for FailingGetDao {
        async fn get(&self, _key: &str) -> BulwarkResult<Option<String>> {
            self.get_call_count.fetch_add(1, Ordering::SeqCst);
            Err(BulwarkError::Dao("模拟清理失败".to_string()))
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
    }

    /// 验证清理失败时 task 只记录 warn 不中断，继续运行下一个周期。
    ///
    /// 策略：使用 get 始终失败的 DAO，启动间隔=1 秒的清理 task。
    /// 等待 1.5 秒后验证 get 被调用 >= 2 次（首次立即执行 + 1 秒后第二次），
    /// 且 task 仍存活（is_finished() == false）。
    #[tokio::test]
    async fn spawn_cleanup_task_cleanup_failure_does_not_crash() {
        let get_call_count = Arc::new(AtomicUsize::new(0));
        let dao: Arc<dyn BulwarkDao> = Arc::new(FailingGetDao {
            get_call_count: get_call_count.clone(),
        });
        let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
        // 添加 token 到内存索引（不经过 DAO，确保 cleanup 有内容可遍历）
        session.add_login_token("user1", "token1");

        // 启动清理 task，间隔 1 秒
        let handle = spawn_cleanup_task(session.clone(), 1).unwrap();

        // 等待 2 个周期（tokio::time::interval 首次 tick 立即返回，第二次在 1 秒后）
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // 验证 cleanup 被调用多次（task 在首次失败后仍继续运行）
        let calls = get_call_count.load(Ordering::SeqCst);
        assert!(
            calls >= 2,
            "清理失败后 task 应继续运行，至少调用 2 次 get，实际: {}",
            calls
        );

        // 验证 task 仍存活（未因 panic 或错误退出）
        assert!(!handle.is_finished(), "清理失败不应导致 task 终止");

        // 清理 task
        handle.abort();
    }

    // ============================================================
    // T114: AuthBackend 桥接测试（R-msa-005）
    // ============================================================
    //
    // 测试 init_backend / get_backend / BulwarkUtil 委托逻辑。
    // 所有涉及 CURRENT_BACKEND 全局状态的测试必须用 #[serial] 串行化，
    // 并在测试前后调用 reset_backend_for_test() 重置状态。

    /// Mock AuthBackend，记录方法调用次数。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    struct MockAuthBackend {
        check_login_calls: Arc<AtomicUsize>,
        check_permission_calls: Arc<AtomicUsize>,
    }

    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    impl MockAuthBackend {
        fn new() -> Self {
            Self {
                check_login_calls: Arc::new(AtomicUsize::new(0)),
                check_permission_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[async_trait::async_trait]
    impl crate::backend::AuthBackend for MockAuthBackend {
        async fn login(&self, _login_id: &str, _params: &LoginParams) -> BulwarkResult<String> {
            Ok("mock-token".to_string())
        }
        async fn logout(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_login(&self, _token: &str) -> BulwarkResult<bool> {
            self.check_login_calls.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }
        async fn check_permission(&self, _token: &str, _permission: &str) -> BulwarkResult<()> {
            self.check_permission_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn check_role(&self, _token: &str, _role: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_safe(&self, _token: &str) -> BulwarkResult<bool> {
            Ok(true)
        }
        async fn check_disable(&self, _token: &str) -> BulwarkResult<bool> {
            Ok(false)
        }
        async fn check_api_key(&self, _api_key: &str, _namespace: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn get_token_info(&self, token: &str) -> BulwarkResult<crate::backend::TokenInfo> {
            Ok(crate::backend::TokenInfo {
                token: token.to_string(),
                created_at: 0,
                last_active_at: 0,
            })
        }
        async fn get_session(&self, token: &str) -> BulwarkResult<crate::backend::SessionData> {
            Ok(crate::backend::SessionData {
                token: token.to_string(),
                login_id: "mock-user".to_string(),
                created_at: 0,
                last_active_at: 0,
                attrs: std::collections::HashMap::new(),
                device: None,
                ip: None,
                user_agent: None,
                safe_services: std::collections::HashMap::new(),
                #[cfg(feature = "dynamic-active-timeout")]
                dynamic_active_timeout: None,
                #[cfg(feature = "anonymous-session")]
                is_anon: false,
            })
        }
        async fn kickout(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn switch_to(&self, _token: &str, _target_login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn renew_to_equivalent(&self, token: &str) -> BulwarkResult<String> {
            Ok(format!("renewed-{}", token))
        }
    }

    /// 验证 init_backend 成功初始化。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_init_backend_success() {
        reset_backend_for_test();
        let backend = Arc::new(MockAuthBackend::new());
        let result = init_backend(backend);
        assert!(result.is_ok(), "init_backend 应成功");
        reset_backend_for_test();
    }

    /// 验证 init_backend 重复调用返回错误。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_init_backend_duplicate_fails() {
        reset_backend_for_test();
        let backend1 = Arc::new(MockAuthBackend::new());
        let backend2 = Arc::new(MockAuthBackend::new());
        init_backend(backend1).unwrap();
        let result = init_backend(backend2);
        assert!(result.is_err(), "重复 init_backend 应返回错误");
        reset_backend_for_test();
    }

    /// 验证 BulwarkUtil::check_login 委托 CURRENT_BACKEND。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_check_login_delegates_to_backend() {
        reset_backend_for_test();
        let mock = MockAuthBackend::new();
        let call_count = mock.check_login_calls.clone();
        init_backend(Arc::new(mock)).unwrap();

        // 设置 token 上下文后调用 check_login
        let result = crate::stp::with_current_token("test-token".to_string(), async {
            BulwarkUtil::check_login().await
        })
        .await;

        assert!(result.is_ok(), "check_login 应成功");
        assert!(result.unwrap(), "MockAuthBackend.check_login 返回 true");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "MockAuthBackend.check_login 应被调用 1 次"
        );
        reset_backend_for_test();
    }

    /// 验证 BulwarkUtil::check_permission 委托 CURRENT_BACKEND。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_check_permission_delegates_to_backend() {
        reset_backend_for_test();
        let mock = MockAuthBackend::new();
        let call_count = mock.check_permission_calls.clone();
        init_backend(Arc::new(mock)).unwrap();

        let result = crate::stp::with_current_token("test-token".to_string(), async {
            BulwarkUtil::check_permission("user:read").await
        })
        .await;

        assert!(result.is_ok(), "check_permission 应成功");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "MockAuthBackend.check_permission 应被调用 1 次"
        );
        reset_backend_for_test();
    }

    /// 验证未初始化时 fallback 到 BulwarkManager（backend-embedded feature）。
    #[cfg(feature = "backend-embedded")]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_fallback_to_bulwark_manager_when_not_initialized() {
        reset_backend_for_test();
        // 未调用 init_backend，应 fallback 到 BulwarkManager
        // BulwarkManager 未初始化时返回 BulwarkError::Session
        let result = crate::stp::with_current_token("test-token".to_string(), async {
            BulwarkUtil::check_login().await
        })
        .await;
        // fallback 路径调用 BulwarkManager::logic()，未初始化时返回 Err
        assert!(
            result.is_err(),
            "未初始化时应 fallback 到 BulwarkManager 并返回其错误"
        );
        reset_backend_for_test();
    }

    /// 验证 check_safe 委托后 bool→Result<()> 适配（is_safe=true → Ok(())）。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_check_safe_true_returns_ok() {
        reset_backend_for_test();
        // MockAuthBackend.check_safe 返回 Ok(true)
        init_backend(Arc::new(MockAuthBackend::new())).unwrap();

        let result = crate::stp::with_current_token("test-token".to_string(), async {
            BulwarkUtil::check_safe().await
        })
        .await;

        assert!(result.is_ok(), "check_safe=true 应返回 Ok(())");
        reset_backend_for_test();
    }

    /// 验证 check_disable 委托后 bool→Result<()> 适配（is_disabled=false → Ok(())）。
    #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn t114_check_disable_false_returns_ok() {
        reset_backend_for_test();
        // MockAuthBackend.check_disable 返回 Ok(false)
        init_backend(Arc::new(MockAuthBackend::new())).unwrap();

        let result = crate::stp::with_current_token("test-token".to_string(), async {
            BulwarkUtil::check_disable().await
        })
        .await;

        assert!(result.is_ok(), "check_disable=false 应返回 Ok(())");
        reset_backend_for_test();
    }

    // ============================================================
    // T116: Embedded 模式行为验证（R-msa-005）
    // ============================================================
    //
    // 验证 init_backend(BackendEmbedded) 后，BulwarkUtil 委托链路：
    // BulwarkUtil → CURRENT_BACKEND(BackendEmbedded) → BulwarkManager
    //
    // 由于 BulwarkManager 未初始化（单元测试环境），BackendEmbedded::check_login
    // 会返回 BulwarkError::Session。这验证了委托链路正确连接。

    /// 验证 Embedded 模式下 BulwarkUtil 委托 BackendEmbedded → BulwarkManager。
    #[cfg(feature = "backend-embedded")]
    #[tokio::test]
    #[serial_test::serial]
    async fn t116_embedded_mode_delegates_to_bulwark_manager() {
        reset_backend_for_test();
        // 初始化 BackendEmbedded
        init_backend(Arc::new(crate::backend::BackendEmbedded::new())).unwrap();

        // 调用 BulwarkUtil::check_login，应委托 BackendEmbedded → BulwarkManager
        // BulwarkManager 未初始化时返回 BulwarkError::Session
        let result = crate::stp::with_current_token("test-token".to_string(), async {
            BulwarkUtil::check_login().await
        })
        .await;

        // 验证委托链路：返回错误说明 BackendEmbedded 调用了 BulwarkManager
        assert!(
            result.is_err(),
            "Embedded 模式应委托 BackendEmbedded → BulwarkManager，未初始化时返回错误"
        );
        reset_backend_for_test();
    }

    /// 验证 Embedded 模式下 fallback 路径与委托路径行为一致。
    ///
    /// fallback 路径（未 init_backend）：直接调用 BulwarkManager::logic()?.check_login()
    /// 委托路径（init_backend(BackendEmbedded)）：BackendEmbedded::check_login() → BulwarkManager::logic()?.check_login()
    ///
    /// 两条路径都调用 BulwarkManager::logic()，未初始化时都返回 BulwarkError::Session。
    #[cfg(feature = "backend-embedded")]
    #[tokio::test]
    #[serial_test::serial]
    async fn t116_embedded_mode_fallback_and_delegate_consistent() {
        // 测试 fallback 路径（未 init_backend）
        reset_backend_for_test();
        let fallback_result = crate::stp::with_current_token("test-token".to_string(), async {
            BulwarkUtil::check_login().await
        })
        .await;

        // 测试委托路径（init_backend(BackendEmbedded)）
        init_backend(Arc::new(crate::backend::BackendEmbedded::new())).unwrap();
        let delegate_result = crate::stp::with_current_token("test-token".to_string(), async {
            BulwarkUtil::check_login().await
        })
        .await;

        // 两条路径都应返回错误（BulwarkManager 未初始化）
        assert!(fallback_result.is_err(), "fallback 路径应返回错误");
        assert!(delegate_result.is_err(), "委托路径应返回错误");

        // 验证错误类型一致（都是 Session 错误）
        match (fallback_result.unwrap_err(), delegate_result.unwrap_err()) {
            (crate::error::BulwarkError::Session(_), crate::error::BulwarkError::Session(_)) => {},
            (f, d) => panic!(
                "两条路径错误类型应一致（Session），fallback={:?}, delegate={:?}",
                f, d
            ),
        }
        reset_backend_for_test();
    }

    // ============================================================
    // T117: Remote 模式委托验证（R-msa-005）
    // ============================================================
    //
    // 验证 init_backend(BackendRemote) 后，BulwarkUtil 委托 BackendRemote 发送 HTTP 请求。
    // 使用 wiremock 启动 mock server，验证 HTTP 请求正确发送。

    /// 验证 Remote 模式下 BulwarkUtil::check_login 委托 BackendRemote 发送 HTTP 请求。
    #[cfg(feature = "backend-remote")]
    #[tokio::test]
    #[serial_test::serial]
    async fn t117_remote_mode_delegates_to_backend_remote() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        reset_backend_for_test();

        // 启动 mock server
        let server = MockServer::start().await;

        // 设置 mock：期望收到 POST /api/v1/auth/check-login + X-API-Key header
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-login"))
            .and(header("X-API-Key", "test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": true,
                "error_code": null,
                "message": null
            })))
            .expect(1)
            .mount(&server)
            .await;

        // 初始化 BackendRemote 指向 mock server
        let remote = crate::backend::BackendRemote::new(
            server.uri(),
            "test-api-key",
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        init_backend(Arc::new(remote)).unwrap();

        // 调用 BulwarkUtil::check_login，应委托 BackendRemote 发送 HTTP 请求
        let result = crate::stp::with_current_token("test-token".to_string(), async {
            BulwarkUtil::check_login().await
        })
        .await;

        assert!(
            result.is_ok(),
            "Remote 模式 check_login 应成功: {:?}",
            result
        );
        assert!(
            result.unwrap(),
            "mock server 返回 true，BulwarkUtil::check_login 应返回 true"
        );
        reset_backend_for_test();
    }

    /// 验证 Remote 模式下 BulwarkUtil::check_permission 委托 BackendRemote。
    #[cfg(feature = "backend-remote")]
    #[tokio::test]
    #[serial_test::serial]
    async fn t117_remote_mode_check_permission_delegates() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        reset_backend_for_test();

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/check-permission"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "error_code": null,
                "message": null
            })))
            .expect(1)
            .mount(&server)
            .await;

        let remote = crate::backend::BackendRemote::new(
            server.uri(),
            "test-api-key",
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        init_backend(Arc::new(remote)).unwrap();

        let result = crate::stp::with_current_token("test-token".to_string(), async {
            BulwarkUtil::check_permission("user:read").await
        })
        .await;

        assert!(
            result.is_ok(),
            "Remote 模式 check_permission 应成功: {:?}",
            result
        );
        reset_backend_for_test();
    }

    // ============================================================
    // 覆盖率补充：JwtMode / has_permission/has_role 错误路径 / 委托链路
    // ============================================================

    /// 验证 `JwtMode::default()` 返回 `Mixin`（推荐默认模式）。
    ///
    /// 覆盖 `#[default]` 标注的 `Mixin` 变体。
    #[test]
    fn jwt_mode_default_is_mixin() {
        let mode = JwtMode::default();
        assert_eq!(
            mode,
            JwtMode::Mixin,
            "JwtMode 默认应为 Mixin（推荐平衡模式）"
        );
    }

    /// 验证 `JwtMode` 三个变体互不相等（PartialEq 派生正确）。
    #[test]
    fn jwt_mode_variants_distinct() {
        assert_ne!(JwtMode::Stateless, JwtMode::Mixin);
        assert_ne!(JwtMode::Mixin, JwtMode::Simple);
        assert_ne!(JwtMode::Stateless, JwtMode::Simple);
        // 自身相等
        assert_eq!(JwtMode::Stateless, JwtMode::Stateless);
        assert_eq!(JwtMode::Mixin, JwtMode::Mixin);
        assert_eq!(JwtMode::Simple, JwtMode::Simple);
    }

    /// 验证 `JwtMode` 的 Clone / Copy 行为（值拷贝，不丢失原值）。
    #[test]
    fn jwt_mode_clone_preserves_value() {
        let original = JwtMode::Stateless;
        let cloned = original;
        // Copy 语义：原值仍可用
        assert_eq!(original, cloned);
        // Clone 等价于 Copy
        assert_eq!(JwtMode::Mixin.clone(), JwtMode::Mixin);
    }

    /// 验证 `has_permission("")` 返回 `InvalidParam`（空字符串校验在本地完成，
    /// 不需要初始化 BulwarkManager）。
    ///
    /// 覆盖 `has_permission` 中的本地参数校验路径。
    #[tokio::test]
    async fn has_permission_empty_returns_invalid_param() {
        let result = BulwarkUtil::has_permission("").await;
        assert!(
            matches!(result, Err(crate::error::BulwarkError::InvalidParam(_))),
            "空 permission 应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// 验证 `has_role("")` 返回 `InvalidParam`。
    ///
    /// 覆盖 `has_role` 中的本地参数校验路径。
    #[tokio::test]
    async fn has_role_empty_returns_invalid_param() {
        let result = BulwarkUtil::has_role("").await;
        assert!(
            matches!(result, Err(crate::error::BulwarkError::InvalidParam(_))),
            "空 role 应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// 验证 `login_simple` 在未初始化 `BulwarkManager` 时返回 `Session` 错误。
    ///
    /// 覆盖 `login_simple` → `login` → `BulwarkManager::logic()?` 委托链路。
    /// 在 backend-embedded feature 下，未 `init_backend()` 时 fallback 到 BulwarkManager 路径。
    #[tokio::test]
    #[serial_test::serial]
    async fn login_simple_delegates_to_bulwark_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::BulwarkManager::reset_for_test();

        let result = BulwarkUtil::login_simple("user1").await;
        assert!(
            matches!(result, Err(crate::error::BulwarkError::Session(ref msg)) if msg.contains("BulwarkManager 未初始化")),
            "未初始化时应返回 'BulwarkManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `logout_by_login_id` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `logout_by_login_id` → `BulwarkManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn logout_by_login_id_delegates_to_bulwark_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::BulwarkManager::reset_for_test();

        let result = BulwarkUtil::logout_by_login_id("user1").await;
        assert!(
            matches!(result, Err(crate::error::BulwarkError::Session(ref msg)) if msg.contains("BulwarkManager 未初始化")),
            "未初始化时应返回 'BulwarkManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `kickout` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `kickout` → `BulwarkManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn kickout_delegates_to_bulwark_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::BulwarkManager::reset_for_test();

        let result = BulwarkUtil::kickout("user1").await;
        assert!(
            matches!(result, Err(crate::error::BulwarkError::Session(ref msg)) if msg.contains("BulwarkManager 未初始化")),
            "未初始化时应返回 'BulwarkManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `config()` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `config()` → `BulwarkManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn config_delegates_to_bulwark_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::BulwarkManager::reset_for_test();

        let result = BulwarkUtil::config();
        assert!(
            matches!(result, Err(crate::error::BulwarkError::Session(ref msg)) if msg.contains("BulwarkManager 未初始化")),
            "未初始化时应返回 'BulwarkManager 未初始化'，实际: {:?}",
            result
        );
    }

    /// 验证 `get_login_id_by_token` 在未初始化时返回 `Session` 错误。
    ///
    /// 覆盖 `get_login_id_by_token` → `with_current_token` → `get_login_id`
    /// → `BulwarkManager::logic()?` 委托链路。
    #[tokio::test]
    #[serial_test::serial]
    async fn get_login_id_by_token_delegates_to_bulwark_manager() {
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        reset_backend_for_test();
        crate::manager::BulwarkManager::reset_for_test();

        let result = BulwarkUtil::get_login_id_by_token("some-token").await;
        assert!(
            matches!(result, Err(crate::error::BulwarkError::Session(ref msg)) if msg.contains("BulwarkManager 未初始化")),
            "未初始化时应返回 'BulwarkManager 未初始化'，实际: {:?}",
            result
        );
    }
}
