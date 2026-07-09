//! BulwarkUtil 静态方法入口 + JwtMode 校验模式枚举。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use crate::config::BulwarkConfig;
use crate::error::BulwarkResult;
use crate::stp::core::BulwarkCore;
use crate::stp::mfa::MfaLogic;
use crate::stp::permission::PermissionLogic;
use crate::stp::session::SessionLogic;
use crate::stp::token::TokenLogic;
use std::sync::Arc;

// ============================================================================
// JwtMode：JWT 校验模式（依据 spec protocol-jwt-modes R-001）
// ============================================================================

/// JWT 校验模式（依据 spec protocol-jwt-modes R-001）。
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
    pub async fn login(id: impl Into<String>) -> BulwarkResult<String> {
        let id: String = id.into();
        crate::manager::BulwarkManager::logic()?.login(&id).await
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

    /// 主动吊销 token：销毁指定 token 的会话（v0.4.2 新增，依据 spec listener-events-extend R-002）。
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

    /// 通过指定 token 获取关联的登录 ID（依据 spec web-adapters D12）。
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
        crate::manager::BulwarkManager::logic()?
            .check_role(role)
            .await
    }

    /// 检查当前会话是否持有指定权限（0.6.1 新增，依据 spec bulwark-util-api R-util-api-001，对应 FRD §5.3.2 hasPermission）。
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

    /// 检查当前会话是否持有指定角色（0.6.1 新增，依据 spec bulwark-util-api R-util-api-002，对应 FRD §5.3.2 hasRole）。
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

    /// 获取当前登录主体的权限列表（0.6.1 新增，依据 spec bulwark-util-api R-util-api-003，对应 FRD §5.3.2 getPermissionList）。
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

    /// 获取当前登录主体的角色列表（0.6.1 新增，依据 spec bulwark-util-api R-util-api-004，对应 FRD §5.3.2 getRoleList）。
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

    /// 校验 access_token 类型会话（0.5.0 新增，依据 spec annotation-macros P2 前置）。
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

    /// 校验 client_token 类型会话（0.5.0 新增，依据 spec annotation-macros P2 前置）。
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

    /// 校验 temp_token 类型会话（0.5.0 新增，依据 spec annotation-macros P2 前置）。
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

    /// 检查二级认证（MFA）状态（0.3.0 新增，依据 spec annotation-handling）。
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
        crate::manager::BulwarkManager::logic()?.check_safe().await
    }

    /// 检查账号是否被禁用（0.3.0 新增，依据 spec annotation-handling）。
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
        crate::manager::BulwarkManager::logic()?
            .check_disable()
            .await
    }

    /// 通过外部 token 反向建立会话（0.2.0 新增，依据 spec core-auth-api）。
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

    /// 验证显式传入的 token 并返回关联的 login_id（0.2.0 新增，依据 spec core-auth-api）。
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

    /// 刷新 token（0.2.0 新增，依据 spec core-auth-api）。
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
