// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 认证逻辑模块：定义以 token 为入参的登录 / 登出抽象，不读取 task_local 上下文，
//! 便于 `protocol-jwt` 等协议层模块复用。

use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;

use crate::core::token::Token;
use crate::error::{GarrisonError, GarrisonResult};
use crate::session::GarrisonSession;

/// 身份切换权限校验 trait：`switch_to` 执行前调用 [`SwitchToGuard::check`]，默认实现
/// [`DenyAllSwitchToGuard`] 拒绝所有切换（fail-closed 安全默认），调用方经
/// [`AuthLogicDefault::with_switch_to_guard`] 注入自定义规则（如基于角色 / PermissionChecker /
/// 配置白名单）。
///
/// # Security Warning
///
/// `switch_to` 是高风险操作：guard 直接返回 `Ok(())` 会让任何身份切换到任意目标（含管理员），
/// 造成**垂直越权**。实现方必须校验 original 的 `switch_to` 权限（如 `admin:switch`）与 target
/// 可切换范围（如同一租户 / 下级账号），并记录审计日志（original / target / timestamp /
/// request_context）；可参考 `AdminOnlyGuard` 示例。
///
/// # 示例
///
/// ```ignore
/// use std::sync::Arc;
/// use garrison::core::auth::{AuthLogicDefault, SwitchToGuard};
/// use garrison::error::GarrisonResult;
///
/// // 仅允许 admin 切换
/// struct AdminOnlyGuard;
/// #[async_trait::async_trait]
/// impl SwitchToGuard for AdminOnlyGuard {
/// async fn check(&self, original: &str, target: &str) -> GarrisonResult<()> {
/// if original.starts_with("admin:") {
/// Ok(())
/// } else {
/// Err(garrison::error::GarrisonError::NotPermission(
/// format!("{} 无权切换到 {}", original, target)
/// ))
/// ))
/// }
/// }
/// }
///
/// let auth = AuthLogicDefault::new(session, token_handler, 3600)
/// .with_switch_to_guard(Arc::new(AdminOnlyGuard));
/// ```
#[async_trait]
pub trait SwitchToGuard: Send + Sync {
    /// 校验是否允许从 `original_login_id` 切换到 `target_login_id`；允许返回 `Ok(())`，
    /// 权限不足返回 `Err(GarrisonError::NotPermission)`。
    async fn check(&self, original_login_id: &str, target_login_id: &str) -> GarrisonResult<()>;
}

/// 拒绝所有切换的默认 guard（fail-closed 安全默认）：未注入自定义 guard 时所有 `switch_to`
/// 调用都被拒绝，强制调用方显式配置权限规则。
pub struct DenyAllSwitchToGuard;

/// 认证逻辑 trait：所有方法以 `token: &str` 显式入参、不读取 `tokio::task_local`，
/// 须用 `#[async_trait]` 标注，trait 绑定 `Send + Sync`。
#[async_trait]
pub trait AuthLogic: Send + Sync {
    /// 执行登录操作，生成非空 token 并建立会话；`params` 为可选参数（如 device、timeout），
    /// 由实现方解析。
    async fn login(&self, id: &str, params: Option<&str>) -> GarrisonResult<String>;

    /// 执行登出操作，销毁指定 token 对应的会话；幂等，不存在的 token 返回 `Ok(())`。
    async fn logout(&self, token: &str) -> GarrisonResult<()>;

    /// 检查 token 是否存在且未过期。
    async fn is_login(&self, token: &str) -> GarrisonResult<bool>;

    /// 获取 token 关联的登录主体标识；token 无效或已过期返回 `Ok(None)`。
    async fn get_login_id(&self, token: &str) -> GarrisonResult<Option<String>>;

    /// 校验 token 有效性并返回关联的 login_id；与 `get_login_id` 不同，失败时抛
    /// `Err(GarrisonError::InvalidToken)` 而非返回 `None`，适用于必须登录的场景。
    async fn verify_token(&self, token: &str) -> GarrisonResult<String>;

    /// 身份切换：验证 token 后把 TokenSession 的 `login_id` 更新为 `target_login_id`，
    /// 原 `login_id` 存入 `attrs["switched_from"]` 供审计追溯。
    ///
    /// # 错误
    /// token 无效或已过期 → `NotLogin`；`target_login_id` 为空 → `InvalidParam`；无权切换或
    /// 目标不可用 → `NotPermission`（反枚举：目标不存在与权限不足返回**同一**模糊错误类型与
    /// 稳定错误码 `core-auth-switch-to-denied`，外部不可借错误差异枚举账号存在性）。
    ///
    /// # 默认实现
    /// 返回 `GarrisonError::NotImplemented`，由 `AuthLogicDefault` 覆盖。
    async fn switch_to(&self, _token: &str, _target_login_id: &str) -> GarrisonResult<()> {
        Err(GarrisonError::NotImplemented(format!(
            "core-switch-to-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }

    /// Token 置换：生成 `login_id` / session attrs / 剩余 TTL 相同但字符串不同的新 token，
    /// 新 session 创建成功后删除旧 session；token 无效或已过期返回 `Err(NotLogin)`。
    ///
    /// # 默认实现
    /// 返回 `GarrisonError::NotImplemented`，由 `AuthLogicDefault` 覆盖。
    async fn renew_to_equivalent(&self, _token: &str) -> GarrisonResult<String> {
        Err(GarrisonError::NotImplemented(format!(
            "core-renew-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }
}

/// `AuthLogic` 的默认实现：委托 `GarrisonSession`（会话管理）与 `core-token::Token`（token 生成与校验），
/// 协议层模块直接复用。
pub struct AuthLogicDefault {
    /// 会话管理器。
    session: Arc<GarrisonSession>,
    /// Token 生成与校验处理器。
    token_handler: Arc<dyn Token>,
    /// 默认 token 有效期（秒）；构造器级正数校验：非正数回退 3600 秒并 warn——负值会在 TTL
    /// 计算处经 `as u64` 回绕成事实上的永久会话（CWE-190）。
    timeout: i64,
    /// 是否启用 remember_me 扩展超时。
    remember_me_enabled: bool,
    /// remember_me 扩展超时秒数（默认 7776000 = 90 天）；同样受构造器级正数校验：
    /// `with_remember_me` 拒绝非正数并回退 7776000、输出 warn。
    remember_me_timeout: i64,
    /// 登录时是否播种主认证因子（amr=["pwd"] / aal:1 / auth_time），默认 `true`，经
    /// [`AuthLogicDefault::with_seed_primary_amr`] 设置（与 `config.seed_primary_amr` 同语义）；
    /// 凭证委托 login 未发生密码校验的部署应关闭，避免向签发 claim 断言不存在的认证事实。
    seed_primary_amr: bool,
    /// 身份切换权限校验 guard（默认 DenyAllSwitchToGuard fail-closed）。
    switch_to_guard: Arc<dyn SwitchToGuard>,
    /// per-token 异步互斥锁（`DashMap<String, Arc<tokio::sync::Mutex<()>>>`，与
    /// `GarrisonSession` 的锁表惯例一致），串行化同一 token 的 `renew_to_equivalent`
    /// 以修复 TOCTOU 竞态（CWE-362）；粒度选 per-token：不同 token 的 renew 仍可并行。
    ///
    /// 内存清理：renew 结束时 `Arc::strong_count == 1` 则移除 entry，防攻击者用大量随机
    /// token 灌满 DashMap 导致 OOM（CWE-770）。已知限制：检查与移除之间存在 TOCTOU 窗口，
    /// 最坏只导致 entry 被错误移除、该任务下次 renew 重建，不损坏数据或造成安全漏洞。
    renew_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

mod default;
mod guards;

#[cfg(test)]
pub(super) use default::parse_remember_me_param;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
