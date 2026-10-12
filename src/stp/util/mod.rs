// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! GarrisonUtil 静态方法入口 + JwtMode 校验模式枚举 + AuthBackend 全局桥接。
use crate::config::GarrisonConfig;
use crate::error::GarrisonResult;
// loc! 使用点由 listener（session kickout 提示）与 backend-*（NotSafe 提示）两处门控，导入需覆盖并集，否则缺宏或 unused import（-D warnings）。
#[cfg(any(
    feature = "backend-embedded",
    feature = "backend-remote",
    feature = "listener"
))]
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

// AuthBackend 全局桥接
// 取 fallback 而非显式初始化 panic（后者属 breaking change，backend-embedded 需 zero-break）：已 init_backend() 时委托 AuthBackend，backend-embedded 未初始化回退 GarrisonManager，仅 backend-remote 未初始化返回 Config，无 backend feature 直接走 GarrisonManager。
// 用 ArcSwapOption 而非 Mutex：get_backend 是每请求热路径（check_login / check_permission 各一次），ArcSwap 读路径无锁（wait-free），并保留测试可重置能力。

/// 全局认证后端实例的 Sized 包装：arc-swap 的 `RefCnt` 要求元素 Sized，无法直接存 `Arc<dyn AuthBackend>`。
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
#[derive(Clone)]
struct BackendHandle(Arc<dyn crate::backend::AuthBackend>);

/// 全局认证后端实例；经 [`init_backend`] 初始化，未初始化时按 feature flag 决定 fallback 行为。
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
static CURRENT_BACKEND: arc_swap::ArcSwapOption<BackendHandle> =
    arc_swap::ArcSwapOption::const_empty();

/// 初始化全局认证后端：必须在使用 `GarrisonUtil` 前调用一次，重复调用返回 `Config`。
///
/// # 示例
///
/// ```ignore
/// use std::sync::Arc;
/// use garrison::backend::{AuthBackend, BackendEmbedded};
/// use garrison::stp::init_backend;
///
/// // Embedded 模式
/// init_backend(Arc::new(BackendEmbedded::new())).unwrap();
///
/// // Remote 模式
/// // init_backend(Arc::new(BackendRemote::new("https://auth:8443", "key", Duration::from_secs(5)).unwrap())).unwrap();
/// ```
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
pub fn init_backend(backend: Arc<dyn crate::backend::AuthBackend>) -> GarrisonResult<()> {
    try_init_backend(&CURRENT_BACKEND, backend)
}

/// CAS 初始化核心（与全局 static 分离，便于在局部 store 做并发测试）：仅当前值为 `None` 时写入，返回写入前的值，非 `None` 即 CAS 失败（已被其他线程初始化）。
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
fn try_init_backend(
    store: &arc_swap::ArcSwapOption<BackendHandle>,
    backend: Arc<dyn crate::backend::AuthBackend>,
) -> GarrisonResult<()> {
    let none: Option<std::sync::Arc<BackendHandle>> = None;
    let previous = store.compare_and_swap(&none, Some(Arc::new(BackendHandle(backend))));
    if previous.is_some() {
        return Err(crate::error::GarrisonError::Config(
            "stp-backend-already-init::".into(),
        ));
    }
    Ok(())
}

/// 获取已初始化的认证后端：`Ok(Some)` 已初始化；`Ok(None)` 未初始化且启用 backend-embedded（调用方应 fallback 到 GarrisonManager）；`Err` 未初始化且未启用 backend-embedded。
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
fn get_backend() -> GarrisonResult<Option<Arc<dyn crate::backend::AuthBackend>>> {
    let guard = CURRENT_BACKEND.load();
    if let Some(handle) = &*guard {
        return Ok(Some(Arc::clone(&handle.0)));
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

/// 重置全局认证后端（仅测试用，生产代码严禁调用）。
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
#[cfg(test)]
pub(crate) fn reset_backend_for_test() {
    CURRENT_BACKEND.store(None);
}

// 测试桩仅 backend-embedded 下存在，故模块门控收窄到单腿；backend-remote 单独启用时本测试不参与。
#[cfg(all(test, feature = "backend-embedded"))]
mod backend_bridge_tests {
    use super::*;

    /// 并发 init_backend（CAS）恰好一个成功、其余返回 Config，且成功后 store 可读到后端；在局部 store 上测试，避免污染全局 CURRENT_BACKEND。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_init_exactly_one_wins() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let store = Arc::new(arc_swap::ArcSwapOption::const_empty());
        let ok_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            let ok_count = Arc::clone(&ok_count);
            handles.push(tokio::spawn(async move {
                if try_init_backend(
                    &store,
                    Arc::new(crate::backend::embedded::BackendEmbedded::new()),
                )
                .is_ok()
                {
                    ok_count.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            ok_count.load(Ordering::SeqCst),
            1,
            "并发初始化应恰好一个成功（CAS 契约）"
        );
        assert!(store.load().is_some(), "初始化成功后 store 应持有后端实例");

        // 重复初始化返回 Config 错误（既有语义保持）
        let err = try_init_backend(
            &store,
            Arc::new(crate::backend::embedded::BackendEmbedded::new()),
        )
        .unwrap_err();
        assert!(
            matches!(err, crate::error::GarrisonError::Config(ref m) if m.contains("stp-backend-already-init")),
            "重复初始化应返回 already-init Config 错误，实际: {:?}",
            err
        );
    }
}

// JwtMode：JWT 校验模式

/// JWT 校验模式：控制 `check_login` 在 JWT verify 与 session 查询之间的组合策略；不依赖 jsonwebtoken，总是编译（即使未启用 protocol-jwt）。
/// Stateless 仅 JWT verify（需 protocol-jwt + token_style=jwt）；Mixin（默认）verify + session 二级校验；Simple 仅 session，JWT 只作 token 载体。未启用 protocol-jwt 时 Stateless 返回 Config、Mixin 退化为仅查 session。
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

// GarrisonUtil：静态方法入口（委托全局 GarrisonManager 单例）

/// 工具结构体（对应 `StpUtil`）：面向使用者的静态方法入口，内部委托 `GarrisonManager::logic()` 全局单例。
/// 使用前提：须先执行 `GarrisonManager::builder().dao(dao).config(config).interface(interface).build().await`，否则返回 `Session("GarrisonManager 未初始化")`。
pub struct GarrisonUtil;

impl GarrisonUtil {
    /// 执行登录：生成 token + 创建会话；未初始化返回 `Session`，生成/创建失败透传 `GarrisonError`。
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

    /// 便捷登录：等价于 `login(id, &LoginParams::default())`（无设备/IP/UA）。
    pub async fn login_simple(id: impl Into<String>) -> GarrisonResult<String> {
        Self::login(id, &LoginParams::default()).await
    }

    /// 执行登出：从 task_local 取当前 token 并销毁；未设置 token 时幂等返回 `Ok(())`。
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

    /// 按账号登出：销毁指定 login_id 的所有会话；backend 模式委托 backend.kickout（login_id 维度销毁，语义等价）。
    pub async fn logout_by_login_id(login_id: impl Into<String>) -> GarrisonResult<()> {
        let login_id: String = login_id.into();
        // 与同族 login/kickout 对齐补 backend 分发——
        // backend 模式下认证状态由后端持有，本地直调 GarrisonManager 会落空。
        // backend.kickout 为 login_id 维度销毁（语义等同 logout_by_login_id）。
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                return backend.kickout(&login_id).await;
            }
        }
        crate::manager::GarrisonManager::logic()?
            .logout_by_login_id(&login_id)
            .await
    }

    /// 踢出用户：按账号踢出，语义等同 [`logout_by_login_id`](Self::logout_by_login_id)。
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

    /// 踢出会话：按 token 踢出；backend 模式委托 backend.logout（token 维度销毁，语义一致）。
    pub async fn kickout_by_token(token: &str) -> GarrisonResult<()> {
        // 与同族 kickout 对齐补 backend 分发。
        // backend.logout 为 token 维度销毁，与 kickout_by_token 语义一致。
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                return backend.logout(token).await;
            }
        }
        crate::manager::GarrisonManager::logic()?
            .kickout_by_token(token)
            .await
    }

    /// 密码修改后失效用户所有会话：清除全部 Token-Session / Account-Session 并广播 `Kickout`（reason: "password-changed"），缩小凭证泄露攻击窗口。
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

    /// 主动吊销 token：销毁会话并广播 `RevokeToken`（仅携 token，语义为"token 失效"）；[`kickout_by_token`](Self::kickout_by_token) 不广播事件（管理员强制下线语义）。token 不存在时幂等返回 `Ok(())`。
    pub async fn revoke_token(token: &str) -> GarrisonResult<()> {
        // 与同族 logout 对齐补 backend 分发。
        // backend.logout 为 token 维度销毁，与 revoke_token 语义一致。
        #[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
        {
            if let Some(backend) = get_backend()? {
                return backend.logout(token).await;
            }
        }
        crate::manager::GarrisonManager::logic()?
            .revoke_token(token)
            .await
    }

    /// 检查登录状态：`Ok(true)` 已登录且 token 有效；`Ok(false)` 未登录或无效（`throw_on_not_login=false`）；未登录且开关为 true 返回 `Session`。
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

    /// 获取当前登录 ID：已登录返回 `Some(login_id)`，未登录或无效返回 `None`。
    pub async fn get_login_id() -> GarrisonResult<Option<String>> {
        crate::manager::GarrisonManager::logic()?
            .get_login_id()
            .await
    }

    /// 通过指定 token 获取关联 login_id（适配 web extractor）：内部经 [`with_current_token`] 将 token 置入 task_local 后查询；与 [`get_login_id`] 的区别是显式接收 token 参数。
    ///
    /// [`get_login_id`]: Self::get_login_id
    /// [`with_current_token`]: crate::stp::with_current_token
    pub async fn get_login_id_by_token(token: &str) -> GarrisonResult<Option<String>> {
        super::with_current_token(token.to_string(), async { Self::get_login_id().await }).await
    }

    /// 校验权限：持有返回 `Ok(())`，未持有返回 `NotPermission`，未登录返回 `NotLogin` 或降级 `NotPermission`。
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

    /// 校验角色：持有返回 `Ok(())`，未持有返回 `NotRole`，未登录返回 `NotLogin` 或降级 `NotRole`。
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

    /// 检查当前会话是否持有权限（返回布尔而非抛异常，未登录或未持有均 `Ok(false)`）；`permission` 为空返回 `InvalidParam`。
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

    /// 检查当前会话是否持有角色（返回布尔而非抛异常，未登录或未持有均 `Ok(false)`）；`role` 为空返回 `InvalidParam`。
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

    /// 获取当前登录主体的权限列表（委托 `GarrisonPermissionStrategy`，未登录返回 `Ok(vec![])`）。
    pub async fn get_permission_list() -> GarrisonResult<Vec<String>> {
        crate::manager::GarrisonManager::logic()?
            .get_permission_list()
            .await
    }

    /// 获取当前登录主体的角色列表（委托 `GarrisonPermissionStrategy`，未登录返回 `Ok(vec![])`）。
    pub async fn get_role_list() -> GarrisonResult<Vec<String>> {
        crate::manager::GarrisonManager::logic()?
            .get_role_list()
            .await
    }

    /// 校验 access_token 类型会话（委托 `TokenLogic::check_access_token`，默认委托 check_login；未登录返回 `NotLogin`）。
    pub async fn check_access_token() -> GarrisonResult<()> {
        crate::manager::GarrisonManager::logic()?
            .check_access_token()
            .await
    }

    /// 校验 client_token 类型会话（委托 `TokenLogic::check_client_token`，默认委托 check_login；未登录返回 `NotLogin`）。
    pub async fn check_client_token() -> GarrisonResult<()> {
        crate::manager::GarrisonManager::logic()?
            .check_client_token()
            .await
    }

    /// 校验 temp_token 类型会话（委托 `TokenLogic::check_temp_token`，默认委托 check_login；未登录返回 `NotLogin`）。
    pub async fn check_temp_token() -> GarrisonResult<()> {
        crate::manager::GarrisonManager::logic()?
            .check_temp_token()
            .await
    }

    /// 检查二级认证（MFA）状态：先验会话（无效/已撤销返回 `Session`），有效会话未启用 MFA 返回 `Ok(())`，未通过返回 `NotSafe`。
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

    /// 检查账号是否被禁用：先验会话（无效返回 `Session`，"token 无效"不与"未封禁"合并），账号已禁用返回 `DisableService`。
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

    /// 校验 API Key：从 task_local CURRENT_TOKEN 取 Key 交 `check_api_key(namespace)`；不存在/已吊销返回 `InvalidToken`，已过期返回 `ExpiredToken`；`protocol-apikey` 关闭时返回 `Ok(())`。
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
    /// GarrisonUtil::check_api_key("internal").await
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

    /// 通过外部 token 反向建立会话（OAuth2/SSO 场景：外部已校验后建立内部会话）；未启用协议层 feature 返回 `NotImplemented`。
    pub async fn login_by_token(token: &str) -> GarrisonResult<()> {
        crate::manager::GarrisonManager::logic()?
            .login_by_token(token)
            .await
    }

    /// 验证显式传入的 token 并返回关联 login_id；token 无效返回 `InvalidToken`。
    pub async fn verify_token(token: &str) -> GarrisonResult<String> {
        crate::manager::GarrisonManager::logic()?
            .verify_token(token)
            .await
    }

    /// 刷新 token 返回新 token；未启用 protocol-jwt 返回 `NotImplemented`，token 已过期返回 `InvalidToken`。
    pub async fn refresh_token(token: &str) -> GarrisonResult<String> {
        crate::manager::GarrisonManager::logic()?
            .refresh_token(token)
            .await
    }

    // 同步版本（check_*_sync）：block_in_place + Handle::current().block_on 包装 async 版本，供 sync fn 宏 wrapper 调用
    // 约束：须在 tokio multi_thread runtime 内调用（block_in_place 要求）；task_local CURRENT_TOKEN 同 task 自动继承；`&str` 参数需 `.to_string()` move 进 block_on future（'static）。

    /// 同步版 [`check_login`](Self::check_login)：在当前 runtime 阻塞执行；不在 tokio multi_thread runtime 上下文会 panic（`block_in_place` 要求）。
    pub fn check_login_sync() -> GarrisonResult<bool> {
        task::block_in_place(|| Handle::current().block_on(Self::check_login()))
    }

    /// 同步版 [`check_permission`](Self::check_permission)；runtime 约束同 [`check_login_sync`](Self::check_login_sync)。
    pub fn check_permission_sync(perm: &str) -> GarrisonResult<()> {
        let perm = perm.to_string();
        task::block_in_place(|| Handle::current().block_on(Self::check_permission(&perm)))
    }

    /// 同步版 [`check_role`](Self::check_role)；runtime 约束同 [`check_login_sync`](Self::check_login_sync)。
    pub fn check_role_sync(role: &str) -> GarrisonResult<()> {
        let role = role.to_string();
        task::block_in_place(|| Handle::current().block_on(Self::check_role(&role)))
    }

    /// 同步版 [`check_access_token`](Self::check_access_token)；runtime 约束同 [`check_login_sync`](Self::check_login_sync)。
    pub fn check_access_token_sync() -> GarrisonResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_access_token()))
    }

    /// 同步版 [`check_client_token`](Self::check_client_token)；runtime 约束同 [`check_login_sync`](Self::check_login_sync)。
    pub fn check_client_token_sync() -> GarrisonResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_client_token()))
    }

    /// 同步版 [`check_temp_token`](Self::check_temp_token)；runtime 约束同 [`check_login_sync`](Self::check_login_sync)。
    pub fn check_temp_token_sync() -> GarrisonResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_temp_token()))
    }

    /// 同步版 [`check_api_key`](Self::check_api_key)（`protocol-apikey` 关闭时返回 `Ok(())`）；runtime 约束同 [`check_login_sync`](Self::check_login_sync)。
    pub fn check_api_key_sync(namespace: &str) -> GarrisonResult<()> {
        let namespace = namespace.to_string();
        task::block_in_place(|| Handle::current().block_on(Self::check_api_key(&namespace)))
    }

    /// 同步版 [`check_safe`](Self::check_safe)；runtime 约束同 [`check_login_sync`](Self::check_login_sync)。
    pub fn check_safe_sync() -> GarrisonResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_safe()))
    }

    /// 同步版 [`check_disable`](Self::check_disable)；runtime 约束同 [`check_login_sync`](Self::check_login_sync)。
    pub fn check_disable_sync() -> GarrisonResult<()> {
        task::block_in_place(|| Handle::current().block_on(Self::check_disable()))
    }

    /// 获取当前 `GarrisonConfig` 的 `Arc` 引用（供 extractor / middleware 使用）。
    pub fn config() -> GarrisonResult<Arc<GarrisonConfig>> {
        Ok(crate::manager::GarrisonManager::logic()?.config())
    }
}

// spawn_cleanup_task：后台定期清理过期 token

/// 启动后台 task 每 `interval_secs` 秒清理 `login_token_map` 中过期/已注销 token；清理失败只记 `warn` 不中断；`interval_secs <= 0` 返回 `None`，否则返回 `Some(JoinHandle)`（可 abort 或 await）。
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
