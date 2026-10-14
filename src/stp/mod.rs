// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Stp 模块，提供核心认证逻辑与工具入口。
//!
//! 5 个子 trait 按职责域分离（super-trait `GarrisonCore`），`GarrisonLogicDefault` 为默认实现；
//! `tokio::task_local` 存储当前请求 token，经 `with_current_token` 设置、`current_token` 读取。

use crate::config::GarrisonConfig;
use crate::core::auth::AuthLogic;
use crate::core::permission::PermissionChecker;
// `GarrisonError`/`GarrisonResult` 供 `default_impl.rs` / `tests.rs` 经 `use super::*` glob 引用（tests.rs 无 feature 门控），故不可 cfg-gate。
#[allow(unused_imports)]
use crate::error::{GarrisonError, GarrisonResult};
#[cfg(feature = "listener")]
use crate::listener::GarrisonListenerManager;
use crate::plugin::GarrisonPluginManager;
use crate::session::GarrisonSession;
use crate::strategy::GarrisonPermissionStrategy;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

// ParameterQuery 参数化查询模块
#[cfg(feature = "parameter-query")]
pub mod parameter;

pub mod clock;
pub mod context;
pub mod core;
pub mod interface;
pub mod mfa;
pub mod password;
pub mod permission;
#[cfg(feature = "security-extra")]
pub mod safe;
pub mod session;
pub mod token;
pub mod util;

// 子 trait re-exports（供 crate::stp::SessionLogic 等路径访问）
pub use self::context::{
    current_ip, current_token, with_current_ip, with_current_token, with_login_id_scope,
};
pub use self::core::GarrisonCore;
pub use self::interface::GarrisonInterface;
pub use self::mfa::MfaLogic;
pub use self::mfa::{
    AmrEntry, MfaChainDecision, RequiredActionChallenge, RequiredActionContext,
    RequiredActionProvider,
};
#[cfg(feature = "mfa-recovery")]
pub use self::mfa::{RecoveryCodeManager, RecoveryVerify};
pub use self::password::PasswordLogic;
pub use self::permission::PermissionLogic;
pub use self::session::SessionLogic;
pub use self::token::TokenLogic;
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
pub use self::util::init_backend;
pub use self::util::{GarrisonUtil, JwtMode};

/// 登录参数：device/ip/user_agent 写入 `TokenSession`，`remember_me` 延长 Token 有效期，`require_mfa` 由 `DeviceBindingPolicy` 在 strict 模式新设备登录时置位。
///
/// # 用法
///
/// ```ignore
/// use garrison::stp::LoginParams;
///
/// // 默认参数（所有字段为 None/false）
/// let token = logic.login("user-1", &LoginParams::default()).await?;
///
/// // 带设备信息
/// let params = LoginParams {
/// device: Some("ios".to_string()),
/// ip: Some("192.168.1.1".to_string()),
/// user_agent: Some("Mozilla/5.0".to_string()),
/// remember_me: false,
/// require_mfa: false,
/// };
/// let token = logic.login("user-1", &params).await?;
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoginParams {
    /// 设备标识（如 "web"/"ios"/"android"）。
    pub device: Option<String>,
    /// 客户端 IP 地址。
    pub ip: Option<String>,
    /// 客户端 User-Agent。
    pub user_agent: Option<String>,
    /// 是否启用记住我（延长 Token 有效期）。
    pub remember_me: bool,
    /// 是否要求二级认证：`DeviceBindingPolicy` 在 strict 模式新设备登录时置 `true`，业务方可据此触发 MFA。
    pub require_mfa: bool,
}

// Manager / Strategy / Factory 等持有方改为具体类型 `Arc<GarrisonLogicDefault>`，
// 方法调用通过子 trait（SessionLogic/PermissionLogic/TokenLogic/MfaLogic/PasswordLogic）解析。

// task_local：存储当前请求的 token

tokio::task_local! {
    /// 当前请求的 token，由 axum middleware 通过 `with_current_token` 设置。
    static CURRENT_TOKEN: String;
}

// 实现在 context.rs，re-export 保持 `crate::stp::with_current_token` 路径不变。

// GarrisonContext：task_local 上下文传播工具（跨 spawn 传播 CURRENT_TOKEN）

/// task_local 上下文快照，用于跨 `tokio::spawn` 传播 `CURRENT_TOKEN`（task_local 不自动传播，子任务内 `current_token()` 会失败）。
/// tokio `scope` 需持有 Future 所有权且无 RAII guard，故用 `within()` scope-based 方案而非 `restore()`（task_local API 固有限制）。
///
/// # 示例
///
/// ```ignore
/// use garrison::stp::{GarrisonContext, current_token, with_current_token};
///
/// // 在当前 task 设置 token 并捕获上下文
/// let ctx = with_current_token("my-token".to_string(), async {
/// GarrisonContext::capture()
/// }).await;
///
/// // spawn 子任务，在子任务内恢复上下文
/// let handle = tokio::spawn(async move {
/// ctx.within(async {
/// // 此处 current_token() 可正常读取
/// assert!(current_token().is_ok());
/// }).await
/// });
/// handle.await.unwrap();
/// ```
pub struct GarrisonContext {
    token: Option<String>,
}

// Clock trait：可注入时钟抽象

/// 时钟抽象 trait，统一时间源：生产用 [`SystemClock`]，测试用 [`MockClock`] 消除 flaky 测试。
pub trait Clock: Send + Sync {
    /// 返回当前 UTC 时间。
    fn now(&self) -> DateTime<Utc>;
}

/// 系统时钟实现，委托 `chrono::Utc::now()`。
pub struct SystemClock;

/// Mock 时钟：`Arc<RwLock>` 共享可变时间，供测试 `advance` / `set_time`，消除 flaky 测试。
#[derive(Clone)]
pub struct MockClock {
    time: Arc<RwLock<DateTime<Utc>>>,
}

// GarrisonLogicDefault：默认实现

/// 默认实现：组合 `GarrisonSession` + `GarrisonConfig`，实现全部 5 个子 trait。
pub struct GarrisonLogicDefault {
    /// 会话管理器（pub(crate) 供测试验证）。
    pub(crate) session: Arc<GarrisonSession>,
    config: Arc<GarrisonConfig>,
    /// 权限策略（pub(crate) 供测试验证）。
    pub(crate) firewall: Arc<dyn GarrisonPermissionStrategy>,
    /// 插件管理器（可选，注入后 login/logout 触发插件钩子）。
    pub(crate) plugin_manager: Option<Arc<GarrisonPluginManager>>,
    /// 监听器管理器（可选，注入后 login/logout/kickout 广播事件）。
    #[cfg(feature = "listener")]
    pub(crate) listener_manager: Option<Arc<GarrisonListenerManager>>,
    /// 认证逻辑（可选，注入后 login_by_token 优先委托此实现）。
    pub(crate) auth_logic: Option<Arc<dyn AuthLogic>>,
    /// 权限校验器（可选，注入后 check_permission/check_role 可委托此实现）。
    pub(crate) permission_checker: Option<Arc<dyn PermissionChecker>>,
    /// Prometheus 指标采集器（可选，注入后 login/check_login/check_permission/check_role emit 指标）。
    #[cfg(feature = "metrics-prometheus")]
    metrics: Option<Arc<crate::observability::GarrisonMetrics>>,
    /// 密码哈希器（可选，注入后 login_with_password 委托此实现校验密码）。
    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    password_hasher: Option<Arc<dyn crate::account::credential::password::PasswordHasher>>,
    /// 用户 Repository（可选，注入后 login_with_password 委托此实现查询用户）。
    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    user_repository: Option<Arc<dyn crate::dao::repository::UserRepository>>,
    /// 默认 login_type：未设置时为 "default"，经 `with_login_type` builder 设置。
    pub(crate) login_type: String,
    /// JWT 校验模式（默认 `JwtMode::Mixin`，`with_jwt_mode` 设置）；字段不 feature gate，verify 调用在 `check_login` 中按 protocol-jwt 门控。
    pub(crate) jwt_mode: JwtMode,
    /// Refresh Token 轮换器（可选，注入后 refresh_access_token 委托此实现）。
    #[cfg(all(feature = "protocol-jwt", feature = "db-sqlite"))]
    refresh_token_rotation: Option<crate::protocol::jwt::refresh::RefreshTokenRotation>,
    /// per-login_id 续签锁：仅序列化并发 `check_and_renew`，独立于 `GarrisonSession::login_locks`（避免 renew→logout 嵌套取锁死锁）。
    /// 用后 `remove_if(strong_count == 1)` 清理无等待者条目，防止随唯一 login_id 数量无界增长（CWE-770）。
    renewal_locks: DashMap<String, Arc<TokioMutex<()>>>,
    /// 可注入时钟（默认 SystemClock，测试可替换为 MockClock）：用于 hover_timeout 检查，消除 flaky 测试。
    clock: Arc<dyn Clock>,
    /// 异常检测器列表（`security-extra` feature）；未注入 no-op，检测失败仅 `tracing::warn!` 不中断主流程。
    #[cfg(feature = "security-extra")]
    pub(crate) anomaly_detectors: Option<Vec<Arc<dyn crate::strategy::alert::AnomalyDetector>>>,
    /// 告警监听器管理器（可选，`security-extra` feature，注入后广播异常检测事件；未注入时不广播）。
    #[cfg(feature = "security-extra")]
    pub(crate) alert_listener_manager: Option<Arc<crate::strategy::alert::AlertListenerManager>>,
    /// 设备绑定策略（可选，`device-binding` feature，注入后 login 检测新设备并置 `require_mfa`；未注入跳过，检测失败仅 warn 不中断 login）。
    #[cfg(feature = "device-binding")]
    pub(crate) device_binding_policy:
        Option<Arc<dyn crate::strategy::device_binding::DeviceBindingPolicy>>,
    /// 封禁库（构造时必需注入）：`check_disable` 委托其查询 login_id 封禁状态；通用传 `DefaultDisableRepository`，也可自定义实现接入其他数据源。
    pub(crate) disable_repository: Arc<dyn crate::account::disable::DisableRepository>,
    /// 用户缓存服务（可选，`three-tier-cache` feature，注入后 logout 失效用户三层缓存；未注入则跳过，失效失败仅 warn 不中断 logout）。
    #[cfg(feature = "three-tier-cache")]
    pub(crate) user_cache_service: Option<Arc<crate::cache::UserCacheService>>,
    /// 标记字段（可选，`with_marker` 注入）：标记 logic 来源，默认 `None`，不影响运行时行为。
    pub(crate) marker: Option<&'static str>,
    /// IP 级暴力破解防护策略（`check_api_key` 专用）：`OnceLock` 惰性初始化一次、全实例复用。
    #[cfg(all(feature = "protocol-apikey", feature = "firewall-bruteforce"))]
    brute_force_strategy:
        std::sync::OnceLock<Arc<crate::strategy::firewall::brute_force::BruteForceStrategy>>,
}

mod default_impl;

#[cfg(test)]
pub(crate) mod mock;

#[cfg(test)]
mod tests;

// security-extra（safe-auth）关闭时 MfaLogic trait default 行为验证

// 测试必须放在非门控 mod.rs，security-extra 关闭的构建才会真正编译运行（放入 safe.rs 会条件矛盾）。
#[cfg(test)]
#[cfg(not(feature = "security-extra"))]
mod safe_feature_gate_tests {
    use super::*;
    use crate::dao::GarrisonDao;
    use crate::stp::mock::{MockDao, MockFirewall};
    use crate::strategy::GarrisonPermissionStrategy;
    use std::sync::Arc;

    /// security-extra 禁用时无 open_safe inherent method，调用解析到 MfaLogic trait default（Ok(())/Ok(true)/Ok(())）。
    #[tokio::test]
    async fn t026_safe_auth_not_in_scope_when_disabled() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
        let mut config = GarrisonConfig::default_config();
        config.throw_on_not_login = false;
        config.token_style = "uuid".to_string();
        let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
            has_permission: true,
            has_role: true,
        });
        let logic = GarrisonLogicDefault::new(
            session,
            Arc::new(config),
            firewall,
            Arc::new(crate::account::disable::DefaultDisableRepository::new(
                dao.clone(),
            )),
        );

        let token = logic
            .login("user-t026-002", &LoginParams::default())
            .await
            .unwrap();

        with_current_token(token, async {
            assert!(
                logic.open_safe("default", 3600).await.is_ok(),
                "security-extra 禁用时 open_safe 应走 trait default 返回 Ok(())"
            );
            assert!(
                logic.is_safe("default").await.unwrap_or(false),
                "security-extra 禁用时 is_safe 应走 trait default 返回 Ok(true)"
            );
            assert!(
                logic.close_safe("default").await.is_ok(),
                "security-extra 禁用时 close_safe 应走 trait default 返回 Ok(())"
            );
        })
        .await;
    }
}
