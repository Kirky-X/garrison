//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Stp 模块，提供核心认证逻辑与工具入口。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `StpLogic` / `StpInterface` / `StpUtil` 三件套，
//! Bulwark 中统一使用 `Bulwark*` 前缀。
//!
//! ## 核心设计
//!
//! - 5 个子 trait（`SessionLogic`/`PermissionLogic`/`TokenLogic`/`MfaLogic`/`PasswordLogic`）：
//!   v0.5.2 拆分原 `BulwarkLogic` 上帝 trait，按职责域分离，super-trait 为 `BulwarkCore`
//! - `BulwarkLogicDefault`：默认实现，组合 `BulwarkSession` + `BulwarkConfig`，实现全部 5 个子 trait
//! - `tokio::task_local`：存储当前请求的 token（类似 Sa-Token 的 `SaHolder`，但适配 async）
//!
//! ## task_local 上下文
//!
//! 在 axum middleware 中调用 `with_current_token(token, async { handler }).await` 设置作用域，
//! stp 核心 API（logout/check_login/get_login_id）从 `current_token()` 读取。

use crate::config::BulwarkConfig;
use crate::core::auth::AuthLogic;
use crate::core::permission::PermissionChecker;
use crate::error::{BulwarkError, BulwarkResult};
#[cfg(feature = "listener")]
use crate::listener::BulwarkListenerManager;
use crate::plugin::BulwarkPluginManager;
use crate::session::BulwarkSession;
use crate::strategy::BulwarkPermissionStrategy;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

// ParameterQuery 参数化查询模块（feature-gated）
#[cfg(feature = "parameter-query")]
pub mod parameter;

// 原 BulwarkLogic 上帝 trait 拆分为 6 个细粒度子 trait
// （BulwarkCore 基座 + 5 个职责域 trait），按职责域分离。
pub mod context;
pub mod core;
pub mod interface;
pub mod mfa;
pub mod password;
pub mod permission;
// safe-auth feature-gated
#[cfg(feature = "safe-auth")]
pub mod safe;
pub mod session;
pub mod token;
pub mod util;

// 子 trait re-exports（供 crate::stp::SessionLogic 等路径访问）
pub use self::core::BulwarkCore;
pub use self::interface::BulwarkInterface;
pub use self::mfa::MfaLogic;
pub use self::password::PasswordLogic;
pub use self::permission::PermissionLogic;
pub use self::session::SessionLogic;
pub use self::token::TokenLogic;
#[cfg(any(feature = "backend-embedded", feature = "backend-remote"))]
pub use self::util::init_backend;
pub use self::util::{BulwarkUtil, JwtMode};

/// 登录参数（v0.6.3 新增）。
///
/// 封装登录时的可选元数据，传递给 `SessionLogic::login`。
/// [借鉴 Sa-Token] 对应 Sa-Token 的 `SaLoginParameter`，但简化为 5 个字段。
///
/// # 字段
///
/// - `device`: 设备标识（如 "web"/"ios"/"android"），写入 `TokenSession.device`
/// - `ip`: 客户端 IP 地址，写入 `TokenSession.ip`
/// - `user_agent`: 客户端 User-Agent，写入 `TokenSession.user_agent`
/// - `remember_me`: 是否启用记住我（延长 Token 有效期至 `remember_me_timeout`）
/// - `require_mfa`: 是否要求二级认证（由 `DeviceBindingPolicy` 在 login 流程中设置，v0.6.5 新增）
///
/// # 用法
///
/// ```ignore
/// use bulwark::stp::LoginParams;
///
/// // 默认参数（所有字段为 None/false）
/// let token = logic.login("user-1", &LoginParams::default()).await?;
///
/// // 带设备信息
/// let params = LoginParams {
///     device: Some("ios".to_string()),
///     ip: Some("192.168.1.1".to_string()),
///     user_agent: Some("Mozilla/5.0".to_string()),
///     remember_me: false,
///     require_mfa: false,
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
    /// 是否要求二级认证（v0.6.5 新增）。
    ///
    /// 由 `DeviceBindingPolicy` 在 login 流程中设置：strict 模式下新设备登录时置为 `true`，
    /// 业务方可在登录后检查此标记触发 MFA 流程。默认 `false`（向后兼容）。
    pub require_mfa: bool,
}

// 原 `BulwarkLogic` 上帝 trait（21 个方法）已彻底删除。
// Manager / Strategy / Factory 等持有方改为具体类型 `Arc<BulwarkLogicDefault>`，
// 方法调用通过子 trait（SessionLogic/PermissionLogic/TokenLogic/MfaLogic/PasswordLogic）解析。

// ============================================================================
// task_local：存储当前请求的 token（类似 Sa-Token 的 SaHolder）
// ============================================================================

tokio::task_local! {
    /// 当前请求的 token，由 axum middleware 通过 `with_current_token` 设置。
    static CURRENT_TOKEN: String;
}

/// 设置当前请求的 token 作用域。
///
/// 在 axum middleware 中调用：
/// ```ignore
/// bulwark::stp::with_current_token(token, async { handler(req).await }).await
/// ```
pub async fn with_current_token<R>(token: String, f: impl Future<Output = R>) -> R {
    CURRENT_TOKEN.scope(token, f).await
}

/// 获取当前请求的 token（从 task_local 读取）。
///
/// # 错误
/// - 若未在 `with_current_token` 作用域内调用，返回 `BulwarkError::Session`。
#[allow(clippy::map_clone)]
pub fn current_token() -> BulwarkResult<String> {
    CURRENT_TOKEN.try_get().map(|t| t.clone()).map_err(|_| {
        BulwarkError::Session("未设置当前请求上下文（未调用 with_current_token）".to_string())
    })
}

// ============================================================================
// BulwarkContext：task_local 上下文传播工具（跨 spawn 传播 CURRENT_TOKEN）
// ============================================================================

/// task_local 上下文快照，用于跨 `tokio::spawn` 传播 `CURRENT_TOKEN`。
///
/// tokio `task_local!` 不会自动传播到 `tokio::spawn` 子任务中，
/// 导致子任务内 `current_token()` / `check_login()` 失败。
/// `BulwarkContext` 通过 capture/within 模式手动传播上下文。
///
/// # 设计说明（RAII vs scope-based）
///
/// tokio `task_local!` 的 `scope(value, future)` 是设置值的唯一方式，
/// 它接受一个 Future 并在 Future 执行期间设置值，Future 结束后自动清除。
/// 不支持 RAII guard 模式（无法"临时设置再恢复"，因为 `scope` 需要
/// 持有 Future 的所有权）。因此采用 `within()` scope-based 方案而非
/// `restore()` RAII guard——这是 tokio task_local API 的固有限制。
///
/// # 示例
///
/// ```ignore
/// use bulwark::stp::{BulwarkContext, current_token, with_current_token};
///
/// // 在当前 task 设置 token 并捕获上下文
/// let ctx = with_current_token("my-token".to_string(), async {
///     BulwarkContext::capture()
/// }).await;
///
/// // spawn 子任务，在子任务内恢复上下文
/// let handle = tokio::spawn(async move {
///     ctx.within(async {
///         // 此处 current_token() 可正常读取
///         assert!(current_token().is_ok());
///     }).await
/// });
/// handle.await.unwrap();
/// ```
pub struct BulwarkContext {
    token: Option<String>,
}

impl BulwarkContext {
    /// 捕获当前 task_local 上下文（`CURRENT_TOKEN`）。
    ///
    /// 在父任务中调用，返回的 `BulwarkContext` 可移动到子任务中。
    /// 未设置 `CURRENT_TOKEN` 时返回 `token: None` 的上下文。
    pub fn capture() -> Self {
        Self {
            token: current_token().ok(),
        }
    }

    /// 在当前 task 恢复上下文，执行 `f` 期间设置 `CURRENT_TOKEN`。
    ///
    /// 使用 tokio `task_local::scope` 设置值，`f` 结束后自动清除。
    /// 若 `capture()` 时未设置 token，直接执行 `f`（不设置 task_local）。
    pub async fn within<F, R>(self, f: F) -> R
    where
        F: Future<Output = R>,
    {
        match self.token {
            Some(token) => CURRENT_TOKEN.scope(token, f).await,
            None => f.await,
        }
    }
}

// ============================================================================
// Clock trait：可注入时钟抽象
// ============================================================================

/// 时钟抽象 trait，统一时间源，支持测试注入 MockClock 消除 flaky 测试。
///
/// 生产环境使用 [`SystemClock`]（委托 `chrono::Utc::now()`），
/// 测试环境使用 [`MockClock`] 手动控制时间推进。
pub trait Clock: Send + Sync {
    /// 返回当前 UTC 时间。
    fn now(&self) -> DateTime<Utc>;
}

/// 系统时钟实现，委托 `chrono::Utc::now()`。
pub struct SystemClock;

impl SystemClock {
    /// 创建系统时钟实例。
    pub fn new() -> Self {
        Self
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        chrono::Utc::now()
    }
}

/// Mock 时钟，持有可设置的固定时间，用于测试。
///
/// 通过 `Arc<RwLock<DateTime<Utc>>>` 共享时间状态，
/// 测试中可 `advance` 推进时间或 `set_time` 设置固定时间，
/// 消除依赖 `tokio::time::sleep` 的 flaky 测试。
#[derive(Clone)]
pub struct MockClock {
    time: Arc<RwLock<DateTime<Utc>>>,
}

impl MockClock {
    /// 创建 MockClock，初始时间为 `time`。
    pub fn new(time: DateTime<Utc>) -> Self {
        Self {
            time: Arc::new(RwLock::new(time)),
        }
    }

    /// 设置当前时间。
    pub fn set_time(&self, time: DateTime<Utc>) {
        *self.time.write() = time;
    }

    /// 推进时间（正数向前，负数向后）。
    pub fn advance(&self, duration: chrono::Duration) {
        let mut w = self.time.write();
        *w += duration;
    }
}

impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        *self.time.read()
    }
}

// ============================================================================
// BulwarkLogicDefault：默认实现
// ============================================================================

/// 默认实现，实现全部 5 个子 trait（SessionLogic/PermissionLogic/TokenLogic/MfaLogic/PasswordLogic）。
///
/// [借鉴 Sa-Token] 对应 `StpLogic` 默认实现（design.md Decision 8）。
pub struct BulwarkLogicDefault {
    /// 会话管理器（pub(crate) 供测试验证）。
    pub(crate) session: Arc<BulwarkSession>,
    config: Arc<BulwarkConfig>,
    /// 权限策略（pub(crate) 供测试验证）。
    pub(crate) firewall: Arc<dyn BulwarkPermissionStrategy>,
    /// 插件管理器（可选，注入后 login/logout 触发插件钩子）。
    plugin_manager: Option<Arc<BulwarkPluginManager>>,
    /// 监听器管理器（可选，注入后 login/logout/kickout 广播事件）。
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<BulwarkListenerManager>>,
    /// 认证逻辑（可选，注入后 login_by_token 优先委托此实现）。
    pub(crate) auth_logic: Option<Arc<dyn AuthLogic>>,
    /// 权限校验器（可选，注入后 check_permission/check_role 可委托此实现）。
    permission_checker: Option<Arc<dyn PermissionChecker>>,
    /// Prometheus 指标采集器（可选，注入后 login/check_login/check_permission/check_role emit 指标）。
    #[cfg(feature = "metrics-prometheus")]
    metrics: Option<Arc<crate::observability::BulwarkMetrics>>,
    /// 密码哈希器（可选，注入后 login_with_password 委托此实现校验密码）。
    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    password_hasher: Option<Arc<dyn crate::account::credential::password::PasswordHasher>>,
    /// 用户 Repository（可选，注入后 login_with_password 委托此实现查询用户）。
    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    user_repository: Option<Arc<dyn crate::dao::repository::UserRepository>>,
    /// 默认 login_type。
    ///
    /// 未设置时默认 "default"，通过 `with_login_type` builder 设置。
    /// `pub(crate)` 供测试验证字段值。
    pub(crate) login_type: String,
    /// JWT 校验模式。
    ///
    /// 默认 `JwtMode::Mixin`，通过 `with_jwt_mode` builder 设置。
    /// 字段不 feature gate（JwtMode 是配置 enum，无外部依赖）；
    /// 实际 JWT verify 调用在 `check_login` 中由 `#[cfg(feature = "protocol-jwt")]` 门控。
    /// `pub(crate)` 供测试验证字段值。
    pub(crate) jwt_mode: JwtMode,
    /// Refresh Token 轮换器（可选，注入后 refresh_access_token 委托此实现）。
    #[cfg(all(feature = "protocol-jwt", feature = "db-sqlite"))]
    refresh_token_rotation: Option<crate::protocol::jwt::refresh::RefreshTokenRotation>,
    /// per-login_id 续签锁（HIGH-001 修复）。
    ///
    /// 独立于 `BulwarkSession::login_locks`，避免 `check_and_renew` 持有
    /// `login_locks` 后调用 `renew_to_equivalent`（内部 `logout` 再次获取
    /// `login_locks`）导致死锁。续签锁仅序列化并发 `check_and_renew` 调用。
    renewal_locks: DashMap<String, Arc<TokioMutex<()>>>,
    /// 可注入时钟（默认 SystemClock，测试可替换为 MockClock）。
    ///
    /// 用于 hover_timeout 检查的时间读取，消除依赖 `tokio::time::sleep` 的 flaky 测试。
    clock: Arc<dyn Clock>,
    /// 异常检测器列表（可选，注入后 login/check_login 触发异常检测）。
    ///
    /// 需启用 `security-alert` feature。未注入时为 no-op（向后兼容）。
    /// 检测失败只 `tracing::warn!` 不中断主流程。
    #[cfg(feature = "security-alert")]
    pub(crate) anomaly_detectors: Option<Vec<Arc<dyn crate::strategy::alert::AnomalyDetector>>>,
    /// 告警监听器管理器（可选，注入后广播异常检测产生的事件）。
    ///
    /// 需启用 `security-alert` feature。未注入时异常事件不广播（向后兼容）。
    #[cfg(feature = "security-alert")]
    pub(crate) alert_listener_manager: Option<Arc<crate::strategy::alert::AlertListenerManager>>,
    /// 设备绑定策略（可选，注入后 login 流程检测新设备并设置 `require_mfa` 标记）。
    ///
    /// 需启用 `device-binding` feature。未注入时跳过检测（向后兼容）。
    /// 检测失败只 `tracing::warn!` 不中断 login。
    #[cfg(feature = "device-binding")]
    pub(crate) device_binding_policy:
        Option<Arc<dyn crate::strategy::device_binding::DeviceBindingPolicy>>,
    /// 封禁库（可选，注入后 check_disable 查询当前 login_id 是否被封禁）。
    ///
    /// 非 feature-gated（核心能力）。未注入时 check_disable 返回 `Ok(())`（向后兼容）。
    pub(crate) disable_repository: Option<Arc<dyn crate::account::disable::DisableRepository>>,
    /// 用户缓存服务（可选，注入后 logout/logout_by_login_id 失效用户三层缓存）。
    ///
    /// 需启用 `three-tier-cache` feature。未注入时 logout 不失效缓存（向后兼容）。
    /// 缓存失效失败只 `tracing::warn!` 不中断 logout 主流程。
    #[cfg(feature = "three-tier-cache")]
    pub(crate) user_cache_service: Option<Arc<crate::cache::UserCacheService>>,
}

mod default_impl;

#[cfg(test)]
pub(crate) mod mock;

#[cfg(test)]
mod tests;
