//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
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
use dashmap::DashMap;
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
#[derive(Debug, Clone, Default)]
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
    auth_logic: Option<Arc<dyn AuthLogic>>,
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
}

impl BulwarkLogicDefault {
    /// 创建默认实现实例。
    ///
    /// # 参数
    /// - `session`: 会话管理器。
    /// - `config`: 全局配置。
    /// - `firewall`: 权限策略（默认 `BulwarkPermissionStrategyDefault`，持有 `BulwarkInterface` 回调）。
    ///
    /// # 返回
    /// 新建的 `BulwarkLogicDefault` 实例。
    pub fn new(
        session: Arc<BulwarkSession>,
        config: Arc<BulwarkConfig>,
        firewall: Arc<dyn BulwarkPermissionStrategy>,
    ) -> Self {
        Self {
            session,
            config,
            firewall,
            plugin_manager: None,
            #[cfg(feature = "listener")]
            listener_manager: None,
            auth_logic: None,
            permission_checker: None,
            #[cfg(feature = "metrics-prometheus")]
            metrics: None,
            #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
            password_hasher: None,
            #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
            user_repository: None,
            login_type: "default".to_string(),
            jwt_mode: JwtMode::default(),
            #[cfg(all(feature = "protocol-jwt", feature = "db-sqlite"))]
            refresh_token_rotation: None,
            renewal_locks: DashMap::new(),
            #[cfg(feature = "security-alert")]
            anomaly_detectors: None,
            #[cfg(feature = "security-alert")]
            alert_listener_manager: None,
            #[cfg(feature = "device-binding")]
            device_binding_policy: None,
        }
    }

    /// 注入插件管理器（builder 模式，返回 Self 便于链式调用）。
    ///
    /// 注入后 `login` / `logout` 将触发 `on_login` / `on_logout` 钩子。
    pub fn with_plugin_manager(mut self, pm: Arc<BulwarkPluginManager>) -> Self {
        self.plugin_manager = Some(pm);
        self
    }

    /// 注入监听器管理器（builder 模式，需启用 `listener` feature）。
    ///
    /// 注入后 `login` / `logout` / `kickout` 将广播 `BulwarkEvent` 事件。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<BulwarkListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 注入认证逻辑（builder 模式）。
    ///
    /// 注入后 `login_by_token` 优先委托 `auth_logic.verify_token` 校验 token。
    pub fn with_auth_logic(mut self, auth: Arc<dyn AuthLogic>) -> Self {
        self.auth_logic = Some(auth);
        self
    }

    /// 注入权限校验器（builder 模式）。
    ///
    /// 注入后 `check_permission` 优先委托 `PermissionChecker::authorize`（走 Decision 路径），
    /// 并广播 `PermissionCheck` 事件供 `AuditLogListener` 记录审计日志。
    /// 未注入时回退到 `firewall.check_permission`（0.4.2 行为）。
    pub fn with_permission_checker(mut self, pc: Arc<dyn PermissionChecker>) -> Self {
        self.permission_checker = Some(pc);
        self
    }

    /// 注入 Prometheus 指标采集器（builder 模式，需启用 `metrics-prometheus` feature）。
    ///
    /// 注入后 `login` / `check_login` / `check_permission` / `check_role` 将自动 emit
    /// Prometheus 指标。未注入时所有指标调用为 no-op。
    #[cfg(feature = "metrics-prometheus")]
    pub fn with_metrics(mut self, metrics: Arc<crate::observability::BulwarkMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// 注入密码哈希器（builder 模式，需启用 `account-credential` + `db-sqlite` feature）。
    ///
    /// 注入后 `login_with_password` 委托此 `PasswordHasher::verify` 校验密码哈希。
    /// 未注入时 `login_with_password` 返回 `BulwarkError::Config("password hasher not configured")`。
    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    pub fn with_password_hasher(
        mut self,
        hasher: Arc<dyn crate::account::credential::password::PasswordHasher>,
    ) -> Self {
        self.password_hasher = Some(hasher);
        self
    }

    /// 注入用户 Repository（builder 模式，需启用 `account-credential` + `db-sqlite` feature）。
    ///
    /// 注入后 `login_with_password` 委托此 `UserRepository::find_by_username` 查询用户。
    /// 未注入时 `login_with_password` 返回 `BulwarkError::Config("user repository not configured")`。
    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    pub fn with_user_repository(
        mut self,
        repo: Arc<dyn crate::dao::repository::UserRepository>,
    ) -> Self {
        self.user_repository = Some(repo);
        self
    }

    /// 设置默认 login_type（builder 模式）。
    ///
    /// 注入后作为权限/角色查询的默认 `login_type` 上下文。未设置时默认 "default"。
    ///
    /// # 参数
    /// - `login_type`: 登录类型字符串（业务方自定义，如 "admin"/"user"/"merchant"）。
    ///
    /// # 示例
    /// ```ignore
    /// let logic = BulwarkLogicDefault::new(session, config, firewall)
    ///     .with_login_type("admin");
    /// ```
    pub fn with_login_type(mut self, login_type: &str) -> Self {
        self.login_type = login_type.to_string();
        self
    }

    /// 设置 JWT 校验模式（builder 模式）。
    ///
    /// 控制 `check_login` 在 JWT verify 与 session 查询之间的组合策略：
    ///
    /// - `JwtMode::Stateless`：仅 JWT verify，不查询 oxcache session（高可用场景）
    /// - `JwtMode::Mixin`（默认）：JWT verify + session 二级校验（推荐）
    /// - `JwtMode::Simple`：仅 session，JWT 仅作为 token 字符串载体
    ///
    /// 未设置时默认 `JwtMode::Mixin`。运行时不可切换（编译期配置）。
    /// `JwtMode` 字段不依赖 `protocol-jwt` feature，但 `Stateless`/`Mixin` 中的
    /// JWT verify 调用需启用 `protocol-jwt` feature，否则 `Stateless` 返回 `Config` 错误。
    ///
    /// # 参数
    /// - `mode`: JWT 校验模式。
    ///
    /// # 示例
    /// ```ignore
    /// let logic = BulwarkLogicDefault::new(session, config, firewall)
    ///     .with_jwt_mode(JwtMode::Stateless);
    /// ```
    pub fn with_jwt_mode(mut self, mode: JwtMode) -> Self {
        self.jwt_mode = mode;
        self
    }

    /// 注入 Refresh Token 轮换器（builder 模式，需启用 `protocol-jwt` + `db-sqlite` feature）。
    ///
    /// 注入后 `refresh_access_token` 委托 `RefreshTokenRotation::rotate` 实现轮换。
    /// 未注入时 `refresh_access_token` 返回 `BulwarkError::NotImplemented`。
    #[cfg(all(feature = "protocol-jwt", feature = "db-sqlite"))]
    pub fn with_refresh_token_rotation(
        mut self,
        rtr: crate::protocol::jwt::refresh::RefreshTokenRotation,
    ) -> Self {
        self.refresh_token_rotation = Some(rtr);
        self
    }

    /// 注入异常检测器（builder 模式，需启用 `security-alert` feature）。
    ///
    /// 可链式调用注入多个检测器，`login` / `check_login` 时按注入顺序依次调用。
    /// 未注入时跳过异常检测（向后兼容）。检测失败只 `tracing::warn!` 不中断主流程。
    #[cfg(feature = "security-alert")]
    pub fn with_anomaly_detector(
        mut self,
        detector: Arc<dyn crate::strategy::alert::AnomalyDetector>,
    ) -> Self {
        self.anomaly_detectors
            .get_or_insert_with(Vec::new)
            .push(detector);
        self
    }

    /// 注入告警监听器管理器（builder 模式，需启用 `security-alert` feature）。
    ///
    /// 注入后异常检测产生的事件通过 `AlertListenerManager::broadcast_alert` 广播。
    /// 未注入时异常事件不广播（向后兼容）。
    #[cfg(feature = "security-alert")]
    pub fn with_alert_listener_manager(
        mut self,
        manager: Arc<crate::strategy::alert::AlertListenerManager>,
    ) -> Self {
        self.alert_listener_manager = Some(manager);
        self
    }

    /// 注入设备绑定策略（builder 模式，需启用 `device-binding` feature）。
    ///
    /// 注入后 `login` 流程在创建 session 前调用 `DeviceBindingPolicy::is_new_device`
    /// + `require_secondary_auth`，新设备且要求二级认证时设置 `LoginParams.require_mfa = true`。
    ///
    /// 未注入时跳过检测（向后兼容）。检测失败只 `tracing::warn!` 不中断 login。
    #[cfg(feature = "device-binding")]
    pub fn with_device_binding_policy(
        mut self,
        policy: Arc<dyn crate::strategy::device_binding::DeviceBindingPolicy>,
    ) -> Self {
        self.device_binding_policy = Some(policy);
        self
    }

    /// 校验 API Key。
    ///
    /// 从当前请求上下文（task_local `CURRENT_TOKEN`）获取 API Key 字符串，
    /// 委托 `protocol::apikey::ApiKeyHandler::verify_with_namespace` 校验。
    ///
    /// # 参数
    /// - `namespace`: 命名空间标识，用于隔离不同业务的 API Key。
    ///
    /// # 返回
    /// - `Ok(())`: API Key 有效（存在、未吊销、未过期、namespace 匹配）。
    /// - `Err(BulwarkError::NotLogin)`: 未设置当前请求上下文（无 API Key 提供）。
    /// - `Err(BulwarkError::InvalidToken)`: API Key 不存在或已吊销。
    /// - `Err(BulwarkError::ExpiredToken)`: API Key 已过期。
    /// - `Err(BulwarkError::InvalidParam)`: namespace 非法。
    ///
    /// # 兼容性
    ///
    /// `protocol-apikey` feature 关闭时，本方法返回 `Ok(())`（兼容 0.6.0 未启用 API Key 场景）。
    #[cfg(feature = "protocol-apikey")]
    pub async fn check_api_key(&self, namespace: &str) -> BulwarkResult<()> {
        // 无 token 上下文 = 请求未携带 API Key，返回 NotLogin（映射 401）
        // 与 check_login 不同：check_api_key 返回 Result<()> 而非 Result<bool>，
        // 无法用 Ok(false) 表达"未通过"，必须返回错误。
        let key = match current_token() {
            Ok(t) => t,
            Err(_) => {
                return Err(BulwarkError::NotLogin("未提供 API Key".to_string()));
            },
        };
        let handler = crate::protocol::apikey::ApiKeyHandler::new(self.session.dao().clone());
        handler.verify_with_namespace(&key, namespace).await?;
        Ok(())
    }

    /// 校验 API Key（`protocol-apikey` feature 关闭时的兼容实现）。
    ///
    /// 返回 `Ok(())`（兼容 0.6.0 未启用 API Key 场景）。
    #[cfg(not(feature = "protocol-apikey"))]
    pub async fn check_api_key(&self, _namespace: &str) -> BulwarkResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
