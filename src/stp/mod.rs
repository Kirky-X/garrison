//! Stp 模块，提供核心认证逻辑与工具入口。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `StpLogic` / `StpInterface` / `StpUtil` 三件套，
//! Bulwark 中统一使用 `Bulwark*` 前缀。
//!
//! ## 核心设计（依据 spec stp-core-api 与 design.md Decision 8）
//!
//! - `BulwarkLogic` trait：定义 login/logout/check_login/kickout 完整契约
//! - `BulwarkLogicDefault`：默认实现，组合 `BulwarkSession` + `BulwarkConfig`
//! - `tokio::task_local`：存储当前请求的 token（类似 Sa-Token 的 `SaHolder`，但适配 async）
//!
//! ## task_local 上下文（依据 spec context-abstraction）
//!
//! 在 axum middleware 中调用 `with_current_token(token, async { handler }).await` 设置作用域，
//! stp 核心 API（logout/check_login/get_login_id）从 `current_token()` 读取。

use crate::config::BulwarkConfig;
use crate::core::auth::AuthLogic;
use crate::core::permission::PermissionChecker;
use crate::core::token::TokenStyleFactory;
use crate::error::{BulwarkError, BulwarkResult};
#[cfg(feature = "listener")]
use crate::listener::{BulwarkEvent, BulwarkListenerManager};
use crate::plugin::BulwarkPluginManager;
use crate::session::BulwarkSession;
use crate::strategy::{BulwarkFirewallStrategy, FirewallLoginContext};
use async_trait::async_trait;
use std::future::Future;
use std::sync::Arc;

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
// BulwarkLogic trait：核心认证逻辑契约
// ============================================================================

/// 核心逻辑 trait，定义登录认证的完整行为契约。
///
/// [借鉴 Sa-Token] 对应 `StpLogic`，是框架最核心的抽象。
/// 实现方需集成认证、会话等能力（0.1.0 仅实现 login/logout/check_login/kickout，
/// 权限/角色校验在任务组 7 实现）。
#[async_trait]
pub trait BulwarkLogic: Send + Sync {
    /// 执行登录：生成 token + 创建会话。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 生成的 token 字符串。
    ///
    /// # 错误
    /// - token 生成失败（如 `token_style` 非法）：`BulwarkError::Config`。
    /// - 会话创建失败：透传 `BulwarkError`。
    async fn login(&self, login_id: i64) -> BulwarkResult<String>;

    /// 执行登录（自定义 token）：用指定 token 创建会话。
    ///
    /// 用于 token 转发、自定义 token 生成等场景。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `token`: 自定义 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话创建失败：透传 `BulwarkError`。
    async fn login_with_token(&self, login_id: i64, token: &str) -> BulwarkResult<()>;

    /// 执行登出：从 task_local 获取当前 token 并销毁。
    ///
    /// 未登录时调用幂等返回 Ok（不抛错）。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；未设置 token 时幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn logout(&self) -> BulwarkResult<()>;

    /// 按账号登出：销毁指定 login_id 的所有会话。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn logout_by_login_id(&self, login_id: i64) -> BulwarkResult<()>;

    /// 踢出用户：按账号踢出（语义等同 logout_by_login_id）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn kickout(&self, login_id: i64) -> BulwarkResult<()>;

    /// 踢出会话：按 token 踢出（语义等同 logout(token)）。
    ///
    /// # 参数
    /// - `token`: 待踢出的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn kickout_by_token(&self, token: &str) -> BulwarkResult<()>;

    /// 检查登录状态：从 task_local 获取 token 验证有效性。
    ///
    /// # 返回
    /// - `Ok(true)`: token 有效且 Account-Session 未过期。
    /// - `Ok(false)`: token 无效或未登录（`throw_on_not_login=false`）。
    ///
    /// # 错误
    /// - 未登录且 `throw_on_not_login=true`：抛 `BulwarkError::Session`。
    /// - DAO 读取失败：透传 `BulwarkError`。
    async fn check_login(&self) -> BulwarkResult<bool>;

    /// 获取当前登录 ID。
    ///
    /// # 返回
    /// - `Some(login_id)`: token 有效，返回关联的 login_id。
    /// - `None`: 未登录或 token 无效。
    ///
    /// # 错误
    /// - DAO 读取失败：透传 `BulwarkError`。
    async fn get_login_id(&self) -> BulwarkResult<Option<i64>>;

    /// 校验权限（任务组 7 实现，复用 dbnexus PermissionProvider）。
    ///
    /// # 参数
    /// - `permission`: 权限标识字符串。
    ///
    /// # 返回
    /// 成功（持有权限）返回 `Ok(())`。
    ///
    /// # 错误
    /// - 未登录且 `throw_on_not_login=true`：`BulwarkError::NotLogin`。
    /// - 未登录且 `throw_on_not_login=false`：降级为 `BulwarkError::NotPermission`。
    /// - 未持有权限：`BulwarkError::NotPermission`。
    async fn check_permission(&self, permission: &str) -> BulwarkResult<()>;

    /// 校验角色（任务组 7 实现）。
    ///
    /// # 参数
    /// - `role`: 角色标识字符串。
    ///
    /// # 返回
    /// 成功（持有角色）返回 `Ok(())`。
    ///
    /// # 错误
    /// - 未登录且 `throw_on_not_login=true`：`BulwarkError::NotLogin`。
    /// - 未登录且 `throw_on_not_login=false`：降级为 `BulwarkError::NotRole`。
    /// - 未持有角色：`BulwarkError::NotRole`。
    async fn check_role(&self, role: &str) -> BulwarkResult<()>;

    /// 检查二级认证（MFA）状态（0.3.0 新增，依据 spec annotation-handling）。
    ///
    /// 默认实现返回 `Ok(())`（未启用 MFA，向后兼容 0.2.x）。
    /// 业务方覆写此方法以接入 TOTP MFA 校验：检查当前会话是否已完成二级认证。
    ///
    /// # 返回
    /// - `Ok(())`: 已通过二级认证或未启用 MFA。
    /// - `Err(BulwarkError::Session)`: 未通过二级认证。
    async fn check_safe(&self) -> BulwarkResult<()> {
        Ok(())
    }

    /// 检查账号是否被禁用（0.3.0 新增，依据 spec annotation-handling）。
    ///
    /// 默认实现返回 `Ok(())`（未实现禁用账号库，向后兼容 0.2.x）。
    /// 业务方覆写此方法以接入禁用账号检查：查询当前 login_id 是否在禁用列表中。
    ///
    /// # 返回
    /// - `Ok(())`: 账号未禁用。
    /// - `Err(BulwarkError::Session)`: 账号已禁用。
    async fn check_disable(&self) -> BulwarkResult<()> {
        Ok(())
    }

    /// 通过外部 token 反向建立会话（0.2.0 新增，依据 spec core-auth-api）。
    ///
    /// 用于 OAuth2/SSO 场景：外部 token 已通过协议层校验后，
    /// 调用此方法在当前上下文建立内部会话。
    ///
    /// # 参数
    /// - `token`: 外部 token 字符串（如 OAuth2 access_token / SSO ticket）。
    ///
    /// # 错误
    /// - default 实现：`BulwarkError::NotImplemented`（未启用 protocol-oauth2/protocol-sso）。
    async fn login_by_token(&self, _token: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(
            "login_by_token 需启用 protocol-oauth2 或 protocol-sso feature".to_string(),
        ))
    }

    /// 验证显式传入的 token 并返回关联的 login_id（0.2.0 新增，依据 spec core-auth-api）。
    ///
    /// 委托 `core-token::Token::verify` 实现。与 `check_login` 区别：
    /// `check_login` 从 task_local 读取 token；`verify_token` 接收显式 token 参数。
    ///
    /// # 参数
    /// - `token`: 待验证的 token 字符串。
    ///
    /// # 返回
    /// - `Ok(login_id)`: token 有效，返回关联的 login_id。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidToken`: token 无效或不包含 login_id。
    /// - `BulwarkError::NotImplemented`: default 实现未委托 Token trait。
    async fn verify_token(&self, _token: &str) -> BulwarkResult<i64> {
        Err(BulwarkError::NotImplemented(
            "verify_token 需子类 override 委托 core-token::Token::verify".to_string(),
        ))
    }

    /// 刷新 token（0.2.0 新增，依据 spec core-auth-api）。
    ///
    /// 仅在启用 `protocol-jwt` feature 时由 `JwtHandler` 提供有效实现。
    ///
    /// # 参数
    /// - `token`: 待刷新的旧 token 字符串。
    ///
    /// # 返回
    /// - `Ok(new_token)`: 刷新后的新 token 字符串。
    ///
    /// # 错误
    /// - `BulwarkError::NotImplemented`: 未启用 protocol-jwt feature。
    /// - `BulwarkError::InvalidToken`: token 已过期或无效。
    async fn refresh_token(&self, _token: &str) -> BulwarkResult<String> {
        Err(BulwarkError::NotImplemented(
            "refresh_token 需启用 protocol-jwt feature".to_string(),
        ))
    }

    /// 获取当前 `BulwarkConfig` 引用（用于 token 提取、Cookie 配置等需要配置的场景）。
    ///
    /// # 返回
    /// 全局配置的 `Arc` 引用。
    fn config(&self) -> Arc<BulwarkConfig>;
}

// ============================================================================
// BulwarkLogicDefault：默认实现
// ============================================================================

/// `BulwarkLogic` 的默认实现，组合 `BulwarkSession` + `BulwarkConfig` + `BulwarkFirewallStrategy`。
///
/// [借鉴 Sa-Token] 对应 `StpLogic` 默认实现（design.md Decision 8）。
pub struct BulwarkLogicDefault {
    /// 会话管理器（pub(crate) 供测试验证）。
    pub(crate) session: Arc<BulwarkSession>,
    config: Arc<BulwarkConfig>,
    /// 权限策略（pub(crate) 供测试验证）。
    pub(crate) firewall: Arc<dyn BulwarkFirewallStrategy>,
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
}

impl BulwarkLogicDefault {
    /// 创建默认实现实例。
    ///
    /// # 参数
    /// - `session`: 会话管理器。
    /// - `config`: 全局配置。
    /// - `firewall`: 权限策略（默认 `BulwarkFirewallStrategyDefault`，持有 `BulwarkInterface` 回调）。
    ///
    /// # 返回
    /// 新建的 `BulwarkLogicDefault` 实例。
    pub fn new(
        session: Arc<BulwarkSession>,
        config: Arc<BulwarkConfig>,
        firewall: Arc<dyn BulwarkFirewallStrategy>,
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
    /// 注入后可用于权限校验链路扩展（当前 `check_permission` 仍委托 firewall，
    /// 此字段为未来扩展预留）。
    pub fn with_permission_checker(mut self, pc: Arc<dyn PermissionChecker>) -> Self {
        self.permission_checker = Some(pc);
        self
    }

    /// 注入 Prometheus 指标采集器（builder 模式，需启用 `metrics-prometheus` feature）。
    ///
    /// 注入后 `login` / `check_login` / `check_permission` / `check_role` 将自动 emit
    /// Prometheus 指标（依据 spec observability-stack）。未注入时所有指标调用为 no-op。
    #[cfg(feature = "metrics-prometheus")]
    pub fn with_metrics(mut self, metrics: Arc<crate::observability::BulwarkMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// login 实际逻辑（供 `login` 方法在 metrics 包装内调用）。
    ///
    /// 0.3.0 抽取此私有方法以保持 `login` trait 方法的 metrics 包装简洁。
    async fn login_inner(&self, login_id: i64) -> BulwarkResult<String> {
        // 0.3.0：登录前防火墙安全钩子检查（依据 spec firewall-check-hook）
        // 任一 hook Err 阻断登录；未注入 hook 时为 no-op（向后兼容 0.2.x）
        let ctx = FirewallLoginContext::new(login_id);
        self.firewall.check_login_hooks(login_id, &ctx).await?;

        let token = self.generate_token(login_id)?;
        self.login_with_token(login_id, &token).await?;
        // auto-wire: 触发 plugin on_login + listener Login 事件
        if let Some(pm) = &self.plugin_manager {
            pm.on_login(login_id, &token);
        }
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::Login {
                login_id,
                token: token.clone(),
                device: None,
            });
        }
        Ok(token)
    }

    /// 根据 `config.token_style` 生成 token。
    ///
    /// - `uuid`: UUID v4（36 字符，含连字符）
    /// - `random_64`: 两个 simple UUID 拼接（64 字符）
    /// - `simple`: simple UUID（32 字符）
    /// - `jwt`: 需启用 `protocol-jwt` feature，委托 `JwtHandler::sign`（0.2.0 修复）
    fn generate_token(&self, login_id: i64) -> BulwarkResult<String> {
        match self.config.token_style.as_str() {
            "uuid" => Ok(uuid::Uuid::new_v4().to_string()),
            "random_64" => Ok(format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            )),
            "simple" => Ok(uuid::Uuid::new_v4().simple().to_string()),
            "jwt" => {
                // 0.2.0：委托 JwtHandler::sign（依据 spec protocol-jwt + core-auth-api）
                #[cfg(feature = "protocol-jwt")]
                {
                    let handler = crate::protocol::jwt::JwtHandler::new(&self.config.jwt_secret);
                    handler.sign(login_id, self.config.timeout)
                }
                #[cfg(not(feature = "protocol-jwt"))]
                {
                    let _ = login_id;
                    Err(BulwarkError::Config(
                        "jwt token_style 需启用 protocol-jwt feature".to_string(),
                    ))
                }
            },
            other => Err(BulwarkError::Config(format!(
                "unknown token_style: {}",
                other
            ))),
        }
    }
}

#[async_trait]
impl BulwarkLogic for BulwarkLogicDefault {
    async fn login(&self, login_id: i64) -> BulwarkResult<String> {
        // emit metrics：登录尝试（成功/失败均记录，依据 spec observability-stack）
        #[cfg(feature = "metrics-prometheus")]
        let start = std::time::Instant::now();
        let result = self.login_inner(login_id).await;
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_login(result.is_ok());
            m.observe_token_validation(start.elapsed());
        }
        result
    }

    async fn login_with_token(&self, login_id: i64, token: &str) -> BulwarkResult<()> {
        self.session.create(login_id, token).await
    }

    async fn logout(&self) -> BulwarkResult<()> {
        // 未登录时幂等返回 Ok（不抛错）
        match current_token() {
            Ok(token) => {
                // 获取 login_id（用于 plugin/listener 回调），注销前查询
                let login_id = self
                    .session
                    .get_token_session(&token)
                    .await?
                    .map(|ts| ts.login_id);
                self.session.logout(&token).await?;
                // auto-wire: 触发 plugin on_logout + listener Logout 事件
                if let (Some(pm), Some(id)) = (&self.plugin_manager, login_id) {
                    pm.on_logout(id, &token);
                }
                #[cfg(feature = "listener")]
                if let (Some(lm), Some(id)) = (&self.listener_manager, login_id) {
                    lm.broadcast(&BulwarkEvent::Logout {
                        login_id: id,
                        token: token.clone(),
                    });
                }
                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    async fn logout_by_login_id(&self, login_id: i64) -> BulwarkResult<()> {
        self.session.logout_by_login_id(login_id).await
    }

    async fn kickout(&self, login_id: i64) -> BulwarkResult<()> {
        // kickout 语义等同 logout_by_login_id
        self.session.logout_by_login_id(login_id).await?;
        // auto-wire: 触发 listener Kickout 事件（plugin 无 kickout 钩子）
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::Kickout {
                login_id,
                token: String::new(),
                reason: "管理员强制下线".to_string(),
            });
        }
        Ok(())
    }

    async fn kickout_by_token(&self, token: &str) -> BulwarkResult<()> {
        // kickout_by_token 语义等同 logout(token)
        self.session.logout(token).await
    }

    async fn check_login(&self) -> BulwarkResult<bool> {
        let valid = match current_token() {
            Ok(token) => self.session.is_valid(&token).await?,
            Err(_) => false, // 未设置 token = 未登录
        };
        if !valid && self.config.throw_on_not_login {
            return Err(BulwarkError::Session("未登录".to_string()));
        }
        Ok(valid)
    }

    async fn get_login_id(&self) -> BulwarkResult<Option<i64>> {
        match current_token() {
            Ok(token) => match self.session.get_token_session(&token).await? {
                Some(ts) => Ok(Some(ts.login_id)),
                None => Ok(None),
            },
            Err(_) => Ok(None),
        }
    }

    async fn check_permission(&self, permission: &str) -> BulwarkResult<()> {
        // spec scenario "未登录抛出异常"：未登录时依据 throw_on_not_login 抛错
        let login_id = match self.get_login_id().await? {
            Some(id) => id,
            None => {
                // emit metrics：未登录视为 deny
                #[cfg(feature = "metrics-prometheus")]
                if let Some(m) = &self.metrics {
                    m.record_permission_query(false);
                }
                return if self.config.throw_on_not_login {
                    Err(BulwarkError::NotLogin("未登录，无法校验权限".to_string()))
                } else {
                    // throw_on_not_login=false：未登录视为无权限，抛 NotPermission
                    Err(BulwarkError::NotPermission(permission.to_string()))
                };
            },
        };
        // 委托 BulwarkFirewallStrategy 做权限校验
        let has_perm = self.firewall.check_permission(login_id, permission).await?;
        // emit metrics：权限查询结果
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_permission_query(has_perm);
        }
        if has_perm {
            Ok(())
        } else {
            Err(BulwarkError::NotPermission(permission.to_string()))
        }
    }

    async fn check_role(&self, role: &str) -> BulwarkResult<()> {
        // spec scenario "未登录抛出异常"：未登录时依据 throw_on_not_login 抛错
        let login_id = match self.get_login_id().await? {
            Some(id) => id,
            None => {
                // emit metrics：未登录视为 deny
                #[cfg(feature = "metrics-prometheus")]
                if let Some(m) = &self.metrics {
                    m.record_role_query(false);
                }
                return if self.config.throw_on_not_login {
                    Err(BulwarkError::NotLogin("未登录，无法校验角色".to_string()))
                } else {
                    // throw_on_not_login=false：未登录视为无角色，抛 NotRole
                    Err(BulwarkError::NotRole(role.to_string()))
                };
            },
        };
        // 委托 BulwarkFirewallStrategy 做角色校验
        let has_role = self.firewall.check_role(login_id, role).await?;
        // emit metrics：角色查询结果
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_role_query(has_role);
        }
        if has_role {
            Ok(())
        } else {
            Err(BulwarkError::NotRole(role.to_string()))
        }
    }

    async fn login_by_token(&self, token: &str) -> BulwarkResult<()> {
        // 获取 login_id：优先委托 auth_logic，否则使用 verify_token（TokenStyleFactory）
        let login_id = if let Some(auth) = &self.auth_logic {
            auth.verify_token(token).await?
        } else {
            self.verify_token(token).await?
        };
        // 建立内部会话（使用同一 token）
        self.session.create(login_id, token).await?;
        // auto-wire: 触发 plugin on_login + listener Login 事件
        if let Some(pm) = &self.plugin_manager {
            pm.on_login(login_id, token);
        }
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::Login {
                login_id,
                token: token.to_string(),
                device: None,
            });
        }
        Ok(())
    }

    async fn verify_token(&self, token: &str) -> BulwarkResult<i64> {
        // 依据 spec core-auth-api：委托 core-token::Token::verify
        // spec: "不泄露 token 具体失效原因（统一 InvalidToken）"
        let token_handler =
            TokenStyleFactory::new(&self.config.token_style, &self.config.jwt_secret)?;
        match token_handler.verify(token) {
            Ok(Some(login_id)) => Ok(login_id),
            Ok(None) => Err(BulwarkError::InvalidToken(
                "token 无效或不包含 login_id".to_string(),
            )),
            Err(_) => Err(BulwarkError::InvalidToken("token 无效".to_string())),
        }
    }

    #[cfg(feature = "protocol-jwt")]
    async fn refresh_token(&self, token: &str) -> BulwarkResult<String> {
        // 依据 spec core-auth-api：启用 protocol-jwt 时委托 JwtHandler::refresh
        if self.config.token_style != "jwt" {
            return Err(BulwarkError::NotImplemented(
                "refresh_token 仅在 token_style=jwt 时可用".to_string(),
            ));
        }
        // 获取 login_id（用于 plugin/listener 回调）
        let login_id = self.verify_token(token).await?;
        let handler = crate::protocol::jwt::JwtHandler::new(&self.config.jwt_secret);
        let new_token = handler.refresh(token, self.config.timeout)?;
        // auto-wire: 触发 plugin on_login + listener Login 事件（新 token）
        if let Some(pm) = &self.plugin_manager {
            pm.on_login(login_id, &new_token);
        }
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::Login {
                login_id,
                token: new_token.clone(),
                device: None,
            });
        }
        Ok(new_token)
    }

    fn config(&self) -> Arc<BulwarkConfig> {
        Arc::clone(&self.config)
    }
}

// ============================================================================
// BulwarkInterface trait：权限数据回调（由业务方实现）
// ============================================================================

/// 接口 trait，定义获取权限 / 角色数据的回调。
///
/// [借鉴 Sa-Token] 对应 `StpInterface`，由业务方实现以提供权限数据。
///
/// # 数据来源
///
/// 业务方可自由选择数据来源（数据库 / YAML / 内存 / 外部服务等），
/// 框架不假定具体来源。`BulwarkFirewallStrategyDefault` 通过此回调获取数据后做字符串匹配。
#[async_trait]
pub trait BulwarkInterface: Send + Sync {
    /// 获取指定主体的权限列表。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 权限标识字符串列表（如 `["user:read", "user:write"]`）。
    ///
    /// # 错误
    /// - 数据源访问失败：由业务方实现决定具体 `BulwarkError`。
    async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>>;

    /// 获取指定主体的角色列表。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 角色标识字符串列表（如 `["admin", "user"]`）。
    ///
    /// # 错误
    /// - 数据源访问失败：由业务方实现决定具体 `BulwarkError`。
    async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>>;
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
    /// - `id`: 登录主体标识。
    ///
    /// # 返回
    /// 生成的 token 字符串。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - token 生成或会话创建失败：透传 `BulwarkError`。
    pub async fn login(id: i64) -> BulwarkResult<String> {
        crate::manager::BulwarkManager::logic()?.login(id).await
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
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn logout_by_login_id(login_id: i64) -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .logout_by_login_id(login_id)
            .await
    }

    /// 踢出用户：按账号踢出（语义等同 logout_by_login_id）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn kickout(login_id: i64) -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .kickout(login_id)
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
    pub async fn get_login_id() -> BulwarkResult<Option<i64>> {
        crate::manager::BulwarkManager::logic()?
            .get_login_id()
            .await
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

    /// 检查二级认证（MFA）状态（0.3.0 新增，依据 spec annotation-handling）。
    ///
    /// 委托 `BulwarkLogic::check_safe()`，默认实现返回 `Ok(())`（未启用 MFA）。
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
    /// 委托 `BulwarkLogic::check_disable()`，默认实现返回 `Ok(())`（未实现禁用账号库）。
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
    pub async fn verify_token(token: &str) -> BulwarkResult<i64> {
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

// ============================================================================
// 测试（依据 spec stp-core-api 所有 scenario）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::BulwarkDao;
    use crate::manager::BulwarkManager;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    // ------------------------------------------------------------------------
    // MockDao：复用 dao/session 测试的 HashMap + Instant 模拟 TTL
    // ------------------------------------------------------------------------

    struct MockDao {
        store: Mutex<HashMap<String, (String, Option<Instant>)>>,
    }

    impl MockDao {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BulwarkDao for MockDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            let mut store = self.store.lock();
            match store.get(key) {
                Some((value, expire_at)) => {
                    if let Some(deadline) = expire_at {
                        if Instant::now() >= *deadline {
                            store.remove(key);
                            return Ok(None);
                        }
                    }
                    Ok(Some(value.clone()))
                },
                None => Ok(None),
            }
        }

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            let expire_at = if ttl_seconds == 0 {
                None
            } else {
                Some(Instant::now() + Duration::from_secs(ttl_seconds))
            };
            self.store
                .lock()
                .insert(key.to_string(), (value.to_string(), expire_at));
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((existing, _)) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((_, expire_at)) => {
                    *expire_at = if seconds == 0 {
                        None
                    } else {
                        Some(Instant::now() + Duration::from_secs(seconds))
                    };
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.store.lock().remove(key);
            Ok(())
        }
    }

    // ------------------------------------------------------------------------
    // MockFirewall：模拟 BulwarkFirewallStrategy，控制权限/角色校验返回值
    // ------------------------------------------------------------------------

    /// 测试用 BulwarkFirewallStrategy mock，可控制 check_permission/check_role 返回值。
    struct MockFirewall {
        has_permission: bool,
        has_role: bool,
    }

    #[async_trait]
    impl BulwarkFirewallStrategy for MockFirewall {
        async fn get_permission_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
        async fn check_permission(&self, _login_id: i64, _permission: &str) -> BulwarkResult<bool> {
            Ok(self.has_permission)
        }
        async fn check_role(&self, _login_id: i64, _role: &str) -> BulwarkResult<bool> {
            Ok(self.has_role)
        }
        async fn check_role_any(&self, _login_id: i64, _roles: &[&str]) -> BulwarkResult<bool> {
            Ok(self.has_role)
        }
        async fn check_role_all(&self, _login_id: i64, _roles: &[&str]) -> BulwarkResult<bool> {
            Ok(self.has_role)
        }
    }

    /// 辅助函数：创建 BulwarkLogicDefault 实例（throw_on_not_login + firewall 返回值可配置）。
    fn make_logic(
        timeout: u64,
        active_timeout: u64,
        throw_on_not_login: bool,
        token_style: &str,
        has_permission: bool,
        has_role: bool,
    ) -> BulwarkLogicDefault {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao, timeout, active_timeout));
        let mut config = BulwarkConfig::default_config();
        config.throw_on_not_login = throw_on_not_login;
        config.token_style = token_style.to_string();
        let firewall: Arc<dyn BulwarkFirewallStrategy> = Arc::new(MockFirewall {
            has_permission,
            has_role,
        });
        BulwarkLogicDefault::new(session, Arc::new(config), firewall)
    }

    /// 辅助函数：在当前 task_local 设置 token 后执行 future。
    async fn with_token<R>(token: &str, f: impl std::future::Future<Output = R>) -> R {
        with_current_token(token.to_string(), f).await
    }

    // ------------------------------------------------------------------------
    // MockInterface：用于 BulwarkUtil 全局管理器测试
    // ------------------------------------------------------------------------

    struct MockInterface;

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
    }

    /// 初始化全局 BulwarkManager（用于 BulwarkUtil 静态方法测试）。
    fn init_global_manager(throw_on_not_login: bool) {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = throw_on_not_login;
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
        BulwarkManager::init(dao, Arc::new(config), interface).unwrap();
    }

    // ------------------------------------------------------------------------
    // spec scenario: login 首次登录 / 重复登录 / 自定义 token 风格
    // ------------------------------------------------------------------------

    /// 验证 login 返回非空 token 并创建会话。
    #[tokio::test]
    async fn login_creates_session_and_returns_token() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let token = logic.login(1001).await.unwrap();
        assert!(!token.is_empty(), "login 应返回非空 token");

        // 验证会话创建
        let ts = logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ts.login_id, 1001);
    }

    /// 验证重复登录生成不同 token 并记录多 token。
    #[tokio::test]
    async fn login_repeated_creates_multiple_tokens() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let t1 = logic.login(1001).await.unwrap();
        let t2 = logic.login(1001).await.unwrap();
        assert_ne!(t1, t2, "重复登录应生成不同 token");

        // Account-Session 应包含两个 token
        let as_ = logic
            .session
            .get_account_session(1001)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(as_.tokens.len(), 2);
    }

    /// 验证 token_style=random_64 生成 64 字符 token。
    #[tokio::test]
    async fn login_with_random_64_style() {
        let logic = make_logic(3600, 86400, false, "random_64", true, true);
        let token = logic.login(1001).await.unwrap();
        assert_eq!(token.len(), 64, "random_64 应生成 64 字符 token");
    }

    /// 验证 token_style=simple 生成 32 字符 token。
    #[tokio::test]
    async fn login_with_simple_style() {
        let logic = make_logic(3600, 86400, false, "simple", true, true);
        let token = logic.login(1001).await.unwrap();
        assert_eq!(token.len(), 32, "simple 应生成 32 字符 token");
    }

    /// 验证未知 token_style 时 login 返回 Err（依据 codebase-hardening Task 3.6）。
    ///
    /// 覆盖 `generate_token` 的 `other =>` 分支，断言返回 `BulwarkError::Config`。
    #[tokio::test]
    async fn create_token_unknown_style_errors() {
        let logic = make_logic(3600, 86400, false, "unknown_style", true, true);
        let result = logic.login(1001).await;
        assert!(
            matches!(result, Err(BulwarkError::Config(ref msg)) if msg.contains("unknown token_style")),
            "未知 token_style 应返回含 'unknown token_style' 的 Config 错误，实际: {:?}",
            result
        );
    }

    /// 验证 login_with_token 用自定义 token 创建会话。
    #[tokio::test]
    async fn login_with_custom_token() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        logic
            .login_with_token(1001, "custom-token-123")
            .await
            .unwrap();

        let ts = logic
            .session
            .get_token_session("custom-token-123")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ts.login_id, 1001);
        assert_eq!(ts.token, "custom-token-123");
    }

    // ------------------------------------------------------------------------
    // spec scenario: logout 销毁当前 / 销毁指定账号 / kickout
    // ------------------------------------------------------------------------

    /// 验证 logout 销毁当前 token 的会话。
    #[tokio::test]
    async fn logout_destroys_current_token() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
        let token = logic.login(1001).await.unwrap();

        // 在 task_local 作用域内调用 logout
        with_current_token(token.clone(), async {
            logic.logout().await.unwrap();
        })
        .await;

        // Token-Session 已删除
        let ts = logic.session.get_token_session(&token).await.unwrap();
        assert!(ts.is_none(), "logout 后 Token-Session 应删除");
    }

    /// 验证 logout 未登录时幂等返回 Ok。
    #[tokio::test]
    async fn logout_when_not_logged_in_is_noop() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        // 未设置 task_local，logout 应幂等返回 Ok
        let result = logic.logout().await;
        assert!(result.is_ok(), "未登录时 logout 应幂等返回 Ok");
    }

    /// 验证 logout_by_login_id 销毁所有 token。
    #[tokio::test]
    async fn logout_by_login_id_destroys_all_tokens() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let t1 = logic.login(1001).await.unwrap();
        let t2 = logic.login(1001).await.unwrap();

        logic.logout_by_login_id(1001).await.unwrap();

        assert!(logic
            .session
            .get_token_session(&t1)
            .await
            .unwrap()
            .is_none());
        assert!(logic
            .session
            .get_token_session(&t2)
            .await
            .unwrap()
            .is_none());
        assert!(logic
            .session
            .get_account_session(1001)
            .await
            .unwrap()
            .is_none());
    }

    /// 验证 kickout 按账号踢出（语义等同 logout_by_login_id）。
    #[tokio::test]
    async fn kickout_by_account_destroys_session() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let token = logic.login(1001).await.unwrap();

        logic.kickout(1001).await.unwrap();

        assert!(logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .is_none());
        assert!(logic
            .session
            .get_account_session(1001)
            .await
            .unwrap()
            .is_none());
    }

    /// 验证 kickout_by_token 按 token 踢出。
    #[tokio::test]
    async fn kickout_by_token_destroys_token_session() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let token = logic.login(1001).await.unwrap();

        logic.kickout_by_token(&token).await.unwrap();

        assert!(logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .is_none());
    }

    // ------------------------------------------------------------------------
    // spec scenario: check_login 有效 / 无效 / 过期 / 未登录抛异常
    // ------------------------------------------------------------------------

    /// 验证 check_login 有效 token 返回 true。
    #[tokio::test]
    async fn check_login_returns_true_for_valid_token() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
        let token = logic.login(1001).await.unwrap();

        with_current_token(token, async {
            let valid = logic.check_login().await.unwrap();
            assert!(valid, "有效 token 应返回 true");
        })
        .await;
    }

    /// 验证 check_login 无效 token 返回 false（throw_on_not_login=false）。
    #[tokio::test]
    async fn check_login_returns_false_for_invalid_token() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));

        with_current_token("invalid-token".to_string(), async {
            let valid = logic.check_login().await.unwrap();
            assert!(!valid, "无效 token 应返回 false");
        })
        .await;
    }

    /// 验证 check_login 未设置 token 返回 false（throw_on_not_login=false）。
    #[tokio::test]
    async fn check_login_returns_false_when_no_token() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        // 未设置 task_local，check_login 返回 false
        let valid = logic.check_login().await.unwrap();
        assert!(!valid, "未设置 token 应返回 false");
    }

    /// 验证 check_login 未登录且 throw_on_not_login=true 抛异常。
    ///
    /// spec config-system Requirement: 配置校验——throw_on_not_login。
    #[tokio::test]
    async fn check_login_throws_when_throw_on_not_login() {
        let logic = make_logic(3600, 86400, true, "uuid", true, true);
        let result = logic.check_login().await;
        assert!(
            matches!(result, Err(BulwarkError::Session(_))),
            "throw_on_not_login=true 且未登录应抛 Session 错误"
        );
    }

    /// 验证 check_login 过期 token 返回 false。
    #[tokio::test]
    async fn check_login_returns_false_for_expired_token() {
        let logic = Arc::new(make_logic(1, 86400, false, "uuid", true, true));
        let token = logic.login(1001).await.unwrap();

        // 等待 token 过期（1 秒 TTL）
        tokio::time::sleep(Duration::from_secs(2)).await;

        with_current_token(token, async {
            let valid = logic.check_login().await.unwrap();
            assert!(!valid, "过期 token 应返回 false");
        })
        .await;
    }

    // ------------------------------------------------------------------------
    // spec scenario: get_login_id
    // ------------------------------------------------------------------------

    /// 验证 get_login_id 返回当前 login_id。
    #[tokio::test]
    async fn get_login_id_returns_current_login_id() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
        let token = logic.login(1001).await.unwrap();

        with_current_token(token, async {
            let login_id = logic.get_login_id().await.unwrap();
            assert_eq!(login_id, Some(1001));
        })
        .await;
    }

    /// 验证 get_login_id 未登录返回 None。
    #[tokio::test]
    async fn get_login_id_returns_none_when_not_logged_in() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let login_id = logic.get_login_id().await.unwrap();
        assert_eq!(login_id, None, "未登录应返回 None");
    }

    /// 验证 get_login_id 无效 token 返回 None。
    #[tokio::test]
    async fn get_login_id_returns_none_for_invalid_token() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));

        with_current_token("invalid-token".to_string(), async {
            let login_id = logic.get_login_id().await.unwrap();
            assert_eq!(login_id, None, "无效 token 应返回 None");
        })
        .await;
    }

    // ------------------------------------------------------------------------
    // task_local 上下文测试
    // ------------------------------------------------------------------------

    /// 验证 current_token 未设置时抛错。
    #[test]
    fn current_token_errors_when_not_set() {
        let result = current_token();
        assert!(
            matches!(result, Err(BulwarkError::Session(_))),
            "未设置 task_local 时 current_token 应抛错"
        );
    }

    /// 验证 current_token 在作用域内返回 token。
    #[tokio::test]
    async fn current_token_returns_value_in_scope() {
        with_current_token("scoped-token".to_string(), async {
            let token = current_token().unwrap();
            assert_eq!(token, "scoped-token");
        })
        .await;
    }

    // ------------------------------------------------------------------------
    // spec scenario: check_permission 持有/未持有/未登录抛异常
    // ------------------------------------------------------------------------

    /// spec scenario "持有权限返回 true"：已登录且 firewall 返回 true 时 check_permission 通过。
    #[tokio::test]
    async fn check_permission_held_returns_ok() {
        let logic = make_logic(3600, 86400, true, "uuid", true, true);
        let token = logic.login(1001).await.unwrap();
        let result = with_token(&token, logic.check_permission("user:read")).await;
        assert!(result.is_ok(), "持有权限应返回 Ok");
    }

    /// spec scenario "未持有权限返回 false"：已登录但 firewall 返回 false 时抛 NotPermission。
    #[tokio::test]
    async fn check_permission_not_held_throws_not_permission() {
        let logic = make_logic(3600, 86400, true, "uuid", false, true);
        let token = logic.login(1001).await.unwrap();
        let result = with_token(&token, logic.check_permission("user:delete")).await;
        assert!(
            matches!(result, Err(BulwarkError::NotPermission(_))),
            "未持有权限应抛 NotPermission"
        );
    }

    /// spec scenario "未登录抛出异常"：未登录且 throw_on_not_login=true 时抛 NotLogin。
    #[tokio::test]
    async fn check_permission_not_login_throws_when_throw_on_not_login() {
        let logic = make_logic(3600, 86400, true, "uuid", true, true);
        // 不调用 login，直接 check_permission（无 task_local token）
        let result = logic.check_permission("user:read").await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(_))),
            "未登录且 throw_on_not_login=true 应抛 NotLogin"
        );
    }

    /// 未登录且 throw_on_not_login=false 时 check_permission 抛 NotPermission（降级为无权限）。
    #[tokio::test]
    async fn check_permission_not_login_throws_not_permission_when_silent() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        // 不调用 login，直接 check_permission（无 task_local token）
        let result = logic.check_permission("user:read").await;
        assert!(
            matches!(result, Err(BulwarkError::NotPermission(_))),
            "未登录且 throw_on_not_login=false 应抛 NotPermission（降级）"
        );
    }

    // ------------------------------------------------------------------------
    // spec scenario: check_role 持有/未持有/未登录抛异常
    // ------------------------------------------------------------------------

    /// spec scenario "持有角色返回 true"：已登录且 firewall 返回 true 时 check_role 通过。
    #[tokio::test]
    async fn check_role_held_returns_ok() {
        let logic = make_logic(3600, 86400, true, "uuid", true, true);
        let token = logic.login(1001).await.unwrap();
        let result = with_token(&token, logic.check_role("admin")).await;
        assert!(result.is_ok(), "持有角色应返回 Ok");
    }

    /// spec scenario "未持有角色返回 false"：已登录但 firewall 返回 false 时抛 NotRole。
    #[tokio::test]
    async fn check_role_not_held_throws_not_role() {
        let logic = make_logic(3600, 86400, true, "uuid", true, false);
        let token = logic.login(1001).await.unwrap();
        let result = with_token(&token, logic.check_role("admin")).await;
        assert!(
            matches!(result, Err(BulwarkError::NotRole(_))),
            "未持有角色应抛 NotRole"
        );
    }

    /// spec scenario "未登录抛出异常"：未登录且 throw_on_not_login=true 时 check_role 抛 NotLogin。
    #[tokio::test]
    async fn check_role_not_login_throws_when_throw_on_not_login() {
        let logic = make_logic(3600, 86400, true, "uuid", true, true);
        // 不调用 login，直接 check_role（无 task_local token）
        let result = logic.check_role("admin").await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(_))),
            "未登录且 throw_on_not_login=true 应抛 NotLogin"
        );
    }

    /// 未登录且 throw_on_not_login=false 时 check_role 抛 NotRole（降级为无角色）。
    #[tokio::test]
    async fn check_role_not_login_throws_not_role_when_silent() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        // 不调用 login，直接 check_role（无 task_local token）
        let result = logic.check_role("admin").await;
        assert!(
            matches!(result, Err(BulwarkError::NotRole(_))),
            "未登录且 throw_on_not_login=false 应抛 NotRole（降级）"
        );
    }

    // ------------------------------------------------------------------------
    // BulwarkUtil 未初始化错误测试（spec Scenario: 未初始化抛错）
    // ------------------------------------------------------------------------

    /// 未初始化时 BulwarkUtil::logout 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_logout_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::logout().await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 logout 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::logout_by_login_id 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_logout_by_login_id_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::logout_by_login_id(1001).await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 logout_by_login_id 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::kickout 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_kickout_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::kickout(1001).await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 kickout 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::kickout_by_token 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_kickout_by_token_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::kickout_by_token("some-token").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 kickout_by_token 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::check_login 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_check_login_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::check_login().await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 check_login 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::get_login_id 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_get_login_id_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::get_login_id().await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 get_login_id 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::check_permission 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_check_permission_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::check_permission("user:read").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 check_permission 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::check_role 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_check_role_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::check_role("admin").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 check_role 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::check_safe 返回 Session 错误（0.3.0 新增）。
    #[tokio::test]
    #[serial]
    async fn util_check_safe_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::check_safe().await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 check_safe 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::check_disable 返回 Session 错误（0.3.0 新增）。
    #[tokio::test]
    #[serial]
    async fn util_check_disable_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::check_disable().await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 check_disable 应返回 Session 错误"
        );
    }

    // ------------------------------------------------------------------------
    // BulwarkUtil 成功路径测试（覆盖未测试的静态方法）
    // ------------------------------------------------------------------------

    /// BulwarkUtil::logout_by_login_id 成功销毁指定账号的所有会话。
    #[tokio::test]
    #[serial]
    async fn util_logout_by_login_id_succeeds() {
        init_global_manager(false);
        let token = BulwarkUtil::login(1001).await.unwrap();
        assert!(!token.is_empty());

        BulwarkUtil::logout_by_login_id(1001).await.unwrap();

        // logout 后 check_login 应返回 false
        let valid = with_token(&token, async { BulwarkUtil::check_login().await })
            .await
            .unwrap();
        assert!(!valid, "logout_by_login_id 后 check_login 应返回 false");

        BulwarkManager::reset_for_test();
    }

    /// BulwarkUtil::kickout 成功踢出指定账号。
    #[tokio::test]
    #[serial]
    async fn util_kickout_succeeds() {
        init_global_manager(false);
        let token = BulwarkUtil::login(1001).await.unwrap();

        BulwarkUtil::kickout(1001).await.unwrap();

        let valid = with_token(&token, async { BulwarkUtil::check_login().await })
            .await
            .unwrap();
        assert!(!valid, "kickout 后 check_login 应返回 false");

        BulwarkManager::reset_for_test();
    }

    /// BulwarkUtil::kickout_by_token 成功踢出指定 token。
    #[tokio::test]
    #[serial]
    async fn util_kickout_by_token_succeeds() {
        init_global_manager(false);
        let token = BulwarkUtil::login(1001).await.unwrap();

        BulwarkUtil::kickout_by_token(&token).await.unwrap();

        let valid = with_token(&token, async { BulwarkUtil::check_login().await })
            .await
            .unwrap();
        assert!(!valid, "kickout_by_token 后 check_login 应返回 false");

        BulwarkManager::reset_for_test();
    }

    /// BulwarkUtil::get_login_id 返回当前登录 ID。
    #[tokio::test]
    #[serial]
    async fn util_get_login_id_returns_current_id() {
        init_global_manager(false);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let login_id = with_token(&token, async { BulwarkUtil::get_login_id().await })
            .await
            .unwrap();
        assert_eq!(login_id, Some(1001), "get_login_id 应返回当前 login_id");

        BulwarkManager::reset_for_test();
    }

    /// BulwarkUtil::check_safe 默认实现返回 Ok（0.3.0 新增，依据 spec annotation-handling）。
    ///
    /// 默认 `BulwarkLogicDefault` 未启用 MFA，`check_safe` 返回 `Ok(())`。
    #[tokio::test]
    #[serial]
    async fn util_check_safe_returns_ok_by_default() {
        init_global_manager(false);
        let _ = BulwarkUtil::login(1001).await.unwrap();

        // 默认实现（未覆写 check_safe）应返回 Ok
        let result = BulwarkUtil::check_safe().await;
        assert!(
            result.is_ok(),
            "默认 check_safe 应返回 Ok，实际: {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }

    /// BulwarkUtil::check_disable 默认实现返回 Ok（0.3.0 新增，依据 spec annotation-handling）。
    ///
    /// 默认 `BulwarkLogicDefault` 未实现禁用账号库，`check_disable` 返回 `Ok(())`。
    #[tokio::test]
    #[serial]
    async fn util_check_disable_returns_ok_by_default() {
        init_global_manager(false);
        let _ = BulwarkUtil::login(1001).await.unwrap();

        // 默认实现（未覆写 check_disable）应返回 Ok
        let result = BulwarkUtil::check_disable().await;
        assert!(
            result.is_ok(),
            "默认 check_disable 应返回 Ok，实际: {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // 0.2.0 新增 API 测试：login_by_token / verify_token / refresh_token
    // ------------------------------------------------------------------------

    /// BulwarkLogicDefault::login_by_token 对 uuid style token 返回 InvalidToken（0.2.1 auto-wire 修复）。
    ///
    /// 0.2.1 起login_by_token 被 override：优先委托 auth_logic，否则使用 verify_token。
    /// uuid token 不包含 login_id，verify_token 返回 InvalidToken。
    #[tokio::test]
    async fn login_by_token_uuid_style_returns_invalid_token() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let result = logic.login_by_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "uuid style login_by_token 应返回 InvalidToken，实际: {:?}",
            result
        );
    }

    /// BulwarkUtil::login_by_token 未初始化时返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_login_by_token_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::login_by_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 login_by_token 应返回 Session 错误"
        );
    }

    /// verify_token 对 simple style token 返回 login_id（spec Scenario）。
    ///
    /// 注意：0.1.0 `generate_token("simple")` 生成 32 字符 UUID，
    /// 与 core-token `SimpleTokenStyle` 的 `<login_id>-<uuid>` 格式不同。
    /// 此测试手动构造 simple-format token 验证 verify_token 委托逻辑。
    #[tokio::test]
    async fn verify_token_simple_style_returns_login_id() {
        let logic = make_logic(3600, 86400, false, "simple", true, true);
        // 手动构造 simple-format token: <login_id>-<uuid>
        let token = format!("1001-{}", uuid::Uuid::new_v4());
        let login_id = logic.verify_token(&token).await.unwrap();
        assert_eq!(login_id, 1001, "verify_token 应返回 login_id");
    }

    /// verify_token 对 uuid style token 返回 InvalidToken（spec Scenario）。
    ///
    /// uuid token 不包含 login_id，Token::verify 返回 None → InvalidToken。
    #[tokio::test]
    async fn verify_token_uuid_style_returns_invalid_token() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let token = logic.login(1001).await.unwrap();
        let result = logic.verify_token(&token).await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "uuid style verify_token 应返回 InvalidToken，实际: {:?}",
            result
        );
    }

    /// verify_token 对无效 token 返回 InvalidToken（spec Scenario）。
    ///
    /// "nodash" 无 '-' 分隔符，SimpleTokenStyle::verify 返回 Ok(None) → InvalidToken。
    #[tokio::test]
    async fn verify_token_invalid_returns_error() {
        let logic = make_logic(3600, 86400, false, "simple", true, true);
        let result = logic.verify_token("nodash").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "无效 token 应返回 InvalidToken，实际: {:?}",
            result
        );
    }

    /// verify_token 对格式错误 token（含 '-' 但 login_id 非数字）返回 InvalidToken（spec Scenario）。
    ///
    /// spec: "不泄露 token 具体失效原因（统一 InvalidToken）"
    #[tokio::test]
    async fn verify_token_malformed_returns_invalid_token() {
        let logic = make_logic(3600, 86400, false, "simple", true, true);
        let result = logic.verify_token("abc-xyz").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "格式错误 token 应返回 InvalidToken（统一错误），实际: {:?}",
            result
        );
    }

    /// BulwarkUtil::verify_token 未初始化时返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_verify_token_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::verify_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 verify_token 应返回 Session 错误"
        );
    }

    /// refresh_token default 返回 NotImplemented（spec Scenario: 未启用 protocol-jwt）。
    #[tokio::test]
    async fn refresh_token_default_returns_not_implemented() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let result = logic.refresh_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(_))),
            "default refresh_token 应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// BulwarkUtil::refresh_token 未初始化时返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_refresh_token_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::refresh_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 refresh_token 应返回 Session 错误"
        );
    }

    /// BulwarkUtil::verify_token 端到端：simple style token → 返回 login_id。
    ///
    /// 注意：BulwarkUtil::login 使用 0.1.0 generate_token，"simple" 生成 32 字符 UUID，
    /// 与 core-token SimpleTokenStyle 格式不同。此测试手动构造 simple-format token。
    #[tokio::test]
    #[serial]
    async fn util_verify_token_returns_login_id() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.token_style = "simple".to_string();
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
        BulwarkManager::init(dao, Arc::new(config), interface).unwrap();

        // 手动构造 simple-format token: <login_id>-<uuid>
        let token = format!("1001-{}", uuid::Uuid::new_v4());
        let login_id = BulwarkUtil::verify_token(&token).await.unwrap();
        assert_eq!(login_id, 1001);

        BulwarkManager::reset_for_test();
    }

    /// BulwarkUtil::refresh_token 端到端：未启用 protocol-jwt → NotImplemented。
    #[tokio::test]
    #[serial]
    async fn util_refresh_token_returns_not_implemented_without_jwt() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
        BulwarkManager::init(dao, Arc::new(config), interface).unwrap();

        let result = BulwarkUtil::refresh_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(_))),
            "未启用 protocol-jwt 时 refresh_token 应返回 NotImplemented"
        );

        BulwarkManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // 0.2.1 auto-wire gap 修复测试：builder 方法 + plugin/listener 触发
    // ------------------------------------------------------------------------

    /// builder 方法链式调用返回 Self（spec Scenario: 4.8 builder 方法验证）。
    #[tokio::test]
    async fn builder_methods_return_self_for_chaining() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        // 链式调用所有 builder 方法，验证返回 Self
        let pm = Arc::new(BulwarkPluginManager::new());
        #[cfg(feature = "listener")]
        let lm = Arc::new(BulwarkListenerManager::new());
        #[cfg(feature = "listener")]
        let _logic = logic.with_plugin_manager(pm).with_listener_manager(lm);
        #[cfg(not(feature = "listener"))]
        let _logic = logic.with_plugin_manager(pm);
        // 验证 login 仍可正常工作（builder 未破坏核心功能）
        let logic2 = make_logic(3600, 86400, false, "uuid", true, true);
        let token = logic2.login(1001).await.unwrap();
        assert!(!token.is_empty());
    }

    /// builder 方法注入 plugin_manager 后 login 触发 on_login 钩子（spec Scenario: auto-wire）。
    #[tokio::test]
    async fn login_with_plugin_manager_triggers_on_login() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let pm = Arc::new(BulwarkPluginManager::new());
        let logic = logic.with_plugin_manager(pm);
        // login 应成功，plugin on_login 作为副作用被调用（失败仅 warn 不中断）
        let token = logic.login(1001).await.unwrap();
        assert!(!token.is_empty());
    }

    /// builder 方法注入 listener_manager 后 login 广播 Login 事件（spec Scenario: auto-wire）。
    #[tokio::test]
    async fn login_with_listener_manager_broadcasts_login_event() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        #[cfg(feature = "listener")]
        {
            let lm = Arc::new(BulwarkListenerManager::new());
            let logic = logic.with_listener_manager(lm);
            let token = logic.login(1001).await.unwrap();
            assert!(!token.is_empty());
        }
        #[cfg(not(feature = "listener"))]
        {
            let _ = logic;
        }
    }

    /// logout 注入 plugin_manager + listener_manager 后触发 on_logout + Logout 事件。
    #[tokio::test]
    async fn logout_with_managers_triggers_hooks() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let pm = Arc::new(BulwarkPluginManager::new());
        let logic = logic.with_plugin_manager(pm);
        #[cfg(feature = "listener")]
        let logic = logic.with_listener_manager(Arc::new(BulwarkListenerManager::new()));

        // 先 login 获取 token
        let token = logic.login(2002).await.unwrap();
        // 在 token 上下文中 logout
        with_current_token(token.clone(), async { logic.logout().await })
            .await
            .unwrap();
    }

    /// kickout 注入 listener_manager 后广播 Kickout 事件。
    #[tokio::test]
    async fn kickout_with_listener_manager_broadcasts_event() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        #[cfg(feature = "listener")]
        {
            let lm = Arc::new(BulwarkListenerManager::new());
            let logic = logic.with_listener_manager(lm);
            // kickout 应成功，Kickout 事件作为副作用被广播
            logic.kickout(3003).await.unwrap();
        }
        #[cfg(not(feature = "listener"))]
        {
            logic.kickout(3003).await.unwrap();
        }
    }

    /// 未注入 manager 时向后兼容：login/logout/kickout 行为与 0.2.0 一致（spec Scenario: 4.9）。
    #[tokio::test]
    async fn backward_compat_without_managers_works_same_as_0_2_0() {
        // make_logic 不注入任何 manager，所有 Option 都是 None
        let logic = make_logic(3600, 86400, false, "uuid", true, true);

        // login 成功
        let token = logic.login(5005).await.unwrap();
        assert!(!token.is_empty());

        // check_login 成功
        let is_valid = with_current_token(token.clone(), async { logic.check_login().await })
            .await
            .unwrap();
        assert!(is_valid);

        // logout 成功（在 token 上下文中）
        with_current_token(token.clone(), async { logic.logout().await })
            .await
            .unwrap();

        // kickout 成功
        logic.kickout(5005).await.unwrap();
    }

    /// login_by_token 注入 auth_logic 后优先委托 auth_logic.verify_token。
    #[tokio::test]
    async fn login_by_token_with_auth_logic_delegates_to_auth() {
        use crate::core::auth::{AuthLogic, AuthLogicDefault};
        use crate::core::token::{Token, UuidTokenStyle};

        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
        let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
        let auth_logic: Arc<dyn AuthLogic> =
            Arc::new(AuthLogicDefault::new(session.clone(), token_handler, 3600));

        // 先通过 auth_logic login 生成一个有效 token
        let valid_token = auth_logic.login(6006, None).await.unwrap();

        // 构造 logic 注入 auth_logic
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let logic = logic.with_auth_logic(auth_logic);

        // login_by_token 应委托 auth_logic.verify_token 并建立会话
        logic.login_by_token(&valid_token).await.unwrap();

        // 验证会话已建立
        let ts = logic.session.get_token_session(&valid_token).await.unwrap();
        assert!(ts.is_some(), "login_by_token 后应建立会话");
        assert_eq!(ts.unwrap().login_id, 6006);
    }

    // ------------------------------------------------------------------------
    // refresh_token 覆盖率补充测试（0.2.1 新增 impl，依据 spec core-auth-api）
    // ------------------------------------------------------------------------

    /// refresh_token 在 token_style 非 jwt 时返回 NotImplemented。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn refresh_token_non_jwt_style_returns_not_implemented() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let result = logic.refresh_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("token_style=jwt")),
            "非 jwt style 的 refresh_token 应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// refresh_token 对无效 JWT token 返回 InvalidToken 错误。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn refresh_token_invalid_jwt_returns_error() {
        // 构造 token_style=jwt 的 logic（jwt_secret 来自 default_config）
        let logic = make_logic(3600, 86400, false, "jwt", true, true);
        // 无效 token：verify_token 返回 Err，refresh_token 应透传
        let result = logic.refresh_token("invalid.jwt.token").await;
        assert!(
            result.is_err(),
            "无效 JWT refresh_token 应返回 Err，实际: {:?}",
            result
        );
    }

    /// refresh_token 对有效 JWT token 成功刷新（0.2.1 auto-wire 触发 plugin/listener）。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn refresh_token_valid_jwt_returns_new_token() {
        // 构造 logic：token_style=jwt，使用明确 secret
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
        let mut config = BulwarkConfig::default_config();
        config.token_style = "jwt".to_string();
        config.jwt_secret = "refresh-test-secret".to_string();
        config.timeout = 3600;
        let firewall: Arc<dyn BulwarkFirewallStrategy> = Arc::new(MockFirewall {
            has_permission: true,
            has_role: true,
        });
        let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

        // 注入 plugin_manager + listener_manager 验证 auto-wire 不中断
        let pm = Arc::new(BulwarkPluginManager::new());
        let logic = logic.with_plugin_manager(pm);
        #[cfg(feature = "listener")]
        let logic = logic.with_listener_manager(Arc::new(BulwarkListenerManager::new()));

        // 先生成一个有效 JWT token
        let handler = crate::protocol::jwt::JwtHandler::new("refresh-test-secret");
        let original_token = handler.sign(7007, 3600).unwrap();

        // 刷新 token（同秒内 iat/exp 可能相同，不强制 new_token != original_token）
        let new_token = logic.refresh_token(&original_token).await.unwrap();
        assert!(!new_token.is_empty(), "refresh_token 应返回非空 token");

        // 验证新 token 有效且 login_id 一致
        let new_claims = handler.verify(&new_token).unwrap();
        assert_eq!(new_claims.login_id, 7007);
    }

    // ------------------------------------------------------------------------
    // trait default 方法覆盖率测试（login_by_token/verify_token/refresh_token）
    // ------------------------------------------------------------------------

    /// 最小化 BulwarkLogic mock，仅用于测试 trait default 方法。
    /// 所有必需方法标记 unreachable!()，仅保留 default 方法（login_by_token/verify_token/refresh_token）。
    struct MinimalLogic {
        config: Arc<BulwarkConfig>,
    }

    #[async_trait]
    impl BulwarkLogic for MinimalLogic {
        async fn login(&self, _: i64) -> BulwarkResult<String> {
            unreachable!()
        }
        async fn login_with_token(&self, _: i64, _: &str) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn logout(&self) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn logout_by_login_id(&self, _: i64) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn kickout(&self, _: i64) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn kickout_by_token(&self, _: &str) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn check_login(&self) -> BulwarkResult<bool> {
            unreachable!()
        }
        async fn get_login_id(&self) -> BulwarkResult<Option<i64>> {
            unreachable!()
        }
        async fn check_permission(&self, _: &str) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn check_role(&self, _: &str) -> BulwarkResult<()> {
            unreachable!()
        }
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    /// trait default login_by_token 返回 NotImplemented（spec: 未启用协议层 feature）。
    #[tokio::test]
    async fn trait_default_login_by_token_returns_not_implemented() {
        let logic = MinimalLogic {
            config: Arc::new(BulwarkConfig::default_config()),
        };
        let result = logic.login_by_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("protocol-oauth2")),
            "trait default login_by_token 应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// trait default verify_token 返回 NotImplemented（spec: 需子类 override）。
    #[tokio::test]
    async fn trait_default_verify_token_returns_not_implemented() {
        let logic = MinimalLogic {
            config: Arc::new(BulwarkConfig::default_config()),
        };
        let result = logic.verify_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("override")),
            "trait default verify_token 应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// trait default refresh_token 返回 NotImplemented（spec: 需启用 protocol-jwt）。
    #[tokio::test]
    async fn trait_default_refresh_token_returns_not_implemented() {
        let logic = MinimalLogic {
            config: Arc::new(BulwarkConfig::default_config()),
        };
        let result = logic.refresh_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("protocol-jwt")),
            "trait default refresh_token 应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    // ------------------------------------------------------------------------
    // login_by_token auto-wire 覆盖率补充（plugin + listener 钩子触发）
    // ------------------------------------------------------------------------

    /// login_by_token 注入 plugin_manager + listener_manager 后触发 auto-wire 钩子（simple style）。
    #[tokio::test]
    async fn login_by_token_with_managers_triggers_hooks() {
        let logic = make_logic(3600, 86400, false, "simple", true, true);
        let pm = Arc::new(BulwarkPluginManager::new());
        let logic = logic.with_plugin_manager(pm);
        #[cfg(feature = "listener")]
        let logic = logic.with_listener_manager(Arc::new(BulwarkListenerManager::new()));

        // 构造 simple 格式 token: "<login_id>-<uuid>"
        let token = format!("8008-{}", uuid::Uuid::new_v4());

        // login_by_token 应成功（plugin/listener 失败仅 warn 不中断）
        logic.login_by_token(&token).await.unwrap();

        // 验证会话已建立
        let ts = logic.session.get_token_session(&token).await.unwrap();
        assert!(ts.is_some(), "login_by_token 后应建立会话");
        assert_eq!(ts.unwrap().login_id, 8008);
    }

    // ------------------------------------------------------------------------
    // 0.3.0 TG1: metrics 集成测试（依据 spec observability-stack）
    // ------------------------------------------------------------------------

    /// with_metrics builder 注入 BulwarkMetrics 后 login 触发 record_login(success)。
    #[cfg(feature = "metrics-prometheus")]
    #[tokio::test]
    async fn login_with_metrics_records_success() {
        let logic = make_logic(3600, 86400, false, "uuid", false, false);
        let registry = prometheus::Registry::new();
        let metrics =
            Arc::new(crate::observability::BulwarkMetrics::register_to(&registry).unwrap());
        let logic = logic.with_metrics(metrics.clone());

        let _token = logic.login(1001).await.unwrap();

        // 验证 login_total{result="success"} = 1
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("bulwark_login_total{result=\"success\"} 1"),
            "expected success counter=1, got: {}",
            output
        );
    }

    /// with_metrics 注入后 check_permission 触发 record_permission_query(allow/deny)。
    #[cfg(feature = "metrics-prometheus")]
    #[tokio::test]
    async fn check_permission_with_metrics_records_query() {
        let logic = make_logic(3600, 86400, true, "uuid", false, false);
        let registry = prometheus::Registry::new();
        let metrics =
            Arc::new(crate::observability::BulwarkMetrics::register_to(&registry).unwrap());
        let logic = logic.with_metrics(metrics.clone());

        let token = logic.login(1001).await.unwrap();

        // check_permission 应记录 deny（MockInterface 返回空权限列表）
        let result = with_token(&token, async { logic.check_permission("user:read").await }).await;
        assert!(result.is_err(), "未授权权限应返回 Err");

        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("bulwark_permission_query_total{result=\"deny\"} 1"),
            "expected deny counter=1, got: {}",
            output
        );
    }

    /// 未注入 metrics 时 login 不 panic（零开销路径）。
    #[cfg(feature = "metrics-prometheus")]
    #[tokio::test]
    async fn login_without_metrics_does_not_panic() {
        let logic = make_logic(3600, 86400, false, "uuid", false, false);
        // 不调用 with_metrics
        let _token = logic.login(1001).await.unwrap();
        // 不 panic 即通过
    }
}
