//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BulwarkLogicDefault 实现块（从 mod.rs 迁移）。

use super::*;

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
            clock: Arc::new(SystemClock::new()),
            #[cfg(feature = "security-alert")]
            anomaly_detectors: None,
            #[cfg(feature = "security-alert")]
            alert_listener_manager: None,
            #[cfg(feature = "device-binding")]
            device_binding_policy: None,
            disable_repository: None,
            #[cfg(feature = "three-tier-cache")]
            user_cache_service: None,
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

    /// 注入时钟（builder 模式）。
    ///
    /// 默认使用 `SystemClock`（委托 `chrono::Utc::now()`）。
    /// 测试中可注入 `MockClock` 手动控制时间推进，消除依赖 `tokio::time::sleep` 的 flaky 测试。
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
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

    /// 注入封禁库（builder 模式，非 feature-gated）。
    ///
    /// 注入后 `check_disable` 从 task_local 获取当前 token → 查询 TokenSession 取 login_id →
    /// 调用 `DisableRepository::is_disable(login_id, "default")`，被封禁则返回
    /// `BulwarkError::DisableService`（携带 `until` 解封时间）。
    ///
    /// 未注入时 `check_disable` 返回 `Ok(())`（向后兼容 0.6.4 之前行为）。
    pub fn with_disable_repository(
        mut self,
        repo: Arc<dyn crate::account::disable::DisableRepository>,
    ) -> Self {
        self.disable_repository = Some(repo);
        self
    }

    /// 注入用户缓存服务（builder 模式，需启用 `three-tier-cache` feature）。
    ///
    /// 注入后 `logout` / `logout_by_login_id` 在销毁会话后调用
    /// `UserCacheService::invalidate(login_id)` 失效用户的三层缓存（权限/角色/用户）。
    /// 未注入时 logout 不失效缓存（向后兼容）。失效失败只 `tracing::warn!` 不中断 logout。
    #[cfg(feature = "three-tier-cache")]
    pub fn with_user_cache_service(mut self, service: Arc<crate::cache::UserCacheService>) -> Self {
        self.user_cache_service = Some(service);
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
                return Err(BulwarkError::NotLogin("stp-no-api-key::".to_string()));
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
