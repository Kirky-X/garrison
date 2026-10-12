// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! GarrisonLogicDefault 实现块（从 mod.rs 迁移）。

use super::*;

impl GarrisonLogicDefault {
    /// 获取底层 DAO 引用（JWT 黑名单读写 / firewall 计数封禁使用）。
    /// cfg 与调用方严格对齐（编译矩阵已验证）：protocol-jwt 与 firewall-bruteforce 两条路径生效，其余消费方直接走 `session.dao()`。
    #[cfg(any(feature = "protocol-jwt", feature = "firewall-bruteforce"))]
    pub(crate) fn dao(&self) -> std::sync::Arc<dyn crate::dao::GarrisonDao> {
        self.session.dao().clone()
    }

    /// 诊断 builder 是否已注入防火墙 hook；唯一调用方 firewall_tests，按同款 cfg 全隔离。
    #[cfg(all(test, feature = "firewall-bruteforce"))]
    pub(crate) fn firewall_hook_injected(&self) -> bool {
        self.firewall.firewall_hook_injected()
    }

    /// 创建默认实现实例；`disable_repository` 交给 `check_disable` 查询封禁状态，通用场景传 `Arc::new(DefaultDisableRepository::new(dao))`。
    pub fn new(
        session: Arc<GarrisonSession>,
        config: Arc<GarrisonConfig>,
        firewall: Arc<dyn GarrisonPermissionStrategy>,
        disable_repository: Arc<dyn crate::account::disable::DisableRepository>,
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
            #[cfg(feature = "security-extra")]
            anomaly_detectors: None,
            #[cfg(feature = "security-extra")]
            alert_listener_manager: None,
            #[cfg(feature = "device-binding")]
            device_binding_policy: None,
            disable_repository,
            #[cfg(feature = "three-tier-cache")]
            user_cache_service: None,
            marker: None,
            #[cfg(all(feature = "protocol-apikey", feature = "firewall-bruteforce"))]
            brute_force_strategy: std::sync::OnceLock::new(),
        }
    }

    /// 注入插件管理器（builder 模式）；注入后 `login` / `logout` 触发 `on_login` / `on_logout` 钩子。
    pub fn with_plugin_manager(mut self, pm: Arc<GarrisonPluginManager>) -> Self {
        self.plugin_manager = Some(pm);
        self
    }

    /// 注入监听器管理器（builder 模式，需 `listener` feature）；注入后 `login` / `logout` / `kickout` 广播 `GarrisonEvent`。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<GarrisonListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 注入认证逻辑（builder 模式）；`login_by_token` 优先委托 `auth_logic.verify_token` 校验。
    pub fn with_auth_logic(mut self, auth: Arc<dyn AuthLogic>) -> Self {
        self.auth_logic = Some(auth);
        self
    }

    /// 注入权限校验器（builder 模式）；`check_permission` 优先走 `PermissionChecker::authorize`（Decision 路径）并广播 `PermissionCheck` 事件供审计，未注入时回退 `firewall.check_permission`。
    pub fn with_permission_checker(mut self, pc: Arc<dyn PermissionChecker>) -> Self {
        self.permission_checker = Some(pc);
        self
    }

    /// 注入 Prometheus 指标采集器（builder 模式，需 `metrics-prometheus` feature）；注入后 login/check_login/check_permission/check_role 自动 emit 指标，未注入时 no-op。
    #[cfg(feature = "metrics-prometheus")]
    pub fn with_metrics(mut self, metrics: Arc<crate::observability::GarrisonMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// 注入密码哈希器（builder 模式，需 `account-credential` + `db-sqlite` feature）；`login_with_password` 委托其 verify，未注入时返回 `Config("stp-password-hasher-not-configured")`。
    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    pub fn with_password_hasher(
        mut self,
        hasher: Arc<dyn crate::account::credential::password::PasswordHasher>,
    ) -> Self {
        self.password_hasher = Some(hasher);
        self
    }

    /// 注入用户 Repository（builder 模式，需 `account-credential` + `db-sqlite` feature）；`login_with_password` 委托其 find_by_username，未注入时返回 `Config("stp-user-repo-not-configured")`。
    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    pub fn with_user_repository(
        mut self,
        repo: Arc<dyn crate::dao::repository::UserRepository>,
    ) -> Self {
        self.user_repository = Some(repo);
        self
    }

    /// 设置权限/角色查询的默认 `login_type`（builder 模式），未设置时 "default"。
    ///
    /// ```ignore
    /// let logic = GarrisonLogicDefault::new(session, config, firewall)
    /// .with_login_type("admin");
    /// ```
    pub fn with_login_type(mut self, login_type: &str) -> Self {
        self.login_type = login_type.to_string();
        self
    }

    /// 设置 JWT 校验模式（builder 模式）：`Stateless` 仅 JWT verify，`Mixin`（默认）JWT + session 二级校验，`Simple` 仅 session。
    /// `Stateless`/`Mixin` 的 JWT verify 需 `protocol-jwt`，否则 `Stateless` 返回 `Config` 错误；编译期配置，运行时不可切换。
    ///
    /// ```ignore
    /// let logic = GarrisonLogicDefault::new(session, config, firewall)
    /// .with_jwt_mode(JwtMode::Stateless);
    /// ```
    pub fn with_jwt_mode(mut self, mode: JwtMode) -> Self {
        self.jwt_mode = mode;
        self
    }

    /// 注入时钟（builder 模式）；默认 `SystemClock`，测试可注入 `MockClock` 控制时间推进，避免 sleep 型 flaky 测试。
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// 注入 Refresh Token 轮换器（builder 模式，需 `protocol-jwt` + `db-sqlite` feature）；`refresh_access_token` 委托其 rotate，未注入时返回 `NotImplemented`。
    #[cfg(all(feature = "protocol-jwt", feature = "db-sqlite"))]
    pub fn with_refresh_token_rotation(
        mut self,
        rtr: crate::protocol::jwt::refresh::RefreshTokenRotation,
    ) -> Self {
        self.refresh_token_rotation = Some(rtr);
        self
    }

    /// 注入异常检测器（builder 模式，需 `security-alert` feature）；可注入多个，按序在 login/check_login 调用，检测失败只 warn 不中断主流程。
    #[cfg(feature = "security-extra")]
    pub fn with_anomaly_detector(
        mut self,
        detector: Arc<dyn crate::strategy::alert::AnomalyDetector>,
    ) -> Self {
        self.anomaly_detectors
            .get_or_insert_with(Vec::new)
            .push(detector);
        self
    }

    /// 注入告警监听器管理器（builder 模式，需 `security-alert` feature）；异常事件经 `AlertListenerManager::broadcast_alert` 广播，未注入时不广播。
    #[cfg(feature = "security-extra")]
    pub fn with_alert_listener_manager(
        mut self,
        manager: Arc<crate::strategy::alert::AlertListenerManager>,
    ) -> Self {
        self.alert_listener_manager = Some(manager);
        self
    }

    /// 注入设备绑定策略（builder 模式，需 `device-binding` feature）；login 创建 session 前检测新设备，要求二级认证时置 `LoginParams.require_mfa`，检测失败只 warn 不中断。
    #[cfg(feature = "device-binding")]
    pub fn with_device_binding_policy(
        mut self,
        policy: Arc<dyn crate::strategy::device_binding::DeviceBindingPolicy>,
    ) -> Self {
        self.device_binding_policy = Some(policy);
        self
    }

    /// 注入用户缓存服务（builder 模式，需 `three-tier-cache` feature）；logout 销毁会话后调用 `UserCacheService::invalidate(login_id)` 失效权限/角色/用户三层缓存，失败只 warn。
    #[cfg(feature = "three-tier-cache")]
    pub fn with_user_cache_service(mut self, service: Arc<crate::cache::UserCacheService>) -> Self {
        self.user_cache_service = Some(service);
        self
    }

    /// 设置标记字段（builder 模式）；测试/工厂扩展点标记 logic 来源，不影响运行时行为。
    pub fn with_marker(mut self, marker: &'static str) -> Self {
        self.marker = Some(marker);
        self
    }

    /// 校验 API Key：从 task_local `CURRENT_TOKEN` 取 key，委托 `ApiKeyHandler::verify_with_namespace`。
    /// `protocol-apikey` 关闭时 fail-closed 返回 `Err(Config)`（杜绝"编译通过但校验全部放行"的安全假象）。
    #[cfg(feature = "protocol-apikey")]
    pub async fn check_api_key(&self, namespace: &str) -> GarrisonResult<()> {
        // 无 token 上下文 = 未携带 API Key，返回 NotLogin（映射 401）；本方法返回 Result<()>，无法用 Ok(false) 表达未通过。
        let key = match current_token() {
            Ok(t) => t,
            Err(_) => {
                return Err(GarrisonError::NotLogin("stp-no-api-key::".to_string()));
            },
        };
        let handler = crate::protocol::apikey::ApiKeyHandler::new(self.session.dao().clone());

        // IP 级认证失败限速（CWE-307）：校验前查封禁短路，仅失败计入（成功路径零写入）；无 IP 上下文时 fail-open 跳过。
        #[cfg(feature = "firewall-bruteforce")]
        if let Some(ip) = crate::stp::current_ip() {
            use crate::strategy::firewall::brute_force::{BruteForceConfig, BruteForceStrategy};
            use crate::strategy::firewall::FirewallContext;
            // 复用惰性初始化的策略实例，避免每次调用重建 ban_storage / limiter 并丢弃已配置实例。
            let strategy = self.brute_force_strategy.get_or_init(|| {
                Arc::new(BruteForceStrategy::new(
                    BruteForceConfig::default(),
                    self.session.dao().clone(),
                ))
            });
            let fw_ctx = FirewallContext::new(&ip);
            if strategy.is_blocked(&fw_ctx).await? {
                return Err(GarrisonError::FirewallBlocked(format!(
                    "stp-apikey-ip-blocked::{}",
                    ip
                )));
            }
            return match handler.verify_with_namespace(&key, namespace).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    // 记录失败（超阈值封禁）；record_failure 自身失败不得覆盖原始认证错误 e，否则 401/403 会误报为 500。
                    if let Err(record_err) = strategy.record_failure(&fw_ctx).await {
                        tracing::warn!(
                            ip = %ip,
                            error = %record_err,
                            "brute force record_failure failed (does not affect the auth result, original auth error is still returned)"
                        );
                    }
                    Err(e)
                },
            };
        }

        handler.verify_with_namespace(&key, namespace).await?;
        Ok(())
    }

    /// fail-closed 返回配置错误：宏在任意 feature 组合下都调用本方法，feature 缺失时若放行则 API Key 认证完全失效。
    #[cfg(not(feature = "protocol-apikey"))]
    pub async fn check_api_key(&self, _namespace: &str) -> GarrisonResult<()> {
        Err(GarrisonError::Config(
            "stp-apikey-feature-required::".to_string(),
        ))
    }
}

#[cfg(all(test, not(feature = "protocol-apikey")))]
mod no_feature_tests {
    use super::*;
    use crate::config::GarrisonConfig;
    use crate::dao::InMemoryDao;
    use crate::manager::GarrisonManager;
    use crate::stp::mock::MockInterface;
    use serial_test::serial;

    /// feature 关闭时 check_api_key 必须 fail-closed 返回 Err(Config)。
    #[serial]
    #[tokio::test]
    async fn check_api_key_without_feature_returns_config_error() {
        GarrisonManager::reset_for_test();
        let dao: std::sync::Arc<dyn crate::dao::GarrisonDao> =
            std::sync::Arc::new(InMemoryDao::new());
        let config = std::sync::Arc::new(GarrisonConfig::default());
        let interface: std::sync::Arc<dyn crate::stp::GarrisonInterface> =
            std::sync::Arc::new(MockInterface);
        GarrisonManager::builder()
            .dao(dao)
            .config(config)
            .interface(interface)
            .build()
            .await
            .unwrap();

        let result = GarrisonUtil::check_api_key("any-namespace").await;
        assert!(
            matches!(result, Err(GarrisonError::Config(ref m)) if m.contains("stp-apikey-feature-required")),
            "feature 关闭时应返回 Err(Config)，实际: {:?}",
            result
        );
    }
}
