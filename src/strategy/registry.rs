//! 策略注册表模块，提供 6 个可插拔策略 trait + Strategy 注册表。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的策略模式设计，
//! 允许运行时替换鉴权策略组件。
//!
//! ## 6 个策略 trait
//!
//! - [`LoginHandler`]：登录策略
//! - [`LogoutHandler`]：登出策略
//! - [`PermissionHandler`]：权限校验策略
//! - [`TokenGenerator`]：Token 生成策略
//! - [`SessionCreator`]：会话创建策略
//! - [`FirewallStrategy`]：防火墙策略
//!
//! ## Strategy 注册表
//!
//! [`Strategy`] struct 持有 6 个 `Arc<dyn Trait>`，
//! 提供 `register_*`/`get_*`/`remove_*` 方法。
//! 默认实现委托 [`BulwarkLogic`](crate::stp::BulwarkLogic)。
//!
//! ## 偏差说明
//!
//! - `login_id` 使用 `i64` 而非 `LoginId` newtype，遵循 `BulwarkLogic` trait 现有惯例
//!   （依据规则 11：惯例优先于新颖）
//! - [`FirewallStrategy`] 与现有 [`BulwarkFirewallStrategy`](crate::strategy::BulwarkFirewallStrategy)
//!   trait 共存（依据 spec Constraints），两者名称不同，不冲突

use crate::error::BulwarkResult;
use crate::stp::BulwarkLogic;
use crate::strategy::hooks::LoginContext;
use async_trait::async_trait;
use std::sync::Arc;

// ============================================================================
// 6 个策略 trait（均为 Send + Sync）
// ============================================================================

/// 登录策略 trait，定义登录行为的可插拔契约。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的 `SaTokenStrategy` 登录部分，
/// 业务方可通过实现此 trait 替换默认的登录逻辑。
///
/// # 默认实现
///
/// [`DefaultLoginHandler`] 委托 [`BulwarkLogic::login`]。
#[async_trait]
pub trait LoginHandler: Send + Sync {
    /// 执行登录：生成 token 并创建会话。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 生成的 token 字符串。
    async fn handle_login(&self, login_id: i64) -> BulwarkResult<String>;
}

/// 登出策略 trait，定义登出行为的可插拔契约。
///
/// # 默认实现
///
/// [`DefaultLogoutHandler`] 委托 [`BulwarkLogic::logout`] /
/// [`BulwarkLogic::logout_by_login_id`]。
#[async_trait]
pub trait LogoutHandler: Send + Sync {
    /// 执行登出：从 task_local 获取当前 token 并销毁。
    async fn handle_logout(&self) -> BulwarkResult<()>;

    /// 按账号登出：销毁指定 login_id 的所有会话。
    async fn handle_logout_by_login_id(&self, login_id: i64) -> BulwarkResult<()>;
}

/// 权限校验策略 trait，定义权限/角色校验的可插拔契约。
///
/// # 默认实现
///
/// [`DefaultPermissionHandler`] 委托 [`BulwarkLogic::check_permission`] /
/// [`BulwarkLogic::check_role`]。
#[async_trait]
pub trait PermissionHandler: Send + Sync {
    /// 校验权限：检查当前主体是否持有指定权限。
    async fn handle_check_permission(&self, permission: &str) -> BulwarkResult<()>;

    /// 校验角色：检查当前主体是否持有指定角色。
    async fn handle_check_role(&self, role: &str) -> BulwarkResult<()>;
}

/// Token 生成策略 trait，定义 token 生成与刷新的可插拔契约。
///
/// # 默认实现
///
/// [`DefaultTokenGenerator`] 委托 [`BulwarkLogic::login`]（生成 token）
/// 与 [`BulwarkLogic::refresh_token`]（刷新 token）。
#[async_trait]
pub trait TokenGenerator: Send + Sync {
    /// 生成 token。
    ///
    /// 默认实现委托 [`BulwarkLogic::login`]，会同时创建会话。
    async fn generate_token(&self, login_id: i64) -> BulwarkResult<String>;

    /// 刷新 token。
    async fn refresh_token(&self, token: &str) -> BulwarkResult<String>;
}

/// 会话创建策略 trait，定义会话创建与登录检查的可插拔契约。
///
/// # 默认实现
///
/// [`DefaultSessionCreator`] 委托 [`BulwarkLogic::login_with_token`] /
/// [`BulwarkLogic::check_login`]。
#[async_trait]
pub trait SessionCreator: Send + Sync {
    /// 创建会话：用指定 token 为 login_id 建立会话。
    async fn create_session(&self, login_id: i64, token: &str) -> BulwarkResult<()>;

    /// 检查登录状态。
    async fn check_login(&self) -> BulwarkResult<bool>;
}

/// 防火墙策略 trait，定义登录前安全检查的可插拔契约。
///
/// 与现有 [`BulwarkFirewallStrategy`](crate::strategy::BulwarkFirewallStrategy) trait 共存
/// （依据 spec Constraints），两者名称不同，职责不同：
/// - `BulwarkFirewallStrategy`：权限/角色数据查询与校验
/// - `FirewallStrategy`（本 trait）：登录前防火墙钩子检查
///
/// # 默认实现
///
/// [`DefaultFirewallStrategy`] 返回 `Ok(())`（no-op，向后兼容），
/// 因 [`BulwarkLogic`] trait 无 `check_login_hooks` 方法。
#[async_trait]
pub trait FirewallStrategy: Send + Sync {
    /// 登录前防火墙安全检查。
    async fn check_login_hooks(&self, login_id: i64, ctx: &LoginContext) -> BulwarkResult<()>;
}

// ============================================================================
// 默认实现：委托 BulwarkLogic
// ============================================================================

/// `LoginHandler` 的默认实现，委托 [`BulwarkLogic::login`]。
pub struct DefaultLoginHandler {
    logic: Arc<dyn BulwarkLogic>,
}

impl DefaultLoginHandler {
    /// 创建默认登录策略实例。
    pub fn new(logic: Arc<dyn BulwarkLogic>) -> Self {
        Self { logic }
    }
}

#[async_trait]
impl LoginHandler for DefaultLoginHandler {
    async fn handle_login(&self, login_id: i64) -> BulwarkResult<String> {
        self.logic.login(login_id).await
    }
}

/// `LogoutHandler` 的默认实现，委托 [`BulwarkLogic::logout`] /
/// [`BulwarkLogic::logout_by_login_id`]。
pub struct DefaultLogoutHandler {
    logic: Arc<dyn BulwarkLogic>,
}

impl DefaultLogoutHandler {
    /// 创建默认登出策略实例。
    pub fn new(logic: Arc<dyn BulwarkLogic>) -> Self {
        Self { logic }
    }
}

#[async_trait]
impl LogoutHandler for DefaultLogoutHandler {
    async fn handle_logout(&self) -> BulwarkResult<()> {
        self.logic.logout().await
    }

    async fn handle_logout_by_login_id(&self, login_id: i64) -> BulwarkResult<()> {
        self.logic.logout_by_login_id(login_id).await
    }
}

/// `PermissionHandler` 的默认实现，委托 [`BulwarkLogic::check_permission`] /
/// [`BulwarkLogic::check_role`]。
pub struct DefaultPermissionHandler {
    logic: Arc<dyn BulwarkLogic>,
}

impl DefaultPermissionHandler {
    /// 创建默认权限校验策略实例。
    pub fn new(logic: Arc<dyn BulwarkLogic>) -> Self {
        Self { logic }
    }
}

#[async_trait]
impl PermissionHandler for DefaultPermissionHandler {
    async fn handle_check_permission(&self, permission: &str) -> BulwarkResult<()> {
        self.logic.check_permission(permission).await
    }

    async fn handle_check_role(&self, role: &str) -> BulwarkResult<()> {
        self.logic.check_role(role).await
    }
}

/// `TokenGenerator` 的默认实现，委托 [`BulwarkLogic::login`]（生成）
/// 与 [`BulwarkLogic::refresh_token`]（刷新）。
pub struct DefaultTokenGenerator {
    logic: Arc<dyn BulwarkLogic>,
}

impl DefaultTokenGenerator {
    /// 创建默认 token 生成策略实例。
    pub fn new(logic: Arc<dyn BulwarkLogic>) -> Self {
        Self { logic }
    }
}

#[async_trait]
impl TokenGenerator for DefaultTokenGenerator {
    async fn generate_token(&self, login_id: i64) -> BulwarkResult<String> {
        self.logic.login(login_id).await
    }

    async fn refresh_token(&self, token: &str) -> BulwarkResult<String> {
        self.logic.refresh_token(token).await
    }
}

/// `SessionCreator` 的默认实现，委托 [`BulwarkLogic::login_with_token`] /
/// [`BulwarkLogic::check_login`]。
pub struct DefaultSessionCreator {
    logic: Arc<dyn BulwarkLogic>,
}

impl DefaultSessionCreator {
    /// 创建默认会话创建策略实例。
    pub fn new(logic: Arc<dyn BulwarkLogic>) -> Self {
        Self { logic }
    }
}

#[async_trait]
impl SessionCreator for DefaultSessionCreator {
    async fn create_session(&self, login_id: i64, token: &str) -> BulwarkResult<()> {
        self.logic.login_with_token(login_id, token).await
    }

    async fn check_login(&self) -> BulwarkResult<bool> {
        self.logic.check_login().await
    }
}

/// `FirewallStrategy` 的默认实现，返回 `Ok(())`（no-op）。
///
/// [`BulwarkLogic`] trait 无 `check_login_hooks` 方法，
/// 默认 no-op 与现有 [`crate::strategy::BulwarkFirewallStrategy`] trait 的
/// `check_login_hooks` 默认行为一致。
pub struct DefaultFirewallStrategy {
    // 保留 logic 字段以与其他 5 个 Default*Handler 保持构造签名一致，
    // 虽然当前 check_login_hooks 无委托目标（BulwarkLogic 无此方法）。
    #[allow(dead_code)]
    logic: Arc<dyn BulwarkLogic>,
}

impl DefaultFirewallStrategy {
    /// 创建默认防火墙策略实例。
    pub fn new(logic: Arc<dyn BulwarkLogic>) -> Self {
        Self { logic }
    }
}

#[async_trait]
impl FirewallStrategy for DefaultFirewallStrategy {
    async fn check_login_hooks(&self, _login_id: i64, _ctx: &LoginContext) -> BulwarkResult<()> {
        Ok(())
    }
}

// ============================================================================
// Strategy 注册表
// ============================================================================

/// 策略注册表，持有 6 个可插拔策略的 `Arc<dyn Trait>`。
///
/// 提供 `register_*`/`get_*`/`remove_*` 方法用于运行时替换、查询、恢复策略。
/// 默认策略委托 [`BulwarkLogic`]，通过 [`Strategy::new`] 构造。
///
/// # 线程安全
///
/// `Strategy` 本身通过 `&self` 提供 `get_*` 方法，通过 `&mut self` 提供 `register_*`/
/// `remove_*` 方法。在 [`BulwarkManager`](crate::manager::BulwarkManager) 中以
/// `Arc<RwLock<Strategy>>` 形式持有，保证线程安全。
///
/// # 示例
///
/// ```ignore
/// use std::sync::Arc;
/// use bulwark::strategy::{Strategy, LoginHandler};
/// use bulwark::BulwarkManager;
///
/// // 获取 strategy 引用
/// let strategy = BulwarkManager::strategy().unwrap();
///
/// // 运行时替换登录策略
/// struct MyLoginHandler;
/// #[async_trait::async_trait]
/// impl LoginHandler for MyLoginHandler {
///     async fn handle_login(&self, login_id: i64) -> bulwark::BulwarkResult<String> {
///         Ok(format!("custom-token-{}", login_id))
///     }
/// }
/// strategy.write().register_login_handler(Arc::new(MyLoginHandler));
///
/// // 恢复默认
/// strategy.write().remove_login_handler();
/// ```
pub struct Strategy {
    /// 当前登录策略。
    login_handler: Arc<dyn LoginHandler>,
    /// 当前登出策略。
    logout_handler: Arc<dyn LogoutHandler>,
    /// 当前权限校验策略。
    permission_handler: Arc<dyn PermissionHandler>,
    /// 当前 token 生成策略。
    token_generator: Arc<dyn TokenGenerator>,
    /// 当前会话创建策略。
    session_creator: Arc<dyn SessionCreator>,
    /// 当前防火墙策略。
    firewall_strategy: Arc<dyn FirewallStrategy>,
    /// 默认登录策略（用于 remove_* 恢复）。
    default_login_handler: Arc<dyn LoginHandler>,
    /// 默认登出策略（用于 remove_* 恢复）。
    default_logout_handler: Arc<dyn LogoutHandler>,
    /// 默认权限校验策略（用于 remove_* 恢复）。
    default_permission_handler: Arc<dyn PermissionHandler>,
    /// 默认 token 生成策略（用于 remove_* 恢复）。
    default_token_generator: Arc<dyn TokenGenerator>,
    /// 默认会话创建策略（用于 remove_* 恢复）。
    default_session_creator: Arc<dyn SessionCreator>,
    /// 默认防火墙策略（用于 remove_* 恢复）。
    default_firewall_strategy: Arc<dyn FirewallStrategy>,
}

impl Strategy {
    /// 创建策略注册表，6 个策略均初始化为委托 `BulwarkLogic` 的默认实现。
    ///
    /// # 参数
    /// - `logic`: `BulwarkLogic` 引用，默认策略委托其方法。
    ///
    /// # 返回
    /// 新建的 `Strategy` 实例，6 个策略与默认策略均为默认实现。
    pub fn new(logic: Arc<dyn BulwarkLogic>) -> Self {
        let login_handler: Arc<dyn LoginHandler> =
            Arc::new(DefaultLoginHandler::new(logic.clone()));
        let logout_handler: Arc<dyn LogoutHandler> =
            Arc::new(DefaultLogoutHandler::new(logic.clone()));
        let permission_handler: Arc<dyn PermissionHandler> =
            Arc::new(DefaultPermissionHandler::new(logic.clone()));
        let token_generator: Arc<dyn TokenGenerator> =
            Arc::new(DefaultTokenGenerator::new(logic.clone()));
        let session_creator: Arc<dyn SessionCreator> =
            Arc::new(DefaultSessionCreator::new(logic.clone()));
        let firewall_strategy: Arc<dyn FirewallStrategy> =
            Arc::new(DefaultFirewallStrategy::new(logic));
        Self {
            login_handler: login_handler.clone(),
            logout_handler: logout_handler.clone(),
            permission_handler: permission_handler.clone(),
            token_generator: token_generator.clone(),
            session_creator: session_creator.clone(),
            firewall_strategy: firewall_strategy.clone(),
            default_login_handler: login_handler,
            default_logout_handler: logout_handler,
            default_permission_handler: permission_handler,
            default_token_generator: token_generator,
            default_session_creator: session_creator,
            default_firewall_strategy: firewall_strategy,
        }
    }

    // ------------------------------------------------------------------
    // LoginHandler: register / get / remove
    // ------------------------------------------------------------------

    /// 替换登录策略。
    pub fn register_login_handler(&mut self, handler: Arc<dyn LoginHandler>) {
        self.login_handler = handler;
    }

    /// 获取当前登录策略引用。
    pub fn login_handler(&self) -> &Arc<dyn LoginHandler> {
        &self.login_handler
    }

    /// 恢复默认登录策略。
    pub fn remove_login_handler(&mut self) {
        self.login_handler = self.default_login_handler.clone();
    }

    // ------------------------------------------------------------------
    // LogoutHandler: register / get / remove
    // ------------------------------------------------------------------

    /// 替换登出策略。
    pub fn register_logout_handler(&mut self, handler: Arc<dyn LogoutHandler>) {
        self.logout_handler = handler;
    }

    /// 获取当前登出策略引用。
    pub fn logout_handler(&self) -> &Arc<dyn LogoutHandler> {
        &self.logout_handler
    }

    /// 恢复默认登出策略。
    pub fn remove_logout_handler(&mut self) {
        self.logout_handler = self.default_logout_handler.clone();
    }

    // ------------------------------------------------------------------
    // PermissionHandler: register / get / remove
    // ------------------------------------------------------------------

    /// 替换权限校验策略。
    pub fn register_permission_handler(&mut self, handler: Arc<dyn PermissionHandler>) {
        self.permission_handler = handler;
    }

    /// 获取当前权限校验策略引用。
    pub fn permission_handler(&self) -> &Arc<dyn PermissionHandler> {
        &self.permission_handler
    }

    /// 恢复默认权限校验策略。
    pub fn remove_permission_handler(&mut self) {
        self.permission_handler = self.default_permission_handler.clone();
    }

    // ------------------------------------------------------------------
    // TokenGenerator: register / get / remove
    // ------------------------------------------------------------------

    /// 替换 token 生成策略。
    pub fn register_token_generator(&mut self, generator: Arc<dyn TokenGenerator>) {
        self.token_generator = generator;
    }

    /// 获取当前 token 生成策略引用。
    pub fn token_generator(&self) -> &Arc<dyn TokenGenerator> {
        &self.token_generator
    }

    /// 恢复默认 token 生成策略。
    pub fn remove_token_generator(&mut self) {
        self.token_generator = self.default_token_generator.clone();
    }

    // ------------------------------------------------------------------
    // SessionCreator: register / get / remove
    // ------------------------------------------------------------------

    /// 替换会话创建策略。
    pub fn register_session_creator(&mut self, creator: Arc<dyn SessionCreator>) {
        self.session_creator = creator;
    }

    /// 获取当前会话创建策略引用。
    pub fn session_creator(&self) -> &Arc<dyn SessionCreator> {
        &self.session_creator
    }

    /// 恢复默认会话创建策略。
    pub fn remove_session_creator(&mut self) {
        self.session_creator = self.default_session_creator.clone();
    }

    // ------------------------------------------------------------------
    // FirewallStrategy: register / get / remove
    // ------------------------------------------------------------------

    /// 替换防火墙策略。
    pub fn register_firewall_strategy(&mut self, strategy: Arc<dyn FirewallStrategy>) {
        self.firewall_strategy = strategy;
    }

    /// 获取当前防火墙策略引用。
    pub fn firewall_strategy(&self) -> &Arc<dyn FirewallStrategy> {
        &self.firewall_strategy
    }

    /// 恢复默认防火墙策略。
    pub fn remove_firewall_strategy(&mut self) {
        self.firewall_strategy = self.default_firewall_strategy.clone();
    }
}

// ============================================================================
// 测试（依据 spec strategy-registry R-001 ~ R-004）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BulwarkConfig;
    use crate::dao::BulwarkDao;
    use crate::error::BulwarkError;
    use crate::session::BulwarkSession;
    use crate::stp::{BulwarkInterface, BulwarkLogicDefault};
    use crate::strategy::BulwarkFirewallStrategyDefault;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    // ------------------------------------------------------------------------
    // MockDao + MockInterface + 辅助函数（复用 manager 测试模式）
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

    struct MockInterface {
        permissions: HashMap<i64, Vec<String>>,
        roles: HashMap<i64, Vec<String>>,
    }

    impl MockInterface {
        fn new() -> Self {
            Self {
                permissions: HashMap::new(),
                roles: HashMap::new(),
            }
        }
    }

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(self.permissions.get(&login_id).cloned().unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(self.roles.get(&login_id).cloned().unwrap_or_default())
        }
    }

    /// 构造测试用 `Arc<dyn BulwarkLogic>`。
    fn make_logic() -> Arc<dyn BulwarkLogic> {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(BulwarkConfig::default_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        let timeout = u64::try_from(config.timeout).unwrap_or(3600);
        let session = Arc::new(BulwarkSession::new(dao, timeout, timeout));
        let firewall: Arc<dyn crate::strategy::BulwarkFirewallStrategy> =
            Arc::new(BulwarkFirewallStrategyDefault::new(interface));
        Arc::new(BulwarkLogicDefault::new(session, config, firewall))
    }

    // ========================================================================
    // R-strategy-registry-001: 6 个策略 trait 可被实现
    // ========================================================================

    /// 验证 `LoginHandler` trait 可被自定义实现。
    #[tokio::test]
    async fn login_handler_trait_can_be_implemented() {
        struct MyLoginHandler;
        #[async_trait]
        impl LoginHandler for MyLoginHandler {
            async fn handle_login(&self, login_id: i64) -> BulwarkResult<String> {
                Ok(format!("token-{}", login_id))
            }
        }
        let handler = MyLoginHandler;
        assert_eq!(handler.handle_login(1001).await.unwrap(), "token-1001");
    }

    /// 验证 `LogoutHandler` trait 可被自定义实现。
    #[tokio::test]
    async fn logout_handler_trait_can_be_implemented() {
        struct MyLogoutHandler;
        #[async_trait]
        impl LogoutHandler for MyLogoutHandler {
            async fn handle_logout(&self) -> BulwarkResult<()> {
                Ok(())
            }
            async fn handle_logout_by_login_id(&self, _login_id: i64) -> BulwarkResult<()> {
                Ok(())
            }
        }
        let handler = MyLogoutHandler;
        assert!(handler.handle_logout().await.is_ok());
        assert!(handler.handle_logout_by_login_id(1001).await.is_ok());
    }

    /// 验证 `PermissionHandler` trait 可被自定义实现。
    #[tokio::test]
    async fn permission_handler_trait_can_be_implemented() {
        struct MyPermissionHandler;
        #[async_trait]
        impl PermissionHandler for MyPermissionHandler {
            async fn handle_check_permission(&self, _permission: &str) -> BulwarkResult<()> {
                Ok(())
            }
            async fn handle_check_role(&self, _role: &str) -> BulwarkResult<()> {
                Ok(())
            }
        }
        let handler = MyPermissionHandler;
        assert!(handler.handle_check_permission("user:read").await.is_ok());
        assert!(handler.handle_check_role("admin").await.is_ok());
    }

    /// 验证 `TokenGenerator` trait 可被自定义实现。
    #[tokio::test]
    async fn token_generator_trait_can_be_implemented() {
        struct MyTokenGenerator;
        #[async_trait]
        impl TokenGenerator for MyTokenGenerator {
            async fn generate_token(&self, login_id: i64) -> BulwarkResult<String> {
                Ok(format!("gen-{}", login_id))
            }
            async fn refresh_token(&self, token: &str) -> BulwarkResult<String> {
                Ok(format!("refreshed-{}", token))
            }
        }
        let gen = MyTokenGenerator;
        assert_eq!(gen.generate_token(1001).await.unwrap(), "gen-1001");
        assert_eq!(gen.refresh_token("old").await.unwrap(), "refreshed-old");
    }

    /// 验证 `SessionCreator` trait 可被自定义实现。
    #[tokio::test]
    async fn session_creator_trait_can_be_implemented() {
        struct MySessionCreator;
        #[async_trait]
        impl SessionCreator for MySessionCreator {
            async fn create_session(&self, _login_id: i64, _token: &str) -> BulwarkResult<()> {
                Ok(())
            }
            async fn check_login(&self) -> BulwarkResult<bool> {
                Ok(true)
            }
        }
        let creator = MySessionCreator;
        assert!(creator.create_session(1001, "tok").await.is_ok());
        assert!(creator.check_login().await.unwrap());
    }

    /// 验证 `FirewallStrategy` trait 可被自定义实现。
    #[tokio::test]
    async fn firewall_strategy_trait_can_be_implemented() {
        struct MyFirewallStrategy;
        #[async_trait]
        impl FirewallStrategy for MyFirewallStrategy {
            async fn check_login_hooks(
                &self,
                _login_id: i64,
                _ctx: &LoginContext,
            ) -> BulwarkResult<()> {
                Ok(())
            }
        }
        let fw = MyFirewallStrategy;
        let ctx = LoginContext::new(1001);
        assert!(fw.check_login_hooks(1001, &ctx).await.is_ok());
    }

    // ========================================================================
    // R-strategy-registry-002: Strategy 注册表
    // ========================================================================

    /// 验证 `Strategy::new(logic)` 构造成功，6 个策略均为默认实现。
    #[tokio::test]
    async fn strategy_new_initializes_with_logic() {
        let logic = make_logic();
        let strategy = Strategy::new(logic);
        // 6 个 getter 均返回非空 Arc
        let _ = strategy.login_handler();
        let _ = strategy.logout_handler();
        let _ = strategy.permission_handler();
        let _ = strategy.token_generator();
        let _ = strategy.session_creator();
        let _ = strategy.firewall_strategy();
    }

    /// 验证默认登录策略委托 `BulwarkLogic::login` 可正常生成 token。
    #[tokio::test]
    #[serial]
    async fn default_login_handler_delegates_to_logic() {
        let logic = make_logic();
        let strategy = Strategy::new(logic);
        let token = strategy.login_handler().handle_login(1001).await.unwrap();
        assert!(
            !token.is_empty(),
            "默认登录策略应委托 logic.login 生成 token"
        );
    }

    /// 验证 `register_login_handler` 替换登录策略。
    #[tokio::test]
    async fn strategy_register_replaces_login_handler() {
        let logic = make_logic();
        let mut strategy = Strategy::new(logic);

        struct CustomLoginHandler;
        #[async_trait]
        impl LoginHandler for CustomLoginHandler {
            async fn handle_login(&self, login_id: i64) -> BulwarkResult<String> {
                Ok(format!("custom-{}", login_id))
            }
        }

        strategy.register_login_handler(Arc::new(CustomLoginHandler));
        let token = strategy.login_handler().handle_login(1001).await.unwrap();
        assert_eq!(token, "custom-1001", "register 后应使用自定义策略");
    }

    /// 验证 `login_handler()` 返回当前策略引用。
    #[tokio::test]
    async fn strategy_get_returns_current_handler() {
        let logic = make_logic();
        let mut strategy = Strategy::new(logic);

        struct TrackingLoginHandler {
            id: i32,
        }
        #[async_trait]
        impl LoginHandler for TrackingLoginHandler {
            async fn handle_login(&self, login_id: i64) -> BulwarkResult<String> {
                Ok(format!("{}-{}", self.id, login_id))
            }
        }

        // 默认策略
        let default_token = strategy.login_handler().handle_login(1).await.unwrap();
        assert!(
            !default_token.starts_with("42-"),
            "默认策略不应是 TrackingLoginHandler"
        );

        // 注册自定义策略
        strategy.register_login_handler(Arc::new(TrackingLoginHandler { id: 42 }));
        let custom_token = strategy.login_handler().handle_login(1).await.unwrap();
        assert_eq!(custom_token, "42-1", "get 应返回当前注册的策略");
    }

    /// 验证 `remove_login_handler` 恢复默认策略。
    #[tokio::test]
    async fn strategy_remove_restores_default_login_handler() {
        let logic = make_logic();
        let mut strategy = Strategy::new(logic);

        struct CustomLoginHandler;
        #[async_trait]
        impl LoginHandler for CustomLoginHandler {
            async fn handle_login(&self, login_id: i64) -> BulwarkResult<String> {
                Ok(format!("custom-{}", login_id))
            }
        }

        // 注册自定义策略
        strategy.register_login_handler(Arc::new(CustomLoginHandler));
        let custom_token = strategy.login_handler().handle_login(1001).await.unwrap();
        assert_eq!(custom_token, "custom-1001");

        // remove 恢复默认
        strategy.remove_login_handler();
        let restored_token = strategy.login_handler().handle_login(1001).await.unwrap();
        assert_ne!(restored_token, "custom-1001", "remove 后应恢复默认策略");
    }

    /// 验证 6 个策略均有 register/get/remove 方法（批量验证）。
    #[tokio::test]
    async fn strategy_all_six_strategies_have_register_get_remove() {
        let logic = make_logic();
        let mut strategy = Strategy::new(logic);

        // 验证 6 个 getter 均可调用
        let _ = strategy.login_handler();
        let _ = strategy.logout_handler();
        let _ = strategy.permission_handler();
        let _ = strategy.token_generator();
        let _ = strategy.session_creator();
        let _ = strategy.firewall_strategy();

        // 验证 6 个 remove 均可调用（恢复默认，不报错）
        strategy.remove_login_handler();
        strategy.remove_logout_handler();
        strategy.remove_permission_handler();
        strategy.remove_token_generator();
        strategy.remove_session_creator();
        strategy.remove_firewall_strategy();

        // 验证 6 个 register 均可调用（用自定义实现替换再恢复）
        struct CustomLogin;
        #[async_trait]
        impl LoginHandler for CustomLogin {
            async fn handle_login(&self, id: i64) -> BulwarkResult<String> {
                Ok(format!("c-{}", id))
            }
        }
        strategy.register_login_handler(Arc::new(CustomLogin));
        strategy.remove_login_handler();
    }

    // ========================================================================
    // R-strategy-registry-004: 策略可插拔（替换一个不影响其他）
    // ========================================================================

    /// 验证替换 `LoginHandler` 不影响 `LogoutHandler`。
    #[tokio::test]
    async fn strategy_replace_one_does_not_affect_others() {
        let logic = make_logic();
        let mut strategy = Strategy::new(logic);

        struct CustomLoginHandler;
        #[async_trait]
        impl LoginHandler for CustomLoginHandler {
            async fn handle_login(&self, login_id: i64) -> BulwarkResult<String> {
                Ok(format!("custom-{}", login_id))
            }
        }

        // 替换前：克隆 logout_handler 的 Arc 引用
        let original_logout = strategy.logout_handler().clone();

        // 替换 login_handler
        strategy.register_login_handler(Arc::new(CustomLoginHandler));

        // 替换后：logout_handler 的 Arc 应指向同一对象（未被替换）
        assert!(
            Arc::ptr_eq(&original_logout, strategy.logout_handler()),
            "替换 LoginHandler 不应影响 LogoutHandler"
        );

        // login_handler 确实已替换
        let token = strategy.login_handler().handle_login(1001).await.unwrap();
        assert_eq!(token, "custom-1001");
    }

    /// 验证替换后旧策略被 drop（无内存泄漏）。
    ///
    /// 使用 `Arc::strong_count` 验证：注册新策略后，旧策略的引用计数降为 0
    /// （前提：旧策略仅被 Strategy 持有，未被外部引用）。
    #[tokio::test]
    async fn strategy_replace_drops_old_handler() {
        let logic = make_logic();
        let mut strategy = Strategy::new(logic);

        struct CustomLoginHandler;
        #[async_trait]
        impl LoginHandler for CustomLoginHandler {
            async fn handle_login(&self, login_id: i64) -> BulwarkResult<String> {
                Ok(format!("v1-{}", login_id))
            }
        }

        // 注册第一个自定义策略
        let handler_v1 = Arc::new(CustomLoginHandler);
        let weak_v1 = Arc::downgrade(&handler_v1);
        strategy.register_login_handler(handler_v1);

        // 注册第二个自定义策略，替换第一个
        struct AnotherLoginHandler;
        #[async_trait]
        impl LoginHandler for AnotherLoginHandler {
            async fn handle_login(&self, login_id: i64) -> BulwarkResult<String> {
                Ok(format!("v2-{}", login_id))
            }
        }
        strategy.register_login_handler(Arc::new(AnotherLoginHandler));

        // 第一个策略应已被 drop（weak 引用失效）
        assert!(
            weak_v1.upgrade().is_none(),
            "替换后旧策略应被 drop，无内存泄漏"
        );
    }

    /// 验证 `DefaultFirewallStrategy::check_login_hooks` 返回 Ok（no-op）。
    #[tokio::test]
    async fn default_firewall_strategy_is_noop() {
        let logic = make_logic();
        let strategy = Strategy::new(logic);
        let ctx = LoginContext::new(1001);
        let result = strategy
            .firewall_strategy()
            .check_login_hooks(1001, &ctx)
            .await;
        assert!(result.is_ok(), "默认防火墙策略应为 no-op 返回 Ok");
    }

    /// 验证 `DefaultSessionCreator::create_session` 委托 `BulwarkLogic::login_with_token`。
    #[tokio::test]
    #[serial]
    async fn default_session_creator_delegates_to_logic() {
        let logic = make_logic();
        let strategy = Strategy::new(logic);
        // create_session 委托 login_with_token，应成功
        let result = strategy
            .session_creator()
            .create_session(1001, "test-token")
            .await;
        assert!(
            result.is_ok(),
            "默认会话创建策略应委托 logic.login_with_token"
        );
    }

    /// 验证 `DefaultPermissionHandler` 委托 `BulwarkLogic::check_permission`。
    #[tokio::test]
    #[serial]
    async fn default_permission_handler_delegates_to_logic() {
        let logic = make_logic();
        let strategy = Strategy::new(logic);
        // 未登录时 check_permission 应返回 Err（委托 logic.check_permission）
        let result = strategy
            .permission_handler()
            .handle_check_permission("user:read")
            .await;
        assert!(
            result.is_err(),
            "未登录时默认权限策略应委托 logic.check_permission 返回 Err"
        );
    }

    // ========================================================================
    // 覆盖率补充：Default*Handler 各方法委托 logic 的验证
    // ========================================================================

    /// 验证 `DefaultLogoutHandler::handle_logout` 委托 `logic.logout`。
    ///
    /// 未登录时 logout 返回 Ok（幂等），验证委托路径被覆盖。
    #[tokio::test]
    #[serial]
    async fn default_logout_handler_handle_logout_delegates() {
        let logic = make_logic();
        let strategy = Strategy::new(logic);
        // 未登录时 logout 应返回 Ok（幂等语义）
        let result = strategy.logout_handler().handle_logout().await;
        assert!(
            result.is_ok(),
            "未登录时 handle_logout 应幂等返回 Ok，实际: {:?}",
            result
        );
    }

    /// 验证 `DefaultLogoutHandler::handle_logout_by_login_id` 委托 `logic.logout_by_login_id`。
    #[tokio::test]
    #[serial]
    async fn default_logout_handler_handle_logout_by_login_id_delegates() {
        let logic = make_logic();
        let strategy = Strategy::new(logic);
        // 注销不存在的 login_id 应返回 Ok（幂等语义）
        let result = strategy
            .logout_handler()
            .handle_logout_by_login_id(99999)
            .await;
        assert!(
            result.is_ok(),
            "handle_logout_by_login_id 不存在的 login_id 应幂等返回 Ok，实际: {:?}",
            result
        );
    }

    /// 验证 `DefaultPermissionHandler::handle_check_role` 委托 `logic.check_role`。
    ///
    /// 未登录时 check_role 返回 Err（NotLogin 或 NotRole），验证委托路径被覆盖。
    #[tokio::test]
    #[serial]
    async fn default_permission_handler_handle_check_role_delegates() {
        let logic = make_logic();
        let strategy = Strategy::new(logic);
        let result = strategy
            .permission_handler()
            .handle_check_role("admin")
            .await;
        assert!(
            result.is_err(),
            "未登录时 handle_check_role 应委托 logic.check_role 返回 Err"
        );
    }

    /// 验证 `DefaultTokenGenerator::generate_token` 委托 `logic.login`。
    #[tokio::test]
    #[serial]
    async fn default_token_generator_generate_token_delegates() {
        let logic = make_logic();
        let strategy = Strategy::new(logic);
        let result = strategy.token_generator().generate_token(1001).await;
        assert!(
            result.is_ok(),
            "generate_token 应委托 logic.login 返回 token，实际: {:?}",
            result
        );
        // 验证返回的 token 非空
        let token = result.unwrap();
        assert!(!token.is_empty(), "生成的 token 不应为空");
    }

    /// 验证 `DefaultTokenGenerator::refresh_token` 委托 `logic.refresh_token`。
    ///
    /// 使用一个无效的 token 调用 refresh_token，应返回 Err（InvalidToken）。
    #[tokio::test]
    #[serial]
    async fn default_token_generator_refresh_token_delegates() {
        let logic = make_logic();
        let strategy = Strategy::new(logic);
        let result = strategy
            .token_generator()
            .refresh_token("invalid-token-for-refresh")
            .await;
        assert!(
            result.is_err(),
            "refresh_token 无效 token 应委托 logic.refresh_token 返回 Err"
        );
    }

    /// 验证 `DefaultSessionCreator::check_login` 委托 `logic.check_login`。
    ///
    /// 未登录时 check_login 的返回取决于 `throw_on_not_login` 配置：
    /// - `true`（默认）：返回 `Err(NotLogin)`
    /// - `false`：返回 `Ok(false)`
    /// 两种情况都验证了委托路径被覆盖。
    #[tokio::test]
    #[serial]
    async fn default_session_creator_check_login_delegates() {
        let logic = make_logic();
        let strategy = Strategy::new(logic);
        let result = strategy.session_creator().check_login().await;
        // 默认 throw_on_not_login=true，未登录应返回 Err(NotLogin)
        assert!(
            result.is_err(),
            "默认 throw_on_not_login=true，未登录时应返回 Err，实际: {:?}",
            result
        );
    }
}
