//! 管理器模块，提供全局管理器单例与编译期工厂注册。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaManager`，
//! 统筹 DAO、配置、策略等组件的全局生命周期。
//!
//! ## 设计（依据 design.md Decision 8）
//!
//! - `BulwarkManager` 持有 `Arc<dyn BulwarkLogic>` 全局单例（基于 `parking_lot::RwLock` 支持重复 init）
//! - `BulwarkLogicFactory` trait 通过 `inventory::submit!` 编译期注册
//! - 业务方调用 `BulwarkManager::init(dao, config, interface)` 注入依赖
//! - `BulwarkUtil::login(id)` 等静态方法委托到 `BULWARK_MANAGER` 单例
//!
//! ## 初始化流程
//!
//! ```ignore
//! use std::sync::Arc;
//! use bulwark::prelude::*;
//!
//! // 1. 准备依赖
//! let dao: Arc<dyn BulwarkDao> = /* oxcache 或 dbnexus 实现 */;
//! let config = Arc::new(BulwarkConfig::default_config());
//! let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface);
//!
//! // 2. 初始化全局管理器
//! BulwarkManager::init(dao, config, interface).unwrap();
//!
//! // 3. 使用静态 API（task_local 上下文由 middleware 设置）
//! let token = BulwarkUtil::login(1001).await.unwrap();
//! ```

use crate::config::BulwarkConfig;
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::session::BulwarkSession;
use crate::stp::{BulwarkInterface, BulwarkLogic, BulwarkLogicDefault};
use crate::strategy::{BulwarkFirewallStrategy, BulwarkFirewallStrategyDefault};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::sync::Arc;

/// 全局管理器，统筹 `BulwarkLogic` 的生命周期。
///
/// [借鉴 Sa-Token] 对应 `SaManager`，
/// 持有全局 `Arc<dyn BulwarkLogic>` 引用，提供静态方法入口。
///
/// # 初始化
///
/// 业务方启动时调用 `BulwarkManager::init(dao, config, interface)` 注入依赖。
/// 未初始化时调用 `BulwarkUtil::login(id)` 等返回 `BulwarkError::Session`。
pub struct BulwarkManager {
    /// 全局 BulwarkLogic 引用（RwLock 支持测试时重复 init 与 reset）。
    logic: RwLock<Option<Arc<dyn BulwarkLogic>>>,
}

impl BulwarkManager {
    /// 创建空的管理器实例（仅用于 BULWARK_MANAGER 单例初始化）。
    fn new() -> Self {
        Self {
            logic: RwLock::new(None),
        }
    }

    /// 初始化全局管理器：注入 dao/config/interface 依赖，构造默认 `BulwarkLogic` 实例。
    ///
    /// # 参数
    /// - `dao`: DAO 引用（oxcache / dbnexus）
    /// - `config`: 全局配置
    /// - `interface`: 权限数据回调（由业务方实现）
    ///
    /// # 行为
    /// 1. 校验配置合法性
    /// 2. 构造 `BulwarkSession::new(dao, timeout, active_timeout)`
    /// 3. 构造 `BulwarkFirewallStrategyDefault::new(interface)`
    /// 4. 通过 `inventory::iter::<BulwarkLogicFactoryEntry>()` 找到注册的 factory
    /// 5. 调用 `factory.build(session, config, firewall)` 生成 `Arc<dyn BulwarkLogic>`
    /// 6. 若无 factory 注册，使用默认 `BulwarkLogicFactoryDefault` 构造 `BulwarkLogicDefault`
    /// 7. 覆盖式更新全局单例（允许重复 init，便于测试）
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 配置非法（timeout ≤ 0 等）：`BulwarkError::Config`
    /// - timeout/active_timeout 溢出 u64：`BulwarkError::Config`
    /// - factory 构造失败：透传 factory 返回的 `BulwarkError`
    pub fn init(
        dao: Arc<dyn BulwarkDao>,
        config: Arc<BulwarkConfig>,
        interface: Arc<dyn BulwarkInterface>,
    ) -> BulwarkResult<()> {
        Self::init_with_factory_selector(dao, config, interface, default_factory_selector)
    }

    /// 内部初始化方法，允许注入自定义 factory selector（便于测试 mock factory）。
    fn init_with_factory_selector(
        dao: Arc<dyn BulwarkDao>,
        config: Arc<BulwarkConfig>,
        interface: Arc<dyn BulwarkInterface>,
        factory_selector: fn() -> Option<&'static BulwarkLogicFactoryEntry>,
    ) -> BulwarkResult<()> {
        // 1. 校验配置
        config.validate()?;

        // 2. 构造 session（处理 active_timeout = -1 的兜底语义）
        let timeout = u64::try_from(config.timeout)
            .map_err(|_| BulwarkError::Config(format!("timeout 溢出 u64: {}", config.timeout)))?;
        let active_timeout = if config.active_timeout < 0 {
            // -1 表示不启用 activity 超时，使用 timeout 兜底（保留 Sa-Token 语义）
            timeout
        } else {
            u64::try_from(config.active_timeout).map_err(|_| {
                BulwarkError::Config(format!(
                    "active_timeout 溢出 u64: {}",
                    config.active_timeout
                ))
            })?
        };
        let session = Arc::new(BulwarkSession::new(dao, timeout, active_timeout));

        // 3. 构造 firewall
        let firewall: Arc<dyn BulwarkFirewallStrategy> =
            Arc::new(BulwarkFirewallStrategyDefault::new(interface));

        // 4. 通过 factory 构造 logic
        let logic: Arc<dyn BulwarkLogic> = match factory_selector() {
            Some(entry) => (entry.factory)(session, config, firewall)?,
            None => Arc::new(BulwarkLogicDefault::new(session, config, firewall)),
        };

        // 5. 覆盖式更新全局单例（允许重复 init，便于测试）
        *BULWARK_MANAGER.logic.write() = Some(logic);

        Ok(())
    }

    /// 获取全局 `BulwarkLogic` 引用。
    ///
    /// # 返回
    /// 已初始化时返回 `Arc<dyn BulwarkLogic>`。
    ///
    /// # 错误
    /// - 若未初始化，返回 `BulwarkError::Session("BulwarkManager 未初始化")`。
    pub fn logic() -> BulwarkResult<Arc<dyn BulwarkLogic>> {
        BULWARK_MANAGER
            .logic
            .read()
            .clone()
            .ok_or_else(|| BulwarkError::Session("BulwarkManager 未初始化".to_string()))
    }

    /// 检查管理器是否已初始化。
    ///
    /// # 返回
    /// - `true`: 已调用 `init` 且全局单例持有 `BulwarkLogic`。
    /// - `false`: 未初始化或已 `reset_for_test`。
    pub fn is_initialized() -> bool {
        BULWARK_MANAGER.logic.read().is_some()
    }

    /// 重置管理器（仅供测试用，业务代码不应调用）。
    ///
    /// 清空全局 `BulwarkLogic` 引用，使后续 `BulwarkUtil::login(id)` 等返回未初始化错误。
    #[cfg(test)]
    pub fn reset_for_test() {
        *BULWARK_MANAGER.logic.write() = None;
    }
}

/// 默认 factory selector：从 inventory 中找到第一个注册的 `BulwarkLogicFactoryEntry`。
///
/// 若无 entry 注册，返回 `None`，由 `init()` 兜底使用 `BulwarkLogicDefault`。
fn default_factory_selector() -> Option<&'static BulwarkLogicFactoryEntry> {
    use std::iter::Iterator;
    inventory::iter::<BulwarkLogicFactoryEntry>().next()
}

/// 全局管理器单例。
///
/// 通过 `once_cell::sync::Lazy` 实现懒加载，
/// 首次访问时调用 `BulwarkManager::new()`。
pub static BULWARK_MANAGER: Lazy<BulwarkManager> = Lazy::new(BulwarkManager::new);

// ============================================================================
// BulwarkLogicFactory：编译期注册的工厂 trait（依据 design.md Decision 8）
// ============================================================================

/// 工厂函数签名：接收 session/config/firewall，返回 `Arc<dyn BulwarkLogic>`。
///
/// 使用裸函数指针（`Fn` trait object 的简化形式）以便 `inventory::submit!` 静态注册。
pub type BulwarkLogicFactoryFn = fn(
    session: Arc<BulwarkSession>,
    config: Arc<BulwarkConfig>,
    firewall: Arc<dyn BulwarkFirewallStrategy>,
) -> BulwarkResult<Arc<dyn BulwarkLogic>>;

/// 工厂 entry：通过 `inventory::submit!` 注册的具体工厂实例。
///
/// # 注册方式
///
/// ```ignore
/// inventory::submit! {
///     BulwarkLogicFactoryEntry {
///         name: "default",
///         factory: bulwark_logic_factory_default,
///     }
/// }
/// ```
pub struct BulwarkLogicFactoryEntry {
    /// 工厂名称（用于诊断与优先级排序，0.1.0 不强制唯一）。
    pub name: &'static str,
    /// 工厂函数指针。
    pub factory: BulwarkLogicFactoryFn,
}

inventory::collect!(BulwarkLogicFactoryEntry);

/// 默认工厂函数：构造 `BulwarkLogicDefault`。
///
/// 此函数通过 `inventory::submit!` 在编译期注册到全局工厂列表，
/// `BulwarkManager::init()` 会找到它并调用以构造 `Arc<dyn BulwarkLogic>`。
///
/// # 参数
/// - `session`: 会话管理器。
/// - `config`: 全局配置。
/// - `firewall`: 权限策略。
///
/// # 返回
/// 新建的 `Arc<dyn BulwarkLogic>`（实际类型为 `BulwarkLogicDefault`）。
///
/// # 错误
/// 当前实现始终返回 `Ok`，保留 `BulwarkResult` 以匹配工厂签名便于扩展。
pub fn bulwark_logic_factory_default(
    session: Arc<BulwarkSession>,
    config: Arc<BulwarkConfig>,
    firewall: Arc<dyn BulwarkFirewallStrategy>,
) -> BulwarkResult<Arc<dyn BulwarkLogic>> {
    Ok(Arc::new(BulwarkLogicDefault::new(
        session, config, firewall,
    )))
}

inventory::submit! {
    BulwarkLogicFactoryEntry {
        name: "default",
        factory: bulwark_logic_factory_default,
    }
}

// ============================================================================
// 测试（依据 spec core-auth-api 所有 scenario + manager 行为契约）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::BulwarkDao;
    use crate::stp::BulwarkUtil;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    // ------------------------------------------------------------------------
    // MockDao：复用 dao/session/stp 测试的 HashMap + Instant 模拟 TTL
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
    // MockInterface：权限/角色数据回调
    // ------------------------------------------------------------------------

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

        fn with_permission(mut self, login_id: i64, perms: &[&str]) -> Self {
            self.permissions
                .insert(login_id, perms.iter().map(|s| s.to_string()).collect());
            self
        }

        fn with_role(mut self, login_id: i64, roles: &[&str]) -> Self {
            self.roles
                .insert(login_id, roles.iter().map(|s| s.to_string()).collect());
            self
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

    // ------------------------------------------------------------------------
    // 辅助函数
    // ------------------------------------------------------------------------

    /// 创建默认测试配置（timeout=3600，throw_on_not_login=false 便于断言）。
    fn make_config() -> BulwarkConfig {
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = false;
        config
    }

    /// 在 task_local 上下文中执行 future（设置当前 token）。
    async fn with_token<R>(token: String, f: impl std::future::Future<Output = R>) -> R {
        crate::stp::with_current_token(token, f).await
    }

    // ------------------------------------------------------------------------
    // 未初始化场景测试（spec Scenario: 未初始化抛错）
    // ------------------------------------------------------------------------

    /// 验证未初始化时 `BulwarkManager::logic()` 返回 Session 错误。
    #[test]
    #[serial]
    fn logic_returns_error_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkManager::logic();
        assert!(result.is_err());
        match result {
            Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化") => {},
            other => panic!(
                "应返回 'BulwarkManager 未初始化'，实际: {:?}",
                other.map(|_| ())
            ),
        }
    }

    /// 验证未初始化时 `BulwarkManager::is_initialized()` 返回 false。
    #[test]
    #[serial]
    fn is_initialized_returns_false_when_not_initialized() {
        BulwarkManager::reset_for_test();
        assert!(!BulwarkManager::is_initialized());
    }

    // ------------------------------------------------------------------------
    // 初始化场景测试（spec Scenario: init 后即可用）
    // ------------------------------------------------------------------------

    /// 验证 init 后 `is_initialized()` 返回 true。
    #[tokio::test]
    #[serial]
    async fn init_sets_initialized_flag() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        let result = BulwarkManager::init(dao, config, interface);
        assert!(result.is_ok(), "init 应成功: {:?}", result.map(|_| ()));
        assert!(BulwarkManager::is_initialized());
        BulwarkManager::reset_for_test();
    }

    /// 验证 init 校验配置：timeout=0 抛 Config 错误。
    #[tokio::test]
    #[serial]
    async fn init_rejects_invalid_config() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 0; // 非法
        let config = Arc::new(config);
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        let result = BulwarkManager::init(dao, config, interface);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BulwarkError::Config(ref msg) if msg.contains("timeout must be positive")
        ));
        assert!(!BulwarkManager::is_initialized());
        BulwarkManager::reset_for_test();
    }

    /// 验证 init 处理 active_timeout=-1 的兜底语义（使用 timeout 兜底）。
    #[tokio::test]
    #[serial]
    async fn init_handles_negative_active_timeout() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config()); // active_timeout = -1
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        let result = BulwarkManager::init(dao, config, interface);
        assert!(result.is_ok(), "active_timeout=-1 应使用 timeout 兜底");
        assert!(BulwarkManager::is_initialized());
        BulwarkManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // 端到端流程测试（spec Scenario: login → check_login → check_permission → logout）
    // ------------------------------------------------------------------------

    /// 验证完整端到端流程：init → login → check_login → logout → check_login 失败。
    #[tokio::test]
    #[serial]
    async fn end_to_end_login_check_logout() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao, config, interface).unwrap();
        assert!(BulwarkManager::is_initialized());

        // login
        let token = BulwarkUtil::login(1001).await.unwrap();
        assert!(!token.is_empty());

        // check_login
        let is_logged_in = with_token(token.clone(), async { BulwarkUtil::check_login().await })
            .await
            .unwrap();
        assert!(is_logged_in, "登录后 check_login 应返回 true");

        // logout
        let logout_result = with_token(token.clone(), async { BulwarkUtil::logout().await }).await;
        assert!(
            logout_result.is_ok(),
            "logout 应成功: {:?}",
            logout_result.map(|_| ())
        );

        // logout 后 check_login 应返回 false
        let is_still_logged_in =
            with_token(token.clone(), async { BulwarkUtil::check_login().await })
                .await
                .unwrap();
        assert!(!is_still_logged_in, "logout 后 check_login 应返回 false");

        BulwarkManager::reset_for_test();
    }

    /// 验证权限校验端到端流程：login → check_permission 持有/未持有。
    #[tokio::test]
    #[serial]
    async fn end_to_end_check_permission() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> =
            Arc::new(MockInterface::new().with_permission(1001, &["user:read", "user:write"]));
        BulwarkManager::init(dao, config, interface).unwrap();

        let token = BulwarkUtil::login(1001).await.unwrap();

        // 持有权限
        let check_result = with_token(token.clone(), async {
            BulwarkUtil::check_permission("user:read").await
        })
        .await;
        assert!(
            check_result.is_ok(),
            "持有权限应通过: {:?}",
            check_result.map(|_| ())
        );

        // 未持有权限
        let check_result = with_token(token.clone(), async {
            BulwarkUtil::check_permission("user:delete").await
        })
        .await;
        assert!(check_result.is_err());
        assert!(matches!(
            check_result.unwrap_err(),
            BulwarkError::NotPermission(ref p) if p == "user:delete"
        ));

        BulwarkManager::reset_for_test();
    }

    /// 验证角色校验端到端流程：login → check_role 持有/未持有。
    #[tokio::test]
    #[serial]
    async fn end_to_end_check_role() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> =
            Arc::new(MockInterface::new().with_role(1001, &["admin"]));
        BulwarkManager::init(dao, config, interface).unwrap();

        let token = BulwarkUtil::login(1001).await.unwrap();

        // 持有角色
        let check_result = with_token(token.clone(), async {
            BulwarkUtil::check_role("admin").await
        })
        .await;
        assert!(
            check_result.is_ok(),
            "持有角色应通过: {:?}",
            check_result.map(|_| ())
        );

        // 未持有角色
        let check_result = with_token(token.clone(), async {
            BulwarkUtil::check_role("superadmin").await
        })
        .await;
        assert!(check_result.is_err());
        assert!(matches!(
            check_result.unwrap_err(),
            BulwarkError::NotRole(ref r) if r == "superadmin"
        ));

        BulwarkManager::reset_for_test();
    }

    /// 验证 BulwarkUtil::login 未初始化时抛错。
    #[tokio::test]
    #[serial]
    async fn util_login_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::login(1001).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BulwarkError::Session(ref msg) if msg.contains("未初始化")
        ));
    }

    /// 验证重复 init 覆盖式更新（不抛错）。
    #[tokio::test]
    #[serial]
    async fn init_overwrites_existing() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao.clone(), config.clone(), interface.clone()).unwrap();
        assert!(BulwarkManager::is_initialized());

        // 重复 init 应覆盖式更新，不抛错
        let result = BulwarkManager::init(dao, config, interface);
        assert!(
            result.is_ok(),
            "重复 init 应覆盖式更新: {:?}",
            result.map(|_| ())
        );
        assert!(BulwarkManager::is_initialized());

        BulwarkManager::reset_for_test();
    }

    /// 验证 inventory 已注册 default factory。
    #[test]
    fn default_factory_registered_via_inventory() {
        use std::iter::Iterator;
        let found = inventory::iter::<BulwarkLogicFactoryEntry>()
            .filter(|e| e.name == "default")
            .count();
        assert!(
            found >= 1,
            "应至少注册一个 name='default' 的 factory，实际: {}",
            found
        );
    }

    /// 验证 default factory 构造的 logic 可正常 login。
    #[tokio::test]
    async fn default_factory_builds_working_logic() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());

        let timeout = u64::try_from(config.timeout).unwrap();
        let session = Arc::new(BulwarkSession::new(dao, timeout, timeout));
        let firewall: Arc<dyn BulwarkFirewallStrategy> =
            Arc::new(BulwarkFirewallStrategyDefault::new(interface));

        let logic = bulwark_logic_factory_default(session, config, firewall).unwrap();
        let token = logic.login(1001).await.unwrap();
        assert!(!token.is_empty());
    }

    // ------------------------------------------------------------------------
    // init 配置分支补充测试
    // ------------------------------------------------------------------------

    /// 验证 init 处理 active_timeout > 0 的非负值（else 分支）。
    ///
    /// 覆盖 `init_with_factory_selector` 中 `else { u64::try_from(active_timeout)... }` 分支：
    /// 当 active_timeout >= 0 时，直接转换为 u64，不使用 timeout 兜底。
    #[tokio::test]
    #[serial]
    async fn init_with_positive_active_timeout() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = 1800; // 正值，走 else 分支
        let config = Arc::new(config);
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());

        let result = BulwarkManager::init(dao, config, interface);
        assert!(
            result.is_ok(),
            "active_timeout=1800 应走 else 分支并成功: {:?}",
            result.map(|_| ())
        );
        assert!(BulwarkManager::is_initialized());

        // 验证 login 仍可正常工作
        let token = BulwarkUtil::login(1001).await.unwrap();
        assert!(!token.is_empty());

        BulwarkManager::reset_for_test();
    }

    /// 验证 init 处理 active_timeout = 0 的边界值（else 分支）。
    ///
    /// 覆盖 `init_with_factory_selector` 中 `else` 分支的边界值 0。
    #[tokio::test]
    #[serial]
    async fn init_with_zero_active_timeout() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = 0; // 边界值 0，走 else 分支
        let config = Arc::new(config);
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());

        let result = BulwarkManager::init(dao, config, interface);
        assert!(result.is_ok(), "active_timeout=0 应走 else 分支并成功");
        assert!(BulwarkManager::is_initialized());

        BulwarkManager::reset_for_test();
    }

    /// 验证 init 校验配置：非法 token_style 抛 Config 错误。
    ///
    /// 覆盖 `init_with_factory_selector` 中 `config.validate()?` 的另一种错误分支
    /// （非法 token_style，区别于 timeout 非法）。
    #[tokio::test]
    #[serial]
    async fn init_rejects_invalid_token_style() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.token_style = "unknown_style".to_string(); // 非法
        let config = Arc::new(config);
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());

        let result = BulwarkManager::init(dao, config, interface);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), BulwarkError::Config(ref msg) if msg.contains("unknown token_style")),
            "应返回 'unknown token_style' 错误"
        );
        assert!(!BulwarkManager::is_initialized());

        BulwarkManager::reset_for_test();
    }
}
