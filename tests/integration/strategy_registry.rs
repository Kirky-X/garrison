//! Strategy 注册表集成测试（v0.4.2 新增，依据 spec strategy-registry R-001 ~ R-004）。
//!
//! 验证外部用户视角下：
//! 1. 6 个策略 trait（`LoginHandler` / `LogoutHandler` / `PermissionHandler` /
//!    `TokenGenerator` / `SessionCreator` / `FirewallStrategy`）可被业务方实现
//! 2. `Strategy::new(logic)` 构造后 6 个 getter 返回默认实现
//! 3. `register_*` / `getter` / `remove_*` 三组方法可运行时替换/查询/恢复
//! 4. 替换一个策略不影响其他策略（独立可插拔）
//! 5. `BulwarkManager::strategy()` 全局访问 + `with_strategy()` 整体替换
//! 6. 运行时通过 `strategy().write().register_*()` 替换立即生效
//!
//! 运行：`cargo test --features "cache-memory" --test strategy_registry_integration`

#![cfg(feature = "cache-memory")]

use async_trait::async_trait;
use bulwark::config::BulwarkConfig;
use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use bulwark::error::BulwarkResult;
use bulwark::session::BulwarkSession;
use bulwark::stp::{BulwarkInterface, BulwarkLogicDefault};
use bulwark::strategy::{
    BulwarkPermissionStrategyDefault, FirewallStrategy, LoginHandler, LogoutHandler,
    PermissionHandler, SessionCreator, Strategy, TokenGenerator,
};
use parking_lot::RwLock;
use serial_test::serial;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ============================================================================
// MockInterface：BulwarkPermissionStrategyDefault::new() 必需
// ============================================================================

struct MockInterface;

#[async_trait]
impl BulwarkInterface for MockInterface {
    async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
}

// ============================================================================
// 辅助函数：构造测试用 Arc<BulwarkLogicDefault>
// ============================================================================

async fn make_logic() -> Arc<BulwarkLogicDefault> {
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    let timeout = u64::try_from(config.timeout).unwrap_or(3600);
    let session = Arc::new(BulwarkSession::new(dao, timeout, timeout));
    let firewall = Arc::new(BulwarkPermissionStrategyDefault::new(interface));
    Arc::new(BulwarkLogicDefault::new(session, config, firewall))
}

// ============================================================================
// R-strategy-registry-001: 6 个策略 trait 可被业务方自定义实现
// ============================================================================

/// 验证 `LoginHandler` trait 可被外部实现并调用。
#[tokio::test(flavor = "multi_thread")]
async fn login_handler_can_be_implemented_externally() {
    struct MyLoginHandler;
    #[async_trait]
    impl LoginHandler for MyLoginHandler {
        async fn handle_login(&self, login_id: &str) -> BulwarkResult<String> {
            Ok(format!("token-{}", login_id))
        }
    }
    let handler = MyLoginHandler;
    assert_eq!(handler.handle_login("1001").await.unwrap(), "token-1001");
}

/// 验证 `LogoutHandler` trait 可被外部实现并调用。
#[tokio::test(flavor = "multi_thread")]
async fn logout_handler_can_be_implemented_externally() {
    struct MyLogoutHandler;
    #[async_trait]
    impl LogoutHandler for MyLogoutHandler {
        async fn handle_logout(&self) -> BulwarkResult<()> {
            Ok(())
        }
        async fn handle_logout_by_login_id(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
    }
    let handler = MyLogoutHandler;
    assert!(handler.handle_logout().await.is_ok());
    assert!(handler.handle_logout_by_login_id("1001").await.is_ok());
}

/// 验证 `PermissionHandler` trait 可被外部实现并调用。
#[tokio::test(flavor = "multi_thread")]
async fn permission_handler_can_be_implemented_externally() {
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

/// 验证 `TokenGenerator` trait 可被外部实现并调用。
#[tokio::test(flavor = "multi_thread")]
async fn token_generator_can_be_implemented_externally() {
    struct MyTokenGenerator;
    #[async_trait]
    impl TokenGenerator for MyTokenGenerator {
        async fn generate_token(&self, login_id: &str) -> BulwarkResult<String> {
            Ok(format!("gen-{}", login_id))
        }
        async fn refresh_token(&self, token: &str) -> BulwarkResult<String> {
            Ok(format!("refreshed-{}", token))
        }
    }
    let gen = MyTokenGenerator;
    assert_eq!(gen.generate_token("1001").await.unwrap(), "gen-1001");
    assert_eq!(gen.refresh_token("old").await.unwrap(), "refreshed-old");
}

/// 验证 `SessionCreator` trait 可被外部实现并调用。
#[tokio::test(flavor = "multi_thread")]
async fn session_creator_can_be_implemented_externally() {
    struct MySessionCreator;
    #[async_trait]
    impl SessionCreator for MySessionCreator {
        async fn create_session(&self, _login_id: &str, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> BulwarkResult<bool> {
            Ok(true)
        }
    }
    let creator = MySessionCreator;
    assert!(creator.create_session("1001", "tok").await.is_ok());
    assert!(creator.check_login().await.unwrap());
}

/// 验证 `FirewallStrategy` trait 可被外部实现并调用。
#[tokio::test(flavor = "multi_thread")]
async fn firewall_strategy_can_be_implemented_externally() {
    use bulwark::strategy::FirewallLoginContext;
    struct MyFirewallStrategy;
    #[async_trait]
    impl FirewallStrategy for MyFirewallStrategy {
        async fn check_login_hooks(
            &self,
            _login_id: &str,
            _ctx: &FirewallLoginContext,
        ) -> BulwarkResult<()> {
            Ok(())
        }
    }
    let fw = MyFirewallStrategy;
    let ctx = FirewallLoginContext::new("1001");
    assert!(fw.check_login_hooks("1001", &ctx).await.is_ok());
}

// ============================================================================
// R-strategy-registry-002: Strategy::new + 6 个 getter
// ============================================================================

/// 验证 `Strategy::new(logic)` 构造成功，6 个 getter 均返回非空 Arc。
#[tokio::test(flavor = "multi_thread")]
async fn strategy_new_initializes_all_six_handlers() {
    let logic = make_logic().await;
    let strategy = Strategy::new(logic);
    // 6 个 getter 均可调用且返回非空 Arc（Arc::strong_count >= 1）
    assert!(Arc::strong_count(strategy.login_handler()) >= 1);
    assert!(Arc::strong_count(strategy.logout_handler()) >= 1);
    assert!(Arc::strong_count(strategy.permission_handler()) >= 1);
    assert!(Arc::strong_count(strategy.token_generator()) >= 1);
    assert!(Arc::strong_count(strategy.session_creator()) >= 1);
    assert!(Arc::strong_count(strategy.firewall_strategy()) >= 1);
}

/// 验证默认登录策略委托 `SessionLogic::login` 可生成非空 token。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_login_handler_generates_token_via_logic() {
    let logic = make_logic().await;
    let strategy = Strategy::new(logic);
    let token = strategy.login_handler().handle_login("1001").await.unwrap();
    assert!(
        !token.is_empty(),
        "默认登录策略应委托 logic.login 生成 token"
    );
}

/// 验证默认防火墙策略为 no-op（返回 Ok）。
#[tokio::test(flavor = "multi_thread")]
async fn default_firewall_strategy_is_noop() {
    use bulwark::strategy::FirewallLoginContext;
    let logic = make_logic().await;
    let strategy = Strategy::new(logic);
    let ctx = FirewallLoginContext::new("1001");
    let result = strategy
        .firewall_strategy()
        .check_login_hooks("1001", &ctx)
        .await;
    assert!(result.is_ok(), "默认防火墙策略应为 no-op 返回 Ok");
}

// ============================================================================
// R-strategy-registry-003: register / get / remove 三组方法
// ============================================================================

/// 验证 `register_login_handler` 替换登录策略，`remove_login_handler` 恢复默认。
#[tokio::test(flavor = "multi_thread")]
async fn register_get_remove_login_handler_roundtrip() {
    struct CustomLoginHandler {
        suffix: &'static str,
    }
    #[async_trait]
    impl LoginHandler for CustomLoginHandler {
        async fn handle_login(&self, login_id: &str) -> BulwarkResult<String> {
            Ok(format!("custom-{}-{}", self.suffix, login_id))
        }
    }

    let logic = make_logic().await;
    let mut strategy = Strategy::new(logic);

    // 注册自定义策略
    strategy.register_login_handler(Arc::new(CustomLoginHandler { suffix: "v1" }));
    let token = strategy.login_handler().handle_login("1001").await.unwrap();
    assert_eq!(token, "custom-v1-1001", "register 后应使用自定义策略");

    // remove 恢复默认
    strategy.remove_login_handler();
    let restored = strategy.login_handler().handle_login("1001").await.unwrap();
    assert_ne!(
        restored, "custom-v1-1001",
        "remove 后应恢复默认策略（非 custom-v1-1001）"
    );
    assert!(!restored.is_empty(), "默认策略应生成非空 token");
}

/// 验证 6 个策略均有 register/get/remove 方法（批量验证）。
#[tokio::test(flavor = "multi_thread")]
async fn all_six_strategies_support_register_get_remove() {
    let logic = make_logic().await;
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

    // 验证 6 个 register 均可调用（用自定义实现替换）
    struct CustomLogin;
    #[async_trait]
    impl LoginHandler for CustomLogin {
        async fn handle_login(&self, id: &str) -> BulwarkResult<String> {
            Ok(format!("c-{}", id))
        }
    }
    struct CustomLogout;
    #[async_trait]
    impl LogoutHandler for CustomLogout {
        async fn handle_logout(&self) -> BulwarkResult<()> {
            Ok(())
        }
        async fn handle_logout_by_login_id(&self, _: &str) -> BulwarkResult<()> {
            Ok(())
        }
    }
    struct CustomPermission;
    #[async_trait]
    impl PermissionHandler for CustomPermission {
        async fn handle_check_permission(&self, _: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn handle_check_role(&self, _: &str) -> BulwarkResult<()> {
            Ok(())
        }
    }
    struct CustomTokenGen;
    #[async_trait]
    impl TokenGenerator for CustomTokenGen {
        async fn generate_token(&self, id: &str) -> BulwarkResult<String> {
            Ok(format!("g-{}", id))
        }
        async fn refresh_token(&self, t: &str) -> BulwarkResult<String> {
            Ok(t.to_string())
        }
    }
    struct CustomSession;
    #[async_trait]
    impl SessionCreator for CustomSession {
        async fn create_session(&self, _: &str, _: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> BulwarkResult<bool> {
            Ok(true)
        }
    }
    struct CustomFirewall;
    #[async_trait]
    impl FirewallStrategy for CustomFirewall {
        async fn check_login_hooks(
            &self,
            _: &str,
            _: &bulwark::strategy::FirewallLoginContext,
        ) -> BulwarkResult<()> {
            Ok(())
        }
    }

    strategy.register_login_handler(Arc::new(CustomLogin));
    strategy.register_logout_handler(Arc::new(CustomLogout));
    strategy.register_permission_handler(Arc::new(CustomPermission));
    strategy.register_token_generator(Arc::new(CustomTokenGen));
    strategy.register_session_creator(Arc::new(CustomSession));
    strategy.register_firewall_strategy(Arc::new(CustomFirewall));

    // 注册后再次 remove 全部恢复默认（不报错）
    strategy.remove_login_handler();
    strategy.remove_logout_handler();
    strategy.remove_permission_handler();
    strategy.remove_token_generator();
    strategy.remove_session_creator();
    strategy.remove_firewall_strategy();
}

// ============================================================================
// R-strategy-registry-004: 替换一个策略不影响其他策略
// ============================================================================

/// 验证替换 `LoginHandler` 不影响 `LogoutHandler`（Arc::ptr_eq 不变）。
#[tokio::test(flavor = "multi_thread")]
async fn replace_one_strategy_does_not_affect_others() {
    struct CustomLoginHandler;
    #[async_trait]
    impl LoginHandler for CustomLoginHandler {
        async fn handle_login(&self, login_id: &str) -> BulwarkResult<String> {
            Ok(format!("custom-{}", login_id))
        }
    }

    let logic = make_logic().await;
    let mut strategy = Strategy::new(logic);

    // 替换前：克隆 logout_handler 的 Arc 引用
    let original_logout = strategy.logout_handler().clone();
    let original_permission = strategy.permission_handler().clone();
    let original_token = strategy.token_generator().clone();
    let original_session = strategy.session_creator().clone();
    let original_firewall = strategy.firewall_strategy().clone();

    // 替换 login_handler
    strategy.register_login_handler(Arc::new(CustomLoginHandler));

    // 替换后：其他 5 个策略的 Arc 应指向同一对象（未被替换）
    assert!(
        Arc::ptr_eq(&original_logout, strategy.logout_handler()),
        "替换 LoginHandler 不应影响 LogoutHandler"
    );
    assert!(
        Arc::ptr_eq(&original_permission, strategy.permission_handler()),
        "替换 LoginHandler 不应影响 PermissionHandler"
    );
    assert!(
        Arc::ptr_eq(&original_token, strategy.token_generator()),
        "替换 LoginHandler 不应影响 TokenGenerator"
    );
    assert!(
        Arc::ptr_eq(&original_session, strategy.session_creator()),
        "替换 LoginHandler 不应影响 SessionCreator"
    );
    assert!(
        Arc::ptr_eq(&original_firewall, strategy.firewall_strategy()),
        "替换 LoginHandler 不应影响 FirewallStrategy"
    );

    // login_handler 确实已替换
    let token = strategy.login_handler().handle_login("1001").await.unwrap();
    assert_eq!(token, "custom-1001");
}

/// 验证替换后旧策略被 drop（无内存泄漏，使用 weak 引用计数验证）。
#[tokio::test(flavor = "multi_thread")]
async fn replace_drops_old_handler_no_leak() {
    struct CustomLoginHandler;
    #[async_trait]
    impl LoginHandler for CustomLoginHandler {
        async fn handle_login(&self, login_id: &str) -> BulwarkResult<String> {
            Ok(format!("v1-{}", login_id))
        }
    }

    let logic = make_logic().await;
    let mut strategy = Strategy::new(logic);

    // 注册第一个自定义策略
    let handler_v1 = Arc::new(CustomLoginHandler);
    let weak_v1 = Arc::downgrade(&handler_v1);
    strategy.register_login_handler(handler_v1);

    // 注册第二个自定义策略，替换第一个
    struct AnotherLoginHandler;
    #[async_trait]
    impl LoginHandler for AnotherLoginHandler {
        async fn handle_login(&self, login_id: &str) -> BulwarkResult<String> {
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

// ============================================================================
// R-strategy-registry-003 集成: BulwarkManager 全局访问
// ============================================================================

/// 验证 `BulwarkManager::init` 后 `strategy()` 返回 `Arc<RwLock<Strategy>>`。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn manager_init_makes_strategy_available() {
    use bulwark::BulwarkManager;

    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    BulwarkManager::init(dao, config, interface).unwrap();

    let strategy = BulwarkManager::strategy();
    assert!(strategy.is_ok(), "init 后应能获取 strategy");

    // 验证 strategy 可读
    let strategy = strategy.unwrap();
    let _guard = strategy.read();
    // 6 个 getter 均可调用
    let _ = _guard.login_handler();
}

/// 验证 `BulwarkManager::with_strategy()` 整体替换 Strategy 注册表。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn manager_with_strategy_replaces_registry() {
    use bulwark::BulwarkManager;

    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    BulwarkManager::init(dao, config, interface).unwrap();

    // 获取原 logic 并构造自定义 Strategy
    let logic = BulwarkManager::logic().unwrap();
    let custom_strategy = Arc::new(RwLock::new(Strategy::new(logic)));

    // 注入自定义 LoginHandler
    struct CustomLogin;
    #[async_trait]
    impl LoginHandler for CustomLogin {
        async fn handle_login(&self, id: &str) -> BulwarkResult<String> {
            Ok(format!("custom-{}", id))
        }
    }
    custom_strategy
        .write()
        .register_login_handler(Arc::new(CustomLogin));

    // with_strategy 替换
    BulwarkManager::with_strategy(custom_strategy).unwrap();

    // 验证替换后使用自定义策略
    let strategy = BulwarkManager::strategy().unwrap();
    let login_handler = strategy.read().login_handler().clone();
    let token = login_handler.handle_login("1001").await.unwrap();
    assert_eq!(token, "custom-1001", "with_strategy 后应使用自定义策略");
}

/// 验证运行时通过 `strategy().write().register_*()` 替换策略立即生效。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn runtime_register_takes_effect_immediately() {
    use bulwark::BulwarkManager;

    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    BulwarkManager::init(dao, config, interface).unwrap();

    // 替换前：默认策略生成 token（先 clone Arc 再 await，避免跨 await 持锁）
    let strategy = BulwarkManager::strategy().unwrap();
    let default_handler = strategy.read().login_handler().clone();
    let default_token = default_handler.handle_login("1001").await.unwrap();
    assert!(!default_token.is_empty());

    // 运行时替换
    struct CustomLogin;
    #[async_trait]
    impl LoginHandler for CustomLogin {
        async fn handle_login(&self, id: &str) -> BulwarkResult<String> {
            Ok(format!("runtime-{}", id))
        }
    }
    strategy
        .write()
        .register_login_handler(Arc::new(CustomLogin));

    // 替换后立即生效（先 clone Arc 再 await）
    let custom_handler = strategy.read().login_handler().clone();
    let token = custom_handler.handle_login("1001").await.unwrap();
    assert_eq!(token, "runtime-1001", "运行时替换策略后应立即生效");
}

/// 验证运行时替换 + remove 恢复默认的完整生命周期。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn runtime_register_then_remove_restores_default() {
    use bulwark::BulwarkManager;

    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    BulwarkManager::init(dao, config, interface).unwrap();

    let strategy = BulwarkManager::strategy().unwrap();

    // 1. 默认策略生成 token
    let default_handler = strategy.read().login_handler().clone();
    let default_token = default_handler.handle_login("42").await.unwrap();
    assert!(!default_token.is_empty());

    // 2. 注册自定义策略
    struct CustomLogin;
    #[async_trait]
    impl LoginHandler for CustomLogin {
        async fn handle_login(&self, id: &str) -> BulwarkResult<String> {
            Ok(format!("lifecycle-{}", id))
        }
    }
    strategy
        .write()
        .register_login_handler(Arc::new(CustomLogin));

    let custom_handler = strategy.read().login_handler().clone();
    let custom_token = custom_handler.handle_login("42").await.unwrap();
    assert_eq!(custom_token, "lifecycle-42");

    // 3. remove 恢复默认
    strategy.write().remove_login_handler();

    let restored_handler = strategy.read().login_handler().clone();
    let restored_token = restored_handler.handle_login("42").await.unwrap();
    assert_ne!(restored_token, "lifecycle-42", "remove 后应恢复默认策略");
    assert!(!restored_token.is_empty());
}

// ============================================================================
// 集成场景: 多策略同时替换 + 并发安全
// ============================================================================

/// 验证同时替换多个策略，每个策略独立工作。
#[tokio::test(flavor = "multi_thread")]
async fn replace_multiple_strategies_independently() {
    struct CustomLoginHandler;
    #[async_trait]
    impl LoginHandler for CustomLoginHandler {
        async fn handle_login(&self, id: &str) -> BulwarkResult<String> {
            Ok(format!("login-{}", id))
        }
    }

    struct CustomTokenGenerator;
    #[async_trait]
    impl TokenGenerator for CustomTokenGenerator {
        async fn generate_token(&self, id: &str) -> BulwarkResult<String> {
            Ok(format!("token-{}", id))
        }
        async fn refresh_token(&self, t: &str) -> BulwarkResult<String> {
            Ok(format!("refreshed-{}", t))
        }
    }

    let logic = make_logic().await;
    let mut strategy = Strategy::new(logic);

    // 同时替换两个策略
    strategy.register_login_handler(Arc::new(CustomLoginHandler));
    strategy.register_token_generator(Arc::new(CustomTokenGenerator));

    // 两个策略各自工作
    let login_token = strategy.login_handler().handle_login("1001").await.unwrap();
    assert_eq!(login_token, "login-1001");

    let gen_token = strategy
        .token_generator()
        .generate_token("1001")
        .await
        .unwrap();
    assert_eq!(gen_token, "token-1001");

    let refreshed = strategy
        .token_generator()
        .refresh_token("old")
        .await
        .unwrap();
    assert_eq!(refreshed, "refreshed-old");
}

/// 验证 Strategy 在多线程环境下通过 `Arc<RwLock<Strategy>>` 安全共享。
#[tokio::test(flavor = "multi_thread")]
async fn strategy_thread_safe_via_arc_rwlock() {
    use std::thread;

    struct CountingLoginHandler {
        counter: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl LoginHandler for CountingLoginHandler {
        async fn handle_login(&self, _id: &str) -> BulwarkResult<String> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            Ok("ok".to_string())
        }
    }

    let logic = make_logic().await;
    let counter = Arc::new(AtomicUsize::new(0));
    let mut strategy = Strategy::new(logic);
    strategy.register_login_handler(Arc::new(CountingLoginHandler {
        counter: counter.clone(),
    }));

    let shared = Arc::new(RwLock::new(strategy));

    // 多线程并发 read + 调用
    let mut handles = vec![];
    for _ in 0..4 {
        let s = shared.clone();
        handles.push(thread::spawn(move || {
            // 在子线程中创建 runtime 调用 async 方法
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let handler = s.read().login_handler().clone();
                handler.handle_login("1").await.unwrap();
            });
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(counter.load(Ordering::SeqCst), 4, "4 个线程应各自调用一次");
}
