//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Plugin / Listener 集成测试：编译期注册 → 钩子调用 → 事件广播。
//!
//! 验证 `BulwarkPluginManager` 与 `BulwarkListenerManager` 的端到端行为：
//! 1. 通过 `inventory::submit!` 注册测试 plugin / listener
//! 2. `BulwarkPluginManager::new()` / `BulwarkListenerManager::new()` 收集已注册条目
//! 3. `on_login` / `on_logout` / `on_permission_check` 钩子被调用
//! 4. `broadcast` 将事件分发到所有 listener
//! 5. 单个 plugin/listener 失败不中断主流程（仅 tracing::warn!）
//!
//! ## auto-wire 集成（0.2.1 修复）
//!
//! 0.2.1 起 `BulwarkManager::init` 自动注入 `BulwarkPluginManager` / `BulwarkListenerManager`
//! 到 `BulwarkLogicDefault`，`BulwarkUtil::login` 会自动触发 `on_login` 钩子与 `Login` 事件。
//! 本文件包含两组测试：
//! 1. 扩展点本身行为（直接调用 plugin/listener 方法）
//! 2. auto-wire 端到端（通过 `BulwarkManager::init` + `BulwarkUtil::login` 验证自动触发）
//!
//! 依据 spec plugin-system + listener-system。

#![cfg(feature = "listener")]

use async_trait::async_trait;
use bulwark::error::BulwarkResult;
use bulwark::listener::{BulwarkEvent, BulwarkListener, BulwarkListenerManager};
use bulwark::plugin::{BulwarkPlugin, BulwarkPluginManager};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ============================================================================
// 测试用 Plugin（计数器记录钩子调用）
// ============================================================================

static PLUGIN_LOGIN_CALLS: AtomicUsize = AtomicUsize::new(0);
static PLUGIN_LOGOUT_CALLS: AtomicUsize = AtomicUsize::new(0);
static PLUGIN_PERM_CHECK_CALLS: AtomicUsize = AtomicUsize::new(0);

struct CountingPlugin;

impl BulwarkPlugin for CountingPlugin {
    fn name(&self) -> &str {
        "counting-plugin"
    }
    fn on_login(&self, _login_id: &str, _token: &str) -> BulwarkResult<()> {
        PLUGIN_LOGIN_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_logout(&self, _login_id: &str, _token: &str) -> BulwarkResult<()> {
        PLUGIN_LOGOUT_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_permission_check(&self, _login_id: &str, _permission: &str) -> BulwarkResult<()> {
        PLUGIN_PERM_CHECK_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn counting_plugin_factory() -> Arc<dyn BulwarkPlugin> {
    Arc::new(CountingPlugin)
}

inventory::submit! {
    bulwark::plugin::BulwarkPluginEntry { factory: counting_plugin_factory }
}

// ============================================================================
// 测试用 Listener（计数器记录事件广播）
// ============================================================================

static LISTENER_LOGIN_EVENTS: AtomicUsize = AtomicUsize::new(0);
static LISTENER_LOGOUT_EVENTS: AtomicUsize = AtomicUsize::new(0);
static LISTENER_PERM_CHECK_EVENTS: AtomicUsize = AtomicUsize::new(0);

struct CountingListener;

#[async_trait]
impl BulwarkListener for CountingListener {
    async fn on_event(&self, event: &BulwarkEvent) -> BulwarkResult<()> {
        match event {
            BulwarkEvent::Login { .. } => {
                LISTENER_LOGIN_EVENTS.fetch_add(1, Ordering::SeqCst);
            },
            BulwarkEvent::Logout { .. } => {
                LISTENER_LOGOUT_EVENTS.fetch_add(1, Ordering::SeqCst);
            },
            BulwarkEvent::PermissionCheck { .. } => {
                LISTENER_PERM_CHECK_EVENTS.fetch_add(1, Ordering::SeqCst);
            },
            _ => {},
        }
        Ok(())
    }
}

fn counting_listener_factory() -> Arc<dyn BulwarkListener> {
    Arc::new(CountingListener)
}

inventory::submit! {
    bulwark::listener::BulwarkListenerEntry { factory: counting_listener_factory }
}

// ============================================================================
// 辅助函数
// ============================================================================

fn reset_counters() {
    PLUGIN_LOGIN_CALLS.store(0, Ordering::SeqCst);
    PLUGIN_LOGOUT_CALLS.store(0, Ordering::SeqCst);
    PLUGIN_PERM_CHECK_CALLS.store(0, Ordering::SeqCst);
    LISTENER_LOGIN_EVENTS.store(0, Ordering::SeqCst);
    LISTENER_LOGOUT_EVENTS.store(0, Ordering::SeqCst);
    LISTENER_PERM_CHECK_EVENTS.store(0, Ordering::SeqCst);
}

// ============================================================================
// Plugin 集成测试
// ============================================================================

/// BulwarkPluginManager 收集 inventory 注册的插件（spec Scenario）。
#[test]
fn plugin_manager_collects_registered_plugins() {
    let manager = BulwarkPluginManager::new();
    assert!(
        manager.count() >= 1,
        "应至少收集到 1 个测试插件（CountingPlugin）"
    );
}

/// on_login 钩子被调用（spec Scenario）。
#[test]
#[serial_test::serial]
fn plugin_on_login_invoked() {
    reset_counters();
    let manager = BulwarkPluginManager::new();
    manager.on_login("1001", "token-xyz");
    assert!(
        PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst) >= 1,
        "CountingPlugin.on_login 应被调用至少 1 次"
    );
}

/// on_logout 钩子被调用（spec Scenario）。
#[test]
#[serial_test::serial]
fn plugin_on_logout_invoked() {
    reset_counters();
    let manager = BulwarkPluginManager::new();
    manager.on_logout("1001", "token-xyz");
    assert!(
        PLUGIN_LOGOUT_CALLS.load(Ordering::SeqCst) >= 1,
        "CountingPlugin.on_logout 应被调用至少 1 次"
    );
}

/// on_permission_check 钩子被调用（spec Scenario）。
#[test]
#[serial_test::serial]
fn plugin_on_permission_check_invoked() {
    reset_counters();
    let manager = BulwarkPluginManager::new();
    manager.on_permission_check("1001", "user:read");
    assert!(
        PLUGIN_PERM_CHECK_CALLS.load(Ordering::SeqCst) >= 1,
        "CountingPlugin.on_permission_check 应被调用至少 1 次"
    );
}

/// 多次调用累计计数（验证 plugin 是无状态可重入的，spec Scenario）。
#[test]
#[serial_test::serial]
fn plugin_multiple_calls_accumulate() {
    reset_counters();
    let manager = BulwarkPluginManager::new();
    for _ in 0..5 {
        manager.on_login("1001", "t");
    }
    assert!(
        PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst) >= 5,
        "5 次 on_login 应使计数器 >= 5"
    );
}

// ============================================================================
// Listener 集成测试
// ============================================================================

/// BulwarkListenerManager 收集 inventory 注册的 listener（spec Scenario）。
#[test]
fn listener_manager_collects_registered_listeners() {
    let manager = BulwarkListenerManager::new();
    assert!(
        manager.count() >= 1,
        "应至少收集到 1 个测试 listener（CountingListener）"
    );
}

/// Login 事件广播到 listener（spec Scenario）。
#[tokio::test]
#[serial_test::serial]
async fn listener_receives_login_event() {
    reset_counters();
    let manager = BulwarkListenerManager::new();
    manager
        .broadcast(&BulwarkEvent::Login {
            login_id: "1001".to_string(),
            token: "T1".to_string(),
            device: Some("web".to_string()),
        })
        .await;
    assert!(
        LISTENER_LOGIN_EVENTS.load(Ordering::SeqCst) >= 1,
        "CountingListener 应收到 Login 事件"
    );
}

/// Logout 事件广播到 listener（spec Scenario）。
#[tokio::test]
#[serial_test::serial]
async fn listener_receives_logout_event() {
    reset_counters();
    let manager = BulwarkListenerManager::new();
    manager
        .broadcast(&BulwarkEvent::Logout {
            login_id: "1001".to_string(),
            token: "T1".to_string(),
        })
        .await;
    assert!(
        LISTENER_LOGOUT_EVENTS.load(Ordering::SeqCst) >= 1,
        "CountingListener 应收到 Logout 事件"
    );
}

/// PermissionCheck 事件广播到 listener（spec Scenario）。
#[tokio::test]
#[serial_test::serial]
async fn listener_receives_permission_check_event() {
    reset_counters();
    let manager = BulwarkListenerManager::new();
    manager
        .broadcast(&BulwarkEvent::PermissionCheck {
            login_id: "1001".to_string(),
            permission: "user:delete".to_string(),
        })
        .await;
    assert!(
        LISTENER_PERM_CHECK_EVENTS.load(Ordering::SeqCst) >= 1,
        "CountingListener 应收到 PermissionCheck 事件"
    );
}

/// 多次广播累计计数（spec Scenario）。
#[tokio::test]
#[serial_test::serial]
async fn listener_multiple_broadcasts_accumulate() {
    reset_counters();
    let manager = BulwarkListenerManager::new();
    for _ in 0..3 {
        manager
            .broadcast(&BulwarkEvent::Login {
                login_id: "1".to_string(),
                token: "t".to_string(),
                device: None,
            })
            .await;
    }
    assert!(
        LISTENER_LOGIN_EVENTS.load(Ordering::SeqCst) >= 3,
        "3 次 Login 广播应使计数器 >= 3"
    );
}

// ============================================================================
// 端到端集成：plugin + listener 协同
// ============================================================================

/// 完整生命周期：login → permission_check → logout
/// （扩展点本身行为：直接调用 plugin/listener 方法）。
#[tokio::test]
#[serial_test::serial]
async fn full_lifecycle_plugin_and_listener_cooperate() {
    reset_counters();

    let plugin_manager = BulwarkPluginManager::new();
    let listener_manager = BulwarkListenerManager::new();

    // 1. 模拟登录：先调用 plugin on_login，再广播 Login 事件
    plugin_manager.on_login("1001", "T1");
    listener_manager
        .broadcast(&BulwarkEvent::Login {
            login_id: "1001".to_string(),
            token: "T1".to_string(),
            device: Some("web".to_string()),
        })
        .await;

    // 2. 模拟权限校验：调用 plugin on_permission_check
    plugin_manager.on_permission_check("1001", "user:read");

    // 3. 模拟登出：调用 plugin on_logout + 广播 Logout 事件
    plugin_manager.on_logout("1001", "T1");
    listener_manager
        .broadcast(&BulwarkEvent::Logout {
            login_id: "1001".to_string(),
            token: "T1".to_string(),
        })
        .await;

    // 验证全部钩子与事件被触发
    assert!(
        PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst) >= 1,
        "plugin on_login"
    );
    assert!(
        PLUGIN_PERM_CHECK_CALLS.load(Ordering::SeqCst) >= 1,
        "plugin on_permission_check"
    );
    assert!(
        PLUGIN_LOGOUT_CALLS.load(Ordering::SeqCst) >= 1,
        "plugin on_logout"
    );
    assert!(
        LISTENER_LOGIN_EVENTS.load(Ordering::SeqCst) >= 1,
        "listener Login 事件"
    );
    assert!(
        LISTENER_LOGOUT_EVENTS.load(Ordering::SeqCst) >= 1,
        "listener Logout 事件"
    );
}

/// PermissionCheck 事件不被 plugin 触发，仅由 listener 接收（spec Scenario）。
#[tokio::test]
#[serial_test::serial]
async fn permission_check_event_only_goes_to_listener() {
    reset_counters();
    let plugin_manager = BulwarkPluginManager::new();
    let listener_manager = BulwarkListenerManager::new();

    // 权限校验被拒时：plugin 收到 on_permission_check，listener 收到 PermissionCheck
    plugin_manager.on_permission_check("1001", "user:delete");
    listener_manager
        .broadcast(&BulwarkEvent::PermissionCheck {
            login_id: "1001".to_string(),
            permission: "user:delete".to_string(),
        })
        .await;

    assert!(PLUGIN_PERM_CHECK_CALLS.load(Ordering::SeqCst) >= 1);
    assert!(LISTENER_PERM_CHECK_EVENTS.load(Ordering::SeqCst) >= 1);
}

// ============================================================================
// auto-wire 集成测试（0.2.1 新增）
// 验证 BulwarkManager::init 自动注入 plugin/listener 后，
// BulwarkUtil::login 会自动触发 on_login 钩子与 Login 事件。
// ============================================================================

/// 辅助 MockDao（复用 manager 测试的 HashMap 模式，适配 async）。
mod auto_wire_helpers {
    use async_trait::async_trait;
    use bulwark::dao::BulwarkDao;
    use bulwark::error::{BulwarkError, BulwarkResult};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use tokio::sync::Mutex;

    pub struct MockDao {
        store: Mutex<HashMap<String, (String, Option<Instant>)>>,
    }

    impl MockDao {
        pub fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BulwarkDao for MockDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            let mut store = self.store.lock().await;
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
                .await
                .insert(key.to_string(), (value.to_string(), expire_at));
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            let mut store = self.store.lock().await;
            match store.get_mut(key) {
                Some((existing, _)) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            let mut store = self.store.lock().await;
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
            self.store.lock().await.remove(key);
            Ok(())
        }
    }
}

/// auto-wire: `BulwarkManager::init` + `BulwarkUtil::login` 自动触发 plugin on_login 钩子。
///
/// 验证 0.2.1 修复：init 阶段注入 PluginManager 后，
/// `BulwarkUtil::login(1001)` 会自动调用编译期注册的 CountingPlugin.on_login。
#[tokio::test]
#[serial_test::serial]
async fn auto_wire_login_triggers_plugin_on_login() {
    use auto_wire_helpers::MockDao;
    use bulwark::config::BulwarkConfig;
    use bulwark::manager::BulwarkManager;
    use bulwark::stp::{BulwarkInterface, BulwarkUtil};

    // 测试用 BulwarkInterface（空权限/角色数据）
    struct EmptyInterface;
    #[async_trait::async_trait]
    impl BulwarkInterface for EmptyInterface {
        async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
    }

    reset_counters();

    let dao: Arc<dyn bulwark::dao::BulwarkDao> = Arc::new(MockDao::new());
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(EmptyInterface);

    // init 自动构造 PluginManager 并注入到 BulwarkLogicDefault（覆盖式更新全局单例）
    BulwarkManager::init(dao, config, interface).unwrap();

    // login 应自动触发 CountingPlugin.on_login（编译期通过 inventory 注册）
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    assert!(!token.is_empty());

    // 验证 plugin on_login 被触发
    let calls = PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst);
    assert!(
        calls >= 1,
        "auto-wire: BulwarkUtil::login 应触发 plugin on_login，实际调用次数: {}",
        calls
    );
}

/// auto-wire: `BulwarkManager::init` + `BulwarkUtil::login` 自动广播 Login 事件到 listener。
#[tokio::test]
#[serial_test::serial]
async fn auto_wire_login_broadcasts_listener_login_event() {
    use auto_wire_helpers::MockDao;
    use bulwark::config::BulwarkConfig;
    use bulwark::manager::BulwarkManager;
    use bulwark::stp::{BulwarkInterface, BulwarkUtil};

    struct EmptyInterface;
    #[async_trait::async_trait]
    impl BulwarkInterface for EmptyInterface {
        async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
    }

    reset_counters();

    let dao: Arc<dyn bulwark::dao::BulwarkDao> = Arc::new(MockDao::new());
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(EmptyInterface);

    BulwarkManager::init(dao, config, interface).unwrap();

    let token = BulwarkUtil::login_simple("2002").await.unwrap();
    assert!(!token.is_empty());

    // 验证 listener Login 事件被广播
    let events = LISTENER_LOGIN_EVENTS.load(Ordering::SeqCst);
    assert!(
        events >= 1,
        "auto-wire: BulwarkUtil::login 应广播 Login 事件，实际事件数: {}",
        events
    );
}

/// auto-wire: `BulwarkManager::init` + `with_current_token` + `BulwarkUtil::logout` 自动触发 on_logout + Logout 事件。
#[tokio::test]
#[serial_test::serial]
async fn auto_wire_logout_triggers_hooks() {
    use auto_wire_helpers::MockDao;
    use bulwark::config::BulwarkConfig;
    use bulwark::manager::BulwarkManager;
    use bulwark::stp::{BulwarkInterface, BulwarkUtil};

    struct EmptyInterface;
    #[async_trait::async_trait]
    impl BulwarkInterface for EmptyInterface {
        async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
    }

    reset_counters();

    let dao: Arc<dyn bulwark::dao::BulwarkDao> = Arc::new(MockDao::new());
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(EmptyInterface);

    BulwarkManager::init(dao, config, interface).unwrap();

    // login（触发 on_login + Login 事件）
    let token = BulwarkUtil::login_simple("3003").await.unwrap();

    // logout（需在 with_current_token 上下文中执行）
    let login_before = PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst);
    bulwark::stp::with_current_token(token, async {
        BulwarkUtil::logout().await.unwrap();
    })
    .await;

    // 验证 plugin on_logout 被触发
    let logout_calls = PLUGIN_LOGOUT_CALLS.load(Ordering::SeqCst);
    assert!(
        logout_calls >= 1,
        "auto-wire: BulwarkUtil::logout 应触发 plugin on_logout，实际调用次数: {}",
        logout_calls
    );
    // login 钩子也应至少触发一次（login 阶段）
    assert!(login_before >= 1, "login 钩子应已触发");

    // 验证 listener Logout 事件被广播
    let logout_events = LISTENER_LOGOUT_EVENTS.load(Ordering::SeqCst);
    assert!(
        logout_events >= 1,
        "auto-wire: BulwarkUtil::logout 应广播 Logout 事件，实际事件数: {}",
        logout_events
    );
}
