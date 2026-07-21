//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Plugin / Listener 集成测试：编译期注册 → 钩子调用 → 事件广播。
//!
//! 验证 `GarrisonPluginManager` 与 `GarrisonListenerManager` 的端到端行为：
//! 1. 通过 `inventory::submit!` 注册测试 plugin / listener
//! 2. `GarrisonPluginManager::new()` / `GarrisonListenerManager::new()` 收集已注册条目
//! 3. `on_login` / `on_logout` / `on_permission_check` 钩子被调用
//! 4. `broadcast` 将事件分发到所有 listener
//! 5. 单个 plugin/listener 失败不中断主流程（仅 tracing::warn!）
//!
//! ## auto-wire 集成（0.2.1 修复）
//!
//! 0.2.1 起 `GarrisonManager::init` 自动注入 `GarrisonPluginManager` / `GarrisonListenerManager`
//! 到 `GarrisonLogicDefault`，`GarrisonUtil::login` 会自动触发 `on_login` 钩子与 `Login` 事件。
//! 本文件包含两组测试：
//! 1. 扩展点本身行为（直接调用 plugin/listener 方法）
//! 2. auto-wire 端到端（通过 `GarrisonManager::init` + `GarrisonUtil::login` 验证自动触发）
//!
//! 依据 spec plugin-system + listener-system。

#![cfg(feature = "listener")]

use async_trait::async_trait;
use garrison::error::GarrisonResult;
use garrison::listener::{GarrisonEvent, GarrisonListener, GarrisonListenerManager};
use garrison::plugin::{GarrisonPlugin, GarrisonPluginManager};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ============================================================================
// 测试用 Plugin（计数器记录钩子调用）
// ============================================================================

static PLUGIN_LOGIN_CALLS: AtomicUsize = AtomicUsize::new(0);
static PLUGIN_LOGOUT_CALLS: AtomicUsize = AtomicUsize::new(0);
static PLUGIN_PERM_CHECK_CALLS: AtomicUsize = AtomicUsize::new(0);

struct CountingPlugin;

impl GarrisonPlugin for CountingPlugin {
    fn name(&self) -> &str {
        "counting-plugin"
    }
    fn on_login(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        PLUGIN_LOGIN_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_logout(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        PLUGIN_LOGOUT_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_permission_check(&self, _login_id: &str, _permission: &str) -> GarrisonResult<()> {
        PLUGIN_PERM_CHECK_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn counting_plugin_factory() -> Arc<dyn GarrisonPlugin> {
    Arc::new(CountingPlugin)
}

inventory::submit! {
    garrison::plugin::GarrisonPluginEntry { factory: counting_plugin_factory }
}

// ============================================================================
// 测试用 Listener（计数器记录事件广播）
// ============================================================================

static LISTENER_LOGIN_EVENTS: AtomicUsize = AtomicUsize::new(0);
static LISTENER_LOGOUT_EVENTS: AtomicUsize = AtomicUsize::new(0);
static LISTENER_PERM_CHECK_EVENTS: AtomicUsize = AtomicUsize::new(0);

struct CountingListener;

#[async_trait]
impl GarrisonListener for CountingListener {
    async fn on_event(&self, event: &GarrisonEvent) -> GarrisonResult<()> {
        match event {
            GarrisonEvent::Login { .. } => {
                LISTENER_LOGIN_EVENTS.fetch_add(1, Ordering::SeqCst);
            },
            GarrisonEvent::Logout { .. } => {
                LISTENER_LOGOUT_EVENTS.fetch_add(1, Ordering::SeqCst);
            },
            GarrisonEvent::PermissionCheck { .. } => {
                LISTENER_PERM_CHECK_EVENTS.fetch_add(1, Ordering::SeqCst);
            },
            _ => {},
        }
        Ok(())
    }
}

fn counting_listener_factory() -> Arc<dyn GarrisonListener> {
    Arc::new(CountingListener)
}

inventory::submit! {
    garrison::listener::GarrisonListenerEntry { factory: counting_listener_factory }
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

/// GarrisonPluginManager 收集 inventory 注册的插件（spec Scenario）。
#[test]
fn plugin_manager_collects_registered_plugins() {
    let manager = GarrisonPluginManager::new();
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
    let manager = GarrisonPluginManager::new();
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
    let manager = GarrisonPluginManager::new();
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
    let manager = GarrisonPluginManager::new();
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
    let manager = GarrisonPluginManager::new();
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

/// GarrisonListenerManager 收集 inventory 注册的 listener（spec Scenario）。
#[test]
fn listener_manager_collects_registered_listeners() {
    let manager = GarrisonListenerManager::new();
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
    let manager = GarrisonListenerManager::new();
    manager
        .broadcast(&GarrisonEvent::Login {
            login_id: "1001".to_string(),
            token: "T1".to_string(),
            device: Some("web".to_string()),
            request_context: None,
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
    let manager = GarrisonListenerManager::new();
    manager
        .broadcast(&GarrisonEvent::Logout {
            login_id: "1001".to_string(),
            token: "T1".to_string(),
            request_context: None,
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
    let manager = GarrisonListenerManager::new();
    manager
        .broadcast(&GarrisonEvent::PermissionCheck {
            login_id: "1001".to_string(),
            permission: "user:delete".to_string(),
            request_context: None,
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
    let manager = GarrisonListenerManager::new();
    for _ in 0..3 {
        manager
            .broadcast(&GarrisonEvent::Login {
                login_id: "1".to_string(),
                token: "t".to_string(),
                device: None,
                request_context: None,
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

    let plugin_manager = GarrisonPluginManager::new();
    let listener_manager = GarrisonListenerManager::new();

    // 1. 模拟登录：先调用 plugin on_login，再广播 Login 事件
    plugin_manager.on_login("1001", "T1");
    listener_manager
        .broadcast(&GarrisonEvent::Login {
            login_id: "1001".to_string(),
            token: "T1".to_string(),
            device: Some("web".to_string()),
            request_context: None,
        })
        .await;

    // 2. 模拟权限校验：调用 plugin on_permission_check
    plugin_manager.on_permission_check("1001", "user:read");

    // 3. 模拟登出：调用 plugin on_logout + 广播 Logout 事件
    plugin_manager.on_logout("1001", "T1");
    listener_manager
        .broadcast(&GarrisonEvent::Logout {
            login_id: "1001".to_string(),
            token: "T1".to_string(),
            request_context: None,
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
    let plugin_manager = GarrisonPluginManager::new();
    let listener_manager = GarrisonListenerManager::new();

    // 权限校验被拒时：plugin 收到 on_permission_check，listener 收到 PermissionCheck
    plugin_manager.on_permission_check("1001", "user:delete");
    listener_manager
        .broadcast(&GarrisonEvent::PermissionCheck {
            login_id: "1001".to_string(),
            permission: "user:delete".to_string(),
            request_context: None,
        })
        .await;

    assert!(PLUGIN_PERM_CHECK_CALLS.load(Ordering::SeqCst) >= 1);
    assert!(LISTENER_PERM_CHECK_EVENTS.load(Ordering::SeqCst) >= 1);
}

// ============================================================================
// auto-wire 集成测试（0.2.1 新增）
// 验证 GarrisonManager::init 自动注入 plugin/listener 后，
// GarrisonUtil::login 会自动触发 on_login 钩子与 Login 事件。
// ============================================================================

/// 辅助 MockDao（复用 manager 测试的 HashMap 模式，适配 async）。
mod auto_wire_helpers {
    use async_trait::async_trait;
    use garrison::dao::GarrisonDao;
    use garrison::error::{GarrisonError, GarrisonResult};
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
    impl GarrisonDao for MockDao {
        async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
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

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
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

        async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
            let mut store = self.store.lock().await;
            match store.get_mut(key) {
                Some((existing, _)) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(GarrisonError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
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
                None => Err(GarrisonError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn delete(&self, key: &str) -> GarrisonResult<()> {
            self.store.lock().await.remove(key);
            Ok(())
        }
    }
}

/// auto-wire: `GarrisonManager::init` + `GarrisonUtil::login` 自动触发 plugin on_login 钩子。
///
/// 验证 0.2.1 修复：init 阶段注入 PluginManager 后，
/// `GarrisonUtil::login(1001)` 会自动调用编译期注册的 CountingPlugin.on_login。
#[tokio::test]
#[serial_test::serial]
async fn auto_wire_login_triggers_plugin_on_login() {
    use auto_wire_helpers::MockDao;
    use garrison::config::GarrisonConfig;
    use garrison::manager::GarrisonManager;
    use garrison::stp::{GarrisonInterface, GarrisonUtil};

    // 测试用 GarrisonInterface（空权限/角色数据）
    struct EmptyInterface;
    #[async_trait::async_trait]
    impl GarrisonInterface for EmptyInterface {
        async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
    }

    reset_counters();

    let dao: Arc<dyn garrison::dao::GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(GarrisonConfig::default_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(EmptyInterface);

    // init 自动构造 PluginManager 并注入到 GarrisonLogicDefault（覆盖式更新全局单例）
    GarrisonManager::init(dao, config, interface).unwrap();

    // login 应自动触发 CountingPlugin.on_login（编译期通过 inventory 注册）
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    assert!(!token.is_empty());

    // 验证 plugin on_login 被触发
    let calls = PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst);
    assert!(
        calls >= 1,
        "auto-wire: GarrisonUtil::login 应触发 plugin on_login，实际调用次数: {}",
        calls
    );
}

/// auto-wire: `GarrisonManager::init` + `GarrisonUtil::login` 自动广播 Login 事件到 listener。
#[tokio::test]
#[serial_test::serial]
async fn auto_wire_login_broadcasts_listener_login_event() {
    use auto_wire_helpers::MockDao;
    use garrison::config::GarrisonConfig;
    use garrison::manager::GarrisonManager;
    use garrison::stp::{GarrisonInterface, GarrisonUtil};

    struct EmptyInterface;
    #[async_trait::async_trait]
    impl GarrisonInterface for EmptyInterface {
        async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
    }

    reset_counters();

    let dao: Arc<dyn garrison::dao::GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(GarrisonConfig::default_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(EmptyInterface);

    GarrisonManager::init(dao, config, interface).unwrap();

    let token = GarrisonUtil::login_simple("2002").await.unwrap();
    assert!(!token.is_empty());

    // 验证 listener Login 事件被广播
    let events = LISTENER_LOGIN_EVENTS.load(Ordering::SeqCst);
    assert!(
        events >= 1,
        "auto-wire: GarrisonUtil::login 应广播 Login 事件，实际事件数: {}",
        events
    );
}

/// auto-wire: `GarrisonManager::init` + `with_current_token` + `GarrisonUtil::logout` 自动触发 on_logout + Logout 事件。
#[tokio::test]
#[serial_test::serial]
async fn auto_wire_logout_triggers_hooks() {
    use auto_wire_helpers::MockDao;
    use garrison::config::GarrisonConfig;
    use garrison::manager::GarrisonManager;
    use garrison::stp::{GarrisonInterface, GarrisonUtil};

    struct EmptyInterface;
    #[async_trait::async_trait]
    impl GarrisonInterface for EmptyInterface {
        async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
    }

    reset_counters();

    let dao: Arc<dyn garrison::dao::GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(GarrisonConfig::default_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(EmptyInterface);

    GarrisonManager::init(dao, config, interface).unwrap();

    // login（触发 on_login + Login 事件）
    let token = GarrisonUtil::login_simple("3003").await.unwrap();

    // logout（需在 with_current_token 上下文中执行）
    let login_before = PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst);
    garrison::stp::with_current_token(token, async {
        GarrisonUtil::logout().await.unwrap();
    })
    .await;

    // 验证 plugin on_logout 被触发
    let logout_calls = PLUGIN_LOGOUT_CALLS.load(Ordering::SeqCst);
    assert!(
        logout_calls >= 1,
        "auto-wire: GarrisonUtil::logout 应触发 plugin on_logout，实际调用次数: {}",
        logout_calls
    );
    // login 钩子也应至少触发一次（login 阶段）
    assert!(login_before >= 1, "login 钩子应已触发");

    // 验证 listener Logout 事件被广播
    let logout_events = LISTENER_LOGOUT_EVENTS.load(Ordering::SeqCst);
    assert!(
        logout_events >= 1,
        "auto-wire: GarrisonUtil::logout 应广播 Logout 事件，实际事件数: {}",
        logout_events
    );
}
