//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! web_actix_example 示例（web-actix feature）。
//!
//! 演示 actix-web 框架集成：
//! 1. `BulwarkRouter`（actix-web 版本）注册受保护路由
//! 2. `BulwarkMiddleware` 自动提取 token 并执行鉴权
//! 3. `with_interceptor` 自定义拦截器（LoggingInterceptor）
//! 4. 注解 `CheckLogin` / `CheckRole` / `CheckPermission` 的路由级鉴权
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin web_actix_example --features web-actix
//! ```

use actix_web::HttpServer;
use async_trait::async_trait;
use bulwark::annotation::Annotation;
use bulwark::config::BulwarkConfig;
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::manager::BulwarkManager;
use bulwark::router::BulwarkInterceptor;
use bulwark::stp::{BulwarkInterface, BulwarkUtil};
use bulwark::web_actix::{BulwarkMiddleware, BulwarkRouter};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ============================================================================
// InMemoryDao（HashMap + Instant 模拟 TTL，参考 alone_cache.rs 模式）
// ============================================================================

/// 最小化内存 DAO 实现（仅供示例，生产环境用 oxcache / dbnexus）。
pub struct InMemoryDao {
    store: Mutex<HashMap<String, (String, Option<Instant>)>>,
}

impl InMemoryDao {
    /// 创建 InMemoryDao 实例。
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryDao {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BulwarkDao for InMemoryDao {
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

// ============================================================================
// MyInterface（预置 login_id=1001 的 admin 角色 + data:read 权限）
// ============================================================================

/// 示例接口实现，仅提供 login_id=1001 的权限与角色。
pub struct MyInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MyInterface {
    /// 创建 MyInterface 实例。
    ///
    /// 预置数据：login_id=1001 持有 `["data:read"]` 权限 + `["admin"]` 角色。
    pub fn new() -> Self {
        let mut permissions = HashMap::new();
        permissions.insert("1001".to_string(), vec!["data:read".to_string()]);
        let mut roles = HashMap::new();
        roles.insert("1001".to_string(), vec!["admin".to_string()]);
        Self { permissions, roles }
    }
}

impl Default for MyInterface {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BulwarkInterface for MyInterface {
    async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.roles.get(login_id).cloned().unwrap_or_default())
    }
}

// ============================================================================
// LoggingInterceptor（自定义拦截器，演示 with_interceptor）
// ============================================================================

/// 自定义拦截器：打印鉴权日志，然后委托给 BulwarkUtil 执行实际鉴权。
///
/// 演示 `BulwarkRouter::with_interceptor` 用法，生产环境可实现更复杂逻辑
/// （如审计日志、指标收集、多租户路由等）。
struct LoggingInterceptor;

#[async_trait]
impl BulwarkInterceptor for LoggingInterceptor {
    async fn pre_handle(&self, path: &str, annotation: &Annotation) -> BulwarkResult<()> {
        println!(
            "[LoggingInterceptor] path={}, annotation={:?}",
            path, annotation
        );
        match annotation {
            Annotation::CheckLogin => {
                let logged_in = BulwarkUtil::check_login().await?;
                if !logged_in {
                    return Err(BulwarkError::NotLogin("未登录".to_string()));
                }
                Ok(())
            },
            Annotation::CheckRole(role) => BulwarkUtil::check_role(role).await,
            Annotation::CheckPermission(perm) => BulwarkUtil::check_permission(perm).await,
            Annotation::Ignore => Ok(()),
            _ => Ok(()),
        }
    }
}

// ============================================================================
// setup / create_middleware / run
// ============================================================================

/// 初始化全局 BulwarkManager（注入 InMemoryDao + MyInterface），并登录获取 token。
///
/// 返回 `(config, token)`，config 用于构建 App 的 app_data，token 用于测试请求。
pub async fn setup() -> (Arc<BulwarkConfig>, String) {
    let dao: Arc<dyn BulwarkDao> = Arc::new(InMemoryDao::new());
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    let config = Arc::new(config);
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface::new());
    BulwarkManager::init(dao, config.clone(), interface).expect("BulwarkManager 初始化失败");

    let token = BulwarkUtil::login("1001").await.expect("login 失败");
    (config, token)
}

/// 创建 BulwarkMiddleware（注册路由规则 + 自定义拦截器）。
///
/// 注册的路由规则：
/// - `/api/protected` → `CheckLogin`
/// - `/api/admin` → `CheckRole("admin")`
/// - `/api/data` → `CheckPermission("data:read")`
/// - `/public` → `Ignore`（无鉴权）
pub fn create_middleware(config: Arc<BulwarkConfig>) -> BulwarkMiddleware {
    BulwarkRouter::new(config)
        .with_interceptor(LoggingInterceptor)
        .route_protected("/api/protected", Annotation::CheckLogin)
        .route_protected("/api/admin", Annotation::CheckRole("admin".to_string()))
        .route_protected(
            "/api/data",
            Annotation::CheckPermission("data:read".to_string()),
        )
        .route_protected("/public", Annotation::Ignore)
        .into_middleware()
}

/// 运行 web_actix 示例：启动 actix-web HttpServer。
///
/// 启动后监听 `127.0.0.1:3001`，可通过 curl 测试：
/// ```sh
/// curl -H "Authorization: Bearer <token>" http://127.0.0.1:3001/api/protected
/// curl http://127.0.0.1:3001/public
/// ```
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark actix-web 集成示例 ===\n");

    let (config, token) = setup().await;
    println!("[初始化] BulwarkManager 已就绪");
    println!("    账号 1001 角色: [admin]");
    println!("    账号 1001 权限: [data:read]");
    println!("    token: {}...", &token[..16.min(token.len())]);
    println!();

    println!("[路由] 受保护路由:");
    println!("    GET /api/protected  → CheckLogin");
    println!("    GET /api/admin      → CheckRole(\"admin\")");
    println!("    GET /api/data       → CheckPermission(\"data:read\")");
    println!("    GET /public         → Ignore（无鉴权）");
    println!();

    println!("[拦截器] LoggingInterceptor: 打印鉴权日志后委托 BulwarkUtil");
    println!();

    println!("[启动] HttpServer 监听 127.0.0.1:3001");
    println!("    测试命令:");
    println!(
        "    curl -H 'Authorization: Bearer {}' http://127.0.0.1:3001/api/protected",
        token
    );
    println!(
        "    curl -H 'Authorization: Bearer {}' http://127.0.0.1:3001/api/admin",
        token
    );
    println!("    curl http://127.0.0.1:3001/public\n");

    let config_for_server = config.clone();
    HttpServer::new(move || {
        let middleware = create_middleware(config_for_server.clone());
        actix_web::App::new()
            .app_data(actix_web::web::Data::new(config_for_server.clone()))
            .wrap(middleware)
            .route(
                "/api/protected",
                actix_web::web::get().to(|| async { "protected ok" }),
            )
            .route(
                "/api/admin",
                actix_web::web::get().to(|| async { "admin ok" }),
            )
            .route(
                "/api/data",
                actix_web::web::get().to(|| async { "data ok" }),
            )
            .route(
                "/public",
                actix_web::web::get().to(|| async { "public ok" }),
            )
    })
    .bind("127.0.0.1:3001")?
    .run()
    .await?;

    Ok(())
}
