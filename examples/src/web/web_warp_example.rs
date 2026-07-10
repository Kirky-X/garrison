//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! web_warp_example 示例（web-warp feature）。
//!
//! 演示 warp 框架集成：
//! 1. `BulwarkRouter`（warp 版本）+ `into_filter` 路由级守卫
//! 2. `BulwarkRejection` rejection 处理 + `recover` 恢复
//! 3. `check_login` / `check_role` / `check_permission` 函数式 Filter
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin web_warp_example --features web-warp
//! ```

use async_trait::async_trait;
use bulwark::annotation::Annotation;
use bulwark::config::BulwarkConfig;
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::manager::BulwarkManager;
use bulwark::stp::{BulwarkInterface, BulwarkUtil};
use bulwark::web_warp::{BulwarkRejection, BulwarkRouter};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use warp::Filter;

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
// setup / build_routes / handle_rejection / run
// ============================================================================

/// 初始化全局 BulwarkManager（注入 InMemoryDao + MyInterface），并登录获取 token。
///
/// 返回 `(config, token)`，config 用于构建 warp Filter，token 用于测试请求。
pub async fn setup() -> (Arc<BulwarkConfig>, String) {
    let dao: Arc<dyn BulwarkDao> = Arc::new(InMemoryDao::new());
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    let config = Arc::new(config);
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface::new());
    BulwarkManager::init(dao, config.clone(), interface).expect("BulwarkManager 初始化失败");

    let token = BulwarkUtil::login_simple("1001").await.expect("login 失败");
    (config, token)
}

/// 构建 warp 路由 Filter（使用 BulwarkRouter + into_filter 路由级守卫）。
///
/// 注册的路由规则：
/// - `/api/protected` → `CheckLogin`
/// - `/api/admin` → `CheckRole("admin")`
/// - `/api/data` → `CheckPermission("data:read")`
/// - `/public` → 无守卫规则（放行）
///
/// 守卫 Filter 检查请求路径是否匹配已注册规则，匹配则执行 interceptor 鉴权。
/// 未注册路径直接放行（仍经过后续路由匹配）。
pub fn build_routes(
    config: Arc<BulwarkConfig>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let guard = BulwarkRouter::new(config)
        .route_protected("/api/protected", Annotation::CheckLogin)
        .route_protected("/api/admin", Annotation::CheckRole("admin".to_string()))
        .route_protected(
            "/api/data",
            Annotation::CheckPermission("data:read".to_string()),
        )
        .into_filter();

    let api_routes = warp::get()
        .and(warp::path("api"))
        .and(warp::path("protected"))
        .and(warp::path::end())
        .map(|| "protected ok")
        .or(warp::get()
            .and(warp::path("api"))
            .and(warp::path("admin"))
            .and(warp::path::end())
            .map(|| "admin ok"))
        .or(warp::get()
            .and(warp::path("api"))
            .and(warp::path("data"))
            .and(warp::path::end())
            .map(|| "data ok"));

    let public = warp::get()
        .and(warp::path("public"))
        .and(warp::path::end())
        .map(|| "public ok");

    warp::any()
        .and(guard)
        .and(api_routes.or(public))
        .map(|_, reply| reply)
}

/// rejection 恢复处理器：将 BulwarkRejection 转换为 JSON 错误响应。
///
/// 返回包含错误消息和正确状态码的 JSON 响应。非 BulwarkRejection 的 rejection 原样传递。
pub async fn handle_rejection(
    err: warp::Rejection,
) -> Result<impl warp::reply::Reply, warp::Rejection> {
    if let Some(rej) = err.find::<BulwarkRejection>() {
        let (status_code, _, _, _) = rej.0.response_parts();
        let status = warp::http::StatusCode::from_u16(status_code)
            .unwrap_or(warp::http::StatusCode::INTERNAL_SERVER_ERROR);
        let body = serde_json::json!({"error": rej.0.to_string()});
        return Ok(warp::reply::with_status(warp::reply::json(&body), status));
    }
    Err(err)
}

/// 运行 web_warp 示例：启动 warp HTTP 服务器。
///
/// 启动后监听 `127.0.0.1:3002`，可通过 curl 测试：
/// ```sh
/// curl -H "Authorization: Bearer <token>" http://127.0.0.1:3002/api/protected
/// curl http://127.0.0.1:3002/public
/// ```
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark warp 集成示例 ===\n");

    let (config, token) = setup().await;
    println!("[初始化] BulwarkManager 已就绪");
    println!("    账号 1001 角色: [admin]");
    println!("    账号 1001 权限: [data:read]");
    println!("    token: {}...", &token[..16.min(token.len())]);
    println!();

    println!("[路由] BulwarkRouter + into_filter 守卫:");
    println!("    GET /api/protected  → CheckLogin");
    println!("    GET /api/admin      → CheckRole(\"admin\")");
    println!("    GET /api/data       → CheckPermission(\"data:read\")");
    println!("    GET /public         → 无守卫（放行）");
    println!();

    println!("[替代方案] check_login / check_role / check_permission 函数式 Filter:");
    println!("    warp::path(\"api\").and(check_login(config.clone())).map(|| \"ok\")");
    println!();

    println!("[rejection] handle_rejection: BulwarkRejection → JSON 错误响应");
    println!();

    println!("[启动] warp::serve 监听 127.0.0.1:3002");
    println!("    测试命令:");
    println!(
        "    curl -H 'Authorization: Bearer {}' http://127.0.0.1:3002/api/protected",
        token
    );
    println!("    curl http://127.0.0.1:3002/public\n");

    let routes = build_routes(config).recover(handle_rejection);
    warp::serve(routes).run(([127, 0, 0, 1], 3002)).await;

    Ok(())
}
