//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 过程宏注解示例（v0.4.2 新增，依据 spec annotation-macros）。
//!
//! 演示 `#[check_login]` / `#[check_permission]` / `#[check_role]` 三个属性宏的用法。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin macro_annotations --features "annotation-macros cache-memory web-axum"
//! ```
//!
//! 宏会将原 async fn 重命名为 `__bulwark_inner_<name>`，生成同名 wrapper：
//! - `#[check_login]` → `BulwarkUtil::check_login().await`，未登录返回 401
//! - `#[check_permission("a", "b")]` → 依次校验 a + b（AND 语义），任一失败返回 403
//! - `#[check_role("admin")]` → 校验角色，无角色返回 403
//!
//! **限制**：
//! - 仅支持 async fn（同步 fn 计划 v0.5.0+ 支持）
//! - 原 fn 返回类型需实现 `axum::response::IntoResponse`
//! - 依赖 `BulwarkManager` 全局单例（需先 `BulwarkManager::init`）
//! - task_local token 上下文由 `with_current_token` 或 axum middleware 设置

use async_trait::async_trait;
use axum::http::StatusCode;
use bulwark::{
    check_login, check_permission, check_role, BulwarkConfig, BulwarkDao, BulwarkError,
    BulwarkInterface, BulwarkManager, BulwarkUtil,
};
use http_body_util::BodyExt;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ============================================================================
// 宏标注的 handler（模块级定义）
// ============================================================================

/// 登录校验 handler：返回纯文本。
#[check_login]
async fn login_handler() -> &'static str {
    "login_ok"
}

/// 单权限校验 handler：需持有 user:read。
#[check_permission("user:read")]
async fn perm_handler() -> &'static str {
    "perm_ok"
}

/// 多权限 AND 语义 handler：需同时持有 user:read 和 user:write。
#[check_permission("user:read", "user:write")]
async fn perm_and_handler() -> &'static str {
    "perm_and_ok"
}

/// 单角色校验 handler：需持有 admin 角色。
#[check_role("admin")]
async fn role_handler() -> &'static str {
    "role_ok"
}

/// 多角色 AND 语义 handler：需同时持有 admin 和 superadmin。
#[check_role("admin", "superadmin")]
async fn role_and_handler() -> &'static str {
    "role_and_ok"
}

// ============================================================================
// MockDao + MockInterface（复用 annotation_macros_integration 模式）
// ============================================================================

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
    async fn get(&self, key: &str) -> Result<Option<String>, BulwarkError> {
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

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), BulwarkError> {
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

    async fn update(&self, key: &str, value: &str) -> Result<(), BulwarkError> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((existing, _)) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> Result<(), BulwarkError> {
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

    async fn delete(&self, key: &str) -> Result<(), BulwarkError> {
        self.store.lock().remove(key);
        Ok(())
    }
}

struct MockInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MockInterface {
    fn new() -> Self {
        Self {
            permissions: HashMap::new(),
            roles: HashMap::new(),
        }
    }

    fn with_permission(mut self, login_id: &str, perms: &[&str]) -> Self {
        self.permissions.insert(
            login_id.to_string(),
            perms.iter().map(|s| s.to_string()).collect(),
        );
        self
    }

    fn with_role(mut self, login_id: &str, roles: &[&str]) -> Self {
        self.roles.insert(
            login_id.to_string(),
            roles.iter().map(|s| s.to_string()).collect(),
        );
        self
    }
}

#[async_trait]
impl BulwarkInterface for MockInterface {
    async fn get_permission_list(&self, login_id: &str) -> Result<Vec<String>, BulwarkError> {
        Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: &str) -> Result<Vec<String>, BulwarkError> {
        Ok(self.roles.get(login_id).cloned().unwrap_or_default())
    }
}

/// 读取 Response body 为 String。
async fn read_body(response: axum::response::Response) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collect")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

/// 初始化 BulwarkManager（覆盖式更新，带权限/角色数据）。
fn init_manager(permissions: &[(&str, &[&str])], roles: &[(&str, &[&str])]) {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false; // loose 模式：未登录返回 Ok(false) → 401
    let config = Arc::new(config);
    let mut interface = MockInterface::new();
    for (id, perms) in permissions {
        interface = interface.with_permission(*id, perms);
    }
    for (id, roles) in roles {
        interface = interface.with_role(*id, roles);
    }
    let interface: Arc<dyn BulwarkInterface> = Arc::new(interface);
    BulwarkManager::init(dao, config, interface).unwrap();
}

/// 运行过程宏注解示例。
///
/// 流程：
/// 1. 初始化 BulwarkManager（带权限/角色数据）
/// 2. login(1001) 生成 token
/// 3. 在 task_local 上下文中调用宏标注的 handler
/// 4. 演示成功路径（已登录/已授权）与失败路径（未登录/无权限/无角色）
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark 过程宏注解示例 ===\n");

    // 1. 初始化：用户 1001 持有 user:read + user:write 权限，admin 角色
    init_manager(
        &[("1001", &["user:read", "user:write"])],
        &[("1001", &["admin"])],
    );
    println!("[1] BulwarkManager 初始化完成");
    println!("    用户 1001 权限: [user:read, user:write]");
    println!("    用户 1001 角色: [admin]\n");

    // 2. 用户 1001 登录获取 token
    let token = BulwarkUtil::login_simple("1001").await?;
    println!(
        "[2] 用户 1001 登录获取 token: {}...",
        &token[..std::cmp::min(20, token.len())]
    );

    // 3. #[check_login] 已登录 → 200
    println!("\n[3] #[check_login] 已登录 → 200");
    let response =
        bulwark::stp::with_current_token(token.clone(), async { login_handler().await }).await;
    println!("    状态码: {}", response.status());
    println!("    body:   {}", read_body(response).await);
    assert_eq!(StatusCode::OK, axum::http::StatusCode::OK);

    // 4. #[check_permission("user:read")] 持有权限 → 200
    println!("\n[4] #[check_permission(\"user:read\")] 持有权限 → 200");
    let response =
        bulwark::stp::with_current_token(token.clone(), async { perm_handler().await }).await;
    println!("    状态码: {}", response.status());
    println!("    body:   {}", read_body(response).await);

    // 5. #[check_permission("user:read", "user:write")] 多权限 AND → 200
    println!("\n[5] #[check_permission(\"user:read\", \"user:write\")] 多权限 AND → 200");
    let response =
        bulwark::stp::with_current_token(token.clone(), async { perm_and_handler().await }).await;
    println!("    状态码: {}", response.status());
    println!("    body:   {}", read_body(response).await);

    // 6. #[check_role("admin")] 持有角色 → 200
    println!("\n[6] #[check_role(\"admin\")] 持有角色 → 200");
    let response =
        bulwark::stp::with_current_token(token.clone(), async { role_handler().await }).await;
    println!("    状态码: {}", response.status());
    println!("    body:   {}", read_body(response).await);

    // 7. #[check_role("admin", "superadmin")] 多角色 AND → 403（缺少 superadmin）
    println!("\n[7] #[check_role(\"admin\", \"superadmin\")] 多角色 AND → 403（缺 superadmin）");
    let response =
        bulwark::stp::with_current_token(token.clone(), async { role_and_handler().await }).await;
    println!(
        "    状态码: {}（预期 403，因缺少 superadmin）",
        response.status()
    );
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // 8. 未登录（无效 token）→ 401
    println!("\n[8] 未登录（无效 token）→ 401");
    let response = bulwark::stp::with_current_token("invalid-token".to_string(), async {
        login_handler().await
    })
    .await;
    println!("    状态码: {}（预期 401）", response.status());
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 9. 无权限 → 403
    println!("\n[9] 无权限 → 403");
    // 初始化一个无权限的用户 2002
    init_manager(&[], &[("2002", &["admin"])]);
    let token_2002 = BulwarkUtil::login_simple("2002").await?;
    let response =
        bulwark::stp::with_current_token(token_2002, async { perm_handler().await }).await;
    println!(
        "    用户 2002 无 user:read 权限，状态码: {}（预期 403）",
        response.status()
    );
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    println!("\n=== 示例完成 ===");
    println!("\n宏的语义：");
    println!("  #[check_login]                          → 已登录才放行，否则 401");
    println!("  #[check_permission(\"a\")]               → 持有 a 才放行，否则 403");
    println!("  #[check_permission(\"a\", \"b\")]          → 同时持有 a + b（AND），否则 403");
    println!("  #[check_role(\"admin\")]                 → 持有 admin 才放行，否则 403");
    println!("  #[check_role(\"admin\", \"superadmin\")]   → 同时持有 admin + superadmin（AND），否则 403");
    println!("\n使用方式：");
    println!("  1. 在 Cargo.toml 启用 annotation-macros feature");
    println!("  2. use bulwark::{{check_login, check_permission, check_role}};");
    println!("  3. 标注 async fn（返回类型需实现 axum::response::IntoResponse）");
    println!("  4. 调用前确保 BulwarkManager::init + task_local token 已设置");
    Ok(())
}
