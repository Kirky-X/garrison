//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! ParameterQuery 参数化查询示例（依据 spec parameter-query，0.4.0 新增）。
//!
//! 演示 `ParameterQueryBuilder` 链式 API：
//! 1. 初始化 `BulwarkManager`（参考 permission_check.rs 的初始化模式）
//! 2. `ParameterQueryBuilder::new().with_login_id(1001).check_permission("user:create").await`
//! 3. 演示 token 上下文：先 login 获取 token，再 `with_token(&token).check_role("admin").await`
//! 4. 展示未设置上下文时返回 Internal 错误
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin parameter_query --features parameter-query
//! ```
//!
//! 注意：测试需要 `#[serial_test::serial]`（修改全局 `BulwarkManager` 单例）。

use async_trait::async_trait;
use bulwark::config::BulwarkConfig;
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::manager::BulwarkManager;
use bulwark::stp::parameter::{ParameterQuery, ParameterQueryBuilder};
use bulwark::stp::{BulwarkInterface, BulwarkUtil};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// 示例接口实现：基于内存 HashMap 存储 login_id 的权限与角色。
pub struct MyInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MyInterface {
    /// 创建接口实例，预置 login_id=1001 的权限与角色。
    pub fn new() -> Self {
        let mut permissions = HashMap::new();
        permissions.insert(
            "1001".to_string(),
            vec!["user:create".to_string(), "user:read".to_string()],
        );
        let mut roles = HashMap::new();
        roles.insert(
            "1001".to_string(),
            vec!["admin".to_string(), "user".to_string()],
        );
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

/// 初始化全局 BulwarkManager（注入 InMemoryDao + MyInterface）。
///
/// `BulwarkManager::init` 为覆盖式更新（允许重复 init），无需先 reset。
fn init_manager() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(InMemoryDao::new());
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface::new());
    BulwarkManager::init(dao, Arc::new(config), interface).expect("BulwarkManager 初始化失败");
}

/// 运行 ParameterQuery 示例。
///
/// 演示 ParameterQueryBuilder 的 with_login_id / with_token / check_permission / check_role 链式 API，
/// 包括未设置上下文时返回 Internal 错误的场景。
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark ParameterQuery 参数化查询示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 初始化 BulwarkManager
    // ----------------------------------------------------------------
    init_manager();
    println!("[初始化] BulwarkManager 已就绪");
    println!("    账号 1001 权限: [user:create, user:read]");
    println!("    账号 1001 角色: [admin, user]\n");

    // ----------------------------------------------------------------
    // 2. with_login_id + check_permission（持有权限 → Ok）
    // ----------------------------------------------------------------
    println!("[login_id 上下文] check_permission:");
    let result = ParameterQueryBuilder::new()
        .with_login_id("1001".to_string())
        .check_permission("user:create")
        .await;
    println!("    with_login_id(1001).check_permission(\"user:create\") → Ok(()) ✓");
    assert!(result.is_ok(), "持有权限应返回 Ok，实际: {:?}", result);

    // 未持有权限 → NotPermission
    let denied = ParameterQueryBuilder::new()
        .with_login_id("1001".to_string())
        .check_permission("user:delete")
        .await;
    match denied {
        Err(BulwarkError::NotPermission(perm)) => {
            println!(
                "    with_login_id(1001).check_permission(\"user:delete\")  → Err(NotPermission(\"{}\"))",
                perm
            );
        },
        other => panic!("期望 NotPermission，实际: {:?}", other),
    }
    println!();

    // ----------------------------------------------------------------
    // 3. with_token + check_role（先 login 获取 token）
    // ----------------------------------------------------------------
    println!("[token 上下文] check_role:");
    let token = BulwarkUtil::login_simple("1001").await?;
    println!(
        "    BulwarkUtil::login(1001) → token={}",
        &token[..16.min(token.len())]
    );

    let result = ParameterQueryBuilder::new()
        .with_token(&token)
        .check_role("admin")
        .await;
    println!("    with_token(&token).check_role(\"admin\") → Ok(()) ✓");
    assert!(result.is_ok(), "持有角色应返回 Ok，实际: {:?}", result);

    // 未持有角色 → NotRole
    let denied_role = ParameterQueryBuilder::new()
        .with_token(&token)
        .check_role("superadmin")
        .await;
    match denied_role {
        Err(BulwarkError::NotRole(role)) => {
            println!(
                "    with_token(&token).check_role(\"superadmin\") → Err(NotRole(\"{}\"))",
                role
            );
        },
        other => panic!("期望 NotRole，实际: {:?}", other),
    }
    println!();

    // ----------------------------------------------------------------
    // 4. 未设置上下文时返回 Internal 错误
    // ----------------------------------------------------------------
    println!("[无上下文] 未设置 login_id / token:");
    let result = ParameterQueryBuilder::new()
        .check_permission("user:read")
        .await;
    match result {
        Err(BulwarkError::Internal(msg)) => {
            println!(
                "    check_permission(\"user:read\") → Err(Internal(\"{}\"))",
                msg
            );
            assert!(msg.contains("login_id not set"));
        },
        other => panic!("期望 Internal 错误，实际: {:?}", other),
    }

    let result = ParameterQueryBuilder::new().check_role("admin").await;
    match result {
        Err(BulwarkError::Internal(msg)) => {
            println!(
                "    check_role(\"admin\")         → Err(Internal(\"{}\"))",
                msg
            );
            assert!(msg.contains("login_id not set"));
        },
        other => panic!("期望 Internal 错误，实际: {:?}", other),
    }

    println!("\n=== 示例完成 ===");
    Ok(())
}
