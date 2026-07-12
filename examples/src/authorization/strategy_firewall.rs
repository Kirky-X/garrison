//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 防火墙策略示例：演示 BulwarkPermissionStrategy trait 与自定义策略实现。
//!
//! 流程：
//! 1. 实现 BulwarkPermissionStrategy trait（自定义权限/角色来源）
//! 2. 创建 BulwarkPermissionStrategyDefault（基于 BulwarkInterface）
//! 3. check_permission 权限校验
//! 4. check_role 角色校验
//! 5. check_role_any 任一角色匹配
//! 6. check_role_all 全部角色匹配
//! 7. 空字符串校验（Fail Loud）
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin strategy_firewall --features "cache-memory,web-axum"
//! ```

use async_trait::async_trait;
use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::manager::BulwarkManager;
use bulwark::prelude::*;
use bulwark::stp::BulwarkInterface;
use bulwark::strategy::{BulwarkPermissionStrategy, BulwarkPermissionStrategyDefault};
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// 自定义防火墙策略：基于内存 HashMap 直接提供权限/角色数据
// ============================================================================

/// 示例自定义策略：绕过 BulwarkInterface，直接从 HashMap 读取权限/角色。
pub struct CustomFirewall {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl CustomFirewall {
    /// 创建 CustomFirewall 实例。
    ///
    /// 预置数据：
    /// - login_id=1001：权限 `["user:read", "user:write"]`，角色 `["admin", "user"]`
    /// - login_id=1002：权限 `["user:read"]`，角色 `["user"]`
    pub fn new() -> Self {
        let mut permissions = HashMap::new();
        permissions.insert(
            "1001".to_string(),
            vec!["user:read".to_string(), "user:write".to_string()],
        );
        permissions.insert("1002".to_string(), vec!["user:read".to_string()]);

        let mut roles = HashMap::new();
        roles.insert(
            "1001".to_string(),
            vec!["admin".to_string(), "user".to_string()],
        );
        roles.insert("1002".to_string(), vec!["user".to_string()]);

        Self { permissions, roles }
    }
}

impl Default for CustomFirewall {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BulwarkPermissionStrategy for CustomFirewall {
    async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.roles.get(login_id).cloned().unwrap_or_default())
    }

    async fn check_permission(&self, login_id: &str, permission: &str) -> BulwarkResult<bool> {
        if permission.is_empty() {
            return Err(BulwarkError::InvalidToken("权限不能为空".to_string()));
        }
        let perms = self.get_permission_list(login_id).await?;
        Ok(perms.iter().any(|p| p == permission))
    }

    async fn check_role(&self, login_id: &str, role: &str) -> BulwarkResult<bool> {
        if role.is_empty() {
            return Err(BulwarkError::InvalidToken("角色不能为空".to_string()));
        }
        let roles = self.get_role_list(login_id).await?;
        Ok(roles.iter().any(|r| r == role))
    }

    async fn check_role_any(&self, login_id: &str, roles: &[&str]) -> BulwarkResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        Ok(roles.iter().any(|r| user_roles.iter().any(|ur| ur == r)))
    }

    async fn check_role_all(&self, login_id: &str, roles: &[&str]) -> BulwarkResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        Ok(roles.iter().all(|r| user_roles.iter().any(|ur| ur == r)))
    }
}

// ============================================================================
// BulwarkInterface 实现（用于 BulwarkPermissionStrategyDefault）
// ============================================================================

/// 示例 BulwarkInterface 实现，仅提供 login_id=1001 的权限/角色。
pub struct MyInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MyInterface {
    /// 创建 MyInterface 实例。
    ///
    /// 预置数据：login_id=1001 持有 `["user:read", "user:write"]` 权限 + `["admin"]` 角色。
    pub fn new() -> Self {
        let mut permissions = HashMap::new();
        permissions.insert(
            "1001".to_string(),
            vec!["user:read".to_string(), "user:write".to_string()],
        );
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

/// 运行防火墙策略示例。
///
/// 演示 CustomFirewall 自定义策略与 BulwarkPermissionStrategyDefault 的
/// check_permission / check_role / check_role_any / check_role_all 校验，
/// 以及空字符串 Fail Loud 行为，最后集成到 BulwarkManager。
pub async fn run() -> BulwarkResult<()> {
    println!("=== Bulwark 防火墙策略示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 自定义策略直接使用
    // ----------------------------------------------------------------
    let firewall = CustomFirewall::new();
    println!("[1] 自定义策略 CustomFirewall:");

    let has_perm = firewall.check_permission("1001", "user:read").await?;
    println!("    check_permission(1001, \"user:read\") = {}", has_perm);
    assert!(has_perm, "1001 应持有 user:read 权限");

    let no_perm = firewall.check_permission("1001", "user:delete").await?;
    println!("    check_permission(1001, \"user:delete\") = {}", no_perm);
    assert!(!no_perm, "1001 不应持有 user:delete 权限");

    let has_role = firewall.check_role("1001", "admin").await?;
    println!("    check_role(1001, \"admin\") = {}", has_role);
    assert!(has_role, "1001 应持有 admin 角色");
    println!();

    // ----------------------------------------------------------------
    // 2. BulwarkPermissionStrategyDefault（基于 BulwarkInterface）
    // ----------------------------------------------------------------
    let interface = Arc::new(MyInterface::new());
    let default_fw = BulwarkPermissionStrategyDefault::new(interface);
    println!("[2] BulwarkPermissionStrategyDefault:");

    let perms = default_fw.get_permission_list("1001").await?;
    println!("    get_permission_list(1001) = {:?}", perms);
    assert!(perms.contains(&"user:read".to_string()));

    let roles = default_fw.get_role_list("1001").await?;
    println!("    get_role_list(1001) = {:?}", roles);
    assert!(roles.contains(&"admin".to_string()));

    let held = default_fw.check_permission("1001", "user:read").await?;
    println!("    check_permission(1001, \"user:read\") = {}", held);
    assert!(held);
    println!();

    // ----------------------------------------------------------------
    // 3. check_role_any 任一匹配
    // ----------------------------------------------------------------
    println!("[3] check_role_any:");
    let any_match = firewall
        .check_role_any("1001", &["admin", "superuser"])
        .await?;
    println!(
        "    check_role_any(1001, [\"admin\", \"superuser\"]) = {}",
        any_match
    );
    assert!(any_match, "1001 持有 admin，应任一匹配");

    let any_no_match = firewall
        .check_role_any("1002", &["admin", "superuser"])
        .await?;
    println!(
        "    check_role_any(1002, [\"admin\", \"superuser\"]) = {}",
        any_no_match
    );
    assert!(!any_no_match, "1002 不持有 admin/superuser");
    println!();

    // ----------------------------------------------------------------
    // 4. check_role_all 全部匹配
    // ----------------------------------------------------------------
    println!("[4] check_role_all:");
    let all_match = firewall.check_role_all("1001", &["admin", "user"]).await?;
    println!(
        "    check_role_all(1001, [\"admin\", \"user\"]) = {}",
        all_match
    );
    assert!(all_match, "1001 应同时持有 admin 和 user");

    let all_no_match = firewall
        .check_role_all("1001", &["admin", "superuser"])
        .await?;
    println!(
        "    check_role_all(1001, [\"admin\", \"superuser\"]) = {}",
        all_no_match
    );
    assert!(!all_no_match, "1001 不持有 superuser");
    println!();

    // ----------------------------------------------------------------
    // 5. 空字符串校验（Fail Loud）
    // ----------------------------------------------------------------
    println!("[5] 空字符串校验:");
    let empty_perm = firewall.check_permission("1001", "").await;
    let perm_err = empty_perm.as_ref().err().map(|e| e.to_string());
    println!("    check_permission(1001, \"\") → {:?}", perm_err);
    assert!(empty_perm.is_err(), "空权限应返回错误（Fail Loud）");

    let empty_role = firewall.check_role("1001", "").await;
    let role_err = empty_role.as_ref().err().map(|e| e.to_string());
    println!("    check_role(1001, \"\") → {:?}", role_err);
    assert!(empty_role.is_err(), "空角色应返回错误（Fail Loud）");
    println!();

    // ----------------------------------------------------------------
    // 6. 集成到 BulwarkManager（完整业务场景）
    // ----------------------------------------------------------------
    println!("[6] 集成到 BulwarkManager:");
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await?);
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface::new());
    BulwarkManager::init(dao, config, interface)?;
    println!("    BulwarkManager 初始化完成（使用 BulwarkPermissionStrategyDefault）");
    println!("    可通过 BulwarkUtil::check_permission/check_role 调用");

    println!("\n=== 示例执行完成 ===");
    Ok(())
}
