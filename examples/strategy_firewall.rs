//! 防火墙策略示例：演示 BulwarkFirewallStrategy trait 与自定义策略实现。
//!
//! 流程：
//! 1. 实现 BulwarkFirewallStrategy trait（自定义权限/角色来源）
//! 2. 创建 BulwarkFirewallStrategyDefault（基于 BulwarkInterface）
//! 3. check_permission 权限校验
//! 4. check_role 角色校验
//! 5. check_role_any 任一角色匹配
//! 6. check_role_all 全部角色匹配
//! 7. 空字符串校验（Fail Loud）
//!
//! 运行方式：
//! ```sh
//! cargo run --example strategy_firewall --features "cache-memory,web-axum"
//! ```

use async_trait::async_trait;
use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::manager::BulwarkManager;
use bulwark::prelude::*;
use bulwark::stp::BulwarkInterface;
use bulwark::strategy::{BulwarkFirewallStrategy, BulwarkFirewallStrategyDefault};
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// 自定义防火墙策略：基于内存 HashMap 直接提供权限/角色数据
// ============================================================================

/// 示例自定义策略：绕过 BulwarkInterface，直接从 HashMap 读取权限/角色。
struct CustomFirewall {
    permissions: HashMap<i64, Vec<String>>,
    roles: HashMap<i64, Vec<String>>,
}

impl CustomFirewall {
    fn new() -> Self {
        let mut permissions = HashMap::new();
        permissions.insert(
            1001,
            vec!["user:read".to_string(), "user:write".to_string()],
        );
        permissions.insert(1002, vec!["user:read".to_string()]);

        let mut roles = HashMap::new();
        roles.insert(1001, vec!["admin".to_string(), "user".to_string()]);
        roles.insert(1002, vec!["user".to_string()]);

        Self { permissions, roles }
    }
}

#[async_trait]
impl BulwarkFirewallStrategy for CustomFirewall {
    async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        Ok(self.permissions.get(&login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        Ok(self.roles.get(&login_id).cloned().unwrap_or_default())
    }

    async fn check_permission(&self, login_id: i64, permission: &str) -> BulwarkResult<bool> {
        if permission.is_empty() {
            return Err(BulwarkError::InvalidToken("权限不能为空".to_string()));
        }
        let perms = self.get_permission_list(login_id).await?;
        Ok(perms.iter().any(|p| p == permission))
    }

    async fn check_role(&self, login_id: i64, role: &str) -> BulwarkResult<bool> {
        if role.is_empty() {
            return Err(BulwarkError::InvalidToken("角色不能为空".to_string()));
        }
        let roles = self.get_role_list(login_id).await?;
        Ok(roles.iter().any(|r| r == role))
    }

    async fn check_role_any(&self, login_id: i64, roles: &[&str]) -> BulwarkResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        Ok(roles.iter().any(|r| user_roles.iter().any(|ur| ur == r)))
    }

    async fn check_role_all(&self, login_id: i64, roles: &[&str]) -> BulwarkResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        Ok(roles.iter().all(|r| user_roles.iter().any(|ur| ur == r)))
    }
}

// ============================================================================
// BulwarkInterface 实现（用于 BulwarkFirewallStrategyDefault）
// ============================================================================

struct MyInterface {
    permissions: HashMap<i64, Vec<String>>,
    roles: HashMap<i64, Vec<String>>,
}

impl MyInterface {
    fn new() -> Self {
        let mut permissions = HashMap::new();
        permissions.insert(1001, vec!["user:read".to_string(), "user:write".to_string()]);
        let mut roles = HashMap::new();
        roles.insert(1001, vec!["admin".to_string()]);
        Self { permissions, roles }
    }
}

#[async_trait]
impl BulwarkInterface for MyInterface {
    async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        Ok(self.permissions.get(&login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        Ok(self.roles.get(&login_id).cloned().unwrap_or_default())
    }
}

#[tokio::main]
async fn main() -> BulwarkResult<()> {
    println!("=== Bulwark 防火墙策略示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 自定义策略直接使用
    // ----------------------------------------------------------------
    let firewall = CustomFirewall::new();
    println!("[1] 自定义策略 CustomFirewall:");

    let has_perm = firewall.check_permission(1001, "user:read").await?;
    println!("    check_permission(1001, \"user:read\") = {}", has_perm);

    let no_perm = firewall.check_permission(1001, "user:delete").await?;
    println!("    check_permission(1001, \"user:delete\") = {}", no_perm);

    let has_role = firewall.check_role(1001, "admin").await?;
    println!("    check_role(1001, \"admin\") = {}", has_role);
    println!();

    // ----------------------------------------------------------------
    // 2. BulwarkFirewallStrategyDefault（基于 BulwarkInterface）
    // ----------------------------------------------------------------
    let interface = Arc::new(MyInterface::new());
    let default_fw = BulwarkFirewallStrategyDefault::new(interface);
    println!("[2] BulwarkFirewallStrategyDefault:");

    let perms = default_fw.get_permission_list(1001).await?;
    println!("    get_permission_list(1001) = {:?}", perms);

    let roles = default_fw.get_role_list(1001).await?;
    println!("    get_role_list(1001) = {:?}", roles);

    let held = default_fw.check_permission(1001, "user:read").await?;
    println!("    check_permission(1001, \"user:read\") = {}", held);
    println!();

    // ----------------------------------------------------------------
    // 3. check_role_any 任一匹配
    // ----------------------------------------------------------------
    println!("[3] check_role_any:");
    let any_match = firewall.check_role_any(1001, &["admin", "superuser"]).await?;
    println!("    check_role_any(1001, [\"admin\", \"superuser\"]) = {}", any_match);

    let any_no_match = firewall.check_role_any(1002, &["admin", "superuser"]).await?;
    println!("    check_role_any(1002, [\"admin\", \"superuser\"]) = {}", any_no_match);
    println!();

    // ----------------------------------------------------------------
    // 4. check_role_all 全部匹配
    // ----------------------------------------------------------------
    println!("[4] check_role_all:");
    let all_match = firewall.check_role_all(1001, &["admin", "user"]).await?;
    println!("    check_role_all(1001, [\"admin\", \"user\"]) = {}", all_match);

    let all_no_match = firewall.check_role_all(1001, &["admin", "superuser"]).await?;
    println!("    check_role_all(1001, [\"admin\", \"superuser\"]) = {}", all_no_match);
    println!();

    // ----------------------------------------------------------------
    // 5. 空字符串校验（Fail Loud）
    // ----------------------------------------------------------------
    println!("[5] 空字符串校验:");
    let empty_perm = firewall.check_permission(1001, "").await;
    println!("    check_permission(1001, \"\") → {:?}", empty_perm.err().map(|e| e.to_string()));

    let empty_role = firewall.check_role(1001, "").await;
    println!("    check_role(1001, \"\") → {:?}", empty_role.err().map(|e| e.to_string()));
    println!();

    // ----------------------------------------------------------------
    // 6. 集成到 BulwarkManager（完整业务场景）
    // ----------------------------------------------------------------
    println!("[6] 集成到 BulwarkManager:");
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await?);
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface::new());
    BulwarkManager::init(dao, config, interface)?;
    println!("    BulwarkManager 初始化完成（使用 BulwarkFirewallStrategyDefault）");
    println!("    可通过 BulwarkUtil::check_permission/check_role 调用");

    println!("\n=== 示例执行完成 ===");
    Ok(())
}
