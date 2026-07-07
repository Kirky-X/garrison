//! 权限校验示例：演示 PermissionChecker trait 与 PermissionCheckerDefault 默认实现。
//!
//! 对应模块：`src/core/permission/mod.rs`（always on，无需 feature）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin permission_check --features full
//! ```

use async_trait::async_trait;
use bulwark::core::permission::{PermissionChecker, PermissionCheckerDefault};
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::stp::BulwarkInterface;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// 业务方实现 BulwarkInterface：提供 login_id → 权限/角色列表
// ============================================================================

/// 示例接口实现：基于内存 HashMap 存储 login_id 的权限与角色。
///
/// 生产环境通常从数据库或 RBAC 系统读取。
pub struct MyInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MyInterface {
    /// 创建接口实例，预置 login_id=1001 的权限与角色。
    pub fn new() -> Self {
        let mut permissions = HashMap::new();
        // 账号 1001 持有 user:read / user:write 权限
        permissions.insert(
            "1001".to_string(),
            vec!["user:read".to_string(), "user:write".to_string()],
        );
        let mut roles = HashMap::new();
        // 账号 1001 持有 admin / user 角色
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

/// 运行权限校验示例。
///
/// 演示 PermissionCheckerDefault 的 has_permission / has_role / check_permission / check_role
/// 以及 has_any_permission / has_all_permissions 批量校验。
pub async fn run() -> BulwarkResult<()> {
    println!("=== Bulwark 权限校验示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 构建 PermissionCheckerDefault（注入 BulwarkInterface）
    // ----------------------------------------------------------------
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface::new());
    let checker = PermissionCheckerDefault::new(interface);
    println!("[1] PermissionCheckerDefault 构建完成");
    println!("    账号 1001 权限: [user:read, user:write]");
    println!("    账号 1001 角色: [admin, user]\n");

    // ----------------------------------------------------------------
    // 2. has_permission / has_role 查询
    // ----------------------------------------------------------------
    let has_read = checker.has_permission("1001", "user:read").await?;
    let has_delete = checker.has_permission("1001", "user:delete").await?;
    println!("[2] has_permission:");
    println!("    user:read  → {}（持有）", has_read);
    println!("    user:delete → {}（未持有）\n", has_delete);
    assert!(has_read);
    assert!(!has_delete);

    let is_admin = checker.has_role("1001", "admin").await?;
    let is_super = checker.has_role("1001", "superadmin").await?;
    println!("[3] has_role:");
    println!("    admin     → {}（持有）", is_admin);
    println!("    superadmin → {}（未持有）\n", is_super);
    assert!(is_admin);
    assert!(!is_super);

    // ----------------------------------------------------------------
    // 3. check_permission / check_role 断言（失败抛异常）
    // ----------------------------------------------------------------
    println!("[4] check_permission / check_role 断言:");
    // 持有权限 → Ok(())
    checker.check_permission("1001", "user:read").await?;
    println!("    check_permission(\"user:read\")  → Ok(()) ✓");
    checker.check_role("1001", "admin").await?;
    println!("    check_role(\"admin\")            → Ok(()) ✓");

    // 未持有权限 → Err(NotPermission)
    let denied = checker.check_permission("1001", "user:delete").await;
    match denied {
        Err(BulwarkError::NotPermission(msg)) => {
            println!("    check_permission(\"user:delete\") → Err(NotPermission)");
            println!("        消息: {}", msg);
        },
        other => panic!("期望 NotPermission，实际: {:?}", other),
    }

    // 未持有角色 → Err(NotRole)
    let denied_role = checker.check_role("1001", "superadmin").await;
    match denied_role {
        Err(BulwarkError::NotRole(msg)) => {
            println!("    check_role(\"superadmin\")       → Err(NotRole)");
            println!("        消息: {}\n", msg);
        },
        other => panic!("期望 NotRole，实际: {:?}", other),
    }

    // ----------------------------------------------------------------
    // 4. has_any_permission / has_all_permissions 批量校验
    // ----------------------------------------------------------------
    let any_ok = checker
        .has_any_permission("1001", &["user:read", "user:delete"])
        .await;
    let any_fail = checker
        .has_any_permission("1001", &["user:delete", "user:create"])
        .await;
    println!("[5] has_any_permission（任一满足即 true）:");
    println!(
        "    [user:read,  user:delete] → {}（user:read 命中）",
        any_ok
    );
    println!(
        "    [user:delete, user:create] → {}（均未命中）\n",
        any_fail
    );
    assert!(any_ok);
    assert!(!any_fail);

    let all_ok = checker
        .has_all_permissions("1001", &["user:read", "user:write"])
        .await;
    let all_fail = checker
        .has_all_permissions("1001", &["user:read", "user:delete"])
        .await;
    println!("[6] has_all_permissions（全部满足才 true）:");
    println!("    [user:read, user:write]  → {}（全部持有）", all_ok);
    println!(
        "    [user:read, user:delete] → {}（user:delete 缺失）\n",
        all_fail
    );
    assert!(all_ok);
    assert!(!all_fail);

    println!("=== 示例执行完成 ===");
    Ok(())
}
