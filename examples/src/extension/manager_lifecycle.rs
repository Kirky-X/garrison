//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Manager 生命周期示例：演示 BulwarkManager 初始化、inventory 工厂与 task_local 上下文。
//!
//! 流程：
//! 1. 准备依赖（DAO + Config + Interface）
//! 2. BulwarkManager::init 注入全局单例
//! 3. BulwarkUtil 静态方法调用（login / check_login / get_login_id）
//! 4. task_local 上下文（with_current_token）
//! 5. 权限/角色校验（check_permission / check_role）
//! 6. 多账号登录与 kickout
//! 7. BulwarkManager::logic 获取底层 logic 实例
//! 8. 配置访问（BulwarkUtil::config）
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin manager_lifecycle --features "cache-memory,web-axum"
//! ```

use async_trait::async_trait;
use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::manager::BulwarkManager;
use bulwark::prelude::*;
use bulwark::stp::{with_current_token, BulwarkInterface, BulwarkUtil};
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// 业务方实现 BulwarkInterface
// ============================================================================

/// 示例 BulwarkInterface 实现，提供 login_id → 权限/角色列表。
///
/// 预置数据：
/// - login_id=1001：权限 `["user:read", "user:write"]`，角色 `["admin"]`
/// - login_id=1002：权限 `["user:read"]`，角色 `["user"]`
pub struct MyInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MyInterface {
    /// 创建 MyInterface 实例。
    pub fn new() -> Self {
        let mut permissions = HashMap::new();
        permissions.insert(
            "1001".to_string(),
            vec!["user:read".to_string(), "user:write".to_string()],
        );
        permissions.insert("1002".to_string(), vec!["user:read".to_string()]);

        let mut roles = HashMap::new();
        roles.insert("1001".to_string(), vec!["admin".to_string()]);
        roles.insert("1002".to_string(), vec!["user".to_string()]);

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

/// 运行 Manager 生命周期示例。
///
/// 演示 BulwarkManager::init 注入、BulwarkUtil 静态方法（login / check_login /
/// get_login_id / check_permission / check_role / kickout / logout）、
/// task_local 上下文（with_current_token）、底层 logic 与配置访问。
pub async fn run() -> BulwarkResult<()> {
    println!("=== Bulwark Manager 生命周期示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 准备依赖
    // ----------------------------------------------------------------
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await?);
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface::new());
    println!("[1] 依赖准备完成: DAO + Config + Interface");

    // ----------------------------------------------------------------
    // 2. BulwarkManager::init
    // ----------------------------------------------------------------
    BulwarkManager::init(dao, config, interface)?;
    println!("[2] BulwarkManager::init 完成（全局单例已注入）\n");

    // ----------------------------------------------------------------
    // 3. BulwarkUtil 静态方法：login
    // ----------------------------------------------------------------
    let token = BulwarkUtil::login("1001").await?;
    println!("[3] login(1001) → token={}...", &token[..16]);
    assert!(!token.is_empty(), "login 应返回非空 token");
    println!();

    // ----------------------------------------------------------------
    // 4. task_local 上下文
    // ----------------------------------------------------------------
    // 注意：check_login / get_login_id / check_permission 等依赖 task_local 中的 token。
    // 实际应用中由 Web 中间件设置；此处显式调用 with_current_token。
    println!("[4] task_local 上下文:");
    let token_clone = token.clone();
    let ctx_result: Result<(), BulwarkError> = with_current_token(token_clone, async {
        // 5. 校验登录状态
        let logged_in = BulwarkUtil::check_login().await?;
        println!("    check_login() = {}", logged_in);
        assert!(logged_in, "登录后 check_login 应返回 true");

        let login_id = BulwarkUtil::get_login_id().await?;
        println!("    get_login_id() = {:?}", login_id);
        assert_eq!(login_id, Some("1001".to_string()));

        // 6. 权限/角色校验
        BulwarkUtil::check_permission("user:read").await?;
        println!("    check_permission(\"user:read\") 通过");

        BulwarkUtil::check_role("admin").await?;
        println!("    check_role(\"admin\") 通过");

        Ok::<(), BulwarkError>(())
    })
    .await;
    ctx_result?;
    println!();

    // ----------------------------------------------------------------
    // 7. 多账号登录与 kickout
    // ----------------------------------------------------------------
    println!("[5] 多账号登录与 kickout:");
    let token2 = BulwarkUtil::login("1002").await?;
    println!("    login(1002) → token={}...", &token2[..16]);

    // 1002 有 user:read 权限但无 user:write
    let perm_result = with_current_token(token2.clone(), async {
        BulwarkUtil::check_permission("user:write").await
    })
    .await;
    let perm_err = perm_result.as_ref().err().map(|e| e.to_string());
    println!(
        "    check_permission(1002, \"user:write\") → {:?}",
        perm_err
    );
    assert!(perm_result.is_err(), "1002 无 user:write 权限应失败");

    // kickout 1002
    BulwarkUtil::kickout("1002").await?;
    println!("    kickout(1002) 完成");

    let valid_after_kickout =
        with_current_token(token2.clone(), async { BulwarkUtil::check_login().await }).await;
    let kickout_status = valid_after_kickout
        .as_ref()
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "Ok".to_string());
    println!("    踢出后 check_login → {:?}", kickout_status);
    assert!(
        valid_after_kickout.is_err() || matches!(valid_after_kickout, Ok(false)),
        "kickout 后 check_login 应失败或返回 false"
    );
    println!();

    // ----------------------------------------------------------------
    // 8. BulwarkManager::logic 获取底层实例
    // ----------------------------------------------------------------
    println!("[6] BulwarkManager 底层访问:");
    let logic = BulwarkManager::logic()?;
    println!(
        "    logic.config().token_style = {}",
        logic.config().token_style
    );
    println!("    logic.config().timeout = {} 秒", logic.config().timeout);

    // ----------------------------------------------------------------
    // 9. 配置访问（BulwarkUtil::config）
    // ----------------------------------------------------------------
    let config = BulwarkUtil::config()?;
    println!("[7] BulwarkUtil::config():");
    println!("    token_name = {}", config.token_name);
    println!("    is_read_header = {}", config.is_read_header);
    println!("    cookie_secure = {}", config.cookie_secure);

    // ----------------------------------------------------------------
    // 10. 登出当前 token
    // ----------------------------------------------------------------
    let token_clone = token.clone();
    with_current_token(token_clone, async {
        BulwarkUtil::logout().await?;
        println!("\n[8] logout() 完成");
        Ok::<(), BulwarkError>(())
    })
    .await?;

    println!("\n=== 示例执行完成 ===");
    Ok(())
}
