//! 基础登录示例：演示 Bulwark 完整业务场景的最小可用登录流程。
//!
//! 流程：
//! 1. 准备依赖（DAO + Config + Interface）
//! 2. 初始化 BulwarkManager
//! 3. 执行登录（login）
//! 4. 在 task_local 上下文中校验登录状态（check_login / get_login_id）
//! 5. 执行权限校验（check_permission / check_role）
//! 6. 执行登出（logout）
//! 7. 验证登出后校验失败
//!
//! 运行方式：
//! ```sh
//! cargo run --example basic_login --features "cache-memory,web-axum"
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
// 业务方实现 BulwarkInterface：提供权限/角色数据
// ============================================================================

/// 示例接口实现：基于内存 HashMap 存储 login_id → 权限/角色列表。
///
/// 生产环境通常从数据库或 RBAC 系统读取，此处仅作演示。
struct MyInterface {
    permissions: HashMap<i64, Vec<String>>,
    roles: HashMap<i64, Vec<String>>,
}

impl MyInterface {
    fn new() -> Self {
        // 为 login_id=1001 预置权限与角色
        let mut permissions = HashMap::new();
        permissions.insert(
            1001,
            vec!["user:read".to_string(), "user:write".to_string()],
        );
        let mut roles = HashMap::new();
        roles.insert(1001, vec!["admin".to_string()]);
        Self {
            permissions,
            roles,
        }
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
    println!("=== Bulwark 基础登录示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 准备依赖：DAO + Config + Interface
    // ----------------------------------------------------------------

    // 使用 oxcache 内存后端（无需外部数据库，对应 cache-memory feature）
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await?);

    // 使用默认配置（timeout=30天，token_style=uuid，throw_on_not_login=true）
    let config = Arc::new(BulwarkConfig::default_config());

    // 业务方接口实现（提供权限/角色数据）
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface::new());

    // ----------------------------------------------------------------
    // 2. 初始化 BulwarkManager（注入全局单例）
    // ----------------------------------------------------------------
    BulwarkManager::init(dao, config, interface)?;
    println!("[1] BulwarkManager 初始化完成");

    // ----------------------------------------------------------------
    // 3. 执行登录：生成 token 并创建会话
    // ----------------------------------------------------------------
    let token = BulwarkUtil::login(1001).await?;
    println!("[2] 登录成功，login_id=1001");
    println!("    token={}\n", token);

    // ----------------------------------------------------------------
    // 4-6. 在 task_local 上下文中执行校验与登出
    // ----------------------------------------------------------------
    // 注意：check_login / get_login_id / logout 等方法依赖 task_local 中的 token，
    // 实际应用中由 Web 中间件（如 axum middleware）设置；此处显式调用 with_current_token。
    let token_for_closure = token.clone();
    with_current_token(token_for_closure, async {
        // 4. 校验登录状态
        let logged_in = BulwarkUtil::check_login().await?;
        println!("[3] check_login 返回: {}", logged_in);

        let login_id = BulwarkUtil::get_login_id().await?;
        println!("[4] get_login_id 返回: {:?}", login_id);

        // 5. 权限/角色校验
        BulwarkUtil::check_permission("user:read").await?;
        println!("[5] check_permission(\"user:read\") 通过");

        BulwarkUtil::check_role("admin").await?;
        println!("[6] check_role(\"admin\") 通过\n");

        // 6. 执行登出
        BulwarkUtil::logout().await?;
        println!("[7] logout 完成");

        Ok::<(), BulwarkError>(())
    })
    .await?;

    // ----------------------------------------------------------------
    // 7. 验证登出后校验失败
    // ----------------------------------------------------------------
    // 登出后再次 check_login：由于默认 throw_on_not_login=true，会返回 Session 错误。
    let result = with_current_token(token.clone(), async { BulwarkUtil::check_login().await })
        .await;

    match result {
        Ok(false) => println!("[8] 登出后 check_login 返回 false（校验失败，符合预期）"),
        Ok(true) => {
            return Err(BulwarkError::Session(
                "登出后 check_login 应返回 false 或错误".to_string(),
            ))
        }
        Err(e) => println!("[8] 登出后 check_login 返回错误（校验失败，符合预期）: {}", e),
    }

    println!("\n=== 示例执行完成 ===");
    Ok(())
}
