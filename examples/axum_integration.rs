//! axum 集成示例：完整 Web 应用演示。
//!
//! 演示 Bulwark + axum 的注解系统集成的完整流程：
//! 1. 实现 `BulwarkInterface` 提供权限 / 角色数据回调
//! 2. 使用 oxcache DAO + 默认配置 + Interface 初始化 `BulwarkManager`
//! 3. 定义 `RoleName` / `PermissionName` marker struct（类型级参数）
//! 4. 创建 axum app，使用 `BulwarkRouter` + `route_protected` 语法糖
//! 5. 注册多个受保护路由（`Ignore` / `CheckLogin` / `CheckRole` / `CheckPermission`）
//! 6. 启动 HTTP 服务器（绑定 `127.0.0.1:3000`）
//!
//! # 编译
//!
//! ```bash
//! cargo build --example axum_integration --features "cache-memory,web-axum"
//! ```
//!
//! # 运行
//!
//! ```bash
//! cargo run --example axum_integration --features "cache-memory,web-axum"
//! ```
//!
//! # 测试
//!
//! 启动后另开终端，按控制台输出的 `测试 token` 与命令进行 curl 测试：
//!
//! ```bash
//! # 1. 公开接口（Ignore 注解，无需 token）
//! curl http://127.0.0.1:3000/api/public
//!
//! # 2. 将控制台输出的 token 设为环境变量
//! TOKEN="<控制台输出的 token>"
//!
//! # 3. CheckLogin 注解（需登录）
//! curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3000/api/user/info
//!
//! # 4. CheckRole 注解（需 admin 角色）
//! curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3000/api/admin/dashboard
//!
//! # 5. CheckPermission 注解（需 data:read 权限）
//! curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3000/api/data/query
//!
//! # 6. 无 token 访问受保护接口 → 401 未登录
//! curl -i http://127.0.0.1:3000/api/user/info
//! ```

use async_trait::async_trait;
use axum::response::Json;
use bulwark::annotation::{Annotation, PermissionName, RoleName};
use bulwark::dao::BulwarkDaoOxcache;
use bulwark::prelude::*;
use serde_json::{json, Value};
use std::sync::Arc;

// ============================================================================
// 1. 定义 marker struct（用于泛型 extractor 的类型级参数）
// ============================================================================
//
// 通过关联常量 `NAME` 把角色 / 权限名编码到类型层面，
// 配合 `CheckRole<R>` / `CheckPermission<P>` extractor 使用：
//   async fn handler(_: CheckRole<AdminRole>) -> ... { ... }
//
// 本示例的路由鉴权走 `route_protected` + `Annotation` 枚举（字符串）的 middleware 路径，
// marker struct 仅作类型级 API 演示；如需在 handler 参数中直接使用 extractor，
// 可将 handler 签名改为 `async fn admin_handler(_: CheckRole<AdminRole>)`。
#[allow(dead_code)]
struct AdminRole;
impl RoleName for AdminRole {
    const NAME: &'static str = "admin";
}

#[allow(dead_code)]
struct ReadPerm;
impl PermissionName for ReadPerm {
    const NAME: &'static str = "data:read";
}

// ============================================================================
// 2. 实现 BulwarkInterface（提供权限 / 角色数据回调）
// ============================================================================
//
// 实际场景中数据可来自数据库 / YAML / 外部服务，此处用硬编码简化演示：
// - `login_id=1001` 持有 `["data:read"]` 权限 + `["admin"]` 角色
// - 其他 `login_id` 返回空列表（无权限 / 无角色）

/// 业务方接口实现，返回指定 `login_id` 的权限 / 角色列表。
struct MyInterface;

impl MyInterface {
    /// 创建接口实例。
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl BulwarkInterface for MyInterface {
    async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        match login_id {
            1001 => Ok(vec!["data:read".to_string()]),
            _ => Ok(vec![]),
        }
    }

    async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        match login_id {
            1001 => Ok(vec!["admin".to_string()]),
            _ => Ok(vec![]),
        }
    }
}

// ============================================================================
// 3. axum handlers
// ============================================================================

/// 公开接口（`Ignore` 注解，无需登录）。
async fn public_handler() -> Json<Value> {
    Json(json!({ "msg": "public", "desc": "无需鉴权的公开接口" }))
}

/// 用户信息接口（`CheckLogin` 注解，需登录）。
async fn user_info_handler() -> Json<Value> {
    Json(json!({ "user": "info", "desc": "已登录用户可访问" }))
}

/// 管理面板接口（`CheckRole<AdminRole>` 注解，需 admin 角色）。
async fn admin_dashboard_handler() -> Json<Value> {
    Json(json!({ "admin": "dashboard", "desc": "仅 admin 角色可访问" }))
}

/// 数据查询接口（`CheckPermission<ReadPerm>` 注解，需 data:read 权限）。
async fn data_query_handler() -> Json<Value> {
    Json(json!({ "data": "query", "desc": "仅持有 data:read 权限可访问" }))
}

// ============================================================================
// 4. main：初始化 + 路由注册 + 启动服务器
// ============================================================================

#[tokio::main]
async fn main() -> BulwarkResult<()> {
    // --- 4.1 准备依赖：DAO + Config + Interface ---
    // 使用 oxcache 内存后端（无需外部数据库，便于示例直接运行）
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await?);

    // 全局配置：基于默认值调整，便于演示鉴权失败场景
    // - `timeout=3600`：token 1 小时过期
    // - `active_timeout=-1`：不启用活动超时（保留 Sa-Token 语义）
    // - `throw_on_not_login=false`：未登录返回 `NotLogin`（401）而非 `Session`（500），
    //   便于演示鉴权失败的 HTTP 语义
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    let config = Arc::new(config);

    // 业务方接口实现（提供权限 / 角色数据回调）
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface::new());

    // --- 4.2 初始化全局 BulwarkManager ---
    // 覆盖式注入 dao / config / interface，构造默认 `BulwarkLogic` 单例。
    // 此后即可通过 `BulwarkUtil::login` 等静态方法调用。
    BulwarkManager::init(dao, config.clone(), interface)?;

    // --- 4.3 模拟登录获取测试 token ---
    // 实际场景由 `/login` 接口处理：用户提交账号密码 → 后端校验通过后调用
    // `BulwarkUtil::login(login_id)` 生成 token 并写入会话。
    // 此处直接为 `login_id=1001`（持有 admin 角色 + data:read 权限）生成 token，
    // 便于示例运行后立即测试受保护接口。
    let token = BulwarkUtil::login(1001).await?;

    // --- 4.4 创建 axum app，使用 BulwarkRouter + route_protected 语法糖 ---
    // `route_protected` 同时完成两件事：
    //   1. 在 axum::Router 上注册 GET 路由
    //   2. 记录鉴权规则（path + annotation），由 middleware 在请求时按 path 匹配并执行
    //
    // middleware 流程：从 header / cookie 提取 token → 设置 task_local →
    // 调用 `DefaultBulwarkInterceptor::pre_handle` → 执行 handler
    let app = BulwarkRouter::new(config)
        // Ignore 注解：跳过鉴权，匿名可访问 → 200
        .route_protected("/api/public", public_handler, Annotation::Ignore)
        // CheckLogin 注解：校验登录状态（未登录 → 401）
        .route_protected("/api/user/info", user_info_handler, Annotation::CheckLogin)
        // CheckRole 注解：校验角色 "admin"（未持有 → 403）
        // 注：此处用字符串形式与 route_protected 配合；marker struct AdminRole
        // 主要用于 handler 参数形式的 extractor 用法。
        .route_protected(
            "/api/admin/dashboard",
            admin_dashboard_handler,
            Annotation::CheckRole("admin".to_string()),
        )
        // CheckPermission 注解：校验权限 "data:read"（未持有 → 403）
        .route_protected(
            "/api/data/query",
            data_query_handler,
            Annotation::CheckPermission("data:read".to_string()),
        )
        .build();

    // --- 4.5 启动 HTTP 服务器（绑定 127.0.0.1:3000） ---
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .map_err(|e| BulwarkError::Internal(format!("绑定监听地址失败: {}", e)))?;

    println!("======================================================");
    println!("Bulwark axum 集成示例已启动: http://127.0.0.1:3000");
    println!("======================================================");
    println!();
    println!("测试 token（login_id=1001，持有 admin 角色 + data:read 权限）:");
    println!("  {}", token);
    println!();
    println!("可用接口：");
    println!("  GET /api/public           （Ignore 注解，无需登录）");
    println!("  GET /api/user/info         （CheckLogin 注解，需登录）");
    println!("  GET /api/admin/dashboard   （CheckRole 注解，需 admin 角色）");
    println!("  GET /api/data/query        （CheckPermission 注解，需 data:read 权限）");
    println!();
    println!("测试命令（另开终端）：");
    println!("  # 1. 公开接口（无需 token）");
    println!("  curl http://127.0.0.1:3000/api/public");
    println!();
    println!("  # 2. 设置 token 后访问受保护接口");
    println!("  TOKEN=\"{}\"", token);
    println!("  curl -H \"Authorization: Bearer $TOKEN\" http://127.0.0.1:3000/api/user/info");
    println!(
        "  curl -H \"Authorization: Bearer $TOKEN\" http://127.0.0.1:3000/api/admin/dashboard"
    );
    println!("  curl -H \"Authorization: Bearer $TOKEN\" http://127.0.0.1:3000/api/data/query");
    println!();
    println!("  # 3. 无 token 访问受保护接口 → 401 未登录");
    println!("  curl -i http://127.0.0.1:3000/api/user/info");
    println!();
    println!("按 Ctrl+C 停止服务器");
    println!("======================================================");

    axum::serve(listener, app)
        .await
        .map_err(|e| BulwarkError::Internal(format!("服务器运行失败: {}", e)))?;

    Ok(())
}
