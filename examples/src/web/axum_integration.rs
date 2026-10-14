// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! axum 集成示例：完整 Web 应用演示。
//!
//! 流程：实现 `GarrisonInterface` → oxcache DAO + 默认配置初始化 `GarrisonManager` → 定义 `RoleName` / `PermissionName` marker struct → `GarrisonRouter` + `route_protected` 注册受保护路由（Ignore / CheckLogin / CheckRole / CheckPermission）→ 启动 HTTP 服务器（`127.0.0.1:3000`）。
//!
//! # 运行
//!
//! ```bash
//! cargo run -p garrison-examples --bin axum_integration --features "cache-memory,web-axum"
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
use axum::Router;
use garrison::annotation::{Annotation, PermissionName, RoleName};
use garrison::dao::{GarrisonDao, GarrisonDaoOxcache};
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::prelude::*;
use garrison::stp::GarrisonInterface;
use serde_json::{json, Value};
use std::sync::Arc;

// 1. 定义 marker struct（用于泛型 extractor 的类型级参数）

/// admin 角色 marker struct（类型级 API 演示）。
pub struct AdminRole;
impl RoleName for AdminRole {
    const NAME: &'static str = "admin";
}

/// data:read 权限 marker struct（类型级 API 演示）。
pub struct ReadPerm;
impl PermissionName for ReadPerm {
    const NAME: &'static str = "data:read";
}

// 2. 实现 GarrisonInterface（提供权限 / 角色数据回调）

/// 业务方接口实现：login_id=1001 持有 data:read 权限 + admin 角色，其他 login_id 返回空列表（无权限 / 无角色）。
pub struct MyInterface;

impl MyInterface {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MyInterface {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GarrisonInterface for MyInterface {
    async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        match login_id {
            "1001" => Ok(vec!["data:read".to_string()]),
            _ => Ok(vec![]),
        }
    }

    async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        match login_id {
            "1001" => Ok(vec!["admin".to_string()]),
            _ => Ok(vec![]),
        }
    }
}

// 3. axum handlers

/// 公开接口（`Ignore` 注解，无需登录）。
pub async fn public_handler() -> Json<Value> {
    Json(json!({ "msg": "public", "desc": "public endpoint, no auth required" }))
}

/// 用户信息接口（`CheckLogin` 注解，需登录）。
pub async fn user_info_handler() -> Json<Value> {
    Json(json!({ "user": "info", "desc": "accessible to logged-in users" }))
}

/// 管理面板接口（`CheckRole<AdminRole>` 注解，需 admin 角色）。
pub async fn admin_dashboard_handler() -> Json<Value> {
    Json(json!({ "admin": "dashboard", "desc": "admin role only" }))
}

/// 数据查询接口（`CheckPermission<ReadPerm>` 注解，需 data:read 权限）。
pub async fn data_query_handler() -> Json<Value> {
    Json(json!({ "data": "query", "desc": "data:read permission required" }))
}

// 4. setup：初始化 + 路由注册（不启动服务器，便于测试）

/// 准备 axum app 与测试 token（不启动 HTTP 服务器）：创建 DAO + 配置 + Interface、builder 注入全局单例、login(1001) 生成 token、注册 4 个受保护路由。
/// 返回 `(router, token)`；调用会覆盖全局 `GarrisonManager` 单例，多测试并行需 `#[serial_test::serial]`。
pub async fn setup() -> GarrisonResult<(Router, String)> {
    // 准备依赖：DAO + Config + Interface
    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await?);

    // 全局配置：基于默认值调整，便于演示鉴权失败场景
    let mut config = GarrisonConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    let config = Arc::new(config);

    let interface: Arc<dyn GarrisonInterface> = Arc::new(MyInterface::new());

    // 初始化全局 GarrisonManager
    GarrisonManager::builder()
        .dao(dao)
        .config(config.clone())
        .interface(interface)
        .build()
        .await?;

    // 模拟登录获取测试 token
    let token = GarrisonUtil::login_simple("1001").await?;
    assert!(!token.is_empty(), "login 应返回非空 token");

    // 创建 axum app，使用 GarrisonRouter + route_protected
    let app = GarrisonRouter::new(config)
        .route_protected("/api/public", public_handler, Annotation::Ignore)
        .route_protected("/api/user/info", user_info_handler, Annotation::CheckLogin)
        .route_protected(
            "/api/admin/dashboard",
            admin_dashboard_handler,
            Annotation::CheckRole("admin".to_string()),
        )
        .route_protected(
            "/api/data/query",
            data_query_handler,
            Annotation::CheckPermission("data:read".to_string()),
        )
        .build();

    Ok((app, token))
}

// 5. main：setup + 启动服务器

/// 运行 axum 集成示例：调用 [`setup`] 完成初始化与路由注册，绑定 `127.0.0.1:3000` 启动 HTTP 服务器（运行至 Ctrl+C）。
pub async fn run() -> GarrisonResult<()> {
    let (app, token) = setup().await?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .map_err(|e| GarrisonError::Internal(format!("failed to bind listener: {}", e)))?;

    println!("======================================================");
    println!("Garrison axum 集成示例已启动: http://127.0.0.1:3000");
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
        .map_err(|e| GarrisonError::Internal(format!("server failed to run: {}", e)))?;

    Ok(())
}
