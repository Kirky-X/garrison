//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! actix-web 框架适配模块。
//!
//! 对应 actix-web 适配器，
//! 提供 BulwarkRouter + FromRequest extractor + BulwarkMiddleware 完整集成。
//!
//! ## 模块拆分（Rule 25 接口隔离）
//!
//! - `mod.rs`：pub struct 声明（BulwarkRouter/BulwarkMiddleware/BulwarkMiddlewareService/
//!   RouteRule/CheckLogin/CheckRole/CheckPermission）+ pub mod 声明 + pub use re-export
//! - `error.rs`：`HeaderLookup for HeaderMap` + `ResponseError for BulwarkError` 实现
//! - `router.rs`：`BulwarkRouter` 方法 + `Default` 实现
//! - `middleware.rs`：`Transform` + `Service` trait 实现（BulwarkMiddleware/BulwarkMiddlewareService）
//! - `extractor.rs`：`FromRequest` extractor 实现（BulwarkPrincipal/CheckLogin/CheckRole/
//!   CheckPermission/TenantContext）
//! - `mock.rs`：测试 mock（MockDao + MockInterface）
//! - `tests.rs`：集成测试
//!
//! ## 设计
//!
//! - `BulwarkRouter`：路由规则构建器，`route_protected` 注册路径 + 注解映射
//! - `BulwarkMiddleware`：actix-web middleware（Transform + Service），请求前调用 interceptor
//! - `CheckLogin` / `CheckRole` / `CheckPermission`：FromRequest extractors，per-handler 鉴权
//! - `ResponseError for BulwarkError`：错误响应，复用 `response_parts()` 保证三框架一致
//!
//! ## 使用示例
//!
//! ```ignore
//! use bulwark::prelude::*;
//! use bulwark::web_actix::{BulwarkRouter, CheckLogin};
//! use actix_web::{App, HttpServer, web};
//!
//! async fn protected_handler(_auth: CheckLogin) -> &'static str {
//!     "authenticated"
//! }
//!
//! let router = BulwarkRouter::new(std::sync::Arc::new(BulwarkConfig::default_config()))
//!     .route_protected("/api/user", Annotation::CheckLogin);
//!
//! App::new()
//!     .route("/api/user", web::get().to(protected_handler))
//!     .wrap(router.into_middleware());
//! ```

use crate::annotation::Annotation;
use crate::config::BulwarkConfig;
use crate::router::BulwarkInterceptor;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

pub mod error;
pub mod extractor;
pub mod middleware;
pub mod router;

/// 登录主体 extractor（从 Authorization: Bearer `<token>` 解析 login_id）。
pub use extractor::BulwarkPrincipal;

// ============================================================================
// 路由规则 + 路由器 struct 声明（impl 见 router.rs）
// ============================================================================

/// 路由规则：路径 → 注解映射。
#[derive(Clone)]
pub struct RouteRule {
    /// 路由路径
    pub path: String,
    /// 关联注解
    pub annotation: Annotation,
}

/// actix-web 路由器，收集鉴权路由规则并生成 middleware。
///
/// 对应 axum 版 `BulwarkRouter`，API 对齐。
pub struct BulwarkRouter {
    rules: HashMap<String, Annotation>,
    interceptor: Arc<dyn BulwarkInterceptor>,
    config: Arc<BulwarkConfig>,
}

// ============================================================================
// BulwarkMiddleware struct 声明（impl Transform/Service 见 middleware.rs）
// ============================================================================

/// actix-web middleware，提取 token + 调用 interceptor + 设置 task_local。
pub struct BulwarkMiddleware {
    rules: Arc<HashMap<String, Annotation>>,
    interceptor: Arc<dyn BulwarkInterceptor>,
    config: Arc<BulwarkConfig>,
}

/// middleware service（Transform 生成的中间层）。
pub struct BulwarkMiddlewareService<S> {
    /// 内部 service（Rc 包装以便在 async block 中 clone，无需 S: Clone）
    pub inner: Rc<S>,
    /// 路由规则
    pub rules: Arc<HashMap<String, Annotation>>,
    /// 拦截器
    pub interceptor: Arc<dyn BulwarkInterceptor>,
    /// 配置
    pub config: Arc<BulwarkConfig>,
}

// ============================================================================
// FromRequest Extractor struct 声明（impl FromRequest 见 extractor.rs）
// ============================================================================

/// CheckLogin extractor：验证用户已登录。
///
/// 在 handler 参数中使用：
/// ```ignore
/// async fn handler(_auth: CheckLogin) -> &'static str { "ok" }
/// ```
pub struct CheckLogin;

/// CheckRole extractor：验证用户持有指定角色。
pub struct CheckRole(pub String);

/// CheckPermission extractor：验证用户持有指定权限。
pub struct CheckPermission(pub String);

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
