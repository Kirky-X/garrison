//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! warp 框架适配模块。
//!
//! 对应 warp 适配器，
//! 提供 BulwarkRouter + Filter extractor + BulwarkInterceptor 完整集成。
//!
//! ## 设计
//!
//! - `BulwarkRouter`：路由规则构建器，`route_protected` 注册路径 + 注解映射，`into_filter` 生成守卫 Filter
//! - `check_login()` / `check_role(role)` / `check_permission(perm)`：guard Filter，per-handler 鉴权
//! - `bulwark_principal` / `tenant_context`：value-extracting Filter
//! - `impl Reply for BulwarkError` + `impl Reject for BulwarkRejection`：错误响应，复用 `response_parts()` 保证三框架一致
//!
//! ## 模块结构（Rule 25 接口隔离）
//!
//! - `mod.rs`：仅声明 `BulwarkRouter` / `BulwarkRejection` 结构体 + re-export
//! - [`extractor`]：value-extracting Filter（`bulwark_principal` / `tenant_context`）
//! - [`extractors`]：guard Filter（`check_login` / `check_role` / `check_permission`）+ `Reject` / `Reply` impl
//! - [`router`]：`impl BulwarkRouter` + `impl Default`
//!
//! ## 使用示例
//!
//! ```ignore
//! use bulwark::prelude::*;
//! use bulwark::web_warp::{BulwarkRouter, check_login};
//! use warp::Filter;
//!
//! let router = BulwarkRouter::new(std::sync::Arc::new(BulwarkConfig::default_config()))
//!     .route_protected("/api/user", Annotation::CheckLogin);
//!
//! let routes = warp::path("api")
//!     .and(warp::path("user"))
//!     .and(check_login(std::sync::Arc::new(BulwarkConfig::default_config())))
//!     .map(|| "authenticated");
//! ```

use crate::annotation::Annotation;
use crate::config::BulwarkConfig;
use crate::error::BulwarkError;
use crate::router::BulwarkInterceptor;
use std::collections::HashMap;
use std::sync::Arc;

pub mod extractor;
pub mod extractors;
pub mod router;

/// 登录主体 extractor Filter（从 Authorization: Bearer `<token>` 解析 login_id）。
pub use extractor::bulwark_principal;

/// 租户上下文 extractor Filter（需 `tenant-isolation` feature，从 X-Tenant-Id header 解析）。
#[cfg(feature = "tenant-isolation")]
pub use extractor::tenant_context;

/// `check_login` guard Filter：验证用户已登录。
pub use extractors::check_login;
/// `check_permission` guard Filter：验证用户持有指定权限。
pub use extractors::check_permission;
/// `check_role` guard Filter：验证用户持有指定角色。
pub use extractors::check_role;

// ============================================================================
// 结构体声明：实现见子模块 router / extractors
// ============================================================================

/// 包装 `BulwarkError` 以实现 `warp::reject::Reject`（warp 拒绝链需要 Reject 类型）。
///
/// `impl Reject` / `impl Reply` 见 [`extractors`]。
#[derive(Debug)]
pub struct BulwarkRejection(pub BulwarkError);

/// warp 路由器，收集鉴权路由规则并生成守卫 Filter。
///
/// 对应 axum 版 `BulwarkRouter`，API 对齐。
/// `impl BulwarkRouter` + `impl Default` 见 [`router`]。
pub struct BulwarkRouter {
    /// 路径 → 注解映射
    pub rules: HashMap<String, Annotation>,
    /// 拦截器
    pub interceptor: Arc<dyn BulwarkInterceptor>,
    /// 配置
    pub config: Arc<BulwarkConfig>,
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
