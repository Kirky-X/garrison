// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! warp 框架适配模块：GarrisonRouter + Filter extractor + GarrisonInterceptor 完整集成。
//!
//! 模块结构：`mod.rs` 结构体声明 + re-export 与 [`router`] impl、`extractor`（value-extracting Filter）、
//! `extractors`（guard Filter + Reject/Reply/Display impl + `garrison_recover()`）。
//! warp 拒绝链不会自动调用 `Reply`，须显式挂 `.recover(garrison_recover)` 才能得到与 axum/actix 一致的 JSON。
//!
//! ## 使用示例
//!
//! ```ignore
//! use garrison::prelude::*;
//! use garrison::web_warp::{GarrisonRouter, check_login};
//! use warp::Filter;
//!
//! let router = GarrisonRouter::new(std::sync::Arc::new(GarrisonConfig::default_config()))
//! .route_protected("/api/user", Annotation::CheckLogin);
//!
//! let routes = warp::path("api")
//! .and(warp::path("user"))
//! .and(check_login(std::sync::Arc::new(GarrisonConfig::default_config())))
//! .map(|| "authenticated");
//! ```

use crate::annotation::Annotation;
use crate::config::GarrisonConfig;
use crate::error::GarrisonError;
use crate::router::GarrisonInterceptor;
use std::collections::HashMap;
use std::sync::Arc;

pub mod extractor;
pub mod extractors;
pub mod request_id;
pub mod router;

/// 登录主体 extractor Filter（从 Authorization: Bearer `<token>` 解析 login_id）。
pub use extractor::garrison_principal;

/// 租户上下文 extractor Filter（需 `tenant-isolation` feature，从 X-Tenant-Id header 解析）。
#[cfg(feature = "tenant-isolation")]
pub use extractor::tenant_context;

/// `check_login` guard Filter：验证用户已登录。
pub use extractors::check_login;
/// `check_permission` guard Filter：验证用户持有指定权限。
pub use extractors::check_permission;
/// `check_role` guard Filter：验证用户持有指定角色。
pub use extractors::check_role;
/// `.recover()` 守卫映射处理器：`GarrisonRejection` → 三框架一致的统一 JSON。
pub use extractors::garrison_recover;
/// X-Request-ID 中间件：提取 / 生成 / 回传请求标识（错误体后置回填 request_id）。
pub use request_id::with_request_id;

// 结构体声明（实现见子模块 router / extractors）

/// 包装 `GarrisonError` 以实现 `warp::reject::Reject`（`impl Reject`/`Reply` 见 [`extractors`]）。
#[derive(Debug)]
pub struct GarrisonRejection(pub GarrisonError);

/// warp 路由器：收集鉴权路由规则并生成守卫 Filter（API 对齐 axum 版；`impl` 见 [`router`]）。
///
/// 内部字段不对外暴露：公开可变字段会让调用方绕过校验任意改写路由表、替换拦截器或更换配置，
/// 静默破坏鉴权行为；请通过 [`GarrisonRouter::new`] / [`GarrisonRouter::with_interceptor`] /
/// [`GarrisonRouter::route_protected`] 注册规则。
pub struct GarrisonRouter {
    rules: HashMap<String, Annotation>,
    interceptor: Arc<dyn GarrisonInterceptor>,
    config: Arc<GarrisonConfig>,
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
