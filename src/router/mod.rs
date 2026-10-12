// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 路由模块：`GarrisonInterceptor` 预处理 hook（按 annotation 调用 `GarrisonUtil`），
//! `DefaultGarrisonInterceptor` 默认实现，`GarrisonRouter` 包装 `axum::Router`（cfg `web-axum`），
//! `GarrisonLayer` middleware 自动从 header/cookie 提取 token 并设置 task_local。

pub mod interceptor;

use crate::annotation::Annotation;
use crate::error::GarrisonResult;
use async_trait::async_trait;

/// 拦截器 trait（对应 `SaInterceptor`）：实现方在 `pre_handle` 中按 annotation 调用
/// `GarrisonUtil` 鉴权方法，middleware 在执行 handler 前调用，返回 `Err` 时短路返回错误响应。
#[async_trait]
pub trait GarrisonInterceptor: Send + Sync {
    /// 根据 annotation 执行鉴权；`Err` 时 middleware 短路返回错误响应（401/403/500）。
    async fn pre_handle(&self, path: &str, annotation: &Annotation) -> GarrisonResult<()>;
}

// DefaultGarrisonInterceptor（always compiled）

/// 默认拦截器：按 annotation 变体分派 `GarrisonUtil` 鉴权方法。
///
/// CheckLogin / CheckRole / CheckPermission / CheckSafe / CheckDisable / CheckApiKey 直接调用对应方法；
/// CheckBasicAuth / CheckDigestAuth / CheckSign 依赖 HTTP 请求上下文（`pre_handle` 仅有 path + annotation）
/// 无法校验，Fail Loud 返回 `GarrisonError::NotImplemented`，引导改用 axum extractor 或 secure 模块；
/// Ignore / CheckOr / CheckAnd / CheckNot / Mode 为 no-op（组合逻辑由注解处理器或路由配置层处理）。
pub struct DefaultGarrisonInterceptor;

// GarrisonRouter（cfg feature = "web-axum"）

#[cfg(feature = "web-axum")]
pub use web_axum::GarrisonRouter;

/// 无 `web-axum` feature 时的占位类型（维持 prelude 重导出可用）。
#[cfg(not(feature = "web-axum"))]
pub struct GarrisonRouter;

#[cfg(feature = "web-axum")]
mod web_axum;

/// 租户解析 middleware 的 re-export。
///
/// 仅在 `web-axum` + `tenant-isolation` 双 feature 启用时可用。
#[cfg(all(feature = "web-axum", feature = "tenant-isolation"))]
pub use web_axum::tenant_resolution_middleware;

#[cfg(all(test, feature = "web-axum"))]
mod mock;

#[cfg(all(test, feature = "web-axum"))]
mod tests;
