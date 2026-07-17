//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 路由模块，提供路由器与拦截器抽象。
//!
//! 对应 路由拦截器（`SaInterceptor`），
//! 适配 axum Web 框架的路由层。
//!
//! ## 设计
//!
//! - `BulwarkInterceptor` trait：预处理 hook，根据 annotation 调用 `BulwarkUtil`
//! - `DefaultBulwarkInterceptor`：默认实现，根据 annotation 变体调用对应 API
//! - `BulwarkRouter`：包装 `axum::Router`，提供 `route_protected` 语法糖（cfg `web-axum`）
//! - `BulwarkLayer` middleware：自动从 header/cookie 提取 token + 设置 task_local

pub mod interceptor;

use crate::annotation::Annotation;
use crate::error::BulwarkResult;
use async_trait::async_trait;

// ============================================================================
// BulwarkInterceptor trait（always compiled，prelude 重导出依赖）
// ============================================================================

/// 拦截器 trait，定义请求预处理抽象。
///
/// 对应 `SaInterceptor`，根据 annotation 执行鉴权逻辑。
///
/// 实现方在 `pre_handle` 中根据 annotation 调用 `BulwarkUtil::check_login` 等方法。
/// middleware 在执行 handler 前调用此方法，返回 `Err` 时短路返回错误响应。
#[async_trait]
pub trait BulwarkInterceptor: Send + Sync {
    /// 预处理请求，根据 annotation 执行鉴权。
    ///
    /// # 参数
    /// - `path`: 请求路径。
    /// - `annotation`: 路由关联的鉴权注解。
    ///
    /// # 返回
    /// - `Ok(())`: 鉴权通过，继续执行 handler。
    /// - `Err`: 鉴权失败，middleware 短路返回错误响应（401/403/500）。
    async fn pre_handle(&self, path: &str, annotation: &Annotation) -> BulwarkResult<()>;
}

// ============================================================================
// DefaultBulwarkInterceptor（always compiled）
// ============================================================================

/// 默认拦截器实现，根据 annotation 变体调用对应 `BulwarkUtil` 方法。
///
/// # 注解处理方式
///
/// **直接鉴权（6 个）**：
/// - `CheckLogin` → `BulwarkUtil::check_login()`（未登录返回 `NotLogin`）
/// - `CheckRole(r)` → `BulwarkUtil::check_role(r)`
/// - `CheckPermission(p)` → `BulwarkUtil::check_permission(p)`
/// - `CheckSafe` → `BulwarkUtil::check_safe()`（0.3.0 二级认证）
/// - `CheckDisable` → `BulwarkUtil::check_disable()`（0.3.0 账号禁用）
/// - `CheckApiKey { namespace }` → `BulwarkUtil::check_api_key(namespace)`（0.6.1 API Key 校验）
///
/// **NotImplemented（3 个）**：依赖 HTTP 请求上下文（Authorization header / method / body），
/// 而 `pre_handle` 签名仅有 `path + annotation`，无法获取。Fail Loud（Rule 12）返回
/// `BulwarkError::NotImplemented`，引导用户改用 axum extractor 或 secure 模块直接调用：
/// - `CheckBasicAuth` → 使用 `secure::httpbasic::HttpBasicAuth` 或 axum extractor
/// - `CheckDigestAuth` → 使用 `secure::httpdigest::HttpDigestAuth` 或 axum extractor
/// - `CheckSign` → 使用 `protocol::sign::SignHandler` 或 axum extractor
///
/// **直接放行（no-op）**：
/// - `Ignore` / 逻辑组合注解（`CheckOr` / `CheckAnd` / `CheckNot` / `Mode`）→ no-op
///   （组合逻辑由注解处理器在编译期或路由配置层处理；`Mode` 是配置注解非直接检查）
pub struct DefaultBulwarkInterceptor;

// ============================================================================
// BulwarkRouter（cfg feature = "web-axum"）
// ============================================================================

#[cfg(feature = "web-axum")]
pub use web_axum::BulwarkRouter;

/// 无 `web-axum` feature 时的占位类型（维持 prelude 重导出可用）。
#[cfg(not(feature = "web-axum"))]
pub struct BulwarkRouter;

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
