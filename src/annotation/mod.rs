//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 注解模块，定义鉴权注解枚举与 axum extractor。
//!
//! 对应 注解体系（`@SaCheckLogin` 等），
//! Rust 中以枚举变体表达（用于 router 中间件配置），
//! 同时提供 axum extractor（`CheckLogin` 等）用于 handler 参数提取。
//!
//! ## 设计
//!
//! - `Annotation` 枚举：保留用于 router 中间件配置
//! - marker trait（`RoleName` / `PermissionName` / `ModeSpec`）：通过关联常量表达类型级参数
//! - extractor struct（`CheckLogin` 等）：实现 `FromRequestParts`，仅在 `web-axum` feature 下编译

pub mod impls;
pub mod modes;

// ============================================================================
// Marker traits（用于泛型 extractor 的类型级参数，always compiled）
// ============================================================================

/// 角色 marker trait，通过关联常量 `NAME` 指定角色名。
///
/// 业务方定义类型实现此 trait，用作 `CheckRole<R>` 的类型参数：
/// ```ignore
/// struct AdminRole;
/// impl RoleName for AdminRole { const NAME: &'static str = "admin"; }
/// async fn handler(CheckRole::<AdminRole>: CheckRole<AdminRole>) { ... }
/// ```
pub trait RoleName: Send + Sync {
    /// 角色名称（如 "admin"）。
    const NAME: &'static str;
}

/// 权限 marker trait，通过关联常量 `NAME` 指定权限名。
///
/// 业务方定义类型实现此 trait，用作 `CheckPermission<P>` 的类型参数。
pub trait PermissionName: Send + Sync {
    /// 权限名称（如 "user:read"）。
    const NAME: &'static str;
}

/// 模式 marker trait，通过关联常量 `STRICT` 指定是否严格模式。
///
/// - `STRICT=true`：未登录抛 `NotLogin` 异常（严格模式）
/// - `STRICT=false`：未登录不抛错，允许匿名访问（宽松模式）
pub trait ModeSpec: Send + Sync {
    /// 是否严格模式。
    const STRICT: bool;
}

// ============================================================================
// 预定义模式（always compiled）
// ============================================================================

/// 严格模式：未登录抛 `NotLogin` 异常。
pub struct Strict;

/// 宽松模式：未登录不抛错，允许匿名访问。
pub struct Loose;

// ============================================================================
// Annotation 枚举（保留用于 router 中间件配置，always compiled）
// ============================================================================

/// 鉴权注解枚举，列出 16 个核心注解。
///
/// 对应 注解集合。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Annotation {
    /// 检查登录（对应 `@SaCheckLogin`）。
    CheckLogin,

    /// 检查权限（对应 `@SaCheckPermission`）。
    CheckPermission(String),

    /// 检查角色（对应 `@SaCheckRole`）。
    CheckRole(String),

    /// 检查二级认证（对应 `@SaCheckSafe`）。
    CheckSafe,

    /// 检查是否被禁用（对应 `@SaCheckDisable`）。
    CheckDisable,

    /// OR 逻辑组合（对应 `@SaCheckOr`）。
    CheckOr,

    /// AND 逻辑组合（对应 `@SaCheckAnd`）。
    CheckAnd,

    /// NOT 逻辑组合（对应 `@SaCheckNot`）。
    CheckNot,

    /// 忽略鉴权（对应 `@SaIgnore`）。
    Ignore,

    /// Basic 认证检查（对应 `@SaCheckBasicAuth`）。
    CheckBasicAuth,

    /// Digest 认证检查（对应 `@SaCheckDigestAuth`）。
    CheckDigestAuth,

    /// 签名检查（对应 `@SaCheckSign`）。
    CheckSign,

    /// API Key 校验（对应 `@CheckApiKey`）。
    ///
    /// `namespace` 为 `Some(s)` 表示命名空间隔离（FRD §5.4.1），
    /// `None` 表示使用默认命名空间 `"default"`。
    CheckApiKey {
        /// 命名空间标识；`None` 表示默认命名空间 `"default"`。
        namespace: Option<String>,
    },

    /// 逻辑组合模式（对应 `@Mode`）。
    ///
    /// 控制 `@CheckPermission` / `@CheckRole` 的多权限组合逻辑：
    /// - [`AnnotationMode::And`]：全部满足
    /// - [`AnnotationMode::Or`]：任一满足
    Mode(AnnotationMode),

    /// OAuth2 access_token 校验。
    ///
    /// 声明受保护路由需要校验 OAuth2 access_token。
    /// 拦截器委托 `OAuth2Handler::verify_access_token` 校验；
    /// 无 OAuth2Handler 注册时返回 `NotImplemented`。
    CheckAccessToken,

    /// OAuth2 client_token 校验。
    ///
    /// 声明受保护路由需要校验 OAuth2 client_token（机器对机器访问）。
    /// 拦截器委托 `OAuth2Handler::verify_client_token` 校验；
    /// 无 OAuth2Handler 注册时返回 `NotImplemented`。
    CheckClientToken,
}

/// 注解逻辑组合模式。
///
/// 控制 `@CheckPermission` / `@CheckRole` 的多权限组合逻辑。
///
/// # 规则7 命名冲突记录
///
/// spec 要求命名为 `Mode`，但现有 `Mode<M: ModeSpec>` extractor struct（web-axum feature）
/// 已 re-export 为 `Mode`，会导致命名冲突。按规则11（惯例优先），保留现有 extractor 不变，
/// 新值级枚举命名为 `AnnotationMode`（语义更清晰：注解逻辑组合模式）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationMode {
    /// AND 模式：全部权限/角色均需满足。
    And,
    /// OR 模式：任一权限/角色满足即可。
    Or,
}

// ============================================================================
// axum extractor（cfg(feature = "web-axum")）
// ============================================================================
// 具体实现已拆到 `extractors.rs`（规则 25：mod.rs 不放具体实现函数）。

#[cfg(feature = "web-axum")]
mod extractors;

#[cfg(feature = "web-axum")]
pub use extractors::{CheckLogin, CheckPermission, CheckRole, Ignore, Mode};

#[cfg(all(test, feature = "web-axum"))]
mod mock;

#[cfg(all(test, feature = "web-axum"))]
mod tests;
