// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 注解模块，定义鉴权注解枚举（`@SaCheckLogin` 等的 Rust 表达，用于 router 中间件配置）
//! 与 axum extractor（`CheckLogin` 等，用于 handler 参数提取）。
//!
//! 配套 marker trait（`RoleName` / `PermissionName` / `ModeSpec`）经关联常量表达提取器类型级参数。

pub mod impls;
pub mod modes;

// Marker traits（用于泛型 extractor 的类型级参数，always compiled）

/// 角色 marker trait，通过关联常量 `NAME` 指定角色名。
///
/// 业务方定义类型实现此 trait，用作 `CheckRole<R>` 的类型参数：
/// ```ignore
/// struct AdminRole;
/// impl RoleName for AdminRole { const NAME: &'static str = "admin"; }
/// async fn handler(check: CheckRole<AdminRole>) { ... }
/// ```
pub trait RoleName: Send + Sync {
    /// 角色名称（如 "admin"）。
    const NAME: &'static str;
}

/// 权限 marker trait，通过关联常量 `NAME` 指定权限名。
pub trait PermissionName: Send + Sync {
    /// 权限名称（如 "user:read"）。
    const NAME: &'static str;
}

/// 模式 marker trait，通过关联常量 `STRICT` 指定是否严格模式。
pub trait ModeSpec: Send + Sync {
    /// 是否严格模式。
    const STRICT: bool;
}

// 预定义模式（always compiled）

/// 严格模式：未登录抛 `NotLogin` 异常。
pub struct Strict;

/// 宽松模式：未登录不抛错，允许匿名访问。
pub struct Loose;

// Annotation 枚举（保留用于 router 中间件配置，always compiled）

/// 鉴权注解枚举，对应 注解集合（16 个核心注解）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Annotation {
    /// 检查登录。
    CheckLogin,

    /// 检查权限。
    CheckPermission(String),

    /// 检查角色。
    CheckRole(String),

    /// 检查二级认证。
    CheckSafe,

    /// 检查是否被禁用。
    CheckDisable,

    /// OR 逻辑组合。
    CheckOr,

    /// AND 逻辑组合。
    CheckAnd,

    /// NOT 逻辑组合。
    CheckNot,

    /// 忽略鉴权。
    Ignore,

    /// Basic 认证检查。
    CheckBasicAuth,

    /// Digest 认证检查。
    CheckDigestAuth,

    /// 签名检查。
    CheckSign,

    /// API Key 校验；`namespace` 为 `Some(s)` 表示命名空间隔离，`None` 表示默认命名空间 `"default"`。
    CheckApiKey {
        /// 命名空间标识；`None` 表示默认命名空间 `"default"`。
        namespace: Option<String>,
    },

    /// 逻辑组合模式：`And` 全部满足，`Or` 任一满足。
    Mode(AnnotationMode),

    /// OAuth2 access_token 校验：拦截器委托 `OAuth2Handler::verify_access_token`，未注册时返回 `NotImplemented`。
    CheckAccessToken,

    /// OAuth2 client_token（机器对机器）校验：委托 `OAuth2Handler::verify_client_token`，未注册时返回 `NotImplemented`。
    CheckClientToken,
}

/// 注解逻辑组合模式：控制 `@CheckPermission` / `@CheckRole` 的多权限组合逻辑。
///
/// 命名为 `AnnotationMode` 是为避免与 `web-axum` feature 下已导出的 `Mode<M: ModeSpec>` 碰撞。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationMode {
    /// AND 模式：全部权限/角色均需满足。
    And,
    /// OR 模式：任一权限/角色满足即可。
    Or,
}

// axum extractor（cfg(feature = "web-axum")）
// 具体实现已拆到 `extractors.rs`（mod.rs 不放具体实现函数）。

#[cfg(feature = "web-axum")]
mod extractors;

#[cfg(feature = "web-axum")]
pub use extractors::{CheckLogin, CheckPermission, CheckRole, Ignore, Mode};

#[cfg(all(test, feature = "web-axum"))]
mod mock;

#[cfg(all(test, feature = "web-axum"))]
mod tests;
