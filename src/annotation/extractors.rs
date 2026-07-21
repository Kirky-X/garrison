//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! axum extractor 实现（`CheckLogin` / `CheckRole` / `CheckPermission` / `Ignore` / `Mode` /
//! `GarrisonPrincipal` / `TenantContext`）。
//!
//! 仅在 `web-axum` feature 下编译（由 `mod.rs` 中的 `#[cfg(feature = "web-axum")]` 控制）。

use super::{ModeSpec, PermissionName, RoleName};
use crate::config::GarrisonConfig;
use crate::context::token_extract::strip_bearer_prefix;
use crate::error::GarrisonError;
use crate::stp::{with_current_token, GarrisonUtil};
use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use std::marker::PhantomData;

// ----------------------------------------------------------------
// 辅助函数：从请求 parts 提取 token（按 config 决定提取顺序与字段名）
// ----------------------------------------------------------------

/// 从请求 parts 提取 token。
///
/// 提取顺序（受 config 开关控制）：
/// 1. 若 `is_read_header=true`：
///    a. `Authorization: Bearer <token>` header（Bearer 大小写不敏感，依据 RFC 7235）
///    b. 自定义 `token_name` header（如 `garrison_token: <token>`）
/// 2. 若 `is_read_cookie=true`：
///    `Cookie: <token_name>=<token>` cookie
fn extract_token_from_parts(parts: &Parts, config: &GarrisonConfig) -> Option<String> {
    // 1. 从 header 提取
    if config.is_read_header {
        // a. Authorization: Bearer <token>（RFC 7235 大小写不敏感）
        if let Some(auth) = parts.headers.get(header::AUTHORIZATION) {
            if let Ok(auth_str) = auth.to_str() {
                // 大小写不敏感匹配 "Bearer " 前缀
                if let Some(token) = strip_bearer_prefix(auth_str) {
                    return Some(token.to_string());
                }
            }
        }
        // b. 自定义 token_name header
        if let Some(token) = parts.headers.get(config.token_name.as_str()) {
            if let Ok(token_str) = token.to_str() {
                return Some(token_str.to_string());
            }
        }
    }
    // 2. 从 cookie 提取
    if config.is_read_cookie {
        if let Some(cookie) = parts.headers.get(header::COOKIE) {
            if let Ok(cookie_str) = cookie.to_str() {
                let cookie_prefix = format!("{}=", config.token_name);
                for c in cookie_str.split(';') {
                    let c = c.trim();
                    if let Some(rest) = c.strip_prefix(&cookie_prefix) {
                        return Some(rest.to_string());
                    }
                }
            }
        }
    }
    None
}

// ----------------------------------------------------------------
// 辅助函数：执行登录校验（严格模式，未登录返回 NotLogin）
// ----------------------------------------------------------------

/// 执行登录校验：调用 `GarrisonUtil::check_login()`，未登录返回 `NotLogin`。
///
/// - `throw_on_not_login=true`：check_login 返回 Err(Session)，`?` 透传
/// - `throw_on_not_login=false`：check_login 返回 Ok(false)，手动返回 Err(NotLogin)
async fn enforce_login() -> Result<(), GarrisonError> {
    let logged_in = GarrisonUtil::check_login().await?;
    if !logged_in {
        return Err(GarrisonError::NotLogin(
            "annotation-not-login::".to_string(),
        ));
    }
    Ok(())
}

// ----------------------------------------------------------------
// CheckLogin
// ----------------------------------------------------------------

/// 登录校验 extractor（对应 `@SaCheckLogin`）。
///
/// 从请求中提取 token 并校验登录状态。校验失败返回 `GarrisonError`。
pub struct CheckLogin;

/// 实现 `FromRequestParts`：从请求 parts 提取 token（若有），调用 `enforce_login` 校验登录状态。
///
/// # 错误
/// - `GarrisonError::NotLogin`：未登录且 `throw_on_not_login=false`。
/// - `GarrisonError::Session`：未登录且 `throw_on_not_login=true`（严格模式）。
impl<S: Send + Sync> FromRequestParts<S> for CheckLogin {
    type Rejection = GarrisonError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let config = GarrisonUtil::config()?;
        if let Some(t) = extract_token_from_parts(parts, &config) {
            with_current_token(t, enforce_login()).await?;
        } else {
            enforce_login().await?;
        }
        Ok(CheckLogin)
    }
}

// ----------------------------------------------------------------
// CheckRole<R>
// ----------------------------------------------------------------

/// 角色校验 extractor（对应 `@SaCheckRole`）。
///
/// 通过泛型参数 `R: RoleName` 指定角色名，校验当前用户是否持有该角色。
pub struct CheckRole<R: RoleName>(PhantomData<R>);

/// 实现 `FromRequestParts`：从请求 parts 提取 token（若有），调用 `GarrisonUtil::check_role(R::NAME)` 校验角色。
///
/// # 错误
/// - `GarrisonError::NotRole`：当前用户未持有角色 `R::NAME`。
/// - `GarrisonError::NotLogin`：未登录（严格模式下）。
impl<R: RoleName, S: Send + Sync> FromRequestParts<S> for CheckRole<R> {
    type Rejection = GarrisonError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let config = GarrisonUtil::config()?;
        if let Some(t) = extract_token_from_parts(parts, &config) {
            with_current_token(t, async {
                GarrisonUtil::check_role(R::NAME).await?;
                Ok::<(), GarrisonError>(())
            })
            .await?;
        } else {
            GarrisonUtil::check_role(R::NAME).await?;
        }
        Ok(CheckRole(PhantomData))
    }
}

// ----------------------------------------------------------------
// CheckPermission<P>
// ----------------------------------------------------------------

/// 权限校验 extractor（对应 `@SaCheckPermission`）。
///
/// 通过泛型参数 `P: PermissionName` 指定权限名，校验当前用户是否持有该权限。
pub struct CheckPermission<P: PermissionName>(PhantomData<P>);

/// 实现 `FromRequestParts`：从请求 parts 提取 token（若有），调用 `GarrisonUtil::check_permission(P::NAME)` 校验权限。
///
/// # 错误
/// - `GarrisonError::NotPermission`：当前用户未持有权限 `P::NAME`。
/// - `GarrisonError::NotLogin`：未登录（严格模式下）。
impl<P: PermissionName, S: Send + Sync> FromRequestParts<S> for CheckPermission<P> {
    type Rejection = GarrisonError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let config = GarrisonUtil::config()?;
        if let Some(t) = extract_token_from_parts(parts, &config) {
            with_current_token(t, async {
                GarrisonUtil::check_permission(P::NAME).await?;
                Ok::<(), GarrisonError>(())
            })
            .await?;
        } else {
            GarrisonUtil::check_permission(P::NAME).await?;
        }
        Ok(CheckPermission(PhantomData))
    }
}

// ----------------------------------------------------------------
// Ignore
// ----------------------------------------------------------------

/// 忽略鉴权 extractor（对应 `@SaIgnore`）。
///
/// 不执行任何校验，直接返回 `Ok`，用于路由配置标记。
pub struct Ignore;

/// 实现 `FromRequestParts`：不执行任何校验，直接返回 `Ok(Ignore)`。
impl<S: Send + Sync> FromRequestParts<S> for Ignore {
    type Rejection = GarrisonError;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Ignore)
    }
}

// ----------------------------------------------------------------
// Mode<M>
// ----------------------------------------------------------------

/// 模式 extractor（对应严格/宽松模式）。
///
/// 通过泛型参数 `M: ModeSpec` 指定模式：
/// - `Mode<Strict>`：未登录抛 `NotLogin` 异常
/// - `Mode<Loose>`：未登录不抛错，允许匿名访问
pub struct Mode<M: ModeSpec>(PhantomData<M>);

/// 执行模式校验：根据 `M::STRICT` 决定行为。
async fn enforce_mode<M: ModeSpec>() -> Result<(), GarrisonError> {
    if M::STRICT {
        enforce_login().await
    } else {
        // 宽松模式：忽略登录状态
        let _ = GarrisonUtil::check_login().await;
        Ok(())
    }
}

/// 实现 `FromRequestParts`：从请求 parts 提取 token（若有），调用 `enforce_mode::<M>` 执行模式校验。
///
/// # 错误
/// - `Mode<Strict>`：未登录时返回 `GarrisonError::NotLogin`。
/// - `Mode<Loose>`：不返回错误（宽松模式允许匿名访问）。
impl<M: ModeSpec, S: Send + Sync> FromRequestParts<S> for Mode<M> {
    type Rejection = GarrisonError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let config = GarrisonUtil::config()?;
        if let Some(t) = extract_token_from_parts(parts, &config) {
            with_current_token(t, enforce_mode::<M>()).await?;
        } else {
            enforce_mode::<M>().await?;
        }
        Ok(Mode(PhantomData))
    }
}

// ----------------------------------------------------------------
// GarrisonPrincipal extractor（携带 login_id）
// ----------------------------------------------------------------

/// 登录主体 extractor（从 `Authorization: Bearer <token>` 解析 `login_id`）。
///
/// 与 actix-web / warp 版本完全对齐：
/// - 无 token → `GarrisonError::NotLogin("未提供 token")`
/// - token 无效或会话不存在 → `GarrisonError::NotLogin("token 无效或会话不存在")`
/// - 有效 token → `Ok(GarrisonPrincipal { login_id })`
///
/// 与 `CheckLogin` extractor 的区别：
/// - `CheckLogin` 仅校验登录状态，返回 unit-like struct
/// - `GarrisonPrincipal` 携带 `login_id` 字段，handler 可直接读取当前用户身份
impl<S: Send + Sync> FromRequestParts<S> for crate::context::GarrisonPrincipal {
    type Rejection = GarrisonError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let config = GarrisonUtil::config()?;
        let token = extract_token_from_parts(parts, &config)
            .ok_or_else(|| GarrisonError::NotLogin("annotation-no-token::".to_string()))?;

        let login_id = GarrisonUtil::get_login_id_by_token(&token)
            .await?
            .ok_or_else(|| GarrisonError::NotLogin("annotation-token-invalid::".to_string()))?;

        Ok(crate::context::GarrisonPrincipal { login_id })
    }
}

// ----------------------------------------------------------------
// TenantContext extractor（cfg tenant-isolation）
// ----------------------------------------------------------------

/// 租户上下文 extractor（从 `X-Tenant-Id` header 解析 `tenant_id`）。
///
/// 与 actix-web / warp 版本完全对齐：
/// - 缺失 `X-Tenant-Id` → `GarrisonError::Config("X-Tenant-Id header missing")`
/// - 非数字 → `GarrisonError::Config("X-Tenant-Id 不是合法的 i64: <raw>")`
/// - 合法 i64 → `Ok(TenantContext { tenant_id, resolved_from: TenantSource::Header })`
///
/// 不依赖 `GarrisonManager`：仅做 header 解析，不查会话/权限。
#[cfg(feature = "tenant-isolation")]
impl<S: Send + Sync> FromRequestParts<S> for crate::context::tenant::TenantContext {
    type Rejection = GarrisonError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let raw = parts
            .headers
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| GarrisonError::Config("X-Tenant-Id header missing".into()))?;

        let tenant_id: i64 = raw
            .parse()
            .map_err(|_| GarrisonError::Config(format!("annotation-tenant-id-invalid::{}", raw)))?;

        Ok(crate::context::tenant::TenantContext {
            tenant_id,
            resolved_from: crate::context::tenant::TenantSource::Header,
        })
    }
}
