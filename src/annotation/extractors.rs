// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! axum extractor 实现（`CheckLogin` / `CheckRole` / `CheckPermission` / `Ignore` / `Mode` /
//! `GarrisonPrincipal` / `TenantContext`），仅在 `web-axum` feature 下编译。

use super::{ModeSpec, PermissionName, RoleName};
use crate::config::GarrisonConfig;
use crate::context::token_extract::strip_bearer_prefix;
use crate::error::GarrisonError;
use crate::stp::{with_current_token, GarrisonUtil};
use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use std::marker::PhantomData;

// 辅助函数：从请求 parts 提取 token（按 config 决定提取顺序与字段名）

/// 从请求 parts 提取 token：header 与 cookie 的提取顺序及字段名受 config 开关控制；
/// cookie 解析名在 production + Secure 上下文为 `__Host-` 前缀名，与写侧同名。
fn extract_token_from_parts(parts: &Parts, config: &GarrisonConfig) -> Option<String> {
    if config.is_read_header {
        if let Some(token) = extract_header_token(parts, config) {
            return Some(token);
        }
    }
    if config.is_read_cookie {
        if let Some(token) = extract_cookie_token(parts, config) {
            return Some(token);
        }
    }
    None
}

/// header 提取：优先 `Authorization: Bearer <token>`（RFC 7235 大小写不敏感），
/// 其次 `config.token_name` 指定的自定义头。
fn extract_header_token(parts: &Parts, config: &GarrisonConfig) -> Option<String> {
    if let Some(auth) = parts.headers.get(header::AUTHORIZATION) {
        if let Some(token) = auth.to_str().ok().and_then(strip_bearer_prefix) {
            return Some(token.to_string());
        }
    }
    parts
        .headers
        .get(config.token_name.as_str())
        .and_then(|token| token.to_str().ok())
        .map(str::to_string)
}

/// cookie 提取：按 `config` 决定的 cookie 名扫描 `Cookie` 头（production + Secure 上下文
/// 为 `__Host-` 前缀名，与写侧同名）。
fn extract_cookie_token(parts: &Parts, config: &GarrisonConfig) -> Option<String> {
    let cookie_str = parts.headers.get(header::COOKIE)?.to_str().ok()?;
    let cookie_prefix = format!("{}=", crate::context::token_cookie_name(config));
    cookie_str
        .split(';')
        .map(str::trim)
        .find_map(|c| c.strip_prefix(&cookie_prefix).map(str::to_string))
}

// 辅助函数：执行登录校验（严格模式，未登录返回 NotLogin）

/// 执行登录校验：调用 `GarrisonUtil::check_login()`；`throw_on_not_login=true` 时未登录
/// 以 `Err(Session)` 透传，`false` 时统一转为 `Err(NotLogin)`。
async fn enforce_login() -> Result<(), GarrisonError> {
    let logged_in = GarrisonUtil::check_login().await?;
    if !logged_in {
        return Err(GarrisonError::NotLogin(
            "annotation-not-login::".to_string(),
        ));
    }
    Ok(())
}

// CheckLogin

/// 登录校验 extractor：从请求提取 token 并校验登录状态，失败返回 `GarrisonError`。
pub struct CheckLogin;

/// 实现 `FromRequestParts`：提取 token（若有）后调用 `enforce_login` 校验登录；
/// 未登录返回 `NotLogin`（`throw_on_not_login=true` 时透传 `Session`）。
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

// CheckRole<R>

/// 角色校验 extractor：经泛型参数 `R: RoleName` 指定角色名，校验当前用户是否持有该角色。
pub struct CheckRole<R: RoleName>(PhantomData<R>);

/// 实现 `FromRequestParts`：提取 token（若有）后调用 `GarrisonUtil::check_role(R::NAME)`；
/// 未持有该角色或未登录时返回 `NotRole` / `NotLogin`。
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

// CheckPermission<P>

/// 权限校验 extractor：经泛型参数 `P: PermissionName` 指定权限名，校验当前用户是否持有该权限。
pub struct CheckPermission<P: PermissionName>(PhantomData<P>);

/// 实现 `FromRequestParts`：提取 token（若有）后调用 `GarrisonUtil::check_permission(P::NAME)`；
/// 未持有该权限或未登录时返回 `NotPermission` / `NotLogin`。
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

// Ignore

/// 忽略鉴权 extractor：不执行任何校验，直接返回 `Ok`。
pub struct Ignore;

impl<S: Send + Sync> FromRequestParts<S> for Ignore {
    type Rejection = GarrisonError;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Ignore)
    }
}

// Mode<M>

/// 模式 extractor：`Mode<Strict>` 未登录抛 `NotLogin`，`Mode<Loose>` 未登录不抛错、允许匿名访问。
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

/// 实现 `FromRequestParts`：提取 token（若有）后调用 `enforce_mode::<M>`；
/// `Mode<Strict>` 未登录返回 `NotLogin`，`Mode<Loose>` 允许匿名访问不报错。
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

// GarrisonPrincipal extractor（携带 login_id）

/// 登录主体 extractor：从 token 解析 `login_id` 供 handler 读取当前用户身份；
/// 无 token 或 token 无效/会话不存在时返回 `NotLogin`。
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

// TenantContext extractor（cfg tenant-isolation）

/// 租户上下文 extractor：仅解析 `X-Tenant-Id` header，缺失或非 i64 返回 `Config` 错误，
/// 不查会话/权限。
#[cfg(feature = "tenant-isolation")]
impl<S: Send + Sync> FromRequestParts<S> for crate::context::tenant::TenantContext {
    type Rejection = GarrisonError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let raw = parts
            .headers
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| GarrisonError::Config("ctx-tenant-id-missing::".into()))?;

        let tenant_id: i64 = raw
            .parse()
            .map_err(|_| GarrisonError::Config(format!("annotation-tenant-id-invalid::{}", raw)))?;

        Ok(crate::context::tenant::TenantContext {
            tenant_id,
            resolved_from: crate::context::tenant::TenantSource::Header,
        })
    }
}
