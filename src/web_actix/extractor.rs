//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! actix-web Extractor 适配器。
//!
//! 集中提供 actix-web `FromRequest` extractor 实现：
//! - `GarrisonPrincipal`：从 `Authorization: Bearer <token>` header 解析当前登录用户 ID，
//!   携带 `login_id` 字段供 handler 直接读取。
//! - `CheckLogin` / `CheckRole` / `CheckPermission`：per-handler 鉴权 extractor，
//!   仅执行鉴权（返回 unit-like struct），struct 声明位于 `mod.rs`。
//! - `TenantContext`（feature gate `tenant-isolation`）：从 `X-Tenant-Id` header 解析租户 ID。
//!
//! ## 设计
//!
//! - `GarrisonPrincipal` 与 `CheckLogin`/`CheckRole`/`CheckPermission` 互补：
//!   前者携带身份信息，后者仅做鉴权校验。
//! - 与 `GarrisonContext` trait（请求/响应/存储上下文抽象层）解耦：trait 名字保持不变，
//!   extractor 使用不同名称 `GarrisonPrincipal` 避免命名冲突（Rule 7 决策）。
//!
//! ## 使用示例
//!
//! ```ignore
//! use garrison::web_actix::GarrisonPrincipal;
//!
//! async fn handler(principal: GarrisonPrincipal) -> String {
//!     format!("login_id = {}", principal.login_id)
//! }
//! ```

// ============================================================================
// GarrisonPrincipal：携带 login_id 的 extractor
// ============================================================================

use crate::context::token_extract::extract_token_from_headers;

pub use crate::context::GarrisonPrincipal;

/// 实现 `FromRequest`：从 `Authorization: Bearer <token>` header 提取 token，
/// 调用 `GarrisonUtil::get_login_id_by_token` 解析关联的 `login_id`。
///
/// # 错误
///
/// - `GarrisonError::NotLogin`: 未提供 token 或 token 无效。
impl actix_web::FromRequest for GarrisonPrincipal {
    type Error = crate::error::GarrisonError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        let config = req
            .app_data::<actix_web::web::Data<std::sync::Arc<crate::config::GarrisonConfig>>>()
            .map(|d| d.get_ref().clone())
            .unwrap_or_else(
                || std::sync::Arc::new(crate::config::GarrisonConfig::default_config()),
            );

        Box::pin(async move {
            let token = extract_token_from_headers(&headers, &config)?.ok_or_else(|| {
                crate::error::GarrisonError::NotLogin("web-not-login".to_string())
            })?;

            let login_id = crate::stp::GarrisonUtil::get_login_id_by_token(&token)
                .await?
                .ok_or_else(|| {
                    crate::error::GarrisonError::NotLogin("web-token-invalid".to_string())
                })?;

            Ok(GarrisonPrincipal { login_id })
        })
    }
}

// ============================================================================
// CheckLogin / CheckRole / CheckPermission extractors（per-handler 鉴权）
// ============================================================================
//
// 这三个 extractor 与上方 `GarrisonPrincipal` 互补：
// - `GarrisonPrincipal` 携带 login_id 供 handler 读取
// - `CheckLogin` / `CheckRole` / `CheckPermission` 仅执行鉴权，返回 unit-like struct
//
// struct 声明位于 `mod.rs`，此处仅提供 `FromRequest` 实现。

/// CheckLogin extractor：验证用户已登录。
///
/// 在 handler 参数中使用：
/// ```ignore
/// async fn handler(_auth: CheckLogin) -> &'static str { "ok" }
/// ```
impl actix_web::FromRequest for super::CheckLogin {
    type Error = crate::error::GarrisonError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        let config = req
            .app_data::<actix_web::web::Data<std::sync::Arc<crate::config::GarrisonConfig>>>()
            .map(|d| d.get_ref().clone())
            .unwrap_or_else(
                || std::sync::Arc::new(crate::config::GarrisonConfig::default_config()),
            );

        Box::pin(async move {
            let token = extract_token_from_headers(&headers, &config)?.ok_or_else(|| {
                crate::error::GarrisonError::NotLogin("web-not-login".to_string())
            })?;

            let result: crate::error::GarrisonResult<()> =
                crate::stp::with_current_token(token, async {
                    let logged_in = crate::stp::GarrisonUtil::check_login().await?;
                    if !logged_in {
                        return Err(crate::error::GarrisonError::NotLogin(
                            "web-not-login".to_string(),
                        ));
                    }
                    Ok(())
                })
                .await;

            result.map(|_| super::CheckLogin)
        })
    }
}

/// CheckRole extractor：验证用户持有指定角色。
impl actix_web::FromRequest for super::CheckRole {
    type Error = crate::error::GarrisonError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        let config = req
            .app_data::<actix_web::web::Data<std::sync::Arc<crate::config::GarrisonConfig>>>()
            .map(|d| d.get_ref().clone())
            .unwrap_or_else(
                || std::sync::Arc::new(crate::config::GarrisonConfig::default_config()),
            );

        // 角色从 header X-Garrison-Role 或 query param role 获取
        let role = req
            .headers()
            .get("x-garrison-role")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| {
                req.uri().query().and_then(|q| {
                    q.split('&').find_map(|kv| {
                        let mut parts = kv.splitn(2, '=');
                        if parts.next() == Some("role") {
                            parts.next().map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                })
            })
            .unwrap_or_default();

        Box::pin(async move {
            let token = extract_token_from_headers(&headers, &config)?.ok_or_else(|| {
                crate::error::GarrisonError::NotLogin("web-not-login".to_string())
            })?;

            let result: crate::error::GarrisonResult<()> =
                crate::stp::with_current_token(token, async {
                    crate::stp::GarrisonUtil::check_role(&role).await
                })
                .await;

            result.map(|_| super::CheckRole(role))
        })
    }
}

/// CheckPermission extractor：验证用户持有指定权限。
impl actix_web::FromRequest for super::CheckPermission {
    type Error = crate::error::GarrisonError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        let config = req
            .app_data::<actix_web::web::Data<std::sync::Arc<crate::config::GarrisonConfig>>>()
            .map(|d| d.get_ref().clone())
            .unwrap_or_else(
                || std::sync::Arc::new(crate::config::GarrisonConfig::default_config()),
            );

        // 权限从 header X-Garrison-Permission 或 query param permission 获取
        let permission = req
            .headers()
            .get("x-garrison-permission")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| {
                req.uri().query().and_then(|q| {
                    q.split('&').find_map(|kv| {
                        let mut parts = kv.splitn(2, '=');
                        if parts.next() == Some("permission") {
                            parts.next().map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                })
            })
            .unwrap_or_default();

        Box::pin(async move {
            let token = extract_token_from_headers(&headers, &config)?.ok_or_else(|| {
                crate::error::GarrisonError::NotLogin("web-not-login".to_string())
            })?;

            let result: crate::error::GarrisonResult<()> =
                crate::stp::with_current_token(token, async {
                    crate::stp::GarrisonUtil::check_permission(&permission).await
                })
                .await;

            result.map(|_| super::CheckPermission(permission))
        })
    }
}

// ============================================================================
// TenantContext extractor（feature gate tenant-isolation）
// ============================================================================

#[cfg(feature = "tenant-isolation")]
impl actix_web::FromRequest for crate::context::tenant::TenantContext {
    type Error = crate::error::GarrisonError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        Box::pin(async move {
            let raw = headers
                .get("x-tenant-id")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    crate::error::GarrisonError::Config("X-Tenant-Id header missing".into())
                })?;

            let tenant_id: i64 = raw.parse().map_err(|_| {
                crate::error::GarrisonError::Config(format!("ctx-tenant-id-invalid::{}", raw))
            })?;

            Ok(crate::context::tenant::TenantContext {
                tenant_id,
                resolved_from: crate::context::tenant::TenantSource::Header,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::mock::{MockDao, MockInterface};
    use super::*;
    use crate::dao::GarrisonDao;
    use crate::manager::GarrisonManager;
    use crate::stp::{GarrisonInterface, GarrisonUtil};
    use actix_web::test;
    use actix_web::FromRequest;
    use serial_test::serial;

    fn make_config() -> crate::config::GarrisonConfig {
        let mut config = crate::config::GarrisonConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = false;
        config
    }

    fn init_manager() {
        GarrisonManager::reset_for_test();
        let dao: std::sync::Arc<dyn GarrisonDao> = std::sync::Arc::new(MockDao::new());
        let config = std::sync::Arc::new(make_config());
        let interface: std::sync::Arc<dyn GarrisonInterface> =
            std::sync::Arc::new(MockInterface::new());
        GarrisonManager::init(dao, config, interface).unwrap();
    }

    // ----------------------------------------------------------------
    // GarrisonPrincipal extractor 测试
    // ----------------------------------------------------------------

    /// 验证 `GarrisonPrincipal::from_request` 从 `Authorization: Bearer <token>`
    /// header 解析出 `login_id`。
    ///
    /// 覆盖 spec web-adapters D12 Requirement: actix extractor 从 token 解析 login_id。
    #[tokio::test]
    #[serial]
    async fn garrison_principal_extracted_from_actix_request() {
        init_manager();
        let login_id = "1001";
        let token = GarrisonUtil::login_simple(login_id).await.unwrap();

        let req = test::TestRequest::get()
            .uri("/api/test")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let principal = GarrisonPrincipal::from_request(&req, &mut payload)
            .await
            .expect("GarrisonPrincipal::from_request 应成功解析 token");

        assert_eq!(principal.login_id, login_id);

        GarrisonManager::reset_for_test();
    }

    /// 验证 `GarrisonPrincipal::from_request` 在无 token 时返回 `NotLogin` 错误。
    ///
    /// 覆盖 spec web-adapters D12 Requirement: extractor 在无 token 时拒绝请求。
    #[tokio::test]
    #[serial]
    async fn garrison_principal_returns_err_without_token() {
        init_manager();

        let req = test::TestRequest::get().uri("/api/test").to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let result = GarrisonPrincipal::from_request(&req, &mut payload).await;
        assert!(
            result.is_err(),
            "无 token 时 from_request 应返回 Err，实际 = {:?}",
            result
        );

        GarrisonManager::reset_for_test();
    }

    /// 验证 `GarrisonPrincipal::from_request` 在无效 token 时返回错误。
    ///
    /// 覆盖 spec web-adapters D12 Requirement: extractor 在 token 无效时拒绝请求。
    #[tokio::test]
    #[serial]
    async fn garrison_principal_returns_err_with_invalid_token() {
        init_manager();

        let req = test::TestRequest::get()
            .uri("/api/test")
            .insert_header(("Authorization", "Bearer invalid_token_xyz"))
            .to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let result = GarrisonPrincipal::from_request(&req, &mut payload).await;
        assert!(
            result.is_err(),
            "无效 token 时 from_request 应返回 Err，实际 = {:?}",
            result
        );

        GarrisonManager::reset_for_test();
    }
}

// ============================================================================
// TenantContext extractor 测试（feature gate tenant-isolation）
// ============================================================================

#[cfg(all(test, feature = "tenant-isolation"))]
mod tenant_tests {
    use crate::context::tenant::{TenantContext, TenantSource};
    use actix_web::test;
    use actix_web::FromRequest;
    use serial_test::serial;

    /// 验证 `TenantContext::from_request` 从 `X-Tenant-Id` header 解析出 `tenant_id`。
    ///
    /// 覆盖 spec web-adapters D12 + tenant-isolation Requirement:
    /// actix extractor 从 X-Tenant-Id header 解析 tenant_id。
    #[tokio::test]
    #[serial]
    async fn tenant_context_extracted_from_actix_request_when_tenant_isolation_enabled() {
        let req = test::TestRequest::get()
            .uri("/api/test")
            .insert_header(("X-Tenant-Id", "42"))
            .to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let ctx = TenantContext::from_request(&req, &mut payload)
            .await
            .expect("TenantContext::from_request 应成功解析 X-Tenant-Id header");

        assert_eq!(ctx.tenant_id, 42);
        assert_eq!(ctx.resolved_from, TenantSource::Header);
    }

    /// 验证 `TenantContext::from_request` 在无 `X-Tenant-Id` header 时返回错误。
    ///
    /// 覆盖 spec tenant-isolation Requirement: 缺失 header 时显式失败（不默认 0）。
    #[tokio::test]
    #[serial]
    async fn tenant_context_returns_err_without_x_tenant_id_header() {
        let req = test::TestRequest::get().uri("/api/test").to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let result = TenantContext::from_request(&req, &mut payload).await;
        assert!(
            result.is_err(),
            "无 X-Tenant-Id header 时 from_request 应返回 Err，实际 = {:?}",
            result
        );
    }

    /// 验证 `TenantContext::from_request` 在 `X-Tenant-Id` 非数字时返回错误。
    ///
    /// 覆盖 spec tenant-isolation Requirement: 非法 tenant_id 显式失败。
    #[tokio::test]
    #[serial]
    async fn tenant_context_returns_err_with_non_numeric_x_tenant_id() {
        let req = test::TestRequest::get()
            .uri("/api/test")
            .insert_header(("X-Tenant-Id", "not_a_number"))
            .to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let result = TenantContext::from_request(&req, &mut payload).await;
        assert!(
            result.is_err(),
            "X-Tenant-Id 非数字时 from_request 应返回 Err，实际 = {:?}",
            result
        );
    }
}
