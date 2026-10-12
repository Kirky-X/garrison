// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! actix-web Extractor 适配器：`GarrisonPrincipal`（Bearer token → `login_id`）、
//! `CheckLogin`/`CheckRole`/`CheckPermission`（per-handler 鉴权，struct 声明在 `mod.rs`）、
//! `TenantContext`（`tenant-isolation`，从 `X-Tenant-Id` 解析租户）。
//! 前者携带身份信息、后者仅鉴权校验；命名与 `GarrisonContext` trait 区分以免冲突。
//!
//! ## 使用示例
//!
//! ```ignore
//! use garrison::web_actix::GarrisonPrincipal;
//!
//! async fn handler(principal: GarrisonPrincipal) -> String {
//! format!("login_id = {}", principal.login_id)
//! }
//! ```

// GarrisonPrincipal：携带 login_id 的 extractor

use crate::context::token_extract::extract_token_from_headers;

/// `GarrisonConfig` 未注册为 actix app_data 时的一次性告警：各 extractor 回退 `default_config`，
/// 安全参数可能不一致；选择回退而非 fail-fast，但以 warn 显性提示。
fn warn_missing_config_once() {
    static WARN: std::sync::Once = std::sync::Once::new();
    WARN.call_once(|| {
        tracing::warn!(
            "{}",
            crate::i18n::translate_detail("logs-actix-config-not-registered", &[])
        );
    });
}

pub use crate::context::GarrisonPrincipal;

/// 从 `Authorization: Bearer <token>` 提取 token 并解析关联 `login_id`；无 token 或无效返回 `NotLogin`。
impl actix_web::FromRequest for GarrisonPrincipal {
    type Error = crate::error::GarrisonError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        let config = req
            .app_data::<actix_web::web::Data<std::sync::Arc<crate::config::GarrisonConfig>>>()
            .map(|d| d.get_ref().clone())
            .unwrap_or_else(|| {
                warn_missing_config_once();
                std::sync::Arc::new(crate::config::GarrisonConfig::default_config())
            });

        Box::pin(async move {
            let token = extract_token_from_headers(&headers, &config)?.ok_or_else(|| {
                crate::error::GarrisonError::NotLogin("web-not-login::".to_string())
            })?;

            let login_id = crate::stp::GarrisonUtil::get_login_id_by_token(&token)
                .await?
                .ok_or_else(|| {
                    crate::error::GarrisonError::NotLogin("web-token-invalid::".to_string())
                })?;

            Ok(GarrisonPrincipal { login_id })
        })
    }
}

// CheckLogin / CheckRole / CheckPermission extractors：per-handler 鉴权，struct 声明在 mod.rs，此处仅 FromRequest 实现。

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
            .unwrap_or_else(|| {
                warn_missing_config_once();
                std::sync::Arc::new(crate::config::GarrisonConfig::default_config())
            });

        Box::pin(async move {
            let token = extract_token_from_headers(&headers, &config)?.ok_or_else(|| {
                crate::error::GarrisonError::NotLogin("web-not-login::".to_string())
            })?;

            let result: crate::error::GarrisonResult<()> =
                crate::stp::with_current_token(token, async {
                    let logged_in = crate::stp::GarrisonUtil::check_login().await?;
                    if !logged_in {
                        return Err(crate::error::GarrisonError::NotLogin(
                            "web-not-login::".to_string(),
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
///
/// 角色名必须经 `web::Data<RequiredRole>` 服务端配置，禁止从客户端可控的 header/query 读取
/// （否则 `?role=admin` 可绕过鉴权）。
///
/// # 使用
///
/// ```ignore
/// use garrison::web_actix::RequiredRole;
/// use actix_web::web;
///
/// App::new()
/// .app_data(web::Data::new(RequiredRole("admin".to_string())))
/// .route("/admin", web::get().to(admin_handler))
/// ```
impl actix_web::FromRequest for super::CheckRole {
    type Error = crate::error::GarrisonError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        let config = req
            .app_data::<actix_web::web::Data<std::sync::Arc<crate::config::GarrisonConfig>>>()
            .map(|d| d.get_ref().clone())
            .unwrap_or_else(|| {
                warn_missing_config_once();
                std::sync::Arc::new(crate::config::GarrisonConfig::default_config())
            });

        // 角色仅取服务端配置，禁止客户端可控来源（防 `?role=admin` 绕过）
        let role = req
            .app_data::<actix_web::web::Data<super::RequiredRole>>()
            .map(|d| d.0.clone())
            .unwrap_or_default();

        Box::pin(async move {
            let token = extract_token_from_headers(&headers, &config)?.ok_or_else(|| {
                crate::error::GarrisonError::NotLogin("web-not-login::".to_string())
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
///
/// 权限名必须经 `web::Data<RequiredPermission>` 服务端配置，禁止从客户端可控的 header/query 读取
/// （否则 `?permission=user:read` 可绕过鉴权）。
///
/// # 使用
///
/// ```ignore
/// use garrison::web_actix::RequiredPermission;
/// use actix_web::web;
///
/// App::new()
/// .app_data(web::Data::new(RequiredPermission("user:read".to_string())))
/// .route("/data", web::get().to(data_handler))
/// ```
impl actix_web::FromRequest for super::CheckPermission {
    type Error = crate::error::GarrisonError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        let config = req
            .app_data::<actix_web::web::Data<std::sync::Arc<crate::config::GarrisonConfig>>>()
            .map(|d| d.get_ref().clone())
            .unwrap_or_else(|| {
                warn_missing_config_once();
                std::sync::Arc::new(crate::config::GarrisonConfig::default_config())
            });

        // 权限仅取服务端配置，禁止客户端可控来源（防 `?permission=xxx` 绕过）
        let permission = req
            .app_data::<actix_web::web::Data<super::RequiredPermission>>()
            .map(|d| d.0.clone())
            .unwrap_or_default();

        Box::pin(async move {
            let token = extract_token_from_headers(&headers, &config)?.ok_or_else(|| {
                crate::error::GarrisonError::NotLogin("web-not-login::".to_string())
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

// TenantContext extractor（feature gate tenant-isolation）

/// `X-Tenant-Id` header 信任模型一次性告警（防日志刷屏）。
#[cfg(feature = "tenant-isolation")]
fn warn_header_tenant_unverified_once() {
    static WARN: std::sync::Once = std::sync::Once::new();
    WARN.call_once(|| {
        tracing::warn!(
            "{}",
            crate::i18n::translate_detail("logs-actix-tenant-header-unverified", &[])
        );
    });
}

/// 从 `X-Tenant-Id` header 解析 `TenantContext`，仅做格式校验（非空 + i64 解析）：
/// **不与认证主体做归属授权比对**（框架 `SessionData` 无主体→租户映射），也不校验租户注册表，
/// 该值客户端可控——任何调用方可声明任意租户 ID。直接信任做隔离（缓存前缀、数据过滤）存在跨租户越权风险。
/// 正确做法：用 `ClaimTenantResolver`（token claim）等服务端可信来源，或业务层校验主体与租户归属，
/// 或仅用于路由/审计标注而不作为隔离边界。
#[cfg(feature = "tenant-isolation")]
impl actix_web::FromRequest for crate::context::tenant::TenantContext {
    type Error = crate::error::GarrisonError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        warn_header_tenant_unverified_once();
        Box::pin(async move {
            let raw = headers
                .get("x-tenant-id")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    crate::error::GarrisonError::Config("ctx-tenant-id-missing::".into())
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

    async fn init_manager() {
        GarrisonManager::reset_for_test();
        let dao: std::sync::Arc<dyn GarrisonDao> = std::sync::Arc::new(MockDao::new());
        let config = std::sync::Arc::new(make_config());
        let interface: std::sync::Arc<dyn GarrisonInterface> =
            std::sync::Arc::new(MockInterface::new());
        GarrisonManager::builder()
            .dao(dao)
            .config(config)
            .interface(interface)
            .build()
            .await
            .unwrap();
    }

    // GarrisonPrincipal extractor 测试

    /// 从 `Authorization: Bearer <token>` header 解析出 `login_id`。
    #[tokio::test]
    #[serial]
    async fn garrison_principal_extracted_from_actix_request() {
        init_manager().await;
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

    /// `GarrisonPrincipal::from_request` 无 token 时返回 `NotLogin` 错误。
    #[tokio::test]
    #[serial]
    async fn garrison_principal_returns_err_without_token() {
        init_manager().await;

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

    /// `GarrisonPrincipal::from_request` 无效 token 时返回错误。
    #[tokio::test]
    #[serial]
    async fn garrison_principal_returns_err_with_invalid_token() {
        init_manager().await;

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

// TenantContext extractor 测试（feature gate tenant-isolation）

#[cfg(all(test, feature = "tenant-isolation"))]
mod tenant_tests {
    use crate::context::tenant::{TenantContext, TenantSource};
    use actix_web::test;
    use actix_web::FromRequest;
    use serial_test::serial;

    /// `X-Tenant-Id` header 解析出 `tenant_id`。
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

    /// 无 `X-Tenant-Id` header 时返回错误（显式失败，不默认 0）。
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

    /// `X-Tenant-Id` 非数字时返回错误（显式失败）。
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
