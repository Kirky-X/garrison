//! actix-web Extractor 适配器（依据 spec web-adapters D12）。
//!
//! 提供 `BulwarkPrincipal` extractor：从 `Authorization: Bearer <token>` header
//! 解析当前登录用户 ID，供 handler 参数注入使用。
//!
//! ## 设计
//!
//! - 与现有 `CheckLogin` / `CheckRole` / `CheckPermission` extractor 互补：
//!   现有 extractor 仅执行鉴权（返回 unit-like struct），`BulwarkPrincipal` 携带
//!   `login_id` 字段供 handler 直接读取当前用户身份。
//! - 与 `BulwarkContext` trait（请求/响应/存储上下文抽象层）解耦：trait 名字保持不变，
//!   extractor 使用不同名称 `BulwarkPrincipal` 避免命名冲突（Rule 7 决策）。
//!
//! ## 使用示例
//!
//! ```ignore
//! use bulwark::web_actix::BulwarkPrincipal;
//!
//! async fn handler(principal: BulwarkPrincipal) -> String {
//!     format!("login_id = {}", principal.login_id)
//! }
//! ```

// ============================================================================
// BulwarkPrincipal：携带 login_id 的 extractor
// ============================================================================

pub use crate::context::BulwarkPrincipal;

/// 实现 `FromRequest`：从 `Authorization: Bearer <token>` header 提取 token，
/// 调用 `BulwarkUtil::get_login_id_by_token` 解析关联的 `login_id`。
///
/// # 错误
///
/// - `BulwarkError::NotLogin`: 未提供 token 或 token 无效。
impl actix_web::FromRequest for BulwarkPrincipal {
    type Error = crate::error::BulwarkError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        let config = req
            .app_data::<actix_web::web::Data<std::sync::Arc<crate::config::BulwarkConfig>>>()
            .map(|d| d.get_ref().clone())
            .unwrap_or_else(|| std::sync::Arc::new(crate::config::BulwarkConfig::default_config()));

        Box::pin(async move {
            let token = super::extract_token_from_headers(&headers, &config)?
                .ok_or_else(|| crate::error::BulwarkError::NotLogin("未提供 token".to_string()))?;

            let login_id = crate::stp::BulwarkUtil::get_login_id_by_token(&token)
                .await?
                .ok_or_else(|| {
                    crate::error::BulwarkError::NotLogin("token 无效或会话不存在".to_string())
                })?;

            Ok(BulwarkPrincipal { login_id })
        })
    }
}

// ============================================================================
// TenantContext extractor（feature gate tenant-isolation）
// ============================================================================

#[cfg(feature = "tenant-isolation")]
impl actix_web::FromRequest for crate::context::tenant::TenantContext {
    type Error = crate::error::BulwarkError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        Box::pin(async move {
            let raw = headers
                .get("x-tenant-id")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    crate::error::BulwarkError::Config("X-Tenant-Id header missing".into())
                })?;

            let tenant_id: i64 = raw.parse().map_err(|_| {
                crate::error::BulwarkError::Config(format!("X-Tenant-Id 不是合法的 i64: {}", raw))
            })?;

            Ok(crate::context::tenant::TenantContext {
                tenant_id,
                resolved_from: crate::context::tenant::TenantSource::Header,
            })
        })
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::BulwarkDao;
    use crate::manager::BulwarkManager;
    use crate::stp::{BulwarkInterface, BulwarkUtil};
    use actix_web::test;
    use actix_web::FromRequest;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    // ----------------------------------------------------------------
    // MockDao / MockInterface（复用 web_actix/mod.rs 测试模式）
    // ----------------------------------------------------------------

    struct MockDao {
        store: Mutex<HashMap<String, (String, Option<Instant>)>>,
    }

    impl MockDao {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BulwarkDao for MockDao {
        async fn get(&self, key: &str) -> Result<Option<String>, crate::error::BulwarkError> {
            let mut store = self.store.lock();
            match store.get(key) {
                Some((value, expire_at)) => {
                    if let Some(deadline) = expire_at {
                        if Instant::now() >= *deadline {
                            store.remove(key);
                            return Ok(None);
                        }
                    }
                    Ok(Some(value.clone()))
                },
                None => Ok(None),
            }
        }

        async fn set(
            &self,
            key: &str,
            value: &str,
            ttl_seconds: u64,
        ) -> Result<(), crate::error::BulwarkError> {
            let expire_at = if ttl_seconds == 0 {
                None
            } else {
                Some(Instant::now() + Duration::from_secs(ttl_seconds))
            };
            self.store
                .lock()
                .insert(key.to_string(), (value.to_string(), expire_at));
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> Result<(), crate::error::BulwarkError> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((existing, _)) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(crate::error::BulwarkError::Dao(format!(
                    "键不存在: {}",
                    key
                ))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> Result<(), crate::error::BulwarkError> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((_, expire_at)) => {
                    *expire_at = if seconds == 0 {
                        None
                    } else {
                        Some(Instant::now() + Duration::from_secs(seconds))
                    };
                    Ok(())
                },
                None => Err(crate::error::BulwarkError::Dao(format!(
                    "键不存在: {}",
                    key
                ))),
            }
        }

        async fn delete(&self, key: &str) -> Result<(), crate::error::BulwarkError> {
            self.store.lock().remove(key);
            Ok(())
        }
    }

    struct MockInterface {
        permissions: HashMap<String, Vec<String>>,
        roles: HashMap<String, Vec<String>>,
    }

    impl MockInterface {
        fn new() -> Self {
            Self {
                permissions: HashMap::new(),
                roles: HashMap::new(),
            }
        }
    }

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(
            &self,
            login_id: &str,
        ) -> Result<Vec<String>, crate::error::BulwarkError> {
            Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
        }

        async fn get_role_list(
            &self,
            login_id: &str,
        ) -> Result<Vec<String>, crate::error::BulwarkError> {
            Ok(self.roles.get(login_id).cloned().unwrap_or_default())
        }
    }

    fn make_config() -> crate::config::BulwarkConfig {
        let mut config = crate::config::BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = false;
        config
    }

    fn init_manager() {
        BulwarkManager::reset_for_test();
        let dao: std::sync::Arc<dyn BulwarkDao> = std::sync::Arc::new(MockDao::new());
        let config = std::sync::Arc::new(make_config());
        let interface: std::sync::Arc<dyn BulwarkInterface> =
            std::sync::Arc::new(MockInterface::new());
        BulwarkManager::init(dao, config, interface).unwrap();
    }

    // ----------------------------------------------------------------
    // BulwarkPrincipal extractor 测试
    // ----------------------------------------------------------------

    /// 验证 `BulwarkPrincipal::from_request` 从 `Authorization: Bearer <token>`
    /// header 解析出 `login_id`。
    ///
    /// 覆盖 spec web-adapters D12 Requirement: actix extractor 从 token 解析 login_id。
    #[tokio::test]
    #[serial]
    async fn bulwark_principal_extracted_from_actix_request() {
        init_manager();
        let login_id = "1001";
        let token = BulwarkUtil::login(login_id).await.unwrap();

        let req = test::TestRequest::get()
            .uri("/api/test")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let principal = BulwarkPrincipal::from_request(&req, &mut payload)
            .await
            .expect("BulwarkPrincipal::from_request 应成功解析 token");

        assert_eq!(principal.login_id, login_id);

        BulwarkManager::reset_for_test();
    }

    /// 验证 `BulwarkPrincipal::from_request` 在无 token 时返回 `NotLogin` 错误。
    ///
    /// 覆盖 spec web-adapters D12 Requirement: extractor 在无 token 时拒绝请求。
    #[tokio::test]
    #[serial]
    async fn bulwark_principal_returns_err_without_token() {
        init_manager();

        let req = test::TestRequest::get().uri("/api/test").to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let result = BulwarkPrincipal::from_request(&req, &mut payload).await;
        assert!(
            result.is_err(),
            "无 token 时 from_request 应返回 Err，实际 = {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }

    /// 验证 `BulwarkPrincipal::from_request` 在无效 token 时返回错误。
    ///
    /// 覆盖 spec web-adapters D12 Requirement: extractor 在 token 无效时拒绝请求。
    #[tokio::test]
    #[serial]
    async fn bulwark_principal_returns_err_with_invalid_token() {
        init_manager();

        let req = test::TestRequest::get()
            .uri("/api/test")
            .insert_header(("Authorization", "Bearer invalid_token_xyz"))
            .to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let result = BulwarkPrincipal::from_request(&req, &mut payload).await;
        assert!(
            result.is_err(),
            "无效 token 时 from_request 应返回 Err，实际 = {:?}",
            result
        );

        BulwarkManager::reset_for_test();
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
