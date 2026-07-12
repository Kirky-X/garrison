//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! warp 框架 Extractor 适配器。
//!
//! 提供 `bulwark_principal` Filter：从 `Authorization: Bearer <token>` header
//! 解析当前登录用户 ID，返回 `BulwarkPrincipal` 供 handler 链使用。
//!
//! ## 设计
//!
//! - 与现有 `check_login` / `check_role` / `check_permission` Filter 互补：
//!   现有 Filter 仅执行鉴权（返回 `()`），`bulwark_principal` 携带
//!   `login_id` 字段供 handler 直接读取当前用户身份。
//! - `BulwarkPrincipal` 类型定义在 [`crate::context`] 模块，与 actix extractor 共享。
//!
//! ## 使用示例
//!
//! ```ignore
//! use bulwark::web_warp::bulwark_principal;
//! use std::sync::Arc;
//! use bulwark::config::BulwarkConfig;
//!
//! let config = Arc::new(BulwarkConfig::default_config());
//! let routes = warp::path("api")
//!     .and(bulwark_principal(config))
//!     .map(|principal| format!("login_id = {}", principal.login_id));
//! ```

use crate::config::BulwarkConfig;
use crate::context::BulwarkPrincipal;
use crate::error::BulwarkError;
use crate::stp::BulwarkUtil;
use std::sync::Arc;
use warp::http::HeaderMap;
use warp::Filter;

// ============================================================================
// bulwark_principal Filter：提取 login_id
// ============================================================================

/// `bulwark_principal` Filter：从请求 header 提取 token 并解析 `login_id`。
///
/// 返回 [`Filter`]，Extract 类型为 `(BulwarkPrincipal,)`，Error 类型为 `warp::Rejection`。
///
/// # 参数
///
/// - `config`: 全局配置（决定从 header 还是 cookie 提取 token）。
///
/// # 错误
///
/// - `BulwarkRejection(BulwarkError::NotLogin)`: 未提供 token 或 token 无效。
pub fn bulwark_principal(
    config: Arc<BulwarkConfig>,
) -> impl Filter<Extract = (BulwarkPrincipal,), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::headers_cloned())
        .and_then(move |headers: HeaderMap| {
            let config = config.clone();
            async move {
                let token = super::extract_token_from_headers(&headers, &config)
                    .map_err(|e| warp::reject::custom(super::BulwarkRejection(e)))?
                    .ok_or_else(|| {
                        warp::reject::custom(super::BulwarkRejection(BulwarkError::NotLogin(
                            "未提供 token".to_string(),
                        )))
                    })?;

                let login_id = BulwarkUtil::get_login_id_by_token(&token)
                    .await
                    .map_err(|e| warp::reject::custom(super::BulwarkRejection(e)))?
                    .ok_or_else(|| {
                        warp::reject::custom(super::BulwarkRejection(BulwarkError::NotLogin(
                            "token 无效或会话不存在".to_string(),
                        )))
                    })?;

                Ok::<BulwarkPrincipal, warp::Rejection>(BulwarkPrincipal { login_id })
            }
        })
}

// ============================================================================
// tenant_context Filter（feature gate tenant-isolation）
// ============================================================================

/// `tenant_context` Filter：从 `X-Tenant-Id` header 解析 `TenantContext`。
///
/// 返回 [`Filter`]，Extract 类型为 `(TenantContext,)`，Error 类型为 `warp::Rejection`。
///
/// # 错误
///
/// - `BulwarkRejection(BulwarkError::Config)`: `X-Tenant-Id` header 缺失或非合法 i64。
#[cfg(feature = "tenant-isolation")]
pub fn tenant_context(
) -> impl Filter<Extract = (crate::context::tenant::TenantContext,), Error = warp::Rejection> + Clone
{
    warp::any()
        .and(warp::header::headers_cloned())
        .and_then(|headers: HeaderMap| async move {
            let raw = headers
                .get("x-tenant-id")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    warp::reject::custom(super::BulwarkRejection(BulwarkError::Config(
                        "X-Tenant-Id header missing".into(),
                    )))
                })?;

            let tenant_id: i64 = raw.parse().map_err(|_| {
                warp::reject::custom(super::BulwarkRejection(BulwarkError::Config(format!(
                    "X-Tenant-Id 不是合法的 i64: {}",
                    raw
                ))))
            })?;

            Ok::<crate::context::tenant::TenantContext, warp::Rejection>(
                crate::context::tenant::TenantContext {
                    tenant_id,
                    resolved_from: crate::context::tenant::TenantSource::Header,
                },
            )
        })
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
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    // ----------------------------------------------------------------
    // MockDao / MockInterface（复用 web_warp/mod.rs 测试模式）
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
        async fn get(&self, key: &str) -> Result<Option<String>, BulwarkError> {
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

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), BulwarkError> {
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

        async fn update(&self, key: &str, value: &str) -> Result<(), BulwarkError> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((existing, _)) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> Result<(), BulwarkError> {
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
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn delete(&self, key: &str) -> Result<(), BulwarkError> {
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
        async fn get_permission_list(&self, login_id: &str) -> Result<Vec<String>, BulwarkError> {
            Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: &str) -> Result<Vec<String>, BulwarkError> {
            Ok(self.roles.get(login_id).cloned().unwrap_or_default())
        }
    }

    fn make_config() -> BulwarkConfig {
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = false;
        config
    }

    fn init_manager() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao, config, interface).unwrap();
    }

    // ----------------------------------------------------------------
    // bulwark_principal Filter 测试
    // ----------------------------------------------------------------

    /// 验证 `bulwark_principal` Filter 从 `Authorization: Bearer <token>`
    /// header 解析出 `login_id`。
    ///
    /// 覆盖 spec web-adapters D12 Requirement: warp extractor 从 token 解析 login_id。
    #[tokio::test]
    #[serial]
    async fn bulwark_principal_extracted_from_warp_request() {
        init_manager();
        let login_id = "2002";
        let token = BulwarkUtil::login_simple(login_id).await.unwrap();

        let config = Arc::new(make_config());
        let filter = bulwark_principal(config);

        let principal = warp::test::request()
            .header("Authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await
            .expect("bulwark_principal filter 应成功提取 BulwarkPrincipal");

        assert_eq!(principal.login_id, login_id);

        BulwarkManager::reset_for_test();
    }

    /// 验证 `bulwark_principal` Filter 在无 token 时返回 Rejection。
    ///
    /// 覆盖 spec web-adapters D12 Requirement: extractor 在无 token 时拒绝请求。
    #[tokio::test]
    #[serial]
    async fn bulwark_principal_returns_rejection_without_token() {
        init_manager();

        let config = Arc::new(make_config());
        let filter = bulwark_principal(config);

        let result = warp::test::request().filter(&filter).await;
        assert!(
            result.is_err(),
            "无 token 时 filter 应返回 Err，实际 = {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }

    /// 验证 `bulwark_principal` Filter 在无效 token 时返回 Rejection。
    ///
    /// 覆盖 spec web-adapters D12 Requirement: extractor 在 token 无效时拒绝请求。
    #[tokio::test]
    #[serial]
    async fn bulwark_principal_returns_rejection_with_invalid_token() {
        init_manager();

        let config = Arc::new(make_config());
        let filter = bulwark_principal(config);

        let result = warp::test::request()
            .header("Authorization", "Bearer invalid_token_xyz")
            .filter(&filter)
            .await;
        assert!(
            result.is_err(),
            "无效 token 时 filter 应返回 Err，实际 = {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }
}

// ============================================================================
// TenantContext Filter 测试（feature gate tenant-isolation）
// ============================================================================

#[cfg(all(test, feature = "tenant-isolation"))]
mod tenant_tests {
    use crate::context::tenant::TenantSource;
    use serial_test::serial;

    /// 验证 `tenant_context` Filter 从 `X-Tenant-Id` header 解析出 `tenant_id`。
    ///
    /// 覆盖 spec web-adapters D12 + tenant-isolation Requirement:
    /// warp extractor 从 X-Tenant-Id header 解析 tenant_id。
    #[tokio::test]
    #[serial]
    async fn tenant_context_extracted_from_warp_request_when_tenant_isolation_enabled() {
        let filter = super::tenant_context();

        let ctx = warp::test::request()
            .header("X-Tenant-Id", "42")
            .filter(&filter)
            .await
            .expect("tenant_context filter 应成功提取 TenantContext");

        assert_eq!(ctx.tenant_id, 42);
        assert_eq!(ctx.resolved_from, TenantSource::Header);
    }

    /// 验证 `tenant_context` Filter 在无 `X-Tenant-Id` header 时返回 Rejection。
    ///
    /// 覆盖 spec tenant-isolation Requirement: 缺失 header 时显式失败。
    #[tokio::test]
    #[serial]
    async fn tenant_context_returns_rejection_without_x_tenant_id_header() {
        let filter = super::tenant_context();

        let result = warp::test::request().filter(&filter).await;
        assert!(
            result.is_err(),
            "无 X-Tenant-Id header 时 filter 应返回 Err，实际 = {:?}",
            result
        );
    }

    /// 验证 `tenant_context` Filter 在 `X-Tenant-Id` 非数字时返回 Rejection。
    ///
    /// 覆盖 spec tenant-isolation Requirement: 非法 tenant_id 显式失败。
    #[tokio::test]
    #[serial]
    async fn tenant_context_returns_rejection_with_non_numeric_x_tenant_id() {
        let filter = super::tenant_context();

        let result = warp::test::request()
            .header("X-Tenant-Id", "not_a_number")
            .filter(&filter)
            .await;
        assert!(
            result.is_err(),
            "X-Tenant-Id 非数字时 filter 应返回 Err，实际 = {:?}",
            result
        );
    }
}
