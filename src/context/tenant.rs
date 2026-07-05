//! 多租户隔离上下文（依据 spec `tenant-isolation`）。
//!
//! 提供：
//! - `TenantContext`：租户上下文，携带 `tenant_id` 与来源标识
//! - `TenantSource`：租户解析来源（Header / Subdomain / Claim）
//! - `TENANT` task_local：跨 async 调用传播租户上下文
//! - `TenantResolver` trait + 三种实现（Header / Subdomain / Claim）
//!
//! ## 设计（依据 spec `tenant-isolation` Constraints）
//!
//! - 类型本身不依赖 `tenant-isolation` feature gate（feature 关闭时仍可构造）
//! - DAO key 前缀与 Repository SQL 过滤才由 feature 控制（见 T033-T034 / T031-T032）

use async_trait::async_trait;
use http::HeaderMap;
use std::collections::HashMap;

use crate::error::{BulwarkError, BulwarkResult};

/// 租户上下文来源标识（依据 spec `tenant-isolation` R-tenant-isolation-001）。
///
/// 描述 `TenantContext` 是从哪种渠道解析得到的，便于排障与审计。
///
/// # 变体
///
/// - `Header`：从 `X-Tenant-Id` 请求头提取
/// - `Subdomain`：从 `Host` 头的子域名提取并查映射表
/// - `Claim`：从 `Authorization: Bearer <jwt>` 的 `tenant_id` claim 提取
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantSource {
    /// 从 `X-Tenant-Id` 请求头提取。
    Header,
    /// 从 `Host` 头的子域名提取并查映射表。
    Subdomain,
    /// 从 `Authorization: Bearer <jwt>` 的 `tenant_id` claim 提取。
    Claim,
}

/// 租户上下文（依据 spec `tenant-isolation` R-tenant-isolation-001）。
///
/// 携带 `tenant_id` 与解析来源，通过 `TENANT` task_local 在 async 调用链中传播。
///
/// # 设计
///
/// - 类型本身不依赖 `tenant-isolation` feature gate（feature 关闭时仍可构造）
/// - DAO key 前缀与 Repository SQL 过滤才由 feature 控制
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    /// 租户 ID（0 表示默认/全局租户，向后兼容旧数据）。
    pub tenant_id: i64,
    /// 解析来源（Header / Subdomain / Claim）。
    pub resolved_from: TenantSource,
}

/// 租户上下文 task_local（依据 spec `tenant-isolation` R-tenant-isolation-001）。
///
/// 通过 `TENANT.scope(ctx, future).await` 进入租户上下文，
/// 在 future 内用 `TENANT.get()` 取当前 `TenantContext`，
/// 或用 `TENANT.try_get()` 在无上下文时返回 `None`（不 panic）。
//
// Note: `task_local!` 宏展开产生的项不接受 `///` doc 注释（rustc 警告 unused_doc_comments），
// 也不继承外部 `#[allow]` 属性；项目级 `#![warn(missing_docs)]` 在 clippy `-D warnings` 下升级为 deny。
// 因此把 `task_local!` 包在内部 module 中，对 module 加 `#[allow(missing_docs)]` 抑制展开项的缺文档告警，
// 文档说明放在 module 外上方。
#[allow(missing_docs)]
mod tenant_local {
    use super::TenantContext;

    tokio::task_local! {
        pub static TENANT: TenantContext;
    }
}

pub use tenant_local::TENANT;

/// 租户解析器 trait（依据 spec `tenant-isolation` R-tenant-isolation-002）。
///
/// 从 HTTP 请求头解析 `TenantContext`，三种实现：
/// - `HeaderTenantResolver`：从 `X-Tenant-Id` header 提取
/// - `SubdomainTenantResolver`：从 `Host` header 提取 subdomain 并查 mapping
/// - `ClaimTenantResolver`：从 `Authorization: Bearer <jwt>` 提取 `tenant_id` claim
///
/// # 设计
///
/// - 接受 `&HeaderMap`（`http::HeaderMap`，框架无关），actix/warp/axum 均基于 http crate
/// - 失败时返回 `BulwarkError`，不静默默认 0（Rule 12 失败显性化）
#[async_trait]
pub trait TenantResolver: Send + Sync {
    /// 从请求头解析租户上下文。
    ///
    /// # 参数
    /// - `headers`: HTTP 请求头（框架无关的 `http::HeaderMap`）
    ///
    /// # 返回
    /// - `Ok(TenantContext)`: 解析成功
    /// - `Err(BulwarkError)`: 解析失败（header 缺失/格式错误/JWT 验证失败等）
    async fn resolve(&self, headers: &HeaderMap) -> BulwarkResult<TenantContext>;
}

/// Header 租户解析器（依据 spec `tenant-isolation` R-tenant-isolation-002）。
///
/// 从 `X-Tenant-Id` 请求头提取 `tenant_id`（i64）。
///
/// # 行为
///
/// - header 存在且为合法 i64：返回 `TenantContext { tenant_id, resolved_from: Header }`
/// - header 缺失：返回 `BulwarkError::Config("X-Tenant-Id header missing".into())`
/// - header 格式非法（非 i64）：返回 `BulwarkError::Config`
///
/// # 设计
///
/// 不默认 0（Rule 12 失败显性化），缺失即报错——避免租户隔离被静默绕过。
#[derive(Debug, Clone, Default)]
pub struct HeaderTenantResolver;

#[async_trait]
impl TenantResolver for HeaderTenantResolver {
    async fn resolve(&self, headers: &HeaderMap) -> BulwarkResult<TenantContext> {
        let value = headers
            .get("X-Tenant-Id")
            .ok_or_else(|| BulwarkError::Config("X-Tenant-Id header missing".into()))?;
        let raw = value
            .to_str()
            .map_err(|e| BulwarkError::Config(format!("X-Tenant-Id not visible ASCII: {e}")))?;
        let tenant_id = raw
            .parse::<i64>()
            .map_err(|e| BulwarkError::Config(format!("invalid X-Tenant-Id `{raw}`: {e}")))?;
        Ok(TenantContext {
            tenant_id,
            resolved_from: TenantSource::Header,
        })
    }
}

/// Subdomain 租户解析器（依据 spec `tenant-isolation` R-tenant-isolation-002）。
///
/// 从 `Host` 请求头提取第一段作为 subdomain，查 `mapping` 表得到 `tenant_id`。
///
/// # 行为
///
/// - Host 存在且 subdomain 在 mapping 中：返回 `TenantContext { resolved_from: Subdomain }`
/// - Host 缺失：返回 `BulwarkError::Config("Host header missing")`
/// - subdomain 未在 mapping 中：返回 `BulwarkError::Config("unknown subdomain")`
///
/// # 设计
///
/// - Host 含端口时（如 `tenant42.example.com:8080`）先 strip port 再提取 subdomain
/// - 不默认 0（Rule 12 失败显性化），未命中即报错——避免租户隔离被静默绕过
#[derive(Debug, Clone, Default)]
pub struct SubdomainTenantResolver {
    /// subdomain → tenant_id 映射表（如 `{"tenant42": 42}`）。
    pub mapping: HashMap<String, i64>,
}

#[async_trait]
impl TenantResolver for SubdomainTenantResolver {
    async fn resolve(&self, headers: &HeaderMap) -> BulwarkResult<TenantContext> {
        let host = headers
            .get("Host")
            .ok_or_else(|| BulwarkError::Config("Host header missing".into()))?
            .to_str()
            .map_err(|e| BulwarkError::Config(format!("Host not visible ASCII: {e}")))?;
        // strip port: `tenant42.example.com:8080` → `tenant42.example.com`
        let hostname = host.split(':').next().unwrap_or(host);
        // extract first segment as subdomain
        let subdomain = hostname.split('.').next().unwrap_or(hostname);
        if subdomain.is_empty() {
            return Err(BulwarkError::Config(format!(
                "invalid Host `{host}`: empty subdomain"
            )));
        }
        let tenant_id = *self
            .mapping
            .get(subdomain)
            .ok_or_else(|| BulwarkError::Config(format!("unknown subdomain `{subdomain}`")))?;
        Ok(TenantContext {
            tenant_id,
            resolved_from: TenantSource::Subdomain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R-tenant-isolation-001: TenantContext 携带 tenant_id 与来源标识。
    ///
    /// 构造 `TenantContext { tenant_id: 42, resolved_from: TenantSource::Header }`，
    /// 断言字段可读。
    #[test]
    fn tenant_context_constructs_with_tenant_id_and_source() {
        let ctx = TenantContext {
            tenant_id: 42,
            resolved_from: TenantSource::Header,
        };
        assert_eq!(ctx.tenant_id, 42);
        assert!(matches!(ctx.resolved_from, TenantSource::Header));
    }

    /// R-tenant-isolation-002: HeaderTenantResolver 从 `X-Tenant-Id` 提取 tenant_id。
    ///
    /// 构造含 `X-Tenant-Id: 42` 的 `HeaderMap`，断言 `HeaderTenantResolver.resolve(&headers)`
    /// 返回 `TenantContext { tenant_id: 42, resolved_from: TenantSource::Header }`。
    #[tokio::test]
    async fn header_tenant_resolver_extracts_x_tenant_id() {
        let mut headers = http::HeaderMap::new();
        headers.insert("X-Tenant-Id", "42".parse().expect("valid header value"));
        let ctx = HeaderTenantResolver
            .resolve(&headers)
            .await
            .expect("X-Tenant-Id 存在时应解析成功");
        assert_eq!(ctx.tenant_id, 42);
        assert!(matches!(ctx.resolved_from, TenantSource::Header));
    }

    /// R-tenant-isolation-002: HeaderTenantResolver 在 header 缺失时返回 Config 错误（不默认 0）。
    #[tokio::test]
    async fn header_tenant_resolver_returns_config_error_when_header_missing() {
        let headers = http::HeaderMap::new();
        let result = HeaderTenantResolver.resolve(&headers).await;
        assert!(matches!(result, Err(BulwarkError::Config(_))));
    }

    /// R-tenant-isolation-002: HeaderTenantResolver 在 header 非法 i64 时返回 Config 错误。
    #[tokio::test]
    async fn header_tenant_resolver_returns_config_error_when_header_not_i64() {
        let mut headers = http::HeaderMap::new();
        headers.insert("X-Tenant-Id", "not-a-number".parse().unwrap());
        let result = HeaderTenantResolver.resolve(&headers).await;
        assert!(matches!(result, Err(BulwarkError::Config(_))));
    }

    /// R-tenant-isolation-001: TENANT.scope 进入租户上下文后 TENANT.get() 可取到 ctx.tenant_id。
    ///
    /// 验证 task_local! 的 scope/get 语义：在 scope 闭包内 `TENANT.get()` 返回
    /// 进入 scope 时传入的 `TenantContext` 引用。
    #[tokio::test]
    async fn tenant_scope_enter_returns_context_value() {
        let ctx = TenantContext {
            tenant_id: 42,
            resolved_from: TenantSource::Header,
        };
        let tenant_id = TENANT.scope(ctx, async { TENANT.get().tenant_id }).await;
        assert_eq!(tenant_id, 42);
    }

    /// R-tenant-isolation-003: TENANT.try_get() 在无 scope 上下文时返回 Err（不 panic）。
    ///
    /// 验证 DAO key 前缀逻辑的兜底条件：`TENANT.try_get().is_err()` 时 key 保持原样。
    #[tokio::test]
    async fn tenant_try_get_returns_err_when_no_scope() {
        // 在无 scope 上下文中调用 try_get，应返回 Err 而非 panic
        assert!(TENANT.try_get().is_err());
    }

    /// R-tenant-isolation-002: SubdomainTenantResolver 从 Host 提取 subdomain 并查 mapping。
    ///
    /// 构造 `Host: tenant42.example.com`，预置映射 `{"tenant42": 42}`，
    /// 断言 `SubdomainTenantResolver.resolve(&headers)` 返回 `tenant_id == 42`。
    #[tokio::test]
    async fn subdomain_tenant_resolver_extracts_from_host() {
        let mut headers = http::HeaderMap::new();
        headers.insert("Host", "tenant42.example.com".parse().unwrap());
        let resolver = SubdomainTenantResolver {
            mapping: std::collections::HashMap::from([("tenant42".to_string(), 42)]),
        };
        let ctx = resolver
            .resolve(&headers)
            .await
            .expect("Host 含已知 subdomain 时应解析成功");
        assert_eq!(ctx.tenant_id, 42);
        assert!(matches!(ctx.resolved_from, TenantSource::Subdomain));
    }

    /// R-tenant-isolation-002: SubdomainTenantResolver 在 mapping 未命中时返回 Config 错误。
    #[tokio::test]
    async fn subdomain_tenant_resolver_returns_config_error_when_mapping_miss() {
        let mut headers = http::HeaderMap::new();
        headers.insert("Host", "unknown.example.com".parse().unwrap());
        let resolver = SubdomainTenantResolver {
            mapping: std::collections::HashMap::from([("tenant42".to_string(), 42)]),
        };
        let result = resolver.resolve(&headers).await;
        assert!(matches!(result, Err(BulwarkError::Config(_))));
    }

    /// R-tenant-isolation-002: SubdomainTenantResolver 在 Host 缺失时返回 Config 错误。
    #[tokio::test]
    async fn subdomain_tenant_resolver_returns_config_error_when_host_missing() {
        let headers = http::HeaderMap::new();
        let resolver = SubdomainTenantResolver {
            mapping: std::collections::HashMap::new(),
        };
        let result = resolver.resolve(&headers).await;
        assert!(matches!(result, Err(BulwarkError::Config(_))));
    }

    /// R-tenant-isolation-002: SubdomainTenantResolver 处理带端口的 Host（如 tenant42.example.com:8080）。
    #[tokio::test]
    async fn subdomain_tenant_resolver_strips_port_from_host() {
        let mut headers = http::HeaderMap::new();
        headers.insert("Host", "tenant42.example.com:8080".parse().unwrap());
        let resolver = SubdomainTenantResolver {
            mapping: std::collections::HashMap::from([("tenant42".to_string(), 42)]),
        };
        let ctx = resolver
            .resolve(&headers)
            .await
            .expect("带端口的 Host 应正确提取 subdomain");
        assert_eq!(ctx.tenant_id, 42);
    }
}
