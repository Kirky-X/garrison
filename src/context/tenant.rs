//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 多租户隔离上下文。
//!
//! 提供：
//! - `TenantContext`：租户上下文，携带 `tenant_id` 与来源标识
//! - `TenantSource`：租户解析来源（Header / Subdomain / Claim）
//! - `TENANT` task_local：跨 async 调用传播租户上下文
//! - `TenantResolver` trait + 三种实现（Header / Subdomain / Claim）
//!
//! ## 设计
//!
//! - 类型本身不依赖 `tenant-isolation` feature gate（feature 关闭时仍可构造）
//! - DAO key 前缀与 Repository SQL 过滤才由 feature 控制（见 T033-T034 / T031-T032）

use async_trait::async_trait;
use http::HeaderMap;
use std::collections::HashMap;

use crate::error::{BulwarkError, BulwarkResult};

/// 租户上下文来源标识。
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

/// 租户上下文。
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

/// 租户上下文 task_local。
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

/// 读取当前 task_local 中的 tenant_id（无上下文时返回 0）。
///
/// 供 `BulwarkLogicDefault::check_permission`（构造 `AuthRequest`）和
/// `AuditLogListener::to_audit_entry`（填充审计日志 tenant_id）使用。
/// 在未进入 `TENANT.scope` 时返回 0（向后兼容单租户场景）。
///
/// # ⚠️ 已弃用（vuln-0003 修复）
///
/// 无上下文时静默返回 0 会导致租户隔离被绕过——多租户环境下 `tenant_id=0`
/// 可能命中默认租户的数据。新代码应使用：
/// - [`current_tenant_id_strict`]：返回 `Option<i64>`，调用方显式处理 `None`
/// - [`current_tenant_id_or_error`]：返回 `BulwarkResult<i64>`，无上下文时 `Err(Config)`
///
/// 仅在 `tenant-isolation` feature 关闭的向后兼容场景下使用本函数，
/// 并应在调用处用 `#[allow(deprecated)]` 显式标注保留原因。
#[deprecated(
    since = "0.7.0",
    note = "使用 current_tenant_id_strict() 或 current_tenant_id_or_error() 替代，避免租户隔离静默绕过（vuln-0003）"
)]
pub fn current_tenant_id() -> i64 {
    TENANT.try_get().map(|ctx| ctx.tenant_id).unwrap_or(0)
}

/// 读取当前 task_local 中的 tenant_id（无上下文时返回 `None`）。
///
/// 与 [`current_tenant_id`] 的差异：后者在无上下文时返回 `0`（向后兼容单租户场景），
/// 本函数返回 `None`，用于多租户严格隔离场景——调用方必须显式处理"无租户上下文"的情况，
/// 避免租户隔离被静默绕过（Rule 12 失败显性化）。
///
/// # 返回
///
/// - `Some(tenant_id)`：当前在 `TENANT.scope` 内，返回上下文中的 `tenant_id`
/// - `None`：未进入 `TENANT.scope`，调用方应决定如何处理（返回错误 / 使用默认值 / panic）
///
/// # 适用场景
///
/// - `tenant-isolation` feature 启用时的审计日志写入（`to_audit_entry`）：无租户上下文应报错
/// - 多租户严格隔离的缓存 key 前缀生成：无租户上下文不应静默退化为 `tenant:0:`
pub fn current_tenant_id_strict() -> Option<i64> {
    TENANT.try_get().ok().map(|ctx| ctx.tenant_id)
}

/// 读取当前 task_local 中的 tenant_id（无上下文时返回 `Err(Config)`，fail-closed）。
///
/// 与 [`current_tenant_id_strict`] 的差异：后者返回 `Option<i64>` 由调用方决定如何处理 `None`，
/// 本函数直接返回 `BulwarkResult<i64>`，无上下文时返回 `Err(BulwarkError::Config)`，
/// 强制 fail-closed（Rule 12 失败显性化 + 安全框架默认拒绝）。
///
/// # 返回
///
/// - `Ok(tenant_id)`：当前在 `TENANT.scope` 内，返回上下文中的 `tenant_id`
/// - `Err(BulwarkError::Config)`：未进入 `TENANT.scope`，租户隔离校验失败
///
/// # 适用场景
///
/// - 多租户严格隔离的权限校验（`AuthRequest` 构造）：无租户上下文应拒绝请求
/// - 多租户严格隔离的缓存 key 前缀生成：无租户上下文应报错而非退化为 `tenant:0:`
///
/// # vuln-0003 修复
///
/// 旧 `current_tenant_id()` 在无上下文时返回 0，可能导致多租户环境下 `tenant_id=0`
/// 命中默认租户数据，绕过租户隔离。本函数强制 fail-closed，避免静默绕过。
pub fn current_tenant_id_or_error() -> BulwarkResult<i64> {
    current_tenant_id_strict().ok_or_else(|| {
        BulwarkError::Config("无租户上下文，租户隔离校验失败（current_tenant_id_or_error）".into())
    })
}

/// 租户解析器 trait。
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

/// Header 租户解析器。
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

/// Subdomain 租户解析器。
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

/// Claim 租户解析器。
///
/// 从 `Authorization: Bearer <jwt>` 提取 JWT，验证签名后解码 `tenant_id` claim。
///
/// # 行为
///
/// - Authorization header 存在且为 `Bearer <jwt>`（大小写不敏感，RFC 7235）：
///   验证 JWT 签名（HS256）+ exp + 解码 `tenant_id` claim
/// - Authorization 缺失：返回 `BulwarkError::InvalidToken`
/// - 非 Bearer scheme：返回 `BulwarkError::InvalidToken`
/// - JWT 签名验证失败：返回 `BulwarkError::InvalidToken`
/// - `tenant_id` claim 缺失：返回 `BulwarkError::InvalidToken`
///
/// # 设计
///
/// - 门控在 `protocol-jwt` feature 下（依赖 `jsonwebtoken` crate）
/// - Bearer scheme 大小写不敏感（RFC 7235：`Bearer`/`bearer`/`BEARER` 均合法）
/// - 不默认 0（Rule 12 失败显性化），任何失败均返回 `InvalidToken`
#[cfg(feature = "protocol-jwt")]
#[derive(Debug, Clone)]
pub struct ClaimTenantResolver {
    /// JWT 验签密钥（HS256）。
    pub jwt_secret: String,
}

#[cfg(feature = "protocol-jwt")]
impl ClaimTenantResolver {
    /// 构造 ClaimTenantResolver。
    pub fn new(jwt_secret: String) -> Self {
        Self { jwt_secret }
    }
}

/// JWT claims 中仅提取 `tenant_id` 字段。
///
/// 其他 claim（如 `sub`/`iat`/`exp`）由 `jsonwebtoken` 自动验证 exp，
/// 这里只反序列化 `tenant_id`，缺失时 serde 报错转为 `InvalidToken`。
#[cfg(feature = "protocol-jwt")]
#[derive(serde::Deserialize)]
struct TenantClaims {
    tenant_id: i64,
}

#[cfg(feature = "protocol-jwt")]
#[async_trait]
impl TenantResolver for ClaimTenantResolver {
    async fn resolve(&self, headers: &HeaderMap) -> BulwarkResult<TenantContext> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        let auth = headers
            .get("Authorization")
            .ok_or_else(|| BulwarkError::InvalidToken("Authorization header missing".into()))?
            .to_str()
            .map_err(|e| {
                BulwarkError::InvalidToken(format!("Authorization not visible ASCII: {e}"))
            })?;
        // 解析 `<scheme> <token>`，scheme 大小写不敏感（RFC 7235）
        let mut parts = auth.splitn(2, ' ');
        let scheme = parts
            .next()
            .ok_or_else(|| BulwarkError::InvalidToken("empty Authorization header".into()))?;
        let jwt = parts.next().ok_or_else(|| {
            BulwarkError::InvalidToken("missing token in Authorization header".into())
        })?;
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return Err(BulwarkError::InvalidToken(format!(
                "unsupported auth scheme `{scheme}` (expected Bearer)"
            )));
        }
        // 验证 JWT 签名 + exp，解码 tenant_id claim
        let key = DecodingKey::from_secret(self.jwt_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.leeway = 0;
        let data = decode::<TenantClaims>(jwt, &key, &validation)
            .map_err(|e| BulwarkError::InvalidToken(format!("JWT verify failed: {e}")))?;
        Ok(TenantContext {
            tenant_id: data.claims.tenant_id,
            resolved_from: TenantSource::Claim,
        })
    }
}

// ============================================================================
// 测试专用 helper（Rule 9：测试桩显式设置 TENANT scope，避免 Rule 12 fail-closed 误触发）
// ============================================================================

/// 测试专用：用默认 `TenantContext { tenant_id: 0, resolved_from: Header }` 包裹 future。
///
/// `tenant-isolation` feature 启用时，`BulwarkLogicDefault::check_permission` 会调用
/// `current_tenant_id_or_error()`（fail-closed）。permission 相关测试验证的是权限逻辑，
/// 不是 tenant 隔离——tenant 隔离有专门测试（本模块 `tests`）。因此 permission 测试应
/// 显式设置默认 TENANT scope 作为测试桩（Rule 9 测试必须有意义），而非修改生产代码
/// 用 `unwrap_or(0)` 规避（Rule 12 失败必须显性化）。
///
/// # 使用
///
/// ```ignore
/// #[tokio::test]
/// async fn my_permission_test() {
///     with_default_tenant(async {
///         // 此处调用 check_permission / has_permission / handler
///     }).await;
/// }
/// ```
///
/// # 门控
///
/// `#[cfg(any(test, feature = "testing"))]`——单元测试（`cfg(test)`）与集成测试
/// （`testing` feature，tests/ 目录外部二进制）均可用。
#[cfg(any(test, feature = "testing"))]
pub async fn with_default_tenant<F, R>(f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    let ctx = TenantContext {
        tenant_id: 0,
        resolved_from: TenantSource::Header,
    };
    TENANT.scope(ctx, f).await
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

    /// H2: `current_tenant_id_strict` 在未进入 `TENANT.scope` 时返回 `None`（不 panic）。
    ///
    /// 与 `current_tenant_id` 的 `unwrap_or(0)` 不同，strict 版本要求调用方显式处理无上下文场景，
    /// 避免租户隔离被静默绕过（Rule 12 失败显性化）。
    #[tokio::test]
    async fn strict_returns_none_without_scope() {
        assert_eq!(current_tenant_id_strict(), None);
    }

    /// H2: `current_tenant_id_strict` 在 `TENANT.scope` 内返回 `Some(tenant_id)`。
    ///
    /// 在 `TENANT.scope(TenantContext { tenant_id: 42, .. }, async { current_tenant_id_strict() })` 内
    /// 断言返回 `Some(42)`，验证 strict 版本能正确读取 task_local 上下文。
    #[tokio::test]
    async fn strict_returns_some_with_scope() {
        let ctx = TenantContext {
            tenant_id: 42,
            resolved_from: TenantSource::Header,
        };
        let result = TENANT
            .scope(ctx, async { current_tenant_id_strict() })
            .await;
        assert_eq!(result, Some(42));
    }

    // ========================================================================
    // vuln-0003 修复：current_tenant_id_or_error 测试
    // ========================================================================

    /// vuln-0003: `current_tenant_id_or_error` 在无 `TENANT.scope` 时返回 `Err(Config)`（fail-closed）。
    ///
    /// 与旧 `current_tenant_id()` 返回 0 的行为对比：本函数强制返回错误，
    /// 避免租户隔离被静默绕过（Rule 12 失败显性化）。
    #[tokio::test]
    async fn or_error_returns_err_when_no_scope() {
        let result = current_tenant_id_or_error();
        assert!(
            result.is_err(),
            "无 scope 时应 fail-closed 返回 Err: {:?}",
            result.ok()
        );
        match result {
            Err(BulwarkError::Config(msg)) => {
                assert!(
                    msg.contains("无租户上下文") || msg.contains("租户隔离"),
                    "错误消息应含 '无租户上下文' 或 '租户隔离'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 Config 错误，实际: {:?}", other),
            Ok(_) => panic!("期望 Err(fail-closed)，实际 Ok"),
        }
    }

    /// vuln-0003: `current_tenant_id_or_error` 在 `TENANT.scope` 内返回 `Ok(tenant_id)`。
    ///
    /// 在 `TENANT.scope(TenantContext { tenant_id: 42, .. }, async { current_tenant_id_or_error() })` 内
    /// 断言返回 `Ok(42)`，验证函数能正确读取 task_local 上下文。
    #[tokio::test]
    async fn or_error_returns_ok_with_scope() {
        let ctx = TenantContext {
            tenant_id: 42,
            resolved_from: TenantSource::Header,
        };
        let result = TENANT
            .scope(ctx, async { current_tenant_id_or_error() })
            .await;
        assert!(result.is_ok(), "scope 内应返回 Ok: {:?}", result.err());
        assert_eq!(result.unwrap(), 42);
    }

    /// vuln-0003: `current_tenant_id_or_error` 在不同 tenant_id 值下正确读取。
    ///
    /// 覆盖 tenant_id=0（合法的默认租户）、负数、大数等边界值，
    /// 确保函数不依赖具体 tenant_id 值，只依赖 scope 是否存在。
    #[tokio::test]
    async fn or_error_handles_various_tenant_ids() {
        // tenant_id = 0（合法的默认租户，scope 已进入）
        let ctx0 = TenantContext {
            tenant_id: 0,
            resolved_from: TenantSource::Header,
        };
        let result0 = TENANT
            .scope(ctx0, async { current_tenant_id_or_error() })
            .await;
        assert!(result0.is_ok(), "tenant_id=0 + scope 应 Ok");
        assert_eq!(result0.unwrap(), 0);

        // tenant_id = i64::MAX（边界值）
        let ctx_max = TenantContext {
            tenant_id: i64::MAX,
            resolved_from: TenantSource::Header,
        };
        let result_max = TENANT
            .scope(ctx_max, async { current_tenant_id_or_error() })
            .await;
        assert!(result_max.is_ok());
        assert_eq!(result_max.unwrap(), i64::MAX);
    }

    /// vuln-0003: 旧 `current_tenant_id()` 已被 `#[deprecated]` 标注，但在 `#[allow(deprecated)]` 下仍可调用。
    ///
    /// 验证 deprecation 不破坏向后兼容——现有代码可用 `#[allow(deprecated)]` 显式抑制警告，
    /// 同时新代码应迁移到 `current_tenant_id_strict` / `current_tenant_id_or_error`。
    #[tokio::test]
    #[allow(deprecated)]
    async fn deprecated_current_tenant_id_still_callable_with_allow() {
        // 无 scope 时返回 0（向后兼容行为保留）
        assert_eq!(current_tenant_id(), 0);

        // 有 scope 时返回 tenant_id
        let ctx = TenantContext {
            tenant_id: 42,
            resolved_from: TenantSource::Header,
        };
        let result = TENANT.scope(ctx, async { current_tenant_id() }).await;
        assert_eq!(result, 42);
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

    /// R-tenant-isolation-002: ClaimTenantResolver 从 Authorization Bearer JWT 提取 tenant_id claim。
    ///
    /// 构造含 `Authorization: Bearer <jwt>` 的 headers（JWT payload 含 `tenant_id: 42`），
    /// 断言 `ClaimTenantResolver::new(secret).resolve(&headers)` 返回 `tenant_id == 42`。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn claim_tenant_resolver_extracts_from_jwt_claim() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        #[derive(serde::Serialize)]
        struct Claims {
            tenant_id: i64,
            exp: i64,
        }

        let secret = "test-secret-claim";
        let claims = Claims {
            tenant_id: 42,
            exp: 9999999999,
        };
        let header = Header::new(Algorithm::HS256);
        let key = EncodingKey::from_secret(secret.as_bytes());
        let jwt = encode(&header, &claims, &key).expect("encode jwt");

        let mut headers = http::HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {jwt}").parse().expect("valid header value"),
        );

        let resolver = ClaimTenantResolver::new(secret.to_string());
        let ctx = resolver
            .resolve(&headers)
            .await
            .expect("valid JWT 应解析成功");
        assert_eq!(ctx.tenant_id, 42);
        assert!(matches!(ctx.resolved_from, TenantSource::Claim));
    }

    /// R-tenant-isolation-002: ClaimTenantResolver 在 Authorization 缺失时返回 InvalidToken。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn claim_tenant_resolver_returns_invalid_token_when_auth_missing() {
        let headers = http::HeaderMap::new();
        let resolver = ClaimTenantResolver::new("secret".to_string());
        let result = resolver.resolve(&headers).await;
        assert!(matches!(result, Err(BulwarkError::InvalidToken(_))));
    }

    /// R-tenant-isolation-002: ClaimTenantResolver 在 JWT 签名验证失败时返回 InvalidToken。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn claim_tenant_resolver_returns_invalid_token_when_signature_bad() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        #[derive(serde::Serialize)]
        struct Claims {
            tenant_id: i64,
            exp: i64,
        }

        let signing_secret = "secret-a";
        let verifying_secret = "secret-b"; // 不匹配
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &Claims {
                tenant_id: 42,
                exp: 9999999999,
            },
            &EncodingKey::from_secret(signing_secret.as_bytes()),
        )
        .expect("encode jwt");

        let mut headers = http::HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {jwt}").parse().unwrap());
        let resolver = ClaimTenantResolver::new(verifying_secret.to_string());
        let result = resolver.resolve(&headers).await;
        assert!(matches!(result, Err(BulwarkError::InvalidToken(_))));
    }

    /// R-tenant-isolation-002: ClaimTenantResolver 在 tenant_id claim 缺失时返回 InvalidToken。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn claim_tenant_resolver_returns_invalid_token_when_claim_missing() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        #[derive(serde::Serialize)]
        struct Claims {
            exp: i64,
            // 故意没有 tenant_id
        }

        let secret = "test-secret-no-claim";
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &Claims { exp: 9999999999 },
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("encode jwt");

        let mut headers = http::HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {jwt}").parse().unwrap());
        let resolver = ClaimTenantResolver::new(secret.to_string());
        let result = resolver.resolve(&headers).await;
        assert!(matches!(result, Err(BulwarkError::InvalidToken(_))));
    }

    /// R-tenant-isolation-002: ClaimTenantResolver 接受小写 bearer scheme（RFC 7235 大小写不敏感）。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn claim_tenant_resolver_accepts_lowercase_bearer_scheme() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        #[derive(serde::Serialize)]
        struct Claims {
            tenant_id: i64,
            exp: i64,
        }

        let secret = "test-secret-lower";
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &Claims {
                tenant_id: 42,
                exp: 9999999999,
            },
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("encode jwt");

        let mut headers = http::HeaderMap::new();
        headers.insert("Authorization", format!("bearer {jwt}").parse().unwrap());
        let resolver = ClaimTenantResolver::new(secret.to_string());
        let ctx = resolver
            .resolve(&headers)
            .await
            .expect("小写 bearer scheme 应被接受");
        assert_eq!(ctx.tenant_id, 42);
    }
}
