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
}
