//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! actix-web 路由规则构建器实现。
//!
//! 提供 `GarrisonRouter` 的构造、配置、规则注册与 middleware 生成方法，
//! 以及 `Default` 实现。struct 声明位于 `mod.rs`。

use crate::annotation::Annotation;
use crate::config::GarrisonConfig;
use crate::context::tenant::{HeaderTenantResolver, TenantResolver};
use crate::router::{DefaultGarrisonInterceptor, GarrisonInterceptor};
use std::collections::HashMap;
use std::sync::Arc;

use super::{GarrisonMiddleware, GarrisonRouter};

impl GarrisonRouter {
    /// 创建新的路由器实例，使用 `DefaultGarrisonInterceptor`。
    pub fn new(config: Arc<GarrisonConfig>) -> Self {
        Self {
            rules: HashMap::new(),
            interceptor: Arc::new(DefaultGarrisonInterceptor),
            config,
            tenant_resolver: None,
        }
    }

    /// 设置自定义拦截器。
    pub fn with_interceptor<I: GarrisonInterceptor + 'static>(mut self, interceptor: I) -> Self {
        self.interceptor = Arc::new(interceptor);
        self
    }

    /// 设置租户解析器（多租户场景）。
    ///
    /// 配置后 middleware 在每个请求前调用 `resolver.resolve(&headers)` 解析租户上下文，
    /// 进入 `TENANT.scope` 后执行鉴权；解析失败时拒绝请求（fail-closed）。
    /// 未配置时行为与旧版一致（不提取租户）。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use garrison::web_actix::GarrisonRouter;
    /// use garrison::context::tenant::HeaderTenantResolver;
    ///
    /// let router = GarrisonRouter::new(config)
    ///     .with_tenant_resolver(HeaderTenantResolver)
    ///     .route_protected("/api/data", Annotation::CheckPermission("data:read".into()));
    /// ```
    pub fn with_tenant_resolver<T: TenantResolver + 'static>(mut self, resolver: T) -> Self {
        self.tenant_resolver = Some(Arc::new(resolver));
        self
    }

    /// 便捷方法：使用 `HeaderTenantResolver`（从 `X-Tenant-Id` 请求头解析租户）。
    ///
    /// 等价于 `with_tenant_resolver(HeaderTenantResolver)`。
    pub fn with_header_tenant(mut self) -> Self {
        self.tenant_resolver = Some(Arc::new(HeaderTenantResolver));
        self
    }

    /// 添加受保护路由：注册路径 + 注解映射。
    ///
    /// 注意：actix-web 的路由注册需在 `App::route()` 中单独配置，
    /// 此方法仅记录鉴权规则，由 `into_middleware()` 生成的 middleware 执行鉴权。
    pub fn route_protected(mut self, path: &str, annotation: Annotation) -> Self {
        self.rules.insert(path.to_string(), annotation);
        self
    }

    /// 消费路由器，生成 actix-web middleware。
    pub fn into_middleware(self) -> GarrisonMiddleware {
        GarrisonMiddleware {
            rules: Arc::new(self.rules),
            interceptor: self.interceptor,
            config: self.config,
            tenant_resolver: self.tenant_resolver,
        }
    }
}

impl Default for GarrisonRouter {
    fn default() -> Self {
        Self::new(Arc::new(GarrisonConfig::default_config()))
    }
}
