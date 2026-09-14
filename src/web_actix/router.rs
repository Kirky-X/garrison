//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
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
            handler_timeout: None,
        }
    }

    /// 设置自定义拦截器。
    pub fn with_interceptor<I: GarrisonInterceptor + 'static>(mut self, interceptor: I) -> Self {
        self.interceptor = Arc::new(interceptor);
        self
    }

    /// 设置内层 handler 超时（可选，默认不设超时，ocr #2141）。
    ///
    /// 鉴权通过后，内层 service 调用将以该时限包裹：超时返回 504 Gateway Timeout
    /// 响应，防止挂起的 handler 无限占用连接与 middleware 资源。默认 `None`
    /// 保持历史行为（不设超时），需显式开启。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use std::time::Duration;
    /// let router = GarrisonRouter::new(config)
    ///     .with_handler_timeout(Duration::from_secs(30));
    /// ```
    pub fn with_handler_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.handler_timeout = Some(timeout);
        self
    }

    /// 设置租户解析器（多租户场景）。
    ///
    /// 配置后 middleware 在每个请求前调用 `resolver.resolve(&headers)` 解析租户上下文，
    /// 进入 `TENANT.scope` 后执行鉴权；解析失败时拒绝请求（fail-closed）。
    /// 未配置时不提取租户。
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
    ///
    /// # 路径校验（ocr #3509/2796）
    ///
    /// - 路径必须非空且以 `/` 开头：非法路径被**拒绝注册**并记录 error 日志
    ///   （此类路径在 middleware 匹配中永不命中，静默注册将导致路由不受保护）。
    /// - 支持参数化模式：`{id}` / `:id` 单段参数、`*` / `{*rest}` 尾部通配
    ///   （middleware 按 axum 风格段匹配，参数化路径不再静默跳过鉴权）。
    ///
    /// # 重复注册（ocr #2144/2795/3508）
    ///
    /// 重复注册同一路径时保留 last-wins 语义（与旧行为一致），但会记录 warn 日志，
    /// 不再静默覆盖（防止误注册的弱注解悄然替换强注解而无任何信号）。
    pub fn route_protected(mut self, path: &str, annotation: Annotation) -> Self {
        // 路径校验：非空 + 前导斜杠（fail-fast，避免畸形路径静默不受保护）
        if path.is_empty() || !path.starts_with('/') {
            tracing::error!(
                path = %path,
                "GarrisonRouter::route_protected 拒绝非法路径（必须非空且以 '/' 开头），该路由不会受鉴权保护"
            );
            return self;
        }
        // 重复注册告警（保留 last-wins 覆盖语义）
        if self.rules.contains_key(path) {
            tracing::warn!(
                path = %path,
                "GarrisonRouter::route_protected 重复注册同一路径，原注解将被覆盖（last-wins）"
            );
        }
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
            handler_timeout: self.handler_timeout,
        }
    }
}

impl Default for GarrisonRouter {
    fn default() -> Self {
        Self::new(Arc::new(GarrisonConfig::default_config()))
    }
}
