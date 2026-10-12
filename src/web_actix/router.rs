// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! actix-web 路由规则构建器：`GarrisonRouter` 的构造/配置/规则注册/生成 middleware 与 `Default` 实现；
//! struct 声明位于 `mod.rs`。

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

    /// 设置内层 handler 超时（默认 `None` 不设超时）：鉴权通过后内层调用以该时限包裹，
    /// 超时返回 504，防挂起 handler 无限占用连接。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use std::time::Duration;
    /// let router = GarrisonRouter::new(config)
    /// .with_handler_timeout(Duration::from_secs(30));
    /// ```
    pub fn with_handler_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.handler_timeout = Some(timeout);
        self
    }

    /// 设置租户解析器：middleware 每请求先 `resolver.resolve()` 解析租户并进入 `TENANT.scope` 再鉴权，
    /// 解析失败拒绝（fail-closed）；未配置时不提取租户。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use garrison::web_actix::GarrisonRouter;
    /// use garrison::context::tenant::HeaderTenantResolver;
    ///
    /// let router = GarrisonRouter::new(config)
    /// .with_tenant_resolver(HeaderTenantResolver)
    /// .route_protected("/api/data", Annotation::CheckPermission("data:read".into()));
    /// ```
    pub fn with_tenant_resolver<T: TenantResolver + 'static>(mut self, resolver: T) -> Self {
        self.tenant_resolver = Some(Arc::new(resolver));
        self
    }

    /// 便捷方法：等价于 `with_tenant_resolver(HeaderTenantResolver)`（从 `X-Tenant-Id` 请求头解析租户）。
    pub fn with_header_tenant(mut self) -> Self {
        self.tenant_resolver = Some(Arc::new(HeaderTenantResolver));
        self
    }

    /// 添加受保护路由：注册路径 + 注解映射（actix 路由本身仍需在 `App::route()` 配置，此处仅记录规则）。
    ///
    /// 路径必须非空且以 `/` 开头，非法路径拒绝注册并记 error（否则 middleware 永不命中，路由静默不受保护）；
    /// 支持 `{id}`/`:id` 参数段与 `*`/`{*rest}` 尾部通配。重复注册保留 last-wins 语义并记 warn（不静默覆盖）。
    pub fn route_protected(mut self, path: &str, annotation: Annotation) -> Self {
        // 路径校验：非空 + 前导斜杠（fail-fast，避免畸形路径静默不受保护）
        if path.is_empty() || !path.starts_with('/') {
            tracing::error!(
                path = %path,
                "{}",
                crate::i18n::translate_detail("logs-router-invalid-path-protected", &[])
            );
            return self;
        }
        // 重复注册告警（保留 last-wins 覆盖语义）
        if self.rules.contains_key(path) {
            tracing::warn!(
                path = %path,
                "{}",
                crate::i18n::translate_detail("logs-router-duplicate-path-override", &[])
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
