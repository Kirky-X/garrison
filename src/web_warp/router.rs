//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `BulwarkRouter` 实现：warp 路由规则构建器。
//!
//! 承接 `mod.rs` 的 `BulwarkRouter` 结构体定义：
//! - `new` / `with_interceptor` / `route_protected`：构建器 API
//! - `into_filter`：消费路由器生成 warp 守卫 Filter，按路径匹配执行 interceptor 鉴权
//! - `Default`：使用 `DefaultBulwarkInterceptor` + 默认配置

use crate::annotation::Annotation;
use crate::config::BulwarkConfig;
use crate::context::token_extract::extract_token_from_headers;
use crate::error::BulwarkResult;
use crate::router::{BulwarkInterceptor, DefaultBulwarkInterceptor};
use crate::stp::with_current_token;
use std::collections::HashMap;
use std::sync::Arc;
use warp::http::HeaderMap;
use warp::Filter;

impl super::BulwarkRouter {
    /// 创建新的路由器实例，使用 `DefaultBulwarkInterceptor`。
    pub fn new(config: Arc<BulwarkConfig>) -> Self {
        Self {
            rules: HashMap::new(),
            interceptor: Arc::new(DefaultBulwarkInterceptor),
            config,
        }
    }

    /// 设置自定义拦截器。
    pub fn with_interceptor<I: BulwarkInterceptor + 'static>(mut self, interceptor: I) -> Self {
        self.interceptor = Arc::new(interceptor);
        self
    }

    /// 添加受保护路由：注册路径 + 注解映射。
    ///
    /// 注意：warp 的路由注册需在 `warp::path()` 链中单独配置，
    /// 此方法仅记录鉴权规则，由 `into_filter()` 生成的守卫 Filter 执行鉴权。
    pub fn route_protected(mut self, path: &str, annotation: Annotation) -> Self {
        self.rules.insert(path.to_string(), annotation);
        self
    }

    /// 消费路由器，生成 warp 守卫 Filter。
    ///
    /// 该 Filter 检查请求路径是否匹配已注册规则，若匹配则执行 interceptor 鉴权。
    /// 鉴权通过返回 `Ok(())`，失败返回 `Rejection`。
    pub fn into_filter(self) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
        let rules = Arc::new(self.rules);
        let interceptor = self.interceptor;
        let config = self.config;

        warp::any()
            .and(warp::path::full())
            .and(warp::header::headers_cloned())
            .and_then(move |path: warp::path::FullPath, headers: HeaderMap| {
                let rules = rules.clone();
                let interceptor = interceptor.clone();
                let config = config.clone();
                async move {
                    let path_str = path.as_str().to_string();
                    let annotation = rules.get(&path_str).cloned();

                    if let Some(annotation) = annotation {
                        // Token 可选：与 actix-web middleware 对齐，
                        // Ignore 注解的 pre_handle 直接返回 Ok(())，不需要 token。
                        let token = extract_token_from_headers(&headers, &config)
                            .map_err(|e| warp::reject::custom(super::BulwarkRejection(e)))?;

                        let auth_check =
                            async { interceptor.pre_handle(&path_str, &annotation).await };

                        let result: BulwarkResult<()> = match token {
                            Some(t) => with_current_token(t, auth_check).await,
                            None => auth_check.await,
                        };

                        result.map_err(|e| warp::reject::custom(super::BulwarkRejection(e)))?;
                    }
                    Ok::<(), warp::Rejection>(())
                }
            })
    }
}

impl Default for super::BulwarkRouter {
    fn default() -> Self {
        Self::new(Arc::new(BulwarkConfig::default_config()))
    }
}
