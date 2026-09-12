//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `GarrisonRouter` 实现：warp 路由规则构建器。
//!
//! 承接 `mod.rs` 的 `GarrisonRouter` 结构体定义：
//! - `new` / `with_interceptor` / `route_protected`：构建器 API
//! - `into_filter`：消费路由器生成 warp 守卫 Filter，按路径匹配执行 interceptor 鉴权
//! - `Default`：使用 `DefaultGarrisonInterceptor` + 默认配置

use crate::annotation::Annotation;
use crate::config::GarrisonConfig;
use crate::context::token_extract::extract_token_from_headers;
use crate::error::GarrisonResult;
use crate::router::{DefaultGarrisonInterceptor, GarrisonInterceptor};
use crate::stp::with_current_token;
use std::collections::HashMap;
use std::sync::Arc;
use warp::http::HeaderMap;
use warp::Filter;

/// 尾斜杠归一化（根路径 `/` 除外）：`/api/users/` 与 `/api/users` 等价匹配。
fn normalize_route_path(path: &str) -> &str {
    if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    }
}

/// 路由规则匹配：支持精确匹配、单段参数与尾部通配（ocr #2136/3513/6490）。
///
/// - 精确段：逐段相等比较（尾斜杠归一化后，`/api/users/` 命中 `/api/users`）
/// - `{param}` / `:param`：匹配任意非空单段（与 axum/actix 参数语义对齐）
/// - `*` / `{*rest}`：匹配剩余所有段（零段或多段，前缀保护语义，如 `/api/*`）
///
/// 返回 true 表示 `pattern` 覆盖请求 `path`。
fn route_matches_rule(pattern: &str, path: &str) -> bool {
    let pattern = normalize_route_path(pattern);
    let path = normalize_route_path(path);
    let mut p = pattern.split('/');
    let mut s = path.split('/');
    loop {
        match (p.next(), s.next()) {
            (None, None) => return true,
            (Some(seg), None) => return is_wildcard_segment(seg),
            (Some(seg), Some(part)) => {
                if is_wildcard_segment(seg) {
                    // 尾部通配：吞掉剩余所有段（含零段）
                    return true;
                }
                if is_param_segment(seg) {
                    // 单段参数：匹配任意非空段
                    if part.is_empty() {
                        return false;
                    }
                } else if seg != part {
                    return false;
                }
            },
            (None, Some(_)) => return false,
        }
    }
}

/// `{xxx}` / `:xxx` 形式的单段参数。
fn is_param_segment(seg: &str) -> bool {
    seg.starts_with(':') || (seg.starts_with('{') && seg.ends_with('}') && seg.len() > 2)
}

/// `*` / `{*xxx}` 形式的尾部通配段。
fn is_wildcard_segment(seg: &str) -> bool {
    seg == "*" || (seg.len() > 3 && seg.starts_with("{*") && seg.ends_with('}'))
}

impl super::GarrisonRouter {
    /// 创建新的路由器实例，使用 `DefaultGarrisonInterceptor`。
    pub fn new(config: Arc<GarrisonConfig>) -> Self {
        Self {
            rules: HashMap::new(),
            interceptor: Arc::new(DefaultGarrisonInterceptor),
            config,
        }
    }

    /// 设置自定义拦截器。
    pub fn with_interceptor<I: GarrisonInterceptor + 'static>(mut self, interceptor: I) -> Self {
        self.interceptor = Arc::new(interceptor);
        self
    }

    /// 添加受保护路由：注册路径 + 注解映射。
    ///
    /// 注意：warp 的路由注册需在 `warp::path()` 链中单独配置，
    /// 此方法仅记录鉴权规则，由 `into_filter()` 生成的守卫 Filter 执行鉴权。
    ///
    /// # 路径校验（ocr #2136/3513）
    ///
    /// - 路径必须非空且以 `/` 开头：非法路径被**拒绝注册**并记录 error 日志
    ///   （此类路径永不匹配请求，静默注册将导致路由不受保护）。
    /// - 支持参数化模式：`{id}` / `:id` 单段参数、`*` / `{*rest}` 尾部通配
    ///   （`into_filter` 按段匹配，注册 `/api/*` 即保护全部子路径）。
    ///
    /// # 重复注册
    ///
    /// 重复注册同一路径时保留 last-wins 语义，但记录 warn 日志（不静默覆盖）。
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

    /// 消费路由器，生成 warp 守卫 Filter。
    ///
    /// 该 Filter 检查请求路径是否命中已注册规则（精确 / 参数段 / 尾部通配，
    /// 尾斜杠归一化），命中则执行 interceptor 鉴权。
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
                    // ocr #2136/3513/6490: 规则匹配支持参数段与尾部通配，
                    // 参数化/子路径不再因精确匹配失败而静默跳过鉴权
                    let annotation = rules
                        .iter()
                        .find(|(pattern, _)| route_matches_rule(pattern, &path_str))
                        .map(|(_, annotation)| annotation.clone());

                    if let Some(annotation) = annotation {
                        // Token 可选：与 actix-web middleware 对齐，
                        // Ignore 注解的 pre_handle 直接返回 Ok(())，不需要 token。
                        let token = extract_token_from_headers(&headers, &config)
                            .map_err(|e| warp::reject::custom(super::GarrisonRejection(e)))?;

                        let auth_check =
                            async { interceptor.pre_handle(&path_str, &annotation).await };

                        let result: GarrisonResult<()> = match token {
                            Some(t) => with_current_token(t, auth_check).await,
                            None => auth_check.await,
                        };

                        result.map_err(|e| warp::reject::custom(super::GarrisonRejection(e)))?;
                    }
                    Ok::<(), warp::Rejection>(())
                }
            })
    }
}

impl Default for super::GarrisonRouter {
    fn default() -> Self {
        Self::new(Arc::new(GarrisonConfig::default_config()))
    }
}

#[cfg(test)]
mod route_match_tests {
    use super::*;

    #[test]
    fn route_matches_rule_exact_and_trailing_slash() {
        assert!(route_matches_rule("/api/users", "/api/users"));
        assert!(route_matches_rule("/api/users", "/api/users/"));
        assert!(route_matches_rule("/api/users/", "/api/users"));
        assert!(!route_matches_rule("/api/users", "/api/other"));
    }

    #[test]
    fn route_matches_rule_param_and_wildcard() {
        assert!(route_matches_rule("/api/users/{id}", "/api/users/42"));
        assert!(route_matches_rule("/api/users/:id", "/api/users/42"));
        assert!(!route_matches_rule("/api/users/{id}", "/api/users/"));
        assert!(route_matches_rule("/api/*", "/api"));
        assert!(route_matches_rule("/api/*", "/api/users/42"));
        assert!(route_matches_rule("/api/users/{*rest}", "/api/users/a/b"));
        assert!(!route_matches_rule("/api/users/{*rest}", "/api/others/x"));
    }

    #[test]
    fn route_matches_rule_mixed_segments() {
        assert!(route_matches_rule(
            "/api/{version}/users/:id",
            "/api/v1/users/42"
        ));
        assert!(!route_matches_rule(
            "/api/{version}/users/:id",
            "/api/v1/items/42"
        ));
    }
}
