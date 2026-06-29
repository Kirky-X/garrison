//! 路由模块，提供路由器与拦截器抽象。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的路由拦截器（`SaInterceptor`），
//! 适配各 Web 框架的路由层。

use crate::error::BulwarkResult;

/// 路由器，管理鉴权路由规则。
///
/// 负责将请求路径与注解规则关联，配合 Web 框架中间件使用。
pub struct BulwarkRouter {
    /// 路由规则占位。
    _rules: (),
}

impl BulwarkRouter {
    /// 创建新的路由器实例。
    pub fn new() -> Self {
        Self { _rules: () }
    }

    /// 添加鉴权规则。
    ///
    /// # 参数
    /// - `path`: 请求路径模式。
    /// - `annotation`: 鉴权注解。
    pub fn add_rule(
        &mut self,
        path: &str,
        annotation: crate::annotation::Annotation,
    ) -> BulwarkResult<()> {
        todo!()
    }

    /// 匹配请求路径对应的注解。
    ///
    /// # 参数
    /// - `path`: 请求路径。
    pub fn match_route(&self, path: &str) -> BulwarkResult<Option<crate::annotation::Annotation>> {
        todo!()
    }
}

impl Default for BulwarkRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// 拦截器 trait，定义请求拦截抽象。
///
/// [借鉴 Sa-Token] 对应 `SaInterceptor`，各 Web 框架适配需实现此 trait。
pub trait BulwarkInterceptor {
    /// 预处理请求，返回是否放行。
    ///
    /// # 参数
    /// - `path`: 请求路径。
    fn pre_handle(&self, path: &str) -> BulwarkResult<bool> {
        todo!()
    }

    /// 后处理请求。
    ///
    /// # 参数
    /// - `path`: 请求路径。
    fn post_handle(&self, path: &str) -> BulwarkResult<()> {
        todo!()
    }
}
