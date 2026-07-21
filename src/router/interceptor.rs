//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `DefaultGarrisonInterceptor` 实现：根据 annotation 变体调用对应 `GarrisonUtil` 方法。

use crate::annotation::Annotation;
use crate::error::{GarrisonError, GarrisonResult};
use crate::stp::GarrisonUtil;
use async_trait::async_trait;

use super::DefaultGarrisonInterceptor;
use super::GarrisonInterceptor;

#[async_trait]
impl GarrisonInterceptor for DefaultGarrisonInterceptor {
    async fn pre_handle(&self, _path: &str, annotation: &Annotation) -> GarrisonResult<()> {
        match annotation {
            Annotation::CheckLogin => {
                let logged_in = GarrisonUtil::check_login().await?;
                if !logged_in {
                    return Err(GarrisonError::NotLogin("router-not-login".to_string()));
                }
                Ok(())
            },
            Annotation::CheckRole(role) => GarrisonUtil::check_role(role).await,
            Annotation::CheckPermission(perm) => GarrisonUtil::check_permission(perm).await,
            // 二级认证检查
            Annotation::CheckSafe => GarrisonUtil::check_safe().await,
            // 账号禁用检查
            Annotation::CheckDisable => GarrisonUtil::check_disable().await,
            // HTTP Basic/Digest/Sign 需 HTTP 请求上下文（Authorization header / method / body），
            // pre_handle 签名仅有 path + annotation，无法获取请求头。
            // Fail Loud（Rule 12）：明确返回 NotImplemented，指示用户使用 axum extractor 或 secure 模块直接调用。
            Annotation::CheckBasicAuth => Err(GarrisonError::NotImplemented(
                "router-check-basic-auth-need-http-context".to_string(),
            )),
            Annotation::CheckDigestAuth => Err(GarrisonError::NotImplemented(
                "router-check-digest-auth-need-http-context".to_string(),
            )),
            Annotation::CheckSign => Err(GarrisonError::NotImplemented(
                "router-check-sign-need-http-context".to_string(),
            )),
            // API Key 校验
            // namespace 为 None 时使用默认命名空间 "default"
            Annotation::CheckApiKey { namespace } => {
                let ns = namespace.as_deref().unwrap_or("default");
                GarrisonUtil::check_api_key(ns).await
            },
            // OAuth2 access_token / client_token 校验
            // DefaultGarrisonInterceptor 不持有 OAuth2Handler 实例，返回 NotImplemented。
            // 业务方应在 handler 中使用 protocol::oauth2::OAuth2Client 或自定义拦截器。
            Annotation::CheckAccessToken => Err(GarrisonError::NotImplemented(
                "router-check-access-token-need-oauth2".to_string(),
            )),
            Annotation::CheckClientToken => Err(GarrisonError::NotImplemented(
                "router-check-client-token-need-oauth2".to_string(),
            )),
            Annotation::Ignore => Ok(()),
            // 逻辑组合注解（CheckOr/CheckAnd/CheckNot/Mode）在 pre_handle 中为 no-op，
            // 实际组合逻辑由注解处理器在编译期或路由配置层处理。
            // Mode（）：控制 @CheckPermission/@CheckRole 的多权限组合逻辑，
            // 是配置注解而非直接检查，pre_handle 中 no-op。
            Annotation::CheckOr
            | Annotation::CheckAnd
            | Annotation::CheckNot
            | Annotation::Mode(_) => Ok(()),
        }
    }
}
