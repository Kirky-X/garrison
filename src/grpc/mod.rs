// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! gRPC 鉴权拦截器 + 健康检查服务模块。
//!
//! `GarrisonGrpcInterceptor` 从 metadata 提取 `authorization: Bearer <token>` 鉴权，失败返回
//! `tonic::Status::UNAUTHENTICATED`（code = 16）；`health_service` 提供 gRPC 标准健康检查
//! （grpc.health.v1.Health，默认 Serving），供 kubelet / 服务网格探针调用。
//!
//! ```ignore
//! use garrison::grpc::{GarrisonGrpcInterceptor, health_service};
//! use tonic::transport::Server;
//!
//! // 重要：interceptor 会拦截所有 service 请求（要求 Authorization Bearer token），
//! // 因此 health_service 必须注册到独立的 tonic Server（无 interceptor），
//! // 否则 kubelet / 服务网格探针因缺少 Authorization 头而被拒绝。
//! let health = health_service().await;
//! Server::builder()
//! .add_service(health)
//! .serve(health_addr)
//! .await?;
//!
//! Server::builder()
//! .interceptor(GarrisonGrpcInterceptor::new())
//! .add_service(my_service)
//! .serve(app_addr)
//! .await?;
//! ```
//!
//! 启用 `grpc` feature 时编译；未启用时模块不存在，不引入 tonic 依赖。

/// gRPC async 鉴权层（`tower::Layer` / `Service` 形态）。
pub mod auth_layer;
/// gRPC 标准健康检查服务。
pub mod health;
/// gRPC 鉴权拦截器实现。
pub mod interceptor;

pub use auth_layer::{GarrisonGrpcAuthLayer, GarrisonGrpcAuthService};
pub use health::health_service;
pub use interceptor::MAX_TOKEN_LEN;

/// 认证上下文注入载体：校验通过的 Bearer token 存入 request extensions，handler 经
/// `request.extensions().get::<GarrisonGrpcToken>()` 读取；`Debug` 手动实现为脱敏输出，防误打印泄露。
#[derive(Clone, PartialEq, Eq)]
pub struct GarrisonGrpcToken(pub String);

impl std::fmt::Debug for GarrisonGrpcToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("GarrisonGrpcToken")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// gRPC 拦截器**同步** token 校验扩展点。
///
/// `tonic::Interceptor::call` 是同步 trait，无法调用异步的 `GarrisonUtil::check_login()`；经
/// [`GarrisonGrpcInterceptor::with_token_validator`] 注入同步实现（如查询本地缓存会话表），
/// 失败返回任意 `tonic::Status` 即拒绝请求。需要 async 全量鉴权请用 [`GarrisonGrpcAuthLayer`]。
pub trait GarrisonGrpcTokenValidator: Send + Sync + 'static {
    /// 校验 token；`Err(_)` 时请求以该 `Status` 拒绝（不进入 handler）。
    fn validate(&self, token: &str) -> Result<(), tonic::Status>;
}

/// Garrison gRPC 鉴权拦截器。
///
/// 实现 `tonic::Interceptor`，从 metadata 提取 Authorization Bearer token：scheme 按 RFC 7235
/// 大小写不敏感（`Bearer` / `bearer` 等均可），token 非空且长度 ≤ 4KB（超长拒绝，防无界分配），
/// 通过校验的 token 以 [`GarrisonGrpcToken`] 注入 request extensions。
///
/// # 鉴权语义
///
/// 未配置校验器时仅格式校验（同步 trait 无法调用异步 `check_login()`），实际鉴权须在 handler 内经
/// `with_current_token` task_local 显式调用；配置 `with_token_validator` 时拦截器内真实鉴权、失败
/// `Status::UNAUTHENTICATED`；完整 async 鉴权用 [`GarrisonGrpcAuthLayer`]。
///
/// ```ignore
/// use garrison::grpc::GarrisonGrpcAuthLayer;
/// let svc = GarrisonGrpcAuthLayer.layer(my_greeter_service);
/// tonic::transport::Server::builder().add_service(svc).serve(addr).await?;
/// ```
///
/// # 使用
///
/// ```ignore
/// use garrison::grpc::GarrisonGrpcInterceptor;
/// use tonic::transport::Server;
///
/// Server::builder()
/// .interceptor(GarrisonGrpcInterceptor::new())
/// .add_service(my_service)
/// .serve(addr)
/// .await?;
/// ```
#[derive(Default, Clone)]
pub struct GarrisonGrpcInterceptor {
    /// 可选的同步 token 校验器（None 时仅格式校验）。
    validator: Option<std::sync::Arc<dyn GarrisonGrpcTokenValidator>>,
}

impl std::fmt::Debug for GarrisonGrpcInterceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GarrisonGrpcInterceptor")
            .field("validator", &self.validator.as_ref().map(|_| "configured"))
            .finish()
    }
}

#[cfg(test)]
mod tests;
