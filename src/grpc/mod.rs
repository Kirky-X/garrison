//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! gRPC 鉴权拦截器 + 健康检查服务模块。
//!
//! ## 设计
//!
//! - `GarrisonGrpcInterceptor`：实现 `tonic::Interceptor` trait
//!   - 从 gRPC 请求 metadata 提取 `authorization: Bearer <token>` header
//!   - 调用 `GarrisonUtil::check_login()` 鉴权
//!   - 鉴权失败返回 `tonic::Status::UNAUTHENTICATED`（code = 16）
//! - `health_service`：返回 `tonic_health::server::HealthServer<impl Health>`
//!   - gRPC 标准健康检查协议（grpc.health.v1.Health）
//!   - 默认设置 ServingStatus::Serving，供 kubelet / 服务网格探针调用
//!
//! ## 使用示例
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
//!     .add_service(health)
//!     .serve(health_addr)
//!     .await?;
//!
//! Server::builder()
//!     .interceptor(GarrisonGrpcInterceptor::new())
//!     .add_service(my_service)
//!     .serve(app_addr)
//!     .await?;
//! ```
//!
//! ## Feature 门控
//!
//! 启用 `grpc` feature 时编译。未启用时模块不存在，不引入 tonic 依赖。

/// gRPC async 鉴权层模块（`GarrisonGrpcAuthLayer`，tower Layer/Service）。
pub mod auth_layer;
/// gRPC 标准健康检查服务模块（`health_service()`）。
pub mod health;
/// gRPC 鉴权拦截器实现模块（`GarrisonGrpcInterceptor` impl 块）。
pub mod interceptor;

pub use auth_layer::{GarrisonGrpcAuthLayer, GarrisonGrpcAuthService};
pub use health::health_service;
pub use interceptor::MAX_TOKEN_LEN;

/// garrison grpc token（认证上下文注入载体）。
///
/// 拦截器 / 鉴权层把校验通过的 Bearer token 以 `GarrisonGrpcToken` 存入
/// request extensions，handler 侧可经
/// `request.extensions().get::<GarrisonGrpcToken>()` 读取（ocr #3277）。
/// `Debug` 手动实现为脱敏输出，防止误打印泄露 token。
#[derive(Clone, PartialEq, Eq)]
pub struct GarrisonGrpcToken(pub String);

impl std::fmt::Debug for GarrisonGrpcToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("GarrisonGrpcToken")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// gRPC 拦截器**同步** token 校验扩展点（ocr #2633/#3036/#3276）。
///
/// `tonic::Interceptor::call` 是同步 trait，无法直接调用异步的
/// `GarrisonUtil::check_login()`。为让 [`GarrisonGrpcInterceptor`] 具备真实鉴权
/// 能力，可通过 [`GarrisonGrpcInterceptor::with_token_validator`] 注入本 trait 的
/// 同步实现（如查询本地缓存会话表）；失败返回任意 `tonic::Status` 即拒绝请求。
///
/// 需要 async 全量鉴权（登录态/过期/封禁校验 + task_local 注入）时，
/// 请使用 [`GarrisonGrpcAuthLayer`]（tower Layer 形态）。
pub trait GarrisonGrpcTokenValidator: Send + Sync + 'static {
    /// 校验 token；`Err(_)` 时请求以该 `Status` 拒绝（不进入 handler）。
    fn validate(&self, token: &str) -> Result<(), tonic::Status>;
}

/// Garrison gRPC 鉴权拦截器。
///
/// 实现 `tonic::Interceptor` trait，从 gRPC 请求 metadata 提取 Authorization Bearer token：
/// - scheme 按 RFC 7235 大小写不敏感匹配（`Bearer` / `bearer` / `bEaReR` 等均可）
/// - token 非空且长度 ≤ 4KB（超长拒绝，防无界分配）
/// - 通过校验的 token 以 [`GarrisonGrpcToken`] 注入 request extensions
///
/// # 鉴权语义
///
/// `tonic::Interceptor::call` 是**同步** trait，无法直接调用异步的
/// `GarrisonUtil::check_login()`：
/// - **未配置校验器**（`new()` / 默认）：仅做上述格式校验，**不**执行登录态校验，
///   实际鉴权须在 handler 内通过 `task_local`（`with_current_token`）显式调用。
/// - **配置了同步校验器**（`with_token_validator`）：在拦截器内执行真实鉴权，
///   失败直接以 `Status::UNAUTHENTICATED` 拒绝。
///
/// # 完整 async 鉴权请使用 [`GarrisonGrpcAuthLayer`]
///
/// 本框架提供的 tower `Layer` 形态支持 async 鉴权：未登录/伪造 token 直接以
/// `Status::UNAUTHENTICATED` 拒绝，放行时把 token 注入 task_local 供 handler 使用：
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
///     .interceptor(GarrisonGrpcInterceptor::new())
///     .add_service(my_service)
///     .serve(addr)
///     .await?;
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
