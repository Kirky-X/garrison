//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! gRPC 鉴权拦截器 + 健康检查服务模块。
//!
//! ## 设计
//!
//! - `BulwarkGrpcInterceptor`：实现 `tonic::Interceptor` trait
//!   - 从 gRPC 请求 metadata 提取 `authorization: Bearer <token>` header
//!   - 调用 `BulwarkUtil::check_login()` 鉴权
//!   - 鉴权失败返回 `tonic::Status::UNAUTHENTICATED`（code = 16）
//! - `health_service`：返回 `tonic_health::server::HealthServer<impl Health>`
//!   - gRPC 标准健康检查协议（grpc.health.v1.Health）
//!   - 默认设置 ServingStatus::Serving，供 kubelet / 服务网格探针调用
//!
//! ## 使用示例
//!
//! ```ignore
//! use bulwark::grpc::{BulwarkGrpcInterceptor, health_service};
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
//!     .interceptor(BulwarkGrpcInterceptor::new())
//!     .add_service(my_service)
//!     .serve(app_addr)
//!     .await?;
//! ```
//!
//! ## Feature 门控
//!
//! 启用 `grpc` feature 时编译。未启用时模块不存在，不引入 tonic 依赖。

/// gRPC 标准健康检查服务模块（`health_service()`）。
pub mod health;
/// gRPC 鉴权拦截器实现模块（`BulwarkGrpcInterceptor` impl 块）。
pub mod interceptor;

pub use health::health_service;

/// Bulwark gRPC 鉴权拦截器。
///
/// 实现 `tonic::Interceptor` trait，从 gRPC 请求 metadata 提取 Authorization Bearer token
/// 并调用 `BulwarkUtil::check_login()` 鉴权。鉴权失败时返回 `Status::UNAUTHENTICATED`。
///
/// # 重要限制：仅提取 token，不执行 async 鉴权
///
/// `tonic::Interceptor::call` 是**同步** trait，无法直接调用异步的 `BulwarkUtil::check_login()`。
/// 本拦截器仅完成 token 提取与基本格式校验（非空、`Bearer ` 前缀正确），
/// **不**执行实际的登录态/权限校验。
///
/// 完整的 async 鉴权推荐方案：
/// - 使用 `tonic` 的 `tower::Layer` middleware（async），在 layer 中调用 `BulwarkContext`
///   执行 `check_login` 等异步 API；
/// - 或在 tonic service handler 内通过 `task_local`（`with_current_token`）读取 token，
///   显式调用 `BulwarkUtil::check_login()`。
///
/// # 使用
///
/// ```ignore
/// use bulwark::grpc::BulwarkGrpcInterceptor;
/// use tonic::transport::Server;
///
/// Server::builder()
///     .interceptor(BulwarkGrpcInterceptor::new())
///     .add_service(my_service)
///     .serve(addr)
///     .await?;
/// ```
#[derive(Debug, Default, Clone)]
pub struct BulwarkGrpcInterceptor;

#[cfg(test)]
mod tests;
