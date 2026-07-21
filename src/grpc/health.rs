//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! gRPC 标准健康检查服务。
//!
//! 从 `mod.rs` 迁移而出（规则 25：mod.rs 接口隔离）。
//! 提供 `health_service()` 返回 `HealthServer<impl Health>`，
//! 供 kubelet / 服务网格探针调用。

/// 创建 gRPC 标准健康检查服务，返回 `HealthServer<impl Health>`。
///
/// 内部通过 `tonic_health::server::health_reporter()` 创建 `(HealthReporter, HealthServer)`，
/// 将默认服务（空字符串 `""`）状态设置为 `ServingStatus::Serving`，然后返回 `HealthServer`。
///
/// 返回的 `HealthServer` 实现 `tonic::server::NamedService`（`NAME = "grpc.health.v1.Health"`），
/// 可直接通过 `Server::add_service()` 注册到 tonic transport server。
///
/// # 服务名
///
/// `grpc.health.v1.Health` — gRPC 标准健康检查协议（[health/v1]）。
///
/// # 状态
///
/// 默认设置为 `ServingStatus::Serving`，表示服务已就绪。
/// 如需动态更新状态，请直接使用 `tonic_health::server::health_reporter()` 获取 `HealthReporter`。
///
/// # 示例
///
/// ```ignore
/// use garrison::grpc::health_service;
/// use tonic::transport::Server;
///
/// let health = health_service().await;
/// Server::builder()
///     .add_service(health)
///     .serve(addr)
///     .await?;
/// ```
///
/// [health/v1]: https://github.com/grpc/grpc/blob/master/doc/health-checking.md
pub async fn health_service(
) -> tonic_health::pb::health_server::HealthServer<impl tonic_health::pb::health_server::Health> {
    let (reporter, server) = tonic_health::server::health_reporter();
    reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;
    server
}
