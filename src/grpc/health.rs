// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! gRPC 标准健康检查服务：`health_service()` 返回 `HealthServer<impl Health>`，供 kubelet / 服务网格探针调用。

/// 创建 gRPC 标准健康检查服务，返回 `HealthServer<impl Health>`。
///
/// 实现 `tonic::server::NamedService`（`NAME = "grpc.health.v1.Health"`，[health/v1]），可经
/// `Server::add_service()` 注册；默认服务状态设为 `ServingStatus::Serving`，动态更新状态请直接用
/// `tonic_health::server::health_reporter()` 获取 `HealthReporter`。
///
/// # 示例
///
/// ```ignore
/// use garrison::grpc::health_service;
/// use tonic::transport::Server;
///
/// let health = health_service().await;
/// Server::builder()
/// .add_service(health)
/// .serve(addr)
/// .await?;
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
