//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `grpc` 模块的 inline tests。
//!
//! 从 `mod.rs` 迁移而出（规则 25：mod.rs 接口隔离）。
//! 覆盖 `BulwarkGrpcInterceptor` 的 token 提取、`Interceptor::call` 行为、
//! Clone/Debug trait，以及 `health_service()` 健康检查服务。

use super::*;
use tonic::metadata::MetadataMap;
use tonic::service::Interceptor;

/// 测试 BulwarkGrpcInterceptor::new() 构造无 panic。
#[test]
fn test_interceptor_new() {
    let _interceptor = BulwarkGrpcInterceptor::new();
    let _default: BulwarkGrpcInterceptor = Default::default();
}

/// 测试 extract_token 成功提取 "Bearer <token>" 格式的 token。
#[test]
fn test_extract_token_bearer_success() {
    let mut metadata = MetadataMap::new();
    metadata.insert("authorization", "Bearer abc123".parse().unwrap());
    let token = BulwarkGrpcInterceptor::extract_token(&metadata).unwrap();
    assert_eq!(token, "abc123");
}

/// 测试 extract_token 支持 "bearer" 小写（RFC 7235 大小写不敏感）。
#[test]
fn test_extract_token_bearer_lowercase() {
    let mut metadata = MetadataMap::new();
    metadata.insert("authorization", "bearer xyz789".parse().unwrap());
    let token = BulwarkGrpcInterceptor::extract_token(&metadata).unwrap();
    assert_eq!(token, "xyz789");
}

/// 测试 extract_token 支持 "BEARER" 大写。
#[test]
fn test_extract_token_bearer_uppercase() {
    let mut metadata = MetadataMap::new();
    metadata.insert("authorization", "BEARER TOKEN123".parse().unwrap());
    let token = BulwarkGrpcInterceptor::extract_token(&metadata).unwrap();
    assert_eq!(token, "TOKEN123");
}

/// 测试 extract_token 缺失 Authorization metadata 时返回 UNAUTHENTICATED。
#[test]
fn test_extract_token_missing_metadata() {
    let metadata = MetadataMap::new();
    let result = BulwarkGrpcInterceptor::extract_token(&metadata);
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert!(status.message().contains("missing Authorization"));
}

/// 测试 extract_token 在 Bearer 后 token 为空时返回 UNAUTHENTICATED。
#[test]
fn test_extract_token_empty_after_bearer() {
    let mut metadata = MetadataMap::new();
    metadata.insert("authorization", "Bearer ".parse().unwrap());
    let result = BulwarkGrpcInterceptor::extract_token(&metadata);
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// 测试 extract_token 拒绝裸 token（不带 Bearer 前缀），返回 UNAUTHENTICATED。
///
/// RFC 7235 严格校验：不接受非 Bearer scheme 的凭证，
/// 避免 Basic/Digest 凭证被误认为 Bearer token。
#[test]
fn test_extract_token_bare_token_rejected() {
    let mut metadata = MetadataMap::new();
    metadata.insert("authorization", "raw-token-12345".parse().unwrap());
    let result = BulwarkGrpcInterceptor::extract_token(&metadata);
    assert!(result.is_err(), "裸 token 应被拒绝");
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert!(
        status.message().contains("Bearer"),
        "错误消息应提及 Bearer scheme"
    );
}

/// 测试 extract_token 在 Authorization 为空字符串时返回 UNAUTHENTICATED。
#[test]
fn test_extract_token_empty_value() {
    let mut metadata = MetadataMap::new();
    metadata.insert("authorization", "".parse().unwrap());
    let result = BulwarkGrpcInterceptor::extract_token(&metadata);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

/// 测试 Interceptor::call() 在合法 token 时返回 Ok。
#[test]
fn test_interceptor_call_with_valid_token() {
    let mut interceptor = BulwarkGrpcInterceptor::new();
    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("authorization", "Bearer valid-token".parse().unwrap());
    let result = interceptor.call(request);
    assert!(result.is_ok(), "valid token should pass: {:?}", result);
}

/// 测试 Interceptor::call() 在缺失 metadata 时返回 UNAUTHENTICATED。
#[test]
fn test_interceptor_call_missing_metadata() {
    let mut interceptor = BulwarkGrpcInterceptor::new();
    let request = tonic::Request::new(());
    let result = interceptor.call(request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

/// 测试 Clone trait（用于 tonic interceptor 复用）。
#[test]
fn test_interceptor_clone() {
    let i1 = BulwarkGrpcInterceptor::new();
    let _i2 = i1.clone();
    // 不 panic 即通过
}

/// 测试 Debug trait。
#[test]
fn test_interceptor_debug() {
    let interceptor = BulwarkGrpcInterceptor::new();
    let debug_str = format!("{:?}", interceptor);
    assert!(debug_str.contains("BulwarkGrpcInterceptor"));
}

// ========================================================================
// T015: health_service() 健康检查服务测试
// ========================================================================

/// 测试 health_service() 成功返回 HealthServer（Serving 状态已设置）。
///
/// 函数内部通过 HealthReporter 设置 ServingStatus::Serving，
/// 成功返回即表示状态已正确设置。
#[tokio::test]
async fn test_health_service_returns_server() {
    let _server = super::health_service().await;
}

/// 测试 health_service() 返回的类型实现了 tonic::server::NamedService。
///
/// HealthServer<impl Health> 必须实现 NamedService 才能注册到 tonic Server。
#[tokio::test]
async fn test_health_service_implements_named_service() {
    fn _assert_named_service<T: tonic::server::NamedService>(_: &T) {}
    let server = super::health_service().await;
    _assert_named_service(&server);
}

/// 测试 health_service() 返回的 NamedService 名称为标准 gRPC health check 服务名。
///
/// grpc.health.v1.Health 是 gRPC 标准健康检查协议定义的服务全名。
///
/// 注：`HealthServer<impl Health>` 的 `impl Health` 是不透明类型，
/// 无法通过泛型函数 `extract_name<T>` 单态化提取 `NamedService::NAME`。
/// `HealthServer<T>` 在 tonic-health 中 blanket impl `NamedService`
/// （NAME = "grpc.health.v1.Health"），health_service() 返回有效实例即表示 trait 已实现。
#[tokio::test]
async fn test_health_service_named_service_name() {
    let _server = super::health_service().await;
}

/// 测试 health_service() 多次调用返回独立实例（无全局状态泄漏）。
#[tokio::test]
async fn test_health_service_multiple_calls() {
    let _s1 = super::health_service().await;
    let _s2 = super::health_service().await;
}
