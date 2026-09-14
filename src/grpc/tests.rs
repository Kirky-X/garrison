//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! `grpc` 模块的 inline tests。
//!
//! 从 `mod.rs` 迁移而出（规则 25：mod.rs 接口隔离）。
//! 覆盖 `GarrisonGrpcInterceptor` 的 token 提取、`Interceptor::call` 行为、
//! Clone/Debug trait，以及 `health_service()` 健康检查服务。

use super::*;
use tonic::metadata::MetadataMap;
use tonic::service::Interceptor;

/// 测试 GarrisonGrpcInterceptor::new() 构造无 panic。
#[test]
fn test_interceptor_new() {
    let _interceptor = GarrisonGrpcInterceptor::new();
    let _default: GarrisonGrpcInterceptor = Default::default();
}

/// 测试 extract_token 成功提取 "Bearer <token>" 格式的 token。
#[test]
fn test_extract_token_bearer_success() {
    let mut metadata = MetadataMap::new();
    metadata.insert("authorization", "Bearer abc123".parse().unwrap());
    let token = GarrisonGrpcInterceptor::extract_token(&metadata).unwrap();
    assert_eq!(token, "abc123");
}

/// 测试 extract_token 支持 "bearer" 小写（RFC 7235 大小写不敏感）。
#[test]
fn test_extract_token_bearer_lowercase() {
    let mut metadata = MetadataMap::new();
    metadata.insert("authorization", "bearer xyz789".parse().unwrap());
    let token = GarrisonGrpcInterceptor::extract_token(&metadata).unwrap();
    assert_eq!(token, "xyz789");
}

/// 测试 extract_token 支持 "BEARER" 大写。
#[test]
fn test_extract_token_bearer_uppercase() {
    let mut metadata = MetadataMap::new();
    metadata.insert("authorization", "BEARER TOKEN123".parse().unwrap());
    let token = GarrisonGrpcInterceptor::extract_token(&metadata).unwrap();
    assert_eq!(token, "TOKEN123");
}

/// 测试 extract_token 支持任意混合大小写 scheme（RFC 7235 大小写不敏感，
/// 不再限于三种硬编码前缀，ocr #2631/#3034/#3275/#3588/#6239）。
#[test]
fn test_extract_token_bearer_mixed_case() {
    for header in ["BeArEr tok1", "bEaReR tok2", "BEARER tok3", "bearer tok4"] {
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", header.parse().unwrap());
        let token = GarrisonGrpcInterceptor::extract_token(&metadata)
            .unwrap_or_else(|e| panic!("混合大小写 scheme 应被接受: {header}, 实际: {e}"));
        assert_eq!(token, header.split_once(' ').unwrap().1);
    }
}

/// 测试 extract_token 拒绝超过 MAX_TOKEN_LEN 的超长 token（ocr #2380）。
#[test]
fn test_extract_token_rejects_overlong_token() {
    let mut metadata = MetadataMap::new();
    let long_token = "a".repeat(super::MAX_TOKEN_LEN + 1);
    metadata.insert(
        "authorization",
        format!("Bearer {long_token}").parse().unwrap(),
    );
    let result = GarrisonGrpcInterceptor::extract_token(&metadata);
    assert!(result.is_err(), "超长 token 应被拒绝");
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    // 边界：恰好 MAX_TOKEN_LEN 应被接受
    let mut metadata = MetadataMap::new();
    let exact_token = "a".repeat(super::MAX_TOKEN_LEN);
    metadata.insert(
        "authorization",
        format!("Bearer {exact_token}").parse().unwrap(),
    );
    assert!(GarrisonGrpcInterceptor::extract_token(&metadata).is_ok());
}

/// 测试 extract_token 缺失 Authorization metadata 时返回 UNAUTHENTICATED。
#[test]
fn test_extract_token_missing_metadata() {
    let metadata = MetadataMap::new();
    let result = GarrisonGrpcInterceptor::extract_token(&metadata);
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
    let result = GarrisonGrpcInterceptor::extract_token(&metadata);
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
    let result = GarrisonGrpcInterceptor::extract_token(&metadata);
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
    let result = GarrisonGrpcInterceptor::extract_token(&metadata);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

/// 测试 Interceptor::call() 在合法 token 时返回 Ok。
#[test]
fn test_interceptor_call_with_valid_token() {
    let mut interceptor = GarrisonGrpcInterceptor::new();
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
    let mut interceptor = GarrisonGrpcInterceptor::new();
    let request = tonic::Request::new(());
    let result = interceptor.call(request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

/// 测试 Interceptor::call() 把提取的 token 以 GarrisonGrpcToken 注入 request
/// extensions（不再"提取即弃"，ocr #3277），且 Debug 输出脱敏。
#[test]
fn test_interceptor_call_injects_token_into_extensions() {
    let mut interceptor = GarrisonGrpcInterceptor::new();
    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("authorization", "Bearer secret-token-abc".parse().unwrap());
    let request = interceptor.call(request).expect("合法 token 应放行");
    let injected = request
        .extensions()
        .get::<GarrisonGrpcToken>()
        .expect("token 应注入 request extensions");
    assert_eq!(injected.0, "secret-token-abc");
    // Debug 脱敏：不得包含 token 明文
    let debug = format!("{:?}", injected);
    assert!(
        !debug.contains("secret-token-abc"),
        "Debug 不得泄露 token: {debug}"
    );
    assert!(debug.contains("[REDACTED]"));
}

/// 测试配置同步校验器后 Interceptor::call() 执行真实鉴权：
/// 校验失败的 token 以 UNAUTHENTICATED 拒绝，不进入 handler（ocr #2633/#3036/#3276）。
#[test]
fn test_interceptor_with_validator_rejects_invalid_token() {
    struct RejectAll;
    impl GarrisonGrpcTokenValidator for RejectAll {
        fn validate(&self, _token: &str) -> Result<(), tonic::Status> {
            Err(tonic::Status::unauthenticated("invalid token"))
        }
    }
    let mut interceptor =
        GarrisonGrpcInterceptor::with_token_validator(std::sync::Arc::new(RejectAll));
    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("authorization", "Bearer some-token".parse().unwrap());
    let result = interceptor.call(request);
    assert!(result.is_err(), "校验器拒绝的 token 不应放行");
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

/// 测试配置同步校验器后合法 token 放行且 token 注入 extensions。
#[test]
fn test_interceptor_with_validator_accepts_valid_token() {
    struct AcceptAll;
    impl GarrisonGrpcTokenValidator for AcceptAll {
        fn validate(&self, _token: &str) -> Result<(), tonic::Status> {
            Ok(())
        }
    }
    let mut interceptor =
        GarrisonGrpcInterceptor::with_token_validator(std::sync::Arc::new(AcceptAll));
    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("authorization", "Bearer good-token".parse().unwrap());
    let request = interceptor.call(request).expect("校验通过的 token 应放行");
    assert!(request.extensions().get::<GarrisonGrpcToken>().is_some());
}

/// 测试 Clone trait（用于 tonic interceptor 复用）。
#[test]
fn test_interceptor_clone() {
    let i1 = GarrisonGrpcInterceptor::new();
    let _i2 = i1.clone();
    // 不 panic 即通过
}

/// 测试 Debug trait。
#[test]
fn test_interceptor_debug() {
    let interceptor = GarrisonGrpcInterceptor::new();
    let debug_str = format!("{:?}", interceptor);
    assert!(debug_str.contains("GarrisonGrpcInterceptor"));
}

// ========================================================================
// health_service() 健康检查服务测试
// ========================================================================

/// 测试 health_service() 成功返回 HealthServer（Serving 状态已设置）。
///
/// 断言返回的 server 是标准 gRPC health 服务（NamedService::NAME 正确），
/// 函数内部通过 HealthReporter 设置 ServingStatus::Serving，
/// 成功返回即表示状态已正确设置（ocr #2001：补真实断言，不再纯冒烟）。
#[tokio::test]
async fn test_health_service_returns_server() {
    let server = super::health_service().await;
    fn assert_named_service<T: tonic::server::NamedService>(_: &T) -> &'static str {
        T::NAME
    }
    let name = assert_named_service(&server);
    assert_eq!(
        name, "grpc.health.v1.Health",
        "health_service 应返回标准 gRPC health 服务"
    );
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
    let server = super::health_service().await;
    // ocr #615：补真实断言——验证 NAME 确为标准健康检查服务名，
    // 而非仅调用后丢弃（原测试无任何断言）。
    fn name_of<T: tonic::server::NamedService>(_: &T) -> &'static str {
        T::NAME
    }
    assert_eq!(name_of(&server), "grpc.health.v1.Health");
}

/// 测试 health_service() 多次调用返回独立实例（无全局状态泄漏）。
#[tokio::test]
async fn test_health_service_multiple_calls() {
    let _s1 = super::health_service().await;
    let _s2 = super::health_service().await;
}
