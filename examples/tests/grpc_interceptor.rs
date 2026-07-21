//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! grpc_interceptor 示例测试（grpc feature）。
//!
//! 验证 GarrisonGrpcInterceptor + with_current_token async 鉴权模式：
//! - `extract_token` 各种格式（Bearer/bearer/BEARER/裸 token/空）
//! - `Interceptor::call()` 同步拦截行为
//! - `authenticate_request()` 完整 async 鉴权（合法/非法 token）
//!
//! 使用 `#[serial_test::serial]` 串行化，因为 `setup()` 修改全局 `GarrisonManager` 单例。

#![cfg(feature = "grpc")]

use garrison_examples::web::grpc_interceptor;
use serial_test::serial;
use tonic::metadata::MetadataMap;
use tonic::service::Interceptor;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_interceptor_new_and_clone() {
    let i1 = garrison::grpc::GarrisonGrpcInterceptor::new();
    let _i2 = i1.clone();
    // 不 panic 即通过
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_extract_token_bearer_variants() {
    use garrison::grpc::GarrisonGrpcInterceptor;

    for prefix in &["Bearer", "bearer", "BEARER"] {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "authorization",
            format!("{} tok_{}", prefix, prefix).parse().unwrap(),
        );
        let token = GarrisonGrpcInterceptor::extract_token(&metadata).unwrap();
        assert_eq!(token, format!("tok_{}", prefix));
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_extract_token_missing_metadata() {
    use garrison::grpc::GarrisonGrpcInterceptor;

    let metadata = MetadataMap::new();
    let result = GarrisonGrpcInterceptor::extract_token(&metadata);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_extract_token_empty_value() {
    use garrison::grpc::GarrisonGrpcInterceptor;

    let mut metadata = MetadataMap::new();
    metadata.insert("authorization", "".parse().unwrap());
    let result = GarrisonGrpcInterceptor::extract_token(&metadata);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_extract_token_bare_token() {
    use garrison::grpc::GarrisonGrpcInterceptor;

    let mut metadata = MetadataMap::new();
    metadata.insert("authorization", "raw-token-xyz".parse().unwrap());
    let token = GarrisonGrpcInterceptor::extract_token(&metadata).unwrap();
    assert_eq!(token, "raw-token-xyz");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_interceptor_call_with_valid_token() {
    use garrison::grpc::GarrisonGrpcInterceptor;

    let (config, token) = grpc_interceptor::setup().await;
    let mut interceptor = GarrisonGrpcInterceptor::new();
    let mut request = tonic::Request::new(());
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );
    let result = interceptor.call(request);
    assert!(result.is_ok(), "合法 token 应通过拦截器");

    drop(config);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_interceptor_call_missing_metadata() {
    use garrison::grpc::GarrisonGrpcInterceptor;

    let mut interceptor = GarrisonGrpcInterceptor::new();
    let request = tonic::Request::new(());
    let result = interceptor.call(request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

/// 测试完整 async 鉴权：合法 token → Ok。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_authenticate_request_with_valid_token() {
    let (_config, token) = grpc_interceptor::setup().await;
    let result = grpc_interceptor::authenticate_request(token).await;
    assert!(result.is_ok(), "合法 token 应鉴权通过: {:?}", result);
}

/// 测试完整 async 鉴权：非法 token → Err。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_authenticate_request_with_invalid_token() {
    let (_config, _token) = grpc_interceptor::setup().await;
    let result = grpc_interceptor::authenticate_request("invalid-token-xxx".to_string()).await;
    assert!(result.is_err(), "非法 token 应鉴权失败");
}

/// 测试 build_metadata_with_token 构造的 metadata 能被 extract_token 正确提取。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_build_metadata_round_trip() {
    use garrison::grpc::GarrisonGrpcInterceptor;

    let token = "my-test-token-12345";
    let metadata = grpc_interceptor::build_metadata_with_token(token);
    let extracted = GarrisonGrpcInterceptor::extract_token(&metadata).unwrap();
    assert_eq!(extracted, token);
}
