# gRPC 鉴权拦截器（0.3.0 新增）

0.3.0 新增 gRPC 鉴权拦截器 `GarrisonGrpcInterceptor`，实现 `tonic::Interceptor`，为 tonic gRPC 服务提供 token 提取与格式校验，通过 `grpc` feature 启用。

## Feature 启用

```toml
[dependencies]
garrison = { version = "0.7", features = ["grpc"] }
tonic = "0.14"
```

`grpc` feature 启用 `tonic`（`transport` feature，提供 `Interceptor` trait）。未启用时模块不存在，不引入 tonic 依赖。

## 设计

- `GarrisonGrpcInterceptor`：实现 `tonic::service::Interceptor` trait
- 从 gRPC 请求 metadata 提取 `authorization: Bearer <token>` header
- **仅校验 token 格式**（非空、`Bearer` 前缀正确），不执行 async 鉴权
- 格式不合法返回 `tonic::Status::UNAUTHENTICATED`（code = 16）

> **重要限制**：`tonic::Interceptor::call` 是同步 trait，无法调用异步的 `GarrisonUtil::check_login()`。
> 本拦截器仅完成 token 提取与基本格式校验，**实际的登录态/权限校验**须在 tonic service handler
> 内通过 `GarrisonContext` 显式调用 `GarrisonUtil::check_login()` 完成，或使用 `tower::Layer` middleware。

```rust
use garrison::grpc::{GarrisonGrpcInterceptor, health_service};
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    GarrisonManager::init(dao, config, interface)?;

    // 健康检查服务须注册到独立 Server（无 interceptor），避免探针缺 Authorization 被拒
    let health = health_service().await;
    Server::builder()
        .add_service(health)
        .serve(health_addr)
        .await?;

    Server::builder()
        .interceptor(GarrisonGrpcInterceptor::new())  // 注入拦截器
        .add_service(my_service)
        .serve(addr)
        .await?;
    Ok(())
}
```

## Token 提取

`extract_token` 从 tonic 请求的 `MetadataMap` 提取 token：

- 解析 `authorization: Bearer <token>`（RFC 7235，scheme 大小写不敏感）
- 支持 `Bearer` / `bearer` / `BEARER` 三种大小写前缀
- **严格 Bearer 校验**：不接受裸 token（避免将 Basic/Digest 凭证误认为 Bearer token）
- 缺失 header / 非 UTF-8 / 空 token → `Status::UNAUTHENTICATED`

```rust
use garrison::grpc::GarrisonGrpcInterceptor;
use tonic::metadata::MetadataMap;

let mut metadata = MetadataMap::new();
metadata.insert("authorization", "Bearer abc123".parse()?);
let token = GarrisonGrpcInterceptor::extract_token(&metadata)?;
assert_eq!(token, "abc123");
```

## 拦截流程

1. tonic 在每个请求前调用 `interceptor.call(request)`
2. 拦截器从 `request.metadata()` 提取 token（严格 Bearer 校验）
3. **格式校验通过** → 返回 `Ok(request)` 继续下游 service
4. **格式校验失败** → 返回 `Err(Status::UNAUTHENTICATED)`，请求被拒绝
5. 实际登录态/权限校验由业务在 service handler 内通过 `GarrisonContext` 异步完成

## 拦截器特性

- **无状态**：`GarrisonGrpcInterceptor` 不持有数据，实现 `Clone` + `Default`
- **可共享**：可在多个 tonic Server 间共享同一实例
- **`new()` 构造**：无参数，简单创建
- **健康检查服务**：模块另提供 `health_service()` 函数，返回 `tonic_health::server::HealthServer`，供 kubelet / 服务网格探针调用

## 与 web 鉴权的一致性

gRPC 拦截器仅做 token 格式校验，业务方在 service handler 内调用 `GarrisonUtil::check_login` 完成实际鉴权，与 axum / actix-web / warp 共用同一套会话与权限逻辑：

- 同一 token 在 HTTP 与 gRPC 服务中均可鉴权（在 handler 内显式调用）
- 权限/角色校验同样通过 `GarrisonUtil::check_permission` / `check_role`
- 多协议共享 oxcache 会话，无需重复登录

## 注意事项

- 拦截器仅校验 token 格式，**不执行实际鉴权**（async check_login 须在 handler 内调用）
- `tonic::Interceptor` 是同步 trait，无法调用异步 API；高 QPS 场景建议使用 `tower::Layer` middleware
- 需在 `GarrisonManager::init` 之后使用，否则 handler 内 `check_login` 返回未初始化错误
- `health_service()` 须注册到独立的 tonic Server（无 interceptor），避免探针因缺 Authorization 被拒
