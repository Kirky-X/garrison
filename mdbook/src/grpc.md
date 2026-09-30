# gRPC 鉴权拦截器（0.3.0 新增）

0.3.0 新增 gRPC 鉴权拦截器 `GarrisonGrpcInterceptor`，实现 `tonic::Interceptor`，为 tonic gRPC 服务提供 token 提取与格式校验，通过 `grpc` feature 启用。

## Feature 启用

```toml
[dependencies]
garrison = { version = "0.9.0-rc.2", features = ["grpc"] }
tonic = "0.14"
```

`grpc` feature 启用 `tonic`（含 `transport` feature，示例中的 `tonic::transport::Server` 需要）、`tonic-health` 与 `tower`，并联动 `sdforge/grpc`；`Interceptor` trait 位于无需 feature 门控的 `tonic::service` 模块。未启用时模块不存在，不引入 tonic 依赖。

## 设计

- `GarrisonGrpcInterceptor`：实现 `tonic::service::Interceptor` trait
- 从 gRPC 请求 metadata 提取 `authorization: Bearer <token>` header
- **默认仅校验 token 格式**（非空、`Bearer` 前缀正确、长度 ≤ 4KB），不执行 async 鉴权；经 `with_token_validator()` 注入同步校验器后可在拦截器内完成真实（同步）鉴权
- 格式不合法返回 `tonic::Status::UNAUTHENTICATED`（code = 16）

> **重要限制**：`tonic::Interceptor::call` 是同步 trait，无法调用异步的 `GarrisonUtil::check_login()`。
> 本拦截器仅完成 token 提取与基本格式校验，并把 token 以 `GarrisonGrpcToken` 注入 request extensions
> （**不**设置 task_local），**实际的登录态/权限校验**须在 tonic service handler 内完成：先经
> `request.extensions().get::<garrison::grpc::GarrisonGrpcToken>()` 取出拦截器注入的 token，再在
> `garrison::stp::with_current_token(token, …)` 作用域内调用 `GarrisonUtil::check_login()` 等 stp 静态 API
> ——task_local 未设置时读不到 token，`current_token()` 报 `GarrisonError::Session`
> （`throw_on_not_login=false` 时 `check_login` 恒返回 `Ok(false)`，即永远视为未登录）。
> 或直接使用 `GarrisonGrpcAuthLayer`（tower Layer，自动在 `with_current_token` 作用域内完成 async
> `check_login`）。`GarrisonContext` 仅用于跨 `tokio::spawn` 传播上下文，不是鉴权调用入口。

```rust
use garrison::grpc::{GarrisonGrpcInterceptor, health_service};
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    GarrisonManager::builder()
    .dao(dao)
    .config(config)
    .interface(interface)
    .build()
    .await?;

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
- 支持 `Bearer` / `bearer` / `bEaReR` 等任意 ASCII 大小写组合前缀
- **严格 Bearer 校验**：不接受裸 token（避免将 Basic/Digest 凭证误认为 Bearer token）
- 缺失 header / 非 UTF-8 / 空 token / 超过 4KB（`MAX_TOKEN_LEN` = 4096）→ `Status::UNAUTHENTICATED`

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
5. 实际登录态/权限校验由业务在 service handler 内完成：先经 `request.extensions().get::<garrison::grpc::GarrisonGrpcToken>()` 取出拦截器注入的 token，再在 `garrison::stp::with_current_token(token, …)` 作用域内异步调用 `GarrisonUtil::check_login()` 等 stp 静态 API（`GarrisonContext` 仅用于跨 `tokio::spawn` 传播上下文，不是鉴权调用入口）；或改用 `GarrisonGrpcAuthLayer`（tower Layer，自动完成 `with_current_token` 注入）

## 拦截器特性

- **默认仅格式校验、可选同步校验器**：`new()` 创建的实例不配置校验器（仅 Bearer 格式校验）；`with_token_validator()` 可注入同步 token 校验器（`GarrisonGrpcTokenValidator`，内部持有 `Option<Arc<dyn GarrisonGrpcTokenValidator>>`），配置后在拦截器内即完成真实鉴权，失败以对应 `Status` 拒绝。仍实现 `Clone` + `Default`
- **可共享**：可在多个 tonic Server 间共享同一实例
- **`new()` 构造**：无参数，简单创建
- **健康检查服务**：模块另提供 `health_service()` 函数，返回 `HealthServer<impl Health>`（完整路径 `tonic_health::pb::health_server::HealthServer`），供 kubelet / 服务网格探针调用

## 与 web 鉴权的一致性

gRPC 拦截器仅做 token 格式校验，业务方在 service handler 内取出拦截器注入的 `GarrisonGrpcToken` 后，在 `with_current_token` 作用域内调用 `GarrisonUtil::check_login` 完成实际鉴权（或直接使用 `GarrisonGrpcAuthLayer`），与 axum / actix-web / warp 共用同一套会话与权限逻辑：

- 同一 token 在 HTTP 与 gRPC 服务中均可鉴权（在 handler 内显式调用）
- 权限/角色校验同样通过 `GarrisonUtil::check_permission` / `check_role`
- 多协议共享 oxcache 会话，无需重复登录

## 注意事项

- 默认构造的拦截器仅校验 token 格式，**不执行实际鉴权**；async `check_login` 须在 handler 内取出 `GarrisonGrpcToken` 后于 `with_current_token` 作用域内调用（task_local 未设置时 `current_token()` 报 `GarrisonError::Session`，`throw_on_not_login=false` 时 `check_login` 恒返回 `Ok(false)`），或直接使用 `GarrisonGrpcAuthLayer`
- `tonic::Interceptor` 是同步 trait，无法调用异步 API；高 QPS 场景建议使用 `tower::Layer` middleware
- 需在 `GarrisonManager::builder().build().await` 之后使用，否则 handler 内 `check_login` 返回未初始化错误
- `health_service()` 须注册到独立的 tonic Server（无 interceptor），避免探针因缺 Authorization 被拒
