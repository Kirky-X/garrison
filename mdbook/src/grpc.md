# gRPC 鉴权拦截器（0.3.0 新增）

0.3.0 新增 gRPC 鉴权拦截器 `BulwarkGrpcInterceptor`，实现 `tonic::Interceptor`，为 tonic gRPC 服务提供统一鉴权，通过 `grpc` feature 启用。

## Feature 启用

```toml
[dependencies]
bulwark = { version = "0.3", features = ["grpc"] }
tonic = "0.13"
```

`grpc` feature 启用 `tonic`（`transport` feature，提供 `Interceptor` trait）。未启用时模块不存在，不引入 tonic 依赖。

## 设计

- `BulwarkGrpcInterceptor`：实现 `tonic::service::Interceptor` trait
- 从 gRPC 请求 metadata 提取 `authorization: Bearer <token>` header
- 调用 `BulwarkUtil::check_login()` 鉴权
- 鉴权失败返回 `tonic::Status::UNAUTHENTICATED`（code = 16）

```rust
use bulwark::grpc::BulwarkGrpcInterceptor;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    BulwarkManager::init(dao, config, interface).await?;

    Server::builder()
        .interceptor(BulwarkGrpcInterceptor::new())  // 注入拦截器
        .add_service(my_service)
        .serve(addr)
        .await?;
    Ok(())
}
```

## Token 提取

`extract_token` 从 tonic 请求的 `MetadataMap` 提取 token：

- 优先解析 `authorization: Bearer <token>`（RFC 7235，scheme 大小写不敏感）
- 支持 `Bearer ` / `bearer ` / `BEARER ` 三种大小写前缀
- 兼容不带 Bearer 前缀的裸 token（至少需非空）
- 缺失 header / 非 UTF-8 / 空 token → `Status::UNAUTHENTICATED`

```rust
use bulwark::grpc::BulwarkGrpcInterceptor;
use tonic::metadata::MetadataMap;

let mut metadata = MetadataMap::new();
metadata.insert("authorization", "Bearer abc123".parse()?);
let token = BulwarkGrpcInterceptor::extract_token(&metadata)?;
assert_eq!(token, "abc123");
```

## 拦截流程

1. tonic 在每个请求前调用 `interceptor.call(request)`
2. 拦截器从 `request.metadata()` 提取 token
3. 设置 task_local 上下文（与 web 中间件一致）
4. 调用 `BulwarkUtil::check_login()` 校验
5. 校验通过 → 返回 `Ok(request)` 继续下游 service
6. 校验失败 → 返回 `Err(Status::UNAUTHENTICATED)`，请求被拒绝

## 拦截器特性

- **无状态**：`BulwarkGrpcInterceptor` 不持有数据，实现 `Clone` + `Default`
- **可共享**：可在多个 tonic Server 间共享同一实例
- **`new()` 构造**：无参数，简单创建

## 与 web 鉴权的一致性

gRPC 拦截器复用 `BulwarkUtil::check_login`，与 axum / actix-web / warp 共用同一套会话与权限逻辑：

- 同一 token 在 HTTP 与 gRPC 服务中均可鉴权
- 权限/角色校验同样通过 `BulwarkUtil::check_permission` / `check_role`
- 多协议共享 oxcache 会话，无需重复登录

## 注意事项

- 拦截器对每个请求都鉴权，无内置缓存（会话缓存由 oxcache 提供）
- `tonic::Interceptor` 是同步 trait，内部通过 `block_on` 调用异步 `check_login`，不适合极高 QPS 场景
- 需在 `BulwarkManager::init` 之后使用，否则校验返回未初始化错误
