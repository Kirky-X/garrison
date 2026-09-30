# axum 适配

axum 是 Garrison 的首选 Web 框架适配（0.1.0 起支持），通过 `web-axum` feature 启用。

## Feature 与依赖

```toml
[dependencies]
garrison = { version = "0.9.0-rc.2", features = ["web-axum"] }
```

> 注：当前版本为 pre-release（0.9.0-rc.2），`version = "0.9"` 不会匹配它——Cargo 要求显式写出完整 pre-release 版本号；待 0.9.0 正式发布后可再改为 `"0.9"`。

`web-axum` 启用 `axum`（`tokio` + `http1` feature），不引入 default features 以减少依赖。

## 适配组件

| 组件 | 作用 |
|:---|:---|
| `GarrisonRouter` | 路由构建器，注册受保护路由并应用中件间（`garrison_middleware`） |
| `garrison_middleware` | 中间件函数，从 header/cookie 提取 token 并设置 task_local 上下文 |
| `impl IntoResponse for GarrisonError` | 错误自动转为 HTTP 响应（统一 `response_parts()`） |
| `CheckLogin` / `CheckRole` / `CheckPermission` | extractor，从请求 parts 校验（对应 `@SaCheckLogin` 等） |

## 路由与中间件示例

```rust
use std::sync::Arc;
use garrison::prelude::*;
use garrison::annotation::{CheckPermission, PermissionName};
use axum::Router;

async fn profile() -> &'static str { "ok" }

struct UserCreatePerm;
impl PermissionName for UserCreatePerm {
    const NAME: &'static str = "user:create";
}

async fn create_user(
    _p: CheckPermission<UserCreatePerm>,  // 校验权限（失败返回 GarrisonError）
) -> &'static str { "created" }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    GarrisonManager::builder()
    .dao(dao)
    .config(config)
    .interface(interface)
    .build()
    .await?;

    let router = GarrisonRouter::new(Arc::new(GarrisonConfig::default_config()))
        .route_protected("/api/profile", profile, Annotation::CheckLogin)
        .route_protected(
            "/api/user/create",
            create_user,
            Annotation::CheckPermission("user:create".into()),
        )
        .build();

    let app = Router::new().merge(router);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

## Extractor 用法

extractor 在 handler 参数中声明即触发校验，失败返回 `GarrisonError`（由 `IntoResponse` 转为 HTTP 响应）：

```rust
use garrison::annotation::{CheckLogin, CheckRole, CheckPermission, RoleName, PermissionName};

struct AdminRole;
impl RoleName for AdminRole {
    const NAME: &'static str = "admin";
}

struct UserReadPerm;
impl PermissionName for UserReadPerm {
    const NAME: &'static str = "user:read";
}

async fn handler(
    _login: CheckLogin,                       // 校验已登录
    _role: CheckRole<AdminRole>,              // 校验角色
    _perm: CheckPermission<UserReadPerm>,     // 校验权限
) -> &'static str { "ok" }
```

> **注**：axum 的 `CheckRole<R>` / `CheckPermission<P>` 为泛型 extractor，需通过实现 `RoleName` / `PermissionName` trait 的类型参数指定角色 / 权限名（编译期常量）。actix-web / warp 版本使用运行时 `String` 参数。

## 错误响应

`GarrisonError` 实现 `IntoResponse`，自动映射为合适的 HTTP 状态码：

| 错误类型 | HTTP 状态 |
|:---|:---|
| `NotLogin` | 401 Unauthorized |
| `NotPermission` / `NotRole` | 403 Forbidden |
| `InvalidToken` / `ExpiredToken` | 401 Unauthorized |
| `Dao` / `Config` / `Internal` / `Session` 等内部错误 | 500 Internal Server Error |
| `Network` / `InvalidResponse` | 502 Bad Gateway |
| `InvalidParam` / `NotSafe` | 400 Bad Request |
| `NotImplemented` | 501 Not Implemented |
| `RateLimited` / `SmsRateLimitExceeded` 等限流错误 | 429 Too Many Requests（仅 `RateLimited` 附 `Retry-After` header） |
| `CreditInsufficient`（`credit-metering` feature） | 402 Payment Required |

## 关键说明

- `GarrisonRouter::build()` 内置的 `garrison_middleware` 负责设置 task_local 上下文，`GarrisonUtil` 静态方法依赖此上下文
- 未注册中间件的路由调用 `GarrisonUtil` 会因 task_local 缺失失败
- 当前已知限制：`route_protected` 仅支持 GET 方法（内部注册的是 `axum::routing::get`），且 `GarrisonRouter` 无公开 API 可为已注册路由补充注解规则（规则列表为私有字段，公开方法仅有 `new` / `with_interceptor` / `route_protected` / `group` / `build`）——直接用 `axum::Router::route` 注册的非 GET 路由不会命中任何规则，middleware 会跳过 `pre_handle` 直接放行（等于未鉴权）。此类路由的鉴权需自行编写 middleware（通过 prelude 的 `with_current_token` 设置 task_local 后校验，`CheckLogin` / `CheckRole` / `CheckPermission` extractor 也依赖该上下文），或扩展 `GarrisonRouter` 支持任意 HTTP 方法后使用
