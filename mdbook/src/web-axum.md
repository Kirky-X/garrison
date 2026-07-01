# axum 适配

axum 是 Bulwark 的首选 Web 框架适配（0.1.0 起支持），通过 `web-axum` feature 启用。

## Feature 与依赖

```toml
[dependencies]
bulwark = { version = "0.3", features = ["web-axum"] }
```

`web-axum` 启用 `axum`（`tokio` + `http1` feature），不引入 default features 以减少依赖。

## 适配组件

| 组件 | 作用 |
|:---|:---|
| `BulwarkRouter` | 路由构建器，注册受保护路由并应用 `BulwarkLayer` |
| `BulwarkLayer` | 中间件，从 header/cookie 提取 token 并设置 task_local 上下文 |
| `impl IntoResponse for BulwarkError` | 错误自动转为 HTTP 响应（统一 `response_parts()`） |
| `CheckLogin` / `CheckRole` / `CheckPermission` | extractor，从请求 parts 校验（对应 `@SaCheckLogin` 等） |

## 路由与中间件示例

```rust
use std::sync::Arc;
use bulwark::prelude::*;
use bulwark::annotation::{CheckLogin, CheckPermission};
use axum::{routing::get, Router};

async fn profile() -> &'static str { "ok" }

async fn create_user(
    _p: CheckPermission,  // 校验权限（失败返回 BulwarkError）
) -> &'static str { "created" }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    BulwarkManager::init(dao, config, interface).await?;

    let router = BulwarkRouter::new(Arc::new(BulwarkConfig::default_config()))
        .route_protected("/api/profile", Annotation::Login)
        .route_protected("/api/user/create", Annotation::Permission("user:create".into()))
        .into_router();

    let app = Router::new()
        .route("/api/profile", get(profile))
        .route("/api/user/create", get(create_user))
        .merge(router);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

## Extractor 用法

extractor 在 handler 参数中声明即触发校验，失败返回 `BulwarkError`（由 `IntoResponse` 转为 HTTP 响应）：

```rust
use bulwark::annotation::{CheckLogin, CheckRole, CheckPermission};

async fn handler(
    _login: CheckLogin,                       // 校验已登录
    _role: CheckRole("admin".into()),          // 校验角色
    _perm: CheckPermission("user:read".into()),// 校验权限
) -> &'static str { "ok" }
```

## 错误响应

`BulwarkError` 实现 `IntoResponse`，自动映射为合适的 HTTP 状态码：

| 错误类型 | HTTP 状态 |
|:---|:---|
| `NotLogin` | 401 Unauthorized |
| `NotPermission` / `NotRole` | 403 Forbidden |
| `InvalidToken` / `ExpiredToken` | 401 Unauthorized |
| 其他 | 500 Internal Server Error |

## 关键说明

- `BulwarkLayer` 负责设置 task_local 上下文，`BulwarkUtil` 静态方法依赖此上下文
- 未注册 `BulwarkLayer` 的路由调用 `BulwarkUtil` 会因 task_local 缺失失败
- 0.1.0 已知限制：`route_protected` 仅支持 GET 方法（0.2.x 已完善）
