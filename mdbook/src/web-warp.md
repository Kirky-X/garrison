# warp 适配（0.3.0 新增）

warp 适配在 0.3.0 新增，采用 Filter 组合模型，通过 `web-warp` feature 启用。

## Feature 与依赖

```toml
[dependencies]
bulwark = { version = "0.3", features = ["web-warp"] }
warp = "0.4"
```

`web-warp` 启用 `warp`（default-features = false）。

## 适配组件

| 组件 | 作用 |
|:---|:---|
| `BulwarkRouter` | 路由构建器，注册受保护路由规则 |
| `impl Reply for BulwarkError` | 错误自动转为 HTTP 响应（复用统一 `response_parts()`） |
| `BulwarkRejection(BulwarkError)` | 实现 `warp::reject::Reject`，用于 Filter 鉴权拒绝 |
| `check_login()` / `check_role(role)` / `check_permission(perm)` | Filter 函数，校验失败返回 `BulwarkRejection` |

## Filter 鉴权示例

warp 采用 Filter 组合模型，鉴权作为 Filter 在路由链中应用：

```rust
use bulwark::web_warp::{BulwarkRouter, check_login, check_role, check_permission};
use warp::Filter;

async fn profile() -> &'static str { "ok" }

#[tokio::main]
async fn main() {
    BulwarkManager::init(dao, config, interface).await.ok();

    // 受保护路由：先 check_login Filter，再处理
    let profile_route = warp::path!("api" / "profile")
        .and(check_login())
        .map(|| "ok");

    let create_route = warp::path!("api" / "user" / "create")
        .and(check_permission("user:create".to_string()))
        .map(|| "created");

    let routes = profile_route.or(create_route);
    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
```

## Filter 函数

| Filter | 签名 | 行为 |
|:---|:---|:---|
| `check_login()` | `Filter<Extract = (), Error = BulwarkRejection>` | 校验已登录，失败 reject |
| `check_role(role: String)` | 同上 | 校验角色，失败 reject |
| `check_permission(perm: String)` | 同上 | 校验权限，失败 reject |

Filter 在 `and()` 链中组合，通过即继续下游 handler，失败则短路返回 `BulwarkRejection`。

## 错误响应

```rust
use bulwark::web_warp::BulwarkRejection;

// 全局 reject 处理：将 BulwarkRejection 转为 HTTP 响应
let routes = routes.recover(|rejection: warp::reject::Rejection| async move {
    if let Some(e) = rejection.find::<BulwarkRejection>() {
        return Ok::<_, warp::Reply>(e.0.clone()); // impl Reply for BulwarkError
    }
    Err(rejection)
});
```

`BulwarkError` 实现 `Reply`，`response_parts()` 与 axum/actix 共用同一逻辑，保证三框架错误格式一致：

- `NotLogin` / `InvalidToken` / `ExpiredToken` → 401
- `NotPermission` / `NotRole` → 403
- 其他 → 500

## 与 axum/actix 的对齐

0.3.0 的 warp 适配在概念上对齐：

| 概念 | axum | actix-web | warp |
|:---|:---|:---|:---|
| 错误响应 | `IntoResponse` | `ResponseError` | `Reply` + `Reject` |
| 鉴权 | extractor | `FromRequest` | Filter 函数 |
| 中间件 | `BulwarkLayer` | `BulwarkMiddleware` | Filter 组合 |

## 注意事项

- warp 无显式中间件概念，鉴权通过 Filter `and()` 组合实现
- `BulwarkRejection` 包装 `BulwarkError`，需在 `recover()` 中统一转响应
- task_local 上下文由 `check_*` Filter 内部设置，未经过 Filter 的路由无法使用 `BulwarkUtil`
