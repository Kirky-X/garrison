# actix-web 适配（0.3.0 新增）

actix-web 适配在 0.3.0 新增，与 axum 适配对齐，通过 `web-actix` feature 启用。

## Feature 与依赖

```toml
[dependencies]
garrison = { version = "0.8", features = ["web-actix"] }
actix-web = "4"
```

`web-actix` 启用 `actix-web`（default-features = false），不引入额外默认依赖。

## 适配组件

| 组件 | 作用 |
|:---|:---|
| `GarrisonRouter` | 路由构建器，注册受保护路由规则 |
| `GarrisonMiddleware` | actix 中间件（实现 `Transform` + `Service`），设置 task_local 上下文 |
| `impl ResponseError for GarrisonError` | 错误自动转为 HTTP 响应（复用统一 `response_parts()`） |
| `CheckLogin` / `CheckRole(String)` / `CheckPermission(String)` | extractor，实现 `FromRequest` |

## GarrisonMiddleware（Transform + Service）

actix 的中间件模型由两部分组成：

- `GarrisonMiddleware`：实现 `Transform<S>`，是中间件工厂
- `GarrisonMiddlewareService<S>`：实际 service，包装内层 service 并在请求前注入上下文

```rust
use garrison::web_actix::{GarrisonRouter, GarrisonMiddleware};
use actix_web::{web, App, HttpServer};

async fn index() -> &'static str { "ok" }

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    GarrisonManager::builder()
    .dao(dao)
    .config(config)
    .interface(interface)
    .build()
    .await.ok();

    let mw = GarrisonRouter::new(config)
        .route_protected("/api/index", Annotation::CheckLogin)
        .into_middleware();

    HttpServer::new(move || {
        App::new()
            .wrap(mw.clone())
            .route("/api/index", web::get().to(index))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
```

## 多租户支持

中间件内置租户解析（`tenant-isolation` 生产场景）：配置 `TenantResolver` 后，
每个请求先解析租户并进入 `TENANT.scope` 再执行鉴权，使 `check_permission` /
`check_role` 获得租户上下文（否则 fail-closed 报 `ctx-tenant-context-missing`）。

```rust
use garrison::web_actix::GarrisonRouter;
use garrison::context::tenant::HeaderTenantResolver;

// 便捷方式：从 X-Tenant-Id 请求头解析租户（缺失/非法 → 拒绝请求，fail-closed）
let mw = GarrisonRouter::new(config)
    .with_header_tenant()
    .route_protected("/api/data", Annotation::CheckPermission("data:read".into()))
    .into_middleware();

// 自定义 resolver（如 SubdomainTenantResolver / ClaimTenantResolver）
let mw = GarrisonRouter::new(config)
    .with_tenant_resolver(HeaderTenantResolver)
    .into_middleware();
```

未配置 resolver 时行为与旧版一致（不提取租户）。注意：配置后所有经过中间件的请求
（含 `Ignore` 公开路径）都会触发租户解析，需带租户标识请求头。

## Extractor 用法（FromRequest）

```rust
use garrison::web_actix::{CheckLogin, CheckRole, CheckPermission};

async fn handler(
    _login: CheckLogin,                       // 校验已登录
    _role: CheckRole("admin".into()),          // 校验角色
    _perm: CheckPermission("user:read".into()),// 校验权限
) -> &'static str { "ok" }
```

extractor 实现 `FromRequest`，从请求提取 token 并调用 `GarrisonUtil` 校验，失败返回 `GarrisonError`（由 `ResponseError` 转为 HTTP 响应）。

## 错误响应

`GarrisonError` 实现 `actix_web::ResponseError`，`error_response()` 与 axum 共用同一套 `response_parts()` 逻辑，保证三框架错误格式一致：

- `NotLogin` / `InvalidToken` / `ExpiredToken` → 401
- `NotPermission` / `NotRole` → 403
- 其他 → 500

## 与 axum 的对齐

0.3.0 的 actix-web 适配在 API 形态上与 axum 完全对齐：相同的 `GarrisonRouter` 接口、相同的 extractor 命名、相同的错误映射。业务方切换框架只需替换中间件注册方式与 handler 宏。

## 注意事项

- actix-web 4 的 `Transform`/`Service` 模型要求中间件 `Clone`，`GarrisonMiddleware` 已实现
- task_local 上下文由 `GarrisonMiddlewareService` 在 `call` 前设置，未 wrap 中间件的路由无法使用 `GarrisonUtil`
- 多租户场景通过 `with_header_tenant()` / `with_tenant_resolver(resolver)` 启用中间件内置租户解析
