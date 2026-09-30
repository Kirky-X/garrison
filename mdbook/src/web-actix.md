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
    .config(config.clone())
    .interface(interface)
    .build()
    .await.ok();

    let mw_config = config;
    HttpServer::new(move || {
        // 工厂闭包为每个 worker 各调用一次：在闭包内重建中间件（各 worker 独立实例）
        let mw = GarrisonRouter::new(mw_config.clone())
            .route_protected("/api/index", Annotation::CheckLogin)
            .into_middleware();

        App::new()
            .wrap(mw)
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
use garrison::web_actix::{CheckLogin, CheckRole, CheckPermission, RequiredRole, RequiredPermission};

async fn handler(
    _login: CheckLogin,     // 校验已登录
    _role: CheckRole,       // 校验角色（角色名来自 RequiredRole app_data）
    _perm: CheckPermission, // 校验权限（权限名来自 RequiredPermission app_data）
) -> &'static str { "ok" }

// 角色 / 权限名在 App 上以 web::Data 服务端配置（禁止客户端可控输入）：
// App::new()
//     .app_data(web::Data::new(RequiredRole("admin".to_string())))
//     .app_data(web::Data::new(RequiredPermission("user:read".to_string())))
```

extractor 实现 `FromRequest`，从请求提取 token 并调用 `GarrisonUtil` 校验，失败返回 `GarrisonError`（由 `ResponseError` 转为 HTTP 响应）。`CheckRole` / `CheckPermission` 的角色名 / 权限名不取自 handler 处的构造值，而是分别从 `web::Data<RequiredRole>` / `web::Data<RequiredPermission>` app_data 读取（未注册时回退空字符串）。

## 错误响应

`GarrisonError` 实现 `actix_web::ResponseError`，`error_response()` 与 axum 共用同一套 `response_parts()` 逻辑，保证三框架错误格式一致：

- `NotLogin` / `InvalidToken` / `ExpiredToken` / `TokenRevoked` → 401
- `NotPermission` / `NotRole` / `FirewallBlocked` / `DisableService` 等 → 403
- `RateLimited` 等限流变体 → 429（携带 `Retry-After` 头）
- `InvalidParam` / `NotSafe` 等参数与校验错误 → 400，`CreditInsufficient` → 402（`credit-metering` feature），`NotImplemented` → 501，`Network` / `InvalidResponse` → 502
- `Dao` / `Config` / `Internal` / `Session` 等内部错误 → 500

## 与 axum 的对齐

0.3.0 的 actix-web 适配与 axum 适配保持 extractor 命名（`CheckLogin` / `CheckRole` / `CheckPermission`）与错误映射一致，但 `GarrisonRouter` 接口与使用方式不同：axum 版 `route_protected(path, handler, annotation)` 同时注册路由与鉴权规则（另有 `group()` 分组），以 `build()` 产出 `Router`；actix 版 `route_protected(path, annotation)` 仅记录鉴权规则，路由需在 `App::route()` 中单独注册，最后以 `into_middleware()` 产出中间件。extractor 机制也不同：axum 的 `CheckRole<R>` / `CheckPermission<P>` 为编译期泛型（类型参数实现 `RoleName` / `PermissionName`），actix 版为运行时 `String`，通过 `web::Data<RequiredRole>` / `web::Data<RequiredPermission>` 在路由注册时服务端配置。此外注解宏 `#[check_login]` 等仅支持 axum handler，actix 侧无对应宏。

## 注意事项

- `HttpServer::new` 的工厂闭包受 `Fn() -> I` 约束，会为每个 worker 各构建一次 `App`：`GarrisonMiddleware` 未实现 `Clone`，应在闭包内通过 `GarrisonRouter::new(config.clone())…into_middleware()` 为每个 worker 重建独立实例（写法同仓库示例 `examples/src/web/web_actix_example.rs`）。注意 actix 的 `Transform` trait 本身并不要求中间件 `Clone`，要求的是闭包可多次调用
- task_local 上下文由 `GarrisonMiddlewareService` 在 `call` 前设置，未 wrap 中间件的路由无法使用 `GarrisonUtil`
- 多租户场景通过 `with_header_tenant()` / `with_tenant_resolver(resolver)` 启用中间件内置租户解析
