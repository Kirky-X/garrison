# 入门指南

本页介绍如何在项目中引入 Bulwark，配置 feature flags，并运行最小登录示例。

## 运行环境要求

- Rust 1.85+（MSRV，`inventory 0.3` 等依赖要求 edition 2024）
- Tokio 运行时（`rt-multi-thread` feature）
- 可选：SQLite（默认数据库后端）/ Redis（L2 缓存）

## Cargo.toml 依赖配置

Bulwark 默认不启用任何 feature，需按需选择：

```toml
[dependencies]
bulwark = { version = "0.3", features = ["web-axum", "cache-memory", "db-sqlite"] }
tokio = { version = "1", features = ["full"] }
```

## Feature flags 说明

| 类别 | Feature | 说明 |
|:---|:---|:---|
| 缓存 | `cache-memory` / `cache-redis` | 基于 oxcache 0.3 的 L1(内存) + L2(redis)，语义别名 |
| 数据库 | `db-sqlite` | 基于 dbnexus 0.2 + auto-migrate |
| Web 框架 | `web-axum` / `web-actix` / `web-warp` | 路由拦截器与 extractor 适配 |
| 协议层 | `protocol-jwt` / `protocol-oauth2` / `protocol-sso` / `protocol-sign` / `protocol-apikey` / `protocol-temp` | 鉴权协议插件 |
| 安全模块 | `secure-totp` / `secure-sign` / `secure-httpbasic` / `secure-httpdigest` | TOTP / 签名 / Basic / Digest |
| 可观测性 | `listener` / `tracing-log` / `metrics-prometheus` / `observability-otlp` | 事件 / 日志 / 指标 / 追踪 |
| 生态 | `grpc` / `i18n` | gRPC 拦截器 / 异常消息国际化 |
| 聚合 | `all-defaults` / `full` / `production` / `development` | 一键启用一组特性 |

`all-defaults` = `cache-memory` + `db-sqlite` + `web-axum`；`full` 启用全部能力。

## 最小示例

初始化管理器 → 执行登录 → 校验登录状态。

```rust
use std::sync::Arc;
use bulwark::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 准备依赖（业务方实现 BulwarkDao / BulwarkInterface）
    let dao: Arc<dyn BulwarkDao> = /* oxcache / dbnexus 实现 */;
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface);

    // 2. 初始化全局管理器（覆盖式注入 dao / config / interface）
    BulwarkManager::init(dao, config, interface).await?;

    // 3. 执行登录：生成 token 并写入会话
    //    注意：login / check_login 依赖 task_local 上下文中的当前 token，
    //    通常由 web 中间件（如 axum middleware）设置。
    let token = BulwarkUtil::login(1001).await?;

    // 4. 校验登录状态
    let logged_in = BulwarkUtil::check_login().await?;
    assert!(logged_in);
    Ok(())
}
```

## 关键约束

- `BulwarkManager::init` 必须在所有 API 调用前完成，否则 `BulwarkUtil` 静态方法会返回未初始化错误。
- `login` / `check_login` 依赖 `task_local` 中的当前 token，需通过 web 中间件（如 `BulwarkLayer`）注入。
- 首次启动需调用 `BulwarkMigration::run_migrations(&db)` 完成数据库建表（幂等）。

## 下一步

- [配置参考](./configuration.md)
- [整体架构](./architecture.md)
