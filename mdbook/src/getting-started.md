# 入门指南

本页介绍如何在项目中引入 Garrison，配置 feature flags，并运行最小登录示例。

## 运行环境要求

- Rust 1.85+（MSRV，`inventory 0.3` 等依赖要求 edition 2024）
- Tokio 运行时（`rt-multi-thread` feature）
- 可选：SQLite（默认数据库后端）/ Redis（L2 缓存）

## Cargo.toml 依赖配置

Garrison 默认启用 `backend-embedded` feature（嵌入式后端模式），可按需选择额外 feature：

```toml
[dependencies]
garrison = { version = "0.9.0-rc.2", features = ["web-axum", "cache-memory", "db-sqlite"] }
tokio = { version = "1", features = ["full"] }
```

> 注：当前版本为 pre-release（0.9.0-rc.2），`version = "0.9"` 不会匹配它——Cargo 要求显式写出完整 pre-release 版本号；待 0.9.0 正式发布后可再改为 `"0.9"`。

## Feature flags 说明

| 类别 | Feature | 说明 |
|:---|:---|:---|
| 缓存 | `cache-memory` / `cache-redis` | 基于 oxcache 0.5 的 L1(内存) + L2(redis)，语义别名 |
| 数据库 | `db-sqlite` / `db-postgres` / `db-mysql` | 基于 dbnexus 0.6 + auto-migrate（三后端，禁混用） |
| Web 框架 | `web-axum` / `web-actix` / `web-warp` | 路由拦截器与 extractor 适配 |
| 协议层 | `protocol-jwt` / `protocol-oauth2` / `protocol-sso` / `protocol-sign` / `protocol-apikey` / `protocol-temp` | 鉴权协议插件 |
| 安全模块 | `secure-totp` / `secure-sign` / `protocol-httpbasic` / `protocol-httpdigest` | TOTP / 签名 / Basic / Digest |
| 可观测性 | `listener` / `tracing-log` / `metrics-prometheus` / `otlp` | 事件 / 日志 / 指标 / 追踪 |
| 生态 | `grpc` / `i18n-icu` | gRPC 拦截器 / ICU4X 增强层（复数 + 日期/数字本地化） |
| 聚合 | `full` / `production` / `development` | 一键启用一组特性 |

`development` = `cache-memory` + `db-sqlite` + `web-axum`（替代已移除的 `all-defaults`）；`full` 启用绝大多数能力但并非全部——数据库后端仅含 `db-sqlite`，也不含 `tracing-log`、`audit-log`、`policy-hibp`、`manager-explicit`、`tls`、`keycloak-oidc` 等十余个 feature（生产组合见 `production`）。

## 最小示例

初始化管理器 → 执行登录 → 校验登录状态。

```rust
use std::sync::Arc;
use garrison::prelude::*;
use garrison::dao::{init_dbnexus, GarrisonMigration};
use garrison::stp::LoginParams;
use async_trait::async_trait;

// 业务方实现 GarrisonInterface（提供权限/角色数据）
struct MyInterface;
#[async_trait]
impl GarrisonInterface for MyInterface {
    async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec!["user:read".into(), "user:write".into()])
    }
    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec!["user".into()])
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 数据库迁移（幂等，首次启动建表；迁移脚本目录来源与注意事项见下方「关键约束」）
    let pool = init_dbnexus("sqlite::memory:").await?;
    GarrisonMigration::new(pool).run_all().await?;

    // 2. 准备依赖（业务方实现 GarrisonDao / GarrisonInterface）
    let dao: Arc<dyn GarrisonDao> = /* oxcache / dbnexus 实现 */;
    let config = Arc::new(GarrisonConfig::default_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MyInterface);

    // 3. 初始化全局管理器（覆盖式注入 dao / config / interface）
    //    必须在所有 GarrisonUtil 静态方法调用前完成
    GarrisonManager::builder()
    .dao(dao)
    .config(config)
    .interface(interface)
    .build()
    .await?;

    // 4. 执行登录：login 接收 login_id 生成并返回新 token，
    //    不读取 task_local 当前 token，无需 with_current_token 包装
    let token = GarrisonUtil::login("1001", &LoginParams::default()).await?;

    // 5. 校验登录状态
    //    check_login / logout 依赖 task_local 中的当前 token，
    //    直连调用（测试/脚本）时用 with_current_token 注入
    let logged_in = garrison::stp::with_current_token(
        token.clone(),
        GarrisonUtil::check_login(),
    ).await?;
    assert!(logged_in);

    // 6. 登出
    garrison::stp::with_current_token(
        token.clone(),
        GarrisonUtil::logout(),
    ).await?;

    Ok(())
}
```

## 关键约束

- `GarrisonManager::builder().build().await` 是 async 函数，必须在所有 `GarrisonUtil` API 调用前完成，否则返回未初始化错误。
- `logout` / `check_login`（以及 `get_login_id` 等）依赖 `task_local` 中的当前 token，需通过 web 中间件（如 `garrison_middleware`）注入，或在测试/脚本中用 `with_current_token()` 包装；`login` 接收 `login_id` 生成并返回新 token，不读取当前 token，无需包装。
- 首次启动需调用 `GarrisonMigration::new(pool).run_all()` 完成数据库建表（幂等）。注意：`GarrisonMigration::new` 默认从**当前工作目录**下的 `migrations/sqlite/` 读取迁移脚本，目录不存在时静默跳过（返回 0，不报错），后续业务 SQL 才会报缺表。仓库外（crates.io 消费者）请将 garrison 仓库 `migrations/` 下对应后端的 SQL 复制到自己项目，并改用 `GarrisonMigration::with_base_dir(pool, 脚本目录)` 指定位置；PostgreSQL 后端可启用 `db-postgres` feature（已透传 `embedded-migrations`）后调用 `run_embedded_postgres()`，无需访问迁移文件目录（MySQL 无嵌入式迁移支持，只能 `with_base_dir`）。

## 下一步

- [配置参考](./configuration.md)
- [整体架构](./architecture.md)
