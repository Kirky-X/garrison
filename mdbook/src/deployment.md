# 部署指南

本页介绍 Bulwark 生产环境部署的 feature 推荐组合、Redis 配置、SQLite 初始化与环境变量。

> 完整部署细节（Docker、反向代理、性能调优、健康检查、升级指南）详见 [../../docs/deployment.md](../../docs/deployment.md)。

## 部署模型

Bulwark 是库（crate），不产出二进制。业务方将其作为依赖集成到 axum / actix-web / warp 服务中：

1. 添加依赖并选择 feature
2. 服务启动时调用 `BulwarkManager::init()`
3. 调用 `BulwarkMigration::run_migrations()` 自动建表
4. 注册路由中间件（如 `BulwarkLayer`）
5. `cargo build --release --features production` 构建产物
6. 通过环境变量注入配置，启动服务

## 生产环境 feature 推荐组合

`production` 聚合 feature 已为生产环境调优：

```toml
[dependencies]
bulwark = { version = "0.3", features = ["production"] }
```

`production` 等价于：

```toml
production = [
    "cache-redis", "db-sqlite", "web-axum",
    "protocol-jwt", "protocol-sign", "secure-sign",
    "listener", "tracing-log", "metrics-prometheus",
]
```

按需追加其他能力：

```toml
features = ["production", "observability-otlp", "grpc", "i18n", "web-actix"]
```

| 场景 | 推荐组合 |
|:---|:---|
| 单实例开发 | `development`（`cache-memory` + `db-sqlite` + `web-axum`） |
| 多实例生产 | `production`（含 `cache-redis`） |
| 全量能力评估 | `full`（启用全部 feature） |
| gRPC 微服务 | `production` + `grpc` |

## Redis 配置（L2 缓存）

多实例部署必须启用 `cache-redis`，否则 Token-Session 跨实例不一致：

```bash
# 通过环境变量配置 oxcache 的 redis 连接（具体变量名见 oxcache 文档）
OXCACHE_REDIS_URL=redis://:password@redis-host:6379/0
```

要点：

- L1 moka 进程内缓存 + L2 redis 跨实例共享
- Token-Session 与 Account-Session 均写入 redis
- TTL 由 `config.timeout` 控制，redis 自动过期
- 生产环境建议 Redis 启用 AOF/RDB 持久化

## SQLite 初始化

`db-sqlite` feature 启用 dbnexus 的 `auto-migrate`，首次启动自动建表：

```rust
use bulwark::BulwarkMigration;

// 幂等：首次启动建表，后续启动跳过
BulwarkMigration::run_migrations(&db).await?;
```

```bash
# 通过环境变量指定 SQLite 文件路径（dbnexus config-env）
DBNEXUS_SQLITE_PATH=/var/lib/bulwark/bulwark.db
```

要点：

- 迁移幂等，可安全重复执行
- 生产环境建议将 db 文件放在持久化卷
- SQLite 适合中小规模；大规模或多写场景待 0.4.0 PostgreSQL/MySQL 支持

## 环境变量

通过 `BULWARK_` 前缀环境变量覆盖配置（详见 [配置参考](./configuration.md)）：

```bash
# Token 配置
BULWARK_TOKEN_NAME=bulwark_token
BULWARK_TIMEOUT=2592000
BULWARK_TOKEN_STYLE=uuid

# Cookie 安全
BULWARK_COOKIE_SECURE=true
BULWARK_COOKIE_SAME_SITE=Lax

# 协议参数
BULWARK_JWT_ALGORITHM=HS256
BULWARK_SIGN_WINDOW_SECONDS=300
BULWARK_SSO_TICKET_TTL_SECONDS=60

# 日志
RUST_LOG=info,bulwark=debug
```

## 启动代码示例

```rust
use bulwark::prelude::*;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 数据库迁移
    bulwark::BulwarkMigration::run_migrations(&db).await?;

    // 2. 准备依赖
    let dao: Arc<dyn BulwarkDao> = /* oxcache + dbnexus 实现 */;
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface);

    // 3. 初始化管理器（必须在所有 API 调用前）
    BulwarkManager::init(dao, config, interface).await?;

    // 4. 启动 web 服务（注册 BulwarkLayer）
    // ...
    Ok(())
}
```

## 安全加固清单

- `cookie_secure = true`（生产强制 HTTPS）
- `cookie_same_site = Lax` 或 `Strict`
- `jwt_secret` 配置非空强密钥（使用 JWT 时）
- Redis 启用密码与 TLS
- 定期轮换 `jwt_secret` 与 API Key
