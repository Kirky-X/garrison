# 部署指南

本页介绍 Bulwark 生产环境部署的 feature 推荐组合、Redis 配置、SQLite 初始化与环境变量。

> 完整部署细节（Docker、反向代理、性能调优、健康检查、升级指南）详见 [../../docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md)。

## 部署模型

Bulwark 是库（crate），不产出二进制。业务方将其作为依赖集成到 axum / actix-web / warp 服务中：

1. 添加依赖并选择 feature
2. 服务启动时调用 `BulwarkManager::init()`（同步函数）
3. 调用 `BulwarkMigration::new(pool).run_all()` 自动建表
4. 注册路由中间件（如 `BulwarkLayer`）
5. `cargo build --release --features production` 构建产物
6. 通过环境变量注入配置，启动服务

## 生产环境 feature 推荐组合

`production` 聚合 feature 已为生产环境调优：

```toml
[dependencies]
bulwark = { version = "0.7", features = ["production"] }
```

`production` 等价于：

```toml
production = [
    "cache-redis", "db-postgres", "web-axum",
    "protocol-jwt", "protocol-sign", "secure-sign",
    "listener", "tracing-log", "metrics-prometheus",
    "audit-inklog", "tenant-isolation",
    "security-alert", "device-binding",
    "safe-defaults", "firewall-waf",
    "three-tier-cache", "sms-rate-limit",
    "backend-embedded", "backend-kit", "auth-server", "auth-server-sdforge", "abac",
]
```

按需追加其他能力：

```toml
features = ["production", "observability-otlp", "grpc", "i18n-icu", "web-actix"]
```

| 场景 | 推荐组合 |
|:---|:---|
| 单实例开发 | `development`（`cache-memory` + `db-sqlite` + `web-axum`） |
| 多实例生产 | `production`（`cache-redis` + `db-postgres` + `auth-server` + `abac` 等） |
| 全量能力评估 | `full`（启用全部 feature） |
| gRPC 微服务 | `production` + `grpc` |

## Redis 配置（L2 缓存）

多实例部署必须启用 `cache-redis`，否则 Token-Session 跨实例不一致：

```bash
# rate-limit-redis 后端的 Redis 连接（Bulwark 自有环境变量）
BULWARK_REDIS_URL=redis://:password@redis-host:6379/0

# TLS + 密码
BULWARK_REDIS_URL=rediss://:password@redis-host:6379/0
```

> oxcache L2 后端的 Redis 连接由 oxcache 自身配置接管，详见 oxcache 0.3 文档；`BULWARK_REDIS_URL` 仅用于 Bulwark 内部 `rate-limit-redis` 后端。

要点：

- L1 内存 + L2 redis 跨实例共享
- Token-Session 与 Account-Session 均写入 redis
- TTL 由 `config.timeout` 控制，redis 自动过期
- 生产环境建议 Redis 启用 AOF/RDB 持久化

## SQLite 初始化

`db-sqlite` feature 启用 dbnexus 0.4 的 `auto-migrate`，首次启动自动建表：

```rust
use bulwark::dao::{init_dbnexus, BulwarkMigration};

// 1. 初始化连接池
let pool = init_dbnexus("sqlite:///var/lib/bulwark/bulwark.db?mode=rwc").await?;

// 2. 幂等迁移：首次启动建表，后续启动跳过
BulwarkMigration::new(pool).run_all().await?;
```

```bash
# 通过 BULWARK_DB_URL 指定数据库连接（dbnexus 0.4 config-env）
BULWARK_DB_URL=sqlite:///var/lib/bulwark/bulwark.db?mode=rwc

# PostgreSQL（需启用 db-postgres feature）
BULWARK_DB_URL=postgres://user:password@localhost:5432/bulwark

# MySQL（需启用 db-mysql feature）
BULWARK_DB_URL=mysql://user:password@localhost:3306/bulwark
```

要点：

- 迁移幂等，可安全重复执行
- 生产环境建议将 db 文件放在持久化卷
- dbnexus 0.4 已支持 SQLite / PostgreSQL / MySQL 三种后端；大规模或多写场景建议使用 `db-postgres`（`production` 聚合特性默认启用）

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
use bulwark::dao::{init_dbnexus, BulwarkMigration};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 数据库迁移（幂等）
    let pool = init_dbnexus("sqlite:///data/bulwark.db?mode=rwc").await?;
    BulwarkMigration::new(pool).run_all().await?;

    // 2. 准备依赖
    let dao: Arc<dyn BulwarkDao> = /* oxcache + dbnexus 实现 */;
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface);

    // 3. 初始化管理器（同步函数，必须在所有 API 调用前）
    BulwarkManager::init(dao, config, interface)?;

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
