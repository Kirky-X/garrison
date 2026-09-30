# 部署指南

本页介绍 Garrison 生产环境部署的 feature 推荐组合、Redis 配置、SQLite 初始化与环境变量。

> 完整部署细节（Docker、反向代理、性能调优、健康检查、升级指南）详见 [../../docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md)。

## 部署模型

Garrison 本体是库（crate），业务方将其作为依赖集成到 axum / actix-web / warp 服务中。crate 另附三个可选二进制：`auth_server` 与 `garrison-cli` 按 feature 门控（`required-features`，默认不编译），`garrison-healthcheck` 为零 feature 的容器健康检查探针；三者均不参与库集成，仅供本仓库 Docker 交付物与运维场景使用。库集成步骤：

1. 添加依赖并选择 feature
2. 服务启动时调用 `GarrisonManager::builder().dao(dao).config(config).interface(interface).build().await`（async 函数）
3. 调用 `GarrisonMigration::new(pool).run_all()` 自动建表（默认加载 `migrations/sqlite/`；PostgreSQL 改用 `GarrisonMigration::with_base_dir(pool, "migrations/postgres".into()).run_all()` 或 `run_embedded_postgres()`，MySQL 同理指定 `migrations/mysql/`）
4. 注册路由中间件（如 `GarrisonLayer`）
5. `cargo build --release --features production` 构建产物
6. 通过环境变量注入配置，启动服务

## 生产环境 feature 推荐组合

`production` 聚合 feature 已为生产环境调优：

```toml
[dependencies]
garrison = { version = "0.9.0-rc.2", features = ["production"] }
```

`production` 等价于：

```toml
production = [
    "cache-redis", "db-postgres", "web-axum",
    "protocol-jwt", "protocol-sign", "secure-sign",
    "protocol-webauthn", "backchannel-logout", "field-encryption", "mfa-recovery", "account-password-reset",
    "listener", "tracing-log", "metrics-prometheus",
    "audit-inklog",
    "tenant-isolation",
    "security-alert", "session-hijack-detection", "security-extra", "device-binding",
    "core-advanced",
    "firewall-waf",
    "three-tier-cache",
    "sms-rate-limit",
    "backend-embedded", "backend-kit", "auth-server", "auth-server-sdforge", "abac",
    "api-docs",
    # 自研库特性吸收（生产环境）
    "config-yaml", "config-distributed", "config-audit",
    "db-sharding", "db-replica",
    "firewall-gcra", "firewall-tower", "firewall-monitoring", "firewall-parallel",
    "cache-batch", "cache-audit",
]
```

按需追加其他能力：

```toml
features = ["production", "otlp", "grpc", "i18n-icu", "web-actix"]
```

| 场景 | 推荐组合 |
|:---|:---|
| 单实例开发 | `development`（`cache-memory` + `db-sqlite` + `web-axum`） |
| 多实例生产 | `production`（`cache-redis` + `db-postgres` + `auth-server` + `abac` 等） |
| 全量能力评估 | `full`（聚合大多数 feature；数据库仅含 `db-sqlite`，`db-postgres` / `db-mysql` 需按需追加） |
| gRPC 微服务 | `production` + `grpc` |

## Redis 配置（L2 缓存）

多实例部署必须启用 `cache-redis`，否则 Token-Session 跨实例不一致：

```bash
# rate-limit-redis 后端的 Redis 连接（Garrison 自有环境变量）
GARRISON_REDIS_URL=redis://:password@redis-host:6379/0

# TLS + 密码
GARRISON_REDIS_URL=rediss://:password@redis-host:6379/0
```

> oxcache L2 后端的 Redis 连接由 oxcache 自身配置接管，详见 oxcache 0.5 文档；`GARRISON_REDIS_URL` 仅用于 Garrison 内部 `rate-limit-redis` 后端。

要点：

- L1 内存 + L2 redis 跨实例共享
- Token-Session 与 Account-Session 均写入 redis
- TTL 由 `config.timeout` 控制，redis 自动过期
- 生产环境建议 Redis 启用 AOF/RDB 持久化

## SQLite 初始化

`db-sqlite` feature 启用 dbnexus 0.6 的 `auto-migrate`，首次启动自动建表：

```rust
use garrison::dao::{init_dbnexus, GarrisonMigration};

// 1. 初始化连接池
let pool = init_dbnexus("sqlite:///var/lib/garrison/garrison.db").await?;

// 2. 幂等迁移：首次启动建表，后续启动跳过
GarrisonMigration::new(pool).run_all().await?;
```

```bash
# 部署前预创建空库文件（sqlite 视 0 字节文件为空库）
mkdir -p /var/lib/garrison && touch /var/lib/garrison/garrison.db

# Garrison 不从环境变量读取数据库连接，URL 一律由 init_dbnexus 参数显式传入（见上）
# 各后端 URL 格式参考（需启用对应 feature）：
# SQLite:      sqlite:///var/lib/garrison/garrison.db
# PostgreSQL:  postgres://user:password@localhost:5432/garrison
# MySQL:       mysql://user:password@localhost:3306/garrison
```

要点：

- 迁移幂等，可安全重复执行
- 生产环境建议将 db 文件放在持久化卷
- 部署前预创建空库文件（`touch /var/lib/garrison/garrison.db`）；不要在 URL 追加 `?mode=rwc`——部分 sqlx 版本会把 query 并入路径解析导致只读打开（attempt to write a readonly database）
- dbnexus 0.6 已支持 SQLite / PostgreSQL / MySQL 三种后端；大规模或多写场景建议使用 `db-postgres`（`production` 聚合特性默认启用）
- `GarrisonMigration::new()` 默认基目录为 `migrations/sqlite/`；PostgreSQL / MySQL 迁移分别位于 `migrations/postgres/`、`migrations/mysql/`，需经 `with_base_dir` 指定；PostgreSQL 也可使用 `run_embedded_postgres()`（`db-postgres` 默认启用 `embedded-migrations`，编译期嵌入，无需访问 garrison 源码目录）

## 环境变量

通过 `GARRISON_` 前缀环境变量覆盖配置（详见 [配置参考](./configuration.md)）：

```bash
# Token 配置
GARRISON_TOKEN_NAME=garrison_token
GARRISON_TIMEOUT=2592000
GARRISON_TOKEN_STYLE=uuid

# Cookie 安全
GARRISON_COOKIE_SECURE=true
GARRISON_COOKIE_SAME_SITE=Lax

# 协议参数
GARRISON_JWT_ALGORITHM=HS256
GARRISON_SIGN_WINDOW_SECONDS=300
GARRISON_SSO_TICKET_TTL_SECONDS=60

# 日志
RUST_LOG=info,garrison=debug
```

## 启动代码示例

```rust
use garrison::prelude::*;
use garrison::dao::{init_dbnexus, GarrisonMigration};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 数据库迁移（幂等）
    let pool = init_dbnexus("sqlite:///data/garrison.db").await?;
    GarrisonMigration::new(pool).run_all().await?;

    // 2. 准备依赖
    let dao: Arc<dyn GarrisonDao> = /* oxcache + dbnexus 实现 */;
    let config = Arc::new(GarrisonConfig::default_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MyInterface);

    // 3. 初始化管理器（async，必须在所有 GarrisonUtil API 调用前完成）
    GarrisonManager::builder()
    .dao(dao)
    .config(config)
    .interface(interface)
    .build()
    .await?;

    // 4. 启动 web 服务（注册 GarrisonLayer）
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
