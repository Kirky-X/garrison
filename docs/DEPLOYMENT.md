# 部署指南

本文件描述 Garrison 项目的生产环境部署步骤、feature 选择建议、数据库初始化、缓存配置、安全加固与性能调优。

- 仓库：<https://github.com/Kirky-X/garrison>
- License：Apache-2.0
- 作者：Kirky.X
- MSRV：Rust 1.85+

> 配置项说明详见 [configuration.md](./CONFIGURATION.md)；安全加固详见 [SECURITY.md](./SECURITY.md)；常见问题详见 [troubleshooting.md](./TROUBLESHOOTING.md)。

---

## 目录

- [1. 生产环境部署步骤](#1-生产环境部署步骤)
- [2. Feature 选择建议](#2-feature-选择建议)
- [3. 数据库初始化](#3-数据库初始化)
- [4. 缓存配置](#4-缓存配置)
- [5. 安全加固清单](#5-安全加固清单)
- [6. Docker 部署示例](#6-docker-部署示例)
- [7. 性能调优建议](#7-性能调优建议)
- [8. 反向代理配置](#8-反向代理配置)
- [9. 健康检查与监控](#9-健康检查与监控)
- [10. 升级指南](#10-升级指南)

---

## 1. 生产环境部署步骤

Garrison 主要作为库（crate）集成到业务方的 axum / actix-web 服务中；自 v0.7.0 起也提供独立的 `auth_server` 二进制（双端口 axum 服务器，需 `auth-server` feature），可直接部署作为认证服务。下面以「库集成」为主流程，「`auth_server` 直接部署」见 1.3。

### 1.1 标准部署流程

1. **添加依赖**：在业务方 `Cargo.toml` 中添加 Garrison 依赖并选择 feature。
2. **编写初始化代码**：在服务启动时调用 `GarrisonManager::init()`。
3. **执行数据库迁移**：通过 `GarrisonMigration::new(pool).run_all()` 自动建表。
4. **注册路由中间件**：通过 `GarrisonRouter::new(config).build()` 构建 axum Router（自动注入 `GarrisonLayer` middleware）。
5. **构建生产产物**：`cargo build --release --features production`。
6. **部署与配置**：通过环境变量注入配置，启动服务。

### 1.2 启动代码示例

```rust
use garrison::prelude::*;
use garrison::annotation::Annotation;
use garrison::dao::{init_dbnexus, GarrisonMigration};
use garrison::router::GarrisonRouter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 建立数据库连接（dbnexus）
    let db = init_dbnexus("sqlite:///data/garrison.db?mode=rwc").await?;

    // 2. 执行迁移（幂等，首次启动自动建表）
    GarrisonMigration::new(db.clone()).run_all().await?;

    // 3. 准备依赖
    let dao: Arc<dyn GarrisonDao> = /* oxcache / dbnexus 实现 */;
    let config = Arc::new(GarrisonConfig::default_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MyInterface);

    // 4. 初始化 GarrisonManager（同步函数，必须在所有 API 调用前）
    GarrisonManager::init(dao, config.clone(), interface)?;

    // 5. 启动 axum 服务（GarrisonRouter::build 自动应用 GarrisonLayer middleware）
    let app = GarrisonRouter::new(config)
        .route_protected("/health", health, Annotation::Ignore)
        .route_protected("/protected", protected_handler, Annotation::CheckLogin)
        .build();

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

### 1.3 直接部署 `auth_server` 二进制（v0.7.0+）

若不想自建 axum 服务，可直接使用 Garrison 自带的 `auth_server` 二进制（需 `auth-server` feature）：

```bash
# 构建
cargo build --release --features auth-server --bin auth_server

# 启动（双端口 axum 服务器）
GARRISON_INTERNAL_API_KEY=$(openssl rand -base64 32) \
GARRISON_EXTERNAL_PORT=8080 \
GARRISON_INTERNAL_PORT=8081 \
GARRISON_RATE_LIMIT=100 \
./target/release/auth_server
```

- 外网端口（默认 8080）：`/api/v1/auth/login`、`/api/v1/auth/logout`、`/api/v1/auth/refresh`
- 内网端口（默认 8081）：`check-login` / `check-permission` / `check-role` / `get-*` / `kickout` 等（需 `X-API-Key` 头）
- `GARRISON_INTERNAL_API_KEY` 必须配置（fail-closed，未设置时进程退出）

---

## 2. Feature 选择建议

Garrison 提供三种聚合 feature 与自定义 feature 组合：

### 2.1 聚合 Feature 对比

| Feature | 适用场景 | 包含的特性 |
|---------|---------|-----------|
| `production` | 生产环境 | `cache-redis` + `db-postgres` + `web-axum` + `protocol-jwt` + `protocol-sign` + `secure-sign` + `listener` + `tracing-log` + `metrics-prometheus` + `audit-inklog` + `tenant-isolation` + `security-alert` + `device-binding` + `safe-defaults` + `firewall-waf` + `three-tier-cache` + `sms-rate-limit` + `backend-embedded` + `backend-kit` + `auth-server` + `auth-server-sdforge` + `abac` |
| `development` | 开发环境 | `cache-memory` + `db-sqlite` + `web-axum` |
| `all-defaults` | 快速启用默认后端 | `cache-memory` + `db-sqlite` + `web-axum` |
| `full` | 全部特性（开发首选） | 全部特性 |

### 2.2 选择建议

```toml
# 生产环境（推荐）
[dependencies]
garrison = { version = "0.7", features = ["production"] }

# 开发环境
[dependencies]
garrison = { version = "0.7", features = ["development"] }

# 自定义组合（按需启用）
[dependencies]
garrison = {
    version = "0.7",
    default-features = false,
    features = [
        "cache-redis",      # 生产环境使用 Redis
        "db-sqlite",        # SQLite 数据库
        "web-axum",         # axum 适配
        "protocol-jwt",     # JWT 认证
        "secure-totp",      # TOTP 二次验证
        "listener",         # 事件监听
        "tracing-log",      # 日志
    ],
}
```

> **生产环境关键差异**：`production` 使用 `cache-redis`（分布式缓存），`development` 使用 `cache-memory`（进程内缓存，重启即丢失）。

---

## 3. 数据库初始化

### 3.1 自动迁移

Garrison 通过 `dbnexus` 的 auto-migrate 能力提供 `GarrisonMigration` 类型，启动时按 `core → extensions → tenant` 顺序执行迁移：

```rust
use garrison::dao::{init_dbnexus, GarrisonMigration};

// 启动时执行迁移（幂等，已应用的版本会跳过）
let pool = init_dbnexus("sqlite:///data/garrison.db?mode=rwc").await?;
GarrisonMigration::new(pool).run_all().await?;  // 等价于 migrate_core + migrate_extensions + migrate_tenant
// 或仅执行核心表迁移：GarrisonMigration::new(pool).migrate_core().await?;
```

### 3.2 核心表结构

dbnexus 自动创建以下 **9 张核心表**（含 `app_user_ext` 扩展表与 `app_user_device` 设备表）：

| 表名 | 用途 |
|------|------|
| `app_user` | 用户主表（id / username / password_hash / status / tenant_id） |
| `app_auth_method` | 认证方式表（password / oauth / passkey / did，含外部 ID 绑定） |
| `app_role` | 角色表（code / name / tenant_id / is_system） |
| `app_permission` | 权限表（code / resource_type / action，全局唯一） |
| `app_user_role` | 用户-角色关联（多对多，含 scope 与 tenant_id） |
| `app_role_permission` | 角色-权限关联（多对多，含 tenant_id） |
| `app_session` | 会话表（可选 DB 持久化，默认存 oxcache） |
| `app_login_log` | 登录日志（login / logout / refresh / kickout / kicked） |
| `app_user_ext` | 用户扩展字段表（KV 设计，保持核心表稳定） |
| `app_user_device` | 用户设备表（设备指纹 / 信任设备 / 异地登录检测） |

> 首次启动时通过 `migrations/sqlite/core/001_init.sql` 自动创建，后续版本升级时通过 `dbnexus_migrations` 历史表的 schema version 检测增量迁移。

### 3.3 数据库连接配置

通过 `GARRISON_DB_URL` 环境变量配置数据库连接：

```env
# SQLite 文件路径（默认）
GARRISON_DB_URL=sqlite://garrison.db?mode=rwc

# PostgreSQL 连接（需启用 db-postgres feature）
GARRISON_DB_URL=postgres://user:password@localhost:5432/garrison

# MySQL 连接（需启用 db-mysql feature）
GARRISON_DB_URL=mysql://user:password@localhost:3306/garrison
```

> dbnexus 0.4+ 支持 SQLite / PostgreSQL / MySQL 三种后端。注意 db-sqlite 与 db-mysql 不能同时启用（dbnexus 限制）。PostgreSQL 与 MySQL 需分别通过 `db-postgres` / `db-mysql` feature 启用。

---

## 4. 缓存配置

Garrison 通过 `oxcache` 0.3（crates.io）提供两级缓存：

### 4.1 缓存架构

```text
请求 → L1 (oxcache 内存层) → L2 (redis 分布式) → 数据库
```

| 层级 | 实现 | 用途 | 特性 |
|------|------|------|------|
| L1 | oxcache 内存层 | 进程内 LRU 缓存 | 低延迟，进程重启丢失 |
| L2 | redis | 分布式缓存 | 跨实例共享，持久化 |

### 4.2 cache-memory（开发环境）

```toml
[dependencies]
garrison = { version = "0.7", features = ["cache-memory"] }
```

- 使用 oxcache 内存缓存
- 适合单实例开发与测试
- 进程重启后缓存丢失

### 4.3 cache-redis（生产环境）

```toml
[dependencies]
garrison = { version = "0.7", features = ["cache-redis"] }
```

通过 `GARRISON_REDIS_URL` 配置 Redis 连接：

```env
# 本地 Redis
GARRISON_REDIS_URL=redis://127.0.0.1:6379/0

# 带 TLS 与密码的 Redis
GARRISON_REDIS_URL=rediss://:password@redis-host:6379/0
```

> 0.6.0 起，Garrison 支持 `RedisDeploymentMode` 枚举配置四种 Redis 部署模式：Single（单节点）/ Sentinel（哨兵）/ Cluster（集群）/ MasterSlave（主从）。详见 [configuration.md](./CONFIGURATION.md) 的 Redis 部署模式配置章节。
>
> 生产环境**必须使用 `cache-redis`**，确保多实例部署时会话状态共享。详见 [SECURITY.md](./SECURITY.md)。

### 4.4 per-entry TTL

oxcache 0.3 支持 per-entry TTL，Garrison 利用此特性为不同会话设置独立的过期时间：

- Token-Session：按 `timeout` 配置设置 TTL
- Account-Session：按 `active_timeout` 配置设置 TTL

> 已知限制：oxcache 0.3 `Cache<K,V>::update` 无法保留 per-entry TTL（详见 [roadmap.md](./ROADMAP.md)）。

---

## 5. 安全加固清单

生产环境部署前，请逐项检查以下安全配置：

| # | 检查项 | 要求 | 配置方式 |
|---|--------|------|---------|
| 1 | JWT 密钥 | ≥ 32 字节随机字符串 | `GARRISON_JWT_SECRET` 环境变量 |
| 2 | 缓存后端 | 使用 `cache-redis` 而非 `cache-memory` | `features = ["cache-redis"]` |
| 3 | Redis 连接 | 启用 TLS 与密码认证 | `GARRISON_REDIS_URL=rediss://...` |
| 4 | TLS 终止 | 由反向代理终止 HTTPS | Nginx / Caddy / ALB |
| 5 | 密钥管理 | 禁止硬编码 secret 到代码或配置文件 | 使用环境变量或密钥管理服务 |
| 6 | 会话超时 | 合理配置 `timeout` 与 `active_timeout` | `GARRISON_TIMEOUT` / `GARRISON_ACTIVE_TIMEOUT` |
| 7 | 最小权限 | RBAC 仅授予所需最低权限 | 业务层配置 |
| 8 | 审计日志 | 启用 `listener` 与 `tracing-log` | `features = ["listener", "tracing-log"]` |
| 9 | 密钥轮换 | JWT 密钥每 90 天轮换 | 运维流程 |
| 10 | `.env` 安全 | `.env` 已被 `.gitignore` 排除 | 检查 `.gitignore` |

> 详细安全政策详见 [SECURITY.md](./SECURITY.md)。

---

## 6. Docker 部署示例

### 6.1 Dockerfile 模板

使用多阶段构建，最终镜像基于 `debian:bookworm-slim`（约 80MB）：

```dockerfile
# ===== 阶段 1：构建 =====
FROM rust:1.85-slim AS builder

# 安装构建所需系统依赖
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 准备源码
WORKDIR /build
COPY . /build/garrison

WORKDIR /build/garrison

# 生产构建（利用 cargo 特性缓存层）
# 业务方自建二进制时替换 <your-binary>；直接用 Garrison 自带二进制则改为 auth_server
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/garrison/target \
    cargo build --release --features production && \
    cp target/release/<your-binary> /app/server

# ===== 阶段 2：运行 =====
FROM debian:bookworm-slim AS runtime

# 安装运行时最小依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 拷贝构建产物
COPY --from=builder /app/server /usr/local/bin/server

# 创建数据目录（SQLite 文件存放）
RUN mkdir -p /data
WORKDIR /data

# 暴露服务端口
EXPOSE 8080

# 环境变量默认值
ENV RUST_LOG=garrison=info
ENV GARRISON_TIMEOUT=2592000
ENV GARRISON_ACTIVE_TIMEOUT=-1
ENV GARRISON_DB_URL=sqlite:///data/garrison.db?mode=rwc

# 启动
ENTRYPOINT ["/usr/local/bin/server"]
```

### 6.2 构建与运行

```bash
# 构建镜像
docker build -t garrison-app:latest .

# 运行容器
docker run -d \
  --name garrison \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  -e GARRISON_REDIS_URL=redis://redis:6379 \
  -e GARRISON_JWT_SECRET=$(openssl rand -base64 32) \
  garrison-app:latest
```

### 6.3 docker-compose 示例

```yaml
version: '3.8'
services:
  garrison:
    build: .
    ports:
      - "8080:8080"
    environment:
      - GARRISON_REDIS_URL=redis://redis:6379/0
      - GARRISON_JWT_SECRET=${JWT_SECRET}
      - GARRISON_DB_URL=sqlite:///data/garrison.db?mode=rwc
      - RUST_LOG=garrison=info
    volumes:
      - garrison-data:/data
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

volumes:
  garrison-data:
  redis-data:
```

---

## 7. 性能调优建议

### 7.1 Release Profile

`Cargo.toml` 中已针对 release profile 配置以下优化项：

```toml
[profile.release]
opt-level = 3       # 最高优化级别
lto = true            # 链接时优化，消除死代码
codegen-units = 1     # 单编译单元，最大化优化空间
strip = true          # 移除调试符号，减小体积
```

无需额外配置即可获得较优性能与较小体积。

### 7.2 进一步体积优化

```bash
# 查看二进制体积构成
cargo bloat --release --features production

# 使用 musl target 完全静态链接（更小）
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl --features production
```

### 7.3 运行时调优

- **tokio worker 线程数**：默认等于 CPU 核心数，可通过 `TOKIO_WORKER_THREADS` 调整。
- **oxcache 内存层缓存容量**：根据内存与并发量调整 L1 缓存上限。
- **Redis 连接池**：根据并发量调整 Redis 连接池大小。

### 7.4 性能基准

> 性能基准测试将在 v1.0.0 稳定版中提供（详见 [roadmap.md](./ROADMAP.md)）。

---

## 8. 反向代理配置

生产环境建议在 Garrison 服务前部署 Nginx 作为反向代理，承担 HTTPS 终止与负载均衡。

### 8.1 Nginx 示例

```nginx
upstream garrison_backend {
    server 127.0.0.1:8080;
    # 多实例负载均衡
    # server 127.0.0.1:8081;
    # server 127.0.0.1:8082;
}

server {
    listen 443 ssl http2;
    server_name auth.example.com;

    # HTTPS 证书
    ssl_certificate     /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # 代理到 Garrison 服务
    location / {
        proxy_pass http://garrison_backend;

        # 透传关键请求头
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Authorization header 透传（Garrison 依赖此头读取 token）
        proxy_pass_request_headers on;
    }

    # 健康检查端点
    location /health {
        proxy_pass http://garrison_backend/health;
        access_log off;
    }
}

# HTTP 跳转 HTTPS
server {
    listen 80;
    server_name auth.example.com;
    return 301 https://$host$request_uri;
}
```

### 8.2 要点

- **HTTPS 终止**：在 Nginx 层完成 TLS 解密，Garrison 服务接收明文 HTTP
- **Authorization 透传**：必须显式透传 `garrison_token` 请求头，否则 Garrison 无法读取 token
- **X-Forwarded-Proto**：告知 Garrison 原始协议为 HTTPS，用于生成正确的回调 URL

---

## 9. 健康检查与监控

### 9.1 健康检查端点

Garrison 作为库集成时不自带 HTTP 端点。**建议业务方**在集成时实现 `/health` 端点（若使用 `auth_server` 二进制，则自带健康检查端点）：

```rust
use axum::{routing::get, Router};

async fn health() -> &'static str {
    if garrison::GarrisonManager::is_initialized() {
        "ok"
    } else {
        "degraded"
    }
}

let app = Router::new().route("/health", get(health));
```

### 9.2 可观测性

Garrison 提供三层可观测性能力，通过 feature flag 启用：

| Feature | 能力 | 启用方式 |
|---------|------|---------|
| `tracing-log` | 结构化日志 | `features = ["tracing-log"]` |
| `metrics-prometheus` | Prometheus 指标 | `features = ["metrics-prometheus"]` |
| `listener` | 事件监听器 | `features = ["listener"]` |

启用后通过 `RUST_LOG` 控制日志级别：

```bash
RUST_LOG=garrison=info ./your-server
```

---

## 10. 升级指南

### 10.1 0.1.0 → 0.2.0

0.2.0 相对 0.1.0 为**非破坏性变更**，升级步骤：

```bash
# 更新依赖
cargo update

# 重新编译验证
cargo build --release --features production

# 运行测试
cargo test --features full
```

无需修改业务代码，无需数据库迁移。

### 10.2 启用新 feature

如需启用新功能（如 `protocol-jwt`、`secure-totp`），在业务方的 `Cargo.toml` 中添加对应 feature：

```toml
[dependencies]
garrison = { version = "0.7", features = ["production", "protocol-jwt", "secure-totp"] }
```

新增 feature 不会影响现有功能，按需启用即可。

### 10.3 升级检查清单

- [ ] 阅读 `CHANGELOG.md` 中的 Breaking Changes 部分
- [ ] 运行 `cargo update --dry-run` 查看待更新依赖
- [ ] 在 staging 环境运行全量测试
- [ ] 备份数据库文件（SQLite 场景下复制 `.db` 文件）
- [ ] 灰度发布，监控 `RUST_LOG=garrison=warn` 日志
