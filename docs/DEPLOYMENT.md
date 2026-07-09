# 部署指南

本文件描述 Bulwark 项目的生产环境部署步骤、feature 选择建议、数据库初始化、缓存配置、安全加固与性能调优。

- 仓库：<https://github.com/Kirky-X/bulwark>
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

Bulwark 是一个库（crate），不直接产出可执行二进制。业务方将 Bulwark 作为依赖集成到自己的 axum / actix-web 服务中。

### 1.1 标准部署流程

1. **添加依赖**：在业务方 `Cargo.toml` 中添加 Bulwark 依赖并选择 feature。
2. **编写初始化代码**：在服务启动时调用 `BulwarkManager::init()`。
3. **执行数据库迁移**：调用 `BulwarkMigration::run_migrations()` 自动建表。
4. **注册路由中间件**：将 `BulwarkLayer` 注册到 axum Router。
5. **构建生产产物**：`cargo build --release --features production`。
6. **部署与配置**：通过环境变量注入配置，启动服务。

### 1.2 启动代码示例

```rust
use bulwark::prelude::*;
use axum::{routing::get, Router};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 建立数据库连接（dbnexus）
    let db = /* dbnexus 连接初始化 */;

    // 2. 执行迁移（幂等，首次启动自动建表）
    bulwark::BulwarkMigration::run_migrations(&db).await?;

    // 3. 准备依赖
    let dao: Arc<dyn BulwarkDao> = /* oxcache / dbnexus 实现 */;
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface);

    // 4. 初始化 BulwarkManager（必须在所有 API 调用前）
    BulwarkManager::init(dao, config, interface).await?;

    // 5. 启动 axum 服务
    let app = Router::new()
        .route("/health", get(health))
        .route("/protected", get(protected_handler))
        .layer(BulwarkLayer::new());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

---

## 2. Feature 选择建议

Bulwark 提供三种聚合 feature 与自定义 feature 组合：

### 2.1 聚合 Feature 对比

| Feature | 适用场景 | 包含的特性 |
|---------|---------|-----------|
| `production` | 生产环境 | `cache-redis` + `db-postgres` + `web-axum` + `protocol-jwt` + `protocol-sign` + `secure-sign` + `listener` + `tracing-log` + `metrics-prometheus` + `tenant-isolation` |
| `development` | 开发环境 | `cache-memory` + `db-sqlite` + `web-axum` |
| `all-defaults` | 快速启用默认后端 | `cache-memory` + `db-sqlite` + `web-axum` |
| `full` | 全部特性（开发首选） | 全部特性 |

### 2.2 选择建议

```toml
# 生产环境（推荐）
[dependencies]
bulwark = { version = "0.6", features = ["production"] }

# 开发环境
[dependencies]
bulwark = { version = "0.6", features = ["development"] }

# 自定义组合（按需启用）
[dependencies]
bulwark = {
    version = "0.6",
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

Bulwark 通过 `dbnexus` 的 auto-migrate 能力提供 `BulwarkMigration::run_migrations` 接口，启动时自动建表：

```rust
// 启动时执行迁移（幂等，已存在的表会跳过）
bulwark::BulwarkMigration::run_migrations(&db).await?;
```

### 3.2 核心表结构

dbnexus 自动创建以下 **8 张核心表**：

| 表名 | 用途 |
|------|------|
| `users` | 用户基础信息 |
| `oauth2_accounts` | OAuth2 第三方账号绑定 |
| `roles` | 角色定义 |
| `permissions` | 权限定义 |
| `user_roles` | 用户-角色关联（多对多） |
| `user_permissions` | 用户-权限关联（多对多，支持授权/撤销标记） |
| `sessions` | 会话存储 |
| `user_ext` | 用户扩展信息（键值对） |

> 首次启动时自动创建，后续版本升级时通过 schema version 检测增量迁移。

### 3.3 数据库连接配置

通过 `BULWARK_DB_URL` 环境变量配置数据库连接：

```env
# SQLite 文件路径（默认）
BULWARK_DB_URL=sqlite://bulwark.db?mode=rwc

# PostgreSQL 连接（需启用 db-postgres feature）
BULWARK_DB_URL=postgres://user:password@localhost:5432/bulwark

# MySQL 连接（需启用 db-mysql feature）
BULWARK_DB_URL=mysql://user:password@localhost:3306/bulwark
```

> dbnexus 0.3+ 支持 SQLite / PostgreSQL / MySQL 三种后端。注意 db-sqlite 与 db-mysql 不能同时启用（dbnexus 限制）。PostgreSQL 与 MySQL 需分别通过 `db-postgres` / `db-mysql` feature 启用。

---

## 4. 缓存配置

Bulwark 通过 `oxcache` 0.3 提供两级缓存：

### 4.1 缓存架构

```text
请求 → L1 (moka 进程内) → L2 (redis 分布式) → 数据库
```

| 层级 | 实现 | 用途 | 特性 |
|------|------|------|------|
| L1 | moka | 进程内 LRU 缓存 | 低延迟，进程重启丢失 |
| L2 | redis | 分布式缓存 | 跨实例共享，持久化 |

### 4.2 cache-memory（开发环境）

```toml
[dependencies]
bulwark = { version = "0.6", features = ["cache-memory"] }
```

- 使用 moka 进程内缓存
- 适合单实例开发与测试
- 进程重启后缓存丢失

### 4.3 cache-redis（生产环境）

```toml
[dependencies]
bulwark = { version = "0.6", features = ["cache-redis"] }
```

通过 `BULWARK_REDIS_URL` 配置 Redis 连接：

```env
# 本地 Redis
BULWARK_REDIS_URL=redis://127.0.0.1:6379/0

# 带 TLS 与密码的 Redis
BULWARK_REDIS_URL=rediss://:password@redis-host:6379/0
```

> 0.6.0 起，Bulwark 支持 `RedisDeploymentMode` 枚举配置四种 Redis 部署模式：Single（单节点）/ Sentinel（哨兵）/ Cluster（集群）/ MasterSlave（主从）。详见 [configuration.md](./CONFIGURATION.md) 的 Redis 部署模式配置章节。
>
> 生产环境**必须使用 `cache-redis`**，确保多实例部署时会话状态共享。详见 [SECURITY.md](./SECURITY.md)。

### 4.4 per-entry TTL

oxcache 0.3 支持 per-entry TTL，Bulwark 利用此特性为不同会话设置独立的过期时间：

- Token-Session：按 `timeout` 配置设置 TTL
- Account-Session：按 `active_timeout` 配置设置 TTL

> 已知限制：oxcache 0.3 `Cache<K,V>::update` 无法保留 per-entry TTL（详见 [roadmap.md](./ROADMAP.md)）。

---

## 5. 安全加固清单

生产环境部署前，请逐项检查以下安全配置：

| # | 检查项 | 要求 | 配置方式 |
|---|--------|------|---------|
| 1 | JWT 密钥 | ≥ 32 字节随机字符串 | `BULWARK_JWT_SECRET` 环境变量 |
| 2 | 缓存后端 | 使用 `cache-redis` 而非 `cache-memory` | `features = ["cache-redis"]` |
| 3 | Redis 连接 | 启用 TLS 与密码认证 | `BULWARK_REDIS_URL=rediss://...` |
| 4 | TLS 终止 | 由反向代理终止 HTTPS | Nginx / Caddy / ALB |
| 5 | 密钥管理 | 禁止硬编码 secret 到代码或配置文件 | 使用环境变量或密钥管理服务 |
| 6 | 会话超时 | 合理配置 `timeout` 与 `active_timeout` | `BULWARK_TIMEOUT` / `BULWARK_ACTIVE_TIMEOUT` |
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
COPY . /build/bulwark

# 若使用本地 oxcache path 依赖，需一并拷贝
# COPY ./oxcache /build/oxcache
# 并修改 Cargo.toml 中 oxcache 的 path 指向 /build/oxcache

WORKDIR /build/bulwark

# 生产构建（利用 cargo 特性缓存层）
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/bulwark/target \
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
ENV RUST_LOG=bulwark=info
ENV BULWARK_TIMEOUT=2592000
ENV BULWARK_ACTIVE_TIMEOUT=-1
ENV BULWARK_DB_URL=sqlite:///data/bulwark.db?mode=rwc

# 启动
ENTRYPOINT ["/usr/local/bin/server"]
```

### 6.2 构建与运行

```bash
# 构建镜像
docker build -t bulwark-app:latest .

# 运行容器
docker run -d \
  --name bulwark \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  -e BULWARK_REDIS_URL=redis://redis:6379 \
  -e BULWARK_JWT_SECRET=$(openssl rand -base64 32) \
  bulwark-app:latest
```

### 6.3 docker-compose 示例

```yaml
version: '3.8'
services:
  bulwark:
    build: .
    ports:
      - "8080:8080"
    environment:
      - BULWARK_REDIS_URL=redis://redis:6379/0
      - BULWARK_JWT_SECRET=${JWT_SECRET}
      - BULWARK_DB_URL=sqlite:///data/bulwark.db?mode=rwc
      - RUST_LOG=bulwark=info
    volumes:
      - bulwark-data:/data
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

volumes:
  bulwark-data:
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
- **moka 缓存容量**：根据内存与并发量调整 L1 缓存上限。
- **Redis 连接池**：根据并发量调整 Redis 连接池大小。

### 7.4 性能基准

> 性能基准测试将在 v1.0.0 稳定版中提供（详见 [roadmap.md](./ROADMAP.md)）。

---

## 8. 反向代理配置

生产环境建议在 Bulwark 服务前部署 Nginx 作为反向代理，承担 HTTPS 终止与负载均衡。

### 8.1 Nginx 示例

```nginx
upstream bulwark_backend {
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

    # 代理到 Bulwark 服务
    location / {
        proxy_pass http://bulwark_backend;

        # 透传关键请求头
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Authorization header 透传（Bulwark 依赖此头读取 token）
        proxy_pass_request_headers on;
    }

    # 健康检查端点
    location /health {
        proxy_pass http://bulwark_backend/health;
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

- **HTTPS 终止**：在 Nginx 层完成 TLS 解密，Bulwark 服务接收明文 HTTP
- **Authorization 透传**：必须显式透传 `bulwark_token` 请求头，否则 Bulwark 无法读取 token
- **X-Forwarded-Proto**：告知 Bulwark 原始协议为 HTTPS，用于生成正确的回调 URL

---

## 9. 健康检查与监控

### 9.1 健康检查端点

Bulwark 是库，不自带 HTTP 端点。**建议业务方**在集成时实现 `/health` 端点：

```rust
use axum::{routing::get, Router};

async fn health() -> &'static str {
    if bulwark::BulwarkManager::is_initialized() {
        "ok"
    } else {
        "degraded"
    }
}

let app = Router::new().route("/health", get(health));
```

### 9.2 可观测性

Bulwark 提供三层可观测性能力，通过 feature flag 启用：

| Feature | 能力 | 启用方式 |
|---------|------|---------|
| `tracing-log` | 结构化日志 | `features = ["tracing-log"]` |
| `metrics-prometheus` | Prometheus 指标 | `features = ["metrics-prometheus"]` |
| `listener` | 事件监听器 | `features = ["listener"]` |

启用后通过 `RUST_LOG` 控制日志级别：

```bash
RUST_LOG=bulwark=info ./your-server
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
bulwark = { version = "0.2", features = ["production", "protocol-jwt", "secure-totp"] }
```

新增 feature 不会影响现有功能，按需启用即可。

### 10.3 升级检查清单

- [ ] 阅读 `CHANGELOG.md` 中的 Breaking Changes 部分
- [ ] 运行 `cargo update --dry-run` 查看待更新依赖
- [ ] 在 staging 环境运行全量测试
- [ ] 备份数据库文件（SQLite 场景下复制 `.db` 文件）
- [ ] 灰度发布，监控 `RUST_LOG=bulwark=warn` 日志
