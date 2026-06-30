# 部署指南

本文件描述 Bulwark 项目的生产构建、运行环境、Docker 部署、配置管理、反向代理、监控与数据库迁移流程。

- 仓库：<https://github.com/Kirky-X/bulwark>
- License：Apache-2.0
- MSRV：Rust 1.85+

---

## 1. 构建发布版本

### 1.1 编译生产产物

Bulwark 提供 `production` 聚合特性，包含生产推荐的功能组合：

```bash
# 生产构建（启用 production 特性）
cargo build --release --features production
```

产物位置：

```
target/release/libbulwark.so   # 动态库
target/release/libbulwark.rlib # 静态库
```

> Bulwark 是一个库（crate），不直接产出可执行二进制。业务方将 Bulwark 作为依赖集成到自己的 axum / actix-web 服务中，再编译出最终二进制。

### 1.2 体积优化

`Cargo.toml` 中已针对 release profile 配置以下优化项：

```toml
[profile.release]
opt-level = 3
lto = true            # 链接时优化，消除死代码
codegen-units = 1     # 单编译单元，最大化优化空间
strip = true          # 移除调试符号
```

无需额外配置即可获得较小体积。如需进一步压缩，可在业务方项目中使用 `UPX` 压缩最终二进制。

---

## 2. 运行环境要求

### 2.1 操作系统与架构

| 平台 | 支持情况 |
|------|----------|
| Linux x86_64 | 推荐（CI 主要验证平台） |
| Linux aarch64 | 支持 |
| macOS x86_64 / arm64 | 支持（开发环境） |
| Windows | 未正式验证 |

### 2.2 运行时依赖

Bulwark 为纯 Rust 实现，**静态链接**，无需额外运行时依赖：

- 无需 JVM / Node.js / Python 运行时
- 无需 glibc 动态链接（可配合 `x86_64-unknown-linux-musl` target 实现完全静态链接）

### 2.3 可选外部依赖

| 依赖 | 对应 feature | 说明 |
|------|-------------|------|
| Redis | `cache-redis` | L2 缓存后端，需通过 `BULWARK_REDIS_URL` 配置连接串 |
| SQLite 数据库文件 | `db-sqlite` | 自动创建于配置路径（默认 `bulwark.db`），首次启动自动建表 |

---

## 3. Docker 部署示例

以下为多阶段构建的 `Dockerfile` 示例。Bulwark 是库，此处演示业务方集成后的服务镜像构建方式。

```dockerfile
# ===== 阶段 1：构建 =====
FROM rust:1.85-slim AS builder

# 安装构建所需系统依赖
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 准备本地依赖（oxcache 通过 path 引用）
# 若 oxcache 已发布到 crates.io，可跳过此步骤
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

# 安装运行时最小依赖（若使用 musl 静态链接可省略）
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
ENV RUST_LOG=info
ENV BULWARK_TIMEOUT=2592000

# 启动
ENTRYPOINT ["/usr/local/bin/server"]
```

### 3.1 构建与运行

```bash
# 构建镜像
docker build -t bulwark-app:latest .

# 运行容器
docker run -d \
  --name bulwark \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  -e BULWARK_REDIS_URL=redis://redis:6379 \
  bulwark-app:latest
```

---

## 4. 配置管理

Bulwark 支持三种配置方式，按优先级从高到低：

### 4.1 环境变量（推荐，12-factor）

遵循 12-factor 应用规范，优先使用环境变量。常用变量：

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `BULWARK_TIMEOUT` | 会话超时时间（秒） | `2592000`（30 天） |
| `BULWARK_ACTIVE_TIMEOUT` | 活跃超时时间（秒） | `86400`（1 天） |
| `BULWARK_TOKEN_NAME` | Token 请求头名称 | `Authorization` |
| `BULWARK_REDIS_URL` | Redis 连接串（cache-redis） | 无 |
| `BULWARK_DB_URL` | 数据库连接串 | `sqlite:///data/bulwark.db` |
| `RUST_LOG` | 日志级别 | `info` |

### 4.2 TOML 配置文件

通过 `ConfigLoader` 加载 `bulwark.toml`：

```toml
# bulwark.toml
[session]
timeout = 2592000
active_timeout = 86400

[token]
name = "Authorization"
prefix = "Bearer"

[cache]
backend = "redis"          # 或 "memory"
redis_url = "redis://127.0.0.1:6379"

[database]
url = "sqlite:///data/bulwark.db"
```

### 4.3 配置热更新

部分配置项支持通过 `tokio::sync::watch` 通道实现运行时热更新，无需重启服务：

```rust
// 业务方订阅配置变更
let (tx, rx) = tokio::sync::watch::channel(config.clone());

// 热更新 timeout
tx.send_modify(|c| c.session.timeout = new_timeout);
```

> 注意：数据库连接池、Redis 连接等底层资源不支持热更新，需重启生效。

---

## 5. 反向代理配置

生产环境建议在 Bulwark 服务前部署 Nginx 作为反向代理，承担 HTTPS 终止与负载均衡。

### 5.1 Nginx 示例

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

    # 健康检查端点（业务方实现）
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

### 5.2 要点

- **HTTPS 终止**：在 Nginx 层完成 TLS 解密，Bulwark 服务接收明文 HTTP
- **Authorization 透传**：必须显式透传 `Authorization` 请求头，否则 Bulwark 无法读取 token
- **X-Forwarded-Proto**：告知 Bulwark 原始协议为 HTTPS，用于生成正确的回调 URL

---

## 6. 健康检查

Bulwark 是库，不自带 HTTP 端点。**建议业务方**在集成时实现 `/health` 端点：

```rust
use axum::{routing::get, Router};

async fn health() -> &'static str {
    // 检查 BulwarkManager 是否初始化、数据库连接是否正常
    if bulwark::BulwarkManager::is_initialized() {
        "ok"
    } else {
        "degraded"
    }
}

let app = Router::new().route("/health", get(health));
```

---

## 7. 监控

Bulwark 提供三层可观测性能力，通过 feature flag 启用：

### 7.1 日志（tracing-log feature）

基于 `tracing` crate 输出结构化日志：

```toml
# 业务方 Cargo.toml
[dependencies]
bulwark = { version = "0.1", features = ["tracing-log"] }
```

启动时设置日志级别：

```bash
RUST_LOG=bulwark=debug,info ./your-server
```

### 7.2 Prometheus 指标（metrics-prometheus feature）

启用 `metrics-prometheus` feature 后，Bulwark 会注册登录次数、会话数、权限校验次数等指标：

```toml
[dependencies]
bulwark = { version = "0.1", features = ["metrics-prometheus"] }
```

业务方需暴露 `/metrics` 端点供 Prometheus 抓取。

### 7.3 事件监听器（listener feature）

通过 `listener` feature 订阅 Bulwark 内部事件（登录、登出、权限校验、会话创建/销毁等）：

```rust
// 实现监听器并注册
inventory::submit!(ListenerRegistration {
    name: "audit-logger",
    handler: |event: &BulwarkEvent| {
        tracing::info!(?event, "audit log");
    }
});
```

---

## 8. 数据库迁移

### 8.1 自动迁移

Bulwark 通过 `dbnexus` 的 auto-migrate 能力提供 `BulwarkMigration::run_migrations` 接口，启动时自动建表：

```rust
// 启动时执行迁移（幂等，已存在的表会跳过）
bulwark::BulwarkMigration::run_migrations(&db).await?;
```

### 8.2 核心表结构

Bulwark 自动创建以下 8 张核心表：

| 表名 | 用途 |
|------|------|
| `users` | 用户基础信息 |
| `oauth2_accounts` | OAuth2 第三方账号绑定 |
| `roles` | 角色定义 |
| `permissions` | 权限定义 |
| `user_roles` | 用户-角色关联（多对多） |
| `user_permissions` | 用户-权限关联（多对多，支持授权 / 撤销标记） |
| `sessions` | 会话存储 |
| `user_ext` | 用户扩展信息（键值对） |

> 首次启动时自动创建，后续版本升级时通过 schema version 检测增量迁移。

---

## 9. 升级指南

### 9.1 0.1.0 → 0.2.0

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

### 9.2 启用新 feature

如需启用新功能（如 `protocol-jwt`、`secure-totp`），在业务方的 `Cargo.toml` 中添加对应 feature：

```toml
[dependencies]
bulwark = { version = "0.2", features = ["production", "protocol-jwt", "secure-totp"] }
```

新增 feature 不会影响现有功能，按需启用即可。

### 9.3 升级检查清单

- [ ] 阅读 `CHANGELOG.md` 中的 Breaking Changes 部分
- [ ] 运行 `cargo update --dry-run` 查看待更新依赖
- [ ] 在 staging 环境运行全量测试
- [ ] 备份数据库文件（SQLite 场景下复制 `.db` 文件）
- [ ] 灰度发布，监控 `RUST_LOG=bulwark=warn` 日志
