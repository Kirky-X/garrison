# Bulwark 配置指南

> Bulwark 配置由 `BulwarkConfig` 统一管理，支持代码默认值、toml 文件、环境变量三源合并，并提供 `tokio::sync::watch` 热更新能力。
>
> - 适用版本：0.1.x（核心配置）/ 0.2.0（JWT / 签名 / SSO 等扩展配置）
> - 配置类型：`BulwarkConfig`，实现 `serde::Serialize / Deserialize`

---

## 一、配置源优先级

Bulwark 配置按以下优先级合并（**高优先级覆盖低优先级**）：

```
环境变量 (BULWARK_*)  >  toml 文件 (bulwark.toml)  >  代码默认值 (BulwarkConfig::default())
```

| 优先级 | 来源 | 说明 |
|--------|------|------|
| 高 | 环境变量 | 以 `BULWARK_` 前缀 + 字段名大写下划线形式，例如 `BULWARK_TIMEOUT`、`BULWARK_JWT_SECRET` |
| 中 | toml 文件 | 路径默认 `./bulwark.toml`，可通过 `ConfigLoader::from_path(...)` 指定 |
| 低 | 代码默认值 | `BulwarkConfig::default()` 内联的默认值 |

> 三源合并发生在 `ConfigLoader::load()` 调用阶段，合并后的结果作为 `BulwarkConfig` 最终生效值。

---

## 二、完整配置项表

### 2.1 核心配置（0.1.x）

| 字段名 | 类型 | 默认值 | 环境变量 | 说明 |
|--------|------|--------|----------|------|
| `timeout` | `i64` | `2592000` | `BULWARK_TIMEOUT` | 会话超时秒数（默认 30 天） |
| `active_timeout` | `i64` | `-1` | `BULWARK_ACTIVE_TIMEOUT` | 活跃超时秒数，`-1` 表示不启用 |
| `is_share` | `bool` | `true` | `BULWARK_IS_SHARE` | 同账号多端是否共享会话 |
| `is_concurrent` | `bool` | `true` | `BULWARK_IS_CONCURRENT` | 是否允许并发登录 |
| `token_name` | `String` | `"bulwark-token"` | `BULWARK_TOKEN_NAME` | Cookie / Header 中的 token 字段名 |
| `token_style` | `String` | `"random-64"` | `BULWARK_TOKEN_STYLE` | Token 风格，可选 `uuid` / `random-32` / `random-64` / `random-128` / `tik` |
| `throw_on_not_login` | `bool` | `true` | `BULWARK_THROW_ON_NOT_LOGIN` | 未登录时是否抛出异常（false 时返回 `false`） |

### 2.2 扩展配置（0.2.0）

| 字段名 | 类型 | 默认值 | 环境变量 | 说明 |
|--------|------|--------|----------|------|
| `jwt_secret` | `String` | `""` | `BULWARK_JWT_SECRET` | JWT 签名密钥，启用 `protocol-jwt` 时必填 |
| `jwt_algorithm` | `String` | `"HS256"` | `BULWARK_JWT_ALGORITHM` | JWT 签名算法，可选 `HS256` / `HS384` / `HS512` / `RS256` 等 |
| `sign_window_seconds` | `i64` | `300` | `BULWARK_SIGN_WINDOW_SECONDS` | API 签名时间窗口（秒），防重放 |
| `sso_ticket_ttl_seconds` | `u64` | `60` | `BULWARK_SSO_TICKET_TTL_SECONDS` | SSO ticket 有效期（秒） |

---

## 三、配置文件示例

### 3.1 `bulwark.toml`

在项目根目录创建 `bulwark.toml`：

```toml
# Bulwark 配置文件
# 详见 docs/configuration.md

# === 会话策略 ===
timeout = 2592000            # 会话超时 30 天
active_timeout = -1          # 不启用活跃超时
is_share = true              # 同账号多端共享会话
is_concurrent = true         # 允许并发登录

# === Token 策略 ===
token_name = "bulwark-token"
token_style = "random-64"    # 可选: uuid / random-32 / random-64 / random-128 / tik

# === 异常行为 ===
throw_on_not_login = true

# === 0.2.0 扩展（不启用 protocol-*  时可省略）===
# jwt_secret = "change-me-in-production"
# jwt_algorithm = "HS256"
# sign_window_seconds = 300
# sso_ticket_ttl_seconds = 60
```

### 3.2 `.env` 环境变量示例

通过 `.env` 注入环境变量（生产环境建议使用容器/编排平台的环境注入）：

```env
# === 会话策略 ===
BULWARK_TIMEOUT=2592000
BULWARK_ACTIVE_TIMEOUT=-1
BULWARK_IS_SHARE=true
BULWARK_IS_CONCURRENT=true

# === Token 策略 ===
BULWARK_TOKEN_NAME=bulwark-token
BULWARK_TOKEN_STYLE=random-64
BULWARK_THROW_ON_NOT_LOGIN=true

# === 0.2.0 扩展 ===
BULWARK_JWT_SECRET=change-me-in-production
BULWARK_JWT_ALGORITHM=HS256
BULWARK_SIGN_WINDOW_SECONDS=300
BULWARK_SSO_TICKET_TTL_SECONDS=60
```

> 加载顺序提示：`.env` 文件本身由应用自行选择 `dotenvy` 之类的 crate 加载，Bulwark 只读取进程环境变量；`bulwark.toml` 与环境变量同时存在时，环境变量优先。

---

## 四、热更新机制

Bulwark 0.1.x 通过 `tokio::sync::watch` 通道广播配置变更，订阅方（如 `BulwarkManager`）收到通知后响应：

### 4.1 工作流程

```
ConfigLoader::watch()  ──►  tokio::sync::watch::Sender<BulwarkConfig>
                                       │
                                       ▼
                          BulwarkManager::subscribe()
                                       │
                                       ▼
                  清空权限缓存 / 重建策略 / 通知 listener
```

### 4.2 使用示例

```rust
use bulwark::config::{ConfigLoader, BulwarkConfig};

// 加载配置并取得 watch 句柄
let loader = ConfigLoader::from_path("./bulwark.toml")?;
let config: BulwarkConfig = loader.load()?;
let watch_rx = loader.watch(); // tokio::sync::watch::Receiver<BulwarkConfig>

// BulwarkManager 内部订阅
BulwarkManager::init_with_config(config).await?;
BulwarkManager::subscribe(watch_rx).await?;

// 运行时更新（不追溯已存在的会话）
BulwarkConfig::update("timeout", 3600)?;
```

### 4.3 热更新语义

| 行为 | 是否影响已存在会话 |
|------|---------------------|
| 修改 `timeout` / `active_timeout` | 否，仅影响后续创建的会话 |
| 修改 `token_style` | 否，已签发 token 不受影响 |
| 修改 `is_share` / `is_concurrent` | 否，仅影响后续登录 |
| 修改 `jwt_secret` | 否，已签发 JWT 验签按旧密钥失效后才切换 |

---

## 五、各 Feature 的配置说明

Bulwark 通过 feature flag 在编译期裁剪，不同 feature 下需要的配置项不同：

| Feature | 默认 | 是否必填 | 关联配置项 |
|---------|------|----------|------------|
| `cache-memory` | 开 | - | 无（使用 moka 进程内缓存） |
| `cache-redis` | 关 | - | 需配置 redis 连接（由 oxcache 管理） |
| `db-sqlite` | 开 | - | 由 dbnexus 管理 SQLite 路径 |
| `db-postgres` | 关 | - | 由 dbnexus 0.3+ 管理 PG 连接 |
| `db-mysql` | 关 | - | 由 dbnexus 0.3+ 管理 MySQL 连接 |
| `web-axum` | 开 | - | 启用 axum extractor / router |
| `protocol-jwt` | 关 | 是 | `jwt_secret`（必填）、`jwt_algorithm` |
| `protocol-oauth2` | 关 | 是 | 需配套 oauth2 client 配置 |
| `protocol-sso` | 关 | 是 | `sso_ticket_ttl_seconds` |
| `protocol-sign` | 关 | 是 | `sign_window_seconds` |
| `protocol-apikey` | 关 | - | 由 ApiKey dao 管理 |
| `protocol-temp` | 关 | - | 临时 token TTL 由调用方指定 |
| `secure-totp` | 关 | - | TOTP secret 由用户绑定关系存储 |
| `secure-sign` | 关 | - | 复用 `sign_window_seconds` |
| `secure-httpbasic` | 关 | - | 凭据由调用方提供 |
| `secure-httpdigest` | 关 | - | nonce / opaque 由内部生成 |

### 5.1 默认 feature 组合

```toml
# Cargo.toml
[dependencies]
bulwark = { version = "0.1", default-features = true }
# 等价于 features = ["cache-memory", "db-sqlite", "web-axum"]
```

### 5.2 启用 JWT + Redis 的组合示例

```toml
[dependencies]
bulwark = {
    version = "0.2",
    default-features = false,
    features = [
        "cache-memory",
        "cache-redis",
        "db-sqlite",
        "web-axum",
        "protocol-jwt",
    ],
}
```

并配套 `bulwark.toml`：

```toml
jwt_secret = "your-256-bit-secret"
jwt_algorithm = "HS256"
```

---

## 六、配置校验规则

`ConfigLoader::load()` 阶段会执行字段校验，非法值抛出 `BulwarkError::Config`：

| 字段 | 校验规则 | 错误信息示例 |
|------|----------|--------------|
| `timeout` | 必须 > 0 | `timeout must be positive` |
| `active_timeout` | `-1` 或 > 0 | `active_timeout must be -1 or positive` |
| `token_style` | 必须在枚举内 | `unknown token_style: invalid` |
| `jwt_secret` | 启用 `protocol-jwt` 时非空 | `jwt_secret must not be empty when protocol-jwt enabled` |
| `jwt_algorithm` | 必须在枚举内 | `unknown jwt_algorithm: invalid` |
| `sign_window_seconds` | 必须 > 0 | `sign_window_seconds must be positive` |
| `sso_ticket_ttl_seconds` | 必须 > 0 | `sso_ticket_ttl_seconds must be positive` |

---

## 七、参考

- 架构设计：见 [architecture.md](./architecture.md)
- 配置规范：`openspec/specs/config-system/spec.md`
- 各 feature 的具体能力：`openspec/changes/protocol-secure-v0-2-0/specs/`
