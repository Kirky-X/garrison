# Bulwark 配置指南

> Bulwark 配置由 `BulwarkConfig` 统一管理，支持三级配置源合并与 `tokio::sync::watch` 热更新能力。
>
> - 适用版本：0.1.0（核心配置）/ 0.2.0（JWT / 签名 / SSO 等扩展配置）
> - 配置类型：`BulwarkConfig`，实现 `serde::Serialize / Deserialize`
> 架构设计详见 [architecture.md](./ARCHITECTURE.md)；部署配置详见 [deployment.md](./DEPLOYMENT.md)。

---

## 一、配置源优先级

Bulwark 配置按以下优先级合并（**高优先级覆盖低优先级**）：

```text
环境变量 (BULWARK_*)  >  toml 文件 (bulwark.toml)  >  代码默认值 (BulwarkConfig::default_config())
```

| 优先级 | 来源 | 说明 |
|--------|------|------|
| 高 | 环境变量 | 以 `BULWARK_` 前缀 + 字段名大写下划线形式，例如 `BULWARK_TIMEOUT`、`BULWARK_JWT_SECRET` |
| 中 | toml 文件 | 通过 `ConfigLoader::load_from_toml_str()` 解析 toml 字符串 |
| 低 | 代码默认值 | `BulwarkConfig::default_config()` 内联的默认值 |

> 三源合并在 `ConfigLoader::load()` 阶段完成：先加载 toml（空字符串使用代码默认值），再由 `apply_env_overrides()` 应用环境变量覆盖，最后 `validate()` 校验。

---

## 二、完整配置项表

### 2.1 核心配置（0.1.0）

| 字段名 | 类型 | 默认值 | 环境变量 | 说明 |
|--------|------|--------|----------|------|
| `timeout` | `i64` | `2592000` | `BULWARK_TIMEOUT` | 会话超时秒数（默认 30 天，必须 > 0） |
| `active_timeout` | `i64` | `-1` | `BULWARK_ACTIVE_TIMEOUT` | 活跃超时秒数，`-1` 表示跟随 `timeout` |
| `is_share` | `bool` | `true` | `BULWARK_IS_SHARE` | 同账号多端是否共享会话 |
| `is_concurrent` | `bool` | `true` | `BULWARK_IS_CONCURRENT` | 是否允许并发登录 |
| `token_name` | `String` | `"bulwark_token"` | `BULWARK_TOKEN_NAME` | Cookie / Header 中的 token 字段名 |
| `token_style` | `String` | `"uuid"` | `BULWARK_TOKEN_STYLE` | Token 风格，可选 `uuid` / `random_64` / `simple` / `jwt` |
| `is_read_cookie` | `bool` | `true` | `BULWARK_IS_READ_COOKIE` | 是否从 Cookie 读取 Token |
| `is_read_header` | `bool` | `true` | `BULWARK_IS_READ_HEADER` | 是否从 Header 读取 Token |
| `is_write_header` | `bool` | `true` | `BULWARK_IS_WRITE_HEADER` | 是否在登录后写入 Header |
| `throw_on_not_login` | `bool` | `true` | `BULWARK_THROW_ON_NOT_LOGIN` | 未登录时是否抛出异常（`false` 时返回 `false`） |
| `cookie_secure` | `bool` | `true` | `BULWARK_COOKIE_SECURE` | Cookie 是否标记 `Secure`（仅 HTTPS 传输） |
| `cookie_same_site` | `String` | `"Lax"` | `BULWARK_COOKIE_SAME_SITE` | Cookie 的 `SameSite` 策略（`Lax` / `Strict` / `None`） |

### 2.2 扩展配置（0.2.0 新增）

| 字段名 | 类型 | 默认值 | 环境变量 | 说明 |
|--------|------|--------|----------|------|
| `jwt_algorithm` | `String` | `"HS256"` | `BULWARK_JWT_ALGORITHM` | JWT 签名算法，可选 `HS256` / `HS512` 等 |
| `sign_window_seconds` | `i64` | `300` | `BULWARK_SIGN_WINDOW_SECONDS` | API 签名时间窗口（秒），防重放 |
| `sso_ticket_ttl_seconds` | `u64` | `60` | `BULWARK_SSO_TICKET_TTL_SECONDS` | SSO ticket 有效期（秒） |

> 此外，`BULWARK_JWT_SECRET` 环境变量用于配置 JWT 签名密钥（启用 `protocol-jwt` 时必填）。

---

## 三、配置文件示例

### 3.1 `bulwark.toml`

在项目根目录创建 `bulwark.toml`：

```toml
# Bulwark 配置文件
# 详见 docs/CONFIGURATION.md

# === 会话策略 ===
timeout = 2592000            # 会话超时 30 天
active_timeout = -1          # -1 表示跟随 timeout
is_share = true              # 同账号多端共享会话
is_concurrent = true         # 允许并发登录

# === Token 策略 ===
token_name = "bulwark_token"
token_style = "uuid"         # 可选: uuid / random_64 / simple / jwt
is_read_cookie = true
is_read_header = true
is_write_header = true

# === 异常行为 ===
throw_on_not_login = true

# === Cookie 策略 ===
cookie_secure = true
cookie_same_site = "Lax"

# === 0.2.0 扩展（不启用 protocol-* 时可省略）===
# jwt_algorithm = "HS256"
# sign_window_seconds = 300
# sso_ticket_ttl_seconds = 60
```

### 3.2 环境变量完整列表

通过 `.env` 或容器环境注入（生产环境建议使用容器/编排平台的环境注入）：

```env
# === 会话策略 ===
BULWARK_TIMEOUT=2592000
BULWARK_ACTIVE_TIMEOUT=-1
BULWARK_IS_SHARE=true
BULWARK_IS_CONCURRENT=true

# === Token 策略 ===
BULWARK_TOKEN_NAME=bulwark_token
BULWARK_TOKEN_STYLE=uuid
BULWARK_IS_READ_COOKIE=true
BULWARK_IS_READ_HEADER=true
BULWARK_IS_WRITE_HEADER=true
BULWARK_THROW_ON_NOT_LOGIN=true

# === Cookie 策略 ===
BULWARK_COOKIE_SECURE=true
BULWARK_COOKIE_SAME_SITE=Lax

# === 0.2.0 扩展 ===
BULWARK_JWT_SECRET=change-me-in-production
BULWARK_JWT_ALGORITHM=HS256
BULWARK_SIGN_WINDOW_SECONDS=300
BULWARK_SSO_TICKET_TTL_SECONDS=60

# === 数据库与缓存 ===
BULWARK_DB_URL=sqlite://bulwark.db?mode=rwc
BULWARK_REDIS_URL=redis://127.0.0.1:6379/0

# === 日志 ===
RUST_LOG=bulwark=info
```

> 加载顺序提示：`.env` 文件由应用自行选择 `dotenvy` 之类的 crate 加载，Bulwark 只读取进程环境变量；`bulwark.toml` 与环境变量同时存在时，环境变量优先。

---

## 四、热更新机制

Bulwark 通过 `tokio::sync::watch` 通道广播配置变更，订阅方收到通知后响应：

### 4.1 工作流程

```mermaid
graph LR
    A[ConfigLoader::load] --> B[BulwarkConfig 实例]
    B --> C[with_watcher 创建 watch channel]
    C --> D[watch::Sender]
    D --> E[watch::Receiver]
    E --> F[BulwarkManager 订阅]
    F --> G[清空权限缓存 / 重建策略]
```

### 4.2 使用示例

```rust
use bulwark::config::BulwarkConfig;

// 创建带 watcher 的配置实例
let config = BulwarkConfig::default_config();

// 订阅配置变更
let mut rx = config.watch().expect("default_config 应有 watcher");

// 闭包式修改配置并广播（自动校验）
config.update(|c| {
    c.timeout = 3600;
}).unwrap();

// 订阅方接收新配置
let new_config = rx.borrow_and_update();
assert_eq!(new_config.timeout, 3600);
```

### 4.3 热更新语义

| 行为 | 是否影响已存在会话 |
|------|---------------------|
| 修改 `timeout` / `active_timeout` | 否，仅影响后续创建的会话 |
| 修改 `token_style` | 否，已签发 token 不受影响 |
| 修改 `is_share` / `is_concurrent` | 否，仅影响后续登录 |
| 修改 `jwt_algorithm` | 否，已签发 JWT 验签按旧密钥失效后才切换 |

> `update()` 闭包修改后的配置会自动通过 `validate()` 校验，非法值将被拒绝且不广播（no-op）。

---

## 五、配置校验规则

`BulwarkConfig::validate()` 会执行字段校验，非法值抛出 `BulwarkError::Config`：

| 字段 | 校验规则 | 错误信息示例 |
|------|----------|--------------|
| `timeout` | 必须 > 0 | `timeout must be positive` |
| `token_style` | 必须在 `["uuid", "random_64", "simple", "jwt"]` 内 | `unknown token_style: invalid` |
| `cookie_same_site` | 必须在 `["Lax", "Strict", "None"]` 内 | `unknown cookie_same_site: invalid` |

> 环境变量覆盖后也会触发 `validate()`，非法值（如 `BULWARK_TIMEOUT=not-a-number`）会被拒绝并返回 `BulwarkError::Config`。

---

## 六、各 Feature 的配置说明

Bulwark 通过 feature flag 在编译期裁剪，不同 feature 下需要的配置项不同：

| Feature | 默认 | 关联配置项 |
|---------|------|------------|
| `cache-memory` | 关 | 无（使用 moka 进程内缓存） |
| `cache-redis` | 关 | 需配置 `BULWARK_REDIS_URL` |
| `db-sqlite` | 关 | 由 dbnexus 管理 SQLite 路径（`BULWARK_DB_URL`） |
| `web-axum` | 关 | 启用 axum extractor / router |
| `protocol-jwt` | 关 | `jwt_algorithm`（`BULWARK_JWT_SECRET` 必填） |
| `protocol-oauth2` | 关 | 需配套 oauth2 client 配置 |
| `protocol-sso` | 关 | `sso_ticket_ttl_seconds` |
| `protocol-sign` | 关 | `sign_window_seconds` |
| `protocol-apikey` | 关 | 由 ApiKey dao 管理 |
| `protocol-temp` | 关 | 临时 token TTL 由调用方指定 |
| `secure-totp` | 关 | TOTP secret 由用户绑定关系存储 |
| `secure-sign` | 关 | 复用 `sign_window_seconds` |
| `secure-httpbasic` | 关 | 凭据由调用方提供 |
| `secure-httpdigest` | 关 | nonce / opaque 由内部生成 |

### 6.1 启用 JWT + Redis 的组合示例

```toml
[dependencies]
bulwark = {
    version = "0.1",
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
jwt_algorithm = "HS256"
```

与 `.env`：

```env
BULWARK_JWT_SECRET=your-256-bit-secret
BULWARK_REDIS_URL=redis://127.0.0.1:6379/0
```

---

## 七、参考

- 架构设计：[architecture.md](./ARCHITECTURE.md)
- 部署配置：[deployment.md](./DEPLOYMENT.md)
- 开发规范：[development.md](./DEVELOPMENT.md)
- 配置规范：`openspec/specs/config-system/spec.md`
