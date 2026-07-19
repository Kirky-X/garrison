# 配置参考

Bulwark 通过 `BulwarkConfig` 定义框架运行参数，支持三源合并与热更新。

## 配置源与优先级

优先级（高 → 低）：**环境变量 > toml 文件 > 代码默认值**

1. **代码默认值**：`BulwarkConfig::default_config()` 返回符合 spec 的默认配置
2. **toml 文件**：通过 `BulwarkConfig::load(Some(path))` 加载 toml 文件（基于 confers 0.4）
3. **环境变量**：`BULWARK_` 前缀自动收集并覆盖（`BULWARK_TOKEN_NAME` → `token_name`，`__` 转嵌套路径如 `TENANT_ISOLATION__ENABLED`）

```rust
use bulwark::config::BulwarkConfig;
// 完整加载：toml 文件 → 环境变量覆盖 → 校验
let config = BulwarkConfig::load(Some("config.toml"))?;

// 或仅使用默认值 + 环境变量（不读 toml）
let config = BulwarkConfig::load(None)?;
```

> `BulwarkConfig::load` 内部完成「默认值 → toml → 环境变量」三源合并与 `validate()` 校验，无需手动调用 `apply_env_overrides()`。

## BulwarkConfig 字段说明

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `token_name` | String | `bulwark_token` | Token 名称（HTTP Header / Cookie 字段名） |
| `timeout` | i64 | `2592000`（30 天） | Token 超时秒数（必须 > 0） |
| `active_timeout` | i64 | `-1` | 活动超时检测（-1 表示不启用） |
| `is_read_cookie` | bool | `true` | 是否从 Cookie 读取 Token |
| `is_read_header` | bool | `true` | 是否从 Header 读取 Token |
| `is_write_header` | bool | `true` | 是否在登录后写入 Header |
| `token_style` | String | `uuid` | Token 风格（`uuid` / `random_64` / `simple` / `jwt`） |
| `throw_on_not_login` | bool | `true` | 未登录时是否抛出异常（false 则返回 false） |
| `cookie_secure` | bool | `true` | Cookie 是否标记 `Secure`（仅 HTTPS） |
| `cookie_same_site` | String | `Lax` | Cookie SameSite 策略（`Lax` / `Strict` / `None`） |
| `jwt_algorithm` | String | `HS256` | JWT 签名算法（`HS256` / `HS512`） |
| `jwt_secret` | String | 空 | JWT 签名密钥（使用 JWT 时必须配置非空） |
| `sign_window_seconds` | i64 | `300` | 签名校验时间窗口秒数（防重放） |
| `sso_ticket_ttl_seconds` | u64 | `60` | SSO ticket TTL 秒数 |

## 环境变量覆盖

所有字段均可通过 `BULWARK_<FIELD>` 环境变量覆盖（字段名大写）：

| 环境变量 | 示例 | 说明 |
|----------|------|------|
| `BULWARK_TOKEN_NAME` | `custom_token` | 覆盖 token_name |
| `BULWARK_TIMEOUT` | `3600` | 覆盖 timeout |
| `BULWARK_ACTIVE_TIMEOUT` | `-1` | 覆盖 active_timeout |
| `BULWARK_IS_READ_COOKIE` | `false` | 覆盖布尔字段（仅支持 true/false，大小写不敏感） |
| `BULWARK_IS_READ_HEADER` | `true` | 覆盖 is_read_header |
| `BULWARK_IS_WRITE_HEADER` | `true` | 覆盖 is_write_header |
| `BULWARK_TOKEN_STYLE` | `jwt` | 覆盖 token_style |
| `BULWARK_THROW_ON_NOT_LOGIN` | `false` | 覆盖 throw_on_not_login |
| `BULWARK_COOKIE_SECURE` | `true` | 覆盖 cookie_secure |
| `BULWARK_COOKIE_SAME_SITE` | `Strict` | 覆盖 cookie_same_site |
| `BULWARK_JWT_ALGORITHM` | `HS512` | 覆盖 jwt_algorithm |
| `BULWARK_SIGN_WINDOW_SECONDS` | `600` | 覆盖 sign_window_seconds |
| `BULWARK_SSO_TICKET_TTL_SECONDS` | `120` | 覆盖 sso_ticket_ttl_seconds |

布尔值仅支持 `true` / `false`（大小写不敏感）。整数按 `i64`/`u64` 解析；其他值视为字符串。非法数值或非合法枚举值会返回 `BulwarkError::Config`。

## 配置校验

`validate()` 在加载与热更新时强制校验，失败返回 `BulwarkError::Config`：

- `token_style` 必须是 `uuid` / `random_64` / `simple` / `jwt` 之一（否则 "unknown token_style"）
- `timeout` 必须 > 0（否则 "timeout must be positive"）
- `cookie_same_site` 必须是 `Lax` / `Strict` / `None` 之一
- `token_style = jwt` 时 `jwt_secret` 必须非空
- `remember_me_enabled = true` 时 `remember_me_timeout` 必须 > `timeout`
- `auto_renewal_threshold` 必须为 `-1` 或 `0..=100`
- `is_share = true` 要求 `is_concurrent = true`
- `device_binding_mode` 必须是 `strict` / `loose` / `disabled` 之一
- feature-gated 校验项（如 `three-tier-cache` 下 `l1_cache_ttl_secs > 0`、`sms-rate-limit` 下 `sms_hourly_limit > 0` 等）随对应 feature 启用

## 配置热更新

通过 `tokio::sync::watch` 通道广播变更：

```rust
let config = BulwarkConfig::default_config();
let mut rx = config.watch().expect("watcher 已启用");
config.update(|c| c.timeout = 3600)?;     // 闭包修改 + 校验 + 广播
let new_config = rx.borrow_and_update();
assert_eq!(new_config.timeout, 3600);
```

`update()` 中非法值会被拒绝且不广播；未调用 `with_watcher()` 的实例 `update()` 为 no-op。
