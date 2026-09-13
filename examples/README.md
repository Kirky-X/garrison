# Garrison 官方示例集

每个示例 bin 演示 Garrison 的一个特性模块，配套 `tests/<name>.rs` 独立测试
（1:1 对应）。示例为独立 workspace member（`garrison-examples` crate），不发布到 crates.io。

## 运行方式

```bash
# 通用形式：按示例文档声明的 feature 组合启用
cargo run -p garrison-examples --bin <name> --features "<features>"

# 例：README 快速开始
cargo run -p garrison-examples --bin readme_quickstart --features "cache-memory"

# 例：axum 集成
cargo run -p garrison-examples --bin axum_integration --features "cache-memory,web-axum"
```

每个示例文件的头部文档标注了编译 / 运行 / curl 验证命令，请以文件内说明为准。

## 示例清单（65 个 bin）

| 示例 | 主题 |
|---|---|
| `basic_login` / `session_management` / `token_styles` / `token_introspection` | 登录 / 会话 / Token 基础 |
| `password_login` / `jwt_login` / `jwt_modes` | 密码与 JWT 登录模式 |
| `permission_check` / `strategy_registry` / `auth_logic_impl` | 权限决策与策略 |
| `macro_annotations` / `axum_integration` / `context_request` | 注解与 axum 集成 |
| `web_actix_example` / `web_warp_example` / `web_security` / `grpc_interceptor` | 多框架与安全中间件 |
| `manager_lifecycle` / `state_machine` / `dao_operations` / `alone_cache` / `three_tier_cache` / `cache_redis` | 管理器 / 状态机 / 存储与缓存 |
| `jwt` 协议族：`oauth2_flow` / `oauth2_pkce` / `oauth2_server_flow` / `token_introspection` | OAuth2 流程 |
| `sso_flow` / `sso_server` / `oidc_handler` / `scope_handler` / `keycloak_oidc` | SSO / OIDC 联合登录 |
| `httpbasic_login` / `httpdigest_login` / `sign_protocol` / `sign_utils` / `apikey_management` / `apikey_namespace` / `temp_credential` / `invitation_credential` / `json_template` | 协议层（Basic/Digest/签名/API Key/临时凭证/邀请码） |
| `totp_login` / `email_verification` / `sms_rate_limit` / `constant_time_eq` / `secure_module` | 安全模块 |
| `abac_policy` / `account_security` | ABAC / 账号安全引擎 |
| `event_listener` / `custom_plugin` / `observability_setup` / `i18n_usage` / `exception_handling` | 可观测性与扩展 |
| `firewall_defense` / `firewall_advanced` / `strategy_firewall` | 安全防护套件 |
| `credit_metering` / `parameter_query` / `config_loader` / `backend_remote` / `health_check` / `auth_server` / `auth_server_serve` | 基础设施（计量 / 配置 / 远程后端 / 独立服务器） |
| `v0_5_0_demo` | 0.5.0 综合演示 |

## 测试

```bash
# 单个示例测试（feature 按示例声明）
cargo test -p garrison-examples --features cache-memory --test readme_quickstart

# 全特性编译检查
cargo check -p garrison-examples --all-features
```
