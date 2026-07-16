# 常见问题

本文件汇总 Bulwark 框架在设计、使用与部署过程中最常被问到的问题。如果你是初次接触 Bulwark，建议先阅读本文件再查阅 API 文档。

> 项目仓库：<https://github.com/Kirky-X/bulwark>
> 当前版本：0.6.0（2026-07-09 发布）｜下一版本：1.0.0（规划中）

---

## 设计相关

### Q: 为什么采用 13 特性域的领域建模？

A: 认证授权领域边界清晰、职责单一才能做到可组合、可裁剪。Bulwark 将认证授权划分为 13 个特性域，每个域边界清晰、API 简洁直观，这种模块化划分非常适合 Rust 生态——用 Rust 的类型系统、所有权与 Feature 门控获得零成本抽象。相比 Actix-Web 的 `actix-identity` 或 `axum-login` 这类只解决单一问题的轻量库，全场景覆盖更符合 Bulwark 的"一站式认证授权框架"目标。

### Q: 为什么使用全局单例 `BulwarkManager` 而非依赖注入？

A: 这是 Bulwark 在工程便利性与架构纯净之间做出的权衡。全局单例允许我们提供 `BulwarkUtil` 这类静态 API，业务代码无需层层传递 `Arc<Manager>` 即可调用 `login`、`checkPermission` 等方法，大幅降低使用心智成本。同时我们保留了 `BulwarkInterface` trait 抽象，配合 `BulwarkManager::reset_for_test()`（仅在 `cfg(test)` 下编译），可以在单元测试中注入 mock 实现而无需引入任何 DI 容器依赖。换言之：**生产用单例取便利，测试用 trait 取可替换**。

### Q: 为什么使用 `inventory` 编译期注册而非运行时反射？

A: Rust 本身没有 Java/C# 那样的运行时反射机制，无法在运行时扫描类型并自动注册。可选方案有 `linkme`（链接期收集）与 `inventory`（编译期分布式切片），二者实现思路相近。Bulwark 选择 `inventory` 是因为它：

- 零运行时开销（无 `OnceLock` 初始化抖动）；
- 跨 crate 注册（插件 crate 只需 `inventory::submit!` 即可被主框架发现）；
- 与 `cargo feature` 门控天然兼容（feature 关闭则对应 submit 宏不编译）。

代价是注册项不能动态卸载，但 Bulwark 的插件（Listener、Plugin、Strategy）本就是启动期装配，运行期不可变，因此编译期注册完全够用。

### Q: 为什么默认使用 `oxcache` + `dbnexus` 而非现有 crate？

A: 现有 crate 各有局限：`moka` 不支持 per-entry TTL，`cached` 抽象层级偏底层，`sqlx` 直接耦合数据库连接池而不抽象后端。Bulwark 需要的是：

- **统一抽象层**：`BulwarkDao` trait 屏蔽底层差异，业务代码只面向 trait；
- **per-entry TTL**：不同 Token / Session 有不同过期时间，必须支持单条级别过期；
- **与框架设计一致**：`oxcache` 0.3.3 提供 per-entry TTL 与 layer 抽象，`dbnexus` 0.3 提供 SQLite / PostgreSQL / MySQL 多后端统一接口，二者组合正好覆盖 Bulwark 的"内存 + 持久化"两级缓存需求，无需再自行造轮子。

### Q: 为什么不直接用 `jsonwebtoken` 而要包装 `JwtHandler`？

A: 直接使用 `jsonwebtoken` 有三个痛点：

1. Claims 结构由用户自定义，框架无法注入标准字段（如 `sub`、`iss`、`bulwark:*` 命名空间字段），导致每次集成都要重复造 claims；
2. 错误类型是 `jsonwebtoken::errors::Error`，与 `BulwarkError` 体系不互通，业务侧需要 `map_err` 转译；
3. 多算法支持、密钥轮换、kid 头部等生产级需求，`jsonwebtoken` 不提供高层 API。

`JwtHandler` 包装层在 `BulwarkJwtClaims` 中预置了框架标准字段，统一错误转换为 `BulwarkError::Jwt`，并提供 `sign`/`verify`/`refresh` 一站式 API。业务侧只需实现 `BulwarkJwtClaimsExt` 即可扩展自定义字段，无需关心底层算法细节。

---

## 使用相关

### Q: 如何切换 Token 风格（uuid / random-64 / jwt）？

A: 在 `BulwarkConfig` 中配置 `token_style` 字段即可：

```rust
let mut config = BulwarkConfig::default();
config.token_style = TokenStyle::Uuid;       // 32 位 UUID
// config.token_style = TokenStyle::Random64; // 64 位随机串
// config.token_style = TokenStyle::Jwt;     // JWT（需启用 protocol-jwt feature）
BulwarkManager::init(config)?;
```

需要注意：

- `Uuid` 与 `Random64` 无需额外 feature；
- `Jwt` 风格需要启用 `protocol-jwt` feature（0.2.0 起已支持）；
- 切换风格后，已签发的旧 Token 仍可正常校验，直至其自然过期。

### Q: 如何实现多端登录互踢？

A: 配置 `is_concurrent = false` 即可。Bulwark 默认允许多端并发登录（如 Web + App 同时在线），当 `is_concurrent` 关闭时，同一账号在新端登录会自动踢掉旧端会话，旧端下次请求会收到 `NotLoginException`。

```rust
config.is_concurrent = false;
config.include_old_token_count = 5; // 可选：保留最近 5 个旧 Token 用于回放检测
```

如需更细粒度控制（如 PC 端互踢但 PC 与 App 共存），可启用 `device-type` feature，按 `device_type` 维度分别配置并发策略。

### Q: 如何在非 axum 框架（如 actix-web、warp、自研 HTTP 框架）中使用？

A: Bulwark 的核心逻辑与 HTTP 框架解耦，axum 集成只是 `BulwarkAxum` crate。在其他框架中：

```rust
use bulwark::task_local_token;

// 1. 在请求中间件中手动设置 task_local
async fn auth_middleware(req: Request, next: Next) -> Response {
    let token = req.headers().get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    task_local_token::scope(token.unwrap_or(""), next.run(req)).await
}

// 2. 在 handler 中直接调用 BulwarkUtil
async fn handler() -> &'static str {
    BulwarkUtil::check_login(); // 自动从 task_local 取当前 Token
    "ok"
}
```

只需实现 `with_current_token` 这一层 task_local 注入即可。Bulwark 已提供 `web-actix`、`web-warp` 官方适配 feature（0.5.0 起完整 Extractor 适配）。

### Q: 如何自定义权限数据源（如从 RPC 服务、文件、自研权限中心加载）？

A: 实现 `BulwarkInterface` trait 并在 `BulwarkManager::init` 时注入：

```rust
struct MyAuthSource;

#[async_trait]
impl BulwarkInterface for MyAuthSource {
    async fn get_permissions(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        // 从你的权限中心 RPC 拉取
        let perms = rpc_client.query_permissions(login_id).await?;
        Ok(perms)
    }
    // 其他方法按需实现
}

BulwarkManager::init_with_interface(BulwarkConfig::default(), Arc::new(MyAuthSource))?;
```

`BulwarkInterface` 提供 Default 实现（返回空集合），你只需覆写关心的方法。该 trait 对所有方法都返回 `BulwarkResult`，便于把外部错误统一收敛进 `BulwarkError`。

### Q: 如何禁用"未登录抛异常"，改为返回 `false` 或自定义错误？

A: 配置 `throw_on_not_login = false`。默认情况下 `BulwarkUtil::check_login` 在未登录时会 `panic` 或返回 `Err`（取决于调用的是 `_` 还是 `_or_false` 变体）；关闭后，所有 check 系列方法在未登录时返回 `false`，便于业务侧用 `if !BulwarkUtil::is_login() { ... }` 的柔和分支。

```rust
config.throw_on_not_login = false;
config.throw_on_not_permission = false; // 同理：无权限时返回 false 而非抛异常
```

如需自定义错误响应体（而非默认 JSON），实现 `BulwarkExceptionTemplate` trait 并注入 `BulwarkManager`。

### Q: 如何在测试中重置全局单例 `BulwarkManager`？

A: 调用 `BulwarkManager::reset_for_test()`。该方法仅在 `cfg(test)` 下编译，会清空内部 `OnceLock` 并重新初始化为默认状态，便于每个测试用例从干净的初始状态开始：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        BulwarkManager::reset_for_test();
        // 重新 init 你的测试 config
        BulwarkManager::init(BulwarkConfig::default_for_test()).unwrap();
    }

    #[test]
    fn test_login() {
        setup();
        // ... 测试逻辑
    }
}
```

切勿在生产代码中调用此方法——它会无条件清空所有在线会话。为防止误用，方法被 `#[cfg(test)]` 门控，release 构建中根本不存在该符号。

---

## 部署相关

### Q: 生产环境应该启用哪些 feature？

A: 推荐使用聚合 feature `production`，它包含以下子特性：

```toml
[dependencies]
bulwark = { version = "0.6", features = ["production"] }
```

`production` 等价于：

- `web-axum`（axum extractor + Router + Interceptor）
- `cache-redis`（Redis 缓存后端）
- `db-postgres`（PostgreSQL 持久化）
- `protocol-jwt`（JWT 签发与验证）
- `protocol-sign`（API 签名 + nonce 防重放）
- `secure-sign`（HMAC 签名工具）
- `listener`（事件监听器，用于审计、日志）
- `tracing-log`（追踪日志）
- `metrics-prometheus`（Prometheus 指标导出）
- `tenant-isolation`（多租户逻辑隔离）

如需 OAuth2、SSO 等其他协议层特性，单独追加：

```toml
features = ["production", "protocol-oauth2", "protocol-sso"]
```

注意：`default = []`（空），仅 `cargo build` 不带 `--features` 时只编译核心模块，便于在无外部依赖的环境（如 Edge、WASM）中使用。

### Q: 是否支持 PostgreSQL / MySQL？

A: **支持。** 0.5.0 起 `dbnexus` 0.3 提供 SQLite / PostgreSQL / MySQL 三种后端统一抽象，通过 `db-sqlite` / `db-postgres` / `db-mysql` feature 选择。`production` 聚合 feature 默认使用 `db-postgres`。

注意：`db-sqlite` 与 `db-mysql` 不能同时启用（dbnexus 编译期 `compile_error!` 约束）。MySQL 后端的集成测试需要 Docker 环境（使用 `testcontainers`）。

### Q: 是否支持分布式会话？

A: 支持。通过启用 `cache-redis` feature，并配置 Redis 连接（单机或 Sentinel 均可）：

```rust
config.cache = CacheConfig::Redis {
    url: "redis://:password@10.0.0.1:6379/0".parse()?,
    prefix: "bulwark:".into(),
    ttl_default: Duration::from_secs(3600),
};
```

多端会话、互踢、权限缓存等所有运行期状态都会落到 Redis，多个 Bulwark 实例共享同一 Redis 即可构成分布式会话集群。0.6.0 起支持四种 Redis 部署模式（`RedisDeploymentMode`：Single / Sentinel / Cluster / MasterSlave），详见 [configuration.md](./CONFIGURATION.md) 的 Redis 部署模式配置章节。

注意：单机 `oxcache` 内存模式无法跨实例共享，仅适合单实例部署或开发环境。

### Q: 如何监控框架运行状态（QPS、延迟、失败率、活跃会话数）？

A: 启用 `listener` 与 `metrics-prometheus` feature：

```rust
config.features |= FeatureFlag::LISTENER | FeatureFlag::METRICS;
BulwarkManager::init(config)?;
```

随后：

- **Listener**：实现 `BulwarkListener` trait，在 `on_login` / `on_logout` / `on_check_permission` 等回调中打日志或上报到 ELK；
- **Prometheus metrics**：框架自动暴露 `/metrics` endpoint（axum 集成下），包含：
  - `bulwark_login_total{result}`
  - `bulwark_permission_check_duration_seconds`
  - `bulwark_active_session_count`
  - `bulwark_token_verify_failures_total{reason}`

0.3.0 起已集成 OpenTelemetry（`observability-otlp` feature），提供分布式追踪能力，便于把 Bulwark 内部耗时计入全链路 trace span。

---

> 本 FAQ 随版本迭代持续更新。如果你有未涵盖的问题，欢迎在 [GitHub Discussions](https://github.com/Kirky-X/bulwark/discussions) 提问。
