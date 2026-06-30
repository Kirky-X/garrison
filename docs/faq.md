# 常见问题

本文件汇总 Bulwark 框架在设计、使用与部署过程中最常被问到的问题。如果你是初次接触 Bulwark，建议先阅读本文件再查阅 API 文档。

> 项目仓库：https://github.com/Kirky-X/bulwark
> 当前版本：0.1.0（2026-06-30 发布）｜下一版本：0.2.0（规划中）

---

## 设计相关

### Q: 为什么选择借鉴 Sa-Token 而非其他框架？

A: Sa-Token 在 Java 生态中已经过长期验证，设计成熟：它将认证授权领域划分为 13 个特性域，边界清晰、职责单一，API 简洁直观。这种模块化划分非常适合移植到 Rust 生态——我们能借鉴其领域建模与 API 设计哲学，同时用 Rust 的类型系统、所有权与 Feature 门控获得零成本抽象。相比 Actix-Web 的 `actix-identity` 或 `axum-login` 这类只解决单一问题的轻量库，Sa-Token 的全场景覆盖更符合 Bulwark 的"一站式认证授权框架"目标。

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
- **与框架设计一致**：`oxcache` 0.3 提供 per-entry TTL 与 layer 抽象，`dbnexus` 0.2 提供多后端统一接口，二者组合正好覆盖 Bulwark 的"内存 + 持久化"两级缓存需求，无需再自行造轮子。

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
- `Uuid` 与 `Random64` 在 0.1.0 即可用，无需额外 feature；
- `Jwt` 风格需要启用 `protocol-jwt` feature，**0.2.0 计划支持**，0.1.0 暂未实现；
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

只需实现 `with_current_token` 这一层 task_local 注入即可，0.3.0 计划提供 `bulwark-actix`、`bulwark-warp` 官方适配 crate。

### Q: 如何自定义权限数据源（如从 RPC 服务、文件、自研权限中心加载）？

A: 实现 `BulwarkInterface` trait 并在 `BulwarkManager::init` 时注入：

```rust
struct MyAuthSource;

#[async_trait]
impl BulwarkInterface for MyAuthSource {
    async fn get_permissions(&self, login_id: &LoginId) -> BulwarkResult<Vec<String>> {
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
bulwark = { version = "0.1", features = ["production"] }
```

`production` 等价于：
- `axum-integration`（axum extractor + Router + Interceptor）
- `cache-redis`（Redis 缓存后端）
- `db-sqlite`（SQLite 持久化，0.2.0 计划）
- `listener`（事件监听器，用于审计、日志）
- `metrics-prometheus`（Prometheus 指标导出）

如需 JWT、OAuth2 等协议层特性，在 0.2.0 发布后单独追加：
```toml
features = ["production", "protocol-jwt", "protocol-oauth2"]
```

注意：`default` feature 默认只包含 `core` 与 `axum-integration`，**不**包含 Redis 与 DB，便于在无外部依赖的环境（如 Edge、WASM）中使用。

### Q: 是否支持 PostgreSQL / MySQL？

A: **0.2.0 仅支持 SQLite**，因为 `dbnexus` 0.2 当前只提供 SQLite 后端。PostgreSQL 与 MySQL 后端已列入 0.3.0 路线图，依赖 `dbnexus` 0.3+ 提供这两个后端的统一抽象。

在 0.2.0 期间，如果你需要 PG/MySQL 持久化，有两种过渡方案：
1. **自实现 `BulwarkDao` trait**：直接对接 `sqlx`，工作量约 200 行；
2. **使用 cache-redis 模式**：把会话全部放 Redis，关闭持久化层，仅用 Redis 作为单一存储。该方案适合无状态部署，但跨重启后会话不丢失依赖 Redis AOF。

### Q: 是否支持分布式会话？

A: 支持。通过启用 `cache-redis` feature，并配置 Redis 连接（单机或 Sentinel 均可）：

```rust
config.cache = CacheConfig::Redis {
    url: "redis://:password@10.0.0.1:6379/0".parse()?,
    prefix: "bulwark:".into(),
    ttl_default: Duration::from_secs(3600),
};
```

多端会话、互踢、权限缓存等所有运行期状态都会落到 Redis，多个 Bulwark 实例共享同一 Redis 即可构成分布式会话集群。0.3.0 计划支持 Redis Cluster 与 Redis Sentinel 高可用模式。

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

0.3.0 计划集成 OpenTelemetry，提供分布式追踪能力，便于把 Bulwark 内部耗时计入全链路 trace span。

---

> 本 FAQ 随版本迭代持续更新。如果你有未涵盖的问题，欢迎在 [GitHub Discussions](https://github.com/Kirky-X/bulwark/discussions) 提问。
