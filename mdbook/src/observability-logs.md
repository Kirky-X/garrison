# 结构化 JSON 日志（0.3.0 新增）

0.3.0 引入基于 `tracing-subscriber` 的结构化 JSON 日志，便于日志聚合系统（ELK / Loki / Datadog）解析。

## Feature 启用

通过 `tracing-log` 或 `metrics-prometheus` feature 启用（后者聚合了 `tracing-subscriber`）：

```toml
[dependencies]
bulwark = { version = "0.3", features = ["tracing-log"] }
# 或包含在 production 聚合 feature 中：
# bulwark = { version = "0.3", features = ["production"] }
```

- `tracing-log`：启用 `tracing/log` feature，桥接 `log` crate 的日志到 `tracing`
- `metrics-prometheus`：聚合 `tracing-subscriber`（含 `fmt` / `json` / `env-filter` feature）

## init_json_logging

调用 `init_json_logging()` 初始化全局 subscriber：

```rust
use bulwark::observability::init_json_logging;

init_json_logging(); // 在 main 早期调用
```

行为要点：

- 解析 `RUST_LOG` 环境变量（默认 `info`）
- 输出 JSON 格式日志，包含 `timestamp` / `level` / `target` / `message` / `span` 字段
- **幂等**：若全局 subscriber 已设置，返回 `Ok(())` 不报错（多次调用安全）
- `with_current_span(true)` + `with_span_list(false)`：附加当前 span 但不输出完整 span 列表

## 日志格式示例

```json
{
  "timestamp": "2026-07-01T12:34:56.789Z",
  "level": "INFO",
  "target": "bulwark::stp",
  "fields": {
    "message": "用户登录成功",
    "login_id": 1001
  },
  "span": {
    "name": "login",
    "attributes": {
      "login_id": 1001
    }
  }
}
```

错误日志示例：

```json
{
  "timestamp": "2026-07-01T12:35:01.123Z",
  "level": "ERROR",
  "target": "bulwark::core::auth",
  "fields": {
    "message": "Token 验证失败",
    "error": "expired token"
  }
}
```

## 与 tracing 集成

业务方可直接使用 `tracing` 宏，自动走 JSON 输出：

```rust
use tracing::{info, warn, error, instrument};

#[instrument(fields(login_id = %login_id))]
async fn login(login_id: i64) -> BulwarkResult<String> {
    info!("开始登录流程");
    let token = BulwarkUtil::login(login_id).await?;
    info!(token = %token, "登录成功");
    Ok(token)
}
```

## RUST_LOG 级别控制

通过环境变量控制日志级别：

```bash
RUST_LOG=info              # 全局 info
RUST_LOG=bulwark=debug     # bulwark 模块 debug，其余 info
RUST_LOG=bulwark::core=trace,info  # 细粒度
```

## 与 OpenTelemetry 协同

启用 `observability-otlp` 时，`tracing-opentelemetry` 桥接 span 到 OTLP，JSON 日志与分布式追踪共用同一 span 上下文，便于关联查询。
