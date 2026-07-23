# 结构化 JSON 日志（0.3.0 新增）

0.3.0 引入基于 `tracing-subscriber` 的结构化 JSON 日志，便于日志聚合系统（ELK / Loki / Datadog）解析。

## Feature 启用

通过 `tracing-log` 或 `metrics-prometheus` feature 启用（后者聚合了 `tracing-subscriber`）：

```toml
[dependencies]
garrison = { version = "0.8", features = ["tracing-log"] }
# 或包含在 production 聚合 feature 中：
# garrison = { version = "0.8", features = ["production"] }
```

- `tracing-log`：启用 `tracing/log` feature，桥接 `log` crate 的日志到 `tracing`
- `metrics-prometheus`：聚合 `tracing-subscriber`（含 `fmt` / `json` / `env-filter` feature）

## JSON 日志初始化

> **v0.7.0 变更**：`init_json_logging()` 已移除，由 inklog（`audit-inklog` feature）作为更强大的替代方案。
> 基础的 `tracing_subscriber` JSON 日志仍然支持，可通过内联调用或 inklog 降级路径使用。

### 方式一：启用 `audit-inklog` feature（推荐）

inklog 提供多输出 / 轮转 / 脱敏 / 健康监控等增强能力，初始化失败时自动降级到 `tracing_subscriber` JSON：

```rust
use garrison::observability::init_inklog_logging_with_fallback;

// 在 async main 早期调用
let logger = init_inklog_logging_with_fallback().await;
if logger.is_degraded() {
    eprintln!("警告：inklog 降级到 tracing-subscriber 默认配置");
}
// logger guard 在 logger 中保持存活，避免日志丢失
```

### 方式二：内联 `tracing_subscriber` JSON 初始化

未启用 `audit-inklog` 时，可内联初始化基础的 JSON 日志（等价于原 `init_json_logging()` 的实现）：

```rust
use tracing_subscriber::EnvFilter;

let filter = EnvFilter::try_from_default_env()
    .unwrap_or_else(|_| EnvFilter::new("info"));
tracing_subscriber::fmt()
    .with_env_filter(filter)
    .json()
    .with_current_span(true)
    .with_span_list(false)
    .try_init()
    .ok(); // 幂等：已初始化时静默跳过
```

行为要点：

- 解析 `RUST_LOG` 环境变量（默认 `info`）
- 输出 JSON 格式日志，包含 `timestamp` / `level` / `target` / `message` / `span` 字段
- **幂等**：`try_init().ok()` 使全局 subscriber 已设置时静默跳过（多次调用安全）
- `with_current_span(true)` + `with_span_list(false)`：附加当前 span 但不输出完整 span 列表

## 日志格式示例

```json
{
  "timestamp": "2026-07-01T12:34:56.789Z",
  "level": "INFO",
  "target": "garrison::stp",
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
  "target": "garrison::core::auth",
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
async fn login(login_id: i64) -> GarrisonResult<String> {
    info!("开始登录流程");
    let token = GarrisonUtil::login(login_id).await?;
    info!(token = %token, "登录成功");
    Ok(token)
}
```

## RUST_LOG 级别控制

通过环境变量控制日志级别：

```bash
RUST_LOG=info              # 全局 info
RUST_LOG=garrison=debug     # garrison 模块 debug，其余 info
RUST_LOG=garrison::core=trace,info  # 细粒度
```

## 与 OpenTelemetry 协同

启用 `observability-otlp` 时，OTLP span 通过全局 tracer provider 导出，JSON 日志与分布式追踪共用同一 span 上下文，便于关联查询。
