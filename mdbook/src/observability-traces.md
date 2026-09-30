# OpenTelemetry 分布式追踪（0.3.0 新增）

0.3.0 引入 OpenTelemetry 分布式追踪，通过 OTLP gRPC 导出 span，通过 `otlp` feature 启用。

## Feature 启用

```toml
[dependencies]
garrison = { version = "0.9.0-rc.2", features = ["otlp"] }
```

> 注：当前版本为 pre-release（0.9.0-rc.2），`version = "0.9"` 不会匹配它——Cargo 要求显式写出完整 pre-release 版本号；待 0.9.0 正式发布后可再改为 `"0.9"`。

`otlp` 独立门控以隔离重依赖（opentelemetry / opentelemetry_sdk / opentelemetry-otlp / tracing-subscriber）：

- `opentelemetry` 0.32（`trace` feature）
- `opentelemetry_sdk` 0.32（`trace` + `rt-tokio`）
- `opentelemetry-otlp` 0.32（`trace` + `grpc-tonic`，OTLP gRPC 导出）

## init_otlp_tracing

初始化 OTLP 导出，将 tracer provider 注册到全局：

```rust
use garrison::observability::init_otlp_tracing;

// endpoint 为 OTLP gRPC 接收端（如 Jaeger / Tempo / OTel Collector）
init_otlp_tracing("http://localhost:4317")?;
// init_otlp_tracing 仅注册全局 tracer provider（批量导出，service.name = "garrison"）
// tracing 宏创建的 span 不会自动导出到 OTLP——需业务方自行引入 tracing-opentelemetry 并注册 OpenTelemetryLayer 桥接，或直接用 OTel API（global::tracer）创建 span
```

行为要点：

- 使用 `SpanExporter::builder().with_tonic().with_endpoint(...)` 构造 OTLP gRPC exporter
- `Resource` 标注 `service.name = "garrison"`
- 通过 `SdkTracerProvider::builder().with_batch_exporter(...)` 批量导出
- `opentelemetry::global::set_tracer_provider(provider)` 全局注册

## Span 创建与传播（需业务方桥接）

`init_otlp_tracing` 仅构建并注册全局 tracer provider；garrison 自身不创建任何 OTel span，也未接入 tracing→OTel 桥接。要产出并导出 span，需业务方自行集成：

- 引入 `tracing-opentelemetry` 并将 `OpenTelemetryLayer` 注册到 tracing subscriber，`tracing::info_span!` 等宏创建的 span 才会转换为 OTel span 并导出；「子 span 继承 trace_id 形成调用链」由桥接后的 tracing 语义提供，garrison 不额外保证；
- 跨进程 trace context 注入 / 提取需业务方在 web 中间件层配置 W3C `TraceContextPropagator`（如 `opentelemetry-http`）处理 `traceparent`——`GarrisonRouter` 中间件仅从 HTTP header 提取 token 用于鉴权，不处理追踪头；
- `GarrisonContext` 经 task_local 传播的只有鉴权 token（`CURRENT_TOKEN`），不承载 OTel trace context。

## 与 JSON 日志协同

`otlp` 同时聚合了 `tracing-subscriber`（供 JSON 日志初始化），但 `tracing` span 与 OpenTelemetry span 分属两套系统，`init_otlp_tracing` 仅注册全局 tracer provider，不会把 `tracing` span 桥接到 OTel：

```rust
use garrison::observability::init_otlp_tracing;

tracing_subscriber::fmt().json().try_init().ok();  // JSON 日志
init_otlp_tracing("http://otel-collector:4317")?; // OTLP 追踪
// 未桥接：日志与追踪分属两套上下文，trace_id 不对应
```

需业务方在 subscriber 上引入 tracing-opentelemetry 的 `OpenTelemetryLayer`（如 `tracing_subscriber::registry().with(tracing_opentelemetry::layer())`）后，JSON 日志才携带 `trace_id` / `span_id`，可与追踪按 trace_id 关联。

## GarrisonOtelError

初始化失败返回 `GarrisonOtelError`：

```rust
pub enum GarrisonOtelError {
    Exporter(String),  // OTLP exporter 构造失败
    Provider(String),  // Tracer provider 设置失败
}
```

## 部署建议

- 生产环境部署 OTel Collector 作为接收端，再转发到 Jaeger / Tempo / Zipkin
- endpoint 通常为 `http://otel-collector:4317`（gRPC）或 `http://otel-collector:4318`（HTTP）
- 批量导出适合高吞吐场景；`init_otlp_tracing` 固定使用批量导出，低延迟场景需业务方自行构建 provider（如搭配 `SimpleSpanProcessor`）
- `production` 聚合 feature 默认不含 `otlp`，需显式追加

## 相关章节

- [Prometheus 指标](./observability-metrics.md)
- [结构化 JSON 日志](./observability-logs.md)
