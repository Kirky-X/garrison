# OpenTelemetry 分布式追踪（0.3.0 新增）

0.3.0 引入 OpenTelemetry 分布式追踪，通过 OTLP gRPC 导出 span，通过 `observability-otlp` feature 启用。

## Feature 启用

```toml
[dependencies]
bulwark = { version = "0.3", features = ["observability-otlp"] }
```

`observability-otlp` 独立门控以隔离重依赖（opentelemetry / opentelemetry_sdk / opentelemetry-otlp / tracing-subscriber）：

- `opentelemetry` 0.30（`trace` feature）
- `opentelemetry_sdk` 0.30（`trace` + `rt-tokio`）
- `opentelemetry-otlp` 0.30（`trace` + `grpc-tonic`，OTLP gRPC 导出）

## init_otlp_tracing

初始化 OTLP 导出，将 tracer provider 注册到全局：

```rust
use bulwark::observability::init_otlp_tracing;

// endpoint 为 OTLP gRPC 接收端（如 Jaeger / Tempo / OTel Collector）
init_otlp_tracing("http://localhost:4317")?;
// 后续 tracing::info_span!("bulwark.login") 会自动导出到 OTLP endpoint
```

行为要点：

- 使用 `SpanExporter::builder().with_tonic().with_endpoint(...)` 构造 OTLP gRPC exporter
- `Resource` 标注 `service.name = "bulwark"`
- 通过 `SdkTracerProvider::builder().with_batch_exporter(...)` 批量导出
- `opentelemetry::global::set_tracer_provider(provider)` 全局注册

## Trace Context 传播

trace context 经 OpenTelemetry 自身的 `Context` 传播（task_local），通过全局 tracer provider 导出 OTLP span：

- 请求进入时，web 中间件从 HTTP header 提取 `traceparent`（W3C Trace Context）
- 通过 `BulwarkContext` 在异步任务间传播上下文
- `BulwarkUtil::login` 等方法内的 `tracing::Span` 自动关联到当前 trace
- 子 span 继承父 span 的 trace_id，形成完整调用链

## 与 JSON 日志协同

`observability-otlp` 聚合了 `tracing-subscriber`，可与 JSON 日志共用同一 span 上下文：

```rust
use bulwark::observability::init_otlp_tracing;

tracing_subscriber::fmt().json().try_init().ok();  // JSON 日志
init_otlp_tracing("http://otel-collector:4317")?; // OTLP 追踪
// 两者共享 span，日志与追踪可按 trace_id 关联
```

## BulwarkOtelError

初始化失败返回 `BulwarkOtelError`：

```rust
pub enum BulwarkOtelError {
    Exporter(String),  // OTLP exporter 构造失败
    Provider(String),  // Tracer provider 设置失败
}
```

## 部署建议

- 生产环境部署 OTel Collector 作为接收端，再转发到 Jaeger / Tempo / Zipkin
- endpoint 通常为 `http://otel-collector:4317`（gRPC）或 `http://otel-collector:4318`（HTTP）
- 批量导出适合高吞吐场景；低延迟场景可配置简单导出器
- `production` 聚合 feature 默认不含 `observability-otlp`，需显式追加

## 相关章节

- [Prometheus 指标](./observability-metrics.md)
- [结构化 JSON 日志](./observability-logs.md)
