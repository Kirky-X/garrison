# Prometheus 指标（0.3.0 新增）

0.3.0 引入 Prometheus 指标采集，覆盖登录、Token 验证、权限与角色查询，通过 `metrics-prometheus` feature 启用。

## 启用方式

```toml
[dependencies]
garrison = { version = "0.9.0-rc.2", features = ["metrics-prometheus"] }
```

> 注：当前版本为 pre-release（0.9.0-rc.2），`version = "0.9"` 不会匹配它——Cargo 要求显式写出完整 pre-release 版本号；待 0.9.0 正式发布后可再改为 `"0.9"`。

`metrics-prometheus` 启用 `prometheus` + `tracing-subscriber`（聚合了 JSON 日志能力）。

## 指标清单

| 指标名 | 类型 | 标签 | 说明 |
|:---|:---|:---|:---|
| `garrison_login_total` | Counter | `result=success\|failure` | 登录尝试次数 |
| `garrison_token_validation_duration_seconds` | Histogram | - | Token 验证延迟（秒） |
| `garrison_permission_query_total` | Counter | `result=allow\|deny` | 权限查询次数 |
| `garrison_role_query_total` | Counter | `result=allow\|deny` | 角色查询次数 |

Token 验证延迟 Histogram 的桶为 `0.001 / 0.005 / 0.01 / 0.05 / 0.1 / 0.5 / 1.0 / 5.0` 秒。

## GarrisonMetrics

`GarrisonMetrics` 持有上述指标集合，通过 `GarrisonLogicDefault::with_metrics` builder 注入：

```rust
use garrison::observability::GarrisonMetrics;
use std::sync::Arc;

let metrics = Arc::new(GarrisonMetrics::new());
metrics.record_login(true);                                  // 记录登录成功
metrics.observe_token_validation(std::time::Duration::from_millis(5));
metrics.record_permission_query(true);                       // 权限允许
metrics.record_role_query(false);                            // 角色拒绝

// 收集为 Prometheus 文本格式，供 /metrics 端点抓取
let output = metrics.gather();
assert!(output.contains("garrison_login_total"));
```

## 注入与零开销

- 通过 `GarrisonLogicDefault::with_metrics(metrics)` 注入
- 未注入时所有 `*_metrics` 调用为 no-op（`Option::None` 短路），零开销
- 指标在 `login` / `check_permission` / `check_role` 方法内 emit（`login` 同时以起止时刻差观测 `garrison_token_validation_duration_seconds`，覆盖 login 全流程耗时；`check_login` 不 emit 指标）

## 注册到自定义 registry

`new()` 默认注册到 `prometheus::default_registry()`，并以 `OnceLock` 缓存进程级单例——多次调用 `new` 直接返回同一实例，不会报错；仅当默认 registry 已被占用（如与 `register_to(default_registry())` 混用）时，以 `tracing::warn` 记录后返回未注册的本地实例。对同一 registry 重复调用 `register_to` 才会返回 `Err(prometheus::Error::AlreadyReg)`。生产环境建议使用 `register_to` 注册到自定义 registry：

```rust
use garrison::observability::prometheus::Registry;
let registry = Registry::new();
let metrics = GarrisonMetrics::register_to(&registry)?;
```

`metrics-prometheus` feature 会 re-export `prometheus` crate（`garrison::observability::prometheus`），无需在业务方 Cargo.toml 中单独声明该依赖。

## 暴露 /metrics 端点

应用内共享同一份指标实例，可用 `OnceLock` 定义进程级全局量，并在组装 `GarrisonLogicDefault` 时与 `with_metrics` 注入同一实例（未写入前访问 `/metrics` 会 panic）：

```rust
use std::sync::{Arc, OnceLock};
use garrison::observability::GarrisonMetrics;

static GLOBAL_METRICS: OnceLock<Arc<GarrisonMetrics>> = OnceLock::new();
```

组装处（示意，`with_metrics` 按值消费 `Arc`，需先克隆）：

```rust
GLOBAL_METRICS.set(Arc::clone(&metrics)).ok(); // 重复 set 失败可忽略
let logic = GarrisonLogicDefault::with_metrics(metrics);
```

以 axum 为例，将 `gather()` 输出暴露为抓取端点：

```rust
use axum::{routing::get, response::IntoResponse, Router};

async fn metrics_handler() -> impl IntoResponse {
    let metrics = GLOBAL_METRICS.get().unwrap();
    metrics.gather()
}

let app = Router::new().route("/metrics", get(metrics_handler));
```

## 未启用 feature 的兼容性

未启用 `metrics-prometheus` 时，`GarrisonMetrics` 解析为 `()`（type alias），`Option<Arc<GarrisonMetrics>>` 仍可编译，调用方代码无需条件编译。
