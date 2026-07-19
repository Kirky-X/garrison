//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 性能基线 E2E 测试——LoadRunner 自实现负载测试工具。
//!
//! 自实现简洁负载生成器（约 100 行），不引入 hyper-loader/wrk 等外部依赖。
//! 通过并发 worker + stop flag 控制测试持续时间，收集 latency 分布计算
//! P50/P95/P99/RPS。性能报告以 JSONL 格式追加到 `logs/perf.jsonl`。
//!
//! # 触发方式
//!
//! 性能测试默认 `#[ignore]`，需要显式 `--ignored` 触发：
//! ```sh
//! cargo test --test e2e --features "full testing" -- --ignored perf_ --test-threads=1
//! ```
//!
//! # 基线
//!
//! - login（external）：P99 < 200ms，RPS >= 1000，error_rate < 0.1%
//! - check-login（internal）：P99 < 50ms，RPS >= 5000
//! - check-permission（internal）：P99 < 50ms，RPS >= 5000
//!
//! # Spec 与环境差异
//!
//! `RemoteContext::spawn_child()` 默认 `BULWARK_RATE_LIMIT=100`，性能测试需要
//! RPS >= 1000/5000，必须提升上限。测试启动前显式 `set_var("BULWARK_RATE_LIMIT",
//! "100000")`，子进程通过 env 继承。`connect_env` 模式下 env 不影响已运行的
//! server（由 CI 环境自行配置），但测试断言可能因 CI 环境配置不达标——
//! spec 已预判此情况："如性能测试因环境（CPU/内存）不达标，记录实际数值
//! 并分析瓶颈，但不阻塞任务完成。"

use super::remote::RemoteContext;
use bulwark::backend::types::LoginParams;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use serde_json::json;
use serial_test::serial;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 性能报告 JSONL 共享单例（OnceCell，append 模式）。
///
/// 首次调用创建 `logs/perf.jsonl` 并以 append 模式打开，后续调用复用
/// 同一 `Arc<Mutex<BufWriter<File>>>`，所有性能测试共享同一文件句柄。
static PERF_LOG: OnceCell<Arc<Mutex<std::io::BufWriter<std::fs::File>>>> = OnceCell::new();

/// 打开 `logs/perf.jsonl` 用于追加性能报告（共享单例，append 模式）。
///
/// 与 `open_http_log()` 不同，本函数使用 append 模式而非 truncate，
/// 允许跨多次 `cargo test --ignored perf_` 调用累积历史报告。
///
/// # 失败处理
/// 创建目录 / 打开文件失败时 panic（规则 12 失败显性化），测试无法继续。
fn open_perf_log() -> Arc<Mutex<std::io::BufWriter<std::fs::File>>> {
    PERF_LOG
        .get_or_init(|| {
            std::fs::create_dir_all("logs").expect("创建 logs/ 目录失败");
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("logs/perf.jsonl")
                .expect("打开 logs/perf.jsonl 失败");
            Arc::new(Mutex::new(std::io::BufWriter::new(file)))
        })
        .clone()
}

/// 追加一条性能报告到 `logs/perf.jsonl`（每行一个 JSON 对象）。
///
/// JSONL 格式：`{"test_name":"...","endpoint":"...","total":N,"errors":N,"rps":N,"p50_ms":N,"p95_ms":N,"p99_ms":N}`
///
/// 写入后立即 flush，确保测试进程结束前数据落盘（OnceCell 单例的 BufWriter
/// 不会在程序生命周期内 drop）。
fn append_perf_report(report: &LoadReport, test_name: &str, endpoint: &str) {
    let entry = json!({
        "test_name": test_name,
        "endpoint": endpoint,
        "total": report.total,
        "errors": report.errors,
        "rps": report.rps,
        "p50_ms": report.p50_ms,
        "p95_ms": report.p95_ms,
        "p99_ms": report.p99_ms,
    });
    let log = open_perf_log();
    let mut writer = log.lock();
    writeln!(writer, "{}", entry).expect("写入 perf.jsonl 失败");
    writer.flush().expect("flush perf.jsonl 失败");
}

/// 配置性能测试环境：设置高 rate_limit（spawn_child 模式下被子进程继承）。
///
/// `RemoteContext::spawn_child()` 默认 `BULWARK_RATE_LIMIT=100`，性能测试需要
/// RPS >= 1000/5000，必须提升上限。设置后子进程通过 env 继承；`connect_env`
/// 模式下 env 不影响已运行的 server（由 CI 环境自行配置）。
///
/// # 线程安全
/// `#[serial]` 保证测试间串行执行，`set_var` 无并发竞争。env 在测试进程
/// 生命周期内持续生效，不影响后续非性能测试（其他测试不依赖 rate_limit）。
fn setup_perf_env() {
    // Rust 2021 edition 中 set_var 是 safe；项目 edition = "2021"（见 Cargo.toml）。
    std::env::set_var("BULWARK_RATE_LIMIT", "100000");
}

/// T031: 自实现负载生成器（约 100 行）。
///
/// 不引入 hyper-loader/wrk 等外部依赖，简洁实现：spawn N 个 worker 并发请求，
/// stop flag 控制持续时间，收集 latency 分布计算 P50/P95/P99/RPS。
///
/// # 字段
/// - `client`：共享 reqwest 客户端（Arc 内部，clone 廉价）
/// - `url`：目标 URL
/// - `method`：HTTP 方法（POST/GET 等）
/// - `body`：可选 JSON body
/// - `headers`：自定义 headers（如 `x-api-key`）
/// - `concurrency`：worker 数量
/// - `duration`：测试持续时间
pub struct LoadRunner {
    client: reqwest::Client,
    url: String,
    method: reqwest::Method,
    body: Option<serde_json::Value>,
    headers: Vec<(String, String)>,
    concurrency: usize,
    duration: Duration,
}

/// T031: 负载测试报告。
///
/// 包含总请求数、错误数、RPS、P50/P95/P99 延迟（毫秒）。
/// 字段全 `pub` 供测试断言与日志序列化使用。
#[derive(Debug)]
pub struct LoadReport {
    pub total: u64,
    pub errors: u64,
    pub rps: u64,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
}

impl LoadRunner {
    /// 构造 LoadRunner。
    ///
    /// # 参数
    /// - `client`：reqwest 客户端（应已配置默认 headers，如 `X-Tenant-Id`）
    /// - `url`：目标 URL（含 scheme + host + port + path）
    /// - `method`：HTTP 方法
    /// - `body`：可选 JSON body（`None` 表示无 body）
    /// - `concurrency`：worker 数量
    /// - `duration`：测试持续时间
    pub fn new(
        client: reqwest::Client,
        url: impl Into<String>,
        method: reqwest::Method,
        body: Option<serde_json::Value>,
        concurrency: usize,
        duration: Duration,
    ) -> Self {
        Self {
            client,
            url: url.into(),
            method,
            body,
            headers: Vec::new(),
            concurrency,
            duration,
        }
    }

    /// 添加自定义 header（如 `x-api-key`），builder pattern。
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }

    /// T032: Worker 循环——发请求记录 latency_ms，错误递增 AtomicU64，总计数递增。
    ///
    /// 单个 worker 独立运行直到 `stop=true`。latency 记录到共享 Vec<u64>，
    /// errors/total 用 AtomicU64 原子递增避免锁竞争。
    ///
    /// # 错误处理（规则 12 失败显性化）
    /// - HTTP 请求错误：errors 递增 1，total 递增 1，不 panic
    /// - HTTP 响应非 2xx：errors 递增 1，total 递增 1，不 panic
    /// - HTTP 响应 2xx：latency 记录到 Vec，total 递增 1
    ///
    /// 上述两种错误情形下 total 都递增（总请求数包含错误），便于计算
    /// error_rate = errors / total。
    async fn worker(
        runner: Arc<LoadRunner>,
        stop: Arc<AtomicBool>,
        latencies: Arc<Mutex<Vec<u64>>>,
        errors: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
    ) {
        while !stop.load(Ordering::Relaxed) {
            let mut req = runner
                .client
                .request(runner.method.clone(), runner.url.as_str());
            for (k, v) in &runner.headers {
                req = req.header(k.as_str(), v.as_str());
            }
            if let Some(b) = &runner.body {
                req = req.json(b);
            }
            let start = Instant::now();
            match req.send().await {
                Ok(resp) => {
                    let latency = start.elapsed().as_millis() as u64;
                    if resp.status().is_success() {
                        latencies.lock().push(latency);
                    } else {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                    total.fetch_add(1, Ordering::Relaxed);
                },
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                    total.fetch_add(1, Ordering::Relaxed);
                },
            }
        }
    }

    /// T033: 运行负载测试——spawn `concurrency` 个 worker，sleep `duration`，停止后计算统计。
    ///
    /// 流程：
    /// 1. 创建 stop flag / latencies Vec / errors / total 共享状态
    /// 2. spawn `concurrency` 个 worker（每个 worker 独立 tokio task）
    /// 3. sleep `duration` 后设 stop=true
    /// 4. await 所有 worker handle（等待 in-flight 请求完成）
    /// 5. sort latencies，计算 P50/P95/P99（nearest rank）+ RPS
    ///
    /// # 百分位算法
    /// 使用 nearest rank 方法：P_k = sorted[(N * k / 100).min(N-1)]
    /// - N=100 → P50=sorted[50], P95=sorted[95], P99=sorted[99]
    /// - N=1 → P50=P95=P99=sorted[0]
    ///
    /// # RPS 计算
    /// `RPS = total / duration_secs`（包含错误请求，反映真实吞吐量）
    pub async fn run(self) -> LoadReport {
        let runner = Arc::new(self);
        let stop = Arc::new(AtomicBool::new(false));
        let latencies: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let errors = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::with_capacity(runner.concurrency);
        for _ in 0..runner.concurrency {
            let handle = tokio::spawn(Self::worker(
                runner.clone(),
                stop.clone(),
                latencies.clone(),
                errors.clone(),
                total.clone(),
            ));
            handles.push(handle);
        }

        tokio::time::sleep(runner.duration).await;
        stop.store(true, Ordering::Relaxed);

        // 等待所有 worker 退出（in-flight 请求完成后退出循环）
        for handle in handles {
            let _ = handle.await;
        }

        let mut latencies_v = latencies.lock();
        latencies_v.sort_unstable();
        let count = latencies_v.len();
        let total_count = total.load(Ordering::Relaxed);
        let errors_count = errors.load(Ordering::Relaxed);
        let duration_secs = runner.duration.as_secs_f64().max(0.001);

        let percentile = |k: usize| -> u64 {
            if count == 0 {
                return 0;
            }
            let idx = (count * k / 100).min(count - 1);
            latencies_v[idx]
        };

        LoadReport {
            total: total_count,
            errors: errors_count,
            rps: (total_count as f64 / duration_secs) as u64,
            p50_ms: percentile(50),
            p95_ms: percentile(95),
            p99_ms: percentile(99),
        }
    }
}

/// T034: login 性能基线——P99 < 200ms，RPS >= 1000，error_rate < 0.1%。
///
/// `RemoteContext::setup()` 启动服务后，对 `/api/v1/auth/login` 发起
/// concurrency=100、duration=10s 的负载测试，断言 P99/RPS/error_rate
/// 满足基线，并将报告追加到 `logs/perf.jsonl`。
///
/// # 基线依据
/// login 涉及 token 生成（含哈希计算）+ DAO 写入，是相对昂贵的操作，
/// 基线 P99 < 200ms / RPS >= 1000（比 check-login 宽松 4x）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore]
async fn perf_login_p99_under_200ms_1000rps() {
    setup_perf_env();
    let ctx = RemoteContext::setup().await;
    let runner = LoadRunner::new(
        ctx.plain_client(),
        format!("{}/api/v1/auth/login", ctx.external_url),
        reqwest::Method::POST,
        Some(json!({
            "login_id": "perf_user",
            "params": LoginParams::default()
        })),
        100,
        Duration::from_secs(10),
    );
    let report = runner.run().await;
    let error_rate = if report.total > 0 {
        report.errors as f64 / report.total as f64
    } else {
        1.0
    };
    println!(
        "perf_login report: {:?}, error_rate={:.4}",
        report, error_rate
    );
    append_perf_report(
        &report,
        "perf_login_p99_under_200ms_1000rps",
        "/api/v1/auth/login",
    );
    assert!(
        report.p99_ms < 200,
        "P99={} 应 < 200ms（login 性能基线）",
        report.p99_ms
    );
    assert!(
        report.rps >= 1000,
        "RPS={} 应 >= 1000（login 性能基线）",
        report.rps
    );
    assert!(
        error_rate < 0.001,
        "error_rate={:.4} 应 < 0.1%（login 性能基线）",
        error_rate
    );
}

/// T035: check-login 性能基线——P99 < 50ms，RPS >= 5000。
///
/// 先 login 获取有效 token，再对 `/api/v1/auth/check-login`（internal 端点）
/// 发起 concurrency=200、duration=10s 的负载测试，断言 P99/RPS 满足基线。
///
/// # 基线依据
/// check-login 仅做 token 查找 + DAO 读取（oxcache 内存层），延迟应 < 50ms，
/// RPS >= 5000（比 login 严格 5x）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore]
async fn perf_check_login_p99_under_50ms_5000rps() {
    setup_perf_env();
    let ctx = RemoteContext::setup().await;
    let client = ctx.plain_client();

    // 先 login 拿一个有效 token（性能测试期间复用同一 token）
    let resp = client
        .post(format!("{}/api/v1/auth/login", ctx.external_url))
        .json(&json!({
            "login_id": "perf_check_login",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .expect("login 失败");
    assert_eq!(resp.status(), 200, "login 应返回 200");
    let body: serde_json::Value = resp.json().await.expect("login 响应非 JSON");
    let token = body["data"]
        .as_str()
        .unwrap_or_else(|| panic!("login 响应 data 字段非字符串: {:?}", body))
        .to_string();

    let runner = LoadRunner::new(
        client,
        format!("{}/api/v1/auth/check-login", ctx.internal_url),
        reqwest::Method::POST,
        Some(json!({ "token": token })),
        200,
        Duration::from_secs(10),
    )
    .with_header("x-api-key", &ctx.api_key);

    let report = runner.run().await;
    let error_rate = if report.total > 0 {
        report.errors as f64 / report.total as f64
    } else {
        1.0
    };
    println!(
        "perf_check_login report: {:?}, error_rate={:.4}",
        report, error_rate
    );
    append_perf_report(
        &report,
        "perf_check_login_p99_under_50ms_5000rps",
        "/api/v1/auth/check-login",
    );
    assert!(
        report.p99_ms < 50,
        "P99={} 应 < 50ms（check-login 性能基线）",
        report.p99_ms
    );
    assert!(
        report.rps >= 5000,
        "RPS={} 应 >= 5000（check-login 性能基线）",
        report.rps
    );
}

/// T036: check-permission 性能基线——P99 < 50ms，RPS >= 5000。
///
/// 先 login 获取有效 token，再对 `/api/v1/auth/check-permission`（internal 端点）
/// body 含 `{"token": ..., "permission": "read"}` 发起 concurrency=200、
/// duration=10s 的负载测试，断言 P99/RPS 满足基线。
///
/// # 基线依据
/// check-permission 与 check-login 走相似代码路径（token 查找 + 权限校验），
/// MockInterface / SimpleInterface 返回空权限列表会返回 `NOT_PERMISSION`
/// 错误码（业务层拒绝，但响应成功 200），不影响 RPS/P99 测量。
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore]
async fn perf_check_permission_p99_under_50ms_5000rps() {
    setup_perf_env();
    let ctx = RemoteContext::setup().await;
    let client = ctx.plain_client();

    // 先 login 拿一个有效 token（性能测试期间复用同一 token）
    let resp = client
        .post(format!("{}/api/v1/auth/login", ctx.external_url))
        .json(&json!({
            "login_id": "perf_check_permission",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .expect("login 失败");
    assert_eq!(resp.status(), 200, "login 应返回 200");
    let body: serde_json::Value = resp.json().await.expect("login 响应非 JSON");
    let token = body["data"]
        .as_str()
        .unwrap_or_else(|| panic!("login 响应 data 字段非字符串: {:?}", body))
        .to_string();

    let runner = LoadRunner::new(
        client,
        format!("{}/api/v1/auth/check-permission", ctx.internal_url),
        reqwest::Method::POST,
        Some(json!({
            "token": token,
            "permission": "read"
        })),
        200,
        Duration::from_secs(10),
    )
    .with_header("x-api-key", &ctx.api_key);

    let report = runner.run().await;
    let error_rate = if report.total > 0 {
        report.errors as f64 / report.total as f64
    } else {
        1.0
    };
    println!(
        "perf_check_permission report: {:?}, error_rate={:.4}",
        report, error_rate
    );
    append_perf_report(
        &report,
        "perf_check_permission_p99_under_50ms_5000rps",
        "/api/v1/auth/check-permission",
    );
    assert!(
        report.p99_ms < 50,
        "P99={} 应 < 50ms（check-permission 性能基线）",
        report.p99_ms
    );
    assert!(
        report.rps >= 5000,
        "RPS={} 应 >= 5000（check-permission 性能基线）",
        report.rps
    );
}
