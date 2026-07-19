//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! HTTP 抓包基础设施——RecordingClient。
//!
//! 包装 `reqwest::Client`，记录每个请求/响应到 JSONL 文件（`logs/e2e_http.jsonl`），
//! 供渗透测试 / 性能分析 / 调试回放使用。
//!
//! # JSONL 行格式
//!
//! ```json
//! {"ts":"2026-...","test_name":"...","method":"POST","url":"...",
//!  "req_headers":{...},"req_body":{...},"status":200,
//!  "resp_headers":{...},"resp_body":{...},"duration_ms":42}
//! ```
//!
//! 写入后立即 flush，确保测试可读取磁盘内容（OnceCell 单例的 BufWriter
//! 不会在程序生命周期内 drop，必须显式 flush）。

use parking_lot::Mutex;
use serial_test::serial;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

/// HTTP 抓包客户端，包装 `reqwest::Client` 并记录每个请求/响应到 JSONL 文件。
pub struct RecordingClient {
    inner: reqwest::Client,
    log_writer: Arc<Mutex<std::io::BufWriter<std::fs::File>>>,
    test_name: Arc<Mutex<String>>,
}

/// 抓包请求构建器，包装 `reqwest::RequestBuilder` 并在 `send()` 时记录请求/响应。
pub struct RecordingRequestBuilder {
    inner: reqwest::RequestBuilder,
    snapshot: RequestSnapshot,
    log_writer: Arc<Mutex<std::io::BufWriter<std::fs::File>>>,
    test_name: Arc<Mutex<String>>,
}

/// 请求快照，记录 method/url/headers/body 供 `send()` 时序列化到 JSONL。
pub struct RequestSnapshot {
    method: String,
    url: String,
    req_headers: serde_json::Value,
    req_body: serde_json::Value,
}

impl RecordingClient {
    /// 构造函数。
    ///
    /// 接受共享的 log_writer（通常来自 `open_http_log()` 单例）和初始 test_name。
    ///
    /// 内部 `reqwest::Client` 复用 `super::default_tenant_headers()` 设置默认
    /// `X-Tenant-Id` header，确保 `tenant-isolation` feature 启用时请求不被
    /// `tenant_resolution_middleware` 以 400 拒绝（与 `make_client()` 行为一致）。
    pub fn new(
        log_writer: Arc<Mutex<std::io::BufWriter<std::fs::File>>>,
        test_name: String,
    ) -> Self {
        let inner = reqwest::Client::builder()
            .default_headers(super::default_tenant_headers())
            .build()
            .expect("构造 reqwest 客户端失败");
        Self {
            inner,
            log_writer,
            test_name: Arc::new(Mutex::new(test_name)),
        }
    }

    /// 设置当前测试名（影响后续 `send()` 记录的 `test_name` 字段）。
    ///
    /// 由于 `test_name` 是 `Arc<Mutex<String>>`，已派发的 `RecordingRequestBuilder`
    /// 在 `send()` 时会读到最新值。
    pub fn set_test_name(&self, name: &str) {
        *self.test_name.lock() = name.to_string();
    }

    /// 构建 POST 请求。
    pub fn post(&self, url: impl AsRef<str>) -> RecordingRequestBuilder {
        let url = url.as_ref().to_string();
        RecordingRequestBuilder {
            inner: self.inner.post(url.as_str()),
            snapshot: RequestSnapshot {
                method: "POST".to_string(),
                url,
                req_headers: serde_json::json!({}),
                req_body: serde_json::Value::Null,
            },
            log_writer: self.log_writer.clone(),
            test_name: self.test_name.clone(),
        }
    }

    /// 构建 GET 请求。
    pub fn get(&self, url: impl AsRef<str>) -> RecordingRequestBuilder {
        let url = url.as_ref().to_string();
        RecordingRequestBuilder {
            inner: self.inner.get(url.as_str()),
            snapshot: RequestSnapshot {
                method: "GET".to_string(),
                url,
                req_headers: serde_json::json!({}),
                req_body: serde_json::Value::Null,
            },
            log_writer: self.log_writer.clone(),
            test_name: self.test_name.clone(),
        }
    }
}

impl RecordingRequestBuilder {
    /// 设置 JSON body，同时记录到 snapshot。
    pub fn json<T: serde::Serialize + ?Sized>(mut self, body: &T) -> Self {
        self.snapshot.req_body = serde_json::to_value(body).unwrap_or(serde_json::Value::Null);
        self.inner = self.inner.json(body);
        self
    }

    /// 设置原始 body（非 JSON），同时记录到 snapshot。
    ///
    /// 用于测试服务端对非 JSON body（空 body / 非 JSON 字符串 / null 字节）
    /// 的拒绝行为。snapshot 中 req_body 以字符串形式存储（无法用 JSON 表达时）。
    pub fn body(mut self, body: impl Into<String>) -> Self {
        let body_str = body.into();
        self.snapshot.req_body = serde_json::Value::String(body_str.clone());
        self.inner = self.inner.body(body_str);
        self
    }

    /// 添加 header，同时记录到 snapshot。
    pub fn header(mut self, key: &str, value: &str) -> Self {
        if let Some(obj) = self.snapshot.req_headers.as_object_mut() {
            obj.insert(
                key.to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
        self.inner = self.inner.header(key, value);
        self
    }

    /// 发送请求并记录请求/响应到 JSONL 文件。
    ///
    /// 记录字段：`ts` / `test_name` / `method` / `url` / `req_headers` / `req_body` /
    /// `status` / `resp_headers` / `resp_body` / `duration_ms`。
    ///
    /// 写入后立即 flush，确保测试可读取磁盘内容。
    /// 重建 `reqwest::Response` 返回（保留原 status/headers/body）。
    pub async fn send(self) -> Result<reqwest::Response, reqwest::Error> {
        let start = Instant::now();
        let method = self.snapshot.method.clone();
        let url = self.snapshot.url.clone();
        let req_headers = self.snapshot.req_headers.clone();
        let req_body = self.snapshot.req_body.clone();
        let test_name = self.test_name.lock().clone();

        let resp = self.inner.send().await?;
        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let resp_body = resp.text().await?;
        let duration_ms = start.elapsed().as_millis();

        // 序列化 JSONL 行
        // T064: ts 使用 to_rfc3339_opts(Millis, true) 显式输出毫秒精度（R-http-logging-001）
        let jsonl = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "test_name": test_name,
            "method": method,
            "url": url,
            "req_headers": req_headers,
            "req_body": req_body,
            "status": status.as_u16(),
            "resp_headers": headers_to_json(&resp_headers),
            "resp_body": parse_body_to_json(&resp_body),
            "duration_ms": duration_ms,
        });

        // 写入并 flush（BufWriter 不会在程序生命周期内 drop，必须显式 flush）
        {
            let mut writer = self.log_writer.lock();
            writeln!(writer, "{}", jsonl).expect("写入 JSONL 失败");
            writer.flush().expect("flush JSONL 失败");
        }

        // 重建 reqwest::Response（保留原 status/headers/body）
        let mut builder = http::Response::builder().status(status);
        for (key, value) in resp_headers.iter() {
            builder = builder.header(key, value);
        }
        let http_resp = builder.body(resp_body).expect("构造 http::Response 失败");
        Ok(http_resp.into())
    }
}

/// 将 `HeaderMap` 转换为 JSON 对象。
fn headers_to_json(headers: &reqwest::header::HeaderMap) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, value) in headers.iter() {
        let key_str = key.as_str().to_string();
        let val_str = value.to_str().unwrap_or("").to_string();
        map.insert(key_str, serde_json::Value::String(val_str));
    }
    serde_json::Value::Object(map)
}

/// 将响应 body 字符串解析为 JSON（失败则包装为 JSON 字符串，空 body 返回 Null）。
fn parse_body_to_json(body: &str) -> serde_json::Value {
    if body.is_empty() {
        return serde_json::Value::Null;
    }
    serde_json::from_str(body).unwrap_or(serde_json::Value::String(body.to_string()))
}

/// 测试 RecordingClient 能正确写入 JSONL 日志。
///
/// 启动 in-process E2E server，用 `make_recording_client("test_recording")` 登录 user1，
/// 断言 `logs/e2e_http.jsonl` 包含一行 JSON 含 `"test_name":"test_recording"` 和 `"status":200`。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_recording_client_writes_jsonl() {
    use super::{make_recording_client, start_e2e_server};

    let (external_url, _internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_recording_client("test_recording");

    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": "user1",
            "params": bulwark::backend::types::LoginParams::default()
        }))
        .send()
        .await
        .expect("登录请求失败");
    assert_eq!(resp.status(), 200, "login 应返回 200");

    // 读取 JSONL 文件验证
    let content = std::fs::read_to_string("logs/e2e_http.jsonl").expect("读取 JSONL 失败");
    assert!(
        content.lines().any(|line| {
            line.contains("\"test_name\":\"test_recording\"") && line.contains("\"status\":200")
        }),
        "JSONL 应包含 test_name=test_recording 且 status=200 的行，实际内容:\n{}",
        content
    );
}
