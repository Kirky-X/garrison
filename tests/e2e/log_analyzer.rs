//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! T050/T051: HTTP 交互日志分析器。
//!
//! 逐行读取 `logs/e2e_http.jsonl`（RecordingClient 写入的 JSONL），
//! 聚合统计：总请求数 / 状态码分布 / 平均/P95/P99 延迟 / 失败请求列表
//! / 响应体超 4KB 警告列表，序列化到 `logs/e2e_summary.json`。
//!
//! # JSONL 输入格式
//!
//! 每行一个 JSON 对象，字段：`ts`/`test_name`/`method`/`url`/
//! `req_headers`/`req_body`/`status`/`resp_headers`/`resp_body`/`duration_ms`。
//! 由 `tests/e2e/har_recorder.rs::RecordingRequestBuilder::send` 写入。
//!
//! # 百分位算法
//!
//! 采用 nearest rank（与 `tests/e2e/perf.rs::LoadRunner::run` 一致）：
//! `P_k = sorted[(N * k / 100).min(N-1)]`。
//!
//! # 规则 25 接口隔离
//!
//! 本文件仅放置：`Summary` / `FailedRequest` / `OversizedResponse` 数据结构、
//! `analyze_http_log` 公共函数、单元测试。无子模块。

use serde::Serialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// 失败请求记录（status >= 400）。
///
/// 字段全 `pub` 供序列化使用，写入 `logs/e2e_summary.json::failed_requests` 数组。
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct FailedRequest {
    pub test_name: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub duration_ms: u64,
}

/// 响应体超 4KB 警告记录。
///
/// `resp_body` 序列化后字符长度 > 4096 字节视为 oversized。
/// 字段全 `pub` 供序列化使用。
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct OversizedResponse {
    pub test_name: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub resp_body_bytes: u64,
}

/// HTTP 交互日志统计汇总。
///
/// 序列化到 `logs/e2e_summary.json`，供 `scripts/e2e_analyze.py` 后续聚合使用。
#[derive(Serialize, Debug)]
pub struct Summary {
    /// 总请求数（含失败）。
    pub total: u64,
    /// 状态码分布——key 为状态码字符串（"200"/"401"/"500" 等）。
    pub status_distribution: HashMap<String, u64>,
    /// 平均响应时间（ms），无请求时为 0.0。
    pub avg_latency_ms: f64,
    /// P95 延迟（ms，nearest rank），无请求时为 0。
    pub p95_latency_ms: u64,
    /// P99 延迟（ms，nearest rank），无请求时为 0。
    pub p99_latency_ms: u64,
    /// 失败请求列表（status >= 400），按日志中出现的顺序。
    pub failed_requests: Vec<FailedRequest>,
    /// 响应体 > 4KB 警告列表。
    pub oversized_responses: Vec<OversizedResponse>,
}

impl Default for Summary {
    /// 空 Summary——所有字段为 0/空，供 `analyze_http_log` 在空文件场景返回。
    fn default() -> Self {
        Self {
            total: 0,
            status_distribution: HashMap::new(),
            avg_latency_ms: 0.0,
            p95_latency_ms: 0,
            p99_latency_ms: 0,
            failed_requests: Vec::new(),
            oversized_responses: Vec::new(),
        }
    }
}

/// 阈值常量——响应体超过此字节数视为 oversized 警告。
const OVERSIZE_THRESHOLD: u64 = 4 * 1024;

/// T050: 分析 HTTP 交互日志，输出统计汇总到 JSON 文件。
///
/// 逐行读取 `input` 指向的 JSONL 文件（RecordingClient 写入的格式），
/// 聚合统计后写入 `output`（JSON 格式），返回 `Summary` 供调用方使用。
///
/// # 行解析容错
///
/// - 空行跳过
/// - JSON 解析失败：跳过该行（不阻断分析），`total` 不递增
/// - 缺失字段：使用默认值（`status=0` / `duration_ms=0` / `test_name=""`）
/// - `resp_body` 字段：可能是对象/数组/字符串/Null，统一序列化为字符串后取长度
///
/// # 失败处理（规则 12 失败显性化）
///
/// - `input` 不存在或不可读：返回底层 `io::Error`（不 panic，便于调用方决定）
/// - `output` 写入失败：返回底层 `io::Error`
/// - JSONL 单行解析失败：跳过该行（不视为致命错误，日志可能被外部 truncate）
pub fn analyze_http_log(input: &Path, output: &Path) -> std::io::Result<Summary> {
    let file = std::fs::File::open(input)?;
    let reader = BufReader::new(file);

    let mut latencies: Vec<u64> = Vec::new();
    let mut total_duration_ms: u64 = 0;
    // MEDIUM-4: 内部用 HashMap<u16, u64> 避免每行 to_string() 分配 String，
    // 序列化输出时再转换为 HashMap<String, u64>
    let mut status_distribution: HashMap<u16, u64> = HashMap::new();
    let mut failed_requests: Vec<FailedRequest> = Vec::new();
    let mut oversized_responses: Vec<OversizedResponse> = Vec::new();
    let mut total: u64 = 0;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };

        total += 1;

        let status = v.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
        let duration_ms = v.get("duration_ms").and_then(|d| d.as_u64()).unwrap_or(0);
        let test_name = v
            .get("test_name")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let method = v
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        let url = v
            .get("url")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();

        *status_distribution.entry(status).or_insert(0) += 1;
        latencies.push(duration_ms);
        total_duration_ms += duration_ms;

        if (status as u16) >= 400 {
            failed_requests.push(FailedRequest {
                test_name: test_name.clone(),
                method: method.clone(),
                url: url.clone(),
                status,
                duration_ms,
            });
        }

        // MEDIUM-5: 原始行长度 <= OVERSIZE_THRESHOLD 时，resp_body 一定不超过阈值
        // 跳过 resp_body_size 调用避免 serde_json::to_string 重新序列化开销
        if (trimmed.len() as u64) > OVERSIZE_THRESHOLD {
            let resp_body_bytes = resp_body_size(&v);
            if resp_body_bytes > OVERSIZE_THRESHOLD {
                oversized_responses.push(OversizedResponse {
                    test_name,
                    method,
                    url,
                    status,
                    resp_body_bytes,
                });
            }
        }
    }

    latencies.sort_unstable();
    let count = latencies.len();
    let avg_latency_ms = if count == 0 {
        0.0
    } else {
        total_duration_ms as f64 / count as f64
    };

    let percentile = |k: usize| -> u64 {
        if count == 0 {
            return 0;
        }
        let idx = (count * k / 100).min(count - 1);
        latencies[idx]
    };

    // MEDIUM-4: 输出时将 HashMap<u16, u64> 转换为 HashMap<String, u64>
    let status_distribution_str: HashMap<String, u64> = status_distribution
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

    let summary = Summary {
        total,
        status_distribution: status_distribution_str,
        avg_latency_ms,
        p95_latency_ms: percentile(95),
        p99_latency_ms: percentile(99),
        failed_requests,
        oversized_responses,
    };

    let json = serde_json::to_string_pretty(&summary)
        .map_err(|e| std::io::Error::other(format!("序列化 Summary 失败: {e}")))?;
    let mut out = std::fs::File::create(output)?;
    out.write_all(json.as_bytes())?;
    out.write_all(b"\n")?;

    Ok(summary)
}

/// 计算 `resp_body` 字段的字节数。
///
/// `resp_body` 可能是：
/// - JSON 对象/数组：序列化为紧凑 JSON 字符串后取字节数
/// - 字符串：直接取 UTF-8 字节数
/// - Null/Bool/Number：序列化为 JSON 字符串后取字节数
fn resp_body_size(v: &serde_json::Value) -> u64 {
    match v.get("resp_body") {
        Some(serde_json::Value::String(s)) => s.len() as u64,
        Some(other) => serde_json::to_string(other)
            .map(|s| s.len() as u64)
            .unwrap_or(0),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T051: 空文件输入应返回全 0 的 Summary。
    ///
    /// 创建临时输入文件（空）和临时输出文件路径，
    /// 调用 `analyze_http_log` 后断言所有字段为 0/空。
    #[test]
    fn test_log_analyzer_handles_empty_file() {
        let tmp_in = tempfile::NamedTempFile::new().expect("创建临时输入文件失败");
        let tmp_out = tempfile::NamedTempFile::new().expect("创建临时输出文件失败");
        let out_path = tmp_out.path().to_path_buf();

        let summary = analyze_http_log(tmp_in.path(), &out_path).expect("空文件分析失败");

        assert_eq!(summary.total, 0, "total 应为 0");
        assert!(
            summary.status_distribution.is_empty(),
            "status_distribution 应为空"
        );
        assert_eq!(summary.avg_latency_ms, 0.0, "avg_latency_ms 应为 0.0");
        assert_eq!(summary.p95_latency_ms, 0, "p95 应为 0");
        assert_eq!(summary.p99_latency_ms, 0, "p99 应为 0");
        assert!(summary.failed_requests.is_empty(), "failed_requests 应为空");
        assert!(
            summary.oversized_responses.is_empty(),
            "oversized_responses 应为空"
        );

        // 输出文件应包含空 Summary 的 JSON（{} + 字段全 0/空）
        let content = std::fs::read_to_string(&out_path).expect("读取输出文件失败");
        assert!(
            content.contains("\"total\": 0") || content.contains("\"total\":0"),
            "输出文件应包含 total=0，实际: {}",
            content
        );
    }

    /// T051: 3 行 JSONL（200/200/500）应正确聚合统计。
    ///
    /// 构造 3 条 HTTP 交互日志：2 个 status=200 + 1 个 status=500，
    /// 断言 total=3、status_distribution={"200":2,"500":1}、
    /// failed_requests 含 1 个 status=500、avg/p95/p99 计算合理。
    #[test]
    fn test_log_analyzer_aggregates_correctly() {
        let tmp_in = tempfile::NamedTempFile::new().expect("创建临时输入文件失败");
        let tmp_out = tempfile::NamedTempFile::new().expect("创建临时输出文件失败");
        let out_path = tmp_out.path().to_path_buf();

        let line1 = serde_json::json!({
            "ts": "2026-07-19T00:00:00Z",
            "test_name": "test_a",
            "method": "POST",
            "url": "http://127.0.0.1/api/v1/auth/login",
            "req_headers": {},
            "req_body": {"login_id": "u1"},
            "status": 200,
            "resp_headers": {"content-type": "application/json"},
            "resp_body": {"data": "token1"},
            "duration_ms": 10
        });
        let line2 = serde_json::json!({
            "ts": "2026-07-19T00:00:01Z",
            "test_name": "test_b",
            "method": "POST",
            "url": "http://127.0.0.1/api/v1/auth/check-login",
            "req_headers": {},
            "req_body": {"token": "tok"},
            "status": 200,
            "resp_headers": {"content-type": "application/json"},
            "resp_body": {"data": true},
            "duration_ms": 20
        });
        let line3 = serde_json::json!({
            "ts": "2026-07-19T00:00:02Z",
            "test_name": "test_c",
            "method": "POST",
            "url": "http://127.0.0.1/api/v1/auth/login",
            "req_headers": {},
            "req_body": {"login_id": "' OR '1'='1"},
            "status": 500,
            "resp_headers": {"content-type": "application/json"},
            "resp_body": {"error_code": "INTERNAL", "message": "boom"},
            "duration_ms": 30
        });

        let mut content = String::new();
        content.push_str(&line1.to_string());
        content.push('\n');
        content.push_str(&line2.to_string());
        content.push('\n');
        content.push_str(&line3.to_string());
        content.push('\n');
        std::fs::write(tmp_in.path(), &content).expect("写入临时输入文件失败");

        let summary = analyze_http_log(tmp_in.path(), &out_path).expect("3 行日志分析失败");

        assert_eq!(summary.total, 3, "total 应为 3");
        assert_eq!(
            summary.status_distribution.get("200"),
            Some(&2),
            "status_distribution[200] 应为 2，实际: {:?}",
            summary.status_distribution
        );
        assert_eq!(
            summary.status_distribution.get("500"),
            Some(&1),
            "status_distribution[500] 应为 1，实际: {:?}",
            summary.status_distribution
        );

        // latencies = [10, 20, 30] sorted, avg = 60/3 = 20.0
        assert_eq!(
            summary.avg_latency_ms, 20.0,
            "avg_latency_ms 应为 20.0，实际: {}",
            summary.avg_latency_ms
        );

        // P95 nearest rank: idx = (3*95/100).min(2) = 2 → latencies[2] = 30
        assert_eq!(summary.p95_latency_ms, 30, "p95 应为 30");
        // P99 nearest rank: idx = (3*99/100).min(2) = 2 → latencies[2] = 30
        assert_eq!(summary.p99_latency_ms, 30, "p99 应为 30");

        // 失败请求：仅 status=500 一条
        assert_eq!(
            summary.failed_requests.len(),
            1,
            "failed_requests 应含 1 条，实际: {}",
            summary.failed_requests.len()
        );
        let failed = &summary.failed_requests[0];
        assert_eq!(failed.status, 500, "失败请求 status 应为 500");
        assert_eq!(failed.test_name, "test_c", "失败请求 test_name 应为 test_c");
        assert_eq!(failed.duration_ms, 30, "失败请求 duration_ms 应为 30");

        // 所有响应体都 < 4KB，无 oversized 警告
        assert!(
            summary.oversized_responses.is_empty(),
            "oversized_responses 应为空"
        );
    }
}
