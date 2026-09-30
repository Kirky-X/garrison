// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 容器/CLI 共用的 liveness 探针逻辑（纯 std，零外部依赖）。
//!
//! `garrison-healthcheck` 探针 bin 与 `garrison-cli healthcheck` 子命令共用
//! 本模块的同一组函数，保证两个入口对同一存活/停服目标行为一致。
//! 探针只读 OS socket API（`TcpStream`），不引入任何外部 crate，
//! 探针 bin 的零依赖性质不变。
//!
//! 探测 `GET http://127.0.0.1:{port}/healthz`。该路由是 sdforge 的 liveness
//! 探针（`server-health-check` feature 下挂载，进程存活即恒 200，绕过限流/
//! 审计中间件），**不是**库消费者的 `/health/live`（readiness 语义由业务方在
//! 自己的端口上自行暴露）。
//!
//! 判定：HTTP/1.1 状态行 2xx → 存活；连接失败/超时/非 2xx/畸形响应 → 失败，
//! 原因以单行字符串返回（供 `docker inspect` / 编排平台定位）。

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// 连接超时：内层超时为平台兜底，连接 + 读写（2s+2s）须整体落在镜像
/// HEALTHCHECK 的 `--timeout=5s` 预算内——保证探针先于平台超时判定快速失败，
/// 避免 HEALTHCHECK 堆积。
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// 读/写超时：与连接超时同级，覆盖服务端挂起不回包的场景（预算对齐见上）。
pub const IO_TIMEOUT: Duration = Duration::from_secs(2);
/// 未设置 `GARRISON_EXTERNAL_PORT` 时的默认外网端口（与 auth_server 默认值对齐）。
pub const DEFAULT_EXTERNAL_PORT: u16 = 8080;
/// 状态行读取上限：正常探针响应远小于此值，超限视为服务端行为异常。
pub const RESPONSE_CAP: usize = 8 * 1024;

/// 解析 HTTP 状态行中的状态码（如 `HTTP/1.1 200 OK` → `Some(200)`）。
/// 畸形行（缺协议头 / 状态码非数字）返回 `None`。
pub fn parse_status_code(line: &str) -> Option<u16> {
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

/// 健康判定：状态行 2xx 即存活（liveness 语义，对应 sdforge `/healthz`）。
pub fn is_healthy(code: u16) -> bool {
    (200..300).contains(&code)
}

/// 构造探针请求（HTTP/1.1 + `Connection: close`，服务端回包后即断开）。
pub fn build_request(port: u16) -> String {
    format!("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
}

/// 对 127.0.0.1:{port} 执行一次探测：成功返回状态码，失败返回单行原因。
///
/// 失败路径全覆盖：连接拒绝/超时、写超时、服务端无回包即断开、响应超限无状态行、
/// 状态行畸形。只读首个 `\r\n` 前的字节，不解析 headers/body。
pub fn probe(port: u16) -> Result<u16, String> {
    // 127.0.0.1 直接构造 SocketAddr，无 DNS 参与，行为确定
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("connect 127.0.0.1:{port} failed: {e}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| format!("set read timeout failed: {e}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|e| format!("set write timeout failed: {e}"))?;

    stream
        .write_all(build_request(port).as_bytes())
        .map_err(|e| format!("send request failed: {e}"))?;

    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        if buf.len() > RESPONSE_CAP {
            return Err(format!(
                "response exceeds {RESPONSE_CAP} bytes without a status line"
            ));
        }
        let n = stream
            .read(&mut chunk)
            .map_err(|e| format!("read response failed: {e}"))?;
        if n == 0 {
            return Err("connection closed before status line".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(&buf[..pos]);
            return parse_status_code(&line)
                .ok_or_else(|| format!("malformed status line: {line:?}"));
        }
    }
}

/// 解析探针目标端口：未设置/为空回退默认端口；设置了但非法则 fail-loud
/// （返回原因，由调用方输出 stderr 并以退出码 1 结束），绝不静默回退。
pub fn parse_port(value: Option<&str>) -> Result<u16, String> {
    match value {
        None => Ok(DEFAULT_EXTERNAL_PORT),
        Some(v) if v.trim().is_empty() => Ok(DEFAULT_EXTERNAL_PORT),
        Some(v) => v
            .trim()
            .parse::<u16>()
            .map_err(|e| format!("invalid GARRISON_EXTERNAL_PORT={v:?}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn parse_status_line_200() {
        assert_eq!(parse_status_code("HTTP/1.1 200 OK"), Some(200));
    }

    #[test]
    fn parse_status_line_503() {
        assert_eq!(
            parse_status_code("HTTP/1.1 503 Service Unavailable"),
            Some(503)
        );
    }

    #[test]
    fn parse_status_line_malformed() {
        assert_eq!(parse_status_code("garbage"), None);
        assert_eq!(parse_status_code("HTTP/1.1 not-a-number"), None);
        assert_eq!(parse_status_code(""), None);
        assert_eq!(parse_status_code("HTTP/1.1"), None);
    }

    #[test]
    fn healthy_boundary() {
        assert!(is_healthy(200));
        assert!(is_healthy(299));
        assert!(!is_healthy(199));
        assert!(!is_healthy(300));
        assert!(!is_healthy(503));
    }

    #[test]
    fn request_targets_healthz_with_close() {
        let req = build_request(8080);
        assert!(req.starts_with("GET /healthz HTTP/1.1\r\n"));
        assert!(req.contains("Host: 127.0.0.1:8080\r\n"));
        assert!(req.ends_with("Connection: close\r\n\r\n"));
    }

    /// 起本地一次性假服务端，返回其临时端口（无外网依赖，无端口抖动）。
    fn serve_once(response: &'static str, close_without_reply: bool) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 1024];
            let _ = conn.read(&mut buf);
            if !close_without_reply {
                conn.write_all(response.as_bytes()).expect("write response");
            }
        });
        port
    }

    #[test]
    fn probe_ok_200_end_to_end() {
        let port = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            false,
        );
        assert_eq!(probe(port), Ok(200));
    }

    #[test]
    fn probe_reports_503_status() {
        let port = serve_once("HTTP/1.1 503 Service Unavailable\r\n\r\n", false);
        assert_eq!(probe(port), Ok(503));
        assert!(!is_healthy(503));
    }

    #[test]
    fn probe_malformed_response_is_error() {
        let port = serve_once("this is not http\r\n", false);
        let err = probe(port).expect_err("malformed response must fail");
        assert!(err.contains("malformed"), "unexpected reason: {err}");
    }

    #[test]
    fn probe_closed_without_status_line_is_error() {
        let port = serve_once("", true);
        let err = probe(port).expect_err("connection closed early must fail");
        assert!(err.contains("closed"), "unexpected reason: {err}");
    }

    #[test]
    fn probe_connection_refused_is_error() {
        // 先绑定再立即释放，得到一个确定无监听的临时端口
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        assert!(probe(port).is_err());
    }

    #[test]
    fn port_parsing() {
        // 未设置 / 空 → 默认 8080
        assert_eq!(parse_port(None), Ok(DEFAULT_EXTERNAL_PORT));
        assert_eq!(parse_port(Some("")), Ok(DEFAULT_EXTERNAL_PORT));
        assert_eq!(parse_port(Some("  ")), Ok(DEFAULT_EXTERNAL_PORT));
        // 合法值（含空白包围）
        assert_eq!(parse_port(Some("9999")), Ok(9999));
        assert_eq!(parse_port(Some(" 8080 ")), Ok(8080));
        // 非法值必须报错而非静默回退（fail-loud）
        assert!(parse_port(Some("abc")).is_err());
        assert!(parse_port(Some("70000")).is_err());
        assert!(parse_port(Some("-1")).is_err());
    }
}
