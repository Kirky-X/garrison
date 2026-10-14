// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `garrison-healthcheck`——容器 HEALTHCHECK 探针（零依赖零 feature）。
//!
//! 探测/判定逻辑全部委托 `garrison::health::probe`（纯 std 共享模块，与
//! `garrison-cli healthcheck` 共用，两入口对同一目标行为一致）；本 bin 只负责
//! 环境变量读取与退出码映射。
//!
//! 探测 `GET http://127.0.0.1:{GARRISON_EXTERNAL_PORT:-8080}/healthz`——sdforge 的
//! liveness 探针（`server-health-check` feature 下挂载，进程存活即恒 200，绕过限流/
//! 审计中间件），**不是**库消费者的 `/health/live`（readiness 语义由业务方自行暴露）。
//!
//! 判定：HTTP/1.1 状态行 2xx → exit 0；连接失败/超时/非 2xx/畸形响应 → exit 1，
//! 原因以单行输出 stderr（供 `docker inspect` / 编排平台定位）。
//!
//! # 用法（Dockerfile HEALTHCHECK）
//!
//! ```text
//! HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
//!     CMD ["/app/garrison-healthcheck"]
//! ```
use std::process::ExitCode;

use garrison::health::probe;
use garrison::i18n::translate_detail;

fn main() -> ExitCode {
    let port = match probe::parse_port(std::env::var("GARRISON_EXTERNAL_PORT").ok().as_deref()) {
        Ok(p) => p,
        Err(reason) => {
            eprintln!(
                "{}",
                translate_detail("bin-healthcheck-failed", &[("arg0", reason.as_str())])
            );
            return ExitCode::FAILURE;
        },
    };
    match probe::probe(port) {
        Ok(code) if probe::is_healthy(code) => ExitCode::SUCCESS,
        Ok(code) => {
            let port_arg = port.to_string();
            let code_arg = code.to_string();
            eprintln!(
                "{}",
                translate_detail(
                    "bin-healthcheck-status",
                    &[("arg0", port_arg.as_str()), ("arg1", code_arg.as_str())]
                )
            );
            ExitCode::FAILURE
        },
        Err(reason) => {
            eprintln!(
                "{}",
                translate_detail("bin-healthcheck-failed", &[("arg0", reason.as_str())])
            );
            ExitCode::FAILURE
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// 一次性 HTTP 服务端：接受一次连接后按 `status_line` 回包（覆盖 2xx 与非 2xx 两态）。
    fn spawn_oneshot_http(status_line: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("绑定回环端口应成功");
        let port = listener.local_addr().expect("读取本地地址应成功").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(format!("{status_line}\r\n\r\n").as_bytes());
            }
        });
        port
    }

    /// 端口非法：不探测，直接以退出码 1 失败（fail-closed）。
    #[test]
    #[serial_test::serial]
    fn invalid_port_env_exits_failure() {
        std::env::set_var("GARRISON_EXTERNAL_PORT", "not-a-port");
        assert_eq!(main(), ExitCode::FAILURE);
        std::env::remove_var("GARRISON_EXTERNAL_PORT");
    }

    /// 探针命中 2xx：退出码 0（容器判定为存活）。
    #[test]
    #[serial_test::serial]
    fn healthy_target_exits_success() {
        let port = spawn_oneshot_http("HTTP/1.1 200 OK");
        std::env::set_var("GARRISON_EXTERNAL_PORT", port.to_string());
        assert_eq!(main(), ExitCode::SUCCESS);
        std::env::remove_var("GARRISON_EXTERNAL_PORT");
    }

    /// 探针命中非 2xx：退出码 1（平台据此重启容器）。
    #[test]
    #[serial_test::serial]
    fn unhealthy_target_exits_failure() {
        let port = spawn_oneshot_http("HTTP/1.1 503 Service Unavailable");
        std::env::set_var("GARRISON_EXTERNAL_PORT", port.to_string());
        assert_eq!(main(), ExitCode::FAILURE);
        std::env::remove_var("GARRISON_EXTERNAL_PORT");
    }

    /// 目标不可达（端口无监听）：退出码 1。
    #[test]
    #[serial_test::serial]
    fn unreachable_target_exits_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("绑定回环端口应成功");
        let port = listener.local_addr().expect("读取本地地址应成功").port();
        drop(listener);
        std::env::set_var("GARRISON_EXTERNAL_PORT", port.to_string());
        assert_eq!(main(), ExitCode::FAILURE);
        std::env::remove_var("GARRISON_EXTERNAL_PORT");
    }
}
