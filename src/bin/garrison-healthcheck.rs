// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `garrison-healthcheck`——容器 HEALTHCHECK 探针（零依赖零 feature）。
//!
//! 探测/判定逻辑全部委托 `garrison::health::probe`（纯 std 共享模块），
//! 与 `garrison-cli healthcheck` 子命令共用同一组函数，两个入口对同一
//! 存活/停服目标行为一致。本 bin 只负责环境变量读取与退出码映射。
//!
//! 探测 `GET http://127.0.0.1:{GARRISON_EXTERNAL_PORT:-8080}/healthz`。该路由是
//! sdforge 的 liveness 探针（`server-health-check` feature 下挂载，进程存活即恒
//! 200，绕过限流/审计中间件），**不是**库消费者的 `/health/live`（readiness 语义
//! 由业务方在自己的端口上自行暴露）。
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

fn main() -> ExitCode {
    let port = match probe::parse_port(std::env::var("GARRISON_EXTERNAL_PORT").ok().as_deref()) {
        Ok(p) => p,
        Err(reason) => {
            eprintln!("garrison-healthcheck: {reason}");
            return ExitCode::FAILURE;
        },
    };
    match probe::probe(port) {
        Ok(code) if probe::is_healthy(code) => ExitCode::SUCCESS,
        Ok(code) => {
            eprintln!(
                "garrison-healthcheck: /healthz on 127.0.0.1:{port} returned non-2xx status {code}"
            );
            ExitCode::FAILURE
        },
        Err(reason) => {
            eprintln!("garrison-healthcheck: {reason}");
            ExitCode::FAILURE
        },
    }
}
