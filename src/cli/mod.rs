// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! garrison 单根二进制的 CLI 面（sdforge `CliBuilder` + inventory 注册 + dispatch）。
//!
//! 子命令面按 feature 裁剪，处理器逻辑全部驻留库层（可在 `cargo test --lib` 下测试）：
//!
//! | 子命令 | 门控 | 来源 |
//! |--------|------|------|
//! | `healthcheck` | 无条件 | 原 `garrison-healthcheck` 探针 bin + 原 `garrison-cli healthcheck`（合并，`--port` 可选） |
//! | `serve` | `auth-server` + `cache-memory` | 原 `auth_server` bin（env 驱动，sdforge 路由装配在库层 server 模块） |
//! | `key-rotate` / `user-hash` / `one-time-access-token` / `change-key` / `check-key` / `vacuum-kv` | `cli-ops` + 依赖 feature | 原 `garrison-cli` 运维命令 |
//!
//! 缺 feature 的子命令注册被 `cfg` 裁剪，用户敲入时 clap 报 unrecognized subcommand（显性失败）。
//!
//! [`build_root_command`] 供 `src/main.rs` 装配；handler 返回 `Value::Null` 表示
//! 「子命令已自行输出」（sdforge dispatch 契约），运维命令沿用既有 stdout 报告行为。

use sdforge::cli::{CliBuilder, CliCommandRegistration, CliHandlerRegistration};
use sdforge::core::{ApiError, HandlerArgs, HandlerFuture, HandlerState};
use sdforge::inventory;

/// 原 `garrison-cli` 运维命令组（`cli-ops` 及其依赖 feature 满足时编译）。
#[cfg(all(
    feature = "cli-ops",
    feature = "account-credential",
    feature = "protocol-zeroize",
    feature = "db-sqlite",
    feature = "protocol-jwt",
    feature = "config-yaml",
    feature = "field-encryption",
    feature = "dao-key-index"
))]
pub mod ops;
/// 原 `auth_server` 参考部署入口（`auth-server` + `cache-memory`，镜像原 `[[bin]]` required-features）。
#[cfg(all(feature = "auth-server", feature = "cache-memory"))]
pub mod serve;

/// garrison CLI 装配：收集本 crate 经 inventory 注册的全部子命令面。
///
/// 程序名固定 `garrison`；`--version` 由 `src/main.rs` 以 garrison 自身
/// `CARGO_PKG_VERSION` 覆盖（`CliBuilder::build` 写死 sdforge 自己的版本）。
pub fn build_root_command() -> CliBuilder {
    CliBuilder::new().with_name("garrison")
}

// healthcheck 子命令（无条件注册：探针只依赖 std socket 与库层 `health::probe`）

inventory::submit! {
    CliCommandRegistration::new(
        "healthcheck",
        env!("CARGO_PKG_VERSION"),
        "Probe GET /healthz on the local auth server (default port from GARRISON_EXTERNAL_PORT, fallback 8080)",
        "handle_healthcheck_cmd",
    )
    .with_args(&[
        sdforge::cli::CliArgInfo::new(
            "port",
            "Probe port override (default: GARRISON_EXTERNAL_PORT env, then 8080)",
            sdforge::cli::CliArgType::Body,
            false,
            None,
        ),
    ])
}
inventory::submit! { CliHandlerRegistration { name: "healthcheck", handler: handle_healthcheck_cmd } }

fn handle_healthcheck_cmd(args: HandlerArgs, _state: HandlerState) -> HandlerFuture {
    Box::pin(async move { run_healthcheck(args).await })
}

/// healthcheck 子命令实现：探测本机 auth_server 外网端口的 sdforge `/healthz`
/// liveness 探针（进程存活即恒 200，绕过限流/审计），合并原两入口行为——
/// 成功打印 `cli-healthcheck-healthy` 报告（探针场景 stdout 输出无害），失败
/// 经 `bin-healthcheck-*` 文案以非零退出码报告（Docker HEALTHCHECK / 编排平台语义）。
///
/// 探测逻辑全部委托 [`crate::health::probe`]（阻塞式 std socket I/O，移入
/// blocking 线程避免占用 runtime worker）。
async fn run_healthcheck(args: HandlerArgs) -> Result<serde_json::Value, ApiError> {
    let port_override: Option<u16> = match args.get("port") {
        Some(raw) => Some(raw.parse::<u16>().map_err(|e| {
            ApiError::internal_error(
                format!("healthcheck-port-invalid::{raw}::{e}"),
                "garrison.healthcheck.port",
            )
        })?),
        None => None,
    };
    let port = match port_override {
        Some(p) => p,
        None => crate::health::probe::parse_port(
            std::env::var("GARRISON_EXTERNAL_PORT").ok().as_deref(),
        )
        .map_err(|reason| {
            ApiError::internal_error(
                crate::i18n::translate_detail(
                    "bin-healthcheck-failed",
                    &[("arg0", reason.as_str())],
                ),
                "garrison.healthcheck.port",
            )
        })?,
    };
    let result = tokio::task::spawn_blocking(move || crate::health::probe::probe(port))
        .await
        .map_err(|e| {
            ApiError::internal_error(
                format!("healthcheck-join::{e}"),
                "garrison.healthcheck.join",
            )
        })?;
    match result {
        Ok(code) if crate::health::probe::is_healthy(code) => {
            let port_arg = port.to_string();
            let code_arg = code.to_string();
            Ok(serde_json::Value::String(crate::i18n::translate_detail(
                "cli-healthcheck-healthy",
                &[("port", port_arg.as_str()), ("code", code_arg.as_str())],
            )))
        },
        Ok(code) => Err(ApiError::internal_error(
            crate::i18n::translate_detail(
                "bin-healthcheck-status",
                &[
                    ("arg0", port.to_string().as_str()),
                    ("arg1", code.to_string().as_str()),
                ],
            ),
            "garrison.healthcheck.status",
        )),
        Err(reason) => Err(ApiError::internal_error(
            crate::i18n::translate_detail("bin-healthcheck-failed", &[("arg0", reason.as_str())]),
            "garrison.healthcheck.probe",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 提取 `ApiError::Internal` 的结构化原因（message 字段）——与
    /// `src/main.rs` 的错误提取契约一致；其余变体回退 Display。
    fn internal_message(err: &ApiError) -> String {
        match err {
            ApiError::Internal { message, .. } if !message.trim().is_empty() => message.clone(),
            other => other.to_string(),
        }
    }

    /// 注册面守卫：healthcheck 无条件注册；serve / ops 按 feature 裁剪。
    #[test]
    fn healthcheck_command_registered_unconditionally() {
        let names: Vec<&str> = sdforge::inventory::iter::<CliCommandRegistration>()
            .map(|r| r.name)
            .collect();
        assert!(names.contains(&"healthcheck"), "实际注册面: {names:?}");
        assert_eq!(
            names.iter().filter(|n| **n == "healthcheck").count(),
            1,
            "healthcheck 不得重复注册（原 garrison-cli 子命令已合并到顶层）"
        );
        if cfg!(all(feature = "auth-server", feature = "cache-memory")) {
            assert!(
                names.contains(&"serve"),
                "auth-server 构建应注册 serve: {names:?}"
            );
        } else {
            assert!(
                !names.contains(&"serve"),
                "缺 auth-server/cache-memory 时 serve 应被裁剪: {names:?}"
            );
        }
    }

    /// 起本地一次性 HTTP 假服务端，返回其临时端口。
    fn serve_once(response: &'static str) -> u16 {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 1024];
            let _ = conn.read(&mut buf);
            conn.write_all(response.as_bytes()).expect("write response");
        });
        port
    }

    /// --port 覆盖命中 2xx：返回 healthy 报告（Value::String）。
    #[tokio::test(flavor = "multi_thread")]
    async fn healthcheck_ok_on_live_target() {
        let port = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let mut args = HandlerArgs::new();
        args.insert("port".to_string(), port.to_string());
        let value = run_healthcheck(args)
            .await
            .expect("live target must be reported healthy");
        let text = value.as_str().expect("healthy 报告应为字符串");
        assert!(text.contains(&port.to_string()), "报告应含端口: {text}");
    }

    /// --port 覆盖命中非 2xx：非零退出语义（Err）且原因携带状态码。
    ///
    /// 断言走 `Internal.message` 字段（与 `src/main.rs` 的错误提取契约一致——
    /// `ApiError::Internal` 的 Display 恒为通用文案，真正原因在 message）。
    #[tokio::test(flavor = "multi_thread")]
    async fn healthcheck_fails_on_non_2xx() {
        let port = serve_once("HTTP/1.1 503 Service Unavailable\r\n\r\n");
        let mut args = HandlerArgs::new();
        args.insert("port".to_string(), port.to_string());
        let err = run_healthcheck(args)
            .await
            .expect_err("503 must not be reported healthy");
        let reason = internal_message(&err);
        assert!(
            reason.contains("503"),
            "错误原因必须携带状态码，实际: {reason}"
        );
    }

    /// 目标不可达（端口无监听）：连接失败显性报错（断言走 `Internal.message`，同上）。
    #[tokio::test(flavor = "multi_thread")]
    async fn healthcheck_fails_on_dead_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        let mut args = HandlerArgs::new();
        args.insert("port".to_string(), port.to_string());
        let err = run_healthcheck(args)
            .await
            .expect_err("dead port must fail");
        let reason = internal_message(&err);
        assert!(
            reason.contains("127.0.0.1") || reason.contains("connect"),
            "连接失败必须显性报错，实际: {reason}"
        );
    }

    /// env 链端口非法（GARRISON_EXTERNAL_PORT 非 numeric）：fail-closed 显性报错。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn healthcheck_invalid_port_env_fails_closed() {
        std::env::set_var("GARRISON_EXTERNAL_PORT", "not-a-port");
        let err = run_healthcheck(HandlerArgs::new())
            .await
            .expect_err("非法端口必须显性失败");
        assert!(!err.to_string().is_empty());
        std::env::remove_var("GARRISON_EXTERNAL_PORT");
    }
}
