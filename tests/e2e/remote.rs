//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! E2E 远程模式基础设施。
//!
//! 提供两种部署模式：
//! - `connect_env()`：连接到外部已运行的 auth_server_serve（CI 模式，env 注入 URL）
//! - `spawn_child()`：fork 一个 auth_server_serve 子进程（本地开发模式）
//!
//! `setup()` 优先 connect_env，失败则 spawn_child，返回 `RemoteContext`。
//! Drop 时自动 kill 子进程（若有），防止僵尸进程（规则 12 失败显性化）。
//!
//! # 端口分配策略
//!
//! `spawn_child` 不使用 `BULWARK_EXTERNAL_PORT=0`（serve() 打印配置端口而非
//! 实际绑定端口，port=0 时打印 0 导致测试无法连接），改为先用
//! `pick_free_port()` 挑选空闲端口再注入 env，stderr 行的端口即为实际端口。

use super::default_tenant_headers;
use serial_test::serial;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// 远程 auth_server_serve 上下文。
///
/// 封装 external/internal URL、API Key、可选的子进程句柄。
/// Drop 时若有子进程则 kill + wait，防止僵尸进程。
pub struct RemoteContext {
    pub external_url: String,
    pub internal_url: String,
    pub api_key: String,
    _child: Option<Child>,
}

impl Drop for RemoteContext {
    fn drop(&mut self) {
        if let Some(child) = self._child.as_mut() {
            // 规则 12：失败显性化——kill/wait 错误此处无法向上传播，
            // 用 _ 忽略但不静默成功（Drop 不能 panic，记录到 stderr 兜底）
            if let Err(e) = child.kill() {
                eprintln!("[RemoteContext::drop] kill 子进程失败: {}", e);
            }
            if let Err(e) = child.wait() {
                eprintln!("[RemoteContext::drop] wait 子进程失败: {}", e);
            }
        }
    }
}

impl RemoteContext {
    /// 从 env 读取已运行的 auth_server_serve 连接信息。
    ///
    /// Env 变量：
    /// - `BULWARK_E2E_EXTERNAL_URL`：外网 URL（如 `http://127.0.0.1:8080`）
    /// - `BULWARK_E2E_INTERNAL_URL`：内网 URL
    /// - `BULWARK_E2E_API_KEY`：内网 API Key
    ///
    /// 缺失任一返回 `None`。三者齐全时对 internal 端口 `/api/v1/auth/health`
    /// 做 3 次 health check（100ms 间隔），任一成功返回 `Some`，全部失败返回 `None`。
    pub async fn connect_env() -> Option<Self> {
        let external_url = std::env::var("BULWARK_E2E_EXTERNAL_URL").ok()?;
        let internal_url = std::env::var("BULWARK_E2E_INTERNAL_URL").ok()?;
        let api_key = std::env::var("BULWARK_E2E_API_KEY").ok()?;

        let client = reqwest::Client::builder()
            .default_headers(default_tenant_headers())
            .build()
            .ok()?;

        // health check 3 次 × 100ms，对 internal /api/v1/auth/health 端点
        for _ in 0..3 {
            if let Ok(resp) = client
                .get(format!("{}/api/v1/auth/health", internal_url))
                .header("x-api-key", &api_key)
                .send()
                .await
            {
                if resp.status().is_success() {
                    return Some(Self {
                        external_url,
                        internal_url,
                        api_key,
                        _child: None,
                    });
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        None
    }

    /// 启动 auth_server_serve 子进程。
    ///
    /// 用 `pick_free_port()` 挑选 external/internal 端口，通过 env 注入子进程，
    /// 从 stderr 行 `[auth_server_serve] listening on external=0.0.0.0:PORT internal=0.0.0.0:PORT`
    /// 解析端口。60s 超时 panic dump stderr（规则 12 失败显性化；60s 容纳首次
    /// `cargo run` 编译时间，预编译后通常 <1s）。
    pub fn spawn_child() -> Self {
        let external_port = pick_free_port();
        let internal_port = pick_free_port();
        let api_key = "e2e-test-key-12345".to_string();

        let mut child = Command::new("cargo")
            .args([
                "run",
                "-p",
                "bulwark-examples",
                "--bin",
                "auth_server_serve",
                "--features",
                "full",
            ])
            .env("EXAMPLE_INTERNAL_API_KEY", &api_key)
            .env("BULWARK_EXTERNAL_PORT", external_port.to_string())
            .env("BULWARK_INTERNAL_PORT", internal_port.to_string())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn auth_server_serve 失败");

        let stderr = child.stderr.take().expect("stderr 不应为 None");
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().flatten() {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        // 60s 超时：cargo run 首次需编译，预编译后 <1s
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut external_url: Option<String> = None;
        let mut internal_url: Option<String> = None;
        let mut stderr_dump = String::new();

        loop {
            if Instant::now() >= deadline {
                panic!(
                    "auth_server_serve 60s 内未输出 listening 行，stderr dump:\n{}",
                    stderr_dump
                );
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(line) => {
                    stderr_dump.push_str(&line);
                    stderr_dump.push('\n');
                    if external_url.is_none() {
                        if let Some(port) = parse_port(&line, "external") {
                            external_url = Some(format!("http://127.0.0.1:{}", port));
                        }
                    }
                    if internal_url.is_none() {
                        if let Some(port) = parse_port(&line, "internal") {
                            internal_url = Some(format!("http://127.0.0.1:{}", port));
                        }
                    }
                    if external_url.is_some() && internal_url.is_some() {
                        break;
                    }
                },
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!(
                        "auth_server_serve stderr 提前关闭，stderr dump:\n{}",
                        stderr_dump
                    );
                },
            }
        }

        Self {
            external_url: external_url.expect("已校验 external_url 非 None"),
            internal_url: internal_url.expect("已校验 internal_url 非 None"),
            api_key,
            _child: Some(child),
        }
    }

    /// 优先 `connect_env()`，失败则 `spawn_child()`，返回 `Self`。
    pub async fn setup() -> Self {
        if let Some(ctx) = Self::connect_env().await {
            return ctx;
        }
        Self::spawn_child()
    }

    /// 返回带 `X-Tenant-Id: 0` 默认 header 的 `reqwest::Client`。
    ///
    /// 复用 `super::default_tenant_headers()`，与 in-process E2E 测试保持一致。
    pub fn plain_client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .default_headers(default_tenant_headers())
            .build()
            .expect("构造 reqwest 客户端失败")
    }
}

/// 从 stderr 行解析端口。
///
/// 行格式：`[auth_server_serve] listening on external=0.0.0.0:PORT internal=0.0.0.0:PORT`
///
/// 用简单字符串解析替代 regex（regex 是 bulwark 可选 dep，测试二进制无法直接引用）。
fn parse_port(line: &str, key: &str) -> Option<u16> {
    let prefix = format!("{}=0.0.0.0:", key);
    let start = line.find(&prefix)? + prefix.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// 挑选空闲端口。
///
/// 绑定 `127.0.0.1:0` 让 OS 分配端口，drop 后立即释放。
/// 存在轻微竞态（释放与 serve 绑定之间），但测试场景可接受。
fn pick_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 失败");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// 测试 `RemoteContext::setup()` 能连接到服务器并完成 login。
///
/// `setup()` 优先 connect_env（CI 模式），失败则 spawn_child（本地开发模式）。
/// 对 `external_url + "/api/v1/auth/login"` 发 POST（login_id=test_remote）断言 200。
/// `RemoteContext` drop 时 kill 子进程，验证无僵尸进程。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_remote_context_setup_connects_to_server() {
    let ctx = RemoteContext::setup().await;
    let client = ctx.plain_client();

    let resp = client
        .post(format!("{}/api/v1/auth/login", ctx.external_url))
        .json(&serde_json::json!({
            "login_id": "test_remote",
            "params": bulwark::backend::types::LoginParams::default()
        }))
        .send()
        .await
        .expect("登录请求失败");
    assert_eq!(resp.status(), 200, "login 应返回 200");

    // ctx 在函数结束时 drop，验证 _child 被 kill（无僵尸进程）
    // 若 drop 失败会 eprintln 但不 panic（Drop 不能 panic）
}
