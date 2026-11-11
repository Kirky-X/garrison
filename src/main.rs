// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! garrison 单根二进制入口（薄壳）：Tokio runtime 构建 + sdforge CLI dispatch。
//!
//! 子命令处理器与注册全部驻留库层 [`garrison::cli`]（`serve` / `healthcheck` /
//! 运维命令组，按 feature 裁剪），本文件只负责：
//! 1. 显式构建 Tokio runtime（`GARRISON_WORKER_THREADS` / `GARRISON_MAX_BLOCKING_THREADS` 调优，serve 面消费）
//! 2. 经 sdforge `CliBuilder` 装配 clap 命令面（`--version` 覆盖为 garrison 自身版本——`build()` 写死 sdforge 的版本）
//! 3. dispatch 到 inventory 注册的 handler，成功输出 handler 值、失败 `error: <原因>` + 退出码 1
//!
//! # 使用
//!
//! ```sh
//! cargo run --features auth-server,cache-memory --bin garrison -- serve
//! cargo run --features "cli-ops,account-credential,protocol-zeroize,db-sqlite,protocol-jwt,config-yaml,field-encryption,dao-key-index" --bin garrison -- key-rotate
//! ```

// mimalloc 全局分配器：serve 面（auth-server feature）多线程分配性能优于系统默认分配器；
// 其余子命令面保持系统分配器（原 auth_server bin 行为等价迁移）。
#[cfg(feature = "auth-server")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    // 显式构建 Tokio runtime，支持通过环境变量调优线程参数（serve 消费；
    // 其余子命令对线程参数不敏感，统一装配无行为影响）
    let worker_threads = std::env::var("GARRISON_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse().ok());
    let max_blocking_threads = std::env::var("GARRISON_MAX_BLOCKING_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);

    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder
        .enable_all()
        .max_blocking_threads(max_blocking_threads);
    if let Some(threads) = worker_threads {
        runtime_builder.worker_threads(threads);
    }

    let runtime = runtime_builder
        .build()
        .expect("failed to build Tokio runtime");

    runtime.block_on(async_main())
}

async fn async_main() {
    let cli = garrison::cli::build_root_command()
        .build()
        .version(env!("CARGO_PKG_VERSION"));
    let matches = cli.get_matches();
    let format = sdforge::cli::output::OutputFormat::from_matches(&matches);
    match sdforge::cli::dispatch::dispatch(&matches, None).await {
        Ok((_name, value)) => {
            // Value::Null = 「子命令已自行输出」哨兵（serve/运维命令组契约）：
            // 不得再渲染——否则 `extract_value` 会把 Null 序列化成字面 "null" 尾行。
            if !value.is_null() {
                let output = sdforge::core::extract_value(&value);
                if !output.is_empty() {
                    println!("{output}");
                }
            }
        },
        Err(e) => {
            // sdforge 的 `Internal` 变体 Display 恒为通用文案，真正的原因在
            // `message` 字段里；CLI 必须把原因说出来，否则用户无从下手。
            let reason = match &e {
                sdforge::core::ApiError::Internal { message, .. } if !message.trim().is_empty() => {
                    message.clone()
                },
                other => other.to_string(),
            };
            // 遵守 sdforge 的 `--format` 契约：json 模式错误以 UnifiedError JSON
            // 写 stdout（与 HTTP/gRPC 同形状），text 模式逐字输出 stderr。
            format.emit_error(&e);
            eprintln!("error: {reason}");
            std::process::exit(1);
        },
    }
}
