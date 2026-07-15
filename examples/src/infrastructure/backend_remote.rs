//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 远程后端示例：演示 BackendRemote 连接远程 Auth Server。
//!
//! 对应模块：`src/backend/remote.rs`（`backend-remote` feature 开启时可用）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin backend_remote --features full
//! ```
//!
//! 注意：本示例不会真正连接服务器（无 Auth Server 运行），
//! 所有 API 调用会返回 Network 错误，示例演示构造方式和预期行为。

use bulwark::backend::{AuthBackend, BackendRemote, LoginParams};
use bulwark::error::{BulwarkError, BulwarkResult};
use std::time::Duration;

/// 运行远程后端示例。
///
/// 演示：
/// 1. 使用 `BackendRemote::new` 构造内网客户端
/// 2. 使用 `BackendRemoteBuilder` 构造带超时的外网客户端
/// 3. 尝试 login / check_login / logout（预期失败，无服务器运行）
pub async fn run() -> BulwarkResult<()> {
    println!("=== Bulwark 远程后端示例 ===\n");

    // 1. 构造内网 BackendRemote（连接 Auth Server 内网端口 8081）
    let internal = BackendRemote::new(
        "http://127.0.0.1:8081",
        "internal-api-key-2026",
        Duration::from_secs(10),
    )?;
    println!("[1] 内网 BackendRemote 构造成功");
    println!("    base_url = http://127.0.0.1:8081");
    println!("    api_key  = internal-api-key-2026");
    println!("    timeout  = 10s\n");

    // 2. 构造外网 BackendRemote（连接外网端口 8080）
    let external = BackendRemote::new(
        "http://127.0.0.1:8080",
        "external-api-key",
        Duration::from_secs(5),
    )?;
    println!("[2] 外网 BackendRemote 构造成功");
    println!("    base_url = http://127.0.0.1:8080");
    println!("    timeout  = 5s\n");

    // 3. 尝试 login（预期失败：无服务器运行）
    let login_result = internal.login("user1001", &LoginParams::default()).await;
    println!("[3] login(\"user1001\") 结果:");
    match &login_result {
        Ok(token) => println!("    token = {}（意外成功：服务器在运行？）\n", token),
        Err(BulwarkError::Network(msg)) => {
            println!("    Network 错误（预期，无服务器运行）");
            println!("    详情: {}\n", msg);
        },
        Err(e) => println!("    其他错误: {:?}\n", e),
    }

    // 4. 尝试 check_login（预期失败）
    let check_result = internal.check_login("some-token").await;
    println!("[4] check_login(\"some-token\") 结果:");
    match &check_result {
        Ok(logged_in) => println!("    logged_in = {}（意外成功）\n", logged_in),
        Err(BulwarkError::Network(msg)) => {
            println!("    Network 错误（预期，无服务器运行）");
            println!("    详情: {}\n", msg);
        },
        Err(e) => println!("    其他错误: {:?}\n", e),
    }

    // 5. 尝试 logout（预期失败）
    let logout_result = internal.logout("some-token").await;
    println!("[5] logout(\"some-token\") 结果:");
    match &logout_result {
        Ok(()) => println!("    Ok(())（意外成功）\n"),
        Err(BulwarkError::Network(msg)) => {
            println!("    Network 错误（预期，无服务器运行）");
            println!("    详情: {}\n", msg);
        },
        Err(e) => println!("    其他错误: {:?}\n", e),
    }

    // 6. 使用外网客户端尝试 login（同样预期失败）
    let ext_login = external.login("user2002", &LoginParams::default()).await;
    println!("[6] 外网客户端 login(\"user2002\") 结果:");
    match &ext_login {
        Ok(token) => println!("    token = {}（意外成功）\n", token),
        Err(BulwarkError::Network(msg)) => {
            println!("    Network 错误（预期，无服务器运行）");
            println!("    详情: {}\n", msg);
        },
        Err(e) => println!("    其他错误: {:?}\n", e),
    }

    println!("=== 示例执行完成 ===");
    println!("提示：启动 Auth Server 后，以上 API 调用将正常工作。");
    Ok(())
}
