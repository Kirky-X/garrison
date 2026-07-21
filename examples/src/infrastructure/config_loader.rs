//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 配置加载示例：演示 GarrisonConfig 的多种创建方式与热更新。
//!
//! 对应模块：`src/config/mod.rs`（always on，无需 feature）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin config_loader --features full
//! ```

use garrison::config::GarrisonConfig;
use garrison::error::{GarrisonError, GarrisonResult};
use std::io::Write as _;

/// 运行配置加载示例。
///
/// 演示默认配置、TOML 文件加载、环境变量覆盖、热更新订阅与配置校验。
///
/// 注意：本示例使用 `std::env::set_var` 设置环境变量，在多线程环境下需串行执行。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 配置加载示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 默认配置
    // ----------------------------------------------------------------
    let config = GarrisonConfig::default_config();
    println!("[1] 默认配置:");
    println!("    token_name = {}", config.token_name);
    println!("    timeout = {} 秒", config.timeout);
    println!("    token_style = {}", config.token_style);
    println!("    is_read_header = {}", config.is_read_header);
    println!("    is_read_cookie = {}", config.is_read_cookie);
    println!("    cookie_secure = {}", config.cookie_secure);
    println!("    cookie_same_site = {}", config.cookie_same_site);
    println!();

    // ----------------------------------------------------------------
    // 2. 从 TOML 文件加载配置（通过 confers）
    // ----------------------------------------------------------------
    let toml_content = r#"token_name = "auth_token"
timeout = 7200
active_timeout = 86400
is_read_cookie = true
is_read_header = true
is_write_header = true
token_style = "uuid"
throw_on_not_login = false
cookie_secure = false
cookie_same_site = "Lax"
"#;
    let mut temp_file = tempfile::Builder::new()
        .prefix("garrison_config_example")
        .suffix(".toml")
        .tempfile()
        .map_err(|e| GarrisonError::Internal(format!("创建临时文件失败: {}", e)))?;
    temp_file
        .write_all(toml_content.as_bytes())
        .map_err(|e| GarrisonError::Internal(format!("写入临时文件失败: {}", e)))?;
    let config = GarrisonConfig::load(temp_file.path().to_str())?;
    println!("[2] TOML 文件加载的配置:");
    println!("    token_name = {}", config.token_name);
    println!("    timeout = {} 秒", config.timeout);
    println!("    throw_on_not_login = {}", config.throw_on_not_login);
    println!();

    // ----------------------------------------------------------------
    // 3. 环境变量覆盖（GARRISON_ 前缀自动覆盖）
    // ----------------------------------------------------------------
    println!("[3] 环境变量覆盖演示:");
    println!("    设置 GARRISON_TOKEN_NAME=custom_token");
    std::env::set_var("GARRISON_TOKEN_NAME", "custom_token");
    let config = GarrisonConfig::load(None)?;
    println!("    覆盖后 token_name = {}", config.token_name);
    std::env::remove_var("GARRISON_TOKEN_NAME");
    println!();

    // ----------------------------------------------------------------
    // 4. 订阅配置热更新
    // ----------------------------------------------------------------
    let config = GarrisonConfig::default_config();
    println!("[4] 配置热更新演示:");
    println!("    初始 timeout = {} 秒", config.timeout);

    let rx = config.watch().expect("watcher 应已启用");
    println!("    已订阅配置变更通道");

    // ----------------------------------------------------------------
    // 5. 修改并广播配置变更
    // ----------------------------------------------------------------
    config.update(|c| {
        c.timeout = 1800;
    })?;
    println!("[5] 已广播配置变更: timeout → 1800 秒");

    let latest = rx.borrow();
    println!("    订阅端收到: timeout = {} 秒", latest.timeout);
    drop(latest);
    println!();

    // ----------------------------------------------------------------
    // 6. 配置校验
    // ----------------------------------------------------------------
    let mut bad_config = GarrisonConfig::default_config();
    bad_config.token_style = "invalid_style".to_string();
    println!("[6] 配置校验演示:");
    match bad_config.validate() {
        Ok(()) => println!("    校验通过"),
        Err(e) => println!("    校验失败（符合预期）: {}", e),
    }

    let good_config = GarrisonConfig::default_config();
    good_config.validate()?;
    println!("    合法配置校验通过");

    println!("\n=== 示例执行完成 ===");
    Ok(())
}
