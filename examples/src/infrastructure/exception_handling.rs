//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 异常处理示例：演示 Garrison 异常体系（NotLoginException + GarrisonException）。
//!
//! 对应模块：`src/exception/mod.rs`（always on，无需 feature）。
//!
//! 展示：
//! 1. NotLoginException 构造与 builder 模式
//! 2. GarrisonException 链式构造（携带 token / login_id / extras 上下文）
//! 3. GarrisonException ↔ GarrisonError 互转
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin exception_handling --features full
//! ```

use garrison::error::{GarrisonError, GarrisonResult};
use garrison::exception::{GarrisonException, NotLoginException};

/// 运行异常处理示例。
///
/// 演示 NotLoginException / GarrisonException 构造与 GarrisonError ↔ GarrisonException 互转。
pub fn run() -> GarrisonResult<()> {
    println!("=== Garrison 异常处理示例 ===\n");

    // ----------------------------------------------------------------
    // 1. NotLoginException：未登录异常（对应 NotLoginException）
    // ----------------------------------------------------------------
    let ex = NotLoginException::new("请先登录").with_login_type("account");
    println!("[1] NotLoginException:");
    println!("    message   = {}", ex.message);
    println!("    login_type= {}", ex.login_type);
    println!("    Display   = {}\n", ex);

    // ----------------------------------------------------------------
    // 2. GarrisonException：携带上下文的业务可恢复异常（Builder 模式）
    // ----------------------------------------------------------------
    let biz_ex = GarrisonException::new(-1, "会话已过期")
        .with_token("T1-uuid-token")
        .with_login_id(1001)
        .with_login_type(1)
        .with_extra("device", "web")
        .with_extra("ip", "192.168.1.100")
        .build();

    println!("[2] GarrisonException（Builder 链式构造）:");
    println!("    code        = {}", biz_ex.code);
    println!("    message     = {}", biz_ex.message);
    println!("    login_type  = {}", biz_ex.login_type);
    println!("    token_value = {:?}", biz_ex.token_value);
    println!("    login_id    = {:?}", biz_ex.login_id);
    println!("    extras      = {:?}", biz_ex.extras);
    println!("    Display     = {}\n", biz_ex);

    // ----------------------------------------------------------------
    // 3. GarrisonException → GarrisonError（通过 From trait 自动转换）
    // ----------------------------------------------------------------
    let err: GarrisonError = biz_ex.into();
    println!("[3] GarrisonException → GarrisonError:");
    println!("    变体 = {:?}", err);
    println!("    Display = {}\n", err);

    // ----------------------------------------------------------------
    // 4. GarrisonError → GarrisonException（反向转换，按语义映射 code）
    // ----------------------------------------------------------------
    let not_login_err = GarrisonError::NotLogin("token 缺失".to_string());
    let converted: GarrisonException = not_login_err.into();
    println!("[4] GarrisonError::NotLogin → GarrisonException:");
    println!("    code    = {}（-1 表示未登录）", converted.code);
    println!("    message = {}\n", converted.message);

    let not_perm_err = GarrisonError::NotPermission("缺少 user:delete 权限".to_string());
    let converted: GarrisonException = not_perm_err.into();
    println!(
        "    NotPermission → code = {}（-2 表示无权限）",
        converted.code
    );
    println!("    message = {}\n", converted.message);

    println!("=== 示例执行完成 ===");
    Ok(())
}
