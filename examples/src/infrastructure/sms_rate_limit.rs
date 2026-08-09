//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SMS 验证码限速示例：演示渐进式短信限速配置与使用。
//!
//! 对应模块：`src/secure/sms/`（`sms-rate-limit` feature 开启时可用）。
//!
//! 限速策略：
//! - 每小时上限（hourly_limit）
//! - 每天上限（daily_limit）
//! - 连续未验证检测（异常发送不验证 → 标记为可疑号码）
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin sms_rate_limit --features "sms-rate-limit"
//! ```

use garrison::error::GarrisonResult;

/// 运行 SMS 验证码限速示例。
///
/// 演示 SMS 限速的 key 空间设计与限速策略。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison SMS 验证码限速示例 ===\n");

    // ----------------------------------------------------------------
    // 1. Key 空间设计
    // ----------------------------------------------------------------
    println!("[1] SMS 限速 Key 空间:");
    println!("    sms:rate:{{phone}}:hour:{{bucket}}  | 3600s  | 小时限速计数器");
    println!("    sms:rate:{{phone}}:day:{{date}}     | 86400s | 天限速计数器");
    println!("    sms:code:{{phone}}                  | 300s   | 验证码");
    println!("    sms:attempts:{{phone}}              | 300s   | 验证尝试次数");
    println!("    sms:unverified:{{phone}}            | 86400s | 连续未验证计数器");
    println!();

    // ----------------------------------------------------------------
    // 2. 限速配置
    // ----------------------------------------------------------------
    println!("[2] 限速配置说明:");
    println!("    • hourly_limit: 每小时每号码最大发送量（如 5 条/小时）");
    println!("    • daily_limit:  每天每号码最大发送量（如 20 条/天）");
    println!("    • max_verify_attempts: 验证码最大验证尝试次数（如 3 次）");
    println!("    • unverified_threshold: 连续未验证次数阈值（超过标记为可疑）");
    println!();

    // ----------------------------------------------------------------
    // 3. 使用流程
    // ----------------------------------------------------------------
    println!("[3] 典型使用流程:");
    println!("    1. 用户请求发送验证码 → SmsRateLimiter.check_rate(phone)");
    println!("       → 检查小时/天限速 → 通过则生成验证码并发送");
    println!("    2. 用户提交验证码 → SmsVerificationService.verify(phone, code)");
    println!("       → 比对验证码 → 成功则清除 attempts/unverified 计数");
    println!("       → 失败则递增 attempts → 超过 max_verify_attempts 则验证码失效");
    println!("    3. 异常检测: 连续发送但不验证 → unverified 计数递增");
    println!("       → 超过 unverified_threshold → 标记为可疑号码");
    println!();

    // ----------------------------------------------------------------
    // 4. 安全约束
    // ----------------------------------------------------------------
    println!("[4] 安全约束:");
    println!("    • 手机号不能包含 ':'（防止 key 注入）");
    println!("    • 验证码使用 OsRng 密码学安全随机数生成器");
    println!("    • 所有计数器通过 DistributedLimiter 原子递增");
    println!("    • SmsSender trait 由业务方实现（Garrison 不内置短信发送）");
    println!();

    println!("=== 示例执行完成 ===");
    Ok(())
}
