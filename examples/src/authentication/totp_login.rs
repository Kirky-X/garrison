//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! TOTP 二次验证（2FA）示例：演示 `TotpHandler` 生成 / 校验动态验证码（依据 spec secure-totp）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin totp_login --features secure-totp
//! ```
//!
//! 本示例演示二步验证流程：
//! 1. 用户已通过密码登录（第一步）
//! 2. 系统要求输入 TOTP 验证码（第二步）
//! 3. `TotpHandler::validate` 校验通过则完成 2FA
//!
//! RFC 6238 默认 SHA1 算法，兼容 Google Authenticator / Microsoft Authenticator 等。

use bulwark::error::BulwarkResult;
use bulwark::secure::totp::TotpHandler;

/// 运行 TOTP 二次验证示例。
///
/// 演示 TotpHandler 的 generate 生成验证码、validate 校验、
/// ±1 时间窗口偏差容忍、错误验证码被拒、Base32 密钥解码。
pub fn run() -> BulwarkResult<()> {
    println!("=== Bulwark TOTP 二次验证示例 ===\n");

    // 1. 用户密钥（20 字节，RFC 6238 推荐长度）
    //    生产环境每个用户应有独立密钥，存于安全位置（加密存储）
    let secret = b"12345678901234567890".to_vec();

    // 2. 创建 TotpHandler（30 秒步长，6 位验证码，±1 时间窗口偏差）
    let handler = TotpHandler::new(secret, 30, 6).expect("TOTP 初始化失败");

    // 3. 模拟当前时间（实际场景用 SystemTime::now()）
    let now: i64 = 1700000000;

    // 4. 生成当前验证码（用户从 Authenticator App 看到的数字）
    let code = handler.generate(now);
    println!("[生成] 当前时间的 TOTP 验证码：{}", code);
    assert_eq!(code.len(), 6, "6 位验证码");

    // 5. 校验用户输入的验证码
    println!("[校验] 用户输入验证码 {} ...", code);
    if handler.validate(&code, now) {
        println!("       校验通过，2FA 完成");
    } else {
        println!("       校验失败");
    }

    // 6. 演示时间窗口偏差容忍（±1 个 30 秒窗口）
    let prev_window = now - 30;
    if handler.validate(&code, prev_window) {
        println!("[偏差] 前一窗口的验证码仍校验通过（±1 窗口容忍）");
    }

    let future_window = now + 30;
    if handler.validate(&code, future_window) {
        println!("[偏差] 后一窗口的验证码仍校验通过（±1 窗口容忍）");
    }

    // 7. 演示错误验证码被拒
    let wrong_code = "000000";
    if !handler.validate(wrong_code, now) {
        println!("[异常] 错误验证码 {} 被拒绝（预期）", wrong_code);
    }

    // 8. 演示从 Base32 密钥解码（兼容 Google Authenticator otpauth URI 的 secret）
    // RFC 6238 标准测试向量（"12345678901234567890" 的 Base32），仅用于示例演示。
    // 生产环境务必从环境变量或安全存储（如 Vault/KMS）获取密钥，切勿硬编码。
    let base32_secret = std::env::var("TOTP_EXAMPLE_SECRET")
        .unwrap_or_else(|_| "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string()); // nosemgrep: generic.secrets.security.detected-generic-secret
    match TotpHandler::secret_from_base32(&base32_secret) {
        Ok(bytes) => {
            println!("[解码] Base32 密钥解码成功，{} 字节", bytes.len());
            let handler2 = TotpHandler::new(bytes, 30, 6).expect("TOTP 初始化失败");
            let code2 = handler2.generate(now);
            println!("       解码密钥生成的验证码：{}", code2);
        },
        Err(e) => println!("[解码] Base32 解码失败：{}", e),
    }

    println!("\n=== 示例完成 ===");
    Ok(())
}
