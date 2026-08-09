//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 常量时间比较示例：演示 `constant_time_eq` 防止时序侧信道攻击。
//!
//! 对应模块：`src/secure/ct_eq.rs`（`secure-ct-eq` feature 开启时可用）。
//!
//! 适用场景：
//! - HMAC 签名验证
//! - API Key / Token 哈希比对
//! - PKCE code_challenge 校验
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin constant_time_eq --features "secure-ct-eq"
//! ```

use garrison::error::GarrisonResult;
use garrison::secure::ct_eq::constant_time_eq;

/// 运行常量时间比较示例。
///
/// 演示 `constant_time_eq` 的正确用法与注意事项。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 常量时间比较示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 基本比较
    // ----------------------------------------------------------------
    println!("[1] 基本比较:");
    let a = b"hello";
    let b = b"hello";
    let c = b"world";
    println!(
        "    constant_time_eq(b\"hello\", b\"hello\") = {}",
        constant_time_eq(a, b)
    );
    println!(
        "    constant_time_eq(b\"hello\", b\"world\") = {}",
        constant_time_eq(a, c)
    );
    assert!(constant_time_eq(a, b));
    assert!(!constant_time_eq(a, c));
    println!();

    // ----------------------------------------------------------------
    // 2. 长度不等
    // ----------------------------------------------------------------
    println!("[2] 长度不等:");
    let short = b"abc";
    let long = b"abcd";
    println!(
        "    constant_time_eq(b\"abc\", b\"abcd\") = {}",
        constant_time_eq(short, long)
    );
    assert!(!constant_time_eq(short, long));
    println!();

    // ----------------------------------------------------------------
    // 3. 空切片
    // ----------------------------------------------------------------
    println!("[3] 空切片:");
    let empty1: &[u8] = b"";
    let empty2: &[u8] = b"";
    println!(
        "    constant_time_eq(b\"\", b\"\") = {}",
        constant_time_eq(empty1, empty2)
    );
    assert!(constant_time_eq(empty1, empty2));
    println!();

    // ----------------------------------------------------------------
    // 4. 典型场景：API Key 哈希比对
    // ----------------------------------------------------------------
    println!("[4] 典型场景：API Key 哈希比对:");
    // 模拟存储的 key 哈希（SHA-256 = 32 bytes）
    let stored_hash = [0u8; 32];
    let provided_hash = [0u8; 32];
    let wrong_hash = {
        let mut h = [0u8; 32];
        h[31] = 1;
        h
    };

    // 先校验长度（推荐做法），再用 constant_time_eq 比较内容
    let valid =
        stored_hash.len() == provided_hash.len() && constant_time_eq(&stored_hash, &provided_hash);
    let invalid =
        stored_hash.len() == wrong_hash.len() && constant_time_eq(&stored_hash, &wrong_hash);
    println!("    正确 key hash 比对: {}", valid);
    println!("    错误 key hash 比对: {}", invalid);
    assert!(valid);
    assert!(!invalid);
    println!();

    // ----------------------------------------------------------------
    // 5. 安全提示
    // ----------------------------------------------------------------
    println!("[5] 安全提示:");
    println!("    • 禁止使用 == 比较敏感数据（HMAC/签名/token hash）");
    println!("    • == 在首字节不匹配时立即返回，攻击者可通过响应时间逐字节推断");
    println!("    • constant_time_eq 遍历全部字节，执行时间与是否匹配无关");
    println!("    • 调用前应先校验输入长度，异常长度直接返回失败");
    println!();

    println!("=== 示例执行完成 ===");
    Ok(())
}
