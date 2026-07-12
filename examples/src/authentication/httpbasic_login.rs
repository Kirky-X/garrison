//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! HTTP Basic 认证示例：演示 RFC 7617 编解码与 Authorization Header 解析。
//!
//! 对应模块：`src/secure/httpbasic/mod.rs`（feature: secure-httpbasic）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin httpbasic_login --features secure-httpbasic
//! ```

use bulwark::error::BulwarkResult;
use bulwark::secure::httpbasic::HttpBasicAuth;

/// 运行 HTTP Basic 认证示例。
///
/// 演示 encode / decode / parse_authorization_header 以及中文特殊字符支持、
/// 非 Basic 方案拒绝。
pub fn run() -> BulwarkResult<()> {
    println!("=== Bulwark HTTP Basic 认证示例 ===\n");

    // ----------------------------------------------------------------
    // 1. encode：编码用户名密码为 Base64 凭证
    // ----------------------------------------------------------------
    let encoded = HttpBasicAuth::encode("alice", "s3cret-pass");
    println!("[1] encode:");
    println!("    user:pass = alice:s3cret-pass");
    println!("    Base64    = {}\n", encoded);

    // ----------------------------------------------------------------
    // 2. decode：解码 Base64 凭证为 Credential
    // ----------------------------------------------------------------
    let cred = HttpBasicAuth::decode(&encoded)?;
    println!("[2] decode:");
    println!("    user = {}", cred.user);
    println!("    pass = {}\n", cred.pass);
    assert_eq!(cred.user, "alice");
    assert_eq!(cred.pass, "s3cret-pass");

    // ----------------------------------------------------------------
    // 3. parse_authorization_header：解析完整 Authorization header
    // ----------------------------------------------------------------
    let header = format!("Basic {}", encoded);
    let cred_from_header = HttpBasicAuth::parse_authorization_header(&header)?;
    println!("[3] parse_authorization_header:");
    println!("    header = \"{}\"", header);
    println!("    user   = {}", cred_from_header.user);
    println!("    pass   = {}\n", cred_from_header.pass);

    // ----------------------------------------------------------------
    // 4. 支持中文与特殊字符
    // ----------------------------------------------------------------
    let encoded_cn = HttpBasicAuth::encode("张三", "密码!@#$%");
    let cred_cn = HttpBasicAuth::decode(&encoded_cn)?;
    println!("[4] 中文与特殊字符:");
    println!("    user = {}", cred_cn.user);
    println!("    pass = {}\n", cred_cn.pass);
    assert_eq!(cred_cn.user, "张三");
    assert_eq!(cred_cn.pass, "密码!@#$%");

    // ----------------------------------------------------------------
    // 5. 错误场景：非 Basic 方案
    // ----------------------------------------------------------------
    let result = HttpBasicAuth::parse_authorization_header("Bearer some.token.value");
    println!("[5] 非 Basic 方案拒绝:");
    println!("    输入 = \"Bearer some.token.value\"");
    println!("    结果 = {:?}\n", result);
    assert!(result.is_err());

    println!("=== 示例执行完成 ===");
    Ok(())
}
