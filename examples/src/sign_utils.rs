//! 签名工具示例：演示 Signer 的 HMAC-SHA256/SHA512、Base64 编解码能力。
//!
//! 对应模块：`src/secure/sign/mod.rs`（feature: secure-sign）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin sign_utils --features secure-sign
//! ```

use bulwark::error::BulwarkResult;
use bulwark::secure::sign::Signer;

/// 运行签名工具示例。
///
/// 演示 HMAC-SHA256 / HMAC-SHA512 签名、Base64 编解码互逆、密钥隔离。
pub fn run() -> BulwarkResult<()> {
    println!("=== Bulwark 签名工具示例 ===\n");

    let secret = b"my-hmac-secret";
    let data = b"POST /api/v1/users\n{\"name\":\"alice\"}";

    // ----------------------------------------------------------------
    // 1. HMAC-SHA256 签名（微服务网关签名认证常用算法）
    // ----------------------------------------------------------------
    let sig_256 = Signer::hmac_sha256(secret, data);
    println!("[1] HMAC-SHA256:");
    println!("    secret = {}", String::from_utf8_lossy(secret));
    println!("    data   = {}", String::from_utf8_lossy(data));
    println!("    签名   = {}", sig_256);
    println!(
        "    长度   = {} 字符（256 bit = 32 字节 → 64 hex）\n",
        sig_256.len()
    );
    assert_eq!(sig_256.len(), 64);

    // ----------------------------------------------------------------
    // 2. HMAC-SHA512 签名（更高安全级别）
    // ----------------------------------------------------------------
    let sig_512 = Signer::hmac_sha512(secret, data);
    println!("[2] HMAC-SHA512:");
    println!("    签名   = {}", sig_512);
    println!(
        "    长度   = {} 字符（512 bit = 64 字节 → 128 hex）\n",
        sig_512.len()
    );
    assert_eq!(sig_512.len(), 128);

    // 相同输入多次调用返回一致结果（确定性）
    assert_eq!(sig_256, Signer::hmac_sha256(secret, data));
    println!("    ✓ 相同输入确定性一致\n");

    // ----------------------------------------------------------------
    // 3. Base64 编码与解码互逆
    // ----------------------------------------------------------------
    let original = "Hello, Bulwark! 签名工具测试";
    let original_bytes = original.as_bytes();
    let encoded = Signer::base64_encode(original_bytes);
    let decoded = Signer::base64_decode(&encoded)?;
    println!("[3] Base64 编解码:");
    println!("    原始   = {}", original);
    println!("    编码   = {}", encoded);
    println!("    解码   = {}", String::from_utf8_lossy(&decoded));
    assert_eq!(decoded, original_bytes);
    println!("    ✓ 编解码互逆一致\n");

    // ----------------------------------------------------------------
    // 4. 不同 secret 产生不同签名（密钥隔离）
    // ----------------------------------------------------------------
    let sig_a = Signer::hmac_sha256(b"secret-A", data);
    let sig_b = Signer::hmac_sha256(b"secret-B", data);
    assert_ne!(sig_a, sig_b);
    println!("[4] 不同 secret 产生不同签名: ✓\n");

    println!("=== 示例执行完成 ===");
    Ok(())
}
