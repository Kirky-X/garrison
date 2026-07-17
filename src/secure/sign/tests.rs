//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `sign` 模块单元测试。

#![allow(deprecated)]

use super::Signer;

// ========================================================================
// HMAC-SHA256 测试
// ========================================================================

/// RFC 4231 Test Case 1: key=[0x0b;20], data="Hi There"。
#[test]
fn hmac_sha256_rfc4231_test_case_1() {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let result = Signer::hmac_sha256(&key, data);
    assert_eq!(result.len(), 64);
    assert_eq!(
        result,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

/// RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?"。
#[test]
fn hmac_sha256_rfc4231_test_case_2() {
    let result = Signer::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        result,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

/// 相同输入多次调用返回一致结果。
#[test]
fn hmac_sha256_deterministic() {
    let a = Signer::hmac_sha256(b"key", b"data");
    let b = Signer::hmac_sha256(b"key", b"data");
    assert_eq!(a, b);
}

/// 不同 secret 产生不同签名。
#[test]
fn hmac_sha256_different_secret_different_result() {
    let a = Signer::hmac_sha256(b"secret1", b"data");
    let b = Signer::hmac_sha256(b"secret2", b"data");
    assert_ne!(a, b);
}

// ========================================================================
// HMAC-SHA512 测试
// ========================================================================

/// RFC 4231 Test Case 1: key=[0x0b;20], data="Hi There"。
#[test]
fn hmac_sha512_rfc4231_test_case_1() {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let result = Signer::hmac_sha512(&key, data);
    assert_eq!(result.len(), 128);
    assert_eq!(
        result,
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    );
}

// ========================================================================
// Base64 测试
// ========================================================================

/// Base64 编码与解码互逆。
#[test]
fn base64_encode_decode_roundtrip() {
    let original = b"Hello, World!";
    let encoded = Signer::base64_encode(original);
    let decoded = Signer::base64_decode(&encoded).unwrap();
    assert_eq!(decoded, original);
}

/// Base64 编码已知值。
#[test]
fn base64_encode_known_values() {
    assert_eq!(Signer::base64_encode(b"hello"), "aGVsbG8=");
    assert_eq!(Signer::base64_encode(b""), "");
}

/// 解码非法 Base64 字符串失败，不 panic。
#[test]
fn base64_decode_invalid_input_errors() {
    let result = Signer::base64_decode("!!!not-base64!!!");
    assert!(result.is_err());
}

// ========================================================================
// MD5 测试
// ========================================================================

/// MD5 输出 32 字符小写十六进制，与标准值一致。
#[test]
fn md5_known_values() {
    assert_eq!(Signer::md5(b"hello"), "5d41402abc4b2a76b9719d911017c592");
    assert_eq!(Signer::md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
}

// ========================================================================
// verify_hmac_sha256 测试（D1：常量时间 HMAC 验证）
// ========================================================================

/// D1-1: 正确签名返回 true。
#[test]
fn verify_hmac_sha256_valid_signature_returns_true() {
    let secret = b"my-secret-key";
    let data = b"request-body";
    let sig = Signer::hmac_sha256(secret, data);
    assert!(Signer::verify_hmac_sha256(secret, data, &sig));
}

/// D1-2: 错误签名返回 false。
#[test]
fn verify_hmac_sha256_invalid_signature_returns_false() {
    let secret = b"my-secret-key";
    let data = b"request-body";
    let tampered = "0".repeat(64);
    assert!(!Signer::verify_hmac_sha256(secret, data, &tampered));
}

/// D1-3: 长度不符的签名返回 false（不 panic）。
#[test]
fn verify_hmac_sha256_wrong_length_signature_returns_false() {
    let secret = b"my-secret-key";
    let data = b"request-body";
    assert!(!Signer::verify_hmac_sha256(secret, data, "tooshort"));
    assert!(!Signer::verify_hmac_sha256(secret, data, ""));
}

/// D1-4: secret 不匹配时返回 false。
#[test]
fn verify_hmac_sha256_wrong_secret_returns_false() {
    let sig = Signer::hmac_sha256(b"secret-a", b"data");
    assert!(!Signer::verify_hmac_sha256(b"secret-b", b"data", &sig));
}

/// D1-5: data 不匹配时返回 false。
#[test]
fn verify_hmac_sha256_wrong_data_returns_false() {
    let sig = Signer::hmac_sha256(b"secret", b"data-a");
    assert!(!Signer::verify_hmac_sha256(b"secret", b"data-b", &sig));
}

/// D1-6: 大小写敏感（hex 小写，传入大写应 false）。
#[test]
fn verify_hmac_sha256_case_sensitive() {
    let sig = Signer::hmac_sha256(b"secret", b"data");
    let upper = sig.to_uppercase();
    assert!(!Signer::verify_hmac_sha256(b"secret", b"data", &upper));
}

/// D1-7: 空数据 + 空 secret 仍可正确验证（边界）。
#[test]
fn verify_hmac_sha256_empty_inputs_boundary() {
    let sig = Signer::hmac_sha256(b"", b"");
    assert!(Signer::verify_hmac_sha256(b"", b"", &sig));
}

/// D1-8: 时序无显著差异（多次取均值，错误签名不应明显更快）。
/// 通过比较正确签名与错误签名的平均耗时，差异不应超过 3 倍。
/// 注意：时序测试有抖动，使用宽松阈值避免 flaky。
#[test]
fn verify_hmac_sha256_constant_time_no_early_return() {
    use std::time::Instant;

    let secret = b"timing-test-secret";
    let data = b"timing-test-data";
    let valid_sig = Signer::hmac_sha256(secret, data);
    // 构造首字节就不同的错误签名，确保非常量时间比较会在第一个字节就提前返回
    let mut invalid_sig = valid_sig.clone();
    // 翻转第一个字符（'0'-'9'/'a'-'f' 互换），保证首字节不同
    invalid_sig.replace_range(0..1, if &valid_sig[0..1] == "0" { "1" } else { "0" });

    const ITERATIONS: usize = 10000;

    // 预热：避免首次编译/缓存影响
    for _ in 0..100 {
        let _ = Signer::verify_hmac_sha256(secret, data, &valid_sig);
        let _ = Signer::verify_hmac_sha256(secret, data, &invalid_sig);
    }

    let start_valid = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = Signer::verify_hmac_sha256(secret, data, &valid_sig);
    }
    let valid_elapsed = start_valid.elapsed();

    let start_invalid = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = Signer::verify_hmac_sha256(secret, data, &invalid_sig);
    }
    let invalid_elapsed = start_invalid.elapsed();

    // 常量时间比较：错误签名不应明显快于正确签名
    // 阈值 3 倍：容忍 CPU 抖动与分支预测影响
    let ratio = if invalid_elapsed < valid_elapsed {
        valid_elapsed.as_nanos() as f64 / invalid_elapsed.as_nanos().max(1) as f64
    } else {
        invalid_elapsed.as_nanos() as f64 / valid_elapsed.as_nanos().max(1) as f64
    };
    assert!(
        ratio < 3.0,
        "时序差异过大 ratio={:.2}, valid={:?}, invalid={:?}（常量时间比较失败）",
        ratio,
        valid_elapsed,
        invalid_elapsed
    );
}

// ========================================================================
// Signer struct 测试
// ========================================================================

/// `Signer` 可构造且 `Default` 可用。
#[test]
fn signer_implements_default() {
    let _signer: Signer = Default::default();
}
