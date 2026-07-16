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
// Signer struct 测试
// ========================================================================

/// `Signer` 可构造且 `Default` 可用。
#[test]
fn signer_implements_default() {
    let _signer: Signer = Default::default();
}
