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

    const BLOCKS: usize = 20;
    const BLOCK_SIZE: usize = 1000; // 共 20000 次/侧

    // 预热：避免首次编译/缓存影响
    for _ in 0..100 {
        let _ = Signer::verify_hmac_sha256(secret, data, &valid_sig);
        let _ = Signer::verify_hmac_sha256(secret, data, &invalid_sig);
    }

    // 交错块测量（ABAB…）：交替计时两侧各 BLOCK_SIZE 次，抵消并行负载的
    // 慢漂移（Phase 4 去 flaky：串行分窗在负载波动下出现偶发 8x+ 假阳性）。
    let mut valid_nanos: u128 = 0;
    let mut invalid_nanos: u128 = 0;
    for _ in 0..BLOCKS {
        let start = Instant::now();
        for _ in 0..BLOCK_SIZE {
            let _ = Signer::verify_hmac_sha256(secret, data, &valid_sig);
        }
        valid_nanos += start.elapsed().as_nanos();

        let start = Instant::now();
        for _ in 0..BLOCK_SIZE {
            let _ = Signer::verify_hmac_sha256(secret, data, &invalid_sig);
        }
        invalid_nanos += start.elapsed().as_nanos();
    }

    // 常量时间比较：错误签名不应明显快于正确签名（阈值 4x，交错后噪声大幅收敛）。
    // 守卫边界（三维审查 L 记录）：本测试可捕获「跳过 HMAC/整段比较」类数量级
    // 回归；「naive 逐字节 ==」类回归耗时比≈1.0-1.2（HMAC 计算占主导），
    // 无法由时序测试捕获——该类由实现侧 constant-time 原语（subtle 全长比较）
    // 保证，见 signer.rs；本测试为防回归粗筛而非时序侧信道唯一防线。
    let ratio = if invalid_nanos < valid_nanos {
        valid_nanos as f64 / invalid_nanos.max(1) as f64
    } else {
        invalid_nanos as f64 / valid_nanos.max(1) as f64
    };
    assert!(
        ratio < 4.0,
        "时序差异过大 ratio={:.2}, valid_ns={}, invalid_ns={}（常量时间比较失败）",
        ratio,
        valid_nanos,
        invalid_nanos
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

// ========================================================================
// DEEP-02 死代码守卫：constant_time_eq_manual fallback 已移除
// ========================================================================

/// DEEP-02: 验证 signer.rs 已移除 `constant_time_eq_manual` 手动 fallback。
///
/// 审查发现：`verify_hmac_sha256` 中 `#[cfg(not(feature = "subtle"))]` 分支引用的
/// `constant_time_eq_manual` 与 `secure::ct_eq::constant_time_eq` /
/// `server::middleware::constant_time_eq` 功能重复；且因 `secure-sign` feature
/// 强制启用 `dep:subtle`（signer 模块仅在 secure-sign 下编译），该 fallback
/// 是**永远不可达的死代码**。
///
/// 源码级守卫测试（与 E3 模式一致）：过滤注释后断言真实代码不再包含
/// `constant_time_eq_manual` 标识符与 `not(subtle)` 分支，防止回归重新引入重复实现。
#[test]
fn deep02_signer_has_no_manual_constant_time_fallback() {
    let source = include_str!("signer.rs");
    let code_only: String = source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !(trimmed.starts_with("//!") || trimmed.starts_with("///") || trimmed.starts_with("//"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code_only.contains("constant_time_eq_manual"),
        "DEEP-02: signer.rs 不应再包含 constant_time_eq_manual 手动 fallback（死代码）"
    );
    assert!(
        !code_only.contains("#[cfg(not(feature = \"subtle\"))]"),
        "DEEP-02: signer.rs 不应再有 not(subtle) 分支（secure-sign 恒启用 subtle）"
    );
}
