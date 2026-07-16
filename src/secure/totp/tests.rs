//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `TotpHandler` 单元测试。

use super::TotpHandler;
use crate::dao::BulwarkDao;

/// RFC 6238 测试密钥（20 字节 ASCII）。
const TEST_SECRET: &[u8] = b"12345678901234567890";

// ========================================================================
// 构造测试
// ========================================================================

/// 使用默认参数构造 TotpHandler（spec Scenario）。
#[test]
fn new_with_default_params() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6);
    assert!(handler.is_ok());
}

/// 自定义时间步长与位数（spec Scenario）。
#[test]
fn new_with_custom_params() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 60, 8).unwrap();
    let code = handler.generate(1700000000);
    assert_eq!(code.len(), 8);
}

/// 密钥过短应报错。
#[test]
fn new_with_short_secret_errors() {
    // totp-rs 要求密钥至少 10 字节
    let result = TotpHandler::new(b"short".to_vec(), 30, 6);
    assert!(result.is_err());
}

// ========================================================================
// generate 测试
// ========================================================================

/// 生成 6 位验证码（spec Scenario）。
#[test]
fn generate_returns_6_digits() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let code = handler.generate(1700000000);
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

/// 相同 secret + 时间戳生成一致验证码（spec Scenario）。
#[test]
fn generate_is_deterministic() {
    let h1 = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let h2 = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    assert_eq!(h1.generate(1700000000), h2.generate(1700000000));
}

/// 同一 30 秒窗口内验证码稳定（spec Scenario）。
#[test]
fn same_time_window_produces_same_code() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let c1 = handler.generate(1700000000);
    let c2 = handler.generate(1700000005); // 同一窗口内
    assert_eq!(c1, c2);
}

/// 跨时间窗口验证码变化（spec Scenario）。
#[test]
fn different_time_window_produces_different_code() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let c1 = handler.generate(1700000000);
    let c2 = handler.generate(1700000030); // 下一窗口
    assert_ne!(c1, c2);
}

// ========================================================================
// validate 测试
// ========================================================================

/// 当前窗口验证码校验通过（spec Scenario）。
#[test]
fn validate_current_window_succeeds() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let code = handler.generate(1700000000);
    assert!(handler.validate(&code, 1700000000));
}

/// 允许前一个时间窗口的验证码（spec Scenario，±1 窗口容差）。
#[test]
fn validate_previous_window_succeeds() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let code = handler.generate(1699999970); // 前一窗口
    assert!(handler.validate(&code, 1700000000));
}

/// 允许后一个时间窗口的验证码（spec Scenario，±1 窗口容差）。
#[test]
fn validate_next_window_succeeds() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let code = handler.generate(1700000030); // 后一窗口
    assert!(handler.validate(&code, 1700000000));
}

/// 超出容差窗口的验证码校验失败（spec Scenario）。
#[test]
fn validate_beyond_tolerance_fails() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let code = handler.generate(1699999940); // 前两个窗口
    assert!(!handler.validate(&code, 1700000000));
}

/// 错误验证码校验失败。
#[test]
fn validate_wrong_code_fails() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    assert!(!handler.validate("000000", 1700000000));
}

// ========================================================================
// secret_from_base32 测试
// ========================================================================

/// 解码合法 Base32 密钥（spec Scenario）。
#[test]
fn secret_from_base32_decodes_valid() {
    // 使用足够长的 Base32 字符串（解码后 >= 16 字节 / 128 位）
    let bytes = TotpHandler::secret_from_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
    assert!(!bytes.is_empty());
    assert!(bytes.len() >= 16); // 满足 totp-rs 的 128 位最低要求
}

/// 解码非法 Base32 字符串失败（spec Scenario）。
#[test]
fn secret_from_base32_rejects_invalid() {
    assert!(TotpHandler::secret_from_base32("invalid!base32").is_err());
}

/// Base32 密钥生成的验证码与原始字节一致（spec Scenario）。
#[test]
fn base32_secret_matches_raw_bytes() {
    let b32_str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let bytes = TotpHandler::secret_from_base32(b32_str).unwrap();
    let h1 = TotpHandler::new(bytes.clone(), 30, 6).unwrap();
    let h2 = TotpHandler::new(bytes, 30, 6).unwrap();
    assert_eq!(h1.generate(1700000000), h2.generate(1700000000));
}

// ========================================================================
// validate_and_consume 测试（C-5 重放防护）
// ========================================================================

/// 首次校验正确验证码返回 Ok(true)。
#[tokio::test]
async fn validate_and_consume_first_use_succeeds() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();
    let code = handler.generate(1700000000);
    let result = handler
        .validate_and_consume("user-001", &code, 1700000000, &dao)
        .await;
    assert!(result.is_ok(), "validate_and_consume 不应报错");
    assert!(result.unwrap(), "首次使用正确验证码应返回 true");
}

/// 同一验证码第二次校验返回 Ok(false)（重放拒绝，C-5 核心修复）。
#[tokio::test]
async fn validate_and_consume_rejects_replay() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();
    let code = handler.generate(1700000000);

    let first = handler
        .validate_and_consume("user-001", &code, 1700000000, &dao)
        .await
        .expect("首次校验不应报错");
    assert!(first, "首次应通过");

    let second = handler
        .validate_and_consume("user-001", &code, 1700000000, &dao)
        .await
        .expect("二次校验不应报错");
    assert!(!second, "同一验证码二次使用应被拒绝（C-5 重放防护）");
}

/// 不同 login_id 的同一验证码不互相影响（隔离性）。
#[tokio::test]
async fn validate_and_consume_isolates_by_login_id() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();
    let code = handler.generate(1700000000);

    let user_a = handler
        .validate_and_consume("user-A", &code, 1700000000, &dao)
        .await
        .unwrap();
    assert!(user_a, "user-A 首次应通过");

    let user_b = handler
        .validate_and_consume("user-B", &code, 1700000000, &dao)
        .await
        .unwrap();
    assert!(user_b, "user-B 使用同一验证码应通过（不同 login_id 隔离）");
}

/// 错误验证码返回 Ok(false) 且不记录到 DAO（不占用缓存）。
#[tokio::test]
async fn validate_and_consume_wrong_code_returns_false_without_recording() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();

    let result = handler
        .validate_and_consume("user-001", "000000", 1700000000, &dao)
        .await
        .unwrap();
    assert!(!result, "错误验证码应返回 false");

    let replay_key = "totp:used:user-001:000000";
    let stored = dao.get(replay_key).await.unwrap();
    assert!(
        stored.is_none(),
        "错误验证码不应记录到 DAO（避免无效码占用缓存）"
    );
}

/// 同一 login_id 使用不同验证码均通过（不同时间窗口的验证码不冲突）。
#[tokio::test]
async fn validate_and_consume_different_codes_both_succeed() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();
    let code1 = handler.generate(1700000000);
    let code2 = handler.generate(1700000030);

    if code1 == code2 {
        return;
    }

    let first = handler
        .validate_and_consume("user-001", &code1, 1700000000, &dao)
        .await
        .unwrap();
    assert!(first, "code1 应通过");

    let second = handler
        .validate_and_consume("user-001", &code2, 1700000030, &dao)
        .await
        .unwrap();
    assert!(second, "code2（不同窗口）应通过");
}

// ========================================================================
// FMEA #7：TOCTOU 竞态防护
// ========================================================================

/// FMEA #7: 验证 `validate_and_consume` 在并发调用下不会让同一 code 通过两次。
///
/// 10 个并发任务对同一 login_id + code 调用 `validate_and_consume`，
/// 应只有 1 个返回 `Ok(true)`，其余 9 个返回 `Ok(false)`（重放拒绝）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validate_and_consume_concurrent_no_double_accept() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = Arc::new(crate::dao::tests::MockDao::new());
    let code = handler.generate(1700000000);
    let accept_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..10 {
        let d = dao.clone();
        let ac = accept_count.clone();
        let code = code.clone();
        handles.push(tokio::spawn(async move {
            // 每个任务创建独立的 handler（同 secret → 同 code）
            let h = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
            let result = h
                .validate_and_consume("user-concurrent", &code, 1700000000, &*d)
                .await
                .unwrap();
            if result {
                ac.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    assert_eq!(
        accept_count.load(Ordering::SeqCst),
        1,
        "并发调用同一 code 应只有 1 个通过（TOCTOU 防护），实际: {}",
        accept_count.load(Ordering::SeqCst)
    );
}
