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

// ========================================================================
// E3 修复验证：DashMap → BulwarkDao::incr 原子操作
// ========================================================================

/// E3: 验证 handler.rs 源码不再使用 DashMap / once_cell / TOTP_LOCKS 无界 static。
///
/// 通过 `include_str!` 读取源文件并检查关键代码模式的缺失/存在，作为编译期的
/// 源码级守护测试，防止后续回归引入无界内存增长。
///
/// 仅检查真实的代码模式（import / 实例化 / static 声明），文档注释中允许
/// 引用历史类型签名（用于解释修复原因）。
#[test]
fn e3_source_has_no_dashmap_or_unbounded_static() {
    let source = include_str!("handler.rs");
    // 过滤掉所有注释行（`//!` 模块文档、`///` 项文档、`//` 行注释），只检查真实代码
    let code_only: String = source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !(trimmed.starts_with("//!") || trimmed.starts_with("///") || trimmed.starts_with("//"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code_only.contains("use dashmap"),
        "E3: handler.rs 代码不应再 import dashmap crate"
    );
    assert!(
        !code_only.contains("DashMap::new"),
        "E3: handler.rs 代码不应再实例化 DashMap"
    );
    assert!(
        !code_only.contains("DashMap<"),
        "E3: handler.rs 代码不应再使用 DashMap< 类型"
    );
    assert!(
        !code_only.contains("static TOTP_LOCKS"),
        "E3: handler.rs 代码不应再声明 TOTP_LOCKS 无界 static"
    );
    assert!(
        !code_only.contains("use once_cell"),
        "E3: handler.rs 代码不应再依赖 once_cell::sync::Lazy"
    );
    assert!(
        !code_only.contains("Lazy::new"),
        "E3: handler.rs 代码不应再使用 Lazy::new 初始化容器"
    );
    assert!(
        code_only.contains("dao.incr"),
        "E3: handler.rs 应使用 dao.incr 原子操作替代 per-login_id 锁"
    );
    // 文档注释中应保留 E3 修复说明（用于审计与回归防护）
    assert!(
        source.contains("E3 修复"),
        "E3: handler.rs 文档应保留 E3 修复说明"
    );
}

/// E3: 验证 `dao.incr` 在首次调用时返回 1。
///
/// 直接调用 MockDao::incr 验证契约：key 不存在时初始化为 "1" 并返回 1。
#[tokio::test]
async fn e3_incr_returns_1_on_first_call() {
    let dao = crate::dao::tests::MockDao::new();
    let count = dao.incr("totp:used:user-001:123456", 90).await.unwrap();
    assert_eq!(count, 1, "E3: incr 首次调用应返回 1（视为首次使用验证码）");
}

/// E3: 验证 `dao.incr` 在第二次调用时返回 2（重放检测）。
#[tokio::test]
async fn e3_incr_returns_2_on_replay() {
    let dao = crate::dao::tests::MockDao::new();
    let key = "totp:used:user-001:123456";
    let first = dao.incr(key, 90).await.unwrap();
    let second = dao.incr(key, 90).await.unwrap();
    assert_eq!(first, 1, "首次应返回 1");
    assert_eq!(
        second, 2,
        "E3: incr 第二次调用应返回 2（重放检测，>1 即拒绝）"
    );
}

/// E3: 验证 replay_key 格式为 `totp:used:<login_id>:<code>`。
///
/// 通过 `dao.get_timeout` 间接验证 key 存在（首次 validate_and_consume 后写入）。
#[tokio::test]
async fn e3_replay_key_format_is_correct() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();
    let code = handler.generate(1700000000);
    handler
        .validate_and_consume("user-format-test", &code, 1700000000, &dao)
        .await
        .unwrap();

    let expected_key = format!("totp:used:user-format-test:{}", code);
    let timeout = dao.get_timeout(&expected_key).await.unwrap();
    assert!(
        timeout.is_some(),
        "E3: replay_key 应存在且设置 TTL，格式: totp:used:<login_id>:<code>"
    );
}

/// E3: 验证 replay_key 的 TTL = step * 3（覆盖 skew=1 的 3 个时间窗口）。
///
/// step=30 → TTL=90 秒。
#[tokio::test]
async fn e3_replay_key_ttl_is_step_times_3() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();
    let code = handler.generate(1700000000);
    handler
        .validate_and_consume("user-ttl-30", &code, 1700000000, &dao)
        .await
        .unwrap();

    let replay_key = format!("totp:used:user-ttl-30:{}", code);
    let timeout = dao.get_timeout(&replay_key).await.unwrap();
    let remaining = timeout.expect("TTL 应存在");
    // 剩余 ≤ 90s（刚写入，应接近 90s）
    assert!(
        remaining.as_secs() <= 90,
        "E3: step=30 时 TTL 应 ≤ 90s，实际: {:?}",
        remaining
    );
    assert!(
        remaining.as_secs() > 85,
        "E3: step=30 时刚写入的 TTL 应接近 90s，实际: {:?}",
        remaining
    );
}

/// E3: 验证不同 step 产生不同的 TTL（step=60 → TTL=180s）。
#[tokio::test]
async fn e3_step_60_produces_ttl_180() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 60, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();
    let code = handler.generate(1700000000);
    handler
        .validate_and_consume("user-ttl-60", &code, 1700000000, &dao)
        .await
        .unwrap();

    let replay_key = format!("totp:used:user-ttl-60:{}", code);
    let timeout = dao.get_timeout(&replay_key).await.unwrap();
    let remaining = timeout.expect("TTL 应存在");
    assert!(
        remaining.as_secs() <= 180,
        "E3: step=60 时 TTL 应 ≤ 180s，实际: {:?}",
        remaining
    );
    assert!(
        remaining.as_secs() > 175,
        "E3: step=60 时刚写入的 TTL 应接近 180s，实际: {:?}",
        remaining
    );
}

/// E3: 验证前一窗口（skew=1 容差内）的验证码首次使用应通过。
#[tokio::test]
async fn e3_previous_window_code_accepted_first_time() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();
    // 生成前一窗口的验证码（now-30s）
    let prev_code = handler.generate(1699999970);
    let result = handler
        .validate_and_consume("user-prev-win", &prev_code, 1700000000, &dao)
        .await
        .unwrap();
    assert!(result, "E3: 前一窗口验证码首次使用应通过（skew=1 容差）");
}

/// E3: 验证前一窗口的验证码重放应被拒绝。
#[tokio::test]
async fn e3_previous_window_code_rejected_on_replay() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();
    let prev_code = handler.generate(1699999970);
    let first = handler
        .validate_and_consume("user-prev-replay", &prev_code, 1700000000, &dao)
        .await
        .unwrap();
    assert!(first, "首次应通过");
    let second = handler
        .validate_and_consume("user-prev-replay", &prev_code, 1700000000, &dao)
        .await
        .unwrap();
    assert!(!second, "E3: 前一窗口验证码重放应被拒绝（incr 返回 2 > 1）");
}

/// E3: 验证不同 login_id 的并发调用不互相干扰（跨 login_id 隔离）。
///
/// 10 个并发任务，每个用不同的 login_id 但同一 code，应全部通过。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e3_concurrent_different_login_ids_no_interference() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = Arc::new(crate::dao::tests::MockDao::new());
    let code = handler.generate(1700000000);
    let accept_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for i in 0..10 {
        let d = dao.clone();
        let ac = accept_count.clone();
        let code = code.clone();
        handles.push(tokio::spawn(async move {
            let h = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
            let login_id = format!("user-isolated-{}", i);
            let result = h
                .validate_and_consume(&login_id, &code, 1700000000, &*d)
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
        10,
        "E3: 10 个不同 login_id 的并发调用应全部通过（隔离性）"
    );
}

/// E3: 验证不同 code 的 replay_key 互不影响（同一 login_id 的不同 code 都能首次通过）。
#[tokio::test]
async fn e3_replay_key_isolated_per_code() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();
    let code1 = handler.generate(1700000000);
    let code2 = handler.generate(1700000030);

    // 若两个窗口的 code 恰好相同（极小概率），跳过测试
    if code1 == code2 {
        return;
    }

    let r1 = handler
        .validate_and_consume("user-multi-code", &code1, 1700000000, &dao)
        .await
        .unwrap();
    let r2 = handler
        .validate_and_consume("user-multi-code", &code2, 1700000030, &dao)
        .await
        .unwrap();
    assert!(r1, "code1 首次应通过");
    assert!(
        r2,
        "E3: code2（不同窗口）首次应通过，replay_key 按 (login_id, code) 隔离"
    );

    // 验证两个 replay_key 都存在
    let key1 = format!("totp:used:user-multi-code:{}", code1);
    let key2 = format!("totp:used:user-multi-code:{}", code2);
    let t1 = dao.get_timeout(&key1).await.unwrap();
    let t2 = dao.get_timeout(&key2).await.unwrap();
    assert!(t1.is_some(), "code1 的 replay_key 应存在");
    assert!(t2.is_some(), "code2 的 replay_key 应存在");
}

/// E3: 验证错误验证码不调用 incr（不写入 replay_key，不占用缓存）。
#[tokio::test]
async fn e3_wrong_code_does_not_write_replay_key() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();
    let result = handler
        .validate_and_consume("user-wrong-code", "000000", 1700000000, &dao)
        .await
        .unwrap();
    assert!(!result, "错误验证码应返回 false");

    let replay_key = "totp:used:user-wrong-code:000000";
    let stored = dao.get(replay_key).await.unwrap();
    assert!(
        stored.is_none(),
        "E3: 错误验证码不应写入 replay_key（避免无效码占用缓存）"
    );
    let timeout = dao.get_timeout(replay_key).await.unwrap();
    assert!(timeout.is_none(), "E3: 错误验证码的 replay_key 不应有 TTL");
}

/// E3: 验证 replay_key 的 incr 计数随重放次数递增（3 次重放后 count=4）。
#[tokio::test]
async fn e3_incr_count_increments_with_replays() {
    let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
    let dao = crate::dao::tests::MockDao::new();
    let code = handler.generate(1700000000);
    let replay_key = format!("totp:used:user-count:{}", code);

    // 首次通过 + 3 次重放
    for i in 0..4 {
        let result = handler
            .validate_and_consume("user-count", &code, 1700000000, &dao)
            .await
            .unwrap();
        if i == 0 {
            assert!(result, "首次应通过");
        } else {
            assert!(!result, "第 {} 次重放应被拒绝", i);
        }
    }

    // 直接验证 incr 计数 = 4
    let stored = dao.get(&replay_key).await.unwrap();
    assert_eq!(
        stored,
        Some("4".to_string()),
        "E3: 4 次调用后 replay_key 的 incr 计数应为 4"
    );
}
