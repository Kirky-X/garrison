//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API 签名协议边界场景测试（TG9，0.2.1 patch release）。
//!
//! 验证 `SignHandler` 在边界条件下的行为：
//! - 9.2 同一 nonce 在时间窗口内重放被拒绝
//! - 9.3 时间戳漂移超出允许窗口被拒绝
//! - 9.4 缺少必填参数（nonce/timestamp/sign）返回错误
//!
//! 依据 spec protocol-sign。使用产品内存 Dao 实现 `InMemoryDao`（garrison::dao::InMemoryDao）。

#![cfg(feature = "protocol-sign")]

use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::error::GarrisonError;
use garrison::protocol::sign::SignHandler;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// 辅助函数
// ============================================================================

/// 创建 SignHandler（使用产品 InMemoryDao）。
fn make_handler() -> SignHandler {
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    // app_secret 最小 32 字节
    SignHandler::new("app-001", "test-secret-key-with-32-bytes!!!", dao).unwrap()
}

/// 获取当前 Unix 时间戳（秒）。
fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ============================================================================
// 边界场景测试
// ============================================================================

/// 9.2 nonce_replay_within_window_rejected
///
/// 验证同一 nonce 在时间窗口内重放被拒绝。
///
/// `SignHandler::validate` 在校验成功后将 nonce 存入 DAO（TTL = timestamp_window）。
/// 第二次使用同一 nonce 校验时，DAO 中已存在该 nonce → 返回 `InvalidToken`。
#[tokio::test]
async fn nonce_replay_within_window_rejected() {
    let handler = make_handler();
    let ts = now_ts();
    let nonce = "nonce-replay-test-001";
    let sig = handler.sign("POST", "/api/v1/data", ts, nonce, "body-md5-hash");

    // 第一次校验：成功
    let first = handler
        .validate("POST", "/api/v1/data", ts, nonce, "body-md5-hash", &sig)
        .await;
    assert!(first.is_ok(), "首次校验应成功");

    // 第二次校验同一 nonce：被拒绝（重放检测）
    let second = handler
        .validate("POST", "/api/v1/data", ts, nonce, "body-md5-hash", &sig)
        .await;
    assert!(second.is_err(), "同一 nonce 重放应被拒绝");
    match second.err() {
        Some(GarrisonError::InvalidToken(msg)) => {
            assert!(msg.contains("nonce"), "错误消息应包含 nonce: {}", msg);
        },
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}

/// 9.3 timestamp_drift_beyond_window_rejected
///
/// 验证时间戳漂移超出允许窗口被拒绝。
///
/// `SignHandler::validate` 默认时间戳窗口为 300 秒。当请求时间戳与当前时间
/// 的差值超过 300 秒（过去或未来）时，返回 `ExpiredToken` 错误。
#[tokio::test]
async fn timestamp_drift_beyond_window_rejected() {
    let handler = make_handler();
    let now = now_ts();

    // 过去时间戳：超出 300 秒窗口（400 秒前）
    let past_ts = now - 400;
    let sig_past = handler.sign("POST", "/api", past_ts, "nonce-past-drift", "body");
    let result_past = handler
        .validate(
            "POST",
            "/api",
            past_ts,
            "nonce-past-drift",
            "body",
            &sig_past,
        )
        .await;
    assert!(result_past.is_err(), "过去时间戳超出窗口应被拒绝");
    match result_past.err() {
        Some(GarrisonError::ExpiredToken(_)) => {},
        other => panic!("期望 ExpiredToken 错误（过去时间戳），实际: {:?}", other),
    }

    // 未来时间戳：超出 300 秒窗口（400 秒后）
    let future_ts = now + 400;
    let sig_future = handler.sign("POST", "/api", future_ts, "nonce-future-drift", "body");
    let result_future = handler
        .validate(
            "POST",
            "/api",
            future_ts,
            "nonce-future-drift",
            "body",
            &sig_future,
        )
        .await;
    assert!(result_future.is_err(), "未来时间戳超出窗口应被拒绝");
    match result_future.err() {
        Some(GarrisonError::ExpiredToken(_)) => {},
        other => panic!("期望 ExpiredToken 错误（未来时间戳），实际: {:?}", other),
    }
}

/// 9.4 missing_required_params_returns_error
///
/// 验证缺少必填参数（nonce/timestamp/sign）时返回错误。
///
/// `SignHandler::validate` 需要所有参数均有效：
/// - 空 nonce：会通过签名校验（nonce 参与签名计算），但首次校验后空 nonce 会被存入 DAO
/// - 无效签名（空字符串）：Base64 解码失败 → `InvalidToken`
/// - 空 signature 配合有效 nonce + 有效 timestamp：签名校验失败
#[tokio::test]
async fn missing_required_params_returns_error() {
    let handler = make_handler();
    let ts = now_ts();

    // 场景 1：空 signature → Base64 解码失败 → InvalidToken
    let result_empty_sig = handler
        .validate("POST", "/api", ts, "nonce-empty-sig", "body", "")
        .await;
    assert!(result_empty_sig.is_err(), "空 signature 应返回错误");
    match result_empty_sig.err() {
        Some(GarrisonError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误（空 signature），实际: {:?}", other),
    }

    // 场景 2：无效 Base64 signature → 解码失败 → InvalidToken
    let result_invalid_sig = handler
        .validate(
            "POST",
            "/api",
            ts,
            "nonce-invalid-sig",
            "body",
            "!!!invalid-base64!!!",
        )
        .await;
    assert!(
        result_invalid_sig.is_err(),
        "无效 Base64 signature 应返回错误"
    );
    match result_invalid_sig.err() {
        Some(GarrisonError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误（无效 Base64），实际: {:?}", other),
    }

    // 场景 3：signature 与请求参数不匹配（篡改 body_md5）
    let sig = handler.sign("POST", "/api", ts, "nonce-mismatch", "original-body");
    let result_mismatch = handler
        .validate("POST", "/api", ts, "nonce-mismatch", "tampered-body", &sig)
        .await;
    assert!(result_mismatch.is_err(), "signature 与参数不匹配应返回错误");
    match result_mismatch.err() {
        Some(GarrisonError::InvalidToken(msg)) => {
            // detail 层英文码（sign-mismatch）；翻译层中文在 response_parts_i18n，本测试直读 GarrisonError 原始 detail
            assert!(
                msg.contains("mismatch"),
                "错误消息应包含 detail 码 'mismatch': {}",
                msg
            );
        },
        other => panic!("期望 InvalidToken 错误（签名不匹配），实际: {:?}", other),
    }
}
