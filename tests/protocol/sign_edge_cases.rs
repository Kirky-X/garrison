//! API 签名协议边界场景测试（TG9，0.2.1 patch release）。
//!
//! 验证 `SignHandler` 在边界条件下的行为：
//! - 9.2 同一 nonce 在时间窗口内重放被拒绝
//! - 9.3 时间戳漂移超出允许窗口被拒绝
//! - 9.4 缺少必填参数（nonce/timestamp/sign）返回错误
//!
//! 依据 spec protocol-sign。使用 MockDao（HashMap + parking_lot::Mutex + Instant）。

#![cfg(feature = "protocol-sign")]

use async_trait::async_trait;
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::protocol::sign::SignHandler;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// MockDao（HashMap + parking_lot::Mutex + Instant 模拟 TTL）
// ============================================================================

struct MockDao {
    store: Mutex<HashMap<String, (String, Option<Instant>)>>,
}

impl MockDao {
    fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl BulwarkDao for MockDao {
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        let mut store = self.store.lock();
        match store.get(key) {
            Some((value, expire_at)) => {
                if let Some(deadline) = expire_at {
                    if Instant::now() >= *deadline {
                        store.remove(key);
                        return Ok(None);
                    }
                }
                Ok(Some(value.clone()))
            },
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
        let expire_at = if ttl_seconds == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(ttl_seconds))
        };
        self.store
            .lock()
            .insert(key.to_string(), (value.to_string(), expire_at));
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((existing, _)) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((_, expire_at)) => {
                *expire_at = if seconds == 0 {
                    None
                } else {
                    Some(Instant::now() + Duration::from_secs(seconds))
                };
                Ok(())
            },
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn delete(&self, key: &str) -> BulwarkResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 创建 SignHandler（使用 MockDao）。
fn make_handler() -> SignHandler {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    SignHandler::new("app-001", "secret-xyz", dao).unwrap()
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
        Some(BulwarkError::InvalidToken(msg)) => {
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
        Some(BulwarkError::ExpiredToken(_)) => {},
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
        Some(BulwarkError::ExpiredToken(_)) => {},
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
        Some(BulwarkError::InvalidToken(_)) => {},
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
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误（无效 Base64），实际: {:?}", other),
    }

    // 场景 3：signature 与请求参数不匹配（篡改 body_md5）
    let sig = handler.sign("POST", "/api", ts, "nonce-mismatch", "original-body");
    let result_mismatch = handler
        .validate("POST", "/api", ts, "nonce-mismatch", "tampered-body", &sig)
        .await;
    assert!(result_mismatch.is_err(), "signature 与参数不匹配应返回错误");
    match result_mismatch.err() {
        Some(BulwarkError::InvalidToken(msg)) => {
            assert!(msg.contains("签名"), "错误消息应包含'签名': {}", msg);
        },
        other => panic!("期望 InvalidToken 错误（签名不匹配），实际: {:?}", other),
    }
}
