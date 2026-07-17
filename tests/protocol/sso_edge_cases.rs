//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SSO 协议边界场景测试（TG7，0.2.1 patch release）。
//!
//! 验证 `SsoClient` 在边界条件下的行为：
//! - 7.2 无效格式的 ticket 返回错误
//! - 7.3 centerId 映射不存在返回错误（等价为 client_id 不匹配）
//! - 7.4 并发 ticket 校验仅一个成功（一次性使用语义）
//!
//! 依据 spec protocol-sso。使用 MockDao（HashMap + parking_lot::Mutex + Instant）。

#![cfg(feature = "protocol-sso")]

use async_trait::async_trait;
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::protocol::sso::SsoClient;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// 创建 SsoClient（使用 MockDao）。
fn make_client() -> SsoClient {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    SsoClient::new(dao, "test-sso-secret-key")
}

// ============================================================================
// 边界场景测试
// ============================================================================

/// 7.2 ticket_invalid_format_returns_error
///
/// 验证无效格式的 ticket 字符串校验时返回错误。
///
/// SSO ticket 由 `issue_ticket` 生成为 64 字符 hex 字符串。此测试用明显无效的
/// 格式（短字符串、非 hex 字符）验证 `validate_ticket` 返回 `InvalidToken` 错误。
///
/// 注意：实现本身不强制 ticket 格式校验，仅依赖 DAO 查找。无效格式的 ticket
/// 在 DAO 中不存在，因此返回 `InvalidToken`（票据不存在或已过期）。
#[tokio::test]
async fn ticket_invalid_format_returns_error() {
    let client = make_client();

    // 明显无效的格式：短字符串
    let result = client.validate_ticket("short", 2001).await;
    assert!(result.is_err(), "无效格式的 ticket 应返回错误");
    match result.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }

    // 明显无效的格式：含非 hex 字符
    let result = client
        .validate_ticket("ZZZZ_invalid_ticket_string_with_non_hex_chars", 2001)
        .await;
    assert!(result.is_err(), "含非 hex 字符的 ticket 应返回错误");
    match result.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}

/// 7.3 center_id_mapping_not_found_returns_error
///
/// 验证当 centerId（在此实现中等价为 client_id）映射不存在时返回错误。
///
/// SSO 模块未实现独立的 centerId 映射概念（centerId → login_id 映射），
/// 而是通过 `client_id` 参数实现客户端隔离。此测试验证：用未注册的 client_id
/// 校验已签发的 ticket 时，返回 `InvalidToken` 错误（client_id 不匹配，0.4.1 修复 M5：
/// 原为 Config，现改为 InvalidToken，认证失败语义更准确），等价于
/// "centerId 映射不存在"的语义。
#[tokio::test]
async fn center_id_mapping_not_found_returns_error() {
    let client = make_client();

    // 为 client_id=2001 签发 ticket
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();

    // 用未注册的 client_id=9999（映射不存在）校验 → 应返回 InvalidToken 错误（M5 修复）
    let result = client.validate_ticket(&ticket, 9999).await;
    assert!(result.is_err(), "未注册的 client_id 应返回错误");
    match result.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!(
            "期望 InvalidToken 错误（client_id 不匹配），实际: {:?}",
            other
        ),
    }
}

/// 7.4 concurrent_ticket_validation_only_one_succeeds
///
/// 验证同一 ticket 在并发校验时仅一个成功（一次性使用语义）。
///
/// `validate_ticket` 在校验成功后立即从 DAO 删除 ticket。由于 MockDao 使用
/// `parking_lot::Mutex`（同步锁），并发校验会被串行化，确保仅第一个校验成功，
/// 其余因 ticket 已删除而失败。
#[tokio::test]
async fn concurrent_ticket_validation_only_one_succeeds() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    // 使用 Arc<SsoClient> 以便在多个并发任务间共享
    let client = Arc::new(SsoClient::new(dao, "test-sso-secret-key"));

    // 签发一个 ticket
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();

    // 并发校验同一 ticket：3 个任务同时执行
    // 通过 Arc<SsoClient> 共享客户端实例（内部 Arc<dyn BulwarkDao> 共享 DAO）
    let c1 = client.clone();
    let c2 = client.clone();
    let c3 = client.clone();
    let t1 = ticket.clone();
    let t2 = ticket.clone();
    let t3 = ticket.clone();

    let (r1, r2, r3) = tokio::join!(
        async move { c1.validate_ticket(&t1, 2001).await },
        async move { c2.validate_ticket(&t2, 2001).await },
        async move { c3.validate_ticket(&t3, 2001).await },
    );

    let results = [r1, r2, r3];
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let failures = results.iter().filter(|r| r.is_err()).count();

    assert_eq!(
        successes, 1,
        "并发校验仅一个应成功，实际成功数: {}",
        successes
    );
    assert_eq!(
        failures, 2,
        "并发校验应有两个失败，实际失败数: {}",
        failures
    );

    // 失败的应返回 InvalidToken（票据不存在或已过期）
    for r in &results {
        if r.is_err() {
            match r.as_ref().err() {
                Some(BulwarkError::InvalidToken(_)) => {},
                other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
            }
        }
    }
}
