//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API Key 协议过期用例（单元测试版）。
//!
//! 下沉说明（production-mock-purge T026）：原 `tests/protocol/apikey_edge_cases.rs`
//! 的 `expired_apikey_validation_fails` 依赖本地 mock DAO 的"get 不清理过期键"
//! 语义——DAO 在 key 过期后仍返回存储值，由 `ApiKeyHandler::verify` 检查
//! `ApiKeyInfo.expire_at` 字段返回 `ExpiredToken`（而非 not-found 的 `InvalidToken`）。
//!
//! 产品 `InMemoryDao` 在 `get` 时会清理已过期键并返回 `None`，`verify` 因此返回
//! `InvalidToken`。两者都拒绝过期 key，仅错误类型细分不同。为保持断言
//! "exactly ExpiredToken" 语义不变，该用例按"纯替身用例下沉"规则移入单元测试目录，
//! 保留本地 mock DAO（单元测试允许 mock）。

#![cfg(feature = "protocol-apikey")]

use async_trait::async_trait;
use garrison::dao::GarrisonDao;
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::protocol::apikey::ApiKeyHandler;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

/// 本地 mock DAO：HashMap + parking_lot::Mutex，`get` 不清理过期键。
///
/// 语义：`set` 忽略 TTL（值持久保留直至 delete），以便 handler 能从存储值读取
/// `ApiKeyInfo.expire_at` 并返回 `ExpiredToken`。这是本用例专属的故障/延迟语义，
/// 只在单元测试中使用。
struct MockDao {
    store: Mutex<HashMap<String, String>>,
}

impl MockDao {
    fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl GarrisonDao for MockDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        Ok(self.store.lock().get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
        self.store.lock().insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some(existing) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(GarrisonError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
        Ok(())
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }
    garrison::atomic_test_fallback!();
}

/// 创建 ApiKeyHandler（使用本地 mock DAO）。
fn make_handler() -> ApiKeyHandler {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    ApiKeyHandler::new(dao)
}

/// 10.3 expired_apikey_validation_fails
///
/// 验证已过期的 APIKey 校验失败，返回 `ExpiredToken` 错误。
///
/// `ApiKeyHandler::verify` 在读取 `ApiKeyInfo` 后检查 `expire_at <= now`，
/// 若已过期则返回 `ExpiredToken`。本地 mock DAO 不清理过期键，使
/// handler 的字段级过期检查可达（Return exactly `ExpiredToken`）。
#[tokio::test]
async fn expired_apikey_validation_fails() {
    let handler = make_handler();

    // 生成一个 1 秒过期的 key
    let key = handler.generate("1001", vec![], 1).await.unwrap();

    // 等待 2 秒让 key 过期
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // verify 应返回 ExpiredToken（mock DAO 保留过期值，handler 检查 expire_at 字段）
    let result = handler.verify(&key).await;
    assert!(result.is_err(), "已过期的 APIKey 校验应失败");
    match result.err() {
        Some(GarrisonError::ExpiredToken(_)) => {},
        other => panic!("期望 ExpiredToken 错误，实际: {:?}", other),
    }
}
