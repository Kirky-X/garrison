//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use super::*;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::Mutex;

/// 测试用 Mock DAO（与 apikey 模块一致的结构）。
struct MockDao {
    data: Mutex<HashMap<String, String>>,
}

impl MockDao {
    fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl BulwarkDao for MockDao {
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        let data = self.data.lock().await;
        Ok(data.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
        let mut data = self.data.lock().await;
        data.insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
        let mut data = self.data.lock().await;
        if data.contains_key(key) {
            data.insert(key.to_string(), value.to_string());
            Ok(())
        } else {
            Err(BulwarkError::Dao("dao-key-not-found".to_string()))
        }
    }

    async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
        Ok(())
    }

    async fn delete(&self, key: &str) -> BulwarkResult<()> {
        let mut data = self.data.lock().await;
        data.remove(key);
        Ok(())
    }
}

/// 创建 handler（使用 MockDao）。
fn make_handler() -> TempCredentialHandler {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    TempCredentialHandler::new(dao)
}

// ========================================================================
// TempCredentialHandler 构造测试
// ========================================================================

/// 构造 handler（spec Scenario）。
#[test]
fn new_creates_handler() {
    let _handler = make_handler();
}

// ========================================================================
// issue 测试
// ========================================================================

/// 成功签发，key 前缀正确（spec Scenario）。
#[tokio::test]
async fn issue_returns_key_with_correct_prefix() {
    let handler = make_handler();
    let key = handler.issue("invite", "payload-data", 600).await.unwrap();
    assert!(key.starts_with("bulwark:temp:invite:"));
}

/// 复用同一 handler 多次签发返回不同 key（spec Scenario）。
#[tokio::test]
async fn issue_multiple_times_returns_different_keys() {
    let handler = make_handler();
    let k1 = handler.issue("invite", "v1", 60).await.unwrap();
    let k2 = handler.issue("invite", "v1", 60).await.unwrap();
    assert_ne!(k1, k2);
}

/// 不同 prefix 产生不同命名空间（spec Scenario）。
#[tokio::test]
async fn issue_different_prefix_different_namespace() {
    let handler = make_handler();
    let k1 = handler.issue("invite", "v1", 60).await.unwrap();
    let k2 = handler.issue("reset", "v2", 60).await.unwrap();
    assert!(k1.starts_with("bulwark:temp:invite:"));
    assert!(k2.starts_with("bulwark:temp:reset:"));
}

/// ttl_seconds <= 0 返回错误（spec Scenario）。
#[tokio::test]
async fn issue_zero_ttl_returns_error() {
    let handler = make_handler();
    let result = handler.issue("invite", "data", 0).await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
    }
}

/// prefix 包含冒号返回错误（spec Scenario）。
#[tokio::test]
async fn issue_prefix_with_colon_returns_error() {
    let handler = make_handler();
    let result = handler.issue("inv:ite", "data", 60).await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
    }
}

/// value 为空字符串允许存储（spec Scenario）。
#[tokio::test]
async fn issue_empty_value_allowed() {
    let dao = Arc::new(MockDao::new());
    let handler = TempCredentialHandler::new(dao.clone());
    let key = handler.issue("invite", "", 60).await.unwrap();
    let value = dao.get(&key).await.unwrap();
    assert_eq!(value, Some("".to_string()));
}

// ========================================================================
// get 测试
// ========================================================================

/// 读取存在的凭据，多次读取不删除（spec Scenario）。
#[tokio::test]
async fn get_returns_value_without_deleting() {
    let handler = make_handler();
    let key = handler.issue("invite", "data", 60).await.unwrap();
    let v1 = handler.get(&key).await.unwrap();
    let v2 = handler.get(&key).await.unwrap();
    assert_eq!(v1, Some("data".to_string()));
    assert_eq!(v2, Some("data".to_string()));
}

/// 读取不存在的凭据返回 None（spec Scenario）。
#[tokio::test]
async fn get_nonexistent_returns_none() {
    let handler = make_handler();
    let result = handler
        .get("bulwark:temp:invite:nonexistent")
        .await
        .unwrap();
    assert_eq!(result, None);
}

// ========================================================================
// revoke 测试
// ========================================================================

/// 撤销存在的凭据（spec Scenario）。
#[tokio::test]
async fn revoke_existing_returns_ok() {
    let handler = make_handler();
    let key = handler.issue("invite", "data", 60).await.unwrap();
    let result = handler.revoke(&key).await;
    assert!(result.is_ok());
    // 再次 get 应为 None
    let value = handler.get(&key).await.unwrap();
    assert_eq!(value, None);
}

/// 撤销不存在的凭据返回 Ok（幂等语义，spec Scenario）。
#[tokio::test]
async fn revoke_nonexistent_returns_ok() {
    let handler = make_handler();
    let result = handler.revoke("bulwark:temp:invite:nonexistent").await;
    assert!(result.is_ok());
}

// ========================================================================
// consume 测试
// ========================================================================

/// 成功消费存在的凭据（spec Scenario）。
#[tokio::test]
async fn consume_returns_value_and_deletes() {
    let handler = make_handler();
    let key = handler.issue("invite", "data", 60).await.unwrap();
    let value = handler.consume(&key).await.unwrap();
    assert_eq!(value, Some("data".to_string()));
    // 再次 consume 应为 None
    let again = handler.consume(&key).await.unwrap();
    assert_eq!(again, None);
}

/// 重复消费返回 None（spec Scenario）。
#[tokio::test]
async fn consume_twice_returns_none_second_time() {
    let handler = make_handler();
    let key = handler.issue("invite", "data", 60).await.unwrap();
    let v1 = handler.consume(&key).await.unwrap();
    let v2 = handler.consume(&key).await.unwrap();
    assert_eq!(v1, Some("data".to_string()));
    assert_eq!(v2, None);
}

/// 消费不存在的凭据返回 None（spec Scenario）。
#[tokio::test]
async fn consume_nonexistent_returns_none() {
    let handler = make_handler();
    let value = handler
        .consume("bulwark:temp:invite:nonexistent")
        .await
        .unwrap();
    assert_eq!(value, None);
}

/// revoke 后 consume 失败返回 None（spec Scenario）。
#[tokio::test]
async fn consume_after_revoke_returns_none() {
    let handler = make_handler();
    let key = handler.issue("invite", "data", 60).await.unwrap();
    handler.revoke(&key).await.unwrap();
    let value = handler.consume(&key).await.unwrap();
    assert_eq!(value, None);
}

// ========================================================================
// Key 命名空间隔离测试
// ========================================================================

/// temp key 与 apikey 命名空间隔离（spec Scenario）。
#[tokio::test]
async fn temp_namespace_isolated() {
    let dao = Arc::new(MockDao::new());
    // 模拟同时存在 temp key 与 apikey key
    dao.set("bulwark:temp:invite:abc", "temp-value", 60)
        .await
        .unwrap();
    dao.set("bulwark:apikey:abc", "apikey-value", 60)
        .await
        .unwrap();
    let handler = TempCredentialHandler::new(dao.clone());
    // consume temp key 不影响 apikey key
    let value = handler.consume("bulwark:temp:invite:abc").await.unwrap();
    assert_eq!(value, Some("temp-value".to_string()));
    let apikey_value = dao.get("bulwark:apikey:abc").await.unwrap();
    assert_eq!(apikey_value, Some("apikey-value".to_string()));
}
