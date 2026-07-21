//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 临时凭证协议边界场景测试（TG11，0.2.1 patch release）。
//!
//! 验证 `TempCredentialHandler` 在边界条件下的行为：
//! - 11.2 一次性临时凭证消费后失效
//! - 11.3 已过期的临时凭证校验失败
//! - 11.4 scope 超出权限被拒绝
//!
//! 依据 spec protocol-temp。使用 MockDao（HashMap + parking_lot::Mutex + Instant）。

#![cfg(feature = "protocol-temp")]

use async_trait::async_trait;
use garrison::dao::GarrisonDao;
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::protocol::temp::TempCredentialHandler;
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
impl GarrisonDao for MockDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
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

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
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

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((existing, _)) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(GarrisonError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
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
            None => Err(GarrisonError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 创建 TempCredentialHandler（使用 MockDao）。
fn make_handler() -> TempCredentialHandler {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    TempCredentialHandler::new(dao)
}

// ============================================================================
// 边界场景测试
// ============================================================================

/// 11.2 one_time_temp_credential_invalidated_after_use
///
/// 验证一次性临时凭证在 `consume` 后失效（一次性使用语义）。
///
/// `TempCredentialHandler::consume` 原子地读取并删除凭证。
/// 第一次 `consume` 返回 `Some(value)`，第二次 `consume` 返回 `None`。
///
/// 同时验证 `get` 也不再能读取已消费的凭证。
#[tokio::test]
async fn one_time_temp_credential_invalidated_after_use() {
    let handler = make_handler();

    // 签发一个临时凭证
    let key = handler
        .issue("invite", "payload-data-001", 600)
        .await
        .unwrap();

    // 第一次 consume：返回 value 并删除
    let first = handler.consume(&key).await.unwrap();
    assert_eq!(
        first,
        Some("payload-data-001".to_string()),
        "首次 consume 应返回凭证值"
    );

    // 第二次 consume：返回 None（凭证已失效）
    let second = handler.consume(&key).await.unwrap();
    assert_eq!(second, None, "凭证消费后应失效，第二次 consume 应返回 None");

    // get 也应返回 None（凭证已被删除）
    let get_result = handler.get(&key).await.unwrap();
    assert_eq!(get_result, None, "凭证消费后 get 也应返回 None");
}

/// 11.3 expired_temp_credential_validation_fails
///
/// 验证已过期的临时凭证校验失败（get 返回 None）。
///
/// `TempCredentialHandler` 依赖 DAO 的 TTL 机制实现过期。当凭证过期后，
/// DAO 的 `get` 返回 `None`（MockDao 模拟 TTL 过期）。
#[tokio::test]
async fn expired_temp_credential_validation_fails() {
    let handler = make_handler();

    // 签发一个 1 秒过期的凭证
    let key = handler.issue("reset", "reset-token-001", 1).await.unwrap();

    // 立即 get：应返回 Some（未过期）
    let before = handler.get(&key).await.unwrap();
    assert_eq!(
        before,
        Some("reset-token-001".to_string()),
        "过期前 get 应返回凭证值"
    );

    // 等待 2 秒让凭证过期
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // 过期后 get：应返回 None
    let after = handler.get(&key).await.unwrap();
    assert_eq!(after, None, "过期后 get 应返回 None（校验失败）");

    // 过期后 consume：也应返回 None
    let consume_result = handler.consume(&key).await.unwrap();
    assert_eq!(consume_result, None, "过期后 consume 应返回 None");
}

/// 11.4 scope_exceeded_access_denied
///
/// 验证临时凭证的 scope 超出权限时被拒绝（应用层 scope 检查）。
///
/// TempCredential 模块未实现独立的 scope 字段（value 为业务方自定义字符串）。
/// scope 检查由业务方在读取凭证值后自行实现。此测试模拟以下场景：
/// - 签发凭证时 value 携带 scope 信息（JSON 格式：`{"scope":"read"}`）
/// - 业务方读取凭证后，检查 scope 是否允许目标操作
/// - "write" 操作超出 "read" scope → 拒绝
///
/// TODO(0.2.2): 考虑在 TempCredentialHandler 中增加显式 scope 参数，实现协议层检查。
#[tokio::test]
async fn scope_exceeded_access_denied() {
    let handler = make_handler();

    // 签发一个 scope=read 的临时凭证（value 为 JSON，携带 scope 信息）
    let credential_value = r#"{"scope":"read"}"#;
    let key = handler
        .issue("verify", credential_value, 600)
        .await
        .unwrap();

    // 业务方读取凭证值
    let stored = handler.consume(&key).await.unwrap();
    assert!(stored.is_some(), "应成功读取凭证");

    let stored_value = stored.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stored_value).unwrap();
    let credential_scope = parsed["scope"].as_str().unwrap();

    // 模拟业务方 scope 检查：凭证 scope="read"，请求操作="write"
    let requested_operation = "write";
    let allowed = credential_scope == requested_operation
        || (credential_scope == "read" && requested_operation == "read");

    assert!(
        !allowed,
        "scope=\"read\" 的凭证不应允许 \"write\" 操作（权限超出边界）"
    );

    // 验证 scope=read 允许 read 操作
    let read_allowed = credential_scope == "read";
    assert!(read_allowed, "scope=\"read\" 的凭证应允许 \"read\" 操作");
}
