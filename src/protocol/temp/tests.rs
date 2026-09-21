//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

use super::*;
use crate::error::{GarrisonError, GarrisonResult};
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
impl GarrisonDao for MockDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        let data = self.data.lock().await;
        Ok(data.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        data.insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        if data.contains_key(key) {
            data.insert(key.to_string(), value.to_string());
            Ok(())
        } else {
            Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key)))
        }
    }

    async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
        Ok(())
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        data.remove(key);
        Ok(())
    }

    /// 原子地 get + delete（测试支撑）。
    ///
    /// 在同一把 `tokio::sync::Mutex` 锁内完成 get + remove，
    /// 保证并发调用同一 key 时仅一个返回 Some（进程内原子）。
    /// 与 `GarrisonDaoOxcache` / 生产 `MockDao` 的 `parking_lot::Mutex` 实现等价。
    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
        let mut data = self.data.lock().await;
        let value = data.get(key).cloned();
        if value.is_some() {
            data.remove(key);
        }
        Ok(value)
    }

    // 其余 5 个原子方法经子集宏展开（逻辑单点维护于
    // dao::atomic_fallback::impls），本 mock 自定义的单锁原子 get_and_delete
    //（一次性语义）保留不被覆盖。
    crate::atomic_test_fallback_no_get_and_delete!();
}

/// 创建 handler（使用 MockDao）。
fn make_handler() -> TempCredentialHandler {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    TempCredentialHandler::new(dao)
}

// ========================================================================
// TempCredentialHandler 构造测试
// ========================================================================

/// 构造 handler）。
#[test]
fn new_creates_handler() {
    let _handler = make_handler();
}

// ========================================================================
// issue 测试
// ========================================================================

/// 成功签发，key 前缀正确）。
#[tokio::test]
async fn issue_returns_key_with_correct_prefix() {
    let handler = make_handler();
    let key = handler.issue("invite", "payload-data", 600).await.unwrap();
    assert!(key.starts_with("garrison:temp:invite:"));
}

/// 复用同一 handler 多次签发返回不同 key）。
#[tokio::test]
async fn issue_multiple_times_returns_different_keys() {
    let handler = make_handler();
    let k1 = handler.issue("invite", "v1", 60).await.unwrap();
    let k2 = handler.issue("invite", "v1", 60).await.unwrap();
    assert_ne!(k1, k2);
}

/// 不同 prefix 产生不同命名空间）。
#[tokio::test]
async fn issue_different_prefix_different_namespace() {
    let handler = make_handler();
    let k1 = handler.issue("invite", "v1", 60).await.unwrap();
    let k2 = handler.issue("reset", "v2", 60).await.unwrap();
    assert!(k1.starts_with("garrison:temp:invite:"));
    assert!(k2.starts_with("garrison:temp:reset:"));
}

/// ttl_seconds <= 0 返回错误）。
#[tokio::test]
async fn issue_zero_ttl_returns_error() {
    let handler = make_handler();
    let result = handler.issue("invite", "data", 0).await;
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
    }
}

/// prefix 包含冒号返回错误）。
#[tokio::test]
async fn issue_prefix_with_colon_returns_error() {
    let handler = make_handler();
    let result = handler.issue("inv:ite", "data", 60).await;
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
    }
}

/// value 为空字符串允许存储）。
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

/// 读取存在的凭据，多次读取不删除）。
#[tokio::test]
async fn get_returns_value_without_deleting() {
    let handler = make_handler();
    let key = handler.issue("invite", "data", 60).await.unwrap();
    let v1 = handler.get(&key).await.unwrap();
    let v2 = handler.get(&key).await.unwrap();
    assert_eq!(v1, Some("data".to_string()));
    assert_eq!(v2, Some("data".to_string()));
}

/// 读取不存在的凭据返回 None）。
#[tokio::test]
async fn get_nonexistent_returns_none() {
    let handler = make_handler();
    let result = handler
        .get("garrison:temp:invite:nonexistent")
        .await
        .unwrap();
    assert_eq!(result, None);
}

// ========================================================================
// revoke 测试
// ========================================================================

/// 撤销存在的凭据）。
#[tokio::test]
async fn revoke_existing_returns_ok() {
    let handler = make_handler();
    let key = handler.issue("invite", "data", 60).await.unwrap();
    let result = handler.revoke(&key).await;
    assert_eq!(result.unwrap(), (), "撤销存在的临时令牌应返回 Ok(())");
    // 再次 get 应为 None
    let value = handler.get(&key).await.unwrap();
    assert_eq!(value, None);
}

/// 撤销不存在的凭据返回 Ok（幂等语义，spec Scenario）。
#[tokio::test]
async fn revoke_nonexistent_returns_ok() {
    let handler = make_handler();
    let result = handler.revoke("garrison:temp:invite:nonexistent").await;
    assert_eq!(
        result.unwrap(),
        (),
        "撤销不存在的临时令牌应返回 Ok(())（幂等）"
    );
}

// ========================================================================
// consume 测试
// ========================================================================

/// 成功消费存在的凭据）。
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

/// 重复消费返回 None）。
#[tokio::test]
async fn consume_twice_returns_none_second_time() {
    let handler = make_handler();
    let key = handler.issue("invite", "data", 60).await.unwrap();
    let v1 = handler.consume(&key).await.unwrap();
    let v2 = handler.consume(&key).await.unwrap();
    assert_eq!(v1, Some("data".to_string()));
    assert_eq!(v2, None);
}

/// 消费不存在的凭据返回 None）。
#[tokio::test]
async fn consume_nonexistent_returns_none() {
    let handler = make_handler();
    let value = handler
        .consume("garrison:temp:invite:nonexistent")
        .await
        .unwrap();
    assert_eq!(value, None);
}

/// revoke 后 consume 失败返回 None）。
#[tokio::test]
async fn consume_after_revoke_returns_none() {
    let handler = make_handler();
    let key = handler.issue("invite", "data", 60).await.unwrap();
    handler.revoke(&key).await.unwrap();
    let value = handler.consume(&key).await.unwrap();
    assert_eq!(value, None);
}

// ========================================================================
// consume TOCTOU 原子性测试
// ========================================================================

/// 并发 consume 同一 key 仅一个返回 Some（TOCTOU 修复验证）。
///
/// 场景：10 个并发任务同时 consume 同一 key，原 `get + delete` 两步操作下
/// 可能多个任务都读到 value 然后才 delete，导致 double-spend。修复后
/// `get_and_delete` 原子执行，仅一个任务返回 Some。
///
/// 参考：`dao::tests::mock_get_and_delete_concurrent_only_one_succeeds`
/// 与 `dao::tests::oxcache_get_and_delete_concurrent_only_one_succeeds`。
#[tokio::test(flavor = "multi_thread")]
async fn consume_concurrent_only_one_succeeds() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let handler = Arc::new(TempCredentialHandler::new(dao));
    let key = handler
        .issue("invite", "concurrent-value", 60)
        .await
        .unwrap();

    let mut handles = Vec::new();
    for _ in 0..10 {
        let h = handler.clone();
        let k = key.clone();
        handles.push(tokio::spawn(async move { h.consume(&k).await }));
    }

    let mut success = 0;
    let mut none_count = 0;
    for handle in handles {
        let result = handle.await.expect("tokio task panicked");
        match result {
            Ok(Some(_)) => success += 1,
            Ok(None) => none_count += 1,
            Err(e) => panic!("consume 不应返回错误: {:?}", e),
        }
    }

    assert_eq!(
        success, 1,
        "并发 consume 仅一个返回 Some（防 double-spend）"
    );
    assert_eq!(none_count, 9, "其余 9 个返回 None");
}

/// 串行 consume 一次性语义验证（修复后回归）。
///
/// 验证修复 `get_and_delete` 后仍保持原有一次性语义：
/// 第一次返回 Some，第二次及之后返回 None。
#[tokio::test]
async fn consume_atomic_still_one_time_use() {
    let handler = make_handler();
    let key = handler.issue("invite", "data", 60).await.unwrap();
    let v1 = handler.consume(&key).await.unwrap();
    let v2 = handler.consume(&key).await.unwrap();
    let v3 = handler.consume(&key).await.unwrap();
    assert_eq!(v1, Some("data".to_string()));
    assert_eq!(v2, None);
    assert_eq!(v3, None);
}

// ========================================================================
// Key 命名空间隔离测试
// ========================================================================

/// temp key 与 apikey 命名空间隔离）。
#[tokio::test]
async fn temp_namespace_isolated() {
    let dao = Arc::new(MockDao::new());
    // 模拟同时存在 temp key 与 apikey key
    dao.set("garrison:temp:invite:abc", "temp-value", 60)
        .await
        .unwrap();
    dao.set("garrison:apikey:abc", "apikey-value", 60)
        .await
        .unwrap();
    let handler = TempCredentialHandler::new(dao.clone());
    // consume temp key 不影响 apikey key
    let value = handler.consume("garrison:temp:invite:abc").await.unwrap();
    assert_eq!(value, Some("temp-value".to_string()));
    let apikey_value = dao.get("garrison:apikey:abc").await.unwrap();
    assert_eq!(apikey_value, Some("apikey-value".to_string()));
}

// ========================================================================
// DAO 错误路径测试（FailingDao：所有操作返回 Err，验证 handler 错误透传）
// ========================================================================

/// 总是失败的 DAO（用于 handler 错误路径测试：所有操作返回 `Dao` 错误）。
struct FailingDao;

#[async_trait]
impl GarrisonDao for FailingDao {
    async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
        Err(GarrisonError::Dao("mock-get-failed".to_string()))
    }

    async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
        Err(GarrisonError::Dao("mock-set-failed".to_string()))
    }

    async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
        Err(GarrisonError::Dao("mock-update-failed".to_string()))
    }

    async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
        Err(GarrisonError::Dao("mock-expire-failed".to_string()))
    }

    async fn delete(&self, _key: &str) -> GarrisonResult<()> {
        Err(GarrisonError::Dao("mock-delete-failed".to_string()))
    }

    async fn get_and_delete(&self, _key: &str) -> GarrisonResult<Option<String>> {
        Err(GarrisonError::Dao("mock-get-and-delete-failed".to_string()))
    }

    crate::atomic_test_fallback_no_get_and_delete!();
}

/// issue 时 dao.set 失败应透传 Dao 错误（错误路径）。
#[tokio::test]
async fn issue_dao_set_error_propagates() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(FailingDao);
    let handler = TempCredentialHandler::new(dao);
    let result = handler.issue("invite", "data", 60).await;
    assert!(
        matches!(&result, Err(GarrisonError::Dao(msg)) if msg.contains("mock-set-failed")),
        "dao.set 失败应透传 Dao 错误，实际: {:?}",
        result
    );
}

/// get 时 dao.get 失败应透传 Dao 错误（错误路径）。
#[tokio::test]
async fn get_dao_error_propagates() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(FailingDao);
    let handler = TempCredentialHandler::new(dao);
    let result = handler.get("garrison:temp:invite:any").await;
    assert!(
        matches!(&result, Err(GarrisonError::Dao(msg)) if msg.contains("mock-get-failed")),
        "dao.get 失败应透传 Dao 错误，实际: {:?}",
        result
    );
}

/// revoke 时 dao.delete 失败应透传 Dao 错误（错误路径）。
#[tokio::test]
async fn revoke_dao_error_propagates() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(FailingDao);
    let handler = TempCredentialHandler::new(dao);
    let result = handler.revoke("garrison:temp:invite:any").await;
    assert!(
        matches!(&result, Err(GarrisonError::Dao(msg)) if msg.contains("mock-delete-failed")),
        "dao.delete 失败应透传 Dao 错误，实际: {:?}",
        result
    );
}

/// consume 时 dao.get_and_delete 失败应透传 Dao 错误（错误路径）。
#[tokio::test]
async fn consume_dao_error_propagates() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(FailingDao);
    let handler = TempCredentialHandler::new(dao);
    let result = handler.consume("garrison:temp:invite:any").await;
    assert!(
        matches!(&result, Err(GarrisonError::Dao(msg)) if msg.contains("mock-get-and-delete-failed")),
        "dao.get_and_delete 失败应透传 Dao 错误，实际: {:?}",
        result
    );
}

// ========================================================================
// listener 集成测试（feature = "listener"）：consume 广播 TempCredentialConsumed
// ========================================================================

/// 捕获广播事件的监听器（验证 consume → TempCredentialConsumed 广播链路）。
#[cfg(feature = "listener")]
struct RecordingListener {
    events: parking_lot::Mutex<Vec<crate::listener::GarrisonEvent>>,
}

#[cfg(feature = "listener")]
#[async_trait]
impl crate::listener::GarrisonListener for RecordingListener {
    async fn on_event(&self, event: &crate::listener::GarrisonEvent) -> GarrisonResult<()> {
        self.events.lock().push(event.clone());
        Ok(())
    }
}

/// 注入 listener manager 后，consume 命中（value 为 Some）应广播 TempCredentialConsumed
/// 事件，且事件携带 key 与 value（feature = "listener"）。
#[cfg(feature = "listener")]
#[tokio::test]
async fn with_listener_manager_broadcasts_on_consume() {
    use crate::listener::{GarrisonEvent, GarrisonListenerManager};

    let recorder = Arc::new(RecordingListener {
        events: parking_lot::Mutex::new(Vec::new()),
    });
    let lm = Arc::new(GarrisonListenerManager::new());
    lm.register(recorder.clone());

    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let handler = TempCredentialHandler::new(dao).with_listener_manager(lm);

    let key = handler
        .issue("invite", "broadcast-value", 60)
        .await
        .unwrap();
    let consumed = handler.consume(&key).await.unwrap();
    assert_eq!(consumed, Some("broadcast-value".to_string()));

    let events = recorder.events.lock();
    assert_eq!(events.len(), 1, "consume 命中应广播恰好 1 个事件");
    match &events[0] {
        GarrisonEvent::TempCredentialConsumed {
            key: event_key,
            value,
            request_context,
        } => {
            assert_eq!(event_key, &key, "事件 key 应与被消费的凭据 key 一致");
            assert_eq!(value, "broadcast-value", "事件 value 应与凭据载荷一致");
            assert!(request_context.is_none(), "handler 广播时不携带请求上下文");
        },
        other => panic!("应广播 TempCredentialConsumed 事件，实际: {:?}", other),
    }
}

/// 注入 listener manager 后，consume 未命中（value 为 None）不应广播事件
///（feature = "listener"）。
#[cfg(feature = "listener")]
#[tokio::test]
async fn with_listener_manager_no_broadcast_when_value_none() {
    use crate::listener::GarrisonListenerManager;

    let recorder = Arc::new(RecordingListener {
        events: parking_lot::Mutex::new(Vec::new()),
    });
    let lm = Arc::new(GarrisonListenerManager::new());
    lm.register(recorder.clone());

    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let handler = TempCredentialHandler::new(dao).with_listener_manager(lm);

    let value = handler
        .consume("garrison:temp:invite:nonexistent")
        .await
        .unwrap();
    assert_eq!(value, None);
    assert!(
        recorder.events.lock().is_empty(),
        "consume 未命中不应广播事件"
    );
}

// ========================================================================
// loom 竞态模型验证（T033）：一次性凭证原子消费
// ========================================================================

/// loom 模型专用 DAO：`loom::sync::Mutex<Option<String>>` 模拟原子 get_and_delete，
/// 锁内取值即消费——loom 可穷举互斥区交错。async 方法体内零 await 点（未来恒
/// Send，锁 guard 不跨悬挂点），由 `loom::future::block_on` 驱动。
#[cfg(feature = "loom-test")]
struct LoomModelDao {
    slot: loom::sync::Mutex<Option<String>>,
}

#[cfg(feature = "loom-test")]
#[async_trait]
impl GarrisonDao for LoomModelDao {
    async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
        let v = {
            let slot = self.slot.lock().unwrap();
            slot.clone()
        };
        Ok(v)
    }

    async fn set(&self, _key: &str, value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
        let mut slot = self.slot.lock().unwrap();
        *slot = Some(value.to_string());
        Ok(())
    }

    async fn update(&self, _key: &str, value: &str) -> GarrisonResult<()> {
        let mut slot = self.slot.lock().unwrap();
        match slot.as_mut() {
            Some(v) => {
                *v = value.to_string();
                Ok(())
            },
            None => Err(GarrisonError::Dao("dao-key-not-found::loom".to_string())),
        }
    }

    async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
        Ok(())
    }

    async fn delete(&self, _key: &str) -> GarrisonResult<()> {
        let mut slot = self.slot.lock().unwrap();
        *slot = None;
        Ok(())
    }

    /// 与 MockDao 单锁语义一致：锁内 take = 原子 get + delete。
    async fn get_and_delete(&self, _key: &str) -> GarrisonResult<Option<String>> {
        let mut slot = self.slot.lock().unwrap();
        Ok(slot.take())
    }

    crate::atomic_test_fallback_no_get_and_delete!();
}

/// 双线程并发 consume 同一 key：loom 穷举全部交错排列下，恰好一次返回
/// Some（一次性语义 / 防 double-spend），消费后 slot 为空。默认构建不编译
/// 本模块；触发方式（loom-test feature 门控，理由见 Cargo.toml loom 依赖注释）：
/// `cargo test --lib --features protocol-temp,loom-test protocol::temp`
#[cfg(feature = "loom-test")]
#[test]
fn loom_consume_same_key_exactly_once() {
    loom::model(|| {
        use loom::thread;

        let dao: std::sync::Arc<dyn GarrisonDao> = std::sync::Arc::new(LoomModelDao {
            slot: loom::sync::Mutex::new(Some("one-shot-payload".to_string())),
        });
        let handler = std::sync::Arc::new(TempCredentialHandler::new(dao));

        let h2 = handler.clone();
        let t = thread::spawn(move || loom::future::block_on(h2.consume("k")));
        let r1 = loom::future::block_on(handler.consume("k"));
        let r2 = t.join().expect("消费线程不应 panic");

        let r1 = r1.expect("消费 1 不应返回 Err");
        let r2 = r2.expect("消费 2 不应返回 Err");
        let some_count = (r1.is_some() as u8) + (r2.is_some() as u8);
        assert_eq!(
            some_count, 1,
            "并发消费同一 key 必须恰好一次 Some（double-spend 防线），实际 {}",
            some_count
        );
        assert_eq!(
            r1.or(r2),
            Some("one-shot-payload".to_string()),
            "唯一成功的消费应取到载荷"
        );
    });
}
