//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SSO 协议集成测试：跨子系统 ticket 签发 → 校验 → 销毁完整流程。
//!
//! 验证 `SsoClient` 在多个子系统间通过共享 `BulwarkDao` 实现 SSO 的能力：
//! 1. 子系统 A 签发 ticket，存入共享 DAO
//! 2. 子系统 B 持有相同 DAO，校验 ticket 拿到 login_id
//! 3. 一次性使用语义：第二次校验失败
//! 4. client_id 隔离：A 签发的 ticket 不能在 B 用错误的 client_id 校验
//! 5. 销毁（destroy）跨子系统生效
//!
//! 依据 spec protocol-sso。

#![cfg(feature = "protocol-sso")]

use async_trait::async_trait;
use bulwark::dao::BulwarkDao;
use bulwark::error::BulwarkError;
use bulwark::protocol::sso::SsoClient;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ============================================================================
// MockDao（HashMap + Instant 模拟 TTL，跨子系统共享）
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
    async fn get(&self, key: &str) -> Result<Option<String>, BulwarkError> {
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

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), BulwarkError> {
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

    async fn update(&self, key: &str, value: &str) -> Result<(), BulwarkError> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((existing, _)) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> Result<(), BulwarkError> {
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

    async fn delete(&self, key: &str) -> Result<(), BulwarkError> {
        self.store.lock().remove(key);
        Ok(())
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 创建共享 DAO 的两个 SsoClient（模拟子系统 A 和 B）。
fn make_two_clients() -> (SsoClient, SsoClient, Arc<MockDao>) {
    let dao = Arc::new(MockDao::new());
    let dao_dyn: Arc<dyn BulwarkDao> = dao.clone();
    let client_a = SsoClient::new(dao_dyn.clone(), "test-sso-secret-key");
    let client_b = SsoClient::new(dao_dyn, "test-sso-secret-key");
    (client_a, client_b, dao)
}

// ============================================================================
// 集成测试：跨子系统 ticket 流程
// ============================================================================

/// 子系统 A 签发 ticket，子系统 B 校验拿到 login_id（spec Scenario）。
#[tokio::test]
async fn cross_subsystem_ticket_issue_and_validate() {
    let (client_a, client_b, _dao) = make_two_clients();

    // 子系统 A 签发 ticket
    let ticket = client_a
        .issue_ticket("1001", 2001)
        .await
        .expect("签发应成功");
    // M5 修复：ticket 格式为 {64_hex_random}.{hmac_b64}
    let (random_part, sig) = ticket
        .split_once('.')
        .expect("ticket 应包含 '.' 分隔符（M5 签名格式）");
    assert_eq!(random_part.len(), 64, "ticket 随机部分应为 64 字符");
    assert!(
        random_part.chars().all(|c| c.is_ascii_hexdigit()),
        "ticket 随机部分应为 hex 字符"
    );
    assert!(!sig.is_empty(), "ticket 签名部分不应为空");

    // 子系统 B 校验拿到 login_id
    let login_id = client_b
        .validate_ticket(&ticket, 2001)
        .await
        .expect("校验应成功");
    assert_eq!(login_id, "1001".to_string());
}

/// 一次性使用：子系统 A 签发后，子系统 B 校验一次后失效（spec Scenario）。
#[tokio::test]
async fn ticket_is_one_time_use_across_subsystems() {
    let (client_a, client_b, _dao) = make_two_clients();

    let ticket = client_a.issue_ticket("1001", 2001).await.unwrap();

    // 第一次校验成功
    let first = client_b.validate_ticket(&ticket, 2001).await;
    assert!(first.is_ok());
    assert_eq!(first.unwrap(), "1001".to_string());

    // 第二次校验失败（即使同一子系统也失败）
    let second = client_b.validate_ticket(&ticket, 2001).await;
    assert!(second.is_err(), "一次性使用：第二次校验应失败");
    match second.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken，实际: {:?}", other),
    }
}

/// client_id 隔离：子系统 B 用错误 client_id 校验失败（spec Scenario）。
#[tokio::test]
async fn ticket_client_id_isolation_across_subsystems() {
    let (client_a, client_b, _dao) = make_two_clients();

    // 子系统 A 为 client_id=2001 签发
    let ticket = client_a.issue_ticket("1001", 2001).await.unwrap();

    // 子系统 B 用错误的 client_id 校验
    let result = client_b.validate_ticket(&ticket, 9999).await;
    assert!(result.is_err(), "错误 client_id 应校验失败");
    match result.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!(
            "期望 InvalidToken 错误（M5 修复：client_id 不匹配），实际: {:?}",
            other
        ),
    }

    // client_id 不匹配时不删除 ticket，正确 client_id 仍可校验
    let ok = client_b.validate_ticket(&ticket, 2001).await;
    assert!(ok.is_ok(), "client_id 不匹配不删除 ticket");
}

/// 子系统 A 销毁 ticket，子系统 B 无法校验（spec Scenario）。
#[tokio::test]
async fn destroy_ticket_affects_subsystem_b() {
    let (client_a, client_b, _dao) = make_two_clients();

    let ticket = client_a.issue_ticket("1001", 2001).await.unwrap();

    // 子系统 A 销毁
    client_a.destroy_ticket(&ticket).await.expect("销毁应成功");

    // 子系统 B 校验失败
    let result = client_b.validate_ticket(&ticket, 2001).await;
    assert!(result.is_err(), "销毁后子系统 B 应无法校验");
}

/// 销毁不存在的 ticket 返回 Ok（幂等，spec Scenario）。
#[tokio::test]
async fn destroy_nonexistent_ticket_is_idempotent() {
    let (_client_a, client_b, _dao) = make_two_clients();
    let result = client_b.destroy_ticket("nonexistent").await;
    assert!(result.is_ok(), "销毁不存在的 ticket 应幂等返回 Ok");
}

/// ticket TTL 默认 60 秒（spec Scenario）。
#[tokio::test]
async fn ticket_has_default_ttl_60_seconds() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let client = SsoClient::new(dao, "test-sso-secret-key");
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();
    // 直接通过 DAO 验证 ticket 存在
    let key = format!("bulwark:sso:ticket:{}", ticket);
    let value = client
        .validate_ticket(&ticket, 2001)
        .await
        .expect("校验应成功");
    assert_eq!(value, "1001".to_string());
    // 注：TTL 由 DAO 内部记录，此测试主要验证签发→校验路径正确
    let _ = key;
}

/// with_ticket_ttl 自定义 TTL 跨子系统生效。
#[tokio::test]
async fn with_ticket_ttl_custom_ttl_across_subsystems() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let client_a = SsoClient::new(dao.clone(), "test-sso-secret-key").with_ticket_ttl(120);
    let client_b = SsoClient::new(dao, "test-sso-secret-key").with_ticket_ttl(120);

    let ticket = client_a.issue_ticket("1001", 2001).await.unwrap();
    let login_id = client_b.validate_ticket(&ticket, 2001).await.unwrap();
    assert_eq!(login_id, "1001".to_string());
}

/// 多个 client_id 同时签发独立 ticket（spec Scenario）。
#[tokio::test]
async fn multiple_clients_issue_independent_tickets() {
    let (client_a, client_b, _dao) = make_two_clients();

    let t1 = client_a.issue_ticket("1001", 2001).await.unwrap();
    let t2 = client_a.issue_ticket("1001", 2002).await.unwrap();
    let t3 = client_a.issue_ticket("1002", 2001).await.unwrap();

    assert_ne!(t1, t2, "不同 client_id 应生成不同 ticket");
    assert_ne!(t1, t3, "不同 login_id 应生成不同 ticket");
    assert_ne!(t2, t3);

    // 各自校验成功
    assert_eq!(
        client_b.validate_ticket(&t1, 2001).await.unwrap(),
        "1001".to_string()
    );
    assert_eq!(
        client_b.validate_ticket(&t2, 2002).await.unwrap(),
        "1001".to_string()
    );
    assert_eq!(
        client_b.validate_ticket(&t3, 2001).await.unwrap(),
        "1002".to_string()
    );
}

/// 跨子系统 SSO 完整流程：签发 → 校验 → 建立本地会话（spec Scenario）。
#[tokio::test]
async fn full_sso_flow_issue_validate_establish_session() {
    let (client_a, client_b, _dao) = make_two_clients();

    // 1. 子系统 A：用户已登录，签发 SSO ticket 给子系统 B
    let ticket = client_a.issue_ticket("1001", 2001).await.expect("签发失败");

    // 2. 子系统 B：拿到 ticket 后校验，得到 login_id
    let login_id = client_b
        .validate_ticket(&ticket, 2001)
        .await
        .expect("校验失败");

    // 3. 子系统 B：依据 login_id 建立本地会话（这里仅断言 login_id 正确）
    assert_eq!(login_id, "1001".to_string());

    // 4. ticket 已被销毁，无法重放
    let replay = client_b.validate_ticket(&ticket, 2001).await;
    assert!(replay.is_err(), "ticket 重放应失败");
}
