//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `SsoClient` 单元测试。

use super::mock::MockDao;
use super::*;
use crate::error::BulwarkError;

/// 创建 SsoClient 实例（使用 MockDao + 测试用 secret）。
fn make_client() -> SsoClient {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    SsoClient::new(dao, "test-sso-secret-key")
}

// ========================================================================
// SsoClient 构造测试
// ========================================================================

/// 构造 SsoClient，持有 dao（spec Scenario）。
#[test]
fn new_creates_client_with_dao() {
    let _client = make_client();
    // 构造成功即验证（dao 通过类型系统保证非空）
}

// ========================================================================
// issue_ticket 测试
// ========================================================================

/// 成功签发票据，格式为 `{64_hex_random}.{hmac_b64}`。
#[tokio::test]
async fn issue_ticket_returns_signed_format() {
    let client = make_client();
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();
    // 格式：{64_hex_random}.{hmac_b64}
    let (random_part, sig) = ticket.split_once('.').expect("ticket 应包含 '.' 分隔符");
    assert_eq!(random_part.len(), 64, "随机部分应为 64 字符 hex");
    assert!(
        random_part.chars().all(|c| c.is_ascii_hexdigit()),
        "随机部分应全为 hex 字符"
    );
    assert!(!sig.is_empty(), "签名部分不应为空");
}

/// 票据随机性：连续签发返回不同票据（spec Scenario）。
#[tokio::test]
async fn issue_ticket_generates_unique_tickets() {
    let client = make_client();
    let t1 = client.issue_ticket("1001", 2001).await.unwrap();
    let t2 = client.issue_ticket("1001", 2001).await.unwrap();
    assert_ne!(t1, t2);
}

/// 相同 login_id 多 client 签发独立票据（spec Scenario）。
#[tokio::test]
async fn issue_ticket_same_login_different_clients() {
    let client = make_client();
    let t1 = client.issue_ticket("1001", 2001).await.unwrap();
    let t2 = client.issue_ticket("1001", 2002).await.unwrap();
    assert_ne!(t1, t2);
}

/// key 前缀正确（spec Scenario）。
#[tokio::test]
async fn issue_ticket_uses_correct_key_prefix() {
    let dao = Arc::new(MockDao::new());
    let client = SsoClient::new(dao.clone(), "test-sso-secret-key");
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();
    let key = format!("bulwark:sso:ticket:{}", ticket);
    let value = dao.get(&key).await.unwrap();
    assert!(value.is_some());
    let data: SsoTicketData = serde_json::from_str(&value.unwrap()).unwrap();
    assert_eq!(data.login_id, "1001");
    assert_eq!(data.client_id, 2001);
}

// ========================================================================
// validate_ticket 测试
// ========================================================================

/// 成功校验返回 login_id（spec Scenario）。
#[tokio::test]
async fn validate_ticket_success_returns_login_id() {
    let client = make_client();
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();
    let login_id = client.validate_ticket(&ticket, 2001).await.unwrap();
    assert_eq!(login_id, "1001");
}

/// 校验成功后票据被删除（一次性使用，spec Scenario）。
#[tokio::test]
async fn validate_ticket_deletes_after_success() {
    let client = make_client();
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();
    let _ = client.validate_ticket(&ticket, 2001).await.unwrap();
    // 第二次校验应失败
    let result = client.validate_ticket(&ticket, 2001).await;
    assert!(result.is_err());
}

/// client_id 不匹配返回 InvalidToken 错误（spec Scenario，M5）。
#[tokio::test]
async fn validate_ticket_client_id_mismatch_returns_error() {
    let client = make_client();
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();
    let result = client.validate_ticket(&ticket, 9999).await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}

/// 票据不存在返回错误（spec Scenario）。
#[tokio::test]
async fn validate_ticket_nonexistent_returns_error() {
    let client = make_client();
    let result = client.validate_ticket("nonexistent-ticket", 2001).await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}

/// 一次性使用：第二次校验失败（spec Scenario）。
#[tokio::test]
async fn validate_ticket_one_time_use_second_fails() {
    let client = make_client();
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();
    let first = client.validate_ticket(&ticket, 2001).await;
    let second = client.validate_ticket(&ticket, 2001).await;
    assert!(first.is_ok());
    assert!(second.is_err());
}

// ========================================================================
// destroy_ticket 测试
// ========================================================================

/// 销毁存在的票据（spec Scenario）。
#[tokio::test]
async fn destroy_ticket_existing() {
    let client = make_client();
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();
    let result = client.destroy_ticket(&ticket).await;
    assert!(result.is_ok());
    // 验证已删除
    let validate_result = client.validate_ticket(&ticket, 2001).await;
    assert!(validate_result.is_err());
}

/// 销毁不存在的票据返回 Ok（幂等，spec Scenario）。
#[tokio::test]
async fn destroy_ticket_nonexistent_returns_ok() {
    let client = make_client();
    let result = client.destroy_ticket("nonexistent-ticket").await;
    assert!(result.is_ok());
}

// ========================================================================
// with_ticket_ttl 测试
// ========================================================================

/// with_ticket_ttl 设置 TTL。
#[test]
fn with_ticket_ttl_sets_ttl() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let client = SsoClient::new(dao, "test-sso-secret-key").with_ticket_ttl(120);
    assert_eq!(client.ticket_ttl_seconds, 120);
}

// ========================================================================
// LoginId newtype 接入（impl Into<LoginId>）
// ========================================================================

/// 验证 `SsoClient::issue_ticket` 接受 String 形式 login_id。
#[tokio::test]
async fn issue_ticket_accepts_login_id_numeric() {
    let client = make_client();
    let ticket = client.issue_ticket("1001".to_string(), 2001).await.unwrap();
    // 验证 ticket 可校验
    let login_id = client.validate_ticket(&ticket, 2001).await.unwrap();
    assert_eq!(login_id, "1001");
}

// ========================================================================
// TOCTOU 修复测试
// ========================================================================

/// R-002: 并发消费同一 ticket 仅一个成功（TOCTOU 修复核心验证）。
///
/// 10 个并发任务同时 validate_ticket，仅一个返回 Ok，其他返回 InvalidToken。
/// R-002 验收标准。
#[tokio::test(flavor = "multi_thread")]
async fn validate_ticket_concurrent_only_one_succeeds() {
    let client = Arc::new(make_client());
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();

    let mut handles = Vec::new();
    for _ in 0..10 {
        let c = client.clone();
        let t = ticket.clone();
        handles.push(tokio::spawn(
            async move { c.validate_ticket(&t, 2001).await },
        ));
    }

    let mut success = 0;
    let mut invalid_token = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(login_id) => {
                assert_eq!(login_id, "1001");
                success += 1;
            },
            Err(BulwarkError::InvalidToken(_)) => invalid_token += 1,
            Err(e) => panic!("期望 InvalidToken 或 Ok，实际: {:?}", e),
        }
    }

    assert_eq!(success, 1, "并发消费同一 ticket 仅一个成功");
    assert_eq!(invalid_token, 9, "其他 9 个应返回 InvalidToken");
}

// ========================================================================
// M5 新增：ticket HMAC 签名测试（依据安全审计 M5）
// ========================================================================

/// M5: 伪造的 ticket（无签名部分）应被拒绝。
#[tokio::test]
async fn validate_ticket_rejects_unsigned_ticket() {
    let client = make_client();
    // 伪造的 ticket：纯 64 hex，无 `.{hmac}` 部分
    let fake_ticket = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let result = client.validate_ticket(fake_ticket, 2001).await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidToken(ref msg)) if msg.contains("格式错误")),
        "无签名的 ticket 应被拒绝，实际: {:?}",
        result
    );
}

/// M5: 签名被篡改的 ticket 应被拒绝。
#[tokio::test]
async fn validate_ticket_rejects_tampered_signature() {
    let client = make_client();
    let ticket = client.issue_ticket("1001", 2001).await.unwrap();
    // 篡改签名部分（在末尾追加字符）
    let tampered_ticket = format!("{}X", ticket);
    let result = client.validate_ticket(&tampered_ticket, 2001).await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidToken(ref msg)) if msg.contains("签名验证失败")),
        "篡改签名的 ticket 应被拒绝，实际: {:?}",
        result
    );
}

/// M5: 使用不同 secret 签发的 ticket 应被另一个 client 拒绝。
#[tokio::test]
async fn validate_ticket_rejects_different_secret() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let issuer = SsoClient::new(dao.clone(), "secret-a");
    let validator = SsoClient::new(dao, "secret-b");

    let ticket = issuer.issue_ticket("1001", 2001).await.unwrap();
    let result = validator.validate_ticket(&ticket, 2001).await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidToken(ref msg)) if msg.contains("签名验证失败")),
        "不同 secret 签发的 ticket 应被拒绝，实际: {:?}",
        result
    );
}

/// M5: 空 secret 应 panic（禁止空 secret）。
#[test]
#[should_panic(expected = "SSO secret 不能为空")]
fn new_rejects_empty_secret() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let _client = SsoClient::new(dao, "");
}
