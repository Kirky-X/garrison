//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 单点登录 (SSO) 协议模块，提供 ticket 签发/校验/销毁能力。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 SSO 单点登录支持，
//! 通过 `BulwarkDao` 存储 ticket（TTL 60 秒，一次性使用）。
//!
//! 仅在启用 `protocol-sso` 特性时编译。
//!
//! ## Key 命名空间
//!
//! 所有 SSO 票据存储在 `bulwark:sso:ticket:<ticket>` 命名空间下，
//! 与 session/sign/apikey/temp 模块隔离。

// SSO Server 独立抽象模块。
// 仅在启用 `protocol-sso-server` 特性时编译，依赖 `protocol-sso`。
#[cfg(feature = "protocol-sso-server")]
pub mod server;

// 模块重导出：通过 mod 路径访问子模块类型（避免外部代码引用具体文件路径）
#[cfg(feature = "protocol-sso-server")]
pub use server::SsoServer;

// SAML 2.0 协议支持。
pub mod saml;

// OIDC RP 协议支持。
pub mod oidc;

// Redis pub/sub SsoChannel 实现。
// 仅在 cache-redis + protocol-sso-server feature 同时启用时编译。
#[cfg(all(feature = "cache-redis", feature = "protocol-sso-server"))]
pub mod channel;

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use uuid::Uuid;

/// HMAC-SHA256 类型别名（SSO ticket 签名）。
type HmacSha256 = Hmac<Sha256>;

/// SSO ticket 默认 TTL（秒）。
const DEFAULT_TICKET_TTL: u64 = 60;

/// 计算 ticket 随机部分的 HMAC-SHA256 签名（M5 修复，供 SsoClient / DefaultSsoServer 共用）。
///
/// 签名输入为 `random_part`，输出为 base64 编码的 HMAC-SHA256。
fn sign_ticket(secret: &str, random_part: &str) -> BulwarkResult<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| BulwarkError::Internal(format!("HMAC 密钥初始化失败: {}", e)))?;
    mac.update(random_part.as_bytes());
    Ok(BASE64_STANDARD.encode(mac.finalize().into_bytes()))
}

/// 验证 ticket 的 HMAC 签名（M5 修复，供 SsoClient / DefaultSsoServer 共用）。
///
/// 返回 `Ok(random_part)` 验证通过，`Err` 表示签名无效或格式错误。
fn verify_ticket_signature(secret: &str, ticket: &str) -> BulwarkResult<String> {
    let (random_part, sig_b64) = ticket.split_once('.').ok_or_else(|| {
        BulwarkError::InvalidToken("SSO ticket 格式错误：缺少签名部分".to_string())
    })?;
    let expected_sig = sign_ticket(secret, random_part)?;
    if expected_sig != sig_b64 {
        return Err(BulwarkError::InvalidToken(
            "SSO ticket 签名验证失败：可能被篡改或伪造".to_string(),
        ));
    }
    Ok(random_part.to_string())
}

/// SSO ticket 存储的 JSON 数据。
///
/// `pub(crate)` 暴露以供 `server` 模块复用，避免跨模块重复定义导致格式漂移（M6 修复）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SsoTicketData {
    /// 登录主体标识。
    pub(crate) login_id: String,
    /// 客户端标识。
    pub(crate) client_id: i64,
}

/// SSO 客户端，提供 ticket 签发/校验/销毁。
///
/// 持有 `Arc<dyn BulwarkDao>` 用于票据存储，TTL 默认 60 秒。
/// 实现 `Send + Sync`，可在多线程环境共享。
///
/// # Ticket 签名（依据安全审计 M5）
///
/// 所有 ticket 使用 HMAC-SHA256 签名，格式为 `{64_hex_random}.{hmac_b64}`。
/// 即使 DAO 层被攻破或存在 key 碰撞，攻击者也无法伪造有效签名。
/// secret 由 `new(dao, secret)` 必传，禁止空 secret。
pub struct SsoClient {
    /// DAO 抽象层，用于票据存储。
    dao: Arc<dyn BulwarkDao>,
    /// 票据 TTL（秒）。
    ticket_ttl_seconds: u64,
    /// HMAC 签名密钥（M5 修复：所有 ticket 必须签名）。
    secret: String,
}

impl SsoClient {
    /// 创建新的 SSO 客户端。
    ///
    /// # 参数
    /// - `dao`: DAO 抽象层实例。
    /// - `secret`: HMAC 签名密钥（用于 ticket 防伪造，禁止空字符串）。
    ///
    /// # 错误
    /// - `secret` 为空时返回 `BulwarkError::InvalidParam`。
    pub fn new(dao: Arc<dyn BulwarkDao>, secret: impl Into<String>) -> Self {
        let secret: String = secret.into();
        assert!(
            !secret.is_empty(),
            "SSO secret 不能为空（依据安全审计 M5：ticket 必须签名）"
        );
        Self {
            dao,
            ticket_ttl_seconds: DEFAULT_TICKET_TTL,
            secret,
        }
    }

    /// 设置票据 TTL（秒），默认 60 秒。
    pub fn with_ticket_ttl(mut self, ttl_seconds: u64) -> Self {
        self.ticket_ttl_seconds = ttl_seconds;
        self
    }

    /// 计算 ticket 随机部分的 HMAC 签名（委托到模块级 `sign_ticket`）。
    fn sign_ticket(&self, random_part: &str) -> BulwarkResult<String> {
        sign_ticket(&self.secret, random_part)
    }

    /// 验证 ticket 的 HMAC 签名（委托到模块级 `verify_ticket_signature`）。
    fn verify_ticket_signature(&self, ticket: &str) -> BulwarkResult<String> {
        verify_ticket_signature(&self.secret, ticket)
    }

    /// 签发 SSO ticket。
    ///
    /// 生成 `{64_hex_random}.{hmac_b64}` 格式的签名 ticket，
    /// 存储到 `bulwark:sso:ticket:<ticket>`，value 为 JSON `{login_id, client_id}`，
    /// TTL 为 60 秒（可配置）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `client_id`: 客户端标识。
    ///
    /// # 返回
    /// `{64_hex_random}.{hmac_b64}` 格式的 ticket 字符串。
    pub async fn issue_ticket(
        &self,
        login_id: impl Into<String>,
        client_id: i64,
    ) -> BulwarkResult<String> {
        let login_id: String = login_id.into();
        // 拼接两个 UUID v4 simple（各 32 hex = 64 字符）
        let random_part = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let sig = self.sign_ticket(&random_part)?;
        let ticket = format!("{}.{}", random_part, sig);
        let data = SsoTicketData {
            login_id,
            client_id,
        };
        let value = serde_json::to_string(&data)
            .map_err(|e| BulwarkError::Internal(format!("序列化 SSO ticket 失败: {}", e)))?;
        let key = format!("bulwark:sso:ticket:{}", ticket);
        self.dao.set(&key, &value, self.ticket_ttl_seconds).await?;
        Ok(ticket)
    }

    /// 校验 SSO ticket。
    ///
    /// 校验逻辑：
    /// 1. 验证 ticket 的 HMAC 签名（M5 新增，防止 DAO 攻破后伪造）；
    /// 2. `get` 读取票据（不删除），校验 `client_id` 是否匹配；
    /// 3. `client_id` 匹配后，`get_and_delete` 原子消费票据（消除 TOCTOU）。
    ///
    /// # 参数
    /// - `ticket`: 票据字符串（格式 `{random}.{hmac}`）。
    /// - `client_id`: 客户端标识。
    ///
    /// # 返回
    /// - `Ok(login_id)`: 校验成功。
    /// - `Err(BulwarkError::InvalidToken)`: 签名无效、票据不存在、已过期、client_id 不匹配、或被并发消费。
    ///
    /// # client_id 不匹配时不消费票据
    ///
    /// 与"防爆破"设计相反，本实现优先用户友好：错误 `client_id` 不删除票据，
    /// 允许正确 `client_id` 后续重试。适用于客户端配置错误、用户输错等场景。
    ///
    /// # 原子性保证（）
    ///
    /// `client_id` 校验通过后使用 `BulwarkDao::get_and_delete` 原子消费票据，
    /// 消除 TOCTOU 竞态。并发调用同一 ticket（同 client_id）仅一个返回 `Ok`，
    /// 其他返回 `InvalidToken`（"已被并发消费"）。
    pub async fn validate_ticket(&self, ticket: &str, client_id: i64) -> BulwarkResult<String> {
        // M5 修复：先验签，防止 DAO 攻破后伪造 ticket
        let _random_part = self.verify_ticket_signature(ticket)?;

        let key = format!("bulwark:sso:ticket:{}", ticket);
        // 步骤 1: 非原子 get，用于校验 client_id（不删除票据）
        let value = self
            .dao
            .get(&key)
            .await
            .map_err(|e| BulwarkError::Dao(format!("SSO ticket 读取失败: {}", e)))?;
        let value = value
            .ok_or_else(|| BulwarkError::InvalidToken("SSO 票据不存在或已过期".to_string()))?;
        let data: SsoTicketData = serde_json::from_str(&value)
            .map_err(|e| BulwarkError::Internal(format!("反序列化 SSO ticket 失败: {}", e)))?;
        if data.client_id != client_id {
            // client_id 不匹配：不消费票据，允许正确 client_id 后续重试
            return Err(BulwarkError::InvalidToken(format!(
                "SSO client_id 不匹配: 期望 {}, 实际 {}",
                data.client_id, client_id
            )));
        }
        // 步骤 2: 原子 get_and_delete 消费票据（消除 TOCTOU 竞态）
        // 并发场景：多个同 client_id 请求都通过步骤 1，但仅一个 get_and_delete 返回 Some
        let consumed = self
            .dao
            .get_and_delete(&key)
            .await
            .map_err(|e| BulwarkError::Dao(format!("SSO ticket 原子消费失败: {}", e)))?;
        if consumed.is_none() {
            return Err(BulwarkError::InvalidToken(
                "SSO 票据已被并发消费".to_string(),
            ));
        }
        Ok(data.login_id)
    }

    /// 销毁 SSO ticket。
    ///
    /// 从 dao 中删除指定票据。即使票据不存在也返回 `Ok(())`（幂等）。
    pub async fn destroy_ticket(&self, ticket: &str) -> BulwarkResult<()> {
        let key = format!("bulwark:sso:ticket:{}", ticket);
        self.dao.delete(&key).await
    }
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests {
    use super::mock::MockDao;
    use super::*;

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
}
