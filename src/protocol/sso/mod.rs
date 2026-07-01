//! 单点登录 (SSO) 协议模块，提供 ticket 签发/校验/销毁能力。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 SSO 单点登录支持，
//! 通过 `BulwarkDao` 存储 ticket（TTL 60 秒，一次性使用）。
//!
//! 仅在启用 `protocol-sso` 特性时编译。
//!
//! ## Key 命名空间（依据 spec protocol-sso）
//!
//! 所有 SSO 票据存储在 `bulwark:sso:ticket:<ticket>` 命名空间下，
//! 与 session/sign/apikey/temp 模块隔离。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// SSO ticket 默认 TTL（秒）。
const DEFAULT_TICKET_TTL: u64 = 60;

/// SSO ticket 存储的 JSON 数据（依据 spec protocol-sso）。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SsoTicketData {
    /// 登录主体标识。
    login_id: i64,
    /// 客户端标识。
    client_id: i64,
}

/// SSO 客户端，提供 ticket 签发/校验/销毁（依据 spec protocol-sso）。
///
/// 持有 `Arc<dyn BulwarkDao>` 用于票据存储，TTL 默认 60 秒。
/// 实现 `Send + Sync`，可在多线程环境共享。
pub struct SsoClient {
    /// DAO 抽象层，用于票据存储。
    dao: Arc<dyn BulwarkDao>,
    /// 票据 TTL（秒）。
    ticket_ttl_seconds: u64,
}

impl SsoClient {
    /// 创建新的 SSO 客户端（依据 spec protocol-sso）。
    ///
    /// # 参数
    /// - `dao`: DAO 抽象层实例。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self {
            dao,
            ticket_ttl_seconds: DEFAULT_TICKET_TTL,
        }
    }

    /// 设置票据 TTL（秒），默认 60 秒。
    pub fn with_ticket_ttl(mut self, ttl_seconds: u64) -> Self {
        self.ticket_ttl_seconds = ttl_seconds;
        self
    }

    /// 签发 SSO ticket（依据 spec protocol-sso）。
    ///
    /// 生成 64 字符随机 hex 字符串作为 ticket，存储到 `bulwark:sso:ticket:<ticket>`，
    /// value 为 JSON `{login_id, client_id}`，TTL 为 60 秒。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `client_id`: 客户端标识。
    ///
    /// # 返回
    /// 64 字符的 ticket 字符串。
    pub async fn issue_ticket(&self, login_id: i64, client_id: i64) -> BulwarkResult<String> {
        // 拼接两个 UUID v4 simple（各 32 hex = 64 字符）
        let ticket = format!(
            "{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        let data = SsoTicketData { login_id, client_id };
        let value = serde_json::to_string(&data)
            .map_err(|e| BulwarkError::Internal(format!("序列化 SSO ticket 失败: {}", e)))?;
        let key = format!("bulwark:sso:ticket:{}", ticket);
        self.dao.set(&key, &value, self.ticket_ttl_seconds).await?;
        Ok(ticket)
    }

    /// 校验 SSO ticket（依据 spec protocol-sso）。
    ///
    /// 校验逻辑：(1) 票据存在；(2) 存储的 `client_id` 与传入 `client_id` 相等；
    /// (3) 票据为一次性，校验成功后立即从 dao 删除。
    ///
    /// # 参数
    /// - `ticket`: 票据字符串。
    /// - `client_id`: 客户端标识。
    ///
    /// # 返回
    /// - `Ok(login_id)`: 校验成功。
    /// - `Err(BulwarkError::InvalidToken)`: 票据不存在或已过期。
    /// - `Err(BulwarkError::Config)`: client_id 不匹配。
    pub async fn validate_ticket(&self, ticket: &str, client_id: i64) -> BulwarkResult<i64> {
        let key = format!("bulwark:sso:ticket:{}", ticket);
        let value = self.dao.get(&key).await?;
        let value = value.ok_or_else(|| {
            BulwarkError::InvalidToken("SSO 票据不存在或已过期".to_string())
        })?;
        let data: SsoTicketData = serde_json::from_str(&value)
            .map_err(|e| BulwarkError::Internal(format!("反序列化 SSO ticket 失败: {}", e)))?;
        if data.client_id != client_id {
            return Err(BulwarkError::Config(
                "SSO client_id 不匹配".to_string(),
            ));
        }
        // 校验成功，立即删除（一次性使用）
        self.dao.delete(&key).await?;
        Ok(data.login_id)
    }

    /// 销毁 SSO ticket（依据 spec protocol-sso）。
    ///
    /// 从 dao 中删除指定票据。即使票据不存在也返回 `Ok(())`（幂等）。
    pub async fn destroy_ticket(&self, ticket: &str) -> BulwarkResult<()> {
        let key = format!("bulwark:sso:ticket:{}", ticket);
        self.dao.delete(&key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    /// 测试用 Mock DAO，支持 TTL 模拟。
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
                Err(BulwarkError::Dao("key 不存在".to_string()))
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

    /// 创建 SsoClient 实例（使用 MockDao）。
    fn make_client() -> SsoClient {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        SsoClient::new(dao)
    }

    // ========================================================================
    // SsoClient 构造测试（依据 spec protocol-sso）
    // ========================================================================

    /// 构造 SsoClient，持有 dao（spec Scenario）。
    #[test]
    fn new_creates_client_with_dao() {
        let _client = make_client();
        // 构造成功即验证（dao 通过类型系统保证非空）
    }

    // ========================================================================
    // issue_ticket 测试（依据 spec protocol-sso）
    // ========================================================================

    /// 成功签发票据，返回 64 字符（spec Scenario）。
    #[tokio::test]
    async fn issue_ticket_returns_64_chars() {
        let client = make_client();
        let ticket = client.issue_ticket(1001, 2001).await.unwrap();
        assert_eq!(ticket.len(), 64);
        assert!(ticket.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// 票据随机性：连续签发返回不同票据（spec Scenario）。
    #[tokio::test]
    async fn issue_ticket_generates_unique_tickets() {
        let client = make_client();
        let t1 = client.issue_ticket(1001, 2001).await.unwrap();
        let t2 = client.issue_ticket(1001, 2001).await.unwrap();
        assert_ne!(t1, t2);
    }

    /// 相同 login_id 多 client 签发独立票据（spec Scenario）。
    #[tokio::test]
    async fn issue_ticket_same_login_different_clients() {
        let client = make_client();
        let t1 = client.issue_ticket(1001, 2001).await.unwrap();
        let t2 = client.issue_ticket(1001, 2002).await.unwrap();
        assert_ne!(t1, t2);
    }

    /// key 前缀正确（spec Scenario）。
    #[tokio::test]
    async fn issue_ticket_uses_correct_key_prefix() {
        let dao = Arc::new(MockDao::new());
        let client = SsoClient::new(dao.clone());
        let ticket = client.issue_ticket(1001, 2001).await.unwrap();
        let key = format!("bulwark:sso:ticket:{}", ticket);
        let value = dao.get(&key).await.unwrap();
        assert!(value.is_some());
        let data: SsoTicketData = serde_json::from_str(&value.unwrap()).unwrap();
        assert_eq!(data.login_id, 1001);
        assert_eq!(data.client_id, 2001);
    }

    // ========================================================================
    // validate_ticket 测试（依据 spec protocol-sso）
    // ========================================================================

    /// 成功校验返回 login_id（spec Scenario）。
    #[tokio::test]
    async fn validate_ticket_success_returns_login_id() {
        let client = make_client();
        let ticket = client.issue_ticket(1001, 2001).await.unwrap();
        let login_id = client.validate_ticket(&ticket, 2001).await.unwrap();
        assert_eq!(login_id, 1001);
    }

    /// 校验成功后票据被删除（一次性使用，spec Scenario）。
    #[tokio::test]
    async fn validate_ticket_deletes_after_success() {
        let client = make_client();
        let ticket = client.issue_ticket(1001, 2001).await.unwrap();
        let _ = client.validate_ticket(&ticket, 2001).await.unwrap();
        // 第二次校验应失败
        let result = client.validate_ticket(&ticket, 2001).await;
        assert!(result.is_err());
    }

    /// client_id 不匹配返回错误（spec Scenario）。
    #[tokio::test]
    async fn validate_ticket_client_id_mismatch_returns_error() {
        let client = make_client();
        let ticket = client.issue_ticket(1001, 2001).await.unwrap();
        let result = client.validate_ticket(&ticket, 9999).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Config(_)) => {}
            other => panic!("期望 Config 错误，实际: {:?}", other),
        }
    }

    /// 票据不存在返回错误（spec Scenario）。
    #[tokio::test]
    async fn validate_ticket_nonexistent_returns_error() {
        let client = make_client();
        let result = client.validate_ticket("nonexistent-ticket", 2001).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidToken(_)) => {}
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// 一次性使用：第二次校验失败（spec Scenario）。
    #[tokio::test]
    async fn validate_ticket_one_time_use_second_fails() {
        let client = make_client();
        let ticket = client.issue_ticket(1001, 2001).await.unwrap();
        let first = client.validate_ticket(&ticket, 2001).await;
        let second = client.validate_ticket(&ticket, 2001).await;
        assert!(first.is_ok());
        assert!(second.is_err());
    }

    // ========================================================================
    // destroy_ticket 测试（依据 spec protocol-sso）
    // ========================================================================

    /// 销毁存在的票据（spec Scenario）。
    #[tokio::test]
    async fn destroy_ticket_existing() {
        let client = make_client();
        let ticket = client.issue_ticket(1001, 2001).await.unwrap();
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
        let client = SsoClient::new(dao).with_ticket_ttl(120);
        assert_eq!(client.ticket_ttl_seconds, 120);
    }
}
