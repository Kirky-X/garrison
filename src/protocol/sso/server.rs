//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SSO Server 独立抽象模块。
//!
//! 与 `SsoClient`（客户端）解耦，通过共享 `BulwarkDao` 间接通信。
//! 提供 `SsoServer` trait / `CenterIdConverter` trait / `SsoChannel` trait，
//! 以及 `DefaultSsoServer` / `IdentityCenterIdConverter` / `NoopSsoChannel` 默认实现。
//!
//! 仅在启用 `protocol-sso-server` 特性时编译。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

// 复用 `sso::client` 中的 `sign_ticket` + `verify_ticket_signature`，
// 以及 `sso::mod.rs` 中的 `SsoTicketData`，避免 ticket 格式漂移和签名逻辑重复。
use super::client::{sign_ticket, verify_ticket_signature};
use super::SsoTicketData;

/// SSO ticket 默认 TTL（秒），与 `SsoClient` 保持一致。
const DEFAULT_TICKET_TTL: u64 = 60;

// ============================================================================
// Trait 定义
// ============================================================================

/// SSO 服务端抽象 trait。
///
/// 与 `SsoClient`（客户端）解耦，通过共享 `BulwarkDao` 间接通信。
/// ticket 一次性使用，校验成功后立即销毁。
#[async_trait]
pub trait SsoServer: Send + Sync {
    /// 签发 SSO ticket。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（将委托 `CenterIdConverter::to_center_id` 转换为 center_id 后存储）。
    /// - `client_id`: 客户端标识。
    ///
    /// # 返回
    /// 64 字符的 ticket 字符串。
    async fn issue_ticket(&self, login_id: &str, client_id: i64) -> BulwarkResult<String>;

    /// 校验 SSO ticket（一次性使用，校验成功后立即销毁）。
    ///
    /// # 参数
    /// - `ticket`: 票据字符串。
    /// - `client_id`: 客户端标识。
    ///
    /// # 返回
    /// - `Ok(login_id)`: 校验成功（经 `CenterIdConverter::to_login_id` 转换回原始 login_id）。
    /// - `Err(BulwarkError::InvalidToken)`: 票据不存在、已过期或 client_id 不匹配。
    ///
    /// # 原子性保证（）
    ///
    /// 与 `SsoClient::validate_ticket` 相同，使用 `BulwarkDao::get_and_delete` 原子操作。
    /// R-002。
    async fn validate_ticket(&self, ticket: &str, client_id: i64) -> BulwarkResult<String>;

    /// 销毁 SSO ticket（幂等，即使票据不存在也返回 `Ok(())`）。
    async fn destroy_ticket(&self, ticket: &str) -> BulwarkResult<()>;

    /// 推送 SSO 消息到指定 login_id。
    ///
    /// 若未注入 `SsoChannel`，则 noop 返回 `Ok(())`。
    async fn push_message(&self, login_id: &str, message: &str) -> BulwarkResult<()>;
}

/// 中心 ID 转换器 trait。
///
/// 用于多子系统 login_id 映射，支持双向转换。
pub trait CenterIdConverter: Send + Sync {
    /// 将 login_id 转换为 center_id。
    fn to_center_id(&self, login_id: &str) -> String;

    /// 将 center_id 转换回 login_id。
    fn to_login_id(&self, center_id: &str) -> String;
}

/// SSO 消息推送通道 trait。
///
/// 作为 SSO 前后端消息推送抽象，支持自定义实现（如 Redis pub-sub）。
#[async_trait]
pub trait SsoChannel: Send + Sync {
    /// 推送消息到指定 topic。
    async fn push(&self, topic: &str, message: &str) -> BulwarkResult<()>;

    /// 订阅指定 topic 的消息。
    ///
    /// # 参数
    /// - `topic`: 订阅主题。
    /// - `handler`: 消息处理回调（收到消息时调用，参数为 owned `String` 以支持 `'static` 要求）。
    async fn subscribe(
        &self,
        topic: &str,
        handler: Box<dyn Fn(String) + Send + Sync>,
    ) -> BulwarkResult<()>;
}

// ============================================================================
// 默认实现
// ============================================================================

/// 默认的 identity `CenterIdConverter` 实现。
///
/// `to_center_id` 和 `to_login_id` 都返回原始值（identity 转换）。
pub struct IdentityCenterIdConverter;

impl CenterIdConverter for IdentityCenterIdConverter {
    fn to_center_id(&self, login_id: &str) -> String {
        login_id.to_string()
    }

    fn to_login_id(&self, center_id: &str) -> String {
        center_id.to_string()
    }
}

/// 空操作 `SsoChannel` 默认实现。
///
/// 所有方法返回 `Ok(())`，不实际推送消息。
pub struct NoopSsoChannel;

#[async_trait]
impl SsoChannel for NoopSsoChannel {
    async fn push(&self, _topic: &str, _message: &str) -> BulwarkResult<()> {
        Ok(())
    }

    async fn subscribe(
        &self,
        _topic: &str,
        _handler: Box<dyn Fn(String) + Send + Sync>,
    ) -> BulwarkResult<()> {
        Ok(())
    }
}

/// 默认 `SsoServer` 实现。
///
/// 持有 `Arc<dyn BulwarkDao>` 用于票据存储，
/// `Option<Arc<dyn SsoChannel>>` 用于消息推送（未注入时 noop），
/// `Arc<dyn CenterIdConverter>` 用于 login_id <-> center_id 转换。
pub struct DefaultSsoServer {
    /// DAO 抽象层，用于票据存储。
    dao: Arc<dyn BulwarkDao>,
    /// 票据 TTL（秒）。
    ticket_ttl_seconds: u64,
    /// 消息推送通道（可选，未注入时 noop）。
    channel: Option<Arc<dyn SsoChannel>>,
    /// 中心 ID 转换器。
    converter: Arc<dyn CenterIdConverter>,
    /// HMAC 签名密钥（M5 修复：所有 ticket 必须签名，与 SsoClient 格式一致）。
    secret: String,
}

impl DefaultSsoServer {
    /// 创建新的 `DefaultSsoServer` 实例。
    ///
    /// 默认配置：
    /// - TTL = 60 秒
    /// - 无消息推送通道（noop）
    /// - identity 转换器
    ///
    /// # 参数
    /// - `dao`: DAO 抽象层实例。
    /// - `secret`: HMAC 签名密钥（与 SsoClient 必须一致，禁止空字符串）。
    pub fn new(dao: Arc<dyn BulwarkDao>, secret: impl Into<String>) -> Self {
        let secret: String = secret.into();
        assert!(
            !secret.is_empty(),
            "SSO secret 不能为空（依据安全审计 M5：ticket 必须签名）"
        );
        Self {
            dao,
            ticket_ttl_seconds: DEFAULT_TICKET_TTL,
            channel: None,
            converter: Arc::new(IdentityCenterIdConverter),
            secret,
        }
    }

    /// 设置票据 TTL（秒），默认 60 秒。
    pub fn with_ticket_ttl(mut self, ttl_seconds: u64) -> Self {
        self.ticket_ttl_seconds = ttl_seconds;
        self
    }

    /// 注入消息推送通道。
    pub fn with_channel(mut self, channel: Arc<dyn SsoChannel>) -> Self {
        self.channel = Some(channel);
        self
    }

    /// 注入中心 ID 转换器。
    pub fn with_converter(mut self, converter: Arc<dyn CenterIdConverter>) -> Self {
        self.converter = converter;
        self
    }
}

#[async_trait]
impl SsoServer for DefaultSsoServer {
    async fn issue_ticket(&self, login_id: &str, client_id: i64) -> BulwarkResult<String> {
        // 委托 CenterIdConverter 将 login_id 转换为 center_id 后存储
        let center_id = self.converter.to_center_id(login_id);
        // 拼接两个 UUID v4 simple（各 32 hex = 64 字符），与 SsoClient 格式一致
        let random_part = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        // M5 修复：对 ticket 签名，防止 DAO 攻破后伪造
        let sig = sign_ticket(&self.secret, &random_part)?;
        let ticket = format!("{}.{}", random_part, sig);
        let data = SsoTicketData {
            login_id: center_id,
            client_id,
        };
        let value = serde_json::to_string(&data)
            .map_err(|e| BulwarkError::Internal(format!("sso-ticket-serialize::{}", e)))?;
        let key = format!("bulwark:sso:ticket:{}", ticket);
        self.dao.set(&key, &value, self.ticket_ttl_seconds).await?;
        Ok(ticket)
    }

    async fn validate_ticket(&self, ticket: &str, client_id: i64) -> BulwarkResult<String> {
        // M5 修复：先验签，防止 DAO 攻破后伪造 ticket
        let _random_part = verify_ticket_signature(&self.secret, ticket)?;

        let key = format!("bulwark:sso:ticket:{}", ticket);
        // 步骤 1: 非原子 get，用于校验 client_id（不删除票据）
        // 与 SsoClient::validate_ticket 行为对齐：client_id 不匹配时不消费票据，
        // 允许正确 client_id 后续重试（用户友好优先于防爆破）。
        let value = self
            .dao
            .get(&key)
            .await
            .map_err(|e| BulwarkError::Dao(format!("sso-ticket-read::{}", e)))?;
        let value = value.ok_or_else(|| {
            BulwarkError::InvalidToken("sso-ticket-missing-or-expired".to_string())
        })?;
        let data: SsoTicketData = serde_json::from_str(&value)
            .map_err(|e| BulwarkError::Internal(format!("sso-ticket-deserialize::{}", e)))?;
        if data.client_id != client_id {
            return Err(BulwarkError::InvalidToken(format!(
                "sso-ticket-client-id-mismatch::{}::{}",
                data.client_id, client_id
            )));
        }
        // 步骤 2: 原子 get_and_delete 消费票据（消除 TOCTOU 竞态）
        let consumed = self
            .dao
            .get_and_delete(&key)
            .await
            .map_err(|e| BulwarkError::Dao(format!("sso-ticket-atomic-consume::{}", e)))?;
        if consumed.is_none() {
            return Err(BulwarkError::InvalidToken(
                "sso-ticket-consumed-by-concurrent".to_string(),
            ));
        }
        // 委托 converter 将 center_id 转回原始 login_id
        let login_id = self.converter.to_login_id(&data.login_id);
        Ok(login_id)
    }

    async fn destroy_ticket(&self, ticket: &str) -> BulwarkResult<()> {
        let key = format!("bulwark:sso:ticket:{}", ticket);
        self.dao.delete(&key).await
    }

    async fn push_message(&self, login_id: &str, message: &str) -> BulwarkResult<()> {
        if let Some(channel) = &self.channel {
            let topic = format!("sso:user:{}", login_id);
            channel.push(&topic, message).await?;
        }
        // 未注入 channel 时 noop
        Ok(())
    }
}

#[cfg(feature = "protocol-zeroize")]
impl Drop for DefaultSsoServer {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::protocol::sso::SsoClient;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ========================================================================
    // 构造测试
    // ========================================================================

    /// 构造 DefaultSsoServer，持有 dao（spec Scenario）。
    #[test]
    fn new_creates_server_with_dao() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let _server = DefaultSsoServer::new(dao, "test-sso-secret-key");
        // 构造成功即验证（dao 通过类型系统保证非空）
    }

    /// with_ticket_ttl / with_channel / with_converter 链式构造。
    #[test]
    fn builder_chain_sets_fields() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let server = DefaultSsoServer::new(dao, "test-sso-secret-key")
            .with_ticket_ttl(120)
            .with_channel(Arc::new(NoopSsoChannel))
            .with_converter(Arc::new(IdentityCenterIdConverter));
        assert_eq!(server.ticket_ttl_seconds, 120);
        assert!(server.channel.is_some());
    }

    // ========================================================================
    // CenterIdConverter 测试
    // ========================================================================

    /// IdentityCenterIdConverter 默认实现往返一致（spec Scenario）。
    #[test]
    fn identity_converter_roundtrip() {
        let converter = IdentityCenterIdConverter;
        let center_id = converter.to_center_id("1001");
        let login_id = converter.to_login_id(&center_id);
        assert_eq!(login_id, "1001");
        // identity 转换：center_id == login_id
        assert_eq!(center_id, "1001");
    }

    /// 自定义 CenterIdConverter 实现（login_id 加前缀 c- 作为 center_id）（spec Scenario）。
    #[test]
    fn custom_converter_roundtrip() {
        struct OffsetConverter;
        impl CenterIdConverter for OffsetConverter {
            fn to_center_id(&self, login_id: &str) -> String {
                format!("c-{}", login_id)
            }
            fn to_login_id(&self, center_id: &str) -> String {
                center_id
                    .strip_prefix("c-")
                    .unwrap_or(center_id)
                    .to_string()
            }
        }
        let converter = OffsetConverter;
        let center_id = converter.to_center_id("1001");
        assert_eq!(center_id, "c-1001");
        let login_id = converter.to_login_id(&center_id);
        assert_eq!(login_id, "1001");
    }

    // ========================================================================
    // NoopSsoChannel 测试
    // ========================================================================

    /// NoopSsoChannel::push 返回 Ok 且不实际推送（spec Scenario）。
    #[tokio::test]
    async fn noop_channel_push_returns_ok() {
        let channel = NoopSsoChannel;
        let result = channel.push("topic", "msg").await;
        assert!(result.is_ok());
    }

    /// NoopSsoChannel::subscribe 返回 Ok。
    #[tokio::test]
    async fn noop_channel_subscribe_returns_ok() {
        let channel = NoopSsoChannel;
        let handler: Box<dyn Fn(String) + Send + Sync> = Box::new(|_msg: String| {});
        let result = channel.subscribe("topic", handler).await;
        assert!(result.is_ok());
    }

    // ========================================================================
    // DefaultSsoServer::issue_ticket + validate_ticket 测试
    // ========================================================================

    /// issue_ticket + validate_ticket 往返（一次性使用，spec Scenario）。
    #[tokio::test]
    async fn issue_and_validate_ticket_roundtrip() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let server = DefaultSsoServer::new(dao, "test-sso-secret-key");
        let ticket = server.issue_ticket("1001", 2001).await.unwrap();
        let login_id = server.validate_ticket(&ticket, 2001).await.unwrap();
        assert_eq!(login_id, "1001");
    }

    /// issue_ticket 返回 64 字符（与 SsoClient 格式一致）。
    #[tokio::test]
    async fn issue_ticket_returns_64_chars() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let server = DefaultSsoServer::new(dao, "test-sso-secret-key");
        let ticket = server.issue_ticket("1001", 2001).await.unwrap();
        // 新格式：{64_hex_random}.{hmac_b64}，长度不再固定为 64
        let parts: Vec<&str> = ticket.splitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "ticket 应包含分隔符 '.'");
        assert_eq!(parts[0].len(), 64, "random 部分应为 64 字符 hex");
        assert!(parts[0].chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// validate_ticket 一次性使用：第二次校验失败（spec Scenario）。
    #[tokio::test]
    async fn validate_ticket_one_time_use_second_fails() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let server = DefaultSsoServer::new(dao, "test-sso-secret-key");
        let ticket = server.issue_ticket("1001", 2001).await.unwrap();
        let first = server.validate_ticket(&ticket, 2001).await;
        let second = server.validate_ticket(&ticket, 2001).await;
        assert!(first.is_ok());
        assert!(second.is_err());
    }

    /// validate_ticket client_id 不匹配返回 InvalidToken 错误（M5 修复）。
    #[tokio::test]
    async fn validate_ticket_client_id_mismatch_returns_error() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let server = DefaultSsoServer::new(dao, "test-sso-secret-key");
        let ticket = server.issue_ticket("1001", 2001).await.unwrap();
        let result = server.validate_ticket(&ticket, 9999).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidToken(_)) => {},
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// validate_ticket 不存在返回 InvalidToken 错误。
    #[tokio::test]
    async fn validate_ticket_nonexistent_returns_error() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let server = DefaultSsoServer::new(dao, "test-sso-secret-key");
        let result = server.validate_ticket("nonexistent-ticket", 2001).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidToken(_)) => {},
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    // ========================================================================
    // destroy_ticket 测试
    // ========================================================================

    /// destroy_ticket 幂等：销毁不存在的票据返回 Ok（spec Scenario）。
    #[tokio::test]
    async fn destroy_ticket_idempotent() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let server = DefaultSsoServer::new(dao, "test-sso-secret-key");
        // 销毁不存在的票据
        let result = server.destroy_ticket("nonexistent-ticket").await;
        assert!(result.is_ok());
        // 销毁存在的票据
        let ticket = server.issue_ticket("1001", 2001).await.unwrap();
        let result1 = server.destroy_ticket(&ticket).await;
        let result2 = server.destroy_ticket(&ticket).await;
        assert!(result1.is_ok());
        assert!(result2.is_ok(), "destroy_ticket 应幂等");
    }

    // ========================================================================
    // 自定义 CenterIdConverter 集成测试
    // ========================================================================

    /// 注入自定义 CenterIdConverter 后，issue_ticket 存储 center_id，validate_ticket 返回原始 login_id。
    #[tokio::test]
    async fn custom_converter_issue_validate_roundtrip() {
        struct OffsetConverter;
        impl CenterIdConverter for OffsetConverter {
            fn to_center_id(&self, login_id: &str) -> String {
                format!("c-{}", login_id)
            }
            fn to_login_id(&self, center_id: &str) -> String {
                center_id
                    .strip_prefix("c-")
                    .unwrap_or(center_id)
                    .to_string()
            }
        }
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let server = DefaultSsoServer::new(dao, "test-sso-secret-key")
            .with_converter(Arc::new(OffsetConverter));
        let ticket = server.issue_ticket("1001", 2001).await.unwrap();
        let login_id = server.validate_ticket(&ticket, 2001).await.unwrap();
        // 往返一致：返回原始 login_id（而非 center_id）
        assert_eq!(login_id, "1001");
    }

    // ========================================================================
    // push_message 测试
    // ========================================================================

    /// push_message 未注入 channel 时返回 Ok（noop）。
    #[tokio::test]
    async fn push_message_noop_when_no_channel() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let server = DefaultSsoServer::new(dao, "test-sso-secret-key");
        let result = server.push_message("1001", "hello").await;
        assert!(result.is_ok());
    }

    /// push_message 注入 channel 后委托 channel.push。
    #[tokio::test]
    async fn push_message_delegates_to_channel() {
        /// 计数器 channel，记录 push 调用次数。
        struct CountingChannel {
            count: AtomicUsize,
        }
        #[async_trait]
        impl SsoChannel for CountingChannel {
            async fn push(&self, _topic: &str, _message: &str) -> BulwarkResult<()> {
                self.count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            async fn subscribe(
                &self,
                _topic: &str,
                _handler: Box<dyn Fn(String) + Send + Sync>,
            ) -> BulwarkResult<()> {
                Ok(())
            }
        }
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let channel = Arc::new(CountingChannel {
            count: AtomicUsize::new(0),
        });
        let server =
            DefaultSsoServer::new(dao, "test-sso-secret-key").with_channel(channel.clone());
        server.push_message("1001", "hello").await.unwrap();
        server.push_message("1002", "world").await.unwrap();
        assert_eq!(channel.count.load(Ordering::SeqCst), 2);
    }

    // ========================================================================
    // SsoServer 与 SsoClient 通过共享 BulwarkDao 间接通信（spec Scenario）
    // ========================================================================

    /// SsoServer 签发的 ticket 可被 SsoClient 校验（共享 DAO，spec Scenario）。
    #[tokio::test]
    async fn server_and_client_communicate_via_shared_dao() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        // SsoServer 签发 ticket
        let server = DefaultSsoServer::new(dao.clone(), "test-sso-secret-key");
        let ticket = server.issue_ticket("1001", 2001).await.unwrap();
        // SsoClient 校验同一 ticket（共享 DAO）
        let client = SsoClient::new(dao, "test-sso-secret-key");
        let login_id = client.validate_ticket(&ticket, 2001).await.unwrap();
        assert_eq!(login_id, "1001");
    }

    /// SsoClient 签发的 ticket 可被 SsoServer 校验（共享 DAO，反向）。
    #[tokio::test]
    async fn client_and_server_communicate_via_shared_dao() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        // SsoClient 签发 ticket
        let client = SsoClient::new(dao.clone(), "test-sso-secret-key");
        let ticket = client.issue_ticket("1001", 2001).await.unwrap();
        // SsoServer 校验同一 ticket（共享 DAO）
        let server = DefaultSsoServer::new(dao, "test-sso-secret-key");
        let login_id = server.validate_ticket(&ticket, 2001).await.unwrap();
        assert_eq!(login_id, "1001");
    }
}
