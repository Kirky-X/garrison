//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `SsoClient` 实现模块。
//!
//! 从 `mod.rs` 迁移以符合规则 25（mod.rs 接口隔离）：
//! impl 块与顶层 `fn sign_ticket` / `fn verify_ticket_signature` 不允许留在 `mod.rs`。
//!
//! 包含 HMAC-SHA256 ticket 签名工具与 `SsoClient` 方法实现。
//! `server.rs` 通过 `use super::client::{sign_ticket, verify_ticket_signature}` 直接引用。

use super::SsoClient;
use super::SsoTicketData;
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
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
pub(crate) fn sign_ticket(secret: &str, random_part: &str) -> GarrisonResult<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| GarrisonError::Internal(format!("sso-ticket-hmac-init::{}", e)))?;
    mac.update(random_part.as_bytes());
    Ok(BASE64_STANDARD.encode(mac.finalize().into_bytes()))
}

/// 验证 ticket 的 HMAC 签名（M5 修复，供 SsoClient / DefaultSsoServer 共用）。
///
/// 返回 `Ok(random_part)` 验证通过，`Err` 表示签名无效或格式错误。
pub(crate) fn verify_ticket_signature(secret: &str, ticket: &str) -> GarrisonResult<String> {
    let (random_part, sig_b64) = ticket
        .split_once('.')
        .ok_or_else(|| GarrisonError::InvalidToken("sso-ticket-format-no-sig".to_string()))?;
    // 常量时间比较：解码 base64 签名后用 mac.verify_slice 验证（与 sign/handler.rs 一致）
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| GarrisonError::Internal(format!("sso-ticket-hmac-init::{}", e)))?;
    mac.update(random_part.as_bytes());
    // 签名解码或验证失败均统一返回 "签名验证失败"，避免向调用方泄露失败原因（防侧信道）
    let sig_bytes = BASE64_STANDARD
        .decode(sig_b64)
        .map_err(|_| GarrisonError::InvalidToken("sso-ticket-sig-verify".to_string()))?;
    mac.verify_slice(&sig_bytes)
        .map_err(|_| GarrisonError::InvalidToken("sso-ticket-sig-verify".to_string()))?;
    Ok(random_part.to_string())
}

impl SsoClient {
    /// 创建新的 SSO 客户端。
    ///
    /// # 参数
    /// - `dao`: DAO 抽象层实例。
    /// - `secret`: HMAC 签名密钥（用于 ticket 防伪造，禁止空字符串）。
    ///
    /// # 错误
    /// - `secret` 为空时返回 `GarrisonError::InvalidParam`。
    pub fn new(dao: Arc<dyn GarrisonDao>, secret: impl Into<String>) -> Self {
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
    fn sign_ticket(&self, random_part: &str) -> GarrisonResult<String> {
        sign_ticket(&self.secret, random_part)
    }

    /// 验证 ticket 的 HMAC 签名（委托到模块级 `verify_ticket_signature`）。
    fn verify_ticket_signature(&self, ticket: &str) -> GarrisonResult<String> {
        verify_ticket_signature(&self.secret, ticket)
    }

    /// 签发 SSO ticket。
    ///
    /// 生成 `{64_hex_random}.{hmac_b64}` 格式的签名 ticket，
    /// 存储到 `garrison:sso:ticket:<ticket>`，value 为 JSON `{login_id, client_id}`，
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
    ) -> GarrisonResult<String> {
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
            .map_err(|e| GarrisonError::Internal(format!("sso-ticket-serialize::{}", e)))?;
        let key = format!("garrison:sso:ticket:{}", ticket);
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
    /// - `Err(GarrisonError::InvalidToken)`: 签名无效、票据不存在、已过期、client_id 不匹配、或被并发消费。
    ///
    /// # client_id 不匹配时不消费票据
    ///
    /// 与"防爆破"设计相反，本实现优先用户友好：错误 `client_id` 不删除票据，
    /// 允许正确 `client_id` 后续重试。适用于客户端配置错误、用户输错等场景。
    ///
    /// # 原子性保证（）
    ///
    /// `client_id` 校验通过后使用 `GarrisonDao::get_and_delete` 原子消费票据，
    /// 消除 TOCTOU 竞态。并发调用同一 ticket（同 client_id）仅一个返回 `Ok`，
    /// 其他返回 `InvalidToken`（"已被并发消费"）。
    pub async fn validate_ticket(&self, ticket: &str, client_id: i64) -> GarrisonResult<String> {
        // M5 修复：先验签，防止 DAO 攻破后伪造 ticket
        let _random_part = self.verify_ticket_signature(ticket)?;

        let key = format!("garrison:sso:ticket:{}", ticket);
        // 步骤 1: 非原子 get，用于校验 client_id（不删除票据）
        let value = self
            .dao
            .get(&key)
            .await
            .map_err(|e| GarrisonError::Dao(format!("sso-ticket-read::{}", e)))?;
        let value = value.ok_or_else(|| {
            GarrisonError::InvalidToken("sso-ticket-missing-or-expired".to_string())
        })?;
        let data: SsoTicketData = serde_json::from_str(&value)
            .map_err(|e| GarrisonError::Internal(format!("sso-ticket-deserialize::{}", e)))?;
        if data.client_id != client_id {
            // client_id 不匹配：不消费票据，允许正确 client_id 后续重试
            return Err(GarrisonError::InvalidToken(format!(
                "sso-ticket-client-id-mismatch::{}::{}",
                data.client_id, client_id
            )));
        }
        // 步骤 2: 原子 get_and_delete 消费票据（消除 TOCTOU 竞态）
        // 并发场景：多个同 client_id 请求都通过步骤 1，但仅一个 get_and_delete 返回 Some
        let consumed = self
            .dao
            .get_and_delete(&key)
            .await
            .map_err(|e| GarrisonError::Dao(format!("sso-ticket-atomic-consume::{}", e)))?;
        if consumed.is_none() {
            return Err(GarrisonError::InvalidToken(
                "sso-ticket-consumed-by-concurrent".to_string(),
            ));
        }
        Ok(data.login_id)
    }

    /// 销毁 SSO ticket。
    ///
    /// 从 dao 中删除指定票据。即使票据不存在也返回 `Ok(())`（幂等）。
    pub async fn destroy_ticket(&self, ticket: &str) -> GarrisonResult<()> {
        let key = format!("garrison:sso:ticket:{}", ticket);
        self.dao.delete(&key).await
    }
}

#[cfg(feature = "protocol-zeroize")]
impl Drop for SsoClient {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}
