// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `SsoClient` 实现（接口隔离：impl 与顶层签名函数不放 `mod.rs`），含 HMAC-SHA256 ticket 签名工具；
//! `server.rs` 经 `use super::client::{sign_ticket, verify_ticket_signature}` 引用。

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

/// HMAC secret 最小长度（字节）：与 qrlogin / protocol-sign 的 32 字节下限对齐（短 secret 可被持票攻击者离线爆破后伪造票据签名）。
pub(crate) const MIN_SECRET_LEN: usize = 32;

/// 计算 ticket 随机部分的 HMAC-SHA256 签名（base64 输出；供 `SsoClient` / `DefaultSsoServer` 共用）。
pub(crate) fn sign_ticket(secret: &str, random_part: &str) -> GarrisonResult<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| GarrisonError::Internal(format!("sso-ticket-hmac-init::{}", e)))?;
    mac.update(random_part.as_bytes());
    Ok(BASE64_STANDARD.encode(mac.finalize().into_bytes()))
}

/// 验证 ticket 的 HMAC 签名，通过返回 `Ok(random_part)`（供 `SsoClient` / `DefaultSsoServer` 共用）。
pub(crate) fn verify_ticket_signature(secret: &str, ticket: &str) -> GarrisonResult<String> {
    let (random_part, sig_b64) = ticket
        .split_once('.')
        .ok_or_else(|| GarrisonError::InvalidToken("sso-ticket-format-no-sig::".to_string()))?;
    // 常量时间比较：解码 base64 签名后用 mac.verify_slice 验证（与 sign/handler.rs 一致）
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| GarrisonError::Internal(format!("sso-ticket-hmac-init::{}", e)))?;
    mac.update(random_part.as_bytes());
    // 签名解码或验证失败均统一返回 "签名验证失败"，避免向调用方泄露失败原因（防侧信道）
    let sig_bytes = BASE64_STANDARD
        .decode(sig_b64)
        .map_err(|_| GarrisonError::InvalidToken("sso-ticket-sig-verify::".to_string()))?;
    mac.verify_slice(&sig_bytes)
        .map_err(|_| GarrisonError::InvalidToken("sso-ticket-sig-verify::".to_string()))?;
    Ok(random_part.to_string())
}

impl SsoClient {
    /// 创建新的 SSO 客户端。
    ///
    /// `secret` 不可为空且不少于 `MIN_SECRET_LEN`（32 字节），否则返回 `GarrisonError::InvalidParam`（可恢复配置错误，不 panic）。
    pub fn new(dao: Arc<dyn GarrisonDao>, secret: impl Into<String>) -> GarrisonResult<Self> {
        let secret: String = secret.into();
        if secret.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "sso-client-secret-empty::".to_string(),
            ));
        }
        if secret.len() < MIN_SECRET_LEN {
            return Err(GarrisonError::InvalidParam(format!(
                "sso-client-secret-too-short::len={}::min={}",
                secret.len(),
                MIN_SECRET_LEN
            )));
        }
        Ok(Self {
            dao,
            ticket_ttl_seconds: DEFAULT_TICKET_TTL,
            secret,
        })
    }

    /// 设置票据 TTL（秒），默认 60 秒。
    pub fn with_ticket_ttl(mut self, ttl_seconds: u64) -> Self {
        self.ticket_ttl_seconds = ttl_seconds;
        self
    }

    fn sign_ticket(&self, random_part: &str) -> GarrisonResult<String> {
        sign_ticket(&self.secret, random_part)
    }

    fn verify_ticket_signature(&self, ticket: &str) -> GarrisonResult<String> {
        verify_ticket_signature(&self.secret, ticket)
    }

    /// 签发 SSO ticket：生成 `{64_hex_random}.{hmac_b64}` 签名票据，存 `garrison:sso:ticket:<ticket>`
    /// （value 为 JSON `{login_id, client_id}`，TTL 默认 60 秒可配置）。
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

    /// 校验 SSO ticket：先验签（防 DAO 攻破后伪造），再 `get` 读取并校验 `client_id`，最后 `get_and_delete` 原子消费（消除 TOCTOU）。
    ///
    /// `client_id` 不匹配时不消费票据（优先用户友好，允许正确 `client_id` 后续重试）；
    /// 并发调用同一 ticket（同 `client_id`）仅一个返回 `Ok`，其他返回 `InvalidToken`（已被并发消费）。
    pub async fn validate_ticket(&self, ticket: &str, client_id: i64) -> GarrisonResult<String> {
        let _random_part = self.verify_ticket_signature(ticket)?;

        let key = format!("garrison:sso:ticket:{}", ticket);
        // 非原子 get 校验 client_id（不删除票据）
        let value = self
            .dao
            .get(&key)
            .await
            .map_err(|e| GarrisonError::Dao(format!("sso-ticket-read::{}", e)))?;
        let value = value.ok_or_else(|| {
            GarrisonError::InvalidToken("sso-ticket-missing-or-expired::".to_string())
        })?;
        let data: SsoTicketData = serde_json::from_str(&value)
            .map_err(|e| GarrisonError::Internal(format!("sso-ticket-deserialize::{}", e)))?;
        if data.client_id != client_id {
            // client_id 不匹配：不消费票据（允许正确 client_id 重试）；错误消息固定，不回显 client_id（防枚举）。
            return Err(GarrisonError::InvalidToken(
                "sso-ticket-client-id-mismatch::".to_string(),
            ));
        }
        // 原子消费票据消除 TOCTOU：并发同 client_id 请求仅一个成功
        let consumed = self
            .dao
            .get_and_delete(&key)
            .await
            .map_err(|e| GarrisonError::Dao(format!("sso-ticket-atomic-consume::{}", e)))?;
        if consumed.is_none() {
            return Err(GarrisonError::InvalidToken(
                "sso-ticket-consumed-by-concurrent::".to_string(),
            ));
        }
        Ok(data.login_id)
    }

    /// 销毁 SSO ticket（幂等：票据不存在也返回 `Ok(())`）。
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
