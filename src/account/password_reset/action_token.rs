// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! ActionToken（找回密码动作令牌）：自包含 JWT（sub / purpose / jti / exp）。
//!
//! 复用 [`JwtHandler`](crate::protocol::jwt::JwtHandler) 的密钥材料与校验语义
//! （`sign_custom` / `verify_custom`），claims 增加 `purpose` 扩展字段：purpose
//! 与 [`PURPOSE_PASSWORD_RESET`] 不符的 token 一律拒绝，防止其他用途签发的
//! JWT 被挪用为改密凭据。
//!
//! jti（RFC 7519 §4.1.7）是一次性消费登记的主键，由 [`ActionTokenConsumer`]
//! 经 DAO `set_if_absent` 原子消费（见 `consumer` 模块）。

use crate::error::{GarrisonError, GarrisonResult};
use crate::protocol::jwt::JwtHandler;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// ActionToken `purpose` claim 固定值：找回密码。
pub const PURPOSE_PASSWORD_RESET: &str = "password_reset";

/// ActionToken 默认有效期（秒）：15 分钟。
///
/// 与既有验证码类凭据（`email:code` 600s）同量级，长时效改密凭据扩大重放窗口。
pub const DEFAULT_TOKEN_TTL_SECS: i64 = 900;

/// ActionToken claims（RFC 7519 子集 + `purpose` 扩展）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTokenClaims {
    /// 目标主体（login_id）：token 只对该主体的密码改密有效。
    pub sub: String,
    /// 用途标识：固定 [`PURPOSE_PASSWORD_RESET`]，其余值在校验时拒绝。
    pub purpose: String,
    /// JWT 唯一标识（一次性消费登记主键）。
    pub jti: String,
    /// 签发时间（Unix 秒）。
    pub iat: i64,
    /// 过期时间（Unix 秒）。
    pub exp: i64,
}

/// 签发结果：token 字符串 + 已写入的 claims（调用方需要 jti 做消费登记与绑定）。
#[derive(Debug, Clone)]
pub struct IssuedActionToken {
    /// JWT 字符串（交付给用户的找回凭据）。
    pub token: String,
    /// 签发时写入的 claims。
    pub claims: ActionTokenClaims,
}

/// ActionToken 签发/校验服务。
///
/// 持有 [`JwtHandler`](crate::protocol::jwt::JwtHandler)（密钥材料复用方），无独立状态；一次性消费语义在
/// [`ActionTokenConsumer`](super::ActionTokenConsumer)。
#[derive(Clone)]
pub struct ActionTokenService {
    jwt: Arc<JwtHandler>,
    ttl_secs: i64,
}

/// 手动实现 `Debug`：仅输出 TTL，不透出 `JwtHandler`（其 `secret` 字段为敏感材料）。
impl std::fmt::Debug for ActionTokenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionTokenService")
            .field("ttl_secs", &self.ttl_secs)
            .finish_non_exhaustive()
    }
}

impl ActionTokenService {
    /// 创建服务，使用默认有效期 [`DEFAULT_TOKEN_TTL_SECS`]。
    pub fn new(jwt: Arc<JwtHandler>) -> Self {
        Self {
            jwt,
            ttl_secs: DEFAULT_TOKEN_TTL_SECS,
        }
    }

    /// 覆盖有效期（秒）。`0` 合法（立即过期的 token，供过期拒绝测试与紧急停用）；
    /// 负值显性拒绝。
    pub fn with_ttl(mut self, ttl_secs: i64) -> GarrisonResult<Self> {
        if ttl_secs < 0 {
            return Err(GarrisonError::InvalidParam(format!(
                "pwdreset-ttl-negative::{}",
                ttl_secs
            )));
        }
        self.ttl_secs = ttl_secs;
        Ok(self)
    }

    /// 签发找回密码 ActionToken：sub + purpose=password_reset + 随机 jti + exp。
    pub fn issue(&self, subject: &str) -> GarrisonResult<IssuedActionToken> {
        let now = unix_now()?;
        let exp = now.checked_add(self.ttl_secs).ok_or_else(|| {
            GarrisonError::InvalidParam(format!("pwdreset-ttl-overflow::{}", self.ttl_secs))
        })?;
        let claims = ActionTokenClaims {
            sub: subject.to_string(),
            purpose: PURPOSE_PASSWORD_RESET.to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now,
            exp,
        };
        let token = self.jwt.sign_custom(&claims)?;
        Ok(IssuedActionToken { token, claims })
    }

    /// 校验 ActionToken：签名 + exp（leeway=0）+ purpose 白名单 + jti 非空。
    ///
    /// # 错误
    /// - 签名/格式非法：[`GarrisonError::InvalidToken`]（透传 `verify_custom`）
    /// - 已过期：[`GarrisonError::ExpiredToken`]
    /// - purpose 不符 / jti 缺失：[`GarrisonError::InvalidToken`]（显性错误码）
    pub fn verify(&self, token: &str) -> GarrisonResult<ActionTokenClaims> {
        let claims: ActionTokenClaims = self.jwt.verify_custom(token)?;
        if claims.purpose != PURPOSE_PASSWORD_RESET {
            return Err(GarrisonError::InvalidToken(format!(
                "action-token-purpose-mismatch::{}",
                claims.purpose
            )));
        }
        validate_jti(&claims.jti)?;
        Ok(claims)
    }
}

/// jti 结构校验（DAO key 注入防护）：非空、无 `:`、长度 ≤ 64。
///
/// jti 由本服务签发时为 UUID v4；校验外来 token 时防御性收口，
/// 防止拼接 `pwdreset:jti:{jti}` / `pwdreset:bind:{jti}` 时发生 key 注入。
pub(crate) fn validate_jti(jti: &str) -> GarrisonResult<()> {
    if jti.is_empty() || jti.len() > 64 || jti.contains(':') {
        return Err(GarrisonError::InvalidToken(format!(
            "action-token-jti-invalid::{}",
            jti.len()
        )));
    }
    Ok(())
}

/// 当前 Unix 秒（时钟倒退视为环境故障，显性报错不静默）。
pub(crate) fn unix_now() -> GarrisonResult<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| GarrisonError::Internal(format!("pwdreset-system-clock::{}", e)))
}
