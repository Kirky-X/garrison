// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! challenge 一次性暂存与原子消费。
//!
//! 仪式态（注册/认证）与完成仪式所需的上下文一起以 JSON 暂存：
//! - 签发走 `set_if_absent`（SETNX）：同键位二次签发显性报错（防覆盖攻击）。
//! - 消费走 `get_and_delete`（GETDEL）：键不存在（已消费/已过期/伪造）统一
//!   判 [`WebauthnCeremonyError::ChallengeReplayed`]——一次性语义下不区分
//!   重放与过期（都拒绝，不泄露状态差异）。
//! - TTL 由 `ttl_secs` 控制，随 SETNX 一并写入。
//!
//! 两原子的并发语义（SETNX 恰一赢家 / GETDEL 一次性消费）由 DAO 契约套件
//! 对全部后端持续回归。

use super::WebauthnCeremonyError;
use crate::error::{GarrisonError, GarrisonResult};
use std::sync::Arc;

/// 构造 challenge 暂存 key：`garrison:webauthn:challenge:<challenge_b64>`。
///
/// challenge 为 webauthn-rs 产出的 base64url 随机串（高熵），直接作键位即
/// 满足一次性消费语义；与 session/qrlogin 等命名空间隔离。
pub(crate) fn challenge_key(challenge_b64: &str) -> String {
    format!("garrison:webauthn:challenge:{challenge_b64}")
}

/// challenge 暂存载荷：仪式态 + 完成仪式所需的上下文。
///
/// `Registration`/`Authentication` 与 webauthn-rs 的 `PasskeyRegistration` /
/// `PasskeyAuthentication` 一一对应；上下文字段在完成仪式时用于凭据落库与
/// 处置分派，不信任完成请求重传。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChallengePayload {
    /// 注册仪式态。
    Registration {
        /// webauthn-rs 注册仪式态（含 challenge/算法策略）。
        state: webauthn_rs::prelude::PasskeyRegistration,
        /// 租户 ID。
        tenant_id: i64,
        /// 绑定目标用户 ID。
        user_id: String,
        /// 准入用途（注册期 policy 门控结论）。
        purpose: super::FactorPurpose,
    },
    /// 认证仪式态。
    Authentication {
        /// webauthn-rs 认证仪式态（含 challenge/允许凭据快照）。
        state: webauthn_rs::prelude::PasskeyAuthentication,
        /// 租户 ID。
        tenant_id: i64,
        /// 认证目标用户 ID（allow-list 流程在 start 时锁定）。
        user_id: String,
    },
}

/// challenge 暂存存储（DAO SETNX 签发 / GETDEL 原子消费）。
pub struct ChallengeStore {
    /// 数据访问抽象。
    dao: Arc<dyn crate::dao::GarrisonDao>,
    /// 仪式态 TTL（秒）。
    ttl_secs: u64,
}

impl ChallengeStore {
    /// 创建实例。
    pub fn new(dao: Arc<dyn crate::dao::GarrisonDao>, ttl_secs: u64) -> Self {
        Self { dao, ttl_secs }
    }

    /// 签发仪式态：SETNX 原子写入（TTL = 配置值）。
    ///
    /// 同键位二次签发（challenge 碰撞或攻击者重放签发）显性报错，
    /// 绝不覆盖既有仪式态。
    pub async fn store(
        &self,
        challenge_b64: &str,
        payload: &ChallengePayload,
    ) -> GarrisonResult<()> {
        let value = serde_json::to_string(payload)
            .map_err(|e| GarrisonError::Internal(format!("webauthn-challenge-serialize::{e}")))?;
        let claimed = self
            .dao
            .set_if_absent(&challenge_key(challenge_b64), &value, self.ttl_secs)
            .await
            .map_err(|e| GarrisonError::Dao(format!("webauthn-challenge-setifabsent::{e}")))?;
        if !claimed {
            return Err(GarrisonError::InvalidParam(format!(
                "webauthn-challenge-conflict::challenge key already claimed: {challenge_b64}"
            )));
        }
        Ok(())
    }

    /// 原子消费仪式态：GETDEL 读删一体。
    ///
    /// 键不存在（已消费 / TTL 过期 / 伪造）统一返回
    /// [`WebauthnCeremonyError::ChallengeReplayed`]；载荷反序列化失败为
    /// 存储完整性破坏，同样显性拒绝。
    pub async fn consume(
        &self,
        challenge_b64: &str,
    ) -> Result<ChallengePayload, WebauthnCeremonyError> {
        let raw = self
            .dao
            .get_and_delete(&challenge_key(challenge_b64))
            .await
            .map_err(|e| {
                WebauthnCeremonyError::CeremonyRejected(format!("webauthn-challenge-getdel::{e}"))
            })?;
        let raw = raw.ok_or(WebauthnCeremonyError::ChallengeReplayed)?;
        serde_json::from_str(&raw).map_err(|e| {
            WebauthnCeremonyError::CeremonyRejected(format!("webauthn-challenge-deserialize::{e}"))
        })
    }
}
