// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 注册/认证仪式编排。
//!
//! 仪式态经 [`ChallengeStore`] 暂存（challenge 一次性），凭据经
//! [`WebauthnCredentialRepository`] 落库（credential_id 唯一约束兜底并发绑定）。
//!
//! ## 反重放链路
//!
//! start_*：webauthn-rs 产出随机 challenge → 仪式态以 challenge 为键 SETNX 暂存。
//! finish_*：从响应的 clientDataJSON 提取 challenge → GETDEL 原子消费
//! （不存在即 [`WebauthnCeremonyError::ChallengeReplayed`]）→ webauthn-rs 复核
//! challenge/signature/origin → 落库或处置。
//!
//! ## 克隆检测
//!
//! webauthn-rs（`require_valid_counter_value` 默认开启）在 assertion 的
//! sign_count ≤ 存储值时返回 `CredentialPossibleCompromise`，本模块映射为
//! [`WebauthnCeremonyError::CloneSuspected`] 显性拒绝。
//!
//! ## RP 配置派生
//!
//! [`RelyingParty::derive`]：`rp_id` = issuer URL host，`origins` = [issuer]。
//! issuer 变更后 rp_id 自动跟随（新凭据绑定新 rp_id；既有凭据的 rpIdHash
//! 由 authenticator 侧绑定旧 rp_id，更换 issuer 属迁移事项，不在本模块处理）。

use super::challenge::{ChallengePayload, ChallengeStore};
use super::credential::WebauthnCredential;
use super::{FactorPurpose, WebauthnCeremonyError, WebauthnConfig};
use crate::dao::repository::{WebauthnBindOutcome, WebauthnCredentialRepository};
use crate::error::{GarrisonError, GarrisonResult};
use std::sync::Arc;
use webauthn_rs::prelude::{
    Base64UrlSafeData, Credential, CredentialID, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid, Webauthn as WebauthnRs, WebauthnBuilder, WebauthnError,
};

/// RP 配置（从 issuer URL 派生）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    /// RP ID（issuer URL host）。
    pub rp_id: String,
    /// RP origin（issuer 本身）。
    pub origin: Url,
}

impl RelyingParty {
    /// 从 issuer URL 派生 RP 配置。
    ///
    /// issuer 非法 URL 或无 host（如相对路径）→ `Config` 显性报错。
    pub fn derive(issuer: &str) -> GarrisonResult<Self> {
        let origin = Url::parse(issuer)
            .map_err(|e| GarrisonError::Config(format!("webauthn-issuer-invalid::{e}")))?;
        let host = origin.host_str().filter(|h| !h.is_empty()).ok_or_else(|| {
            GarrisonError::Config(format!("webauthn-issuer-host-missing::{issuer}"))
        })?;
        Ok(Self {
            rp_id: host.to_string(),
            origin,
        })
    }

    /// 构造 webauthn-rs 实例（rp_id 与 origin 的强一致由 builder 校验）。
    fn build_webauthn(&self) -> GarrisonResult<WebauthnRs> {
        WebauthnBuilder::new(&self.rp_id, &self.origin)
            .map_err(|e| GarrisonError::Config(format!("webauthn-rp-mismatch::{e}")))?
            .build()
            .map_err(|e| GarrisonError::Config(format!("webauthn-rp-build::{e}")))
    }
}

/// 认证仪式结果视图（供 MFA 编排层消费）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebauthnAuthentication {
    /// 租户 ID。
    pub tenant_id: i64,
    /// 用户 ID（challenge 暂存时锁定）。
    pub user_id: String,
    /// 凭据 ID（base64url）。
    pub credential_id: String,
    /// 断言后的 sign_count。
    pub sign_count: u32,
    /// 断言后的 backup_eligible。
    pub backup_eligible: bool,
    /// 断言后的 backup_state。
    pub backup_state: bool,
    /// 本次断言是否通过用户验证（UV）。
    pub user_verified: bool,
    /// 凭据状态是否因本次断言发生变更（sign_count/backup flags 落库更新）。
    pub credential_updated: bool,
}

/// WebAuthn 仪式服务。
pub struct WebauthnService {
    /// challenge 暂存存储。
    challenges: ChallengeStore,
    /// 凭据仓库。
    credentials: Arc<dyn WebauthnCredentialRepository>,
    /// 配置（构造后不可变）。
    config: WebauthnConfig,
}

/// 从 clientDataJSON 提取 challenge（base64url 字符串）。
///
/// challenge 是攻击者可控输入且被用作 KV 消费键位——校验 base64url 字符集
/// 与长度上界（服务器签发的 challenge 为 16 字节随机数编码，≤ 512 字符已
/// 远超实际需要），防超长/任意字节键造成的资源消耗面。
fn extract_client_data_challenge(
    client_data_json: &Base64UrlSafeData,
) -> Result<String, WebauthnCeremonyError> {
    const MAX_CHALLENGE_KEY_CHARS: usize = 512;
    let text = std::str::from_utf8(client_data_json.as_slice())
        .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("clientdata-utf8::{e}")))?;
    let v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("clientdata-parse::{e}")))?;
    let challenge = v.get("challenge").and_then(|c| c.as_str()).ok_or_else(|| {
        WebauthnCeremonyError::CeremonyRejected("clientdata-challenge-missing".to_string())
    })?;
    if challenge.len() > MAX_CHALLENGE_KEY_CHARS
        || !challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(WebauthnCeremonyError::CeremonyRejected(
            "clientdata-challenge-malformed".to_string(),
        ));
    }
    Ok(challenge.to_string())
}

/// 从 assertion 的 authenticatorData 提取 sign_count（偏移 33 起 4 字节大端）。
///
/// 仅用于克隆嫌疑错误的诊断信息；真伪由 webauthn-rs 签名验证裁决。
fn assertion_counter(authenticator_data: &Base64UrlSafeData) -> Option<u32> {
    let bytes = authenticator_data.as_slice();
    if bytes.len() < 37 {
        return None;
    }
    Some(u32::from_be_bytes([
        bytes[33], bytes[34], bytes[35], bytes[36],
    ]))
}

/// webauthn-rs 错误 → 仪式错误（显性保留上游语义）。
fn map_webauthn_error(e: &WebauthnError) -> WebauthnCeremonyError {
    match e {
        WebauthnError::CredentialPossibleCompromise => {
            // 上游在 sign_count ≤ 存储值时返回（克隆嫌疑）；stored/asserted
            // 数值由调用方补充，此处先以语义化变体标记
            WebauthnCeremonyError::CeremonyRejected(format!("credential-possible-compromise::{e}"))
        },
        other => WebauthnCeremonyError::CeremonyRejected(format!("ceremony::{other}")),
    }
}

impl WebauthnService {
    /// 创建实例。
    pub fn new(
        dao: Arc<dyn crate::dao::GarrisonDao>,
        credentials: Arc<dyn WebauthnCredentialRepository>,
        config: WebauthnConfig,
    ) -> Self {
        Self {
            challenges: ChallengeStore::new(dao, config.challenge_ttl_secs),
            credentials,
            config,
        }
    }

    /// 按 issuer 派生 RP 并构造 webauthn-rs 实例。
    fn webauthn_for_current_issuer(&self) -> GarrisonResult<WebauthnRs> {
        RelyingParty::derive(&self.config.issuer)?.build_webauthn()
    }

    /// 提取 challenge 的 base64url 键位。
    fn challenge_key_of(challenge: &Base64UrlSafeData) -> GarrisonResult<String> {
        serde_json::to_string(challenge)
            .map(|s| s.trim_matches('"').to_string())
            .map_err(|e| GarrisonError::Internal(format!("webauthn-challenge-encode::{e}")))
    }

    /// policy 门控：用途关闭 → [`WebauthnCeremonyError::PolicyDisabled`]。
    fn ensure_purpose_enabled(&self, purpose: FactorPurpose) -> Result<(), WebauthnCeremonyError> {
        let enabled = match purpose {
            FactorPurpose::Passwordless => self.config.passwordless.enabled,
            FactorPurpose::SecondFactor => self.config.second_factor.enabled,
        };
        if enabled {
            Ok(())
        } else {
            Err(WebauthnCeremonyError::PolicyDisabled(purpose))
        }
    }

    // ========================================================================
    // 注册仪式
    // ========================================================================

    /// 发起注册：ExcludeCredentials 携带用户既有凭据（防同 authenticator
    /// 重复绑定的协议级防线），仪式态按 challenge 暂存。
    pub async fn start_registration(
        &self,
        tenant_id: i64,
        user_id: &str,
        user_name: &str,
        display_name: &str,
        user_unique_id: Uuid,
        purpose: FactorPurpose,
    ) -> Result<webauthn_rs::prelude::CreationChallengeResponse, WebauthnCeremonyError> {
        self.ensure_purpose_enabled(purpose)?;
        let wan = self
            .webauthn_for_current_issuer()
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("rp::{e}")))?;

        let existing = self
            .credentials
            .list_by_user(tenant_id, user_id)
            .await
            .map_err(|e| {
                WebauthnCeremonyError::CeremonyRejected(format!("list-credentials::{e}"))
            })?;
        // 仅需 credential_id 一列——不做整行 from_row 解析（注册为冷路径，
        // 但避免无谓的 KB 级 public_key JSON 反序列化）
        let mut exclude_ids = Vec::with_capacity(existing.len());
        for row in &existing {
            let id: CredentialID = serde_json::from_str(&format!("\"{}\"", row.credential_id))
                .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("cred-id::{e}")))?;
            exclude_ids.push(id);
        }
        let exclude = if exclude_ids.is_empty() {
            None
        } else {
            Some(exclude_ids)
        };

        let (ccr, state) = wan
            .start_passkey_registration(user_unique_id, user_name, display_name, exclude)
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("start-register::{e}")))?;
        let challenge_b64 = Self::challenge_key_of(&ccr.public_key.challenge)
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("challenge::{e}")))?;
        self.challenges
            .store(
                &challenge_b64,
                &ChallengePayload::Registration {
                    state,
                    tenant_id,
                    user_id: user_id.to_string(),
                    purpose,
                },
            )
            .await
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("store::{e}")))?;
        Ok(ccr)
    }

    /// 完成注册：challenge 原子消费 → attestation 复核 → 凭据落库。
    ///
    /// 同 authenticator（credential_id）重复绑定在唯一约束处显性拒绝
    /// （[`WebauthnCeremonyError::CredentialAlreadyBound`]），库内不产生第二行。
    pub async fn finish_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
    ) -> Result<WebauthnCredential, WebauthnCeremonyError> {
        let challenge_b64 = extract_client_data_challenge(&reg.response.client_data_json)?;
        let payload = self.challenges.consume(&challenge_b64).await?;
        let (state, tenant_id, user_id) = match payload {
            ChallengePayload::Registration {
                state,
                tenant_id,
                user_id,
                ..
            } => (state, tenant_id, user_id),
            ChallengePayload::Authentication { .. } => {
                return Err(WebauthnCeremonyError::ChallengeKindMismatch);
            },
        };

        let wan = self
            .webauthn_for_current_issuer()
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("rp::{e}")))?;
        let passkey = wan
            .finish_passkey_registration(reg, &state)
            .map_err(|e| map_webauthn_error(&e))?;
        let credential =
            WebauthnCredential::from_ceremony(tenant_id, &user_id, Credential::from(passkey));
        let credential = credential
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("model::{e}")))?;
        let row = credential
            .to_row()
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("model::{e}")))?;

        match self.credentials.create(&row).await {
            Ok(WebauthnBindOutcome::Bound) => Ok(credential),
            Ok(WebauthnBindOutcome::AlreadyBound { .. }) => {
                Err(WebauthnCeremonyError::CredentialAlreadyBound)
            },
            Err(e) => Err(WebauthnCeremonyError::CeremonyRejected(format!(
                "bind::{e}"
            ))),
        }
    }

    // ========================================================================
    // 认证仪式
    // ========================================================================

    /// 发起认证：以用户既有凭据构造 allow-list，仪式态按 challenge 暂存。
    pub async fn start_authentication(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> Result<RequestChallengeResponse, WebauthnCeremonyError> {
        let rows = self
            .credentials
            .list_by_user(tenant_id, user_id)
            .await
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("list::{e}")))?;
        if rows.is_empty() {
            return Err(WebauthnCeremonyError::NoCredentialBound);
        }
        let mut passkeys = Vec::with_capacity(rows.len());
        for row in rows {
            let cred = WebauthnCredential::from_row(row)
                .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("row::{e}")))?;
            passkeys.push(cred.to_passkey());
        }

        let wan = self
            .webauthn_for_current_issuer()
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("rp::{e}")))?;
        let (rcr, state) = wan
            .start_passkey_authentication(&passkeys)
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("start-auth::{e}")))?;
        let challenge_b64 = Self::challenge_key_of(&rcr.public_key.challenge)
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("challenge::{e}")))?;
        self.challenges
            .store(
                &challenge_b64,
                &ChallengePayload::Authentication {
                    state,
                    tenant_id,
                    user_id: user_id.to_string(),
                },
            )
            .await
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("store::{e}")))?;
        Ok(rcr)
    }

    /// 完成认证：challenge 原子消费 → assertion 复核（含 sign_count 单调性，
    /// 回退即克隆嫌疑拒绝）→ backup flags / sign_count 更新落库。
    pub async fn finish_authentication(
        &self,
        assertion: &PublicKeyCredential,
    ) -> Result<WebauthnAuthentication, WebauthnCeremonyError> {
        let challenge_b64 = extract_client_data_challenge(&assertion.response.client_data_json)?;
        let payload = self.challenges.consume(&challenge_b64).await?;
        let (state, tenant_id, user_id) = match payload {
            ChallengePayload::Authentication {
                state,
                tenant_id,
                user_id,
            } => (state, tenant_id, user_id),
            ChallengePayload::Registration { .. } => {
                return Err(WebauthnCeremonyError::ChallengeKindMismatch);
            },
        };

        let wan = self
            .webauthn_for_current_issuer()
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("rp::{e}")))?;
        let result = match wan.finish_passkey_authentication(assertion, &state) {
            Ok(r) => r,
            Err(WebauthnError::CredentialPossibleCompromise) => {
                // 克隆嫌疑：sign_count ≤ 存储值。stored 取被断言凭据的当前
                // 落库值，asserted 取 authenticatorData 声称值（仅诊断用；
                // 真伪由上游签名验证裁决）
                let stored = self
                    .stored_counter_for(tenant_id, assertion)
                    .await
                    .unwrap_or(0);
                let asserted =
                    assertion_counter(&assertion.response.authenticator_data).unwrap_or(0);
                return Err(WebauthnCeremonyError::CloneSuspected { stored, asserted });
            },
            Err(other) => {
                return Err(WebauthnCeremonyError::CeremonyRejected(format!(
                    "assertion::{other}"
                )));
            },
        };

        // 按主键 (tenant_id, credential_id) 直取被断言凭据（O(1) 行、1 次解析；
        // 认证是热路径，不做 list_by_user 全量拉取），落库更新 sign_count /
        // backup flags
        let asserted_id = base64url_string(result.cred_id())
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("cred-id::{e}")))?;
        let matched = self
            .credentials
            .find_by_credential_id(tenant_id, &asserted_id)
            .await
            .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("find::{e}")))?;
        let mut credential = match matched {
            Some(row) => WebauthnCredential::from_row(row)
                .map_err(|e| WebauthnCeremonyError::CeremonyRejected(format!("row::{e}")))?,
            None => {
                return Err(WebauthnCeremonyError::CeremonyRejected(
                    "asserted-credential-not-found".to_string(),
                ));
            },
        };

        // 权威值复核（克隆检测的落库基准）：上游 CredentialPossibleCompromise
        // 判定对照的是 start_authentication 时刻的仪式态快照；仪式 in-flight
        // 期间（TTL 120s 窗口）落库值可能已被并发认证推进——克隆与原件交错
        // 使用时快照基准会漏报回退。此处以落库权威值复核，沿用上游零值规则
        // （双方为 0 的计数器不适用单调性——不符合规范的认证器恒 0）。
        let asserted_counter = result.counter();
        if (asserted_counter > 0 || credential.sign_count > 0)
            && asserted_counter <= credential.sign_count
        {
            return Err(WebauthnCeremonyError::CloneSuspected {
                stored: credential.sign_count,
                asserted: asserted_counter,
            });
        }

        let credential_updated = credential.apply_authentication_result(&result);
        if credential_updated {
            self.credentials
                .update_authenticator_state(
                    tenant_id,
                    &credential.credential_id,
                    credential.sign_count,
                    credential.backup_eligible,
                    credential.backup_state,
                )
                .await
                .map_err(|e| {
                    WebauthnCeremonyError::CeremonyRejected(format!("update-state::{e}"))
                })?;
        }

        Ok(WebauthnAuthentication {
            tenant_id,
            user_id,
            credential_id: credential.credential_id,
            sign_count: credential.sign_count,
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
            user_verified: result.user_verified(),
            credential_updated,
        })
    }

    /// 查询被断言凭据的当前落库 sign_count（克隆嫌疑诊断用）。
    async fn stored_counter_for(
        &self,
        tenant_id: i64,
        assertion: &PublicKeyCredential,
    ) -> Option<u32> {
        let asserted_id = base64url_string(&assertion.raw_id).ok()?;
        self.credentials
            .find_by_credential_id(tenant_id, &asserted_id)
            .await
            .ok()
            .flatten()
            .map(|row| row.sign_count)
    }
}

/// serde 值 → base64url 字符串（`CredentialID`/`Base64UrlSafeData` 的 JSON
/// 形态即 base64url 无填充串）。
fn base64url_string<T: serde::Serialize>(v: &T) -> GarrisonResult<String> {
    serde_json::to_string(v)
        .map(|s| s.trim_matches('"').to_string())
        .map_err(|e| GarrisonError::Internal(format!("webauthn-cred-id-encode::{e}")))
}

impl std::fmt::Display for super::WebauthnCeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChallengeReplayed => write!(f, "webauthn challenge replayed or expired"),
            Self::ChallengeKindMismatch => write!(f, "webauthn challenge kind mismatch"),
            Self::CeremonyRejected(detail) => write!(f, "webauthn ceremony rejected: {detail}"),
            Self::CredentialAlreadyBound => write!(f, "webauthn credential already bound"),
            Self::CloneSuspected { stored, asserted } => write!(
                f,
                "webauthn sign_count regression (clone suspected): stored={stored}, asserted={asserted}"
            ),
            Self::NoCredentialBound => write!(f, "no webauthn credential bound for user"),
            Self::PolicyDisabled(purpose) => {
                write!(f, "webauthn factor policy disabled: {purpose:?}")
            },
        }
    }
}

impl std::error::Error for super::WebauthnCeremonyError {}

/// 供 GarrisonError 边界映射使用（stp/mfa 接线点）。
impl From<WebauthnCeremonyError> for GarrisonError {
    fn from(e: WebauthnCeremonyError) -> Self {
        GarrisonError::InvalidParam(format!("webauthn-ceremony::{e}"))
    }
}
