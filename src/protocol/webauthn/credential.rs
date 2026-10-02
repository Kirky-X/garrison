// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! WebAuthn 凭据领域模型与 SQL 行双向映射。
//!
//! [`WebauthnCredential`] 持有 webauthn-rs 的 [`Credential`] 协议态：
//! `public_key` 列存其完整 JSON（公钥 COSEKey / attestation 对象 / 注册期
//! policy / extensions——注册后不变的密钥材料）；`sign_count` / backup
//! flags 为**可变认证器状态**，以投影列为权威（认证仪式单调推进后由
//! `update_authenticator_state` 落库）。`from_row` 重建时以投影值覆盖协议
//! 态中的可变字段，并核对身份字段（credential_id）一致——不一致即行被
//! 篡改或写路径漂移，显性报错。

use crate::dao::repository::WebauthnCredentialRow;
use crate::error::{GarrisonError, GarrisonResult};
use webauthn_rs::prelude::{AuthenticationResult, Credential, CredentialID, Passkey};

/// WebAuthn 凭据领域模型。
#[derive(Debug, Clone)]
pub struct WebauthnCredential {
    /// 租户 ID。
    pub tenant_id: i64,
    /// 绑定用户 ID。
    pub user_id: String,
    /// 凭据 ID（base64url，唯一）。
    pub credential_id: String,
    /// 签名计数器（sign_count；克隆检测依据）。
    pub sign_count: u32,
    /// 备份资格（backup eligible；只升不降）。
    pub backup_eligible: bool,
    /// 备份状态（backup state；跟随最新断言）。
    pub backup_state: bool,
    /// attestation 格式标识（如 "none" / "packed"）。
    pub attestation_format: String,
    /// 创建时间（epoch seconds）。
    pub created_at: i64,
    /// 更新时间（epoch seconds）。
    pub updated_at: i64,
    /// 协议态（webauthn-rs Credential；序列化落 `public_key` 列）。
    credential: Credential,
}

/// 凭据 ID（`CredentialID`）↔ base64url 字符串互转。
///
/// `CredentialID`（`HumanBinaryData`）的 JSON 形态即 base64url 无填充串，
/// 借 serde 完成编解码，不引入额外 base64 依赖。
fn credential_id_to_base64(id: &CredentialID) -> GarrisonResult<String> {
    serde_json::to_string(id)
        .map(|s| s.trim_matches('"').to_string())
        .map_err(|e| GarrisonError::Internal(format!("webauthn-cred-id-encode::{e}")))
}

impl WebauthnCredential {
    /// 从注册仪式产物构造领域模型（注册落库入口）。
    pub fn from_ceremony(
        tenant_id: i64,
        user_id: &str,
        credential: Credential,
    ) -> GarrisonResult<Self> {
        let now = chrono::Utc::now().timestamp();
        let attestation_format = serde_json::to_string(&credential.attestation_format)
            .map_err(|e| GarrisonError::Internal(format!("webauthn-attestation-format::{e}")))?
            .trim_matches('"')
            .to_string();
        let credential_id = credential_id_to_base64(&credential.cred_id)?;
        Ok(Self {
            tenant_id,
            user_id: user_id.to_string(),
            sign_count: credential.counter,
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
            attestation_format,
            credential_id,
            created_at: now,
            updated_at: now,
            credential,
        })
    }

    /// 从 SQL 行重建：协议态 JSON 提供注册期不变的密钥材料，可变认证器
    /// 状态（sign_count/backup flags）以投影列为权威覆盖。
    ///
    /// 身份核对：JSON 内 credential_id 与投影列不一致 → `Dao` 显性报错
    /// （行被篡改或写路径漂移，不静默采信任一来源）。
    pub fn from_row(row: WebauthnCredentialRow) -> GarrisonResult<Self> {
        let mut credential: Credential = serde_json::from_str(&row.public_key)
            .map_err(|e| GarrisonError::Dao(format!("webauthn-cred-row-parse::{e}")))?;
        let attestation_format = serde_json::to_string(&credential.attestation_format)
            .map_err(|e| GarrisonError::Dao(format!("webauthn-cred-row-format::{e}")))?
            .trim_matches('"')
            .to_string();
        let credential_id = credential_id_to_base64(&credential.cred_id)?;

        if credential_id != row.credential_id {
            return Err(GarrisonError::Dao(format!(
                "webauthn-cred-row-identity-mismatch::credential_id={}",
                row.credential_id
            )));
        }
        // 可变状态以投影列为权威（认证仪式更新走投影列落库）
        credential.counter = row.sign_count;
        credential.backup_eligible = row.backup_eligible;
        credential.backup_state = row.backup_state;

        Ok(Self {
            tenant_id: row.tenant_id,
            user_id: row.user_id,
            credential_id,
            sign_count: row.sign_count,
            backup_eligible: row.backup_eligible,
            backup_state: row.backup_state,
            attestation_format,
            created_at: row.created_at,
            updated_at: row.updated_at,
            credential,
        })
    }

    /// 投影为 SQL 行（`public_key` 列承载完整协议态 JSON）。
    pub fn to_row(&self) -> GarrisonResult<WebauthnCredentialRow> {
        let public_key = serde_json::to_string(&self.credential)
            .map_err(|e| GarrisonError::Internal(format!("webauthn-cred-row-encode::{e}")))?;
        Ok(WebauthnCredentialRow {
            tenant_id: self.tenant_id,
            user_id: self.user_id.clone(),
            credential_id: self.credential_id.clone(),
            public_key,
            sign_count: self.sign_count,
            backup_eligible: self.backup_eligible,
            backup_state: self.backup_state,
            attestation: Some(self.attestation_format.clone()),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    /// 重建 webauthn-rs [`Passkey`]（认证仪式 allow-list 输入）。
    pub fn to_passkey(&self) -> Passkey {
        Passkey::from(self.credential.clone())
    }

    /// 应用认证结果（webauthn-rs `AuthenticationResult`），返回是否发生变更。
    ///
    /// 语义与上游 `Passkey::update_credential` 一致：
    /// - counter 只进不退（max）——回退本身由仪式侧判克隆拒绝，到不了这里；
    /// - backup_eligible 只升不降（BE 升级单向）；
    /// - backup_state 跟随最新断言。
    pub fn apply_authentication_result(&mut self, res: &AuthenticationResult) -> bool {
        let mut changed = false;
        if res.counter() > self.sign_count {
            self.sign_count = res.counter();
            self.credential.counter = self.sign_count;
            changed = true;
        }
        if res.backup_state() != self.backup_state {
            self.backup_state = res.backup_state();
            self.credential.backup_state = self.backup_state;
            changed = true;
        }
        if res.backup_eligible() && !self.backup_eligible {
            self.backup_eligible = true;
            self.credential.backup_eligible = true;
            changed = true;
        }
        changed
    }

    /// 凭据是否属于指定用户。
    pub fn belongs_to(&self, tenant_id: i64, user_id: &str) -> bool {
        self.tenant_id == tenant_id && self.user_id == user_id
    }

    /// 协议态只读视图（测试植入/对照用）。
    /// 与唯一调用方 `protocol::webauthn::tests::domain_to_credential` 同门控：
    /// 仅 db-sqlite 测试面编译，否则 webauthn 开 + db-sqlite 关的组合下 dead_code。
    #[cfg(all(test, feature = "db-sqlite"))]
    pub(crate) fn protocol_credential(&self) -> &Credential {
        &self.credential
    }
}
