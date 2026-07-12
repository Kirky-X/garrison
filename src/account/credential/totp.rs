//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! TOTP 凭证子模块。
//! 提供 `TotpCredential`，实现 `Credential` trait，复用
//! `secure::totp::TotpHandler`（RFC 6238）的校验逻辑。
//!
//! ## secret_data 格式
//!
//! `CredentialModel.secret_data` 存储如下 JSON：
//!
//! ```json
//! {"secret":"JBSWY3DPEHPK3PXP","step":30,"digits":6}
//! ```
//!
//! - `secret`: Base32 编码的 TOTP 密钥（兼容 Google Authenticator）
//! - `step`: 时间步长（秒），默认 30
//! - `digits`: 验证码位数，默认 6
//!
//! `verify(input)` 解析此 JSON，构造 `TotpHandler`，用当前时间戳校验 `input`。

use super::{Credential, CredentialModel, CredentialType};
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::secure::totp::TotpHandler;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// TOTP 凭证 secret_data 的 JSON 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TotpSecretData {
    /// Base32 编码的 TOTP 密钥。
    secret: String,
    /// 时间步长（秒）。
    step: u64,
    /// 验证码位数。
    digits: u32,
}

impl TotpSecretData {
    /// 从 `secret_data` JSON 字符串解析。
    fn from_json(secret_data: &str) -> BulwarkResult<Self> {
        serde_json::from_str(secret_data).map_err(|e| {
            BulwarkError::InvalidParam(format!(
                "TOTP secret_data 解析失败（期望 JSON {{secret, step, digits}}）: {}",
                e
            ))
        })
    }

    /// 构造 `TotpHandler`。
    fn to_handler(&self) -> BulwarkResult<TotpHandler> {
        let secret_bytes = TotpHandler::secret_from_base32(&self.secret)?;
        TotpHandler::new(secret_bytes, self.step, self.digits)
    }
}

/// TOTP 凭证（实现 [`Credential`] trait，复用 [`TotpHandler`] 校验）。
///
/// 持有 `CredentialModel`，`verify()` 解析 `secret_data` 中的 TOTP secret，
/// 构造 `TotpHandler`，用当前时间戳校验用户输入的验证码。
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::credential::totp::TotpCredential;
/// use bulwark::account::credential::CredentialModel;
///
/// let model = CredentialModel {
///     id: "cred-001".into(),
///     user_id: "alice".into(),
///     credential_type: "totp".into(),
///     secret_data: r#"{"secret":"JBSWY3DPEHPK3PXP","step":30,"digits":6}"#.into(),
///     label: Some("iPhone TOTP".into()),
///     created_at: 0,
///     enabled: true,
///     priority: 0,
/// };
/// let cred = TotpCredential::new(model);
/// // let ok = cred.verify("123456").await?;
/// ```
#[cfg_attr(
    feature = "account-credential-zeroize",
    derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)
)]
pub struct TotpCredential {
    /// 凭证存储模型。
    model: CredentialModel,
}

impl TotpCredential {
    /// 创建 TOTP 凭证。
    ///
    /// # 参数
    /// - `model`: 凭证存储模型（`secret_data` 字段应为 `{"secret":"...","step":30,"digits":6}` JSON）
    pub fn new(model: CredentialModel) -> Self {
        Self { model }
    }

    /// 生成当前时间的 TOTP 验证码（便捷方法，委托 [`TotpHandler::generate`]）。
    ///
    /// # 错误
    /// - `secret_data` JSON 解析失败：`BulwarkError::InvalidParam`
    /// - Base32 解码失败 / TotpHandler 构造失败：透传
    pub fn generate_current(&self) -> BulwarkResult<String> {
        let data = TotpSecretData::from_json(&self.model.secret_data)?;
        let handler = data.to_handler()?;
        let now = chrono::Utc::now().timestamp();
        Ok(handler.generate(now))
    }

    /// 校验 TOTP 验证码并防止重放攻击（委托 [`TotpHandler::validate_and_consume`]）。
    ///
    /// 生产环境认证流程应使用此方法而非 [`verify`](Credential::verify)，
    /// 以防止同一 TOTP 验证码在时间窗口内被重复使用。
    ///
    /// # 参数
    /// - `input`: 用户输入的验证码。
    /// - `login_id`: 登录主体标识（用户 ID），用于重放隔离。
    /// - `dao`: DAO 抽象（用于记录已用验证码）。
    ///
    /// # 返回
    /// - `Ok(true)`: 校验通过且首次使用。
    /// - `Ok(false)`: 校验失败或验证码已使用。
    /// - `Err(_)`: `secret_data` 解析失败或 DAO 读写失败。
    pub async fn verify_with_replay_check(
        &self,
        input: &str,
        login_id: &str,
        dao: &dyn BulwarkDao,
    ) -> BulwarkResult<bool> {
        let data = TotpSecretData::from_json(&self.model.secret_data)?;
        let handler = data.to_handler()?;
        let now = chrono::Utc::now().timestamp();
        handler
            .validate_and_consume(login_id, input, now, dao)
            .await
    }
}

#[async_trait]
impl Credential for TotpCredential {
    fn credential_type(&self) -> CredentialType {
        "totp"
    }

    fn to_model(&self) -> CredentialModel {
        self.model.clone()
    }

    async fn verify(&self, input: &str) -> BulwarkResult<bool> {
        let data = TotpSecretData::from_json(&self.model.secret_data)?;
        let handler = data.to_handler()?;
        let now = chrono::Utc::now().timestamp();
        Ok(handler.validate(input, now))
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 辅助函数：构造测试用 TotpCredential + 当前时间戳验证码。
    fn make_totp_cred() -> (TotpCredential, String) {
        // RFC 6238 标准测试密钥 "12345678901234567890" 的 Base32 编码
        let secret_data = r#"{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","step":30,"digits":6}"#;
        let model = CredentialModel {
            id: "cred-totp-001".to_string(),
            user_id: "alice".to_string(),
            credential_type: "totp".to_string(),
            secret_data: secret_data.to_string(),
            label: Some("iPhone TOTP".to_string()),
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let cred = TotpCredential::new(model);
        // 生成当前时间戳的验证码用于测试
        let code = cred.generate_current().expect("generate_current 应成功");
        (cred, code)
    }

    /// R-005: `credential_type()` 返回常量 `"totp"`。
    #[test]
    fn totp_credential_type_returns_totp() {
        let (cred, _) = make_totp_cred();
        assert_eq!(cred.credential_type(), "totp");
    }

    /// R-005: `to_model()` 返回原始 CredentialModel（字段一致）。
    #[test]
    fn totp_credential_to_model_returns_original() {
        let (cred, _) = make_totp_cred();
        let model = cred.to_model();
        assert_eq!(model.id, "cred-totp-001");
        assert_eq!(model.user_id, "alice");
        assert_eq!(model.credential_type, "totp");
        assert!(model.secret_data.contains("GEZDGNBVGY3TQOJQ"));
        assert_eq!(model.label, Some("iPhone TOTP".to_string()));
    }

    /// R-005: `verify()` 正确验证码返回 `Ok(true)`。
    #[tokio::test]
    async fn totp_credential_verify_correct_code() {
        let (cred, code) = make_totp_cred();
        let result = cred.verify(&code).await.expect("verify 应成功");
        assert!(result, "正确 TOTP code 应校验通过");
    }

    /// R-005: `verify()` 错误验证码返回 `Ok(false)`。
    #[tokio::test]
    async fn totp_credential_verify_wrong_code() {
        let (cred, _) = make_totp_cred();
        let result = cred
            .verify("000000")
            .await
            .expect("verify 应成功（返回 false 而非报错）");
        assert!(!result, "错误 TOTP code 应校验失败");
    }

    /// R-005: `secret_data` JSON 解析 — 非法 JSON 返回错误。
    #[tokio::test]
    async fn totp_credential_invalid_secret_data_returns_error() {
        let model = CredentialModel {
            id: "bad".to_string(),
            user_id: "alice".to_string(),
            credential_type: "totp".to_string(),
            secret_data: "not-json".to_string(),
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let cred = TotpCredential::new(model);
        let result = cred.verify("123456").await;
        assert!(
            result.is_err(),
            "非法 secret_data 应返回错误，实际: {:?}",
            result
        );
    }

    /// R-005: `secret_data` JSON 解析 — 合法 JSON 但 Base32 非法返回错误。
    #[tokio::test]
    async fn totp_credential_invalid_base32_returns_error() {
        let model = CredentialModel {
            id: "bad2".to_string(),
            user_id: "alice".to_string(),
            credential_type: "totp".to_string(),
            secret_data: r#"{"secret":"invalid!base32","step":30,"digits":6}"#.to_string(),
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let cred = TotpCredential::new(model);
        let result = cred.verify("123456").await;
        assert!(result.is_err(), "非法 Base32 应返回错误");
    }

    /// R-005: `generate_current()` 生成 6 位数字验证码。
    #[test]
    fn totp_credential_generate_current_returns_6_digits() {
        let (cred, _) = make_totp_cred();
        // generate_current 已在 make_totp_cred 中调用一次，再调一次验证
        let code = cred.generate_current().expect("generate_current 应成功");
        assert_eq!(code.len(), 6, "验证码应为 6 位");
        assert!(
            code.chars().all(|c| c.is_ascii_digit()),
            "验证码应全为数字，实际: {}",
            code
        );
    }

    /// R-005: `TotpCredential` 可作 `Box<dyn Credential>` 使用（对象安全验证）。
    #[tokio::test]
    async fn totp_credential_usable_as_dyn_credential() {
        let (cred, code) = make_totp_cred();
        let dyn_cred: Box<dyn Credential> = Box::new(cred);
        assert_eq!(dyn_cred.credential_type(), "totp");
        let result = dyn_cred.verify(&code).await.expect("verify 应成功");
        assert!(result, "dyn Credential 正确 code 应校验通过");
    }

    /// C-5: `verify_with_replay_check` 首次校验通过，二次同一码拒绝。
    #[tokio::test]
    async fn totp_credential_verify_with_replay_check_rejects_replay() {
        let (cred, code) = make_totp_cred();
        let dao = crate::dao::tests::MockDao::new();

        let first = cred
            .verify_with_replay_check(&code, "user-001", &dao)
            .await
            .expect("首次校验不应报错");
        assert!(first, "首次应通过");

        let second = cred
            .verify_with_replay_check(&code, "user-001", &dao)
            .await
            .expect("二次校验不应报错");
        assert!(!second, "同一验证码二次使用应被拒绝（C-5 重放防护）");
    }
}
