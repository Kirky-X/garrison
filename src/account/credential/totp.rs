// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! TOTP 凭证子模块：`TotpCredential` 实现 `Credential` trait，复用 `secure::totp::TotpHandler`
//! （RFC 6238）的校验逻辑。
//!
//! `CredentialModel.secret_data` 存储如下 JSON：
//!
//! ```json
//! {"secret":"JBSWY3DPEHPK3PXP","step":30,"digits":6}
//! ```
//!
//! `secret` 为 Base32 编码密钥（兼容 Google Authenticator），`step` 为时间步长（秒，默认 30），
//! `digits` 为验证码位数（默认 6）；`verify(input)` 解析此 JSON 构造 `TotpHandler`，用当前时间戳校验。

use super::{Credential, CredentialModel, CredentialType};
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
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

/// TOTP 时间步长合理上界（秒）：RFC 6238 常见值为 30/60，超过 1 小时视为配置错误；同时防下游重放
/// TTL（`step * 3`）整数溢出（超大 step 可能使 TTL 计算回绕为极小值，削弱重放防护）。
const MAX_TOTP_STEP: u64 = 3600;

impl TotpSecretData {
    /// 从 `secret_data` JSON 字符串解析。
    fn from_json(secret_data: &str) -> GarrisonResult<Self> {
        serde_json::from_str(secret_data)
            .map_err(|e| GarrisonError::InvalidParam(format!("account-totp-parse-failed::{}", e)))
    }

    /// 构造 `TotpHandler`。
    fn to_handler(&self) -> GarrisonResult<TotpHandler> {
        // 校验 step>0（防除零）且 step ≤ MAX_TOTP_STEP（防下游 `step * 3` 重放 TTL 计算溢出回绕）
        if self.step == 0 || self.step > MAX_TOTP_STEP {
            return Err(GarrisonError::InvalidParam(format!(
                "credential-totp-step-invalid::step={}",
                self.step
            )));
        }
        let secret_bytes = TotpHandler::secret_from_base32(&self.secret)?;
        TotpHandler::new(secret_bytes, self.step, self.digits)
    }
}

/// TOTP 凭证（实现 [`Credential`] trait）：`verify()` 解析 `secret_data` 中的 TOTP secret，
/// 构造 `TotpHandler`，用当前时间戳校验用户输入。
///
/// # 示例
///
/// ```ignore
/// use garrison::account::credential::totp::TotpCredential;
/// use garrison::account::credential::CredentialModel;
///
/// let model = CredentialModel {
/// id: "cred-001".into(),
/// user_id: "alice".into(),
/// credential_type: "totp".into(),
/// secret_data: r#"{"secret":"JBSWY3DPEHPK3PXP","step":30,"digits":6}"#.into(),
/// label: Some("iPhone TOTP".into()),
/// created_at: 0,
/// enabled: true,
/// priority: 0,
/// };
/// let cred = TotpCredential::new(model);
/// // let ok = cred.verify("123456").await?;
/// ```
#[cfg_attr(
    feature = "credential-zeroize",
    derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)
)]
pub struct TotpCredential {
    /// 凭证存储模型。
    model: CredentialModel,
}

impl TotpCredential {
    /// 进程内 TOTP 重放缓存：trait `verify` 签名无 DAO 参数（对象安全 + 兼容既有实现），无法复用
    /// [`TotpHandler::validate_and_consume`] 的 DAO 原子 `incr`；此处用进程级缓存
    /// （`LazyLock<Mutex<HashMap>>`）原子记录「已使用的 `(user_id, credential_id, code)`」，
    /// TTL = 3 × step（覆盖 skew=±1 的 3 个时间窗口，与 handler 语义一致）。
    ///
    /// 仅防进程内重放，多实例/多进程部署请用
    /// [`verify_with_replay_check`](Self::verify_with_replay_check)（DAO 原子记录）；缓存容量有界
    /// （超限先清理过期条目）。返回 `true` 为首次使用（已原子记录），`false` 为窗口内重放（拒绝）。
    fn check_and_record_replay(
        user_id: &str,
        cred_id: &str,
        code: &str,
        step: u64,
        now: i64,
    ) -> bool {
        use std::collections::HashMap;
        use std::sync::{LazyLock, Mutex};
        static SEEN: LazyLock<Mutex<HashMap<String, i64>>> =
            LazyLock::new(|| Mutex::new(HashMap::new()));

        const MAX_CACHE_ENTRIES: usize = 4096;

        // to_handler 已保证 step <= MAX_TOTP_STEP(3600)，3×step 无溢出
        let ttl_secs = step.saturating_mul(3) as i64;
        let key = format!("totp:verify-used:{user_id}:{cred_id}:{code}");
        let mut map = SEEN.lock().expect("totp verify replay cache poisoned");

        // 容量保护：超限先清理过期条目，防止无界内存增长
        if map.len() >= MAX_CACHE_ENTRIES {
            map.retain(|_, exp| *exp > now);
        }

        // 同锁内「查 + 记」原子完成：并发重复提交仅有一个能记录成功
        match map.get(&key) {
            Some(expiry) if *expiry > now => false,
            _ => {
                map.insert(key, now.saturating_add(ttl_secs));
                true
            },
        }
    }

    /// 创建 TOTP 凭证（`model.secret_data` 应为 `{"secret":"...","step":30,"digits":6}` JSON）。
    pub fn new(model: CredentialModel) -> Self {
        Self { model }
    }

    /// 生成当前时间的 TOTP 验证码（委托 [`TotpHandler::generate`]）；`secret_data` 解析失败返回
    /// `InvalidParam`，Base32 解码 / 构造失败透传。
    pub fn generate_current(&self) -> GarrisonResult<String> {
        let data = TotpSecretData::from_json(&self.model.secret_data)?;
        let handler = data.to_handler()?;
        let now = chrono::Utc::now().timestamp();
        handler.generate(now)
    }

    /// 校验 TOTP 验证码并用 DAO 原子 `incr` 记录已用码（委托 [`TotpHandler::validate_and_consume`]），
    /// 可跨进程防重放：多实例/多进程部署的生产认证流程应使用本方法，而非 [`verify`](Credential::verify)
    /// （仅进程内防重放）。`input` 为用户验证码，`login_id` 用于重放隔离；`Ok(false)` 为校验失败或码已使用。
    pub async fn verify_with_replay_check(
        &self,
        input: &str,
        login_id: &str,
        dao: &dyn GarrisonDao,
    ) -> GarrisonResult<bool> {
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

    async fn verify(&self, input: &str) -> GarrisonResult<bool> {
        // trait 签名无 DAO 参数（对象安全），跨进程防重放请用 verify_with_replay_check()；
        // 此处校验通过后以进程内缓存原子记录已用 (user_id, credential_id, code)，
        // 同一验证码在 3×step 窗口内重复提交会被拒绝
        let data = TotpSecretData::from_json(&self.model.secret_data)?;
        let handler = data.to_handler()?;
        let now = chrono::Utc::now().timestamp();
        if !handler.validate(input, now)? {
            return Ok(false);
        }
        Ok(Self::check_and_record_replay(
            &self.model.user_id,
            &self.model.id,
            input,
            data.step,
            now,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 辅助函数：构造测试用 TotpCredential + 当前时间戳验证码。
    ///
    /// `tag` 用于生成唯一的 user_id/credential_id：`verify()` 内置进程级重放缓存（键含这两者 + code），
    /// 各测试用不同 tag 避免缓存串扰。
    fn make_totp_cred(tag: &str) -> (TotpCredential, String) {
        // RFC 6238 标准测试密钥 "12345678901234567890" 的 Base32 编码
        let secret_data = r#"{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","step":30,"digits":6}"#;
        let model = CredentialModel {
            id: format!("cred-totp-{tag}"),
            user_id: format!("user-{tag}"),
            credential_type: "totp".to_string(),
            secret_data: secret_data.to_string(),
            label: Some("iPhone TOTP".to_string()),
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let cred = TotpCredential::new(model);
        let code = cred.generate_current().expect("generate_current 应成功");
        (cred, code)
    }

    /// `credential_type()` 返回常量 `"totp"`。
    #[test]
    fn totp_credential_type_returns_totp() {
        let (cred, _) = make_totp_cred("t001");
        assert_eq!(cred.credential_type(), "totp");
    }

    /// `to_model()` 返回原始 CredentialModel（字段一致）。
    #[test]
    fn totp_credential_to_model_returns_original() {
        let (cred, _) = make_totp_cred("t002");
        let model = cred.to_model();
        assert_eq!(model.id, "cred-totp-t002");
        assert_eq!(model.user_id, "user-t002");
        assert_eq!(model.credential_type, "totp");
        assert!(model.secret_data.contains("GEZDGNBVGY3TQOJQ"));
        assert_eq!(model.label, Some("iPhone TOTP".to_string()));
    }

    /// `verify()` 正确验证码返回 `Ok(true)`。
    #[tokio::test]
    async fn totp_credential_verify_correct_code() {
        let (cred, code) = make_totp_cred("t003");
        let result = cred.verify(&code).await.expect("verify 应成功");
        assert!(result, "正确 TOTP code 应校验通过");
    }

    /// `verify()` 错误验证码返回 `Ok(false)`。
    #[tokio::test]
    async fn totp_credential_verify_wrong_code() {
        let (cred, _) = make_totp_cred("t004");
        let result = cred
            .verify("000000")
            .await
            .expect("verify 应成功（返回 false 而非报错）");
        assert!(!result, "错误 TOTP code 应校验失败");
    }

    /// `verify()` 重放防护——同一验证码第二次提交被拒绝。
    #[tokio::test]
    async fn totp_credential_verify_rejects_replayed_code() {
        let (cred, code) = make_totp_cred("t005");

        let first = cred.verify(&code).await.expect("首次 verify 不应报错");
        assert!(first, "首次提交应通过");

        let replay = cred.verify(&code).await.expect("重放 verify 不应报错");
        assert!(!replay, "同一验证码窗口内重复提交应被拒绝（重放防护）");
    }

    /// step 超过上界（MAX_TOTP_STEP）时返回错误（防止下游 TTL 溢出）。
    #[tokio::test]
    async fn totp_credential_step_over_upper_bound_returns_error() {
        let model = CredentialModel {
            id: "cred-totp-big-step".to_string(),
            user_id: "user-big-step".to_string(),
            credential_type: "totp".to_string(),
            secret_data: r#"{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","step":18446744073709551615,"digits":6}"#.to_string(),
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let cred = TotpCredential::new(model);
        let result = cred.verify("123456").await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref m)) if m.contains("step")),
            "step 超上界应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// step=0 时返回错误（保留既有防御）。
    #[tokio::test]
    async fn totp_credential_step_zero_returns_error() {
        let model = CredentialModel {
            id: "cred-totp-zero-step".to_string(),
            user_id: "user-zero-step".to_string(),
            credential_type: "totp".to_string(),
            secret_data: r#"{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","step":0,"digits":6}"#
                .to_string(),
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let cred = TotpCredential::new(model);
        let result = cred.verify("123456").await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref m)) if m.contains("step")),
            "step=0 应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// `secret_data` JSON 解析 — 非法 JSON 返回错误。
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

    /// `secret_data` JSON 解析 — 合法 JSON 但 Base32 非法返回错误。
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

    /// `generate_current()` 生成 6 位数字验证码。
    #[test]
    fn totp_credential_generate_current_returns_6_digits() {
        let (cred, _) = make_totp_cred("t006");
        // generate_current 已在 make_totp_cred 中调用一次，再调一次验证
        let code = cred.generate_current().expect("generate_current 应成功");
        assert_eq!(code.len(), 6, "验证码应为 6 位");
        assert!(
            code.chars().all(|c| c.is_ascii_digit()),
            "验证码应全为数字，实际: {}",
            code
        );
    }

    /// `TotpCredential` 可作 `Box<dyn Credential>` 使用（对象安全验证）。
    #[tokio::test]
    async fn totp_credential_usable_as_dyn_credential() {
        let (cred, code) = make_totp_cred("t007");
        let dyn_cred: Box<dyn Credential> = Box::new(cred);
        assert_eq!(dyn_cred.credential_type(), "totp");
        let result = dyn_cred.verify(&code).await.expect("verify 应成功");
        assert!(result, "dyn Credential 正确 code 应校验通过");
    }

    /// `verify_with_replay_check` 首次校验通过，二次同一码拒绝。
    #[tokio::test]
    async fn totp_credential_verify_with_replay_check_rejects_replay() {
        let (cred, code) = make_totp_cred("t008");
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
