//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 邮箱验证码凭证子模块。
//! 提供 `EmailCodeCredential`（实现 `Credential` trait）+
//! `EmailCodeCredentialBuilder`（实现 `CredentialBuilder`，注入验证码服务），
//! 复用 `secure::email::EmailVerificationService` 的校验逻辑。
//!
//! ## secret_data 格式
//!
//! `CredentialModel.secret_data` 存储如下 JSON：
//!
//! ```json
//! {"email":"user@example.com"}
//! ```
//!
//! 邮箱验证码是"动态发送"凭证：真实验证码不落 `secret_data`（TOTP 静态 secret
//! 模式不适用），而是经 `EmailVerificationService::send_code` 写入 KV
//! （`email:code:{addr}`，带 TTL）。`verify(input)` 委托
//! `EmailVerificationService::verify_code(email, input)` 完成校验与一次性消费。
//!
//! ## verify 错误语义
//!
//! - `Ok(true)`：校验通过（验证码正确，KV 状态已清除）
//! - `Ok(false)`：码错误 / 码不存在或已过期（普通校验失败）
//! - `Err(EmailVerifyMaxAttempts)`：尝试超限通道已锁定（安全事件，透传）
//! - `Err(_)`：DAO 故障等校验过程错误（透传）

use super::{Credential, CredentialModel, CredentialType};
use crate::error::{GarrisonError, GarrisonResult};
use crate::secure::email::EmailVerificationService;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 凭证类型标识（与 `AuthStep::Mfa(Some("email-code"))` 配对使用）。
pub const EMAIL_CODE_CREDENTIAL_TYPE: &str = "email-code";

/// 邮箱验证码凭证 secret_data 的 JSON 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EmailSecretData {
    /// 接收验证码的邮箱地址（存储前应已规范化）。
    email: String,
}

impl EmailSecretData {
    /// 从 `secret_data` JSON 字符串解析。
    fn from_json(secret_data: &str) -> GarrisonResult<Self> {
        serde_json::from_str(secret_data)
            .map_err(|e| GarrisonError::InvalidParam(format!("account-email-parse-failed::{}", e)))
    }
}

/// 邮箱验证码凭证（实现 [`Credential`] trait，委托
/// [`EmailVerificationService::verify_code`](crate::secure::email::EmailVerificationService::verify_code) 校验）。
///
/// # 示例
///
/// ```ignore
/// use garrison::account::credential::email::EmailCodeCredential;
/// use garrison::account::credential::CredentialModel;
/// use std::sync::Arc;
///
/// let model = CredentialModel {
///     id: "cred-email-001".into(),
///     user_id: "alice".into(),
///     credential_type: "email-code".into(),
///     secret_data: r#"{"email":"alice@example.com"}"#.into(),
///     label: Some("邮箱验证码".into()),
///     created_at: 0,
///     enabled: true,
///     priority: 0,
/// };
/// let cred = EmailCodeCredential::new(model, service);
/// // let ok = cred.verify("123456").await?;
/// ```
pub struct EmailCodeCredential {
    /// 凭证存储模型。
    model: CredentialModel,
    /// 邮箱验证码服务（发送/验证/限速/异常检测）。
    service: Arc<EmailVerificationService>,
}

impl EmailCodeCredential {
    /// 创建邮箱验证码凭证。
    ///
    /// # 参数
    /// - `model`: 凭证存储模型（`secret_data` 字段应为 `{"email":"..."}` JSON）
    /// - `service`: 邮箱验证码服务（业务方构造，持有 DAO/限速器/发送器）
    pub fn new(model: CredentialModel, service: Arc<EmailVerificationService>) -> Self {
        Self { model, service }
    }

    /// 读取凭证绑定的邮箱地址（解析 `secret_data`）。
    ///
    /// # 错误
    /// - `secret_data` JSON 解析失败：`GarrisonError::InvalidParam`
    pub fn email(&self) -> GarrisonResult<String> {
        Ok(EmailSecretData::from_json(&self.model.secret_data)?.email)
    }
}

#[async_trait]
impl Credential for EmailCodeCredential {
    fn credential_type(&self) -> CredentialType {
        EMAIL_CODE_CREDENTIAL_TYPE
    }

    fn to_model(&self) -> CredentialModel {
        self.model.clone()
    }

    async fn verify(&self, input: &str) -> GarrisonResult<bool> {
        let data = EmailSecretData::from_json(&self.model.secret_data)?;
        match self.service.verify_code(&data.email, input).await {
            Ok(()) => Ok(true),
            // 码不存在（未发送/过期/已消费）与码错误：普通校验失败
            Err(GarrisonError::EmailCodeNotFound) => Ok(false),
            Err(GarrisonError::InvalidParam(msg))
                if msg.starts_with(crate::secure::email::service::ERR_EMAIL_CODE_WRONG) =>
            {
                Ok(false)
            },
            // 尝试超限（通道锁定）与 DAO 故障等：透传
            Err(e) => Err(e),
        }
    }
}

/// 邮箱验证码凭证构造器（实现 `CredentialBuilder`，注入 [`EmailVerificationService`]）。
///
/// 业务方在调用 `AuthExecutor::execute_with_full` 时作为 `builder` 参数传入，
/// 使 `AuthStep::Mfa(Some("email-code"))` 步骤可以按 `"email-code"` 类型构造凭证。
///
/// 仅在 `account-authflow` feature 启用时编译（避免 feature 链穿透，
/// 见 `executor.rs` SocialProviderResolver 同款设计约束）。
pub struct EmailCodeCredentialBuilder {
    service: Arc<EmailVerificationService>,
}

impl EmailCodeCredentialBuilder {
    /// 创建构造器。
    pub fn new(service: Arc<EmailVerificationService>) -> Self {
        Self { service }
    }
}

#[cfg(feature = "account-authflow")]
#[async_trait]
impl crate::account::authflow::executor::CredentialBuilder for EmailCodeCredentialBuilder {
    fn build(&self, model: CredentialModel) -> GarrisonResult<Box<dyn Credential>> {
        Ok(Box::new(EmailCodeCredential::new(
            model,
            self.service.clone(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::dao::GarrisonDao;
    use crate::secure::email::{EmailRateLimiter, EmailSender};

    /// 捕获验证码的测试 EmailSender。
    struct CapturingSender {
        mail: parking_lot::Mutex<Option<(String, String)>>,
    }

    #[async_trait]
    impl EmailSender for CapturingSender {
        async fn send(&self, to: &str, subject: &str, _body: &str) -> GarrisonResult<()> {
            *self.mail.lock() = Some((to.to_string(), subject.to_string()));
            Ok(())
        }
    }

    /// 构造（凭证, 验证码服务）对：service 绑定 MockDao + 捕获发送器。
    fn make_cred() -> (
        EmailCodeCredential,
        Arc<EmailVerificationService>,
        Arc<dyn GarrisonDao>,
    ) {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let service = Arc::new(EmailVerificationService::new(
            EmailRateLimiter::new(dao.clone(), 100, 100),
            Arc::new(CapturingSender {
                mail: parking_lot::Mutex::new(None),
            }),
            dao.clone(),
            3,
            100,
            600,
        ));
        let model = CredentialModel {
            id: "cred-email-001".to_string(),
            user_id: "alice".to_string(),
            credential_type: EMAIL_CODE_CREDENTIAL_TYPE.to_string(),
            secret_data: r#"{"email":"alice@example.com"}"#.to_string(),
            label: Some("邮箱验证码".to_string()),
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        (
            EmailCodeCredential::new(model, service.clone()),
            service,
            dao,
        )
    }

    /// `credential_type()` 返回常量 `"email-code"`。
    #[test]
    fn email_credential_type_returns_email_code() {
        let (cred, _, _) = make_cred();
        assert_eq!(cred.credential_type(), "email-code");
    }

    /// `to_model()` 返回原始 CredentialModel（字段一致）。
    #[test]
    fn email_credential_to_model_returns_original() {
        let (cred, _, _) = make_cred();
        let model = cred.to_model();
        assert_eq!(model.id, "cred-email-001");
        assert_eq!(model.user_id, "alice");
        assert_eq!(model.credential_type, "email-code");
        assert!(model.secret_data.contains("alice@example.com"));
    }

    /// `email()` 解析 secret_data 中的邮箱地址。
    #[test]
    fn email_credential_email_accessor_parses_address() {
        let (cred, _, _) = make_cred();
        assert_eq!(cred.email().unwrap(), "alice@example.com");
    }

    /// `verify()` 正确验证码返回 `Ok(true)`（委托 service 校验并一次性消费）。
    #[tokio::test]
    async fn email_credential_verify_correct_code() {
        let (cred, _, dao) = make_cred();
        // 直接写入已知验证码（KV 即契约，避免依赖邮件正文解析）
        dao.set("email:code:alice@example.com", "123456", 600)
            .await
            .unwrap();
        let result = cred.verify("123456").await.unwrap();
        assert!(result, "正确验证码应返回 Ok(true)");
        let stored = dao.get("email:code:alice@example.com").await.unwrap();
        assert!(stored.is_none(), "验证通过后验证码应被消费删除");
    }

    /// `verify()` 码不存在（未发送）返回 `Ok(false)`。
    #[tokio::test]
    async fn email_credential_verify_missing_code_returns_false() {
        let (cred, _, _) = make_cred();
        let result = cred.verify("123456").await.unwrap();
        assert!(!result, "未发送验证码应返回 Ok(false)");
    }

    /// `verify()` 尝试超限返回 `Err(EmailVerifyMaxAttempts)`（安全事件透传）。
    #[tokio::test]
    async fn email_credential_verify_max_attempts_propagates() {
        let (cred, service, _) = make_cred();
        service.send_code("alice@example.com").await.unwrap();
        for _ in 0..3 {
            assert!(
                !cred.verify("000000").await.unwrap(),
                "前 3 次应为 Ok(false)"
            );
        }
        let result = cred.verify("000000").await;
        assert!(
            matches!(result, Err(GarrisonError::EmailVerifyMaxAttempts)),
            "第 4 次应透传 EmailVerifyMaxAttempts，实际: {:?}",
            result
        );
    }

    /// `verify()` secret_data 非法 JSON 返回错误。
    #[tokio::test]
    async fn email_credential_invalid_secret_data_returns_error() {
        let (_, service, _) = make_cred();
        let model = CredentialModel {
            id: "bad".to_string(),
            user_id: "alice".to_string(),
            credential_type: EMAIL_CODE_CREDENTIAL_TYPE.to_string(),
            secret_data: "not-json".to_string(),
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let cred = EmailCodeCredential::new(model, service);
        let result = cred.verify("123456").await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref msg)) if msg.starts_with("account-email-parse-failed")),
            "非法 secret_data 应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// `EmailCodeCredential` 可作 `Box<dyn Credential>` 使用（对象安全验证）。
    #[tokio::test]
    async fn email_credential_usable_as_dyn_credential() {
        let (cred, _, dao) = make_cred();
        dao.set("email:code:alice@example.com", "654321", 600)
            .await
            .unwrap();
        let dyn_cred: Box<dyn Credential> = Box::new(cred);
        assert_eq!(dyn_cred.credential_type(), "email-code");
        assert!(
            dyn_cred.verify("654321").await.unwrap(),
            "dyn 凭证正确码应通过"
        );
    }

    /// `EmailCodeCredentialBuilder` 按 model 构造 `Box<dyn Credential>`（account-authflow）。
    #[cfg(feature = "account-authflow")]
    #[tokio::test]
    async fn email_credential_builder_builds_dyn_credential() {
        use crate::account::authflow::executor::CredentialBuilder;

        let (_, service, _) = make_cred();
        let builder = EmailCodeCredentialBuilder::new(service);
        let model = CredentialModel {
            id: "cred-email-002".to_string(),
            user_id: "bob".to_string(),
            credential_type: EMAIL_CODE_CREDENTIAL_TYPE.to_string(),
            secret_data: r#"{"email":"bob@example.com"}"#.to_string(),
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let dyn_cred = builder.build(model).unwrap();
        assert_eq!(dyn_cred.credential_type(), "email-code");
    }
}
