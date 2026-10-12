// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! EmailVerificationService 实现：发送/验证/异常检测三层抽象。

use super::rate_limiter::{normalize_email, validate_email};
use super::{EmailRateLimiter, EmailSender, EmailVerificationService, GarrisonDao, GarrisonResult};
use crate::error::GarrisonError;
use crate::secure::ct_eq::constant_time_eq;
use std::sync::Arc;

/// 错误码：`verify_code` 在验证码不匹配时返回 `InvalidParam(ERR_EMAIL_CODE_WRONG)`（带 `::` 后缀）。
pub const ERR_EMAIL_CODE_WRONG: &str = "secure-email-code-wrong";

impl EmailVerificationService {
    /// 创建验证码服务实例。
    pub fn new(
        rate_limiter: EmailRateLimiter,
        sender: Arc<dyn EmailSender>,
        dao: Arc<dyn GarrisonDao>,
        max_verify_attempts: u32,
        unverified_threshold: u32,
        code_ttl: u64,
    ) -> Self {
        Self {
            rate_limiter,
            sender,
            dao,
            max_verify_attempts,
            unverified_threshold,
            code_ttl,
        }
    }

    /// 发送验证码。
    pub async fn send_code(&self, email: &str) -> GarrisonResult<()> {
        let normalized = normalize_email(email);
        validate_email(&normalized)?;

        let recycled_key = format!("email:recycled:{}", normalized);
        if self.dao.get(&recycled_key).await?.is_some() {
            return Err(GarrisonError::EmailChannelRecycled);
        }

        // 限速检查（已规范化，调 inner 避免重复 normalize；窗口桶快照供失败路径回滚）
        let windows = self
            .rate_limiter
            .check_and_increment_inner(&normalized)
            .await?;

        let code = generate_code()?;

        let code_key = format!("email:code:{}", normalized);
        let ttl = self.code_ttl;
        if let Err(e) = self.dao.set(&code_key, &code, ttl).await {
            // 存储失败：best-effort 回滚限速（清理失败仅告警），保留原始存储错误不掩盖真实原因
            if let Err(re) = self
                .rate_limiter
                .rollback_inner_with(&normalized, &windows)
                .await
            {
                tracing::error!(
                    error = %re,
                    email = mask_email_for_log(&normalized),
                    "rollback rate limiter counter failed after code store failure"
                );
            }
            return Err(e);
        }

        let unverified_key = format!("email:unverified:{}", normalized);
        let unverified_count = self.dao.incr(&unverified_key, 86400).await?;

        if unverified_count > self.unverified_threshold as u64 {
            if let Err(e) = self
                .rate_limiter
                .rollback_inner_with(&normalized, &windows)
                .await
            {
                tracing::error!(error = %e, email = mask_email_for_log(&normalized), "rollback rate limiter counter failed during channel recycling");
            }
            if let Err(e) = EmailRateLimiter::decrement_counter(&*self.dao, &unverified_key).await {
                tracing::error!(error = %e, key = %unverified_key, "rollback unverified counter failed");
            }
            self.dao.set(&recycled_key, "1", 86400).await?;
            return Err(GarrisonError::EmailChannelRecycled);
        }

        // 发送验证码（主题/正文走 FTL 本地化，禁止硬编码文案）
        let subject = crate::i18n::translate_detail("secure-email-code-mail-subject", &[]);
        let minutes = (self.code_ttl / 60).to_string();
        let body = crate::i18n::translate_detail(
            "secure-email-code-mail-body",
            &[("code", code.as_str()), ("minutes", minutes.as_str())],
        );
        if let Err(e) = self.sender.send(&normalized, &subject, &body).await {
            // 发送失败：聚合清理（限速回滚 + 删码 + 递减未验证计数），单项失败仅告警不中断，保留原始发送错误
            if let Err(re) = self
                .rate_limiter
                .rollback_inner_with(&normalized, &windows)
                .await
            {
                tracing::error!(error = %re, email = mask_email_for_log(&normalized), "rollback rate limiter counter failed after send failure");
            }
            if let Err(re) = self.dao.delete(&code_key).await {
                tracing::error!(error = %re, key = %code_key, "delete code failed after send failure");
            }
            if let Err(re) = EmailRateLimiter::decrement_counter(&*self.dao, &unverified_key).await
            {
                tracing::error!(error = %re, key = %unverified_key, "rollback unverified counter failed after send failure");
            }
            return Err(e);
        }

        Ok(())
    }

    /// 验证验证码。
    pub async fn verify_code(&self, email: &str, code: &str) -> GarrisonResult<()> {
        let normalized = normalize_email(email);
        validate_email(&normalized)?;

        let code_key = format!("email:code:{}", normalized);
        let stored = self.dao.get(&code_key).await?;
        let stored = stored.ok_or(GarrisonError::EmailCodeNotFound)?;

        // 比对统一走 ADR-0003 常量时间原语；验证码定长 6 位，长度不符必然不等，长度检查提前短路——
        // 用户可控输入长度不得进入比较循环（防 CPU DoS），且长度是公开参数、提前拒绝不泄露秘密。
        let matched = code.len() == 6 && constant_time_eq(stored.as_bytes(), code.as_bytes());
        if matched {
            self.dao.delete(&code_key).await?;
            let unverified_key = format!("email:unverified:{}", normalized);
            self.dao.delete(&unverified_key).await?;
            let attempts_key = format!("email:attempts:{}", normalized);
            self.dao.delete(&attempts_key).await?;
            Ok(())
        } else {
            let attempts_key = format!("email:attempts:{}", normalized);
            let attempts = self.dao.incr(&attempts_key, self.code_ttl).await?;
            if attempts > self.max_verify_attempts as u64 {
                self.dao.delete(&code_key).await?;
                self.dao.delete(&attempts_key).await?;
                Err(GarrisonError::EmailVerifyMaxAttempts)
            } else {
                Err(GarrisonError::InvalidParam(format!(
                    "{ERR_EMAIL_CODE_WRONG}::"
                )))
            }
        }
    }
}

/// 生成 6 位随机数字验证码（密码学安全）：范围 `100000..1000000` 保证首位非零且永不生成 `000000`（弱码易爆破）。
pub(super) fn generate_code() -> GarrisonResult<String> {
    use rand::RngExt;
    let code: u32 = rand::rng().random_range(100000..1000000);
    Ok(format!("{:06}", code))
}

/// 邮箱脱敏：保留首字符 + `***` + `@` + 域名；无 `@` 时整体以 `*` 屏蔽。
///
/// 模块内本地实现（对齐 SMS 侧 `mask_phone`）：`secure-masking` 是独立 feature，`email-verification` 不传递它，跨模块引用会在单 feature 组合下编译失败。
fn mask_email_for_log(email: &str) -> String {
    match email.find('@') {
        Some(at_pos) if at_pos > 0 => {
            let first = email[..at_pos].chars().next().unwrap_or('*');
            format!("{first}***{}", &email[at_pos..])
        },
        _ => "*".repeat(email.chars().count()),
    }
}
