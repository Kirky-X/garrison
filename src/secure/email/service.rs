//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! EmailVerificationService 实现：发送/验证/异常检测三层抽象。

use super::rate_limiter::{normalize_email, validate_email};
use super::{EmailRateLimiter, EmailSender, EmailVerificationService, GarrisonDao, GarrisonResult};
use crate::error::GarrisonError;
use std::sync::Arc;

/// 错误码：邮箱验证码错误。
///
/// `EmailVerificationService::verify_code` 在验证码不匹配时返回
/// `InvalidParam(ERR_EMAIL_CODE_WRONG)`（带 `::` 后缀）。
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

        // 检查通道是否已回收
        let recycled_key = format!("email:recycled:{}", normalized);
        if self.dao.get(&recycled_key).await?.is_some() {
            return Err(GarrisonError::EmailChannelRecycled);
        }

        // 限速检查（已规范化，调用 inner 避免重复 normalize）
        self.rate_limiter
            .check_and_increment_inner(&normalized)
            .await?;

        // 生成 6 位随机码（密码学安全）
        let code = generate_code()?;

        // 存储验证码（TTL = code_ttl）
        let code_key = format!("email:code:{}", normalized);
        let ttl = self.code_ttl;
        if let Err(e) = self.dao.set(&code_key, &code, ttl).await {
            // 存储失败，回滚限速
            self.rate_limiter.rollback_inner(&normalized).await?;
            return Err(e);
        }

        // 递增未验证计数（TTL 24 小时）
        let unverified_key = format!("email:unverified:{}", normalized);
        let unverified_count = self.dao.incr(&unverified_key, 86400).await?;

        // 检查异常发送
        if unverified_count > self.unverified_threshold as u64 {
            // 回滚限速计数器
            if let Err(e) = self.rate_limiter.rollback_inner(&normalized).await {
                tracing::error!(error = %e, email = %normalized, "rollback rate limiter counter failed during channel recycling");
            }
            // 回滚未验证计数
            if let Err(e) = EmailRateLimiter::decrement_counter(&*self.dao, &unverified_key).await {
                tracing::error!(error = %e, key = %unverified_key, "rollback unverified counter failed");
            }
            // 回收通道（TTL 24 小时）
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
            // 发送失败，回滚限速 + 删除验证码 + 递减未验证计数
            self.rate_limiter.rollback_inner(&normalized).await?;
            self.dao.delete(&code_key).await?;
            if let Err(e) = EmailRateLimiter::decrement_counter(&*self.dao, &unverified_key).await {
                tracing::error!(error = %e, key = %unverified_key, "rollback unverified counter failed after send failure");
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

        if constant_time_eq(&stored, code) {
            // 验证成功：删除验证码 + 清零未验证计数 + 清零尝试次数
            self.dao.delete(&code_key).await?;
            let unverified_key = format!("email:unverified:{}", normalized);
            self.dao.delete(&unverified_key).await?;
            let attempts_key = format!("email:attempts:{}", normalized);
            self.dao.delete(&attempts_key).await?;
            Ok(())
        } else {
            // 验证失败：递增尝试次数
            let attempts_key = format!("email:attempts:{}", normalized);
            let attempts = self.dao.incr(&attempts_key, self.code_ttl).await?;
            if attempts > self.max_verify_attempts as u64 {
                // 超过最大尝试次数，验证码失效
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

/// 生成 6 位随机数字验证码（密码学安全）。
///
/// 范围 `100000..1000000` 保证：
/// 1. 永远不生成 `000000`（弱验证码，易被暴力破解）
/// 2. 所有结果均为 6 位数字（首位非零）
pub(super) fn generate_code() -> GarrisonResult<String> {
    use rand::rngs::OsRng;
    use rand::Rng;
    let code: u32 = OsRng.gen_range(100000..1000000);
    Ok(format!("{:06}", code))
}

/// 常量时间字符串比较（防止时序攻击）。
///
/// 当 `secure-ct-eq` feature 启用时，优先使用框架统一实现。
/// 未启用时 fallback 到模块内私有实现（与 SMS 模块当前实现相同）。
#[cfg(feature = "secure-ct-eq")]
pub(super) fn constant_time_eq(a: &str, b: &str) -> bool {
    crate::secure::ct_eq::constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// 常量时间字符串比较（fallback，未启用 secure-ct-eq 时使用）。
#[cfg(not(feature = "secure-ct-eq"))]
pub(super) fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}
