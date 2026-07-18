//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SmsVerificationService 实现：发送/验证/异常检测三层抽象。

use super::rate_limiter::validate_phone;
use super::{BulwarkDao, BulwarkResult, SmsRateLimiter, SmsSender, SmsVerificationService};
use crate::error::BulwarkError;
use std::sync::Arc;

impl SmsVerificationService {
    /// 创建验证码服务实例。
    pub fn new(
        rate_limiter: SmsRateLimiter,
        sender: Arc<dyn SmsSender>,
        dao: Arc<dyn BulwarkDao>,
        max_verify_attempts: u32,
        unverified_threshold: u32,
    ) -> Self {
        Self {
            rate_limiter,
            sender,
            dao,
            max_verify_attempts,
            unverified_threshold,
        }
    }

    /// 发送验证码。
    pub async fn send_code(&self, phone: &str) -> BulwarkResult<()> {
        validate_phone(phone)?;

        // 检查通道是否已回收
        let recycled_key = format!("sms:recycled:{}", phone);
        if self.dao.get(&recycled_key).await?.is_some() {
            return Err(BulwarkError::SmsChannelRecycled);
        }

        // 限速检查
        self.rate_limiter.check_and_increment(phone).await?;

        // 生成 6 位随机码（密码学安全）
        let code = generate_code()?;

        // 存储验证码（TTL 5 分钟 = 300 秒）
        let code_key = format!("sms:code:{}", phone);
        if let Err(e) = self.dao.set(&code_key, &code, 300).await {
            // 存储失败，回滚限速
            self.rate_limiter.rollback(phone).await?;
            return Err(e);
        }

        // 递增未验证计数（TTL 24 小时）
        let unverified_key = format!("sms:unverified:{}", phone);
        let unverified_count = self.dao.incr(&unverified_key, 86400).await?;

        // 检查异常发送
        if unverified_count > self.unverified_threshold as u64 {
            // 回滚限速计数器
            if let Err(e) = self.rate_limiter.rollback(phone).await {
                tracing::warn!(error = %e, phone = phone, "通道回收时回滚限速计数器失败");
            }
            // 回滚未验证计数
            if let Err(e) = SmsRateLimiter::decrement_counter(&*self.dao, &unverified_key).await {
                tracing::warn!(error = %e, key = %unverified_key, "回滚未验证计数器失败");
            }
            // 回收通道（TTL 24 小时）
            self.dao.set(&recycled_key, "1", 86400).await?;
            return Err(BulwarkError::SmsChannelRecycled);
        }

        // 发送验证码
        if let Err(e) = self.sender.send(phone, &code).await {
            // 发送失败，回滚限速 + 删除验证码 + 递减未验证计数
            self.rate_limiter.rollback(phone).await?;
            self.dao.delete(&code_key).await?;
            // 递减未验证计数
            if let Err(e) = SmsRateLimiter::decrement_counter(&*self.dao, &unverified_key).await {
                tracing::warn!(error = %e, key = %unverified_key, "发送失败回滚未验证计数器失败");
            }
            return Err(e);
        }

        Ok(())
    }

    /// 验证验证码。
    pub async fn verify_code(&self, phone: &str, code: &str) -> BulwarkResult<()> {
        validate_phone(phone)?;

        let code_key = format!("sms:code:{}", phone);
        let stored = self.dao.get(&code_key).await?;
        let stored = stored.ok_or(BulwarkError::SmsCodeNotFound)?;

        if constant_time_eq(&stored, code) {
            // 验证成功：删除验证码 + 清零未验证计数 + 清零尝试次数
            self.dao.delete(&code_key).await?;
            let unverified_key = format!("sms:unverified:{}", phone);
            self.dao.delete(&unverified_key).await?;
            let attempts_key = format!("sms:attempts:{}", phone);
            self.dao.delete(&attempts_key).await?;
            Ok(())
        } else {
            // 验证失败：递增尝试次数
            let attempts_key = format!("sms:attempts:{}", phone);
            let attempts = self.dao.incr(&attempts_key, 300).await?;
            if attempts > self.max_verify_attempts as u64 {
                // 超过最大尝试次数，验证码失效
                self.dao.delete(&code_key).await?;
                self.dao.delete(&attempts_key).await?;
                Err(BulwarkError::SmsVerifyMaxAttempts)
            } else {
                Err(BulwarkError::InvalidParam(
                    "secure-sms-code-wrong::".to_string(),
                ))
            }
        }
    }
}

/// 生成 6 位随机数字验证码（密码学安全）。
///
/// 范围 `100000..1000000` 保证：
/// 1. 永远不生成 `000000`（弱验证码，易被暴力破解）
/// 2. 所有结果均为 6 位数字（首位非零）
pub(super) fn generate_code() -> BulwarkResult<String> {
    use rand::rngs::OsRng;
    use rand::Rng;
    let code: u32 = OsRng.gen_range(100000..1000000);
    Ok(format!("{:06}", code))
}

/// 常量时间字符串比较（防止时序攻击）。
///
/// 长度相同时，逐字节 XOR 累积，无论在哪一位首次不同，循环次数相同。
/// 长度不同时立即返回 false（仅泄露长度信息，不泄露内容；验证码固定 6 位，长度泄露无风险）。
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
