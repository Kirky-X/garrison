// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! SmsVerificationService 实现：发送/验证/异常检测三层抽象。

use super::rate_limiter::validate_phone;
use super::{GarrisonDao, GarrisonResult, SmsRateLimiter, SmsSender, SmsVerificationService};
use crate::error::GarrisonError;
use std::sync::Arc;

/// 错误码：SMS 验证码错误。
///
/// `SmsVerificationService::verify_code` 在验证码不匹配时返回
/// `InvalidParam(ERR_SMS_CODE_WRONG)`（带 `::` 后缀）。
/// 消费方用此常量做 `starts_with` 匹配，避免硬编码字符串契约。
pub const ERR_SMS_CODE_WRONG: &str = "secure-sms-code-wrong";

impl SmsVerificationService {
    /// 创建验证码服务实例。
    pub fn new(
        rate_limiter: SmsRateLimiter,
        sender: Arc<dyn SmsSender>,
        dao: Arc<dyn GarrisonDao>,
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
    pub async fn send_code(&self, phone: &str) -> GarrisonResult<()> {
        validate_phone(phone)?;

        // 检查通道是否已回收
        let recycled_key = format!("sms:recycled:{}", phone);
        if self.dao.get(&recycled_key).await?.is_some() {
            return Err(GarrisonError::SmsChannelRecycled);
        }

        // 限速检查（携带窗口桶信息，供失败路径精确回滚，防跨窗口边界递减错桶）
        let windows = self.rate_limiter.check_and_increment_with(phone).await?;

        // 生成 6 位随机码（密码学安全）
        let code = generate_code()?;

        // 存储验证码（TTL 5 分钟 = 300 秒）
        let code_key = format!("sms:code:{}", phone);
        if let Err(e) = self.dao.set(&code_key, &code, 300).await {
            // 存储失败，回滚限速（best-effort：清理失败仅告警，保留原始存储错误）
            if let Err(re) = self.rate_limiter.rollback_with(phone, &windows).await {
                tracing::error!(
                    error = %re,
                    phone = %mask_phone(phone),
                    "rollback rate limiter counter failed after code store failure"
                );
            }
            return Err(e);
        }

        // 递增未验证计数（TTL 24 小时）
        let unverified_key = format!("sms:unverified:{}", phone);
        // 递增失败时必须回滚已写入的验证码与已递增的限速计数（best-effort），
        // 否则 Redis 中残留无对应发送记录的验证码 + 膨胀的限速计数
        let unverified_count = match self.dao.incr(&unverified_key, 86400).await {
            Ok(count) => count,
            Err(e) => {
                if let Err(re) = self.rate_limiter.rollback_with(phone, &windows).await {
                    tracing::error!(
                        error = %re,
                        phone = %mask_phone(phone),
                        "rollback rate limiter counter failed after unverified incr failure"
                    );
                }
                if let Err(re) = self.dao.delete(&code_key).await {
                    tracing::error!(
                        error = %re,
                        key = %code_key,
                        "delete stored code failed after unverified incr failure"
                    );
                }
                return Err(e);
            },
        };

        // 检查异常发送
        if unverified_count > self.unverified_threshold as u64 {
            // 回滚限速计数器
            if let Err(e) = self.rate_limiter.rollback_with(phone, &windows).await {
                // decr 失败不再 warn 吞错，改为 error 触发运维告警
                tracing::error!(
                    error = %e,
                    phone = %mask_phone(phone),
                    "rollback rate limiter counter failed during channel recycling"
                );
            }
            // 回滚未验证计数
            if let Err(e) = SmsRateLimiter::decrement_counter(&*self.dao, &unverified_key).await {
                // decr 失败不再 warn 吞错，改为 error 触发运维告警
                tracing::error!(
                    error = %e,
                    key = %mask_phone_in_key(&unverified_key),
                    "rollback unverified counter failed"
                );
            }
            // 回收通道（TTL 24 小时）
            self.dao.set(&recycled_key, "1", 86400).await?;
            return Err(GarrisonError::SmsChannelRecycled);
        }

        // 发送验证码
        if let Err(e) = self.sender.send(phone, &code).await {
            // 发送失败：聚合执行全部清理（限速回滚 + 删码 + 递减未验证计数），
            // 任一清理失败仅 error 告警不中断剩余清理，最终保留原始发送错误。
            // 删除验证码必须尽力执行——否则验证码在 TTL 内仍有效，
            // 攻击者可在发送失败后用同一验证码完成验证。
            if let Err(re) = self.rate_limiter.rollback_with(phone, &windows).await {
                tracing::error!(
                    error = %re,
                    phone = %mask_phone(phone),
                    "rollback rate limiter counter failed after send failure"
                );
            }
            if let Err(re) = self.dao.delete(&code_key).await {
                tracing::error!(
                    error = %re,
                    key = %code_key,
                    "delete code failed after send failure"
                );
            }
            // 递减未验证计数
            if let Err(re) = SmsRateLimiter::decrement_counter(&*self.dao, &unverified_key).await {
                // decr 失败不再 warn 吞错，改为 error 触发运维告警
                tracing::error!(
                    error = %re,
                    key = %mask_phone_in_key(&unverified_key),
                    "rollback unverified counter failed after send failure"
                );
            }
            return Err(e);
        }

        Ok(())
    }

    /// 验证验证码。
    pub async fn verify_code(&self, phone: &str, code: &str) -> GarrisonResult<()> {
        validate_phone(phone)?;

        let code_key = format!("sms:code:{}", phone);
        let stored = self.dao.get(&code_key).await?;
        let stored = stored.ok_or(GarrisonError::SmsCodeNotFound)?;

        if constant_time_eq(&stored, code) {
            // 验证成功：删除验证码 + 清零未验证计数 + 清零尝试次数。
            // 聚合执行三个 delete（首个失败不中断剩余清理），返回首个错误：
            // code 已删后其余 delete 失败不应让调用方误以为验证码仍有效。
            let mut first_err: Option<GarrisonError> = None;
            if let Err(e) = self.dao.delete(&code_key).await {
                first_err.get_or_insert(e);
            }
            let unverified_key = format!("sms:unverified:{}", phone);
            if let Err(e) = self.dao.delete(&unverified_key).await {
                first_err.get_or_insert(e);
            }
            let attempts_key = format!("sms:attempts:{}", phone);
            if let Err(e) = self.dao.delete(&attempts_key).await {
                first_err.get_or_insert(e);
            }
            match first_err {
                Some(e) => Err(e),
                None => Ok(()),
            }
        } else {
            // 验证失败：递增尝试次数
            let attempts_key = format!("sms:attempts:{}", phone);
            let attempts = self.dao.incr(&attempts_key, 300).await?;
            if attempts > self.max_verify_attempts as u64 {
                // 超过最大尝试次数，验证码失效
                self.dao.delete(&code_key).await?;
                self.dao.delete(&attempts_key).await?;
                Err(GarrisonError::SmsVerifyMaxAttempts)
            } else {
                Err(GarrisonError::InvalidParam(format!(
                    "{ERR_SMS_CODE_WRONG}::"
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
    use rand::RngExt;
    let code: u32 = rand::rng().random_range(100000..1000000);
    Ok(format!("{:06}", code))
}

/// 手机号脱敏（日志 PII 防护）：保留前 3 后 4（长度 >= 7 时），其余以 `*` 填充。
///
/// 短于 7 位时整体以 `*` 屏蔽（长度与输入一致）。用于 `tracing` 日志字段，
/// 防止手机号明文进入日志（PII 泄露）。
pub(super) fn mask_phone(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    if chars.len() < 7 {
        return "*".repeat(chars.len());
    }
    let prefix: String = chars[..3].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    let stars = "*".repeat(chars.len() - 7);
    format!("{prefix}{stars}{suffix}")
}

/// 对含手机号的 key 字符串脱敏（`sms:unverified:{phone}` → `sms:unverified:138****8000`）。
pub(super) fn mask_phone_in_key(key: &str) -> String {
    // 取最后一个 `:` 之前为 key 前缀（如 "sms:unverified"），末段视为 phone 主体
    match key.rsplit_once(':') {
        Some((prefix, phone)) => format!("{}:{}", prefix, mask_phone(phone)),
        None => mask_phone(key),
    }
}

/// 常量时间字符串比较（防止时序攻击）。
///
/// 启用 `secure-ct-eq` feature 时优先使用框架统一实现
/// [`crate::secure::ct_eq`]（基于 `subtle::ConstantTimeEq`，长度比较不 early return）。
#[cfg(feature = "secure-ct-eq")]
pub(super) fn constant_time_eq(a: &str, b: &str) -> bool {
    crate::secure::ct_eq::constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// 常量时间字符串比较（fallback，未启用 `secure-ct-eq` 时使用）。
///
/// 与 [`crate::secure::ct_eq`] 同构：长度比较不 early return，短方按 0 padding
/// 循环到 `max_len`，消除原实现的长度早退（长度信息泄露）；
/// 验证码固定 6 位，实际泄露面极小，此处统一采用无早退语义。
#[cfg(not(feature = "secure-ct-eq"))]
pub(super) fn constant_time_eq(a: &str, b: &str) -> bool {
    let len_eq = (a.len() as u64) == (b.len() as u64);
    let max_len = a.len().max(b.len());
    let mut byte_diff: u8 = 0;
    let (a_bytes, b_bytes) = (a.as_bytes(), b.as_bytes());
    for i in 0..max_len {
        let x = a_bytes.get(i).copied().unwrap_or(0);
        let y = b_bytes.get(i).copied().unwrap_or(0);
        byte_diff |= x ^ y;
    }
    len_eq && byte_diff == 0
}
