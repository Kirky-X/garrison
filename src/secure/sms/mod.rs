//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SMS 验证码渐进式限速模块。
//!
//! 提供 SmsSender trait（业务方实现短信发送）+ SmsRateLimiter（双窗口限速）+
//! SmsVerificationService（发送/验证/异常检测）三层抽象。
//!
//! # Key 空间设计
//!
//! | key | TTL | 用途 |
//! |-----|-----|------|
//! | `sms:rate:{phone}:hour:{bucket}` | 3600s | 小时限速计数器 |
//! | `sms:rate:{phone}:day:{date}` | 86400s | 天限速计数器 |
//! | `sms:code:{phone}` | 300s | 验证码 |
//! | `sms:attempts:{phone}` | 300s | 验证尝试次数 |
//! | `sms:unverified:{phone}` | 86400s | 连续未验证计数器 |
//! | `sms:recycled:{phone}` | 86400s | 通道回收标记 |
//!
//! # 安全约束
//!
//! - phone 不能包含 ':'（防止 key 注入）
//! - 验证码使用 `rand::rngs::OsRng` 密码学安全随机数生成器
//! - 所有计数器通过 `BulwarkDao::incr` 原子递增

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::limiteron::BulwarkDaoDistributedLimiter;
use async_trait::async_trait;
use limiteron::limiters::DistributedLimiter;
use std::sync::Arc;
use std::time::Duration;

/// 短信发送 trait（业务方实现）。
#[async_trait]
pub trait SmsSender: Send + Sync {
    /// 发送短信验证码。
    async fn send(&self, phone: &str, code: &str) -> BulwarkResult<()>;
}

/// NoopSmsSender：仅日志不实际发送（用于测试）。
#[cfg(test)]
pub struct NoopSmsSender;

#[cfg(test)]
#[async_trait]
impl SmsSender for NoopSmsSender {
    async fn send(&self, phone: &str, _code: &str) -> BulwarkResult<()> {
        tracing::debug!(phone = phone, "NoopSmsSender 发送验证码（code 已省略）");
        Ok(())
    }
}

/// 校验手机号格式（key 注入防护 + DoS 防护）。
///
/// spec 约束：phone 不能含 ':'（防止 key 结构破坏）。
/// 额外校验：非空、无控制字符、长度 <= 20（防止超大 key 消耗内存）。
fn validate_phone(phone: &str) -> BulwarkResult<()> {
    if phone.is_empty() {
        return Err(BulwarkError::InvalidParam("phone 不能为空".to_string()));
    }
    if phone.contains(':') {
        return Err(BulwarkError::InvalidParam(
            "phone 不能包含 ':' 字符".to_string(),
        ));
    }
    if phone.chars().any(|c| c.is_control()) {
        return Err(BulwarkError::InvalidParam(
            "phone 不能包含控制字符".to_string(),
        ));
    }
    if phone.len() > 20 {
        return Err(BulwarkError::InvalidParam(
            "phone 长度不能超过 20 字符".to_string(),
        ));
    }
    Ok(())
}

/// SMS 限速器。
///
/// 使用 limiteron `DistributedLimiter` trait 实现原子计数（替换 `dao.incr`），
/// 保留 `dao` 用于 `decrement_counter`（limiteron 无 decrement 方法，需通过
/// `dao.get/update/delete` 实现回滚，且 `dao.update` 保留原 TTL 语义）。
pub struct SmsRateLimiter {
    /// DAO（用于 decrement_counter 的回滚操作，保留原 TTL 语义）。
    dao: Arc<dyn BulwarkDao>,
    /// 分布式限流器（limiteron DistributedLimiter 适配器，替换 dao.incr）。
    limiter: Arc<dyn DistributedLimiter>,
    hourly_limit: u32,
    daily_limit: u32,
}

impl SmsRateLimiter {
    /// 创建限速器实例。
    ///
    /// 内部创建 [`BulwarkDaoDistributedLimiter`] 适配器，将 `dao` 桥接到
    /// limiteron `DistributedLimiter` trait，用于原子 `incr_with_ttl`。
    pub fn new(dao: Arc<dyn BulwarkDao>, hourly_limit: u32, daily_limit: u32) -> Self {
        let limiter = Arc::new(BulwarkDaoDistributedLimiter::new(dao.clone()));
        Self {
            dao,
            limiter,
            hourly_limit,
            daily_limit,
        }
    }

    /// 递减计数器（get → parse → update/delete）。
    ///
    /// 计数器值降为 0 时删除 key，否则更新为新值。
    /// 解析失败返回错误（不静默吞掉）。
    async fn decrement_counter(dao: &dyn BulwarkDao, key: &str) -> BulwarkResult<()> {
        if let Some(v) = dao.get(key).await? {
            let count: u64 = v.parse::<u64>().map_err(|e| {
                BulwarkError::Internal(format!("计数器值解析失败 key={}: {}", key, e))
            })?;
            if count > 0 {
                let new_val = count - 1;
                if new_val == 0 {
                    dao.delete(key).await?;
                } else {
                    dao.update(key, &new_val.to_string()).await?;
                }
            }
        }
        Ok(())
    }

    /// 检查并递增限速计数器。
    ///
    /// 超限时回滚已递增的计数器，避免拒绝的请求消耗配额。
    pub async fn check_and_increment(&self, phone: &str) -> BulwarkResult<()> {
        validate_phone(phone)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| BulwarkError::Internal(format!("系统时间错误: {}", e)))?;
        let hour_bucket = now.as_secs() / 3600;
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // 小时窗口：1 小时 TTL（limiteron DistributedLimiter.incr_with_ttl 替换 dao.incr）
        let hour_key = format!("sms:rate:{}:hour:{}", phone, hour_bucket);
        let hour_count = self
            .limiter
            .incr_with_ttl(&hour_key, 1, Duration::from_secs(3600))
            .await
            .map_err(|e| BulwarkError::Internal(format!("limiteron incr_with_ttl 失败: {}", e)))?;
        if hour_count > self.hourly_limit as u64 {
            // 超限，回滚 incr
            if let Err(e) = Self::decrement_counter(&*self.dao, &hour_key).await {
                tracing::warn!(error = %e, key = %hour_key, "回滚小时窗口计数器失败");
            }
            return Err(BulwarkError::SmsRateLimitExceeded {
                window: "hourly".to_string(),
            });
        }

        // 天窗口：24 小时 TTL（limiteron DistributedLimiter.incr_with_ttl 替换 dao.incr）
        let day_key = format!("sms:rate:{}:day:{}", phone, date);
        let day_count = self
            .limiter
            .incr_with_ttl(&day_key, 1, Duration::from_secs(86400))
            .await
            .map_err(|e| BulwarkError::Internal(format!("limiteron incr_with_ttl 失败: {}", e)))?;
        if day_count > self.daily_limit as u64 {
            // 超限，回滚 day 和 hour
            if let Err(e) = Self::decrement_counter(&*self.dao, &day_key).await {
                tracing::warn!(error = %e, key = %day_key, "回滚天窗口计数器失败");
            }
            if let Err(e) = Self::decrement_counter(&*self.dao, &hour_key).await {
                tracing::warn!(error = %e, key = %hour_key, "回滚小时窗口计数器失败");
            }
            return Err(BulwarkError::SmsRateLimitExceeded {
                window: "daily".to_string(),
            });
        }

        Ok(())
    }

    /// 回滚限速计数器（发送失败时调用）。
    pub async fn rollback(&self, phone: &str) -> BulwarkResult<()> {
        validate_phone(phone)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| BulwarkError::Internal(format!("系统时间错误: {}", e)))?;
        let hour_bucket = now.as_secs() / 3600;
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // 递减小时窗口计数
        let hour_key = format!("sms:rate:{}:hour:{}", phone, hour_bucket);
        Self::decrement_counter(&*self.dao, &hour_key).await?;

        // 递减天窗口计数
        let day_key = format!("sms:rate:{}:day:{}", phone, date);
        Self::decrement_counter(&*self.dao, &day_key).await?;

        Ok(())
    }
}

/// SMS 验证码服务。
pub struct SmsVerificationService {
    rate_limiter: SmsRateLimiter,
    sender: Arc<dyn SmsSender>,
    dao: Arc<dyn BulwarkDao>,
    max_verify_attempts: u32,
    unverified_threshold: u32,
}

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

        if stored == code {
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
                Err(BulwarkError::InvalidParam("验证码错误".to_string()))
            }
        }
    }
}

/// 生成 6 位随机数字验证码（密码学安全）。
fn generate_code() -> BulwarkResult<String> {
    use rand::rngs::OsRng;
    use rand::Rng;
    let code: u32 = OsRng.gen_range(0..1000000);
    Ok(format!("{:06}", code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use std::sync::Arc;

    /// 构造测试用 SmsVerificationService（默认配置）。
    fn make_service() -> SmsVerificationService {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let rate_limiter = SmsRateLimiter::new(dao.clone(), 5, 10);
        let sender: Arc<dyn SmsSender> = Arc::new(NoopSmsSender);
        SmsVerificationService::new(rate_limiter, sender, dao, 3, 100)
    }

    /// 测试 1：小时限速 5/h 放行（前 5 次成功）。
    #[tokio::test]
    async fn hourly_limit_allows_first_5() {
        let service = make_service();
        for i in 0..5 {
            let result = service.send_code("13800138000").await;
            assert!(
                result.is_ok(),
                "第 {} 次发送应成功，实际: {:?}",
                i + 1,
                result
            );
        }
    }

    /// 测试 2：小时限速 5/h 拦截第 6 次。
    #[tokio::test]
    async fn hourly_limit_blocks_6th() {
        let service = make_service();
        for _ in 0..5 {
            service.send_code("13800138001").await.unwrap();
        }
        let result = service.send_code("13800138001").await;
        assert!(
            matches!(result, Err(BulwarkError::SmsRateLimitExceeded { ref window }) if window == "hourly"),
            "第 6 次应被小时限速拦截，实际: {:?}",
            result
        );
    }

    /// 测试 3：天限速 10/d 拦截第 11 次。
    ///
    /// 通过手动递增小时窗口计数器绕过小时限速，验证天窗口独立拦截。
    #[tokio::test]
    async fn daily_limit_blocks_11th() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let service = SmsVerificationService::new(
            SmsRateLimiter::new(dao.clone(), 100, 10),
            Arc::new(NoopSmsSender),
            dao.clone(),
            3,
            100,
        );
        for _ in 0..10 {
            service.send_code("13800138002").await.unwrap();
        }
        let result = service.send_code("13800138002").await;
        assert!(
            matches!(result, Err(BulwarkError::SmsRateLimitExceeded { ref window }) if window == "daily"),
            "第 11 次应被天限速拦截，实际: {:?}",
            result
        );
    }

    /// 测试 4：验证码验证 3 次后失效（第 4 次返回 SmsVerifyMaxAttempts）。
    #[tokio::test]
    async fn verify_max_attempts_after_3_failures() {
        let service = make_service();
        service.send_code("13800138003").await.unwrap();
        // 前 3 次错误验证返回 InvalidParam
        for _ in 0..3 {
            let r = service.verify_code("13800138003", "000000").await;
            assert!(
                matches!(r, Err(BulwarkError::InvalidParam(_))),
                "前 3 次错误应返回 InvalidParam"
            );
        }
        // 第 4 次应返回 SmsVerifyMaxAttempts
        let result = service.verify_code("13800138003", "000000").await;
        assert!(
            matches!(result, Err(BulwarkError::SmsVerifyMaxAttempts)),
            "第 4 次应返回 SmsVerifyMaxAttempts，实际: {:?}",
            result
        );
    }

    /// 测试 5：正确验证码验证通过（验证后验证码被删除）。
    #[tokio::test]
    async fn correct_code_verifies_and_deletes() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        // 用自定义 sender 捕获验证码
        struct CapturingSender {
            code: parking_lot::Mutex<Option<String>>,
        }
        #[async_trait]
        impl SmsSender for CapturingSender {
            async fn send(&self, _phone: &str, code: &str) -> BulwarkResult<()> {
                *self.code.lock() = Some(code.to_string());
                Ok(())
            }
        }
        let sender = Arc::new(CapturingSender {
            code: parking_lot::Mutex::new(None),
        });
        let service = SmsVerificationService::new(
            SmsRateLimiter::new(dao.clone(), 5, 10),
            sender.clone(),
            dao.clone(),
            3,
            3,
        );
        service.send_code("13800138004").await.unwrap();
        let code = sender.code.lock().as_ref().cloned().unwrap();
        // 验证通过
        let result = service.verify_code("13800138004", &code).await;
        assert!(result.is_ok(), "正确验证码应验证通过");
        // 验证码已被删除
        let stored = dao.get("sms:code:13800138004").await.unwrap();
        assert!(stored.is_none(), "验证后验证码应被删除");
    }

    /// 测试 6：错误验证码计数增加。
    #[tokio::test]
    async fn wrong_code_increments_attempts() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let service = SmsVerificationService::new(
            SmsRateLimiter::new(dao.clone(), 5, 10),
            Arc::new(NoopSmsSender),
            dao.clone(),
            3,
            3,
        );
        service.send_code("13800138005").await.unwrap();
        // 第一次错误
        service
            .verify_code("13800138005", "wrong")
            .await
            .unwrap_err();
        let attempts = dao.get("sms:attempts:13800138005").await.unwrap();
        assert_eq!(attempts, Some("1".to_string()));
        // 第二次错误
        service
            .verify_code("13800138005", "wrong")
            .await
            .unwrap_err();
        let attempts = dao.get("sms:attempts:13800138005").await.unwrap();
        assert_eq!(attempts, Some("2".to_string()));
    }

    /// 测试 7：验证码不存在返回 SmsCodeNotFound。
    #[tokio::test]
    async fn missing_code_returns_not_found() {
        let service = make_service();
        let result = service.verify_code("13800138006", "123456").await;
        assert!(
            matches!(result, Err(BulwarkError::SmsCodeNotFound)),
            "不存在的验证码应返回 SmsCodeNotFound，实际: {:?}",
            result
        );
    }

    /// 测试 8：限速 key 格式验证（sms:rate:{phone}:hour:{bucket}）。
    #[tokio::test]
    async fn rate_key_format_hour() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let service = SmsVerificationService::new(
            SmsRateLimiter::new(dao.clone(), 5, 10),
            Arc::new(NoopSmsSender),
            dao.clone(),
            3,
            3,
        );
        service.send_code("13800138007").await.unwrap();
        // 验证 key 存在
        let keys = dao.keys("sms:rate:13800138007:hour:*").await.unwrap();
        assert!(
            !keys.is_empty(),
            "应存在 sms:rate:{{phone}}:hour:{{bucket}} 格式的 key"
        );
    }

    /// 测试 9：验证码 key 格式验证（sms:code:{phone}）。
    #[tokio::test]
    async fn code_key_format() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let service = SmsVerificationService::new(
            SmsRateLimiter::new(dao.clone(), 5, 10),
            Arc::new(NoopSmsSender),
            dao.clone(),
            3,
            3,
        );
        service.send_code("13800138008").await.unwrap();
        let stored = dao.get("sms:code:13800138008").await.unwrap();
        assert!(stored.is_some(), "应存在 sms:code:{{phone}} 格式的 key");
    }

    /// 测试 10：并发发送不超限（用 MockDao 的原子 incr 保证）。
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_send_does_not_exceed_limit() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let service = Arc::new(SmsVerificationService::new(
            SmsRateLimiter::new(dao.clone(), 5, 10),
            Arc::new(NoopSmsSender),
            dao.clone(),
            3,
            100,
        ));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let s = service.clone();
            handles.push(tokio::spawn(
                async move { s.send_code("13800138009").await },
            ));
        }
        let mut success = 0;
        let mut rate_limited = 0;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(()) => success += 1,
                Err(BulwarkError::SmsRateLimitExceeded { .. }) => rate_limited += 1,
                Err(e) => panic!("不应返回其他错误: {:?}", e),
            }
        }
        assert_eq!(success, 5, "仅 5 次发送应成功（小时限速 5/h）");
        assert_eq!(rate_limited, 5, "其余 5 次应被限速");
    }

    /// 测试 11：SmsSender mock（NoopSmsSender 不报错）。
    #[tokio::test]
    async fn noop_sms_sender_does_not_error() {
        let sender = NoopSmsSender;
        let result = sender.send("13800138010", "123456").await;
        assert!(result.is_ok(), "NoopSmsSender 不应报错");
    }

    /// 测试 12：异常发送检测（连续未验证 3 次后回收通道）。
    #[tokio::test]
    async fn unverified_threshold_recycles_channel() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        // unverified_threshold = 3：第 4 次未验证发送应触发回收
        let service = SmsVerificationService::new(
            SmsRateLimiter::new(dao.clone(), 100, 100),
            Arc::new(NoopSmsSender),
            dao.clone(),
            3,
            3,
        );
        // 前 3 次发送成功（unverified 计数 1, 2, 3）
        for i in 0..3 {
            let r = service.send_code("13800138011").await;
            assert!(r.is_ok(), "第 {} 次发送应成功", i + 1);
        }
        // 第 4 次发送应触发通道回收
        let result = service.send_code("13800138011").await;
        assert!(
            matches!(result, Err(BulwarkError::SmsChannelRecycled)),
            "第 4 次发送应触发 SmsChannelRecycled，实际: {:?}",
            result
        );
        // 通道已回收，后续发送直接被拒
        let result = service.send_code("13800138011").await;
        assert!(
            matches!(result, Err(BulwarkError::SmsChannelRecycled)),
            "通道回收后应继续返回 SmsChannelRecycled"
        );
    }
}
