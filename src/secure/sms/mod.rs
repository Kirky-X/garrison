//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
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
//! - 所有计数器通过 `GarrisonDao::incr` 原子递增

use crate::dao::GarrisonDao;
use crate::error::GarrisonResult;
use async_trait::async_trait;
use limiteron::limiters::DistributedLimiter;
use std::sync::Arc;

pub mod rate_limiter;
pub mod sender;
pub mod service;

#[cfg(test)]
mod tests;

/// 短信发送 trait（业务方实现）。
#[async_trait]
pub trait SmsSender: Send + Sync {
    /// 发送短信验证码。
    async fn send(&self, phone: &str, code: &str) -> GarrisonResult<()>;
}

/// NoopSmsSender：仅日志不实际发送（用于测试）。
#[cfg(test)]
pub struct NoopSmsSender;

/// SMS 限速器。
///
/// 使用 limiteron `DistributedLimiter` trait 实现原子计数（替换 `dao.incr`），
/// 保留 `dao` 用于 `decrement_counter`（limiteron 无 decrement 方法，需通过
/// `dao.get/update/delete` 实现回滚，且 `dao.update` 保留原 TTL 语义）。
pub struct SmsRateLimiter {
    /// DAO（用于 decrement_counter 的回滚操作，保留原 TTL 语义）。
    dao: Arc<dyn GarrisonDao>,
    /// 分布式限流器（limiteron DistributedLimiter 适配器，替换 dao.incr）。
    limiter: Arc<dyn DistributedLimiter>,
    hourly_limit: u32,
    daily_limit: u32,
}

/// SMS 验证码服务。
///
/// # DAO 注入约束（重要）
///
/// 本服务持有独立的 [`GarrisonDao`]（用于 code/attempts/unverified/recycled key），
/// 同时内嵌的 [`SmsRateLimiter`] 也持有自己的 DAO（用于限速计数器与回滚）。
/// **两者必须指向同一 DAO 实例/后端**（构造时传入同一个 `Arc`），框架不强制该约束：
/// 若注入不同实例，服务与限速器将观察到不一致的状态（如限速器在一个后端递增、
/// 服务在另一个后端读码），导致限速失效或验证码状态错乱。
pub struct SmsVerificationService {
    rate_limiter: SmsRateLimiter,
    sender: Arc<dyn SmsSender>,
    dao: Arc<dyn GarrisonDao>,
    max_verify_attempts: u32,
    unverified_threshold: u32,
}
