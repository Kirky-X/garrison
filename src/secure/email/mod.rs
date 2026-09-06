//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 邮箱验证码模块。
//!
//! 提供 EmailSender trait（业务方实现邮件发送）+ EmailRateLimiter（双窗口限速）+
//! EmailVerificationService（发送/验证/异常检测）三层抽象。
//!
//! # Key 空间设计
//!
//! | key | TTL | 用途 |
//! |-----|-----|------|
//! | `email:rate:{addr}:hour:{bucket}` | 3600s | 小时限速计数器 |
//! | `email:rate:{addr}:day:{date}` | 86400s | 天限速计数器 |
//! | `email:code:{addr}` | 600s | 验证码（默认 10 分钟） |
//! | `email:attempts:{addr}` | 600s | 验证尝试次数 |
//! | `email:unverified:{addr}` | 86400s | 连续未验证计数器 |
//! | `email:recycled:{addr}` | 86400s | 通道回收标记 |
//!
//! # 安全约束
//!
//! - 所有 key 中的邮箱地址经过 `normalize_email()` 规范化（trim + 小写化）
//! - email 不能包含 ':'（防止 key 注入）
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

#[cfg(feature = "email-verification-smtp")]
pub mod smtp;

#[cfg(test)]
mod tests;

/// 邮件发送 trait（业务方实现）。
#[async_trait]
pub trait EmailSender: Send + Sync {
    /// 发送邮件验证码。
    ///
    /// # 参数
    /// - `to`: 收件人邮箱地址（已规范化）。
    /// - `subject`: 邮件主题。
    /// - `body`: 邮件正文（纯文本或 HTML）。
    async fn send(&self, to: &str, subject: &str, body: &str) -> GarrisonResult<()>;
}

/// 邮箱验证码限速器。
///
/// 使用 limiteron `DistributedLimiter` trait 实现原子计数，保留 `dao` 用于
/// `decrement_counter`（limiteron 无 decrement 方法）。
pub struct EmailRateLimiter {
    /// DAO（用于 decrement_counter 的回滚操作，保留原 TTL 语义）。
    dao: Arc<dyn GarrisonDao>,
    /// 分布式限流器（limiteron DistributedLimiter 适配器）。
    limiter: Arc<dyn DistributedLimiter>,
    hourly_limit: u32,
    daily_limit: u32,
}

/// 邮箱验证码服务。
pub struct EmailVerificationService {
    rate_limiter: EmailRateLimiter,
    sender: Arc<dyn EmailSender>,
    dao: Arc<dyn GarrisonDao>,
    max_verify_attempts: u32,
    unverified_threshold: u32,
    code_ttl: u64,
}
