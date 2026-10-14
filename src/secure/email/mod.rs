// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 邮箱验证码模块。
//!
//! 三层抽象：`EmailSender` trait（业务方实现邮件发送）+ `EmailRateLimiter`（双窗口限速）+ `EmailVerificationService`（发送/验证/异常检测）。
//!
//! # Key 空间设计
//!
//! | key | TTL | 用途 |
//! |-----|-----|------|
//! | `quota:hour:email:{addr}` | 3600s | 小时限速账本（limiteron QuotaStorage） |
//! | `quota:day:email:{addr}` | 86400s | 天限速账本（limiteron QuotaStorage） |
//! | `email:code:{addr}` | 600s | 验证码（默认 10 分钟） |
//! | `email:attempts:{addr}` | 600s | 验证尝试次数 |
//! | `email:unverified:{addr}` | 86400s | 连续未验证计数器 |
//! | `email:recycled:{addr}` | 86400s | 通道回收标记 |
//!
//! # 安全约束
//!
//! 所有 key 中的邮箱地址经 `normalize_email()` 规范化（trim + 小写化）且不含 ':'
//! （防 key 注入）；验证码用 `rand::rng()`（ThreadRng，ChaCha12 CSPRNG）；限速账本与
//! 未验证计数器均经 `GarrisonDao::incr`/`decr` 原子增减（QuotaStorage 适配器）。

use crate::dao::GarrisonDao;
use crate::error::GarrisonResult;
use crate::limiteron::storage::GarrisonDaoQuotaStorage;
use crate::secure::dual_window::DualWindowQuota;
use async_trait::async_trait;
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
    /// 发送邮件验证码（`to` 收件人地址已规范化）。
    async fn send(&self, to: &str, subject: &str, body: &str) -> GarrisonResult<()>;
}

/// 邮箱验证码限速器（双窗口：小时 + 天）。
///
/// 窗口判定与补偿委托泛型内核 `DualWindowQuota`（limiteron `QuotaStorage` 账本，经
/// `GarrisonDaoQuotaStorage` 落 DAO）；本类型只保留邮箱特有面：normalize/validate、
/// `email:` 命名空间与 `EmailRateLimitExceeded` 错误变体。
pub struct EmailRateLimiter {
    /// 双窗口账本内核（hour/day 判定与补偿）。
    kernel: DualWindowQuota<GarrisonDaoQuotaStorage>,
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
