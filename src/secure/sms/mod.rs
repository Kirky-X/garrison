// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! SMS 验证码渐进式限速模块。
//!
//! 三层抽象：`SmsSender` trait（业务方实现短信发送）+ `SmsRateLimiter`（双窗口限速）+ `SmsVerificationService`（发送/验证/异常检测）。
//!
//! # Key 空间设计
//!
//! | key | TTL | 用途 |
//! |-----|-----|------|
//! | `quota:hour:sms:{phone}` | 3600s | 小时限速账本（limiteron QuotaStorage） |
//! | `quota:day:sms:{phone}` | 86400s | 天限速账本（limiteron QuotaStorage） |
//! | `sms:code:{phone}` | 300s | 验证码 |
//! | `sms:attempts:{phone}` | 300s | 验证尝试次数 |
//! | `sms:unverified:{phone}` | 86400s | 连续未验证计数器 |
//! | `sms:recycled:{phone}` | 86400s | 通道回收标记 |
//!
//! # 安全约束
//!
//! phone 不含 ':'（防 key 注入）；验证码用 `rand::rng()`（ThreadRng，ChaCha12 CSPRNG）；限速账本与
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

/// SMS 限速器（双窗口：小时 + 天）。
///
/// 窗口判定与补偿委托泛型内核 [`DualWindowQuota`]（limiteron `QuotaStorage` 账本，经 `GarrisonDaoQuotaStorage` 落 DAO）；
/// 本类型只保留 SMS 特有面：normalize/validate、`sms:` 命名空间与 `SmsRateLimitExceeded` 错误变体。
pub struct SmsRateLimiter {
    /// 双窗口账本内核（hour/day 判定与补偿）。
    kernel: DualWindowQuota<GarrisonDaoQuotaStorage>,
}

/// SMS 验证码服务。
///
/// # DAO 注入约束（重要）
///
/// 本服务与内嵌 [`SmsRateLimiter`] 各持有一个 [`GarrisonDao`]（分别用于 code/attempts/unverified/recycled key 与限速计数），
/// **两者必须指向同一实例/后端**（构造时传同一个 `Arc`）；框架不强制该约束，若注入不同实例，限速递增与读码落在不同后端，
/// 导致限速失效或验证码状态错乱。
pub struct SmsVerificationService {
    rate_limiter: SmsRateLimiter,
    sender: Arc<dyn SmsSender>,
    dao: Arc<dyn GarrisonDao>,
    max_verify_attempts: u32,
    unverified_threshold: u32,
}
