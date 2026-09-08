//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 邀请码定向注册协议模块，提供可设失效时间、单次/N 次有效、可吊销的邀请码全生命周期管理。
//!
//! 对应 邀请码注册 机制，
//! 覆盖签发（`create`/`create_batch`）、只读校验（`validate`）、原子消费（`redeem`）、
//! 吊销（`revoke`）与列出（`list`），并内置防爆破尝试锁定与可选的注册编排钩子
//! （[`InvitationRedeemHook`](crate::protocol::invitation::InvitationRedeemHook)）。
//!
//! 仅在启用 `protocol-invitation` 特性时编译。
//!
//! ## Key 命名空间
//!
//! 邀请码记录存储在 `garrison:invitation:code:<normalized_code>` 命名空间下，
//! 与 session/temp/sign/apikey 模块隔离。防爆破计数存储在
//! `garrison:invitation:attempt:<md5hex(source)>` 命名空间下。
//!
//! ## 消费原子性
//!
//! `redeem` 经 `GarrisonDao::get_and_delete` 原子取出并删除记录（check-and-restore）：
//! 并发消费同一单次码时恰有一个调用成功，其余收到 NotFound；
//! N 次码在取出后更新 `used_count`，仍有剩余次数时以剩余 TTL 回写。

use crate::error::GarrisonResult;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod code;
pub mod handler;
pub mod limiter;

/// 邀请码生命周期状态。
///
/// `Revoked` 为终态：吊销后记录保留至原过期时间，供 validate 复核，但不可再消费。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvitationStatus {
    /// 有效，可消费。
    Active,
    /// 已被邀请人吊销。
    Revoked,
}

/// 邀请码记录（DAO KV 中的持久化形态，serde_json 序列化）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationRecord {
    /// 规范化后的邀请码（无连字符大写形态，与存储键一致）。
    pub code: String,
    /// 邀请人标识。
    pub issuer_id: String,
    /// 绑定租户（可选）。
    pub tenant_id: Option<String>,
    /// 注册成功后应授予的角色列表。
    pub bound_roles: Vec<String>,
    /// 最大消费次数（1 = 单次有效）。
    pub max_uses: u32,
    /// 已消费次数。
    pub used_count: u32,
    /// 已消费主体标识（redeemer_id，按消费顺序）。
    pub redeemed_by: Vec<String>,
    /// 签发时间（unix 秒）。
    pub created_at: i64,
    /// 过期时间（unix 秒）；回写时用于重算剩余 TTL。
    pub expires_at: i64,
    /// 生命周期状态。
    pub status: InvitationStatus,
}

impl InvitationRecord {
    /// 记录当前是否可消费（不考虑 KV 存在性；过期由调用方按 `expires_at` 判定）。
    pub fn consumable(&self, now: i64) -> bool {
        self.status == InvitationStatus::Active
            && now < self.expires_at
            && self.used_count < self.max_uses
    }
}

/// 邀请码签发规格。
#[derive(Debug, Clone)]
pub struct InvitationSpec {
    /// 邀请人标识。
    pub issuer_id: String,
    /// 绑定租户（可选）。
    pub tenant_id: Option<String>,
    /// 注册成功后应授予的角色列表。
    pub bound_roles: Vec<String>,
    /// 最大消费次数（1 = 单次有效，必须 >= 1）。
    pub max_uses: u32,
    /// 有效秒数（必须 > 0）。
    pub ttl_seconds: i64,
}

/// 校验/消费失败原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitationInvalidReason {
    /// 邀请码不存在（或已过期被 KV 清除、或为脏数据）。
    NotFound,
    /// 已过有效期。
    Expired,
    /// 已被吊销。
    Revoked,
    /// 消费次数已用尽。
    Exhausted,
}

/// validate 返回的状态报告（只读，不产生消费副作用）。
#[derive(Debug, Clone)]
pub struct InvitationStatusReport {
    /// 邀请码记录（有效或虽无效但记录仍存于 KV 时携带）。
    pub record: Option<InvitationRecord>,
    /// 无效原因；`None` 表示有效可消费。
    pub reason: Option<InvitationInvalidReason>,
}

impl InvitationStatusReport {
    /// 是否有效可消费。
    pub fn is_valid(&self) -> bool {
        self.reason.is_none()
    }
}

/// 注册编排钩子（可选注入）。
///
/// `redeem` 在邀请码消费路径上回调本钩子，由应用侧完成账号创建、凭证写入与
/// `bound_roles` 角色授予。钩子失败时 `redeem` 传播错误且回写取出前的原记录
/// （`used_count` 回滚），邀请码不被吞掉，应用修正后可重试。
#[async_trait::async_trait]
pub trait InvitationRedeemHook: Send + Sync {
    /// 消费生效前回调（`record.used_count` 已含本次消费）。
    async fn on_redeem(&self, record: &InvitationRecord) -> GarrisonResult<()>;
}

/// 邀请码处理器。
///
/// 持有 `Arc<dyn GarrisonDao>` 用于邀请码存储，可选注入 listener 管理器与注册编排钩子。
/// 实现 `Send + Sync`，可在多线程环境共享。
pub struct InvitationHandler {
    /// DAO 抽象层，用于邀请码存储与原子消费。
    pub(crate) dao: Arc<dyn crate::dao::GarrisonDao>,
    /// 防爆破尝试锁定器。
    pub(crate) limiter: limiter::InvitationAttemptLimiter,
    /// 可选监听器管理器，注入后 create/redeem/revoke 广播对应事件。
    #[cfg(feature = "listener")]
    pub(crate) listener_manager: Option<Arc<crate::listener::GarrisonListenerManager>>,
    /// 可选注册编排钩子，redeem 成功路径回调。
    pub(crate) hook: Option<Arc<dyn InvitationRedeemHook>>,
}

#[cfg(test)]
mod tests;
