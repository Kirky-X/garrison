// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! jti 一次性消费登记：DAO `set_if_absent`（SETNX 语义）原子消费。
//!
//! 登记与消费共用同一 key 空间（`pwdreset:jti:{jti}`）：登记即消费——
//! `set_if_absent` 恰一赢家（并发下其余调用方返回 `false`），二次消费
//! 因 key 已存在返回 `false`。TTL 与 ActionToken 剩余寿命对齐：token
//! 过期后登记自然失效，不滞留键空间。
//!
//! `InMemoryDao` / `oxcache` 的 `set_if_absent` 均为进程内/分布式原子实现
//! （见 `dao/mod.rs` 的 SETNX 契约），登记原子性由 DAO 保证。

use super::action_token::validate_jti;
use crate::constants::DaoKeyPrefix;
use crate::dao::GarrisonDao;
use crate::error::GarrisonResult;
use std::sync::Arc;

/// jti 一次性消费登记器。
pub struct ActionTokenConsumer {
    dao: Arc<dyn GarrisonDao>,
}

impl ActionTokenConsumer {
    /// 创建消费登记器。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self { dao }
    }

    /// 原子消费 jti：仅当该 jti 从未被消费过时成功。
    ///
    /// `ttl_seconds` 取 ActionToken 剩余寿命（过期后登记自然失效）。
    ///
    /// # 返回
    /// - `Ok(true)`：本次消费成功（该 jti 首次被消费）。
    /// - `Ok(false)`：消费失败——jti 已被消费过（二次消费/并发竞争败者）。
    ///
    /// # 错误
    /// - jti 结构非法（空/超长/含 `:`，DAO key 注入防护）：[`GarrisonError::InvalidToken`]
    /// - DAO 故障：透传 [`GarrisonError::Dao`]
    pub async fn consume(&self, jti: &str, ttl_seconds: u64) -> GarrisonResult<bool> {
        validate_jti(jti)?;
        let key = jti_key(jti);
        self.dao.set_if_absent(&key, "1", ttl_seconds).await
    }

    /// 授权凭据操作前调用：校验 jti 是否已被消费（**不**登记）。
    ///
    /// 两段式流程的第一段防线上移——已被消费过的 token 直接拒绝授权
    /// 凭据操作，避免「先改密后发现已消费」的回滚压力（见 `service`
    /// 模块两段式说明）。此检查为 best-effort 快速路径，真正的防重放
    /// 由 [`Self::consume`] 的原子语义兜底。
    pub async fn is_consumed(&self, jti: &str) -> GarrisonResult<bool> {
        validate_jti(jti)?;
        Ok(self.dao.get(&jti_key(jti)).await?.is_some())
    }
}

/// jti 消费登记 DAO key：`pwdreset:jti:{jti}`。
fn jti_key(jti: &str) -> String {
    format!("{}jti:{}", DaoKeyPrefix::PasswordReset, jti)
}
