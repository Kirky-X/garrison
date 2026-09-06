//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `InvitationHandler` 实现。
//!
//! 包含邀请码签发/读取/校验/撤销/消费/列出逻辑。
//!
//! 仅在启用 `protocol-invitation` 特性时编译。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::code;
use super::limiter::InvitationAttemptLimiter;
use super::{
    InvitationHandler, InvitationInvalidReason, InvitationRecord, InvitationSpec, InvitationStatus,
    InvitationStatusReport,
};

/// KV 键前缀：邀请码记录命名空间。
pub(crate) const KEY_PREFIX: &str = "garrison:invitation:code:";

/// `set_if_absent` 键碰撞时的最大重试次数。
const MAX_COLLISION_RETRIES: usize = 3;

impl InvitationHandler {
    /// 创建新的邀请码处理器（默认防爆破阈值：10 次 / 600 秒窗口）。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self {
            limiter: InvitationAttemptLimiter::new(dao.clone()),
            dao,
            #[cfg(feature = "listener")]
            listener_manager: None,
            hook: None,
        }
    }

    /// 注入 `GarrisonListenerManager`，启用 InvitationCreated/Redeemed/Revoked 事件广播。
    ///
    /// 未注入时为 no-op（与 `TempCredentialHandler::with_listener_manager` 语义一致）。
    /// 需启用 `listener` feature。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(
        mut self,
        lm: Arc<crate::listener::GarrisonListenerManager>,
    ) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 注入注册编排钩子，`redeem` 成功路径回调（应用侧完成账号创建与角色授予）。
    pub fn with_hook(mut self, hook: Arc<dyn super::InvitationRedeemHook>) -> Self {
        self.hook = Some(hook);
        self
    }

    /// 签发单条邀请码。
    ///
    /// 校验规格（TTL > 0、max_uses >= 1）后生成短码，经 `set_if_absent` 写入
    /// `garrison:invitation:code:<code>`，碰撞时重试最多 [`MAX_COLLISION_RETRIES`] 次。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidParam`: `ttl_seconds <= 0`、`max_uses == 0` 或碰撞重试耗尽。
    pub async fn create(&self, spec: InvitationSpec) -> GarrisonResult<InvitationRecord> {
        validate_spec(&spec)?;
        let record = self.persist_new_record(spec).await?;
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&crate::listener::GarrisonEvent::InvitationCreated {
                code: record.code.clone(),
                issuer_id: record.issuer_id.clone(),
            })
            .await;
        }
        Ok(record)
    }

    /// 批量签发 `count` 条邀请码（同一规格，码互异）。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidParam`: `count == 0`，或任一条签发失败（规格校验/碰撞）。
    pub async fn create_batch(
        &self,
        spec: InvitationSpec,
        count: usize,
    ) -> GarrisonResult<Vec<InvitationRecord>> {
        if count == 0 {
            return Err(GarrisonError::InvalidParam(
                "invitation-count-invalid::".to_string(),
            ));
        }
        validate_spec(&spec)?;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            records.push(self.persist_new_record(spec.clone()).await?);
        }
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            for record in &records {
                lm.broadcast(&crate::listener::GarrisonEvent::InvitationCreated {
                    code: record.code.clone(),
                    issuer_id: record.issuer_id.clone(),
                })
                .await;
            }
        }
        Ok(records)
    }

    /// 吊销邀请码（幂等）。
    ///
    /// 对存在且未吊销的记录：status 置 Revoked 回写（剩余 TTL）并广播 `InvitationRevoked`；
    /// 对已吊销记录：回写原状、不重复广播；对未知码或脏数据：`Ok(())`（删除即清理，幂等语义）。
    ///
    /// 注意：`issuer_id` 仅用于事件落账（取记录内真实邀请人），吊销权限校验属应用层职责
    /// （框架不持有权限模型，与 temp/apikey 协议同风格）。
    pub async fn revoke(&self, code_input: &str, _issuer_id: &str) -> GarrisonResult<()> {
        let normalized = code::normalize(code_input)?;
        let key = format!("{}{}", KEY_PREFIX, normalized);
        let raw = match self.dao.get_and_delete(&key).await? {
            Some(raw) => raw,
            None => return Ok(()),
        };
        let mut record: InvitationRecord = match serde_json::from_str(&raw) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        let already_revoked = record.status == InvitationStatus::Revoked;
        if !already_revoked {
            record.status = InvitationStatus::Revoked;
        }
        self.restore(&key, &record).await?;
        #[cfg(feature = "listener")]
        if !already_revoked {
            if let Some(lm) = &self.listener_manager {
                lm.broadcast(&crate::listener::GarrisonEvent::InvitationRevoked {
                    code: record.code.clone(),
                    issuer_id: record.issuer_id.clone(),
                })
                .await;
            }
        }
        Ok(())
    }

    /// 列出指定邀请人的邀请码记录（管理面，低频操作）。
    ///
    /// 经 `dao.keys("garrison:invitation:code:*")` 枚举后逐键读取反序列化，
    /// 过滤 `issuer_id` 匹配的记录；脏数据键跳过。大型 Redis 后端注意 `keys` 的
    /// 阻塞成本（管理面可接受；分页为后续变更）。
    pub async fn list(&self, issuer_id: &str) -> GarrisonResult<Vec<InvitationRecord>> {
        let pattern = format!("{}*", KEY_PREFIX);
        let keys = self.dao.keys(&pattern).await?;
        let mut records = Vec::new();
        for key in keys {
            let Some(raw) = self.dao.get(&key).await? else {
                continue;
            };
            if let Ok(record) = serde_json::from_str::<InvitationRecord>(&raw) {
                if record.issuer_id == issuer_id {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    /// 只读校验邀请码（不产生任何 KV 写副作用）。
    ///
    /// 输入经规范化后查 KV，返回 [`InvitationStatusReport`]：
    /// 有效时 `reason` 为 `None` 且携带记录；无效时 `reason` 精确区分
    /// NotFound / Expired / Revoked / Exhausted。
    pub async fn validate(&self, code_input: &str) -> GarrisonResult<InvitationStatusReport> {
        let normalized = code::normalize(code_input)?;
        let key = format!("{}{}", KEY_PREFIX, normalized);
        let raw = match self.dao.get(&key).await? {
            Some(raw) => raw,
            None => {
                return Ok(InvitationStatusReport {
                    record: None,
                    reason: Some(InvitationInvalidReason::NotFound),
                })
            },
        };
        let record: InvitationRecord = match serde_json::from_str(&raw) {
            Ok(r) => r,
            Err(_) => {
                // 脏数据视为不存在
                return Ok(InvitationStatusReport {
                    record: None,
                    reason: Some(InvitationInvalidReason::NotFound),
                });
            },
        };
        let reason = classify(&record, unix_now());
        Ok(InvitationStatusReport {
            record: Some(record),
            reason,
        })
    }

    /// 消费邀请码（原子 check-and-restore）。
    ///
    /// 经 `dao.get_and_delete` 原子取出并删除——并发消费同一单次码时恰有一个调用成功，
    /// 其余收到 NotFound（防 double-spend）。取出后校验：
    /// - `Revoked`：回写原记录（供 validate 复核）并拒绝；
    /// - 过期：不回写并拒绝；
    /// - 耗尽（`used_count >= max_uses`）：回写并拒绝；
    /// - 有效：`used_count += 1`，仍有剩余次数时回写更新记录（剩余 TTL），否则不回写。
    ///
    /// 成功消费广播 `InvitationRedeemed`（需 listener feature 且已注入 manager）。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidParam`: 码格式非法、不存在、过期、已吊销或已耗尽
    ///   （`invitation-*::` key 前缀）。
    pub async fn redeem(
        &self,
        code_input: &str,
        redeemer_id: &str,
        source: &str,
    ) -> GarrisonResult<InvitationRecord> {
        // 防爆破：首步计数并检查（被锁定时短路径返回，不触碰邀请码 KV）
        self.limiter.check(source).await?;
        let normalized = code::normalize(code_input)?;
        let key = format!("{}{}", KEY_PREFIX, normalized);
        // 原子取出并删除：并发消费同一码仅一者拿到记录
        let raw = match self.dao.get_and_delete(&key).await? {
            Some(raw) => raw,
            None => {
                return Err(GarrisonError::InvalidParam(
                    "invitation-code-not-found::".to_string(),
                ))
            },
        };
        let mut record: InvitationRecord = match serde_json::from_str(&raw) {
            Ok(r) => r,
            Err(_) => {
                // 脏数据不回写
                return Err(GarrisonError::InvalidParam(
                    "invitation-code-not-found::".to_string(),
                ));
            },
        };
        let now = unix_now();
        // 吊销：回写原记录（未过期时）供复核
        if record.status == InvitationStatus::Revoked {
            if now < record.expires_at {
                self.restore(&key, &record).await?;
            }
            return Err(GarrisonError::InvalidParam(format!(
                "invitation-code-revoked::{}",
                record.code
            )));
        }
        // 过期：不回写
        if now >= record.expires_at {
            return Err(GarrisonError::InvalidParam(
                "invitation-code-expired::".to_string(),
            ));
        }
        // 耗尽：回写原记录供复核
        if record.used_count >= record.max_uses {
            self.restore(&key, &record).await?;
            return Err(GarrisonError::InvalidParam(format!(
                "invitation-code-exhausted::{}",
                record.code
            )));
        }
        // 有效：更新计数（hook 回调时 record 已含本次消费）
        let original = record.clone();
        record.used_count += 1;
        record.redeemed_by.push(redeemer_id.to_string());
        // 注册编排钩子：应用侧账号创建/凭证写入/角色授予。
        // 失败则回写取出前原记录（计数回滚），邀请码不被吞掉，修正后可重试。
        if let Some(hook) = &self.hook {
            if let Err(e) = hook.on_redeem(&record).await {
                self.restore(&key, &original).await?;
                return Err(e);
            }
        }
        // 回写策略：仍有剩余次数、或多次码已耗尽（保留供 validate 复核 Exhausted、
        // 后续消费报 invitation-code-exhausted::）时回写；
        // 单次码（max_uses == 1）消费即删除，二次消费报 invitation-code-not-found::。
        if record.max_uses > 1 || record.used_count < record.max_uses {
            self.restore(&key, &record).await?;
        }
        // 成功消费清除该来源的尝试计数（幂等删除）
        self.limiter.reset(source).await?;
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&crate::listener::GarrisonEvent::InvitationRedeemed {
                code: record.code.clone(),
                redeemer_id: redeemer_id.to_string(),
            })
            .await;
        }
        Ok(record)
    }

    /// 以记录的 `expires_at` 重算剩余 TTL 回写 KV。
    pub(crate) async fn restore(&self, key: &str, record: &InvitationRecord) -> GarrisonResult<()> {
        let remaining = (record.expires_at - unix_now()).max(1) as u64;
        self.dao
            .set(
                key,
                &serde_json::to_string(record)
                    .map_err(|e| GarrisonError::Dao(format!("invitation-serialize-failed::{e}")))?,
                remaining,
            )
            .await
    }

    /// 生成码并落 KV（spec 已校验）。
    async fn persist_new_record(&self, spec: InvitationSpec) -> GarrisonResult<InvitationRecord> {
        let now = unix_now();
        let expires_at = now + spec.ttl_seconds;
        for _ in 0..MAX_COLLISION_RETRIES {
            let normalized = code::normalize(&code::generate())?;
            let record = InvitationRecord {
                code: normalized.clone(),
                issuer_id: spec.issuer_id.clone(),
                tenant_id: spec.tenant_id.clone(),
                bound_roles: spec.bound_roles.clone(),
                max_uses: spec.max_uses,
                used_count: 0,
                redeemed_by: Vec::new(),
                created_at: now,
                expires_at,
                status: InvitationStatus::Active,
            };
            let key = format!("{}{}", KEY_PREFIX, normalized);
            if self
                .dao
                .set_if_absent(
                    &key,
                    &serde_json::to_string(&record).map_err(|e| {
                        GarrisonError::Dao(format!("invitation-serialize-failed::{e}"))
                    })?,
                    (expires_at - now) as u64,
                )
                .await?
            {
                return Ok(record);
            }
            // 键碰撞：极小概率随机码冲突，重试
        }
        Err(GarrisonError::InvalidParam(
            "invitation-code-collision::".to_string(),
        ))
    }
}

/// 校验签发规格。
pub(crate) fn validate_spec(spec: &InvitationSpec) -> GarrisonResult<()> {
    if spec.ttl_seconds <= 0 {
        return Err(GarrisonError::InvalidParam(
            "invitation-ttl-invalid::".to_string(),
        ));
    }
    if spec.max_uses == 0 {
        return Err(GarrisonError::InvalidParam(
            "invitation-max-uses-invalid::".to_string(),
        ));
    }
    Ok(())
}

/// 按记录内容与当前时间判定无效原因；`None` 表示有效可消费。
pub(crate) fn classify(record: &InvitationRecord, now: i64) -> Option<InvitationInvalidReason> {
    if record.status == InvitationStatus::Revoked {
        return Some(InvitationInvalidReason::Revoked);
    }
    if now >= record.expires_at {
        return Some(InvitationInvalidReason::Expired);
    }
    if record.used_count >= record.max_uses {
        return Some(InvitationInvalidReason::Exhausted);
    }
    None
}

/// 当前 unix 秒。
pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
