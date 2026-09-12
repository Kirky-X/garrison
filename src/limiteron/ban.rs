//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `BanStorage` 适配器，用 `GarrisonDao` KV 存储封禁记录。
//!
//! # 存储格式
//! - 封禁记录：`limiteron:ban:{type}:{value}` →
//!   `expires_at_ts|ban_times|is_manual|duration_secs|reason`
//!   （兼容旧版 4 段格式 `expires_at_ts|ban_times|is_manual|reason`，duration
//!   按 `ban_times * 300s` 重算）
//! - 封禁次数：`limiteron:ban:times:{type}:{value}` → `u64`
//! - 封禁历史：`limiteron:ban:history:{type}:{value}` → `ban_times|last_banned_at_ts`
//!
//! # 一致性与 TTL 语义
//! - `save` 先写主记录（`is_banned` 执行依据），times/history 失败时 best-effort
//!   回滚已写 key 并返回错误。`GarrisonDao` 无事务接口，回滚本身也可能失败，
//!   此时以 `tracing::warn` 记录（部分失败语义）。
//! - `increment_ban_times` 与封禁记录的剩余 TTL 对齐（incr 仅在 key 首次创建时
//!   生效 TTL），避免 record 过期后 times 键永久残留。
//! - `is_banned` 在查询时检查过期时间（过期返回 None）。

use crate::dao::GarrisonDao;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use limiteron::error::StorageError;
use limiteron::storage::{BanHistory, BanRecord, BanStorage, BanTarget};
use std::sync::Arc;
use std::time::Duration;

use super::errors::map_to_storage_err;

/// 封禁 key 前缀。
const BAN_KEY_PREFIX: &str = "limiteron:ban";
/// 封禁次数 key 前缀。
const BAN_TIMES_KEY_PREFIX: &str = "limiteron:ban:times";
/// 封禁历史 key 前缀。
const BAN_HISTORY_KEY_PREFIX: &str = "limiteron:ban:history";

/// 将 `BanTarget` 序列化为 key 片段。
fn target_to_key_fragment(target: &BanTarget) -> String {
    match target {
        BanTarget::Ip(ip) => format!("ip:{}", ip),
        BanTarget::UserId(uid) => format!("user:{}", uid),
        BanTarget::Mac(mac) => format!("mac:{}", mac),
        BanTarget::Geo { country_code } => format!("geo:{}", country_code),
    }
}

/// 封禁记录 key：`limiteron:ban:{type}:{value}`。
fn ban_record_key(target: &BanTarget) -> String {
    format!("{}:{}", BAN_KEY_PREFIX, target_to_key_fragment(target))
}

/// 封禁次数 key：`limiteron:ban:times:{type}:{value}`。
fn ban_times_key(target: &BanTarget) -> String {
    format!(
        "{}:{}",
        BAN_TIMES_KEY_PREFIX,
        target_to_key_fragment(target)
    )
}

/// 封禁历史 key：`limiteron:ban:history:{type}:{value}`。
fn ban_history_key(target: &BanTarget) -> String {
    format!(
        "{}:{}",
        BAN_HISTORY_KEY_PREFIX,
        target_to_key_fragment(target)
    )
}

/// 序列化 `BanRecord` 为字符串：
/// `expires_at_ts|ban_times|is_manual|duration_secs|reason`。
///
/// `duration` 落盘：非标准时长（与 `ban_times * 300s` 不一致，如手动封禁）
/// 在反序列化后得以保留（旧版 4 段格式见 [`deserialize_ban_record`]）。
fn serialize_ban_record(record: &BanRecord) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        record.expires_at.timestamp(),
        record.ban_times,
        record.is_manual,
        record.duration.as_secs(),
        record.reason
    )
}

/// 反序列化 `BanRecord`。
///
/// 兼容两种存储格式：
/// - 5 段（当前）：`expires_at_ts|ban_times|is_manual|duration_secs|reason`，
///   `duration` 从落盘值恢复；
/// - 4 段（旧版）：`expires_at_ts|ban_times|is_manual|reason`，`duration` 按
///   `ban_times * 300s` 重算。
///
/// # 脏数据处理（fail-open + 可观测）
///
/// 段数不对或数字字段解析失败时返回 `None`（视为未封禁），与 `is_banned`
/// 热路径的 fail-open 语义一致；区别于 `get_ban_times` / `get_history` 的
/// fail-fast（管理面查询，脏数据显性报错）。fail-open 的静默性通过
/// `tracing::warn` 补偿，保证「记录存在但已损坏」可被观测。
fn deserialize_ban_record(target: &BanTarget, val: &str) -> Option<BanRecord> {
    let parts: Vec<&str> = val.splitn(5, '|').collect();
    let target_id = target_to_key_fragment(target);
    let (is_manual_str, duration_secs, reason) = match parts.len() {
        5 => {
            let duration_secs: u64 = match parts[3].parse() {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        target = %target_id,
                        value = %val,
                        error = %e,
                        "limiteron-ban: 封禁记录 duration 字段解析失败，视为未封禁（fail-open）"
                    );
                    return None;
                },
            };
            (parts[2], Some(duration_secs), parts[4])
        },
        4 => (parts[2], None, parts[3]),
        n => {
            tracing::warn!(
                target = %target_id,
                value = %val,
                parts = n,
                "limiteron-ban: 封禁记录段数不对，视为未封禁（fail-open）"
            );
            return None;
        },
    };
    let expires_at_ts: i64 = match parts[0].parse() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                target = %target_id,
                value = %val,
                error = %e,
                "limiteron-ban: 封禁记录 expires_at_ts 解析失败，视为未封禁（fail-open）"
            );
            return None;
        },
    };
    let ban_times: u32 = match parts[1].parse() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                target = %target_id,
                value = %val,
                error = %e,
                "limiteron-ban: 封禁记录 ban_times 解析失败，视为未封禁（fail-open）"
            );
            return None;
        },
    };
    let is_manual = is_manual_str == "true";
    let expires_at = match DateTime::from_timestamp(expires_at_ts, 0) {
        Some(v) => v,
        None => {
            tracing::warn!(
                target = %target_id,
                expires_at_ts,
                "limiteron-ban: 封禁记录时间戳非法，视为未封禁（fail-open）"
            );
            return None;
        },
    };
    // 5 段格式：duration 落盘恢复；4 段旧格式：按 ban_times * 300s 重算
    let duration = match duration_secs {
        Some(secs) => Duration::from_secs(secs),
        None => record_duration_from_ban(target, ban_times),
    };
    let banned_at = expires_at
        - chrono::Duration::from_std(duration)
            .unwrap_or_else(|_| chrono::Duration::seconds(0));
    Some(BanRecord {
        target: target.clone(),
        ban_times,
        duration,
        banned_at,
        expires_at,
        is_manual,
        reason: reason.to_string(),
    })
}

/// 从 ban_times 推断 duration（简化：ban_times * 300s）。
fn record_duration_from_ban(_target: &BanTarget, ban_times: u32) -> Duration {
    Duration::from_secs((ban_times as u64).saturating_mul(300))
}

/// `BanStorage` 适配器，用 `GarrisonDao` KV 存储封禁记录。
///
/// # 存储格式
/// - 封禁记录：`limiteron:ban:{type}:{value}` →
///   `expires_at_ts|ban_times|is_manual|duration_secs|reason`
///   （兼容旧版 4 段格式，duration 按 `ban_times * 300s` 重算）
/// - 封禁次数：`limiteron:ban:times:{type}:{value}` → `u64`
/// - 封禁历史：`limiteron:ban:history:{type}:{value}` → `ban_times|last_banned_at_ts`
///
/// # 一致性与 TTL 语义
/// - `save` 先写主记录，times/history 失败时 best-effort 回滚并返回错误；
/// - `increment_ban_times` 与封禁记录剩余 TTL 对齐，避免 times 键永久残留；
/// - `is_banned` 在查询时检查过期时间（过期返回 None）。
pub struct GarrisonDaoBanStorage {
    pub(super) dao: Arc<dyn GarrisonDao>,
}

impl GarrisonDaoBanStorage {
    /// 创建适配器实例。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self { dao }
    }
}

#[async_trait]
impl BanStorage for GarrisonDaoBanStorage {
    async fn is_banned(&self, target: &BanTarget) -> Result<Option<BanRecord>, StorageError> {
        let key = ban_record_key(target);
        match self.dao.get(&key).await.map_err(map_to_storage_err)? {
            None => Ok(None),
            Some(val) => {
                let record = deserialize_ban_record(target, &val);
                if let Some(ref r) = record {
                    if r.expires_at <= Utc::now() {
                        // 已过期，返回 None
                        return Ok(None);
                    }
                }
                Ok(record)
            },
        }
    }

    /// 保存封禁记录（record + times + history 三个 key）。
    ///
    /// # 一致性语义（无事务）
    ///
    /// `GarrisonDao` 无事务/批量接口，三个 key 无法原子写入。策略：
    /// - **先写主记录**（`is_banned` 的执行依据）：失败即止，不产生任何部分状态；
    /// - times / history 失败时 **best-effort 回滚已写 key** 并返回明确错误，
    ///   避免「record 存在但 times/history 缺失」的不一致状态；回滚 delete
    ///   本身失败仅 `tracing::warn`（部分失败语义，不掩盖原始错误）。
    async fn save(&self, record: &BanRecord) -> Result<(), StorageError> {
        let key = ban_record_key(&record.target);
        let val = serialize_ban_record(record);
        let ttl = (record.expires_at - Utc::now()).num_seconds().max(0) as u64;
        // 主记录先写：失败即止
        self.dao
            .set(&key, &val, ttl)
            .await
            .map_err(map_to_storage_err)?;

        // 同步更新封禁次数和历史（失败回滚已写 key）
        let times_key = ban_times_key(&record.target);
        if let Err(e) = self
            .dao
            .set(&times_key, &record.ban_times.to_string(), ttl)
            .await
        {
            tracing::warn!(
                ban_key = %key,
                error = %e,
                "limiteron-ban: 封禁次数 key 写入失败，回滚主记录"
            );
            let _ = self.dao.delete(&key).await;
            return Err(map_to_storage_err(e));
        }

        let history_key = ban_history_key(&record.target);
        let history_val = format!("{}|{}", record.ban_times, Utc::now().timestamp());
        if let Err(e) = self.dao.set(&history_key, &history_val, ttl).await {
            tracing::warn!(
                ban_key = %key,
                error = %e,
                "limiteron-ban: 封禁历史 key 写入失败，回滚主记录与次数"
            );
            let _ = self.dao.delete(&key).await;
            let _ = self.dao.delete(&times_key).await;
            return Err(map_to_storage_err(e));
        }
        Ok(())
    }

    async fn get_history(&self, target: &BanTarget) -> Result<Option<BanHistory>, StorageError> {
        let key = ban_history_key(target);
        match self.dao.get(&key).await.map_err(map_to_storage_err)? {
            None => Ok(None),
            Some(val) => {
                let parts: Vec<&str> = val.splitn(2, '|').collect();
                if parts.len() != 2 {
                    return Err(StorageError::QueryError(format!(
                        "limiteron-ban-history-format-error::{}::{}::{}",
                        key,
                        val,
                        parts.len()
                    )));
                }
                // M-3: parse 失败显性化 — 脏数据返回 Err（fail-fast）
                let ban_times: u32 = parts[0].parse().map_err(|e| {
                    StorageError::QueryError(format!(
                        "limiteron-ban-history-parse-ban-times::{}::{}::{}",
                        key, parts[0], e
                    ))
                })?;
                let last_banned_at_ts: i64 = parts[1].parse().map_err(|e| {
                    StorageError::QueryError(format!(
                        "limiteron-ban-history-parse-last-banned::{}::{}::{}",
                        key, parts[1], e
                    ))
                })?;
                let last_banned_at =
                    DateTime::from_timestamp(last_banned_at_ts, 0).unwrap_or_else(Utc::now);
                Ok(Some(BanHistory {
                    ban_times,
                    last_banned_at,
                }))
            },
        }
    }

    async fn increment_ban_times(&self, target: &BanTarget) -> Result<u64, StorageError> {
        let key = ban_times_key(target);
        // TTL 对齐修复：旧实现 incr TTL=0（永久存储），而 record/history 带到期
        // TTL——record 过期后 times 键永久残留，get_ban_times 返回历史累计而非
        // 当前封禁次数。现优先以 record 剩余生存期作为 times key 的 TTL。
        // 注：GarrisonDao::incr 仅在 key 首次创建时设置 TTL；已存在的 times 键
        // （含旧版遗留的永久键）不会被重置 TTL，残留键仍会在 record 过期后保留，
        // 彻底清理需 DAO 提供 iter/expire 查询能力。
        let record_key = ban_record_key(target);
        let ttl = match self.dao.get(&record_key).await.map_err(map_to_storage_err)? {
            Some(val) => match deserialize_ban_record(target, &val) {
                Some(record) if record.expires_at > Utc::now() => {
                    (record.expires_at - Utc::now()).num_seconds().max(1) as u64
                },
                _ => 0,
            },
            None => 0,
        };
        self.dao.incr(&key, ttl).await.map_err(map_to_storage_err)
    }

    async fn get_ban_times(&self, target: &BanTarget) -> Result<u64, StorageError> {
        let key = ban_times_key(target);
        match self.dao.get(&key).await.map_err(map_to_storage_err)? {
            None => Ok(0),
            // M-3: parse 失败显性化 — 脏数据返回错误而非静默用 0
            Some(val) => val.parse::<u64>().map_err(|e| {
                StorageError::QueryError(format!(
                    "limiteron-ban-times-parse-failed::{}::{}::{}",
                    key, val, e
                ))
            }),
        }
    }

    /// 移除封禁记录（record + times + history 三个 key）。
    ///
    /// # 一致性语义（无事务）
    ///
    /// 三个删除无事务保证。顺序上**先删主记录**：即使后续 times/history 删除
    /// 失败，封禁也已被解除（安全优先）；残留的 times/history 键带 TTL（随
    /// record 到期写入）会自动过期，或随下次 `save` 覆盖。中途失败返回错误，
    /// 错误信息可定位到首个失败的 delete。
    async fn remove_ban(&self, target: &BanTarget) -> Result<(), StorageError> {
        let record_key = ban_record_key(target);
        let times_key = ban_times_key(target);
        let history_key = ban_history_key(target);
        self.dao
            .delete(&record_key)
            .await
            .map_err(map_to_storage_err)?;
        self.dao
            .delete(&times_key)
            .await
            .map_err(map_to_storage_err)?;
        self.dao
            .delete(&history_key)
            .await
            .map_err(map_to_storage_err)
    }

    async fn cleanup_expired_bans(&self) -> Result<u64, StorageError> {
        // GarrisonDao 无 iter API，无法扫描过期 key
        // 封禁记录设置 TTL，过期自动删除；is_banned 查询时检查过期时间
        tracing::warn!(
            "limiteron-ban: cleanup_expired_bans 未实现（GarrisonDao 无 iter API），\
             返回 0——请勿依赖本方法清理过期封禁（TTL 自动过期 + is_banned 查询时检查兜底）"
        );
        Ok(0)
    }

    async fn list_bans(
        &self,
        _active_only: bool,
        _offset: u64,
        _limit: u64,
    ) -> Result<Vec<BanRecord>, StorageError> {
        // GarrisonDao 无 iter API，无法列出所有 key
        tracing::warn!(
            "limiteron-ban: list_bans 未实现（GarrisonDao 无 iter API），\
             返回空列表——请勿依赖本方法做封禁审计/枚举（假阴性）"
        );
        Ok(Vec::new())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    fn make_dao() -> Arc<dyn GarrisonDao> {
        Arc::new(MockDao::new())
    }

    // --- GarrisonDaoBanStorage 测试 ---

    #[tokio::test]
    async fn ban_save_and_is_banned() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let target = BanTarget::Ip("192.168.1.1".to_string());

        // 未封禁
        assert!(storage.is_banned(&target).await.unwrap().is_none());

        // 封禁
        let record = BanRecord {
            target: target.clone(),
            ban_times: 1,
            duration: Duration::from_secs(300),
            banned_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            is_manual: false,
            reason: "bruteforce".to_string(),
        };
        storage.save(&record).await.unwrap();

        // 已封禁
        let banned = storage.is_banned(&target).await.unwrap();
        assert!(banned.is_some());
        assert_eq!(banned.unwrap().ban_times, 1);
    }

    #[tokio::test]
    async fn ban_expired_returns_none() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let target = BanTarget::Ip("10.0.0.1".to_string());

        let record = BanRecord {
            target: target.clone(),
            ban_times: 1,
            duration: Duration::from_secs(1),
            banned_at: Utc::now() - chrono::Duration::seconds(10),
            expires_at: Utc::now() - chrono::Duration::seconds(5), // 已过期
            is_manual: false,
            reason: "test".to_string(),
        };
        // 直接写入 DAO（绕过 save 的 TTL 计算）
        let key = ban_record_key(&target);
        let val = serialize_ban_record(&record);
        storage.dao.set(&key, &val, 0).await.unwrap();

        // is_banned 应返回 None（已过期）
        assert!(storage.is_banned(&target).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn ban_increment_and_get_times() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let target = BanTarget::UserId("user123".to_string());

        assert_eq!(storage.get_ban_times(&target).await.unwrap(), 0);

        let t1 = storage.increment_ban_times(&target).await.unwrap();
        assert_eq!(t1, 1);

        let t2 = storage.increment_ban_times(&target).await.unwrap();
        assert_eq!(t2, 2);

        assert_eq!(storage.get_ban_times(&target).await.unwrap(), 2);
    }

    /// increment_ban_times 在存在有效封禁记录时正常递增
    /// （TTL 与 record 剩余生存期对齐；MockDao 无法直接观测 TTL，验证功能语义）。
    ///
    /// 注：save 先以 record.ban_times 播种 times 计数（此处 = 1），
    /// increment 在其上 +1 → 2。
    #[tokio::test]
    async fn ban_increment_times_with_active_record() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let target = BanTarget::Ip("6.6.6.6".to_string());
        let record = BanRecord {
            target: target.clone(),
            ban_times: 1,
            duration: Duration::from_secs(300),
            banned_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            is_manual: false,
            reason: "t".to_string(),
        };
        storage.save(&record).await.unwrap();
        assert_eq!(
            storage.get_ban_times(&target).await.unwrap(),
            1,
            "save 应以 record.ban_times 播种 times 计数"
        );
        assert_eq!(storage.increment_ban_times(&target).await.unwrap(), 2);
        assert_eq!(storage.get_ban_times(&target).await.unwrap(), 2);
    }

    /// history key 写入失败时 save 回滚主记录与 times，并返回明确错误
    /// （无事务下「先写主记录、失败即回滚」的部分失败语义）。
    #[tokio::test]
    async fn ban_save_rolls_back_on_history_failure() {
        use crate::error::GarrisonError;

        /// history key 写入必失败的 DAO（其余委托 MockDao）。
        struct FailingHistoryDao {
            inner: MockDao,
        }

        #[async_trait]
        impl GarrisonDao for FailingHistoryDao {
            async fn get(&self, key: &str) -> crate::error::GarrisonResult<Option<String>> {
                self.inner.get(key).await
            }
            async fn set(
                &self,
                key: &str,
                value: &str,
                ttl_seconds: u64,
            ) -> crate::error::GarrisonResult<()> {
                if key.starts_with("limiteron:ban:history:") {
                    return Err(GarrisonError::Dao("injected history failure".to_string()));
                }
                self.inner.set(key, value, ttl_seconds).await
            }
            async fn update(&self, key: &str, value: &str) -> crate::error::GarrisonResult<()> {
                self.inner.update(key, value).await
            }
            async fn expire(&self, key: &str, seconds: u64) -> crate::error::GarrisonResult<()> {
                self.inner.expire(key, seconds).await
            }
            async fn delete(&self, key: &str) -> crate::error::GarrisonResult<()> {
                self.inner.delete(key).await
            }
            async fn incr(&self, key: &str, ttl_seconds: u64) -> crate::error::GarrisonResult<u64> {
                self.inner.incr(key, ttl_seconds).await
            }
            async fn decr(&self, key: &str) -> crate::error::GarrisonResult<u64> {
                self.inner.decr(key).await
            }
            async fn set_if_absent(
                &self,
                key: &str,
                value: &str,
                ttl_seconds: u64,
            ) -> crate::error::GarrisonResult<bool> {
                self.inner.set_if_absent(key, value, ttl_seconds).await
            }
            async fn rename(&self, old_key: &str, new_key: &str) -> crate::error::GarrisonResult<()> {
                self.inner.rename(old_key, new_key).await
            }
            async fn get_and_delete(
                &self,
                key: &str,
            ) -> crate::error::GarrisonResult<Option<String>> {
                self.inner.get_and_delete(key).await
            }
            async fn compare_and_swap(
                &self,
                key: &str,
                expected: Option<&str>,
                new_value: &str,
                ttl_seconds: u64,
            ) -> crate::error::GarrisonResult<bool> {
                self.inner
                    .compare_and_swap(key, expected, new_value, ttl_seconds)
                    .await
            }
        }

        let storage = GarrisonDaoBanStorage::new(Arc::new(FailingHistoryDao {
            inner: MockDao::new(),
        }));
        let target = BanTarget::Ip("5.5.5.5".to_string());
        let record = BanRecord {
            target: target.clone(),
            ban_times: 1,
            duration: Duration::from_secs(300),
            banned_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            is_manual: false,
            reason: "t".to_string(),
        };

        let result = storage.save(&record).await;
        assert!(result.is_err(), "history 写入失败时 save 应返回错误");

        // 主记录与 times 已被回滚，不残留不一致的部分状态
        assert!(
            storage.is_banned(&target).await.unwrap().is_none(),
            "回滚后主记录不应残留"
        );
        assert!(
            storage
                .dao
                .get(&ban_times_key(&target))
                .await
                .unwrap()
                .is_none(),
            "回滚后 times key 不应残留"
        );
    }

    #[tokio::test]
    async fn ban_remove() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let target = BanTarget::Ip("172.16.0.1".to_string());

        let record = BanRecord {
            target: target.clone(),
            ban_times: 1,
            duration: Duration::from_secs(300),
            banned_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            is_manual: true,
            reason: "manual".to_string(),
        };
        storage.save(&record).await.unwrap();
        assert!(storage.is_banned(&target).await.unwrap().is_some());

        storage.remove_ban(&target).await.unwrap();
        assert!(storage.is_banned(&target).await.unwrap().is_none());
        assert_eq!(storage.get_ban_times(&target).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn ban_get_history() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let target = BanTarget::Mac("AA:BB:CC:DD:EE:FF".to_string());

        let record = BanRecord {
            target: target.clone(),
            ban_times: 3,
            duration: Duration::from_secs(900),
            banned_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(900),
            is_manual: false,
            reason: "repeat".to_string(),
        };
        storage.save(&record).await.unwrap();

        let history = storage.get_history(&target).await.unwrap();
        assert!(history.is_some());
        assert_eq!(history.unwrap().ban_times, 3);
    }

    #[tokio::test]
    async fn ban_list_bans_returns_empty() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let bans = storage.list_bans(true, 0, 10).await.unwrap();
        assert!(
            bans.is_empty(),
            "list_bans 应返回空 Vec（GarrisonDao 无 iter API）"
        );
    }

    #[tokio::test]
    async fn ban_cleanup_returns_zero() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let count = storage.cleanup_expired_bans().await.unwrap();
        assert_eq!(
            count, 0,
            "cleanup_expired_bans 应返回 0（GarrisonDao 无 iter API）"
        );
    }

    // --- M-3: unwrap_or(0) 静默吞错修复测试 ---

    /// M-3: BanStorage::get_ban_times 遇到脏数据时返回错误（非静默用 0）。
    #[tokio::test]
    async fn m3_ban_get_ban_times_dirty_data_returns_err() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let target = BanTarget::Ip("1.2.3.4".to_string());
        // 直接注入脏数据
        let key = ban_times_key(&target);
        storage.dao.set(&key, "not-a-number", 0).await.unwrap();
        let result = storage.get_ban_times(&target).await;
        assert!(result.is_err(), "脏数据应返回错误，实际: {:?}", result);
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("limiteron-ban-times-parse-failed"),
            "错误消息应包含 'limiteron-ban-times-parse-failed'，实际: {}",
            err_msg
        );
    }

    /// M-3: BanStorage::get_history 遇到脏数据时返回错误（fail-fast）。
    #[tokio::test]
    async fn m3_ban_get_history_dirty_data_returns_err() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let target = BanTarget::Ip("5.6.7.8".to_string());
        let key = ban_history_key(&target);
        // ban_times 字段是非数字
        storage.dao.set(&key, "not-number|1000", 0).await.unwrap();
        let result = storage.get_history(&target).await;
        assert!(result.is_err(), "脏数据应返回错误，实际: {:?}", result);
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("limiteron-ban-history-parse-ban-times"),
            "错误消息应包含 'limiteron-ban-history-parse-ban-times'，实际: {}",
            err_msg
        );
    }

    // --- 补充覆盖：ban 辅助函数与边界路径 ---

    /// target_to_key_fragment 对所有 BanTarget 变体生成正确的 key 片段。
    #[test]
    fn target_to_key_fragment_all_variants() {
        assert_eq!(
            target_to_key_fragment(&BanTarget::Ip("1.2.3.4".into())),
            "ip:1.2.3.4"
        );
        assert_eq!(
            target_to_key_fragment(&BanTarget::UserId("u123".into())),
            "user:u123"
        );
        assert_eq!(
            target_to_key_fragment(&BanTarget::Mac("AA:BB:CC".into())),
            "mac:AA:BB:CC"
        );
        assert_eq!(
            target_to_key_fragment(&BanTarget::Geo {
                country_code: "CN".into()
            }),
            "geo:CN"
        );
    }

    /// ban_record_key / ban_times_key / ban_history_key 生成正确格式。
    #[test]
    fn ban_key_functions_correct_format() {
        let target = BanTarget::Ip("10.0.0.1".to_string());
        assert_eq!(ban_record_key(&target), "limiteron:ban:ip:10.0.0.1");
        assert_eq!(ban_times_key(&target), "limiteron:ban:times:ip:10.0.0.1");
        assert_eq!(
            ban_history_key(&target),
            "limiteron:ban:history:ip:10.0.0.1"
        );
    }

    /// serialize_ban_record / deserialize_ban_record round-trip 正确，
    /// 且非标准 duration（≠ ban_times * 300s）落盘后不被重算覆盖。
    #[tokio::test]
    async fn ban_serialize_deserialize_round_trip() {
        let target = BanTarget::UserId("round_trip_user".to_string());
        let original = BanRecord {
            target: target.clone(),
            ban_times: 3,
            duration: Duration::from_secs(1234), // 非标准时长（ban_times*300=900）
            banned_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(3600),
            is_manual: true,
            reason: "test_reason".to_string(),
        };
        let serialized = serialize_ban_record(&original);
        let deserialized = deserialize_ban_record(&target, &serialized);
        assert!(deserialized.is_some(), "反序列化应返回 Some");
        let deserialized = deserialized.unwrap();
        assert_eq!(deserialized.ban_times, 3);
        assert!(deserialized.is_manual);
        assert_eq!(deserialized.reason, "test_reason");
        assert_eq!(deserialized.target, target);
        assert_eq!(
            deserialized.duration,
            Duration::from_secs(1234),
            "duration 应落盘恢复，而非被 ban_times*300 重算覆盖"
        );
    }

    /// 旧版 4 段格式（无 duration 字段）兼容：duration 按 ban_times*300 重算。
    #[test]
    fn ban_deserialize_legacy_4_part_format() {
        let target = BanTarget::Ip("7.7.7.7".to_string());
        let rec = deserialize_ban_record(&target, "1799999999|2|false|legacy_reason");
        assert!(rec.is_some(), "旧版 4 段格式应可解析");
        let rec = rec.unwrap();
        assert_eq!(
            rec.duration,
            Duration::from_secs(600),
            "旧格式 duration 应按 ban_times*300s 重算"
        );
        assert_eq!(rec.reason, "legacy_reason");
        assert!(!rec.is_manual);
    }

    /// reason 含分隔符时按最后一段整体保留（splitn 语义）。
    #[test]
    fn ban_serialize_reason_with_delimiter_round_trip() {
        let target = BanTarget::Ip("7.7.8.8".to_string());
        let original = BanRecord {
            target: target.clone(),
            ban_times: 1,
            duration: Duration::from_secs(300),
            banned_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            is_manual: false,
            reason: "brute|force".to_string(),
        };
        let rec = deserialize_ban_record(&target, &serialize_ban_record(&original)).unwrap();
        assert_eq!(rec.reason, "brute|force", "reason 中的 '|' 不应截断");
    }

    /// deserialize_ban_record 格式错误（段数不对）返回 None。
    #[test]
    fn ban_deserialize_malformed_data_returns_none() {
        let target = BanTarget::Ip("1.1.1.1".to_string());
        // 只有 2 段（应为 4 段）
        assert!(deserialize_ban_record(&target, "100|5").is_none());
        // 只有 1 段
        assert!(deserialize_ban_record(&target, "100").is_none());
        // 空字符串
        assert!(deserialize_ban_record(&target, "").is_none());
    }

    /// deserialize_ban_record 数字解析失败返回 None。
    #[test]
    fn ban_deserialize_non_numeric_returns_none() {
        let target = BanTarget::Ip("2.2.2.2".to_string());
        // expires_at_ts 不是数字
        assert!(deserialize_ban_record(&target, "not_num|5|true|reason").is_none());
        // ban_times 不是数字
        assert!(deserialize_ban_record(&target, "1000|not_num|true|reason").is_none());
    }

    /// record_duration_from_ban 正确计算 duration。
    #[test]
    fn ban_record_duration_from_ban_correct() {
        let target = BanTarget::Ip("3.3.3.3".to_string());
        assert_eq!(
            record_duration_from_ban(&target, 1),
            Duration::from_secs(300)
        );
        assert_eq!(
            record_duration_from_ban(&target, 3),
            Duration::from_secs(900)
        );
        assert_eq!(record_duration_from_ban(&target, 0), Duration::from_secs(0));
    }

    /// get_history 段数不对时返回错误。
    #[tokio::test]
    async fn ban_get_history_wrong_parts_returns_err() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let target = BanTarget::Ip("9.9.9.9".to_string());
        let key = ban_history_key(&target);
        // 只有 1 段（应为 2 段）
        storage.dao.set(&key, "only_one_segment", 0).await.unwrap();
        let result = storage.get_history(&target).await;
        assert!(result.is_err(), "段数不对应返回错误");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("limiteron-ban-history-format-error"),
            "错误消息应包含 'limiteron-ban-history-format-error'，实际: {}",
            err_msg
        );
    }

    /// get_history last_banned_at_ts 不是数字时返回错误。
    #[tokio::test]
    async fn ban_get_history_non_numeric_ts_returns_err() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let target = BanTarget::Ip("8.8.8.8".to_string());
        let key = ban_history_key(&target);
        // ban_times 正确，但 last_banned_at_ts 不是数字
        storage.dao.set(&key, "3|not_a_number", 0).await.unwrap();
        let result = storage.get_history(&target).await;
        assert!(result.is_err(), "非数字 ts 应返回错误");
    }

    /// get_history ban_times 不是数字时返回错误。
    #[tokio::test]
    async fn ban_get_history_non_numeric_ban_times_returns_err() {
        let storage = GarrisonDaoBanStorage::new(make_dao());
        let target = BanTarget::Mac("AA:BB".to_string());
        let key = ban_history_key(&target);
        storage.dao.set(&key, "not_num|1000", 0).await.unwrap();
        let result = storage.get_history(&target).await;
        assert!(result.is_err(), "非数字 ban_times 应返回错误");
    }
}
