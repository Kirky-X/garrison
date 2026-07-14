//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! limiteron 适配器模块。
//!
//! 提供 4 个适配器，将 `BulwarkDao` 桥接到 limiteron 的 `Storage` / `QuotaStorage` /
//! `BanStorage` / `DistributedLimiter` trait，使 bulwark 的限速/封禁策略可以
//! 委托 limiteron 的统一抽象。
//!
//! # 适配器清单
//!
//! | 适配器 | 实现 trait | 用途 |
//! |--------|-----------|------|
//! | [`BulwarkDaoStorage`](crate::limiteron::BulwarkDaoStorage) | `Storage` | KV get/set/delete |
//! | [`BulwarkDaoQuotaStorage`](crate::limiteron::BulwarkDaoQuotaStorage) | `QuotaStorage` | 原子配额消费（SMS 限速） |
//! | [`BulwarkDaoDistributedLimiter`](crate::limiteron::BulwarkDaoDistributedLimiter) | `DistributedLimiter` | 原子计数 + TTL（滑动窗口） |
//! | [`BulwarkDaoBanStorage`](crate::limiteron::BulwarkDaoBanStorage) | `BanStorage` | 封禁记录管理（暴力破解防护） |
//!
//! # 已知限制
//!
//! - `BulwarkDao::incr` 默认实现非原子（get→parse→+1→update），`MockDao` 重写为进程内原子
//! - `QuotaStorage::consume` 通过循环 `dao.incr` 实现，cost > 1 时非原子
//! - `BanStorage::list_bans` / `cleanup_expired_bans` 无法实现（BulwarkDao 无 iter API），返回空/0

use crate::dao::BulwarkDao;
use crate::error::BulwarkError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use limiteron::error::{LimiteronError, StorageError};
use limiteron::limiters::{DistributedLimiter, Limiter};
use limiteron::storage::{
    BanHistory, BanRecord, BanStorage, BanTarget, QuotaInfo, QuotaStorage, Storage,
};
use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// 错误映射
// ============================================================================

/// 将 `BulwarkError` 映射为 `StorageError`。
fn map_to_storage_err(e: BulwarkError) -> StorageError {
    StorageError::QueryError(format!("{}", e))
}

/// 将 `BulwarkError` 映射为 `LimiteronError`。
fn map_to_limiter_err(e: BulwarkError) -> LimiteronError {
    LimiteronError::StorageError(StorageError::QueryError(format!("{}", e)))
}

// ============================================================================
// BulwarkDaoStorage — impl Storage
// ============================================================================

/// `Storage` 适配器，将 `BulwarkDao` 桥接到 limiteron `Storage` trait。
///
/// `set` 的 `ttl: None` 映射为 `dao.set(key, value, 0)`（永久驻留）。
pub struct BulwarkDaoStorage {
    /// 内部 DAO。
    dao: Arc<dyn BulwarkDao>,
}

impl BulwarkDaoStorage {
    /// 创建适配器实例。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }
}

#[async_trait]
impl Storage for BulwarkDaoStorage {
    async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.dao.get(key).await.map_err(map_to_storage_err)
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> Result<(), StorageError> {
        let ttl_secs = ttl.unwrap_or(0);
        self.dao
            .set(key, value, ttl_secs)
            .await
            .map_err(map_to_storage_err)
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.dao.delete(key).await.map_err(map_to_storage_err)
    }
}

// ============================================================================
// BulwarkDaoQuotaStorage — impl QuotaStorage
// ============================================================================

/// 配额 key 前缀。
const QUOTA_KEY_PREFIX: &str = "limiteron:quota";
/// 配额计数 key：`limiteron:quota:{user_id}:{resource}:count`，存储 u64 计数值。
fn quota_count_key(user_id: &str, resource: &str) -> String {
    format!("{}:{}:{}:count", QUOTA_KEY_PREFIX, user_id, resource)
}
/// 配额元数据 key：`limiteron:quota:{user_id}:{resource}:meta`，存储 `consumed|limit|window_start|window_end`。
fn quota_meta_key(user_id: &str, resource: &str) -> String {
    format!("{}:{}:{}:meta", QUOTA_KEY_PREFIX, user_id, resource)
}

/// `QuotaStorage` 适配器，用 `BulwarkDao::incr` 实现配额消费。
///
/// `consume` 通过循环 `dao.incr` 实现：cost=1 时单次 incr（进程内原子），
/// cost>1 时多次 incr（非原子，中间可能被其他请求插入）。
pub struct BulwarkDaoQuotaStorage {
    dao: Arc<dyn BulwarkDao>,
}

impl BulwarkDaoQuotaStorage {
    /// 创建适配器实例。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }
}

#[async_trait]
impl QuotaStorage for BulwarkDaoQuotaStorage {
    async fn get_quota(
        &self,
        user_id: &str,
        resource: &str,
    ) -> Result<Option<QuotaInfo>, StorageError> {
        let meta_key = quota_meta_key(user_id, resource);
        let count_key = quota_count_key(user_id, resource);

        let meta = self.dao.get(&meta_key).await.map_err(map_to_storage_err)?;
        let count = self.dao.get(&count_key).await.map_err(map_to_storage_err)?;

        match (meta, count) {
            (Some(meta_str), Some(count_str)) => {
                // M-3: parse 失败显性化 — 脏数据返回 Err（fail-fast）
                let consumed: u64 = count_str.parse().map_err(|e| {
                    map_to_storage_err(BulwarkError::Dao(format!(
                        "get_quota parse 失败 (count, key={}, val={}): {}",
                        count_key, count_str, e
                    )))
                })?;
                let parts: Vec<&str> = meta_str.split('|').collect();
                if parts.len() != 4 {
                    return Err(map_to_storage_err(BulwarkError::Dao(format!(
                        "get_quota meta 格式错误 (key={}, val={}): 期望 4 段, 实际 {} 段",
                        meta_key,
                        meta_str,
                        parts.len()
                    ))));
                }
                let limit: u64 = parts[1].parse().map_err(|e| {
                    map_to_storage_err(BulwarkError::Dao(format!(
                        "get_quota parse 失败 (limit, key={}, val={}): {}",
                        meta_key, parts[1], e
                    )))
                })?;
                let window_start_ts: i64 = parts[2].parse().map_err(|e| {
                    map_to_storage_err(BulwarkError::Dao(format!(
                        "get_quota parse 失败 (window_start_ts, key={}, val={}): {}",
                        meta_key, parts[2], e
                    )))
                })?;
                let window_end_ts: i64 = parts[3].parse().map_err(|e| {
                    map_to_storage_err(BulwarkError::Dao(format!(
                        "get_quota parse 失败 (window_end_ts, key={}, val={}): {}",
                        meta_key, parts[3], e
                    )))
                })?;
                let window_start =
                    DateTime::from_timestamp(window_start_ts, 0).ok_or_else(|| {
                        map_to_storage_err(BulwarkError::Dao(format!(
                            "get_quota DateTime 转换失败 (window_start_ts={})",
                            window_start_ts
                        )))
                    })?;
                let window_end = DateTime::from_timestamp(window_end_ts, 0).ok_or_else(|| {
                    map_to_storage_err(BulwarkError::Dao(format!(
                        "get_quota DateTime 转换失败 (window_end_ts={})",
                        window_end_ts
                    )))
                })?;
                Ok(Some(QuotaInfo {
                    consumed,
                    limit,
                    window_start,
                    window_end,
                }))
            },
            _ => Ok(None),
        }
    }

    async fn consume(
        &self,
        user_id: &str,
        resource: &str,
        cost: u64,
        limit: u64,
        window: Duration,
    ) -> Result<limiteron::error::ConsumeResult, StorageError> {
        let count_key = quota_count_key(user_id, resource);
        let meta_key = quota_meta_key(user_id, resource);
        let ttl = window.as_secs();

        // 循环 incr cost 次（cost=1 时单次，进程内原子）
        let mut new_count = 0u64;
        for _ in 0..cost {
            new_count = self
                .dao
                .incr(&count_key, ttl)
                .await
                .map_err(map_to_storage_err)?;
        }

        // 初始化/更新元数据（首次消费时设置窗口）
        let now = Utc::now();
        let window_end = now
            + chrono::Duration::from_std(window)
                .unwrap_or_else(|_| chrono::Duration::seconds(window.as_secs() as i64));
        let meta_val = format!(
            "{}|{}|{}|{}",
            new_count,
            limit,
            now.timestamp(),
            window_end.timestamp()
        );
        // 用 set 覆盖元数据（保留 TTL 与窗口一致）
        self.dao
            .set(&meta_key, &meta_val, ttl)
            .await
            .map_err(map_to_storage_err)?;

        let allowed = new_count <= limit;
        let remaining = limit.saturating_sub(new_count);
        let usage_percent = if limit == 0 {
            100.0
        } else {
            (new_count as f64 / limit as f64) * 100.0
        };

        Ok(limiteron::error::ConsumeResult {
            allowed,
            remaining,
            alert_triggered: usage_percent >= 80.0,
            usage_percent,
        })
    }

    async fn reset(
        &self,
        user_id: &str,
        resource: &str,
        _limit: u64,
        _window: Duration,
    ) -> Result<(), StorageError> {
        let count_key = quota_count_key(user_id, resource);
        let meta_key = quota_meta_key(user_id, resource);
        self.dao
            .delete(&count_key)
            .await
            .map_err(map_to_storage_err)?;
        self.dao.delete(&meta_key).await.map_err(map_to_storage_err)
    }
}

// ============================================================================
// BulwarkDaoDistributedLimiter — impl DistributedLimiter
// ============================================================================

/// `DistributedLimiter` 适配器，用 `BulwarkDao::incr` 实现原子计数。
///
/// `incr(key, amount)` 通过循环 `dao.incr(key, 0)` amount 次实现。
/// `incr_with_ttl(key, amount, ttl)` 通过循环 `dao.incr(key, ttl_secs)` amount 次实现。
pub struct BulwarkDaoDistributedLimiter {
    dao: Arc<dyn BulwarkDao>,
}

impl BulwarkDaoDistributedLimiter {
    /// 创建适配器实例。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }

    /// 原子 check-and-increment（Lua 脚本实现）。
    ///
    /// 原子递增计数器并检查是否超过阈值：
    /// 1. 调用 `eval_lua` 执行 INCR + EXPIRE Lua 脚本（Redis 后端原子操作）
    /// 2. 若返回计数 > 阈值，拒绝（计数已递增，TTL 后自动重置）
    /// 3. 若 `eval_lua` 返回 `NotImplemented`（非 Redis 后端），降级到 `incr` + 阈值判断
    ///
    /// # 参数
    /// - `key`: 计数器键。
    /// - `threshold`: 允许的最大计数（超过则拒绝）。
    /// - `ttl`: 计数器窗口 TTL（首次创建时设置）。
    ///
    /// # 返回
    /// - `Ok(true)`: 允许（计数 <= 阈值）。
    /// - `Ok(false)`: 拒绝（计数 > 阈值）。
    pub async fn atomic_check_and_incr(
        &self,
        key: &str,
        threshold: u64,
        ttl: Duration,
    ) -> Result<bool, LimiteronError> {
        const LUA_SCRIPT: &str = "local c=redis.call('INCR',KEYS[1]); if c==1 then redis.call('EXPIRE',KEYS[1],ARGV[2]) end; return c";
        let keys = vec![key.to_string()];
        let args = vec![threshold.to_string(), ttl.as_secs().to_string()];

        match self.dao.eval_lua(LUA_SCRIPT, keys, args).await {
            Ok(values) => {
                let count: u64 = values
                    .first()
                    .ok_or_else(|| {
                        map_to_limiter_err(BulwarkError::Dao("eval_lua 返回空结果".to_string()))
                    })?
                    .parse()
                    .map_err(|e| {
                        map_to_limiter_err(BulwarkError::Dao(format!(
                            "eval_lua 返回值解析失败: {}",
                            e
                        )))
                    })?;
                Ok(count <= threshold)
            },
            Err(BulwarkError::NotImplemented(_)) => {
                // 降级：非 Redis 后端，用 incr + 阈值判断（进程内原子）
                let count = self
                    .dao
                    .incr(key, ttl.as_secs())
                    .await
                    .map_err(map_to_limiter_err)?;
                Ok(count <= threshold)
            },
            Err(e) => Err(map_to_limiter_err(e)),
        }
    }
}

#[async_trait]
impl Limiter for BulwarkDaoDistributedLimiter {
    async fn allow(&self, cost: u64) -> Result<bool, LimiteronError> {
        // Limiter trait 的 allow 无 key 参数，用固定 key 计数
        // 真正的分布式限流通过 incr + get_count + 阈值判断实现
        self.incr("_global", cost).await?;
        Ok(true)
    }
}

#[async_trait]
impl DistributedLimiter for BulwarkDaoDistributedLimiter {
    async fn incr(&self, key: &str, amount: u64) -> Result<u64, LimiteronError> {
        let mut count = 0u64;
        for _ in 0..amount {
            count = self.dao.incr(key, 0).await.map_err(map_to_limiter_err)?;
        }
        if amount == 0 {
            count = self.get_count(key).await?;
        }
        Ok(count)
    }

    async fn incr_with_ttl(
        &self,
        key: &str,
        amount: u64,
        ttl: Duration,
    ) -> Result<u64, LimiteronError> {
        let ttl_secs = ttl.as_secs();
        let mut count = 0u64;
        for _ in 0..amount {
            count = self
                .dao
                .incr(key, ttl_secs)
                .await
                .map_err(map_to_limiter_err)?;
        }
        if amount == 0 {
            count = self.get_count(key).await?;
        }
        Ok(count)
    }

    async fn get_count(&self, key: &str) -> Result<u64, LimiteronError> {
        match self.dao.get(key).await.map_err(map_to_limiter_err)? {
            None => Ok(0),
            // M-3: parse 失败显性化 — 脏数据返回错误而非静默用 0
            Some(val) => val.parse::<u64>().map_err(|e| {
                map_to_limiter_err(BulwarkError::Dao(format!(
                    "get_count parse 失败 (key={}, val={}): {}",
                    key, val, e
                )))
            }),
        }
    }

    async fn reset(&self, key: &str) -> Result<(), LimiteronError> {
        self.dao.delete(key).await.map_err(map_to_limiter_err)
    }
}

// ============================================================================
// BulwarkDaoBanStorage — impl BanStorage
// ============================================================================

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

/// 序列化 `BanRecord` 为字符串：`expires_at_ts|ban_times|is_manual|reason`。
fn serialize_ban_record(record: &BanRecord) -> String {
    format!(
        "{}|{}|{}|{}",
        record.expires_at.timestamp(),
        record.ban_times,
        record.is_manual,
        record.reason
    )
}

/// 反序列化 `BanRecord`。
fn deserialize_ban_record(target: &BanTarget, val: &str) -> Option<BanRecord> {
    let parts: Vec<&str> = val.splitn(4, '|').collect();
    if parts.len() != 4 {
        return None;
    }
    let expires_at_ts: i64 = parts[0].parse().ok()?;
    let ban_times: u32 = parts[1].parse().ok()?;
    let is_manual = parts[2] == "true";
    let reason = parts[3].to_string();
    let expires_at = DateTime::from_timestamp(expires_at_ts, 0)?;
    let banned_at = expires_at
        - chrono::Duration::from_std(record_duration_from_ban(target, ban_times))
            .unwrap_or_else(|_| chrono::Duration::seconds(0));
    let duration = record_duration_from_ban(target, ban_times);
    Some(BanRecord {
        target: target.clone(),
        ban_times,
        duration,
        banned_at,
        expires_at,
        is_manual,
        reason,
    })
}

/// 从 ban_times 推断 duration（简化：ban_times * 300s）。
fn record_duration_from_ban(_target: &BanTarget, ban_times: u32) -> Duration {
    Duration::from_secs((ban_times as u64).saturating_mul(300))
}

/// `BanStorage` 适配器，用 `BulwarkDao` KV 存储封禁记录。
///
/// # 存储格式
/// - 封禁记录：`limiteron:ban:{type}:{value}` → `expires_at_ts|ban_times|is_manual|reason`
/// - 封禁次数：`limiteron:ban:times:{type}:{value}` → `u64`
/// - 封禁历史：`limiteron:ban:history:{type}:{value}` → `ban_times|last_banned_at_ts`
///
/// # 限制
/// `list_bans` 和 `cleanup_expired_bans` 无法实现（BulwarkDao 无 iter API），
/// `is_banned` 在查询时检查过期时间（过期返回 None）。
pub struct BulwarkDaoBanStorage {
    dao: Arc<dyn BulwarkDao>,
}

impl BulwarkDaoBanStorage {
    /// 创建适配器实例。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }
}

#[async_trait]
impl BanStorage for BulwarkDaoBanStorage {
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

    async fn save(&self, record: &BanRecord) -> Result<(), StorageError> {
        let key = ban_record_key(&record.target);
        let val = serialize_ban_record(record);
        let ttl = (record.expires_at - Utc::now()).num_seconds().max(0) as u64;
        self.dao
            .set(&key, &val, ttl)
            .await
            .map_err(map_to_storage_err)?;

        // 同步更新封禁次数和历史
        let times_key = ban_times_key(&record.target);
        self.dao
            .set(&times_key, &record.ban_times.to_string(), ttl)
            .await
            .map_err(map_to_storage_err)?;

        let history_key = ban_history_key(&record.target);
        let history_val = format!("{}|{}", record.ban_times, Utc::now().timestamp());
        self.dao
            .set(&history_key, &history_val, ttl)
            .await
            .map_err(map_to_storage_err)
    }

    async fn get_history(&self, target: &BanTarget) -> Result<Option<BanHistory>, StorageError> {
        let key = ban_history_key(target);
        match self.dao.get(&key).await.map_err(map_to_storage_err)? {
            None => Ok(None),
            Some(val) => {
                let parts: Vec<&str> = val.splitn(2, '|').collect();
                if parts.len() != 2 {
                    return Err(StorageError::QueryError(format!(
                        "get_history 格式错误 (key={}, val={}): 期望 2 段, 实际 {} 段",
                        key,
                        val,
                        parts.len()
                    )));
                }
                // M-3: parse 失败显性化 — 脏数据返回 Err（fail-fast）
                let ban_times: u32 = parts[0].parse().map_err(|e| {
                    StorageError::QueryError(format!(
                        "get_history parse 失败 (ban_times, key={}, val={}): {}",
                        key, parts[0], e
                    ))
                })?;
                let last_banned_at_ts: i64 = parts[1].parse().map_err(|e| {
                    StorageError::QueryError(format!(
                        "get_history parse 失败 (last_banned_at_ts, key={}, val={}): {}",
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
        // 用 incr 递增（默认 TTL=0，永久存储）
        self.dao.incr(&key, 0).await.map_err(map_to_storage_err)
    }

    async fn get_ban_times(&self, target: &BanTarget) -> Result<u64, StorageError> {
        let key = ban_times_key(target);
        match self.dao.get(&key).await.map_err(map_to_storage_err)? {
            None => Ok(0),
            // M-3: parse 失败显性化 — 脏数据返回错误而非静默用 0
            Some(val) => val.parse::<u64>().map_err(|e| {
                StorageError::QueryError(format!(
                    "get_ban_times parse 失败 (key={}, val={}): {}",
                    key, val, e
                ))
            }),
        }
    }

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
        // BulwarkDao 无 iter API，无法扫描过期 key
        // 封禁记录设置 TTL，过期自动删除；is_banned 查询时检查过期时间
        Ok(0)
    }

    async fn list_bans(
        &self,
        _active_only: bool,
        _offset: u64,
        _limit: u64,
    ) -> Result<Vec<BanRecord>, StorageError> {
        // BulwarkDao 无 iter API，无法列出所有 key
        Ok(Vec::new())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    fn make_dao() -> Arc<dyn BulwarkDao> {
        Arc::new(MockDao::new())
    }

    // --- BulwarkDaoStorage 测试 ---

    #[tokio::test]
    async fn storage_get_set_delete() {
        let storage = BulwarkDaoStorage::new(make_dao());

        // 初始 get 返回 None
        assert!(storage.get("key1").await.unwrap().is_none());

        // set + get
        storage.set("key1", "value1", Some(60)).await.unwrap();
        assert_eq!(
            storage.get("key1").await.unwrap(),
            Some("value1".to_string())
        );

        // delete + get
        storage.delete("key1").await.unwrap();
        assert!(storage.get("key1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn storage_set_ttl_none_is_permanent() {
        let storage = BulwarkDaoStorage::new(make_dao());
        storage.set("perm", "val", None).await.unwrap();
        assert_eq!(storage.get("perm").await.unwrap(), Some("val".to_string()));
    }

    // --- BulwarkDaoQuotaStorage 测试 ---

    #[tokio::test]
    async fn quota_consume_within_limit() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        let result = quota
            .consume("user1", "sms", 1, 5, Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.remaining, 4);
    }

    #[tokio::test]
    async fn quota_consume_exceeds_limit() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        // 消费 5 次，第 6 次超限
        for _ in 0..5 {
            let r = quota
                .consume("user2", "sms", 1, 5, Duration::from_secs(3600))
                .await
                .unwrap();
            assert!(r.allowed);
        }
        let result = quota
            .consume("user2", "sms", 1, 5, Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }

    #[tokio::test]
    async fn quota_reset_clears_counters() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        quota
            .consume("user3", "sms", 3, 10, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(quota.get_quota("user3", "sms").await.unwrap().is_some());

        quota
            .reset("user3", "sms", 10, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(quota.get_quota("user3", "sms").await.unwrap().is_none());
    }

    // --- BulwarkDaoDistributedLimiter 测试 ---

    #[tokio::test]
    async fn limiter_incr_and_get_count() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());

        let count1 = limiter.incr("test:key", 1).await.unwrap();
        assert_eq!(count1, 1);

        let count2 = limiter.incr("test:key", 1).await.unwrap();
        assert_eq!(count2, 2);

        assert_eq!(limiter.get_count("test:key").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn limiter_incr_with_ttl() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        let count = limiter
            .incr_with_ttl("ttl:key", 1, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(limiter.get_count("ttl:key").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn limiter_reset() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        limiter.incr("reset:key", 3).await.unwrap();
        assert_eq!(limiter.get_count("reset:key").await.unwrap(), 3);

        limiter.reset("reset:key").await.unwrap();
        assert_eq!(limiter.get_count("reset:key").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn limiter_get_count_nonexistent() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        assert_eq!(limiter.get_count("noexist").await.unwrap(), 0);
    }

    // --- BulwarkDaoBanStorage 测试 ---

    #[tokio::test]
    async fn ban_save_and_is_banned() {
        let storage = BulwarkDaoBanStorage::new(make_dao());
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
        let storage = BulwarkDaoBanStorage::new(make_dao());
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
        let storage = BulwarkDaoBanStorage::new(make_dao());
        let target = BanTarget::UserId("user123".to_string());

        assert_eq!(storage.get_ban_times(&target).await.unwrap(), 0);

        let t1 = storage.increment_ban_times(&target).await.unwrap();
        assert_eq!(t1, 1);

        let t2 = storage.increment_ban_times(&target).await.unwrap();
        assert_eq!(t2, 2);

        assert_eq!(storage.get_ban_times(&target).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn ban_remove() {
        let storage = BulwarkDaoBanStorage::new(make_dao());
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
        let storage = BulwarkDaoBanStorage::new(make_dao());
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
        let storage = BulwarkDaoBanStorage::new(make_dao());
        let bans = storage.list_bans(true, 0, 10).await.unwrap();
        assert!(
            bans.is_empty(),
            "list_bans 应返回空 Vec（BulwarkDao 无 iter API）"
        );
    }

    #[tokio::test]
    async fn ban_cleanup_returns_zero() {
        let storage = BulwarkDaoBanStorage::new(make_dao());
        let count = storage.cleanup_expired_bans().await.unwrap();
        assert_eq!(
            count, 0,
            "cleanup_expired_bans 应返回 0（BulwarkDao 无 iter API）"
        );
    }

    // --- M-3: unwrap_or(0) 静默吞错修复测试 ---

    /// M-3: QuotaStorage::get_quota 遇到脏 count 数据时返回错误（fail-fast）。
    #[tokio::test]
    async fn m3_quota_get_quota_dirty_count_returns_err() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        // 直接注入脏数据：count 是非数字字符串
        quota
            .dao
            .set("limiteron:quota:user1:res:count", "not-a-number", 0)
            .await
            .unwrap();
        quota
            .dao
            .set("limiteron:quota:user1:res:meta", "1|5|1000|2000", 0)
            .await
            .unwrap();
        let result = quota.get_quota("user1", "res").await;
        assert!(
            result.is_err(),
            "脏 count 数据应返回错误，实际: {:?}",
            result
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("parse 失败"),
            "错误消息应包含 'parse 失败'，实际: {}",
            err_msg
        );
    }

    /// M-3: QuotaStorage::get_quota 遇到脏 meta 数据时返回错误（fail-fast）。
    #[tokio::test]
    async fn m3_quota_get_quota_dirty_meta_returns_err() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        quota
            .dao
            .set("limiteron:quota:user2:res:count", "1", 0)
            .await
            .unwrap();
        // meta 中 limit 字段是非数字
        quota
            .dao
            .set(
                "limiteron:quota:user2:res:meta",
                "1|not-number|1000|2000",
                0,
            )
            .await
            .unwrap();
        let result = quota.get_quota("user2", "res").await;
        assert!(
            result.is_err(),
            "脏 meta 数据应返回错误，实际: {:?}",
            result
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("parse 失败"),
            "错误消息应包含 'parse 失败'，实际: {}",
            err_msg
        );
    }

    /// M-3: DistributedLimiter::get_count 遇到脏数据时返回错误（非静默用 0）。
    #[tokio::test]
    async fn m3_limiter_get_count_dirty_data_returns_err() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        limiter
            .dao
            .set("dirty-count-key", "not-a-number", 0)
            .await
            .unwrap();
        let result = limiter.get_count("dirty-count-key").await;
        assert!(result.is_err(), "脏数据应返回错误，实际: {:?}", result);
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("parse 失败"),
            "错误消息应包含 'parse 失败'，实际: {}",
            err_msg
        );
    }

    /// M-3: BanStorage::get_ban_times 遇到脏数据时返回错误（非静默用 0）。
    #[tokio::test]
    async fn m3_ban_get_ban_times_dirty_data_returns_err() {
        let storage = BulwarkDaoBanStorage::new(make_dao());
        let target = BanTarget::Ip("1.2.3.4".to_string());
        // 直接注入脏数据
        let key = ban_times_key(&target);
        storage.dao.set(&key, "not-a-number", 0).await.unwrap();
        let result = storage.get_ban_times(&target).await;
        assert!(result.is_err(), "脏数据应返回错误，实际: {:?}", result);
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("parse 失败"),
            "错误消息应包含 'parse 失败'，实际: {}",
            err_msg
        );
    }

    /// M-3: BanStorage::get_history 遇到脏数据时返回错误（fail-fast）。
    #[tokio::test]
    async fn m3_ban_get_history_dirty_data_returns_err() {
        let storage = BulwarkDaoBanStorage::new(make_dao());
        let target = BanTarget::Ip("5.6.7.8".to_string());
        let key = ban_history_key(&target);
        // ban_times 字段是非数字
        storage.dao.set(&key, "not-number|1000", 0).await.unwrap();
        let result = storage.get_history(&target).await;
        assert!(result.is_err(), "脏数据应返回错误，实际: {:?}", result);
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("parse 失败"),
            "错误消息应包含 'parse 失败'，实际: {}",
            err_msg
        );
    }

    // ------------------------------------------------------------------------
    // T010: Redis Lua 脚本原子化限速（check-and-increment）测试
    // ------------------------------------------------------------------------

    /// T010: 并发 100 次 atomic_check_and_incr（阈值 10）结果精确为 10 通过 + 90 拒绝。
    ///
    /// 验证 BulwarkDaoDistributedLimiter::atomic_check_and_incr 通过 eval_lua 实现
    /// 原子 check-and-increment：100 个并发任务同时调用，仅前 10 个通过（count <= 10），
    /// 后 90 个被拒绝（count > 10）。
    #[tokio::test(flavor = "multi_thread")]
    async fn t010_atomic_check_and_incr_concurrent_threshold() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let dao = Arc::new(MockDao::new());
        let limiter = Arc::new(BulwarkDaoDistributedLimiter::new(
            dao as Arc<dyn BulwarkDao>,
        ));

        let key = "rate_limit:t010:concurrent";
        let threshold = 10u64;
        let ttl = Duration::from_secs(60);

        let allowed = Arc::new(AtomicU64::new(0));
        let rejected = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for _ in 0..100 {
            let l = limiter.clone();
            let a = allowed.clone();
            let r = rejected.clone();
            handles.push(tokio::spawn(async move {
                let ok = l
                    .atomic_check_and_incr(key, threshold, ttl)
                    .await
                    .expect("atomic_check_and_incr 不应失败");
                if ok {
                    a.fetch_add(1, Ordering::SeqCst);
                } else {
                    r.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for handle in handles {
            handle.await.expect("task panicked");
        }

        assert_eq!(
            allowed.load(Ordering::SeqCst),
            10,
            "应精确 10 次通过，实际: {}",
            allowed.load(Ordering::SeqCst)
        );
        assert_eq!(
            rejected.load(Ordering::SeqCst),
            90,
            "应精确 90 次拒绝，实际: {}",
            rejected.load(Ordering::SeqCst)
        );
    }

    /// T010: 单线程连续 5 次 atomic_check_and_incr（阈值 3）— 前 3 通过，后 2 拒绝。
    #[tokio::test]
    async fn t010_atomic_check_and_incr_sequential_threshold() {
        let dao = Arc::new(MockDao::new());
        let limiter = BulwarkDaoDistributedLimiter::new(dao as Arc<dyn BulwarkDao>);

        let key = "rate_limit:t010:seq";
        let threshold = 3u64;
        let ttl = Duration::from_secs(60);

        assert!(limiter
            .atomic_check_and_incr(key, threshold, ttl)
            .await
            .unwrap());
        assert!(limiter
            .atomic_check_and_incr(key, threshold, ttl)
            .await
            .unwrap());
        assert!(limiter
            .atomic_check_and_incr(key, threshold, ttl)
            .await
            .unwrap());
        assert!(!limiter
            .atomic_check_and_incr(key, threshold, ttl)
            .await
            .unwrap());
        assert!(!limiter
            .atomic_check_and_incr(key, threshold, ttl)
            .await
            .unwrap());
    }

    /// T010: eval_lua 默认实现返回 NotImplemented（BulwarkDaoOxcache 不支持 Lua）。
    ///
    /// 验证 trait 默认实现：未重写 eval_lua 的实现者调用时返回 NotImplemented。
    #[tokio::test]
    async fn t010_eval_lua_default_returns_not_implemented() {
        use crate::dao::tests::MinimalDao;

        let dao = MinimalDao::new();
        let result = dao
            .eval_lua(
                "return 'test'",
                vec!["k1".to_string()],
                vec!["a1".to_string()],
            )
            .await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(_))),
            "eval_lua 默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    // ------------------------------------------------------------------------
    // 补充覆盖：quota / limiter / ban 辅助函数与边界路径
    // ------------------------------------------------------------------------

    /// quota_count_key 与 quota_meta_key 生成正确的 key 格式。
    #[test]
    fn quota_key_format_correct() {
        assert_eq!(
            quota_count_key("user1", "sms"),
            "limiteron:quota:user1:sms:count"
        );
        assert_eq!(
            quota_meta_key("user1", "sms"),
            "limiteron:quota:user1:sms:meta"
        );
        assert_eq!(quota_count_key("", ""), "limiteron:quota:::count");
    }

    /// get_quota 在 consume 后返回正确的 QuotaInfo（round-trip）。
    #[tokio::test]
    async fn quota_get_quota_after_consume_returns_valid_info() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        quota
            .consume("user_rt", "res", 1, 10, Duration::from_secs(3600))
            .await
            .unwrap();
        let info = quota.get_quota("user_rt", "res").await.unwrap();
        assert!(info.is_some(), "consume 后 get_quota 应返回 Some");
        let info = info.unwrap();
        assert_eq!(info.consumed, 1);
        assert_eq!(info.limit, 10);
    }

    /// consume cost > 1 时正确递增计数。
    #[tokio::test]
    async fn quota_consume_cost_greater_than_one() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        let result = quota
            .consume("user_cost", "res", 5, 10, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(result.allowed, "5 <= 10 应允许");
        assert_eq!(result.remaining, 5, "remaining = 10 - 5 = 5");
        assert!(
            result.usage_percent >= 50.0,
            "usage_percent 应 >= 50%，实际: {}",
            result.usage_percent
        );
    }

    /// consume 在 limit=0 时 usage_percent 为 100%。
    #[tokio::test]
    async fn quota_consume_limit_zero_usage_100_percent() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        let result = quota
            .consume("user_zero", "res", 1, 0, Duration::from_secs(60))
            .await
            .unwrap();
        // limit=0, count=1 > 0 → 不允许
        assert!(!result.allowed, "count 1 > limit 0 应拒绝");
        assert_eq!(result.remaining, 0);
        assert_eq!(
            result.usage_percent, 100.0,
            "limit=0 时 usage_percent 应为 100%"
        );
    }

    /// consume 在使用率达到 80% 时触发 alert_triggered。
    #[tokio::test]
    async fn quota_consume_alert_triggered_at_80_percent() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        // 消费 8 次（limit=10），usage=80%，应触发 alert
        let result = quota
            .consume("user_alert", "res", 8, 10, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(
            result.alert_triggered,
            "usage 80% 应触发 alert，实际 usage_percent: {}",
            result.usage_percent
        );
        assert!(result.usage_percent >= 80.0);
    }

    /// consume 在使用率低于 80% 时不触发 alert。
    #[tokio::test]
    async fn quota_consume_no_alert_below_80_percent() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        let result = quota
            .consume("user_noalert", "res", 7, 10, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(
            !result.alert_triggered,
            "usage 70% 不应触发 alert，实际 usage_percent: {}",
            result.usage_percent
        );
    }

    /// get_quota meta 格式错误（段数不对）返回错误。
    #[tokio::test]
    async fn quota_get_quota_meta_wrong_parts_returns_err() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        // 注入 count 正确但 meta 段数不对的数据
        quota
            .dao
            .set("limiteron:quota:user_w:res:count", "1", 0)
            .await
            .unwrap();
        // meta 只有 2 段（应为 4 段）
        quota
            .dao
            .set("limiteron:quota:user_w:res:meta", "1|5", 0)
            .await
            .unwrap();
        let result = quota.get_quota("user_w", "res").await;
        assert!(result.is_err(), "meta 段数不对应返回错误");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("格式错误"),
            "错误消息应包含 '格式错误'，实际: {}",
            err_msg
        );
    }

    /// get_quota window_start_ts 无效时返回错误。
    #[tokio::test]
    async fn quota_get_quota_invalid_window_start_ts_returns_err() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        quota
            .dao
            .set("limiteron:quota:user_ts:res:count", "1", 0)
            .await
            .unwrap();
        // window_start_ts 不是数字
        quota
            .dao
            .set("limiteron:quota:user_ts:res:meta", "1|5|not_number|2000", 0)
            .await
            .unwrap();
        let result = quota.get_quota("user_ts", "res").await;
        assert!(result.is_err(), "无效 window_start_ts 应返回错误");
    }

    /// get_quota 仅 count 存在但 meta 缺失时返回 None。
    #[tokio::test]
    async fn quota_get_quota_count_without_meta_returns_none() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        // 只有 count 没有 meta
        quota
            .dao
            .set("limiteron:quota:user_nm:res:count", "5", 0)
            .await
            .unwrap();
        let result = quota.get_quota("user_nm", "res").await.unwrap();
        assert!(result.is_none(), "count 有但 meta 缺失时应返回 None");
    }

    /// Limiter::allow 始终返回 Ok(true)（全局计数器递增但不拒绝）。
    #[tokio::test]
    async fn limiter_allow_returns_true() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        let result = limiter.allow(3).await;
        assert!(result.is_ok(), "allow 应返回 Ok");
        assert!(result.unwrap(), "allow 应返回 true");
        // 验证全局计数器已递增
        assert!(
            limiter.get_count("_global").await.unwrap() >= 3,
            "_global 计数器应 >= 3"
        );
    }

    /// incr amount=0 时返回当前 count（不递增）。
    #[tokio::test]
    async fn limiter_incr_zero_amount_returns_current_count() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        // 先递增到 3
        limiter.incr("zero_key", 3).await.unwrap();
        // amount=0 应返回当前值 3
        let count = limiter.incr("zero_key", 0).await.unwrap();
        assert_eq!(count, 3, "amount=0 应返回当前 count 而不递增");
    }

    /// incr_with_ttl amount=0 时返回当前 count。
    #[tokio::test]
    async fn limiter_incr_with_ttl_zero_amount_returns_current_count() {
        let limiter = BulwarkDaoDistributedLimiter::new(make_dao());
        limiter
            .incr_with_ttl("ttl_zero_key", 2, Duration::from_secs(60))
            .await
            .unwrap();
        let count = limiter
            .incr_with_ttl("ttl_zero_key", 0, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(count, 2, "amount=0 应返回当前 count");
    }

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

    /// serialize_ban_record / deserialize_ban_record round-trip 正确。
    #[tokio::test]
    async fn ban_serialize_deserialize_round_trip() {
        let target = BanTarget::UserId("round_trip_user".to_string());
        let original = BanRecord {
            target: target.clone(),
            ban_times: 3,
            duration: Duration::from_secs(900),
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
        assert_eq!(deserialized.is_manual, true);
        assert_eq!(deserialized.reason, "test_reason");
        assert_eq!(deserialized.target, target);
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
        let storage = BulwarkDaoBanStorage::new(make_dao());
        let target = BanTarget::Ip("9.9.9.9".to_string());
        let key = ban_history_key(&target);
        // 只有 1 段（应为 2 段）
        storage.dao.set(&key, "only_one_segment", 0).await.unwrap();
        let result = storage.get_history(&target).await;
        assert!(result.is_err(), "段数不对应返回错误");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("格式错误"),
            "错误消息应包含 '格式错误'，实际: {}",
            err_msg
        );
    }

    /// get_history last_banned_at_ts 不是数字时返回错误。
    #[tokio::test]
    async fn ban_get_history_non_numeric_ts_returns_err() {
        let storage = BulwarkDaoBanStorage::new(make_dao());
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
        let storage = BulwarkDaoBanStorage::new(make_dao());
        let target = BanTarget::Mac("AA:BB".to_string());
        let key = ban_history_key(&target);
        storage.dao.set(&key, "not_num|1000", 0).await.unwrap();
        let result = storage.get_history(&target).await;
        assert!(result.is_err(), "非数字 ban_times 应返回错误");
    }

    /// map_to_storage_err 和 map_to_limiter_err 正确映射错误。
    #[test]
    fn error_mapping_functions_correct() {
        let err1 = BulwarkError::Dao("test error".to_string());
        let storage_err = map_to_storage_err(err1);
        let storage_msg = format!("{}", storage_err);
        assert!(storage_msg.contains("test error"));

        let err2 = BulwarkError::Dao("test error".to_string());
        let limiter_err = map_to_limiter_err(err2);
        let limiter_msg = format!("{}", limiter_err);
        assert!(limiter_msg.contains("test error"));
    }

    /// atomic_check_and_incr 在 eval_lua 成功时正确判断阈值。
    ///
    /// MockDao 支持 eval_lua（返回 INCR 结果），验证成功路径。
    #[tokio::test]
    async fn atomic_check_and_incr_eval_lua_success_path() {
        let dao = Arc::new(MockDao::new());
        let limiter = BulwarkDaoDistributedLimiter::new(dao as Arc<dyn BulwarkDao>);

        // 阈值 5，首次 INCR 返回 1 <= 5 → 允许
        let ok = limiter
            .atomic_check_and_incr("lua_key", 5, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(ok, "count 1 <= 5 应允许");

        // 继续递增到 6 > 5 → 拒绝
        for _ in 0..5 {
            limiter
                .atomic_check_and_incr("lua_key", 5, Duration::from_secs(60))
                .await
                .unwrap();
        }
        let blocked = limiter
            .atomic_check_and_incr("lua_key", 5, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(!blocked, "count 7 > 5 应拒绝");
    }
}
