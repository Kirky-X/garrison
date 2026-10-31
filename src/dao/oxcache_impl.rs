// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! GarrisonDaoOxcache 实现。

use super::GarrisonDao;
#[cfg(feature = "cache-redis")]
use super::RedisConfig;
#[cfg(feature = "tenant-isolation")]
use crate::constants::DaoKeyPrefix;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use oxcache::Cache;
use std::time::Duration;

/// 根据租户上下文返回实际存储 key（[`strip_prefix`] 的逆操作）：
/// `tenant-isolation` 启用且有 `TENANT` 上下文时返回 `tenant:{id}:{key}`，否则原样返回（不 panic）。
fn prefixed_key(key: &str) -> String {
    #[cfg(feature = "tenant-isolation")]
    {
        if let Ok(ctx) = crate::context::tenant::TENANT.try_get() {
            return format!("{}{}:{}", DaoKeyPrefix::Tenant, ctx.tenant_id, key);
        }
    }
    #[allow(unused_variables)]
    let _ = key;
    key.to_string()
}

/// 通配符匹配（`*` 任意字符序列 / `?` 单字符），委托 [`crate::dao::in_memory::glob_match`]
///（单一事实来源，O(n+m) 双指针算法）与 `InMemoryDao::keys`、Redis `KEYS` 语义一致。
///
/// # Feature gate
/// 使用 `dao-key-index`（由 `protocol-apikey` / `anomalous-detector-dual` 传递），
/// 而非更严格的 `anomalous-detector-dual`，确保只启用 `protocol-apikey` 时 `keys()` 仍可用。
#[cfg(feature = "dao-key-index")]
fn matches_pattern(key: &str, pattern: &str) -> bool {
    super::in_memory::glob_match(pattern, key)
}

/// 去除 `tenant:{id}:` 前缀返回原始 key（[`prefixed_key`] 的逆操作，无前缀时原样返回）；同样 `dao-key-index` 门控。
#[cfg(feature = "dao-key-index")]
fn strip_prefix(prefixed: &str) -> String {
    #[cfg(feature = "tenant-isolation")]
    {
        // 格式 "tenant:{id}:{key}"，取第二个 ':' 之后的内容
        if let Some(rest) = prefixed.strip_prefix("tenant:") {
            if let Some(pos) = rest.find(':') {
                return rest[pos + 1..].to_string();
            }
        }
    }
    // 无前缀（tenant-isolation 关闭或无 TENANT 上下文）时原样返回
    prefixed.to_string()
}

/// oxcache 缓存 DAO：包装 `oxcache::Cache<String, String>`，L1 内存 + L2 Redis 均由 oxcache 管理，无自有缓存逻辑。
///
/// 启用 `sync_mode(true)` 使用 `_sync` API：in-memory 后端读 <100ns、写 <1μs，快于 `spawn_blocking`（~10-50μs）；
/// 需 multi_thread tokio runtime，且 Redis L2 网络 I/O 会阻塞 worker——`check_redis_compat` 据此拒绝 `_sync` 原子方法。
/// TTL 保留：`update` 用 `ttl_sync` + `set_with_ttl_sync`，`expire` 用 `expire_sync`；`ttl_sync` 依赖本地 oxcache 仓库（crates.io 0.3.0 未暴露）。
pub struct GarrisonDaoOxcache {
    /// 原子操作互斥锁：串行化 `set_if_absent` / `get_and_delete` / `incr` 等（跨**所有 key** 的单把全局锁）。
    ///
    /// 用 `parking_lot::Mutex` + `_sync` API（锁内全同步 <1μs，不让出 tokio task），不用 `tokio::sync::Mutex`（跨 await 持锁）。
    /// 字段按访问频率降序排列以优先命中 L1 Cache Line；目标十万级 QPS 前应改按 key hash 分片锁（16-64 shard）。
    atomic_mutex: parking_lot::Mutex<()>,
    /// key 索引（oxcache 0.3.3 无原生 keys/iter API），仅 `dao-key-index` 启用时维护；
    /// 过期项在 `keys()` 调用时惰性清理。
    #[cfg(feature = "dao-key-index")]
    key_index: parking_lot::RwLock<std::collections::HashSet<String>>,
    /// 缓存后端（oxcache L1 内存 + L2 Redis）。
    cache: Cache<String, String>,
    /// Redis 部署模式配置（`cache-redis` 门控），经 [`with_redis_config`] 设置；未设置时 `None`（用 oxcache 默认配置）。
    #[cfg(feature = "cache-redis")]
    redis_config: Option<RedisConfig>,
}

impl GarrisonDaoOxcache {
    /// 创建默认的 oxcache DAO 实例（启用 `sync_mode(true)` 以支持 `_sync` API）。
    ///
    /// 错误：oxcache 初始化失败返回 `GarrisonError::Dao`。
    pub async fn new() -> GarrisonResult<Self> {
        // 钉定 TTL 精确语义（ttl_jitter(0.0)）：oxcache rc.6 起 builder 默认 ±10% 抖动，
        // 而 DAO 层要求 TTL 精确（conformance 断言 get_with_ttl ≤ 请求值；限流/锁定窗口提前过期会放宽限制）。抖动仅三层缓存 L1 显式启用。
        let builder = Cache::builder().sync_mode(true).ttl_jitter(0.0);
        // cache-audit：缓存操作审计事件（hit/miss/set/delete/evict/expired，键名自动脱敏）
        // 经 TracingAuditPublisher 桥接 tracing（→ inklog / metrics-prometheus 采集链）
        #[cfg(feature = "cache-audit")]
        let builder = builder.audit_publisher(std::sync::Arc::new(
            oxcache::features::TracingAuditPublisher,
        ));
        let cache = builder
            .build()
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-init::{}", e)))?;
        Ok(Self {
            atomic_mutex: parking_lot::Mutex::new(()),
            #[cfg(feature = "dao-key-index")]
            key_index: parking_lot::RwLock::new(std::collections::HashSet::new()),
            cache,
            #[cfg(feature = "cache-redis")]
            redis_config: None,
        })
    }

    /// 设置 Redis 部署模式配置（`cache-redis` 门控，builder：消费 self 返回新实例）；未调用时保持 oxcache 默认配置。
    #[cfg(feature = "cache-redis")]
    pub fn with_redis_config(mut self, config: RedisConfig) -> Self {
        // 默认地址（127.0.0.1:6379）仅在缺配时出现——一次性 warn 显性化降级路径
        config.warn_default_once();
        // M4 防护：_sync API 仅兼容 in-memory 后端，Redis L2 网络 I/O 会阻塞 tokio worker；
        // 当前仅存储配置不实际添加后端，故此处 warn 并在原子方法入口经 check_redis_compat 拒绝。
        tracing::warn!(
            mode = %config.mode,
            db = config.db,
            "Redis config stored, but the _sync API (set_if_absent/incr/decr/get_and_delete) is incompatible with the Redis L2 backend; \
             atomic operation methods will return Err(Config) when called until migrated to the async API"
        );
        self.redis_config = Some(config);
        self
    }

    /// `cache-redis` 且已设置 `redis_config` 时返回 `Err(Config)`：`_sync` 原子方法只兼容
    /// in-memory 后端（Redis L2 网络 I/O 会阻塞 tokio worker），失败显性化而非静默阻塞。
    #[cfg(feature = "cache-redis")]
    fn check_redis_compat(&self) -> GarrisonResult<()> {
        if self.redis_config.is_some() {
            return Err(GarrisonError::Config(
                "dao-oxcache-sync-api-incompatible-with-redis::".to_string(),
            ));
        }
        Ok(())
    }

    /// 返回当前 Redis 配置（测试与诊断用：确认 `with_redis_config` 是否已调用）。
    #[cfg(feature = "cache-redis")]
    pub fn redis_config(&self) -> Option<&RedisConfig> {
        self.redis_config.as_ref()
    }
}

#[async_trait]
impl GarrisonDao for GarrisonDaoOxcache {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        let actual_key = prefixed_key(key);
        self.cache
            .get_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-get-sync::{}", e)))
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
        let actual_key = prefixed_key(key);
        let ttl = if ttl_seconds == 0 {
            None
        } else {
            Some(Duration::from_secs(ttl_seconds))
        };
        self.cache
            .set_with_ttl_sync(&actual_key, &value.to_string(), ttl)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-set-with-ttl-sync::{}", e)))?;
        #[cfg(feature = "dao-key-index")]
        self.key_index.write().insert(actual_key);
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        // 进程内原子：将 ttl_sync → set_with_ttl_sync 置于 atomic_mutex 临界区，
        // 避免并发 update / expire 之间的 TOCTOU。
        let _guard = self.atomic_mutex.lock();
        let actual_key = prefixed_key(key);
        // ttl_sync 返回 None 既可能是“永久键”也可能是“键已消失”，需 exists_sync 二次甄别。
        let remaining_ttl = self
            .cache
            .ttl_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-ttl-sync::{}", e)))?;
        let remaining_ttl =
            match remaining_ttl {
                Some(ttl) => Some(ttl),
                None => {
                    if !self.cache.exists_sync(&actual_key).map_err(|e| {
                        GarrisonError::Dao(format!("dao-oxcache-exists-sync::{}", e))
                    })? {
                        // 键已消失（过期瞬间 / 被删除）→ 报 missing，绝不写入永久值
                        return Err(GarrisonError::Dao(format!("dao-key-missing::{}", key)));
                    }
                    None // 永久键，保留
                },
            };
        self.cache
            .set_with_ttl_sync(&actual_key, &value.to_string(), remaining_ttl)
            .map_err(|e| {
                GarrisonError::Dao(format!("dao-oxcache-update-set-with-ttl-sync::{}", e))
            })?;
        // key_index 维护：update 只写 cache 不写索引会使 keys() 漏报该 key
        #[cfg(feature = "dao-key-index")]
        self.key_index.write().insert(actual_key);
        Ok(())
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        // oxcache 的 Cache<K,V> 暴露了 expire_sync(key, ttl) 方法（原子更新 TTL，不触碰 value）。
        // expire_sync 返回 bool：true=更新成功，false=键不存在。
        // 注意：seconds=0 表示永久驻留，需要用 get_sync + set_with_ttl_sync(None) 实现
        // （cache.expire_sync(key, Duration::from_secs(0)) 会让键立即过期，不符合 spec 的 0=永久语义）。
        let actual_key = prefixed_key(key);
        if seconds == 0 {
            let value = self
                .cache
                .get_sync(&actual_key)
                .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-get-sync::{}", e)))?
                .ok_or_else(|| GarrisonError::Dao(format!("dao-key-missing::{}", key)))?;
            self.cache
                .set_with_ttl_sync(&actual_key, &value, None)
                .map_err(|e| {
                    GarrisonError::Dao(format!("dao-oxcache-expire-set-with-ttl-sync::{}", e))
                })
        } else {
            let updated = self
                .cache
                .expire_sync(&actual_key, Duration::from_secs(seconds))
                .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-expire-sync::{}", e)))?;
            if !updated {
                return Err(GarrisonError::Dao(format!("dao-key-missing::{}", key)));
            }
            Ok(())
        }
    }

    /// 删除 key（`delete_sync`）并同步清理 `key_index` 条目。
    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        let actual_key = prefixed_key(key);
        self.cache
            .delete_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-delete-sync::{}", e)))?;
        #[cfg(feature = "dao-key-index")]
        self.key_index.write().remove(&actual_key);
        Ok(())
    }

    /// 用 `set_with_ttl_sync(None)` 写入永久键（oxcache 原生无 TTL API，避免 ttl=0 歧义）。
    async fn set_permanent(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let actual_key = prefixed_key(key);
        self.cache
            .set_with_ttl_sync(&actual_key, &value.to_string(), None)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-set-with-ttl-sync::{}", e)))?;
        #[cfg(feature = "dao-key-index")]
        self.key_index.write().insert(actual_key);
        Ok(())
    }

    /// 用 `ttl_sync` 查询剩余 TTL：`Some(remaining)` 有 TTL，`None` 不存在或为永久键。
    async fn get_timeout(&self, key: &str) -> GarrisonResult<Option<Duration>> {
        let actual_key = prefixed_key(key);
        self.cache
            .ttl_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-ttl-sync::{}", e)))
    }

    /// get → ttl_sync → set_with_ttl_sync → delete 四步，整体置于 `atomic_mutex` 临界区并保留原键 TTL；
    /// `ttl_sync` 返回 None 时用 `exists_sync` 甄别永久键 / 已消失键（后者返回 `InvalidParam("dao-key-missing")` 而非写入永久值）；
    /// 同步迁移 `key_index`（移除旧键、插入新键）。
    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
        let _guard = self.atomic_mutex.lock();
        let actual_old = prefixed_key(old_key);
        let actual_new = prefixed_key(new_key);
        let value = self
            .cache
            .get_sync(&actual_old)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-get-sync::{}", e)))?
            .ok_or_else(|| GarrisonError::InvalidParam(format!("dao-key-missing::{}", old_key)))?;
        let remaining_ttl = self
            .cache
            .ttl_sync(&actual_old)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-ttl-sync::{}", e)))?;
        let remaining_ttl =
            match remaining_ttl {
                Some(ttl) => Some(ttl),
                None => {
                    if !self.cache.exists_sync(&actual_old).map_err(|e| {
                        GarrisonError::Dao(format!("dao-oxcache-exists-sync::{}", e))
                    })? {
                        return Err(GarrisonError::InvalidParam(format!(
                            "dao-key-missing::{}",
                            old_key
                        )));
                    }
                    None
                },
            };
        self.cache
            .set_with_ttl_sync(&actual_new, &value, remaining_ttl)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-set-with-ttl-sync::{}", e)))?;
        self.cache
            .delete_sync(&actual_old)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-delete-sync::{}", e)))?;
        #[cfg(feature = "dao-key-index")]
        {
            let mut index = self.key_index.write();
            index.remove(&actual_old);
            index.insert(actual_new);
        }
        Ok(())
    }

    /// `parking_lot::Mutex` + `_sync` API 保护 get+delete（进程内原子：并发同 key 仅一个返回 `Some`），
    /// 删除成功时清理 `key_index`；跨进程共享 Redis L2 仍存在 TOCTOU（待引入后端后用 Lua GET+DEL 修复）。
    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
        #[cfg(feature = "cache-redis")]
        self.check_redis_compat()?;
        let _guard = self.atomic_mutex.lock();
        let actual_key = prefixed_key(key);
        let value = self
            .cache
            .get_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-get-sync::{}", e)))?;
        if value.is_some() {
            self.cache
                .delete_sync(&actual_key)
                .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-delete-sync::{}", e)))?;
            #[cfg(feature = "dao-key-index")]
            self.key_index.write().remove(&actual_key);
        }
        Ok(value)
    }

    /// `parking_lot::Mutex` + `_sync` API 保护（进程内原子）：锁内 `exists_sync` 检查 + `set_with_ttl_sync` 写入；
    /// `_sync` 直操作底层 HashMap（绕过 Moka channel 延迟）。跨进程共享 Redis L2 仍有 TOCTOU（待 Redis `SET NX EX` 修复）。
    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        #[cfg(feature = "cache-redis")]
        self.check_redis_compat()?;
        let _guard = self.atomic_mutex.lock();
        let actual_key = prefixed_key(key);

        if self
            .cache
            .exists_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-exists-sync::{}", e)))?
        {
            return Ok(false);
        }

        let ttl = if ttl_seconds == 0 {
            None
        } else {
            Some(Duration::from_secs(ttl_seconds))
        };
        self.cache
            .set_with_ttl_sync(&actual_key, &value.to_string(), ttl)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-set-with-ttl-sync::{}", e)))?;
        #[cfg(feature = "dao-key-index")]
        self.key_index.write().insert(actual_key);
        Ok(true)
    }

    /// `parking_lot::Mutex` + `_sync` API 保护（进程内原子）：锁内 `get_sync` → 递增 → 写回，新键初始化为 1；
    /// 已存在键用 `ttl_sync` 保留剩余 TTL。跨进程共享 Redis L2 仍有 TOCTOU（待 Redis `INCR` 修复）。
    async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64> {
        #[cfg(feature = "cache-redis")]
        self.check_redis_compat()?;
        let _guard = self.atomic_mutex.lock();
        let actual_key = prefixed_key(key);

        match self
            .cache
            .get_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-get-sync::{}", e)))?
        {
            Some(v) => {
                // parse 失败必须显式报错，禁止静默返回 0 导致计数器重置
                let cur_val: u64 = v.parse().map_err(|_| {
                    GarrisonError::Dao(format!("dao-incr-parse-u64::{}::{}", actual_key, v))
                })?;
                let new_val = cur_val.checked_add(1).ok_or_else(|| {
                    GarrisonError::Dao(format!("counter-overflow::{}", actual_key))
                })?;
                let remaining_ttl = self
                    .cache
                    .ttl_sync(&actual_key)
                    .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-ttl-sync::{}", e)))?;
                self.cache
                    .set_with_ttl_sync(&actual_key, &new_val.to_string(), remaining_ttl)
                    .map_err(|e| {
                        GarrisonError::Dao(format!("dao-oxcache-set-with-ttl-sync::{}", e))
                    })?;
                Ok(new_val)
            },
            None => {
                let ttl = if ttl_seconds == 0 {
                    None
                } else {
                    Some(Duration::from_secs(ttl_seconds))
                };
                self.cache
                    .set_with_ttl_sync(&actual_key, &"1".to_string(), ttl)
                    .map_err(|e| {
                        GarrisonError::Dao(format!("dao-oxcache-set-with-ttl-sync::{}", e))
                    })?;
                // key_index 维护：incr 新建 key 时插入索引，否则 keys() 漏报该 key
                #[cfg(feature = "dao-key-index")]
                self.key_index.write().insert(actual_key);
                Ok(1)
            },
        }
    }

    /// `parking_lot::Mutex` + `_sync` API 保护（进程内原子，与 `incr` 对称）：不存在/值为 0 返回 0；
    /// 递减到 0 删除 key，> 0 用 `ttl_sync` 保留原 TTL。跨进程共享 Redis L2 仍有 TOCTOU（待 Redis `DECR` 修复）。
    async fn decr(&self, key: &str) -> GarrisonResult<u64> {
        #[cfg(feature = "cache-redis")]
        self.check_redis_compat()?;
        let _guard = self.atomic_mutex.lock();
        let actual_key = prefixed_key(key);

        match self
            .cache
            .get_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-get-sync::{}", e)))?
        {
            Some(v) => {
                // parse 失败必须显式报错（与 incr 一致，禁止静默返回 0）
                let cur_val: u64 = v.parse().map_err(|_| {
                    GarrisonError::Dao(format!("dao-decr-parse-u64::{}::{}", actual_key, v))
                })?;
                if cur_val == 0 {
                    return Ok(0);
                }
                let new_val = cur_val - 1;
                if new_val == 0 {
                    self.cache.delete_sync(&actual_key).map_err(|e| {
                        GarrisonError::Dao(format!("dao-oxcache-delete-sync::{}", e))
                    })?;
                    #[cfg(feature = "dao-key-index")]
                    self.key_index.write().remove(&actual_key);
                } else {
                    let remaining_ttl = self
                        .cache
                        .ttl_sync(&actual_key)
                        .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-ttl-sync::{}", e)))?;
                    self.cache
                        .set_with_ttl_sync(&actual_key, &new_val.to_string(), remaining_ttl)
                        .map_err(|e| {
                            GarrisonError::Dao(format!("dao-oxcache-set-with-ttl-sync::{}", e))
                        })?;
                }
                Ok(new_val)
            },
            None => Ok(0),
        }
    }

    /// `parking_lot::Mutex` + `_sync` API 保护（进程内原子）：不存在视 0，`new_value > current` 时写入
    ///（已存在保留剩余 TTL）；用于 HTTP Digest nc 单调性校验（RFC 7616 §3.4.6）。跨进程共享 Redis L2 仍有 TOCTOU（待 Lua 修复）。
    async fn compare_and_update_if_greater(
        &self,
        key: &str,
        new_value: u64,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        #[cfg(feature = "cache-redis")]
        self.check_redis_compat()?;
        let _guard = self.atomic_mutex.lock();
        let actual_key = prefixed_key(key);

        let current_val: u64 = match self
            .cache
            .get_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-get-sync::{}", e)))?
        {
            Some(v) => {
                // parse 失败必须显式报错（与 incr 方法一致，错误显性化），
                // 禁止 unwrap_or(0) 静默返回 0 导致 nc 计数器被错误重置
                v.parse().map_err(|_| {
                    GarrisonError::Dao(format!(
                        "dao-compare-and-update-parse-u64::{}::{}",
                        actual_key, v
                    ))
                })?
            },
            None => 0,
        };

        if new_value > current_val {
            let ttl = if ttl_seconds == 0 {
                None
            } else {
                let remaining = self
                    .cache
                    .ttl_sync(&actual_key)
                    .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-ttl-sync::{}", e)))?;
                Some(remaining.unwrap_or_else(|| Duration::from_secs(ttl_seconds)))
            };
            self.cache
                .set_with_ttl_sync(&actual_key, &new_value.to_string(), ttl)
                .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-set-with-ttl-sync::{}", e)))?;
            #[cfg(feature = "dao-key-index")]
            self.key_index.write().insert(actual_key);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// `parking_lot::Mutex` + `_sync` API 保护（进程内原子）：单锁内 get → compare → set；用于备份码消费等 CAS 场景。
    /// 跨进程共享 Redis L2 仍有 TOCTOU（待 Lua 修复）。
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        #[cfg(feature = "cache-redis")]
        self.check_redis_compat()?;
        let _guard = self.atomic_mutex.lock();
        let actual_key = prefixed_key(key);

        let current = self
            .cache
            .get_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-cas-get-sync::{}", e)))?;

        if current.as_deref() == expected {
            let ttl = if ttl_seconds == 0 {
                None
            } else {
                Some(Duration::from_secs(ttl_seconds))
            };
            self.cache
                .set_with_ttl_sync(&actual_key, &new_value.to_string(), ttl)
                .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-cas-set-sync::{}", e)))?;
            // key_index 维护：CAS 可创建新 key（expected=None 且 key 不存在），
            // 与 set/set_if_absent 一致地插入索引，否则 keys() 漏报该 key
            #[cfg(feature = "dao-key-index")]
            self.key_index.write().insert(actual_key);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 遍历 `key_index` 过滤匹配 pattern 的 key 并惰性清理过期项（oxcache 0.3.3 无原生 keys/iter API）。
    ///
    /// `exists_sync` 返回 `Err`（backend 故障）**不等于键不存在**：保留索引条目、记 warn、不计入结果，
    /// 绝不静默按不存在处理——否则有效 key 会被误判过期并从索引永久删除。
    #[cfg(feature = "dao-key-index")]
    async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
        let actual_pattern = prefixed_key(pattern);
        // 预分配：匹配结果通常占 key_index 的一小部分，取 1/8 与 8 的较大值
        let estimated_matches = (self.key_index.read().len() / 8).max(8);
        let mut result = Vec::with_capacity(estimated_matches);
        let mut expired_keys = Vec::new(); // 过期 key 数量不可预测，不预分配

        // 阶段 1：读锁内仅收集匹配 pattern 的 key（无 I/O，避免阻塞写锁）
        let matched_keys: Vec<String> = {
            let index = self.key_index.read();
            index
                .iter()
                .filter(|key| matches_pattern(key, &actual_pattern))
                .cloned()
                .collect()
        };

        // 阶段 2：无锁检查存在性 + 分类（exists_sync 是无锁读，不阻塞写锁）
        for key in &matched_keys {
            match self.cache.exists_sync(key) {
                Ok(true) => result.push(strip_prefix(key)),
                Ok(false) => expired_keys.push(key.clone()),
                Err(e) => {
                    // backend 故障 ≠ 键不存在：保留索引条目，仅 warn
                    // （不误删有效 key 的索引条目，下次 keys() 重试）
                    tracing::warn!(
                        key = %key,
                        error = %e,
                        "keys() exists_sync failed; keep key_index entry"
                    );
                },
            }
        }

        // 惰性清理过期 key
        if !expired_keys.is_empty() {
            let mut index = self.key_index.write();
            for key in &expired_keys {
                index.remove(key);
            }
            tracing::debug!("keys() cleaned up {} expired keys", expired_keys.len());
        }

        Ok(result)
    }

    /// 委托 oxcache `Cache::eval_lua`（`cache-redis` 门控，启用 `oxcache/lua`），
    /// 将 `oxcache::redis::Value` 递归转为 `Vec<String>`。
    ///
    /// 非 Redis 后端无 Lua 能力：oxcache 返回 `Operation` 错误，映射为 `NotImplemented`
    /// 以兑现 [`GarrisonDao::eval_lua`] 契约（非 Redis 后端以 NotImplemented 通知调用方）——
    /// `atomic_check_and_incr` 与 `RateLimitStrategy::check` 只在 NotImplemented 信号下降级
    /// 非原子路径；Redis 运行期错误仍为 `Dao`（fail-closed，不降级）。
    #[cfg(feature = "cache-redis")]
    async fn eval_lua(
        &self,
        script: &str,
        keys: Vec<String>,
        args: Vec<String>,
    ) -> GarrisonResult<Vec<String>> {
        let key_refs: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let value = self
            .cache
            .eval_lua(script, &key_refs, &arg_refs)
            .await
            .map_err(|e| {
                if is_lua_backend_unsupported(&e) {
                    GarrisonError::NotImplemented(format!("dao-oxcache-eval-lua::{}", e))
                } else {
                    GarrisonError::Dao(format!("dao-oxcache-eval-lua::{}", e))
                }
            })?;
        Ok(redis_value_to_strings(value))
    }
}

/// 判定 oxcache 错误是否为「后端无 Lua 能力」：非 Redis 后端执行 Lua 时 oxcache
/// 统一返回 `Operation` 变体（固定文案，rc.10/rc.11 一致）。变体 + 文案双匹配，
/// 任一漂移即落到 `Dao`（fail-closed），不误降级。
#[cfg(feature = "cache-redis")]
fn is_lua_backend_unsupported(e: &oxcache::OxCacheError) -> bool {
    matches!(e, oxcache::OxCacheError::Operation(_))
        && e.to_string()
            .contains("Lua scripts require a Redis backend")
}

/// 将 `oxcache::redis::Value` 递归展平为 `Vec<String>`：Nil→空、Int/Double→格式化、
/// BulkString→UTF-8 lossy、SimpleString→原文、Okay→"OK"、Array/Set/Map/Attribute 递归展平。
#[cfg(feature = "cache-redis")]
fn redis_value_to_strings(value: oxcache::redis::Value) -> Vec<String> {
    match value {
        oxcache::redis::Value::Nil => vec![],
        oxcache::redis::Value::Int(i) => vec![i.to_string()],
        oxcache::redis::Value::BulkString(v) => {
            vec![String::from_utf8_lossy(&v).to_string()]
        },
        oxcache::redis::Value::SimpleString(s) => vec![s],
        oxcache::redis::Value::Okay => vec!["OK".to_string()],
        oxcache::redis::Value::Double(d) => vec![d.to_string()],
        oxcache::redis::Value::Array(items) => {
            items.into_iter().flat_map(redis_value_to_strings).collect()
        },
        oxcache::redis::Value::Set(items) => {
            items.into_iter().flat_map(redis_value_to_strings).collect()
        },
        oxcache::redis::Value::Map(pairs) => {
            // 预分配：每个 pair 产生 key + value 两个字符串
            let mut result = Vec::with_capacity(pairs.len() * 2);
            for (k, v) in pairs {
                result.extend(redis_value_to_strings(k));
                result.extend(redis_value_to_strings(v));
            }
            result
        },
        oxcache::redis::Value::Attribute { data, .. } => redis_value_to_strings(*data),
        _ => vec!["[unsupported redis value type]".to_string()],
    }
}

// 单元测试（生产后端实现层；trait 契约测试见 mod.rs 的 oxcache_tests / oxcache_keys_tests）

#[cfg(test)]
mod tests {
    use super::*;

    // 基础 KV：set 覆盖、TTL 过期、边界 key

    /// 重复 set 覆盖值与新 TTL。
    #[tokio::test(flavor = "multi_thread")]
    async fn set_overwrites_value_and_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("ow", "v1", 3600).await.unwrap();
        dao.set("ow", "v2", 1).await.unwrap();
        assert_eq!(dao.get("ow").await.unwrap().as_deref(), Some("v2"));
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            dao.get("ow").await.unwrap().is_none(),
            "重复 set 应覆盖原 TTL，新 TTL 过期后应返回 None"
        );
    }

    /// 过期后 get 与 get_timeout 均返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn expired_key_reads_return_none() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("exp_read", "v", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            dao.get("exp_read").await.unwrap().is_none(),
            "过期后 get → None"
        );
        assert!(
            dao.get_timeout("exp_read").await.unwrap().is_none(),
            "过期后 get_timeout → None"
        );
    }

    /// 边界 key（空 key / 特殊字符 / 超长 key）不 panic 且可 roundtrip。
    #[tokio::test(flavor = "multi_thread")]
    async fn boundary_keys_roundtrip_without_panic() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("", "empty", 60).await.unwrap();
        assert_eq!(dao.get("").await.unwrap().as_deref(), Some("empty"));
        // 特殊字符（冒号 / 换行 / 引号 / emoji——协议注入类输入）
        let weird = "a:b\nc\"d'e\u{1f4af}";
        dao.set(weird, "v", 60).await.unwrap();
        assert_eq!(dao.get(weird).await.unwrap().as_deref(), Some("v"));
        let long = "k".repeat(4096);
        dao.set(&long, "lv", 60).await.unwrap();
        assert_eq!(dao.get(&long).await.unwrap().as_deref(), Some("lv"));
    }

    // incr：存在 / 不存在 key、TTL 保留、非数字值

    /// incr 不存在的 key 初始化为 1 并设置 TTL。
    #[tokio::test(flavor = "multi_thread")]
    async fn incr_missing_key_initializes_to_one_with_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        assert_eq!(dao.incr("ic_new", 60).await.unwrap(), 1);
        assert_eq!(dao.get("ic_new").await.unwrap().as_deref(), Some("1"));
        let ttl = dao.get_timeout("ic_new").await.unwrap();
        assert!(ttl.is_some(), "首次 incr 应设置 TTL");
        assert!(ttl.unwrap() <= Duration::from_secs(60));
    }

    /// incr 已存在的 key 递增值且保留原 TTL：set(k,"5",2) 后 incr(k,3600) 返回 6，原 2s TTL 过期后键消失。
    #[tokio::test(flavor = "multi_thread")]
    async fn incr_existing_key_preserves_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("ic_exist", "5", 2).await.unwrap();
        assert_eq!(dao.incr("ic_exist", 3600).await.unwrap(), 6);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            dao.get("ic_exist").await.unwrap().is_none(),
            "incr 不应重置 TTL：原 2s TTL 过期后应返回 None"
        );
    }

    /// incr 新 key 且 ttl_seconds=0 时永久驻留。
    #[tokio::test(flavor = "multi_thread")]
    async fn incr_new_key_with_zero_ttl_is_permanent() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        assert_eq!(dao.incr("ic_perm", 0).await.unwrap(), 1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(dao.get("ic_perm").await.unwrap().as_deref(), Some("1"));
        assert!(dao.get_timeout("ic_perm").await.unwrap().is_none());
    }

    /// incr 现存值非 u64 时显式报错（禁止静默重置计数器）。
    #[tokio::test(flavor = "multi_thread")]
    async fn incr_non_numeric_value_returns_error() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("ic_bad", "not-a-number", 60).await.unwrap();
        let result = dao.incr("ic_bad", 60).await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-incr-parse-u64")),
            "incr 非数字值应返回含'dao-incr-parse-u64'的 Dao 错误，实际: {:?}",
            result
        );
    }

    // decr：全部分支（missing / 递减 / 归零删除 / 0 值保持 / TTL 保留 / 非数字）

    /// decr 不存在的 key 返回 0 且不创建 key。
    #[tokio::test(flavor = "multi_thread")]
    async fn decr_missing_key_returns_zero_without_creating() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        assert_eq!(dao.decr("dc_missing").await.unwrap(), 0);
        assert!(
            dao.get("dc_missing").await.unwrap().is_none(),
            "decr 不存在的 key 不应创建 key"
        );
    }

    /// decr 递减到 0 时删除 key；继续 decr 返回 0。
    #[tokio::test(flavor = "multi_thread")]
    async fn decr_decrements_and_deletes_at_zero() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("dc_counter", "3", 60).await.unwrap();
        assert_eq!(dao.decr("dc_counter").await.unwrap(), 2);
        assert_eq!(dao.decr("dc_counter").await.unwrap(), 1);
        assert_eq!(dao.decr("dc_counter").await.unwrap(), 0);
        assert!(
            dao.get("dc_counter").await.unwrap().is_none(),
            "decr 到 0（new_val == 0 分支）应删除 key"
        );
        assert_eq!(
            dao.decr("dc_counter").await.unwrap(),
            0,
            "key 已删除后 decr → 0"
        );
    }

    /// decr 当前值为 0 时返回 0 且不删除 key（不递减为负）。
    #[tokio::test(flavor = "multi_thread")]
    async fn decr_zero_value_stays_zero_and_keeps_key() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("dc_zero", "0", 60).await.unwrap();
        assert_eq!(dao.decr("dc_zero").await.unwrap(), 0);
        assert_eq!(
            dao.get("dc_zero").await.unwrap().as_deref(),
            Some("0"),
            "cur_val == 0 时 decr 不应删除 key"
        );
    }

    /// decr 递减后值 > 0 时保留原 TTL（不重置窗口）。
    #[tokio::test(flavor = "multi_thread")]
    async fn decr_positive_result_preserves_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("dc_ttl", "5", 2).await.unwrap();
        assert_eq!(dao.decr("dc_ttl").await.unwrap(), 4);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            dao.get("dc_ttl").await.unwrap().is_none(),
            "decr 保留原 2s TTL，过期后应返回 None"
        );
    }

    /// decr 现存值非 u64 时显式报错（与 incr 对称）。
    #[tokio::test(flavor = "multi_thread")]
    async fn decr_non_numeric_value_returns_error() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("dc_bad", "not-a-number", 60).await.unwrap();
        let result = dao.decr("dc_bad").await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-decr-parse-u64")),
            "decr 非数字值应返回含'dao-decr-parse-u64'的 Dao 错误，实际: {:?}",
            result
        );
    }

    // compare_and_update_if_greater（HTTP Digest nc 单调性校验）

    /// CAS-greater：key 不存在时以 0 为 current，new_value > 0 初始化并设置 TTL。
    #[tokio::test(flavor = "multi_thread")]
    async fn compare_greater_missing_key_initializes_with_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        let updated = dao
            .compare_and_update_if_greater("cg_new", 5, 60)
            .await
            .unwrap();
        assert!(updated, "key 不存在（current=0）且 new=5 > 0 应更新");
        assert_eq!(dao.get("cg_new").await.unwrap().as_deref(), Some("5"));
        assert!(dao.get_timeout("cg_new").await.unwrap().is_some());
    }

    /// CAS-greater：ttl_seconds=0 时写入永久键。
    #[tokio::test(flavor = "multi_thread")]
    async fn compare_greater_with_zero_ttl_is_permanent() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        let updated = dao
            .compare_and_update_if_greater("cg_perm", 5, 0)
            .await
            .unwrap();
        assert!(updated);
        assert!(
            dao.get_timeout("cg_perm").await.unwrap().is_none(),
            "ttl_seconds=0 应写入永久键（get_timeout → None）"
        );
    }

    /// CAS-greater：已存在 key 保留剩余 TTL（不重置为 ttl_seconds 参数）。
    #[tokio::test(flavor = "multi_thread")]
    async fn compare_greater_existing_key_preserves_remaining_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("cg_exist", "3", 2).await.unwrap();
        let updated = dao
            .compare_and_update_if_greater("cg_exist", 5, 3600)
            .await
            .unwrap();
        assert!(updated);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            dao.get("cg_exist").await.unwrap().is_none(),
            "CAS 更新应保留原 2s 剩余 TTL，过期后应返回 None"
        );
    }

    /// CAS-greater：new_value <= current 时不修改返回 false；缺失 key + new=0 亦然。
    #[tokio::test(flavor = "multi_thread")]
    async fn compare_not_greater_returns_false() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("cg_hold", "10", 60).await.unwrap();
        let smaller = dao
            .compare_and_update_if_greater("cg_hold", 5, 60)
            .await
            .unwrap();
        assert!(!smaller, "5 <= 10 不应更新");
        let equal = dao
            .compare_and_update_if_greater("cg_hold", 10, 60)
            .await
            .unwrap();
        assert!(!equal, "10 <= 10（相等）不应更新");
        assert_eq!(
            dao.get("cg_hold").await.unwrap().as_deref(),
            Some("10"),
            "未更新时值应保持不变"
        );
        // 缺失 key（current=0）+ new_value=0：0 > 0 为 false，且不创建 key
        let zero = dao
            .compare_and_update_if_greater("cg_absent", 0, 60)
            .await
            .unwrap();
        assert!(!zero, "缺失 key + new_value=0 不应更新");
        assert!(
            dao.get("cg_absent").await.unwrap().is_none(),
            "不应创建 key"
        );
    }

    /// CAS-greater：现存值非 u64 时显式报错。
    #[tokio::test(flavor = "multi_thread")]
    async fn compare_greater_non_numeric_value_returns_error() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("cg_bad", "not-a-number", 60).await.unwrap();
        let result = dao.compare_and_update_if_greater("cg_bad", 1, 60).await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-compare-and-update-parse-u64")),
            "非数字值应返回含 'dao-compare-and-update-parse-u64' 的 Dao 错误，实际: {:?}",
            result
        );
    }

    // compare_and_swap（备份码消费等原子 CAS 场景）

    /// CAS：匹配时替换成功并写入新 TTL。
    #[tokio::test(flavor = "multi_thread")]
    async fn cas_match_replaces_value_with_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("cs_k", "old", 60).await.unwrap();
        let ok = dao
            .compare_and_swap("cs_k", Some("old"), "new", 60)
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(dao.get("cs_k").await.unwrap().as_deref(), Some("new"));
        assert!(
            dao.get_timeout("cs_k").await.unwrap().is_some(),
            "CAS 写入应带 TTL"
        );
    }

    /// CAS：不匹配 / 缺失 key 各分支返回 false 且不写入。
    #[tokio::test(flavor = "multi_thread")]
    async fn cas_mismatch_and_absent_branches_return_false() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        dao.set("cs_m", "actual", 60).await.unwrap();
        let ok = dao
            .compare_and_swap("cs_m", Some("expected"), "new", 60)
            .await
            .unwrap();
        assert!(!ok);
        assert_eq!(dao.get("cs_m").await.unwrap().as_deref(), Some("actual"));
        // expected=None 但 key 已存在
        let ok = dao.compare_and_swap("cs_m", None, "new", 60).await.unwrap();
        assert!(!ok);
        // expected=Some 但 key 不存在
        let ok = dao
            .compare_and_swap("cs_absent", Some("old"), "new", 60)
            .await
            .unwrap();
        assert!(!ok);
        assert!(
            dao.get("cs_absent").await.unwrap().is_none(),
            "不应创建 key"
        );
    }

    /// CAS：expected=None + key 不存在初始化成功；ttl=0 写入永久键。
    #[tokio::test(flavor = "multi_thread")]
    async fn cas_none_expected_creates_and_zero_ttl_is_permanent() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        let ok = dao
            .compare_and_swap("cs_init", None, "initial", 0)
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(
            dao.get("cs_init").await.unwrap().as_deref(),
            Some("initial")
        );
        assert!(
            dao.get_timeout("cs_init").await.unwrap().is_none(),
            "ttl=0 应写入永久键"
        );
    }

    // 私有 helper：prefixed_key（无 TENANT 上下文时 key 原样返回）

    /// `prefixed_key` 在 TENANT 上下文不存在时原样返回 key（不 panic）。
    #[tokio::test(flavor = "multi_thread")]
    async fn prefixed_key_without_tenant_context_is_identity() {
        assert_eq!(prefixed_key("plain_key"), "plain_key");
        assert_eq!(prefixed_key(""), "");
    }

    // 私有 helper + keys() 补充分支（dao-key-index）

    #[cfg(feature = "dao-key-index")]
    mod key_index {
        use super::*;

        /// `matches_pattern`：`*` 全匹配、后缀通配、精确匹配、无匹配。
        #[test]
        fn matches_pattern_basic_cases() {
            assert!(matches_pattern("anything", "*"));
            assert!(matches_pattern("anomalous:login:1:1", "anomalous:login:*"));
            assert!(matches_pattern("exact-key", "exact-key"));
            assert!(!matches_pattern("other:key", "anomalous:login:*"));
            assert!(!matches_pattern("short", "exact-key"));
        }

        /// `matches_pattern`：`*` 可出现在 pattern 任意位置（与 `glob_match` / Redis `KEYS` 语义一致）。
        #[test]
        fn matches_pattern_middle_star_is_wildcard() {
            assert!(matches_pattern("axb", "a*b"), "中间 * 应做通配");
            assert!(matches_pattern("ab", "a*b"), "* 可匹配空序列");
            assert!(matches_pattern("aXYzb", "a*b"), "* 跨多字符");
            assert!(
                matches_pattern("a/b", "a*b"),
                "* 回溯时可匹配任意字符（含 /）"
            );
            assert!(
                !matches_pattern("aXbY", "a*b"),
                "尾部无剩余 pattern 时不应命中"
            );
        }

        /// `matches_pattern`：`?` 恰匹配单个任意字符（与 `glob_match` / Redis `KEYS` 语义一致）。
        #[test]
        fn matches_pattern_question_mark_is_single_char() {
            assert!(matches_pattern("key1", "key?"), "? 应匹配单个字符");
            assert!(
                matches_pattern("key:", "key?"),
                "? 匹配任意单字符（含冒号）"
            );
            assert!(!matches_pattern("key12", "key?"), "? 不匹配两个字符");
            assert!(!matches_pattern("key", "key?"), "? 不匹配零个字符");
            assert!(
                matches_pattern("user:1:tok", "user:*:tok"),
                "* 与 ? 组合（跨段通配）"
            );
            assert!(matches_pattern("user:1", "user:?"), "? 恰好匹配尾段单字符");
        }

        /// `strip_prefix`：无前缀原样返回；`tenant:{id}:{key}` 去前缀；
        /// `tenant:` 后无第二个 `:` 时原样返回。
        #[test]
        fn strip_prefix_variants() {
            assert_eq!(strip_prefix("plain"), "plain");
            #[cfg(feature = "tenant-isolation")]
            {
                assert_eq!(strip_prefix("tenant:42:real_key"), "real_key");
                assert_eq!(strip_prefix("tenant:42"), "tenant:42");
            }
            #[cfg(not(feature = "tenant-isolation"))]
            {
                assert_eq!(strip_prefix("tenant:42:real_key"), "tenant:42:real_key");
            }
        }

        /// keys() 精确 pattern 与无匹配：返回原始（去前缀后的）key 名。
        #[tokio::test(flavor = "multi_thread")]
        async fn keys_exact_pattern_and_no_match() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("kx_exact", "v", 3600).await.unwrap();
            let keys = dao.keys("kx_exact").await.unwrap();
            assert_eq!(
                keys,
                vec!["kx_exact".to_string()],
                "精确 pattern 应命中该 key"
            );
            let none = dao.keys("kx_no_such_*").await.unwrap();
            assert!(none.is_empty(), "无匹配应返回空 Vec");
        }

        /// key_index 维护：incr 新建的 key 应出现在 keys() 结果中。
        #[tokio::test(flavor = "multi_thread")]
        async fn keys_includes_key_created_by_incr() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            assert_eq!(dao.incr("ki_incr_key", 60).await.unwrap(), 1);
            let keys = dao.keys("ki_incr_key").await.unwrap();
            assert_eq!(
                keys,
                vec!["ki_incr_key".to_string()],
                "incr 新建的 key 应被 key_index 收录"
            );
        }

        /// key_index 维护：rename 应迁移索引条目（旧键移除、新键收录）。
        #[tokio::test(flavor = "multi_thread")]
        async fn keys_rename_migrates_index_entry() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("kr_old", "v", 3600).await.unwrap();
            dao.rename("kr_old", "kr_new").await.unwrap();

            let old_keys = dao.keys("kr_old").await.unwrap();
            assert!(old_keys.is_empty(), "rename 后旧键应从 key_index 移除");
            let new_keys = dao.keys("kr_new").await.unwrap();
            assert_eq!(
                new_keys,
                vec!["kr_new".to_string()],
                "rename 后新键应被 key_index 收录"
            );
        }

        /// key_index 维护：get_and_delete 应清理索引条目（与 delete 一致）。
        #[tokio::test(flavor = "multi_thread")]
        async fn keys_get_and_delete_cleans_index_entry() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("kg_k", "v", 3600).await.unwrap();
            let v = dao.get_and_delete("kg_k").await.unwrap();
            assert_eq!(v.as_deref(), Some("v"));
            let keys = dao.keys("kg_k").await.unwrap();
            assert!(
                keys.is_empty(),
                "get_and_delete 后 key 不应残留在 key_index 中"
            );
        }

        /// keys() 在 TENANT 上下文内返回去前缀的原始 key 名。
        #[cfg(feature = "tenant-isolation")]
        #[tokio::test(flavor = "multi_thread")]
        async fn keys_strip_tenant_prefix_in_tenant_context() {
            use crate::context::tenant::{TenantContext, TenantSource, TENANT};
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let ctx = TenantContext {
                tenant_id: 7,
                resolved_from: TenantSource::Header,
            };
            TENANT
                .scope(ctx, async {
                    dao.set("tk1", "v1", 3600).await.unwrap();
                    dao.set("tk2", "v2", 3600).await.unwrap();
                    dao.set("other:k", "v3", 3600).await.unwrap();
                    let mut keys = dao.keys("tk*").await.unwrap();
                    keys.sort();
                    assert_eq!(
                        keys,
                        vec!["tk1".to_string(), "tk2".to_string()],
                        "keys() 应返回去租户前缀的原始 key 名"
                    );
                })
                .await;
        }
    }

    // cache-redis：check_redis_compat（M4 防护）、eval_lua、redis_value_to_strings

    #[cfg(feature = "cache-redis")]
    mod redis_compat {
        use super::*;
        use crate::dao::RedisDeploymentMode;

        /// 构造测试用 RedisConfig（Single 模式）。
        fn test_redis_config() -> RedisConfig {
            RedisConfig {
                mode: RedisDeploymentMode::Single {
                    url: "redis://127.0.0.1:6379".to_string(),
                },
                password: None,
                db: 0,
                connection_timeout_secs: 5,
                pool_size: 10,
            }
        }

        /// M4 防护：`with_redis_config` 后 6 个 `_sync` 原子方法应返回 `Err(Config)`。
        #[tokio::test(flavor = "multi_thread")]
        async fn with_redis_config_blocks_sync_atomic_ops() {
            let dao = GarrisonDaoOxcache::new()
                .await
                .unwrap()
                .with_redis_config(test_redis_config());
            assert!(dao.redis_config().is_some(), "配置应已存储");

            let r = dao.set_if_absent("rc_k", "v", 60).await;
            assert!(matches!(r, Err(GarrisonError::Config(_))), "实际: {:?}", r);
            let r = dao.incr("rc_k", 60).await;
            assert!(matches!(r, Err(GarrisonError::Config(_))), "实际: {:?}", r);
            let r = dao.decr("rc_k").await;
            assert!(matches!(r, Err(GarrisonError::Config(_))), "实际: {:?}", r);
            let r = dao.get_and_delete("rc_k").await;
            assert!(matches!(r, Err(GarrisonError::Config(_))), "实际: {:?}", r);
            let r = dao.compare_and_swap("rc_k", None, "v", 60).await;
            assert!(matches!(r, Err(GarrisonError::Config(_))), "实际: {:?}", r);
            let r = dao.compare_and_update_if_greater("rc_k", 1, 60).await;
            assert!(matches!(r, Err(GarrisonError::Config(_))), "实际: {:?}", r);
        }

        /// eval_lua 在内存后端（非 Redis）必须返回 `NotImplemented`（含 dao-oxcache-eval-lua 标识）：
        /// `GarrisonDao::eval_lua` 契约规定非 Redis 后端以 NotImplemented 通知调用方降级；
        /// `Dao` 错误会绕过两条降级分支——`atomic_check_and_incr`（仅 NotImplemented 降级）
        /// 与 `RateLimitStrategy::check`（消息含 NotImplemented 才降级），使限流显性报错。
        #[tokio::test(flavor = "multi_thread")]
        async fn eval_lua_on_memory_backend_returns_not_implemented() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let result = dao
                .eval_lua("return 1", vec!["el_k".to_string()], vec![])
                .await;
            assert!(
                matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("dao-oxcache-eval-lua")),
                "内存后端 eval_lua 应返回含 'dao-oxcache-eval-lua' 的 NotImplemented 错误，实际: {:?}",
                result
            );
        }

        /// 端到端回归：`GarrisonDaoOxcache`（内存后端）经 `GarrisonDaoDistributedLimiter`
        /// 原子计数在 `cache-redis` 下仍走 incr 降级路径（eval_lua NotImplemented → 降级），
        /// 与 `cache-memory` 单开时行为一致——启用 cache-redis 不得改变降级语义。
        #[tokio::test(flavor = "multi_thread")]
        async fn distributed_limiter_falls_back_to_incr_with_oxcache_dao() {
            use crate::limiteron::GarrisonDaoDistributedLimiter;
            let dao: std::sync::Arc<dyn GarrisonDao> =
                std::sync::Arc::new(GarrisonDaoOxcache::new().await.unwrap());
            let limiter = GarrisonDaoDistributedLimiter::new(dao.clone());
            let allowed = limiter
                .atomic_check_and_incr("rc_lua_fb", 5, Duration::from_secs(60))
                .await
                .expect("内存后端应走 incr 降级而非报错");
            assert!(allowed, "count 1 <= 5 应放行");
            assert_eq!(
                dao.get("rc_lua_fb").await.unwrap().as_deref(),
                Some("1"),
                "降级路径应经 incr 落盘计数"
            );
        }

        /// `redis_value_to_strings`：标量变体逐个转换。
        #[test]
        fn redis_value_to_strings_scalars() {
            assert!(
                redis_value_to_strings(oxcache::redis::Value::Nil).is_empty(),
                "Nil → 空"
            );
            assert_eq!(
                redis_value_to_strings(oxcache::redis::Value::Int(-7)),
                vec!["-7"]
            );
            assert_eq!(
                redis_value_to_strings(oxcache::redis::Value::BulkString(b"hello".to_vec())),
                vec!["hello"]
            );
            // 非法 UTF-8 → lossy 替换字符
            assert_eq!(
                redis_value_to_strings(oxcache::redis::Value::BulkString(vec![0xff])),
                vec!["\u{FFFD}"]
            );
            assert_eq!(
                redis_value_to_strings(oxcache::redis::Value::SimpleString("PONG".to_string())),
                vec!["PONG"]
            );
            assert_eq!(
                redis_value_to_strings(oxcache::redis::Value::Okay),
                vec!["OK"]
            );
            assert_eq!(
                redis_value_to_strings(oxcache::redis::Value::Double(1.5)),
                vec!["1.5"]
            );
        }

        /// `redis_value_to_strings`：复合变体递归展平 + 未支持类型占位符。
        #[test]
        fn redis_value_to_strings_composites_and_fallback() {
            assert_eq!(
                redis_value_to_strings(oxcache::redis::Value::Array(vec![
                    oxcache::redis::Value::Int(1),
                    oxcache::redis::Value::Array(vec![oxcache::redis::Value::Okay]),
                ])),
                vec!["1", "OK"]
            );
            assert_eq!(
                redis_value_to_strings(oxcache::redis::Value::Set(vec![
                    oxcache::redis::Value::Int(2)
                ])),
                vec!["2"]
            );
            assert_eq!(
                redis_value_to_strings(oxcache::redis::Value::Map(vec![(
                    oxcache::redis::Value::BulkString(b"k".to_vec()),
                    oxcache::redis::Value::Int(1),
                )])),
                vec!["k", "1"]
            );
            assert_eq!(
                redis_value_to_strings(oxcache::redis::Value::Attribute {
                    data: Box::new(oxcache::redis::Value::Int(9)),
                    attributes: vec![],
                }),
                vec!["9"]
            );
            assert_eq!(
                redis_value_to_strings(oxcache::redis::Value::Boolean(true)),
                vec!["[unsupported redis value type]"]
            );
        }
    }
    /// TTL 精确性回归锁：DAO 显式钉定 `ttl_jitter(0.0)`，`get_timeout` 不得超过请求 TTL——
    /// rc.6 默认 ±10% 抖动会以约 1/2 概率违反单条断言，20 键取样把漏检率压到 ~1e-6。
    #[tokio::test(flavor = "multi_thread")]
    async fn ttl_exact_after_jitter_pin() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        let mut max_seen = Duration::ZERO;
        for i in 0..20 {
            let k = format!("jitter_pin_{i}");
            dao.set(&k, "v", 60).await.unwrap();
            let ttl = dao.get_timeout(&k).await.unwrap().expect("TTL 键应可读");
            max_seen = max_seen.max(ttl);
        }
        assert!(
            max_seen <= Duration::from_secs(60),
            "DAO TTL 必须精确（ttl_jitter(0.0) 钉定）：实测最大 {max_seen:?} > 60s，抖动回归？"
        );
    }
}
