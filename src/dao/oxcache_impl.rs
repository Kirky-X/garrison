//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! GarrisonDaoOxcache 实现（从 mod.rs 迁移，Rule 25 合规）。

use super::GarrisonDao;
#[cfg(feature = "cache-redis")]
use super::RedisConfig;
#[cfg(feature = "tenant-isolation")]
use crate::constants::DaoKeyPrefix;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use oxcache::Cache;
use std::time::Duration;

/// 根据租户上下文返回实际存储 key。
///
/// - `tenant-isolation` feature 启用且 `TENANT.try_get()` 返回 `Ok(ctx)`：
///   返回 `format!("{}{}:{}", DaoKeyPrefix::Tenant, ctx.tenant_id, key)`
/// - feature 关闭或 `TENANT` 上下文不存在（`try_get` 返回 `Err`）：返回 `key.to_string()`（不变）
///
/// # 设计
///
/// - `TENANT.try_get()` 返回 `Err` 而非 `None`（tokio task_local 语义），用 `Ok` 模式匹配
/// - 不 panic：无上下文时 key 保持原样，保证向后兼容
/// - 同步函数：`try_get` 是同步的，无需 async
fn prefixed_key(key: &str) -> String {
    #[cfg(feature = "tenant-isolation")]
    {
        if let Ok(ctx) = crate::context::tenant::TENANT.try_get() {
            return format!("{}{}:{}", DaoKeyPrefix::Tenant, ctx.tenant_id, key);
        }
    }
    // feature 关闭或无 TENANT 上下文时 key 保持原样
    #[allow(unused_variables)]
    let _ = key;
    key.to_string()
}

/// 通配符匹配（支持 `*` 匹配任意字符序列）。
///
/// 用于 `keys()` 方法过滤匹配 pattern 的 key。
/// pattern 如 `"anomalous:login:*"` 匹配 `"anomalous:login:1001:1234567890"`。
///
/// # Feature gate
/// 与 `mod.rs` 内联实现保持一致：使用 `dao-key-index`（由 `protocol-apikey` /
/// `anomalous-detector-dual` 传递启用），而非更严格的 `anomalous-detector-dual`，
/// 确保只启用 `protocol-apikey` 的场景 `keys()` 仍可用。
#[cfg(feature = "dao-key-index")]
fn matches_pattern(key: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return key.starts_with(prefix);
    }
    key == pattern
}

/// 去除 DAO 前缀，返回原始 key（`prefixed_key` 的逆操作）。
///
/// `prefixed_key` 在 `tenant-isolation` 启用且有 TENANT 上下文时
/// 返回 `format!("tenant:{id}:{key}")`，否则原样返回。
/// 本函数逆向该操作：去除 `"tenant:{id}:"` 前缀，或原样返回。
///
/// # Feature gate
/// 与 `matches_pattern` 一致，使用 `dao-key-index`（详见 `matches_pattern` 文档）。
#[cfg(feature = "dao-key-index")]
fn strip_prefix(prefixed: &str) -> String {
    #[cfg(feature = "tenant-isolation")]
    {
        // 格式 "tenant:{id}:{key}"，找到第二个 ':' 之后的内容
        if let Some(rest) = prefixed.strip_prefix("tenant:") {
            if let Some(pos) = rest.find(':') {
                return rest[pos + 1..].to_string();
            }
        }
    }
    // 无前缀（tenant-isolation 关闭或无 TENANT 上下文）时原样返回
    prefixed.to_string()
}

/// oxcache 0.3 默认实现，包装 `oxcache::Cache<String, String>`。
///
/// - L1（内存）+ L2（redis）由 oxcache 0.3 自动管理（oxcache 0.3 支持 per-entry TTL）。
/// - Garrison 自身不实现任何缓存逻辑，全部委托给 oxcache。
/// - 启用 `sync_mode(true)` 后使用 `_sync` API，
///   要求调用方在 multi_thread tokio runtime 中执行。
///
/// # TTL 保留
/// - `update` 通过 `cache.ttl_sync()` 读取剩余 TTL，用 `set_with_ttl_sync` 保留原 TTL（不重置过期时间）
/// - `expire` 通过 `cache.expire_sync()` 原子更新 TTL（不触碰 value）
/// - 依赖本地 oxcache 仓库（crates.io 0.3.0 未暴露 `Cache<K,V>::ttl_sync()`，本地仓库已暴露）
///
/// # 性能约束（A-009 评估结论）
///
/// `_sync` API 仅适用于 oxcache in-memory 后端：
/// - 读操作（`get_sync`/`exists_sync`/`ttl_sync`）：无锁读，<100ns
/// - 写操作（`set_with_ttl_sync`/`delete_sync`/`expire_sync`）：短临界区，<1μs
/// - 对比 `tokio::task::spawn_blocking` 开销：~10-50μs（线程池调度）
///
/// 结论：对 in-memory backend，`_sync` 调用比 `spawn_blocking` 更快，保留现有实现。
///
/// **后续跟进**：若未来引入 Redis/分布式 backend，需改用 async API（`_sync` 在网络 I/O 场景下会阻塞 tokio worker 线程）。
pub struct GarrisonDaoOxcache {
    /// 原子操作互斥锁，保证 `set_if_absent` / `get_and_delete` / `incr` 等的串行化。
    ///
    /// **字段排序依据**（Cache 局部性优化）：按访问频率降序排列，
    /// 高频字段前置以优先命中 L1 Cache Line（鲲鹏 128B / x86 64B）。
    ///
    /// **为何用 `parking_lot::Mutex` 而非 `tokio::sync::Mutex`**（H3 修复）：
    /// 原实现用 `tokio::sync::Mutex` + async cache API（`cache.get().await`），
    /// 跨 await 持锁序列化所有原子操作。改为 `parking_lot::Mutex` + `_sync` API
    /// （`cache.get_sync()`），锁内全同步操作（<1μs），不让出 tokio task，
    /// 与 `get`/`set` 方法的 `_sync` 模式对齐（文件 L118-127 设计结论）。
    atomic_mutex: parking_lot::Mutex<()>,
    /// key 索引，用于实现 `keys()` 方法（oxcache 0.3.3 无原生 keys/iter API）。
    /// 仅在 `dao-key-index` feature 启用时维护（由 `protocol-apikey` /
    /// `anomalous-detector-dual` 传递），避免影响其他场景的内存开销。
    /// TTL 过期的 key 会在 `keys()` 调用时惰性清理。
    #[cfg(feature = "dao-key-index")]
    key_index: parking_lot::RwLock<std::collections::HashSet<String>>,
    /// 缓存后端（oxcache L1 内存 + L2 Redis）。
    cache: Cache<String, String>,
    /// Redis 部署模式配置（仅在 `cache-redis` feature 启用时存在）。
    ///
    /// 通过 [`with_redis_config`] builder 方法设置。未设置时为 `None`，
    /// oxcache 使用默认 Redis 配置。
    #[cfg(feature = "cache-redis")]
    redis_config: Option<RedisConfig>,
}

impl GarrisonDaoOxcache {
    /// 创建默认的 oxcache DAO 实例。
    ///
    /// 启用 `sync_mode(true)` 以支持 `_sync` API。
    ///
    /// # 返回
    /// 已初始化的 `GarrisonDaoOxcache` 实例（内部 `oxcache::Cache` 已就绪，sync_mode 启用）。
    ///
    /// # 错误
    /// - `GarrisonError::Dao`：oxcache 初始化失败（消息含 "oxcache 初始化失败"）。
    pub async fn new() -> GarrisonResult<Self> {
        let cache = Cache::builder()
            .sync_mode(true)
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

    /// 设置 Redis 部署模式配置。
    ///
    /// 仅在 `cache-redis` feature 启用时可用。消费 self 并返回新实例（builder 模式）。
    /// 调用后 oxcache 的 Redis L2 后端使用指定部署模式。
    /// 未调用时保持现有行为（oxcache 默认 Redis 配置）。
    ///
    /// # 参数
    /// - `config`: Redis 配置（包含部署模式、连接池参数、认证信息）。
    ///
    /// # 返回
    /// 消费 self 并返回新实例。
    #[cfg(feature = "cache-redis")]
    pub fn with_redis_config(mut self, config: RedisConfig) -> Self {
        // M4 防护：_sync API（set_if_absent/incr/decr/get_and_delete）仅适用于
        // in-memory 后端。oxcache sync_mode(true) + backend_arc() 会返回
        // Err(NotSupported)（见 oxcache cache_builder.rs L93-101）。
        // Redis L2 后端的网络 I/O 会阻塞 tokio worker 线程（_sync API 同步阻塞）。
        // 当前 with_redis_config 仅存储配置,不实际添加 Redis 后端;
        // 若未来引入 Redis L2 后端,原子操作方法会通过 check_redis_compat 返回 Err。
        tracing::warn!(
            mode = %config.mode,
            db = config.db,
            "Redis 配置已存储,但 _sync API（set_if_absent/incr/decr/get_and_delete）与 Redis L2 后端不兼容;\
             原子操作方法将在调用时返回 Err(配置错误),直到迁移到 async API"
        );
        self.redis_config = Some(config);
        self
    }

    /// 检查 _sync API 与 Redis L2 后端的兼容性（M4 防护）。
    ///
    /// `_sync` API（`set_if_absent` / `incr` / `decr` / `get_and_delete`）仅适用于
    /// in-memory 后端,Redis L2 后端的网络 I/O 会阻塞 tokio worker 线程。
    ///
    /// 当 `cache-redis` feature 启用且 `redis_config` 已设置时,返回 `Err(Config)` 提示不兼容,
    /// 防止用户误用 _sync API 导致 tokio worker 阻塞（规则12 失败必须显性化）。
    ///
    /// # 返回
    /// - `Ok(())`: in-memory 后端,`_sync` API 可用
    /// - `Err(Config)`: Redis L2 后端已配置,`_sync` API 不兼容
    #[cfg(feature = "cache-redis")]
    fn check_redis_compat(&self) -> GarrisonResult<()> {
        if self.redis_config.is_some() {
            return Err(GarrisonError::Config(
                "dao-oxcache-sync-api-incompatible-with-redis::\
                 _sync API（set_if_absent/incr/decr/get_and_delete）与 Redis L2 后端不兼容,\
                 请改用 async API 或移除 with_redis_config 调用"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// 返回当前 Redis 配置（仅在 `cache-redis` feature 启用时可用）。
    ///
    /// 用于测试与诊断：确认 `with_redis_config` 是否已调用。
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
        // 通过 cache.ttl_sync() 读取剩余 TTL，用 set_with_ttl_sync 保留原 TTL（不重置过期时间）。
        // ttl_sync() 返回 None 表示永久驻留（set_with_ttl_sync 接受 None 表示无 TTL）。
        // 但 None 也可能表示键不存在，需要先检查键存在性。
        let actual_key = prefixed_key(key);
        if !self
            .cache
            .exists_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-exists-sync::{}", e)))?
        {
            return Err(GarrisonError::Dao(format!("dao-key-missing::{}", key)));
        }
        let remaining_ttl = self
            .cache
            .ttl_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-ttl-sync::{}", e)))?;
        self.cache
            .set_with_ttl_sync(&actual_key, &value.to_string(), remaining_ttl)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-update-set-with-ttl-sync::{}", e)))
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        // oxcache 0.3 的 Cache<K,V> 暴露了 expire_sync(key, ttl) 方法（原子更新 TTL，不触碰 value）。
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

    /// delete 用 `delete_sync` 删除 key。
    ///
    /// 跨进程限制：多进程共享 Redis L2 时，仍需确保删除传播一致性。
    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        let actual_key = prefixed_key(key);
        self.cache
            .delete_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-delete-sync::{}", e)))?;
        #[cfg(feature = "dao-key-index")]
        self.key_index.write().remove(&actual_key);
        Ok(())
    }

    /// set_permanent 用 set_with_ttl_sync(None) 写入永久键。
    ///
    /// 重写默认实现以使用 oxcache 原生"无 TTL"API（避免 ttl=0 歧义）。
    async fn set_permanent(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let actual_key = prefixed_key(key);
        self.cache
            .set_with_ttl_sync(&actual_key, &value.to_string(), None)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-set-with-ttl-sync::{}", e)))?;
        #[cfg(feature = "dao-key-index")]
        self.key_index.write().insert(actual_key);
        Ok(())
    }

    /// get_timeout 用 ttl_sync 查询剩余 TTL。
    ///
    /// oxcache 0.3 的 `ttl_sync(key)` 返回 `Option<Duration>`：
    /// - `Some(remaining)`: 键存在且设置了 TTL
    /// - `None`: 键不存在，或键存在但未设置 TTL（永久驻留）
    async fn get_timeout(&self, key: &str) -> GarrisonResult<Option<Duration>> {
        let actual_key = prefixed_key(key);
        self.cache
            .ttl_sync(&actual_key)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-ttl-sync::{}", e)))
    }

    /// rename 用 get → ttl_sync → set_with_ttl_sync → delete 四步。
    ///
    /// 重写默认实现以保留原键 TTL（用 `ttl_sync` 读取剩余 TTL，用 `set_with_ttl_sync` 写入）。
    /// 仍是**非原子**操作（oxcache 0.3.3 无原子 rename API，待 oxcache 提供原子 rename API）。
    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
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
        self.cache
            .set_with_ttl_sync(&actual_new, &value, remaining_ttl)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-set-with-ttl-sync::{}", e)))?;
        self.cache
            .delete_sync(&actual_old)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-delete-sync::{}", e)))
    }

    /// get_and_delete 用 `parking_lot::Mutex` + `_sync` API 保护 get+delete。
    ///
    /// 进程内原子：同一进程内并发调用同一 key 仅一个返回 `Some`。
    /// `delete_sync` 是同步删除（已由 `oxcache_get_and_delete_concurrent`
    /// 测试验证），无需额外状态追踪。
    /// 跨进程限制：多进程共享 Redis L2 时，仍存在 TOCTOU 竞态
    /// （需 Redis Lua 脚本 `redis.call('GET',K[1]);redis.call('DEL',K[1])` 修复，待引入 Redis L2 后端）。
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
        }
        Ok(value)
    }

    /// set_if_absent 用 `parking_lot::Mutex` + `_sync` API 保护原子性（进程内原子）。
    ///
    /// **流程**：Mutex 内通过 `exists_sync` 检查 key 是否存在，不存在则 `set_with_ttl_sync` 写入。
    /// oxcache `_sync` API 直接操作底层 HashMap（绕过 Moka channel 延迟），
    /// `exists_sync` + `set_with_ttl_sync` 在 Mutex 串行化下提供原子语义。
    ///
    /// **H3 修复**：原实现用 `tokio::sync::Mutex` + async cache API，跨 await 持锁。
    /// 改为 `parking_lot::Mutex` + `_sync` API，锁内全同步操作（<1μs）。
    ///
    /// 跨进程限制：多进程共享 Redis L2 时仍存在 TOCTOU 竞态
    /// （需 Redis `SET key value NX EX ttl` 修复，待引入 Redis L2 后端）。
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

    /// incr 用 `parking_lot::Mutex` + `_sync` API 保护原子性（进程内原子）。
    ///
    /// **流程**：Mutex 内通过 `get_sync` 读取当前值，递增后用 `set_with_ttl_sync` 写回。
    /// key 不存在时初始化为 1。key 已存在时通过 `ttl_sync` 读取剩余 TTL 并保留。
    ///
    /// **H3 修复**：原实现用 `tokio::sync::Mutex` + async cache API，跨 await 持锁。
    /// 改为 `parking_lot::Mutex` + `_sync` API，锁内全同步操作（<1μs）。
    ///
    /// 跨进程限制：多进程共享 Redis L2 时仍存在 TOCTOU 竞态
    /// （需 Redis `INCR` 原子命令修复，待引入 Redis L2 后端）。
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
                // Rule 12：parse 失败必须显式报错，禁止静默返回 0 导致计数器重置
                let cur_val: u64 = v.parse().map_err(|_| {
                    GarrisonError::Dao(format!(
                        "incr: 现存值非 u64，key={}, value={}",
                        actual_key, v
                    ))
                })?;
                let new_val = cur_val + 1;
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
                Ok(1)
            },
        }
    }

    /// decr 用 `parking_lot::Mutex` + `_sync` API 保护原子性（进程内原子，与 `incr` 对称）。
    ///
    /// **语义**（与 trait 默认实现 + `MockDao::decr` 一致）：
    /// - key 不存在或已过期：返回 0（不创建 key）
    /// - cur_val == 0：返回 0（不递减为负，不删除 key）
    /// - cur_val > 0：递减 1；new_val == 0 时 `delete_sync` 删除 key；
    ///   new_val > 0 时用 `ttl_sync` 读取剩余 TTL 并 `set_with_ttl_sync` 保留（不重置窗口）
    ///
    /// **H3 修复**：原实现用 `tokio::sync::Mutex` + async cache API，跨 await 持锁。
    /// 改为 `parking_lot::Mutex` + `_sync` API，锁内全同步操作（<1μs）。
    ///
    /// 跨进程限制：多进程共享 Redis L2 时仍存在 TOCTOU 竞态
    /// （需 Redis `DECR` 原子命令修复，待引入 Redis L2 后端）。
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
                // Rule 12：parse 失败必须显式报错（与 incr 一致，禁止静默返回 0）
                let cur_val: u64 = v.parse().map_err(|_| {
                    GarrisonError::Dao(format!(
                        "decr: 现存值非 u64，key={}, value={}",
                        actual_key, v
                    ))
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

    /// compare_and_update_if_greater 用 `parking_lot::Mutex` + `_sync` API 保护原子性（进程内原子）。
    ///
    /// **语义**：
    /// - key 不存在或已过期：current_val = 0，new_value > 0 时初始化并设置 TTL
    /// - key 已存在且 new_value > current_val：用 `ttl_sync` 读取剩余 TTL 保留（不重置）
    /// - key 已存在但 new_value <= current_val：不修改，返回 false
    ///
    /// **H3 修复**：原实现用 `tokio::sync::Mutex` + async cache API，跨 await 持锁。
    /// 改为 `parking_lot::Mutex` + `_sync` API，锁内全同步操作（<1μs）。
    ///
    /// 用于 HTTP Digest nc 单调性校验（RFC 7616 §3.4.6），消除 get→compare→set TOCTOU 竞态。
    /// 跨进程限制：多进程共享 Redis L2 时仍存在 TOCTOU 竞态
    /// （需 Redis Lua 脚本（GET + COMPARE + SET 原子执行）修复，待引入 Redis L2 后端）。
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
                // M1 修复：parse 失败必须显式报错（与 incr 方法一致，Rule 12 错误显性化），
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

    /// compare_and_swap 用 `parking_lot::Mutex` + `_sync` API 保护原子性（进程内原子）。
    ///
    /// 在单个 `lock()` 作用域内完成 get → compare → set，消除 TOCTOU 竞态。
    /// 用于备份码消费等需要原子 CAS 语义的场景。
    ///
    /// **H3 修复**：原实现用 `tokio::sync::Mutex` + async cache API，跨 await 持锁。
    /// 改为 `parking_lot::Mutex` + `_sync` API，锁内全同步操作（<1μs）。
    ///
    /// 跨进程限制：多进程共享 Redis L2 时仍存在 TOCTOU 竞态
    /// （需 Redis Lua 脚本修复，待引入 Redis L2 后端）。
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
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// keys 用 key_index 实现（oxcache 0.3.3 无原生 keys/iter API）。
    ///
    /// 遍历 key_index，过滤匹配 pattern 的 key，同时惰性清理已过期的 key。
    /// pattern 支持 `*` 通配符（与 MockDao::keys 一致）。
    #[cfg(feature = "dao-key-index")]
    async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
        let actual_pattern = prefixed_key(pattern);
        let mut result = Vec::new();
        let mut expired_keys = Vec::new();

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
            if self.cache.exists_sync(key).unwrap_or(false) {
                result.push(strip_prefix(key));
            } else {
                expired_keys.push(key.clone());
            }
        }

        // 惰性清理过期 key
        if !expired_keys.is_empty() {
            let mut index = self.key_index.write();
            for key in &expired_keys {
                index.remove(key);
            }
            tracing::debug!("keys() 清理了 {} 个过期 key", expired_keys.len());
        }

        Ok(result)
    }
}
