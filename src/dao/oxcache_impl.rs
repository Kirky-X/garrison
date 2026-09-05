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

/// 通配符匹配（支持 `*` 匹配任意字符序列、`?` 匹配单个字符）。
///
/// 用于 `keys()` 方法过滤匹配 pattern 的 key。
/// pattern 如 `"anomalous:login:*"` 匹配 `"anomalous:login:1001:1234567890"`，
/// `"user:?"` 匹配 `"user:1"` 但不匹配 `"user:12"`。
///
/// 实现委托 [`crate::dao::in_memory::glob_match`]（单一事实来源，O(n+m) 双指针算法）：
/// 与 `InMemoryDao::keys`、Redis `KEYS` 的 glob 语义保持一致，消除此前
/// 「`?`/中间 `*` 按字面量处理」的行为分叉（trait 文档承诺支持 `*` 与 `?`）。
///
/// # Feature gate
/// 使用 `dao-key-index`（由 `protocol-apikey` /
/// `anomalous-detector-dual` 传递启用），而非更严格的 `anomalous-detector-dual`，
/// 确保只启用 `protocol-apikey` 的场景 `keys()` 仍可用。
#[cfg(feature = "dao-key-index")]
fn matches_pattern(key: &str, pattern: &str) -> bool {
    super::in_memory::glob_match(pattern, key)
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
    ///
    /// **扩展上限**（性能审查 P2）：此为跨**所有 key** 的单把全局锁——
    /// 六个原子方法在不同 key 上也无法并行（实测 100-task 不同 key 与同 key
    /// 同为全串行）。当前负载（临界区 <1μs、单请求原子操作个位数）不构成
    /// 瓶颈；目标十万级 QPS 前应引入按 key hash 的分片锁（16-64 shard）。
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
        // 默认地址（127.0.0.1:6379）仅在缺配时出现——一次性 warn 显性化降级路径
        config.warn_default_once();
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
        // 进程内原子：将 ttl_sync → set_with_ttl_sync 置于 atomic_mutex 临界区，
        // 避免并发 update / expire 之间的 TOCTOU（T025）。
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
    /// 进程内原子：整体置于 `atomic_mutex` 临界区（T025）。
    /// `ttl_sync` 返回 None 时追加 `exists_sync` 甄别永久键 / 已消失键，
    /// 已消失返回 `Dao("dao-key-missing")` 而非写入永久值（T025）。
    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
        let _guard = self.atomic_mutex.lock();
        let actual_old = prefixed_key(old_key);
        let actual_new = prefixed_key(new_key);
        let value = self
            .cache
            .get_sync(&actual_old)
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-get-sync::{}", e)))?
            .ok_or_else(|| GarrisonError::Dao(format!("dao-key-missing::{}", old_key)))?;
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
                        return Err(GarrisonError::Dao(format!("dao-key-missing::{}", old_key)));
                    }
                    None
                },
            };
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

    /// eval_lua 委托 oxcache 的 `Cache::eval_lua` 执行 Redis Lua 脚本。
    ///
    /// 仅在 `cache-redis` feature 启用时可用（启用 `oxcache/lua` → 编译 `Cache::eval_lua`）。
    /// 将 `redis::Value` 递归转换为 `Vec<String>`，与 `GarrisonDao::eval_lua` 签名对齐。
    ///
    /// 非 Redis 后端（内存模式）调用时返回 `Operation` 错误（oxcache 语义），
    /// 调用方应据此降级到非原子路径。
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
            .map_err(|e| GarrisonError::Dao(format!("dao-oxcache-eval-lua::{}", e)))?;
        Ok(redis_value_to_strings(value))
    }
}

/// 将 `redis::Value` 递归转换为 `Vec<String>`。
///
/// 匹配 redis 1.5 的 `Value` 枚举变体：
/// - `Nil` → 空
/// - `Int(i)` → `[i.to_string()]`
/// - `BulkString(v)` → `[UTF-8 lossy]`
/// - `SimpleString(s)` → `[s]`
/// - `Okay` → `["OK"]`
/// - `Double(d)` → `[d.to_string()]`
/// - `Array/Set` → 递归展平
/// - `Map` → 递归展平 key-value 对
/// - `Attribute` → 递归转换 data 部分
#[cfg(feature = "cache-redis")]
fn redis_value_to_strings(value: redis::Value) -> Vec<String> {
    match value {
        redis::Value::Nil => vec![],
        redis::Value::Int(i) => vec![i.to_string()],
        redis::Value::BulkString(v) => {
            vec![String::from_utf8_lossy(&v).to_string()]
        },
        redis::Value::SimpleString(s) => vec![s],
        redis::Value::Okay => vec!["OK".to_string()],
        redis::Value::Double(d) => vec![d.to_string()],
        redis::Value::Array(items) => items.into_iter().flat_map(redis_value_to_strings).collect(),
        redis::Value::Set(items) => items.into_iter().flat_map(redis_value_to_strings).collect(),
        redis::Value::Map(pairs) => {
            // 预分配：每个 pair 产生 key + value 两个字符串
            let mut result = Vec::with_capacity(pairs.len() * 2);
            for (k, v) in pairs {
                result.extend(redis_value_to_strings(k));
                result.extend(redis_value_to_strings(v));
            }
            result
        },
        redis::Value::Attribute { data, .. } => redis_value_to_strings(*data),
        _ => vec!["[unsupported redis value type]".to_string()],
    }
}

// ============================================================================
// 单元测试（GarrisonDaoOxcache 生产后端实现层）
// ============================================================================
//
// trait 层契约测试见 `mod.rs` 的 `oxcache_tests` / `oxcache_keys_tests`，
// 本模块聚焦本文件私有 helper（`matches_pattern` / `strip_prefix` / `prefixed_key`）
// 与 mod.rs 未覆盖的分支（incr 存在路径 / decr 全路径 / CAS 全路径 /
// check_redis_compat / eval_lua / redis_value_to_strings）。

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // 基础 KV：set 覆盖、TTL 过期、边界 key
    // ------------------------------------------------------------------------

    /// Scenario: 重复 set 覆盖值与新 TTL。
    /// WHEN set("ow","v1",3600) 后再次 set("ow","v2",1)
    /// THEN get 返回 "v2"，且原 3600s TTL 被覆盖为 1s（2 秒后过期）
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

    /// Scenario: 过期后 get 返回 None 且 get_timeout 返回 None。
    /// WHEN set(k, v, 1) 并等待 2 秒
    /// THEN get → None、get_timeout → None（键已消失）
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
        // 空 key
        dao.set("", "empty", 60).await.unwrap();
        assert_eq!(dao.get("").await.unwrap().as_deref(), Some("empty"));
        // 特殊字符（冒号 / 换行 / 引号 / emoji——协议注入类输入）
        let weird = "a:b\nc\"d'e\u{1f4af}";
        dao.set(weird, "v", 60).await.unwrap();
        assert_eq!(dao.get(weird).await.unwrap().as_deref(), Some("v"));
        // 超长 key（4096 字符）
        let long = "k".repeat(4096);
        dao.set(&long, "lv", 60).await.unwrap();
        assert_eq!(dao.get(&long).await.unwrap().as_deref(), Some("lv"));
    }

    // ------------------------------------------------------------------------
    // incr：存在 / 不存在 key、TTL 保留、非数字值
    // ------------------------------------------------------------------------

    /// Scenario: incr 不存在的 key 初始化为 1 并设置 TTL。
    #[tokio::test(flavor = "multi_thread")]
    async fn incr_missing_key_initializes_to_one_with_ttl() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        assert_eq!(dao.incr("ic_new", 60).await.unwrap(), 1);
        assert_eq!(dao.get("ic_new").await.unwrap().as_deref(), Some("1"));
        let ttl = dao.get_timeout("ic_new").await.unwrap();
        assert!(ttl.is_some(), "首次 incr 应设置 TTL");
        assert!(ttl.unwrap() <= Duration::from_secs(60));
    }

    /// Scenario: incr 已存在的 key 递增值且保留原 TTL（不重置窗口）。
    /// WHEN set(k,"5",2) 后 incr(k, 3600)
    /// THEN 返回 6，且 3 秒后键已过期（TTL 保留为原 2s，未被重置为 3600s）
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

    /// Scenario: incr 新 key 且 ttl_seconds=0 时永久驻留。
    #[tokio::test(flavor = "multi_thread")]
    async fn incr_new_key_with_zero_ttl_is_permanent() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        assert_eq!(dao.incr("ic_perm", 0).await.unwrap(), 1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(dao.get("ic_perm").await.unwrap().as_deref(), Some("1"));
        assert!(dao.get_timeout("ic_perm").await.unwrap().is_none());
    }

    /// Rule 12：incr 现存值非 u64 时显式报错（禁止静默重置计数器）。
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

    // ------------------------------------------------------------------------
    // decr：全部分支（missing / 递减 / 归零删除 / 0 值保持 / TTL 保留 / 非数字）
    // ------------------------------------------------------------------------

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

    /// Rule 12：decr 现存值非 u64 时显式报错（与 incr 对称）。
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

    // ------------------------------------------------------------------------
    // compare_and_update_if_greater（HTTP Digest nc 单调性校验）
    // ------------------------------------------------------------------------

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

    /// CAS-greater：现存值非 u64 时显式报错（M1 修复，Rule 12）。
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

    // ------------------------------------------------------------------------
    // compare_and_swap（备份码消费等原子 CAS 场景）
    // ------------------------------------------------------------------------

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
        // 值不匹配
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

    // ------------------------------------------------------------------------
    // 私有 helper：prefixed_key（无 TENANT 上下文时 key 原样返回）
    // ------------------------------------------------------------------------

    /// `prefixed_key` 在 TENANT 上下文不存在时原样返回 key（不 panic）。
    #[tokio::test(flavor = "multi_thread")]
    async fn prefixed_key_without_tenant_context_is_identity() {
        assert_eq!(prefixed_key("plain_key"), "plain_key");
        assert_eq!(prefixed_key(""), "");
    }

    // ------------------------------------------------------------------------
    // 私有 helper + keys() 补充分支（dao-key-index）
    // ------------------------------------------------------------------------

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

        /// `matches_pattern`：`*` 可出现在 pattern 任意位置（中间通配）。
        ///
        /// 与 `InMemoryDao::glob_match` / Redis `KEYS` 语义一致（修复前
        /// 中间 `*` 按字面量处理，属行为分叉）。
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

        /// `matches_pattern`：`?` 匹配单个任意字符（恰一个，不匹配多字符）。
        ///
        /// 与 `InMemoryDao::glob_match` / Redis `KEYS` 语义一致（修复前
        /// `?` 按字面量处理，与 trait 文档「支持 `*` 与 `?`」承诺相悖）。
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

        /// keys() 在 TENANT 上下文内返回去前缀的原始 key 名
        ///（覆盖 `prefixed_key` 带上下文分支 + `strip_prefix` 的 `tenant:` 分支）。
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

    // ------------------------------------------------------------------------
    // cache-redis：check_redis_compat（M4 防护）、eval_lua、redis_value_to_strings
    // ------------------------------------------------------------------------

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

        /// eval_lua 在内存后端（非 Redis）返回 Dao 错误（oxcache Operation 语义），
        /// 调用方应据此降级到非原子路径。
        #[tokio::test(flavor = "multi_thread")]
        async fn eval_lua_on_memory_backend_returns_dao_error() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let result = dao
                .eval_lua("return 1", vec!["el_k".to_string()], vec![])
                .await;
            assert!(
                matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-oxcache-eval-lua")),
                "内存后端 eval_lua 应返回含 'dao-oxcache-eval-lua' 的 Dao 错误，实际: {:?}",
                result
            );
        }

        /// `redis_value_to_strings`：标量变体逐个转换。
        #[test]
        fn redis_value_to_strings_scalars() {
            assert!(
                redis_value_to_strings(redis::Value::Nil).is_empty(),
                "Nil → 空"
            );
            assert_eq!(redis_value_to_strings(redis::Value::Int(-7)), vec!["-7"]);
            assert_eq!(
                redis_value_to_strings(redis::Value::BulkString(b"hello".to_vec())),
                vec!["hello"]
            );
            // 非法 UTF-8 → lossy 替换字符
            assert_eq!(
                redis_value_to_strings(redis::Value::BulkString(vec![0xff])),
                vec!["\u{FFFD}"]
            );
            assert_eq!(
                redis_value_to_strings(redis::Value::SimpleString("PONG".to_string())),
                vec!["PONG"]
            );
            assert_eq!(redis_value_to_strings(redis::Value::Okay), vec!["OK"]);
            assert_eq!(
                redis_value_to_strings(redis::Value::Double(1.5)),
                vec!["1.5"]
            );
        }

        /// `redis_value_to_strings`：复合变体递归展平 + 未支持类型占位符。
        #[test]
        fn redis_value_to_strings_composites_and_fallback() {
            // Array 嵌套展平
            assert_eq!(
                redis_value_to_strings(redis::Value::Array(vec![
                    redis::Value::Int(1),
                    redis::Value::Array(vec![redis::Value::Okay]),
                ])),
                vec!["1", "OK"]
            );
            // Set 展平
            assert_eq!(
                redis_value_to_strings(redis::Value::Set(vec![redis::Value::Int(2)])),
                vec!["2"]
            );
            // Map 递归展平 key-value 对
            assert_eq!(
                redis_value_to_strings(redis::Value::Map(vec![(
                    redis::Value::BulkString(b"k".to_vec()),
                    redis::Value::Int(1),
                )])),
                vec!["k", "1"]
            );
            // Attribute → data 部分
            assert_eq!(
                redis_value_to_strings(redis::Value::Attribute {
                    data: Box::new(redis::Value::Int(9)),
                    attributes: vec![],
                }),
                vec!["9"]
            );
            // 未匹配变体（Boolean 无显式分支）→ 占位符
            assert_eq!(
                redis_value_to_strings(redis::Value::Boolean(true)),
                vec!["[unsupported redis value type]"]
            );
        }
    }
}
