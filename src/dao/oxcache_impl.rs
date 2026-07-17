//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BulwarkDaoOxcache 实现（从 mod.rs 迁移，Rule 25 合规）。

    use super::BulwarkDao;
    #[cfg(feature = "cache-redis")]
    use super::RedisConfig;
    #[cfg(feature = "tenant-isolation")]
    use crate::constants::DaoKeyPrefix;
    use crate::error::{BulwarkError, BulwarkResult};
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
    #[cfg(feature = "anomalous-detector-dual")]
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
    #[cfg(feature = "anomalous-detector-dual")]
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
    /// - Bulwark 自身不实现任何缓存逻辑，全部委托给 oxcache。
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
    pub struct BulwarkDaoOxcache {
        cache: Cache<String, String>,
        /// 原子操作锁，仅用于 `get_and_delete` 的进程内原子性保护。
        /// 其他操作（get/set/delete 等）不持有此锁，不影响并发性能。
        atomic_lock: parking_lot::Mutex<()>,
        /// Redis 部署模式配置（仅在 `cache-redis` feature 启用时存在）。
        ///
        /// 通过 [`with_redis_config`] builder 方法设置。未设置时为 `None`，
        /// oxcache 使用默认 Redis 配置。
        #[cfg(feature = "cache-redis")]
        redis_config: Option<RedisConfig>,
        /// key 索引，用于实现 `keys()` 方法（oxcache 0.3.3 无原生 keys/iter API）。
        /// 仅在 `anomalous-detector-dual` feature 启用时维护，避免影响其他场景的内存开销。
        /// TTL 过期的 key 会在 `keys()` 调用时惰性清理。
        #[cfg(feature = "anomalous-detector-dual")]
        key_index: parking_lot::RwLock<std::collections::HashSet<String>>,
    }

    impl BulwarkDaoOxcache {
        /// 创建默认的 oxcache DAO 实例。
        ///
        /// 启用 `sync_mode(true)` 以支持 `_sync` API。
        ///
        /// # 返回
        /// 已初始化的 `BulwarkDaoOxcache` 实例（内部 `oxcache::Cache` 已就绪，sync_mode 启用）。
        ///
        /// # 错误
        /// - `BulwarkError::Dao`：oxcache 初始化失败（消息含 "oxcache 初始化失败"）。
        pub async fn new() -> BulwarkResult<Self> {
            let cache = Cache::builder()
                .sync_mode(true)
                .build()
                .await
                .map_err(|e| BulwarkError::Dao(format!("oxcache 初始化失败: {}", e)))?;
            Ok(Self {
                cache,
                atomic_lock: parking_lot::Mutex::new(()),
                #[cfg(feature = "cache-redis")]
                redis_config: None,
                #[cfg(feature = "anomalous-detector-dual")]
                key_index: parking_lot::RwLock::new(std::collections::HashSet::new()),
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
            tracing::info!(
                mode = %config.mode,
                db = config.db,
                pool_size = config.pool_size,
                "设置 Redis 部署模式配置"
            );
            self.redis_config = Some(config);
            self
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
    impl BulwarkDao for BulwarkDaoOxcache {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            let actual_key = prefixed_key(key);
            self.cache
                .get_sync(&actual_key)
                .map_err(|e| BulwarkError::Dao(format!("oxcache get_sync 失败: {}", e)))
        }

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            let actual_key = prefixed_key(key);
            let ttl = if ttl_seconds == 0 {
                None
            } else {
                Some(Duration::from_secs(ttl_seconds))
            };
            self.cache
                .set_with_ttl_sync(&actual_key, &value.to_string(), ttl)
                .map_err(|e| BulwarkError::Dao(format!("oxcache set_with_ttl_sync 失败: {}", e)))?;
            #[cfg(feature = "anomalous-detector-dual")]
            self.key_index.write().insert(actual_key);
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            // 通过 cache.ttl_sync() 读取剩余 TTL，用 set_with_ttl_sync 保留原 TTL（不重置过期时间）。
            // ttl_sync() 返回 None 表示永久驻留（set_with_ttl_sync 接受 None 表示无 TTL）。
            // 但 None 也可能表示键不存在，需要先检查键存在性。
            let actual_key = prefixed_key(key);
            if !self
                .cache
                .exists_sync(&actual_key)
                .map_err(|e| BulwarkError::Dao(format!("oxcache exists_sync 失败: {}", e)))?
            {
                return Err(BulwarkError::Dao(format!("键不存在: {}", key)));
            }
            let remaining_ttl = self
                .cache
                .ttl_sync(&actual_key)
                .map_err(|e| BulwarkError::Dao(format!("oxcache ttl_sync 失败: {}", e)))?;
            self.cache
                .set_with_ttl_sync(&actual_key, &value.to_string(), remaining_ttl)
                .map_err(|e| {
                    BulwarkError::Dao(format!("oxcache update (set_with_ttl_sync) 失败: {}", e))
                })
        }

        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            // oxcache 0.3 的 Cache<K,V> 暴露了 expire_sync(key, ttl) 方法（原子更新 TTL，不触碰 value）。
            // expire_sync 返回 bool：true=更新成功，false=键不存在。
            // 注意：seconds=0 表示永久驻留，需要用 get_sync + set_with_ttl_sync(None) 实现
            // （cache.expire_sync(key, Duration::from_secs(0)) 会让键立即过期，不符合 spec 的 0=永久语义）。
            let actual_key = prefixed_key(key);
            if seconds == 0 {
                let value = self
                    .cache
                    .get_sync(&actual_key)
                    .map_err(|e| BulwarkError::Dao(format!("oxcache get_sync 失败: {}", e)))?
                    .ok_or_else(|| BulwarkError::Dao(format!("键不存在: {}", key)))?;
                self.cache
                    .set_with_ttl_sync(&actual_key, &value, None)
                    .map_err(|e| {
                        BulwarkError::Dao(format!("oxcache expire (set_with_ttl_sync) 失败: {}", e))
                    })
            } else {
                let updated = self
                    .cache
                    .expire_sync(&actual_key, Duration::from_secs(seconds))
                    .map_err(|e| BulwarkError::Dao(format!("oxcache expire_sync 失败: {}", e)))?;
                if !updated {
                    return Err(BulwarkError::Dao(format!("键不存在: {}", key)));
                }
                Ok(())
            }
        }

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            let actual_key = prefixed_key(key);
            self.cache
                .delete_sync(&actual_key)
                .map_err(|e| BulwarkError::Dao(format!("oxcache delete_sync 失败: {}", e)))?;
            #[cfg(feature = "anomalous-detector-dual")]
            self.key_index.write().remove(&actual_key);
            Ok(())
        }

        /// set_permanent 用 set_with_ttl_sync(None) 写入永久键。
        ///
        /// 重写默认实现以使用 oxcache 原生"无 TTL"API（避免 ttl=0 歧义）。
        async fn set_permanent(&self, key: &str, value: &str) -> BulwarkResult<()> {
            let actual_key = prefixed_key(key);
            self.cache
                .set_with_ttl_sync(&actual_key, &value.to_string(), None)
                .map_err(|e| BulwarkError::Dao(format!("oxcache set_with_ttl_sync 失败: {}", e)))?;
            #[cfg(feature = "anomalous-detector-dual")]
            self.key_index.write().insert(actual_key);
            Ok(())
        }

        /// get_timeout 用 ttl_sync 查询剩余 TTL。
        ///
        /// oxcache 0.3 的 `ttl_sync(key)` 返回 `Option<Duration>`：
        /// - `Some(remaining)`: 键存在且设置了 TTL
        /// - `None`: 键不存在，或键存在但未设置 TTL（永久驻留）
        async fn get_timeout(&self, key: &str) -> BulwarkResult<Option<Duration>> {
            let actual_key = prefixed_key(key);
            self.cache
                .ttl_sync(&actual_key)
                .map_err(|e| BulwarkError::Dao(format!("oxcache ttl_sync 失败: {}", e)))
        }

        /// rename 用 get → ttl_sync → set_with_ttl_sync → delete 四步。
        ///
        /// 重写默认实现以保留原键 TTL（用 `ttl_sync` 读取剩余 TTL，用 `set_with_ttl_sync` 写入）。
        /// 仍是**非原子**操作（oxcache 0.3.3 无原子 rename API，待 oxcache 提供原子 rename API）。
        async fn rename(&self, old_key: &str, new_key: &str) -> BulwarkResult<()> {
            let actual_old = prefixed_key(old_key);
            let actual_new = prefixed_key(new_key);
            let value = self
                .cache
                .get_sync(&actual_old)
                .map_err(|e| BulwarkError::Dao(format!("oxcache get_sync 失败: {}", e)))?
                .ok_or_else(|| BulwarkError::InvalidParam(format!("键不存在: {}", old_key)))?;
            let remaining_ttl = self
                .cache
                .ttl_sync(&actual_old)
                .map_err(|e| BulwarkError::Dao(format!("oxcache ttl_sync 失败: {}", e)))?;
            self.cache
                .set_with_ttl_sync(&actual_new, &value, remaining_ttl)
                .map_err(|e| BulwarkError::Dao(format!("oxcache set_with_ttl_sync 失败: {}", e)))?;
            self.cache
                .delete_sync(&actual_old)
                .map_err(|e| BulwarkError::Dao(format!("oxcache delete_sync 失败: {}", e)))
        }

        /// get_and_delete 用 `parking_lot::Mutex` 保护 get+delete。
        ///
        /// 进程内原子：同一进程内并发调用同一 key 仅一个返回 `Some`。
        /// 跨进程限制：多进程共享 Redis L2 时，仍存在 TOCTOU 竞态
        /// （需 Redis Lua 脚本 `redis.call('GET',K[1]);redis.call('DEL',K[1])` 修复，待引入 Redis L2 后端）。
        async fn get_and_delete(&self, key: &str) -> BulwarkResult<Option<String>> {
            let _guard = self.atomic_lock.lock();
            let actual_key = prefixed_key(key);
            let value = self
                .cache
                .get_sync(&actual_key)
                .map_err(|e| BulwarkError::Dao(format!("oxcache get_sync 失败: {}", e)))?;
            if value.is_some() {
                self.cache
                    .delete_sync(&actual_key)
                    .map_err(|e| BulwarkError::Dao(format!("oxcache delete_sync 失败: {}", e)))?;
            }
            Ok(value)
        }

        /// incr 用 `parking_lot::Mutex` 保护原子性（进程内原子）。
        ///
        /// 在单个 lock() 作用域内完成 get → set_with_ttl_sync，保证进程内原子。
        /// key 已存在时通过 `ttl_sync` 读取剩余 TTL 并保留（不重置过期时间）。
        async fn incr(&self, key: &str, ttl_seconds: u64) -> BulwarkResult<u64> {
            let _guard = self.atomic_lock.lock();
            let actual_key = prefixed_key(key);
            match self
                .cache
                .get_sync(&actual_key)
                .map_err(|e| BulwarkError::Dao(format!("oxcache get_sync 失败: {}", e)))?
            {
                Some(v) => {
                    // Rule 12：parse 失败必须显式报错，禁止静默返回 0 导致计数器重置
                    let cur_val: u64 = v.parse().map_err(|_| {
                        BulwarkError::Dao(format!(
                            "incr: 现存值非 u64，key={}, value={}",
                            actual_key, v
                        ))
                    })?;
                    let new_val = cur_val + 1;
                    let remaining_ttl = self
                        .cache
                        .ttl_sync(&actual_key)
                        .map_err(|e| BulwarkError::Dao(format!("oxcache ttl_sync 失败: {}", e)))?;
                    self.cache
                        .set_with_ttl_sync(&actual_key, &new_val.to_string(), remaining_ttl)
                        .map_err(|e| {
                            BulwarkError::Dao(format!("oxcache set_with_ttl_sync 失败: {}", e))
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
                            BulwarkError::Dao(format!("oxcache set_with_ttl_sync 失败: {}", e))
                        })?;
                    Ok(1)
                },
            }
        }

        /// keys 用 key_index 实现（oxcache 0.3.3 无原生 keys/iter API）。
        ///
        /// 遍历 key_index，过滤匹配 pattern 的 key，同时惰性清理已过期的 key。
        /// pattern 支持 `*` 通配符（与 MockDao::keys 一致）。
        #[cfg(feature = "anomalous-detector-dual")]
        async fn keys(&self, pattern: &str) -> BulwarkResult<Vec<String>> {
            let actual_pattern = prefixed_key(pattern);
            let mut result = Vec::new();
            let mut expired_keys = Vec::new();

            {
                let index = self.key_index.read();
                for key in index.iter() {
                    if matches_pattern(key, &actual_pattern) {
                        // 检查 key 是否仍然存在（TTL 可能已过期）
                        if self.cache.exists_sync(key).unwrap_or(false) {
                            // 去除 prefix 返回原始 key
                            let raw_key = strip_prefix(key);
                            result.push(raw_key);
                        } else {
                            expired_keys.push(key.clone());
                        }
                    }
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
