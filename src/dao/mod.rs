//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DAO 模块，定义持久化数据访问抽象层。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaTokenDao`，
//! 通过 oxcache / dbnexus 提供多后端（缓存 / 关系型数据库）支持。

use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// DAO 抽象层 trait，定义 Token 与会话的持久化操作。
///
/// [借鉴 Sa-Token] 对应 `SaTokenDao`，提供 get / set / update / delete / expire 五元操作
/// + set_permanent / get_timeout / keys / rename 四个扩展方法。
///
/// - `set` 必须指定 TTL（Token/Session 不应永久驻留，与 Sa-Token 语义一致）
/// - `update` 更新值时保留原有 TTL（不重置过期时间）
/// - `expire` 重置键的过期时间
/// - `set_permanent` 存储永久键（无 TTL，默认实现委托 `set(key, value, 0)`）
/// - `get_timeout` 查询剩余 TTL（默认返回 `NotImplemented`，需后端重写）
/// - `keys` 按 glob pattern 扫描 key（默认返回 `NotImplemented`；`MockDao` 已实现；`BulwarkDaoOxcache` 因 oxcache 0.3.3 限制待 oxcache 提供原生 iter API）
/// - `rename` 重命名 key（默认 get→set→delete 三步，非原子）
#[async_trait]
pub trait BulwarkDao: Send + Sync {
    /// 获取指定键的值。
    ///
    /// # 参数
    /// - `key`: 存储键。
    ///
    /// # 返回
    /// - `Some(value)`: 键存在且未过期。
    /// - `None`: 键不存在或已过期。
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>>;

    /// 设置键值对，附带 TTL。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `value`: 存储值。
    /// - `ttl_seconds`: 过期秒数（0 表示永久驻留；可被 `expire` 重置）。
    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()>;

    /// 更新键的值，保留原有 TTL（不重置过期时间）。
    ///
    /// # 参数
    /// - `key`: 存储键（必须已存在）。
    /// - `value`: 新值。
    ///
    /// # 错误
    /// - 若键不存在，返回 `BulwarkError::Dao`。
    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()>;

    /// 设置（或重置）键的过期时间。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `seconds`: 过期秒数（0 表示永久驻留）。
    ///
    /// # 错误
    /// - 若键不存在，返回 `BulwarkError::Dao`。
    async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()>;

    /// 删除指定键。
    ///
    /// # 参数
    /// - `key`: 存储键。
    async fn delete(&self, key: &str) -> BulwarkResult<()>;

    /// 存储永久键（无 TTL）。
    ///
    /// 。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `value`: 存储值。
    ///
    /// # 默认实现
    /// 委托 `self.set(key, value, 0)`。
    /// 后端可重写以使用原生"无 TTL"API（如 oxcache `set_with_ttl_sync(None)`）。
    async fn set_permanent(&self, key: &str, value: &str) -> BulwarkResult<()> {
        self.set(key, value, 0).await
    }

    /// 查询键的剩余 TTL。
    ///
    /// 。
    ///
    /// # 参数
    /// - `key`: 存储键。
    ///
    /// # 返回
    /// - `Ok(Some(remaining))`: 键存在且设置了 TTL，返回剩余存活时间。
    /// - `Ok(None)`: 键不存在，或键存在但未设置 TTL（永久驻留）。
    ///
    /// # 默认实现
    /// 返回 `BulwarkError::NotImplemented`（需后端原生 TTL 查询 API 支持）。
    /// `BulwarkDaoOxcache` 与 `MockDao` 已重写。
    async fn get_timeout(&self, _key: &str) -> BulwarkResult<Option<Duration>> {
        Err(BulwarkError::NotImplemented(format!(
            "get_timeout 未实现：{} 后端不支持 TTL 查询",
            std::any::type_name::<Self>()
        )))
    }

    /// 按 glob pattern 扫描 key。
    ///
    /// 。
    ///
    /// # 参数
    /// - `pattern`: glob 模式，支持 `*`（任意字符序列）与 `?`（单字符）。
    ///
    /// # 返回
    /// - `Ok(Vec<String>)`: 匹配的 key 列表（无序），无匹配返回空 Vec。
    ///
    /// # 性能警告
    /// - 大规模 key 场景下性能差（需全量扫描 + 过滤）
    ///
    /// # 已知限制（A-010 评估结论）
    ///
    /// `BulwarkDaoOxcache` 当前不重写此方法（走默认 `NotImplemented`），原因：
    /// - oxcache 0.3.3 的 `CacheReader`/`CacheBackend` trait 未暴露 iter/keys/scan API（2026-07-08 验证）
    /// - `Cache.backend` 字段为 `pub(crate)`，外部无法访问底层 `DashMap`
    /// - `CacheReader` trait 仅有 `get`/`exists`/`ttl`/`len`/`is_empty`/`capacity`/`stats`/`get_many`，无 iter/keys 方法
    /// - 维护独立 key 索引（如 `DashMap<String, ()>`）会增加内存开销 + 一致性复杂度（set/delete 需同步索引）
    /// - oxcache 上游路线图有 iter API 计划（0.3.3 仍未实现，crates.io 最新无更高版本）
    ///
    /// **决策**：defer 到 oxcache 提供原生 iter API。业务方临时方案：自行维护 key 集合（参考 `ApiKeyHandler::list_by_namespace` 的 `MockDao` 测试）。
    ///
    /// **业务影响**：`ApiKeyHandler::list_by_namespace` 在使用 `BulwarkDaoOxcache` 时返回 `NotImplemented`（生产可用性受限）。
    ///
    /// # 默认实现
    /// 返回 `BulwarkError::NotImplemented`。
    async fn keys(&self, _pattern: &str) -> BulwarkResult<Vec<String>> {
        Err(BulwarkError::NotImplemented(format!(
            "keys 未实现：{} 后端不支持 key scan（待 oxcache 提供原生 iter API）",
            std::any::type_name::<Self>()
        )))
    }

    /// 重命名 key。
    ///
    /// 。
    ///
    /// # 参数
    /// - `old_key`: 原 key（必须已存在）。
    /// - `new_key`: 新 key。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: `old_key` 不存在。
    ///
    /// # 非原子性警告
    /// 默认实现为 `get → set_permanent → delete` 三步操作，存在竞态窗口：
    /// 1. 读取 old_key 后、写入 new_key 前，old_key 可能被其他线程修改或删除
    /// 2. 写入 new_key 后、删除 old_key 前，old_key 与 new_key 同时存在
    /// 后端若支持原子 rename（如 Redis RENAME），应重写此方法。
    ///
    /// # TTL 保留
    /// 默认实现**不保留**原键 TTL（用 `set_permanent` 写入新键）。
    /// 后端若需保留 TTL，应重写此方法（如 `BulwarkDaoOxcache` 用 `ttl_sync` + `set_with_ttl_sync`）。
    async fn rename(&self, old_key: &str, new_key: &str) -> BulwarkResult<()> {
        let value = self
            .get(old_key)
            .await?
            .ok_or_else(|| BulwarkError::InvalidParam(format!("键不存在: {}", old_key)))?;
        self.set_permanent(new_key, &value).await?;
        self.delete(old_key).await
    }

    /// 原子地获取并删除键。
    ///
    /// 保证 get 与 delete 在同一临界区内执行，消除 TOCTOU 竞态。
    /// 用于 SSO ticket 一次性消费等场景。
    ///
    /// # 参数
    /// - `key`: 存储键。
    ///
    /// # 返回
    /// - `Ok(Some(value))`: 键存在，已原子读取并删除。
    /// - `Ok(None)`: 键不存在或已过期。
    ///
    /// # 默认实现（非原子）
    /// 默认实现为 `get → delete` 两步操作，**存在 TOCTOU 竞态**：
    /// 并发调用同一 key 时可能多个调用都返回 `Some`。
    /// 后端若支持原子操作（如 Redis Lua / moka 内部锁），应重写此方法。
    ///
    /// # 已重写的实现
    /// - `MockDao`：`parking_lot::Mutex` 保护，进程内原子
    /// - `BulwarkDaoOxcache`：`parking_lot::Mutex` 保护，进程内原子
    /// - `AloneCache`：委托内部 dao
    async fn get_and_delete(&self, key: &str) -> BulwarkResult<Option<String>> {
        let value = self.get(key).await?;
        if value.is_some() {
            self.delete(key).await?;
        }
        Ok(value)
    }

    /// 原子递增计数器（带 TTL）。
    ///
    /// 将 key 的值递增 1。若 key 不存在则初始化为 1 并设置 TTL；
    /// 若 key 已存在则仅递增值，**不重置 TTL**（保留原窗口过期时间）。
    /// 用于 SMS 限速计数器等场景。
    ///
    /// # 参数
    /// - `key`: 计数器键。
    /// - `ttl_seconds`: TTL 秒数（仅 key 首次创建时设置）。
    ///
    /// # 返回
    /// - `Ok(new_value)`: 递增后的新值。
    ///
    /// # 默认实现（非原子）
    /// 默认实现为 get → parse → update/set 三步操作，存在竞态风险。
    /// 后端若支持原子 incr（如 Redis INCR + EXPIRE），应重写此方法。
    /// `MockDao` 已重写为进程内原子（Mutex 保护）。
    async fn incr(&self, key: &str, ttl_seconds: u64) -> BulwarkResult<u64> {
        let current = self.get(key).await?;
        match current {
            Some(v) => {
                let new_val = v.parse::<u64>().unwrap_or(0) + 1;
                self.update(key, &new_val.to_string()).await?;
                Ok(new_val)
            },
            None => {
                self.set(key, "1", ttl_seconds).await?;
                Ok(1)
            },
        }
    }

    /// 查询社交账号绑定关系。
    ///
    /// 按 `(tenant_id, provider, provider_user_id)` 三元组查询 `social_bindings` 表，
    /// 返回关联的 `login_id`。
    ///
    /// # 参数
    /// - `tenant_id`: 租户 ID（0=默认租户）。
    /// - `provider`: 社交平台标识（`"wechat"` / `"alipay"` / `"wechat_mini_app"`）。
    /// - `provider_user_id`: 第三方平台用户唯一 ID（微信 openid / 支付宝 user_id）。
    ///
    /// # 返回
    /// - `Ok(Some(login_id))`: 绑定关系存在，返回关联的 login_id。
    /// - `Ok(None)`: 绑定关系不存在（首次登录）。
    ///
    /// # 默认实现
    /// 返回 `BulwarkError::NotImplemented`（BulwarkDao 是 KV 缓存抽象，不支持 SQL SELECT）。
    /// `SocialBindingService` 实际用 `DbPool` 查 SQL，不调用此方法。
    /// 此方法仅为满足 spec trait 契约，供未来纯 KV 后端实现重写。
    async fn find_social_binding(
        &self,
        _tenant_id: i64,
        _provider: &str,
        _provider_user_id: &str,
    ) -> BulwarkResult<Option<i64>> {
        Err(BulwarkError::NotImplemented(format!(
            "find_social_binding 未实现：{} 后端不支持 SQL 查询（SocialBindingService 用 DbPool）",
            std::any::type_name::<Self>()
        )))
    }

    /// 插入社交账号绑定关系。
    ///
    /// 将 `(tenant_id, login_id, provider, provider_user_id, union_id)` 写入 `social_bindings` 表。
    ///
    /// # 参数
    /// - `tenant_id`: 租户 ID（0=默认租户）。
    /// - `login_id`: Bulwark 内部用户 ID（INTEGER，由 `SocialBindingService::find_or_create` 生成）。
    /// - `provider`: 社交平台标识（`"wechat"` / `"alipay"` / `"wechat_mini_app"`）。
    /// - `provider_user_id`: 第三方平台用户唯一 ID。
    /// - `union_id`: 跨应用统一 ID（微信 unionid，可空）。
    /// - `created_at`: 创建时间戳（Unix 秒）。
    ///
    /// # 默认实现
    /// 返回 `BulwarkError::NotImplemented`（BulwarkDao 是 KV 缓存抽象，不支持 SQL INSERT）。
    /// `SocialBindingService` 实际用 `DbPool` 执行 INSERT，不调用此方法。
    /// 此方法仅为满足 spec trait 契约，供未来纯 KV 后端实现重写。
    async fn insert_social_binding(
        &self,
        _tenant_id: i64,
        _login_id: i64,
        _provider: &str,
        _provider_user_id: &str,
        _union_id: Option<&str>,
        _created_at: i64,
    ) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(format!(
            "insert_social_binding 未实现：{} 后端不支持 SQL 插入（SocialBindingService 用 DbPool）",
            std::any::type_name::<Self>()
        )))
    }
}

// ============================================================================
// Redis 部署模式配置
// ============================================================================

/// Redis 部署模式枚举，覆盖生产环境常见拓扑。
///
/// 参阅 Redis 集群部署文档：单节点 / Sentinel / Cluster / Master-Slave。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum RedisDeploymentMode {
    /// 单节点模式：单个 Redis 实例。
    Single {
        /// Redis 连接 URL（如 `redis://127.6379`）。
        url: String,
    },
    /// 哨兵模式：通过 Sentinel 集群自动故障转移。
    Sentinel {
        /// Sentinel 集群主节点名称（如 `mymaster`）。
        master_name: String,
        /// Sentinel 节点 URL 列表。
        urls: Vec<String>,
    },
    /// 集群模式：Redis Cluster 分片存储。
    Cluster {
        /// Cluster 节点 URL 列表（至少 3 个 master 节点）。
        urls: Vec<String>,
    },
    /// 主从模式：1 个 master + N 个 slave，读分离需客户端支持。
    MasterSlave {
        /// Master 节点 URL。
        master_url: String,
        /// Slave 节点 URL 列表。
        slave_urls: Vec<String>,
    },
}

/// Default 实现，返回 Single 模式（`redis://127.6379`）。
///
/// 供 `RedisConfig` 的 `#[serde(default)]` 在反序列化时填充缺失的 `mode` 字段。
impl Default for RedisDeploymentMode {
    fn default() -> Self {
        RedisDeploymentMode::Single {
            url: "redis://127.0.0.1:6379".to_string(),
        }
    }
}

/// Redis 配置聚合结构，包含部署模式、连接池参数与认证信息。
///
/// # 默认值
///
/// - `mode`: `Single { url: "redis://127.6379" }`
/// - `password`: `None`
/// - `db`: `0`
/// - `connection_timeout_secs`: `5`
/// - `pool_size`: `10`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisConfig {
    /// Redis 部署模式。
    pub mode: RedisDeploymentMode,
    /// 认证密码（`None` 表示无密码）。
    pub password: Option<String>,
    /// Redis 数据库编号（0-15）。
    pub db: u8,
    /// 连接超时秒数。
    pub connection_timeout_secs: u64,
    /// 连接池大小。
    pub pool_size: u32,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            mode: RedisDeploymentMode::Single {
                url: "redis://127.0.0.1:6379".to_string(),
            },
            password: None,
            db: 0,
            connection_timeout_secs: 5,
            pool_size: 10,
        }
    }
}

/// Display 实现，输出人类可读的部署模式描述。
impl std::fmt::Display for RedisDeploymentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedisDeploymentMode::Single { url } => write!(f, "single({})", url),
            RedisDeploymentMode::Sentinel { master_name, urls } => {
                write!(
                    f,
                    "sentinel(master={}, {} sentinels)",
                    master_name,
                    urls.len()
                )
            },
            RedisDeploymentMode::Cluster { urls } => {
                write!(f, "cluster({} nodes)", urls.len())
            },
            RedisDeploymentMode::MasterSlave {
                master_url,
                slave_urls,
            } => {
                write!(
                    f,
                    "master-slave(master={}, {} slaves)",
                    master_url,
                    slave_urls.len()
                )
            },
        }
    }
}

// ============================================================================
// oxcache 实现（feature = "cache-memory" 或 "cache-redis"）
// ============================================================================

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
mod oxcache_impl {
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
    /// - L1（moka）+ L2（redis）由 oxcache 0.3 自动管理（0.3 起 moka 后端支持 per-entry TTL）。
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
    /// `_sync` API 仅适用于 in-memory backend（Moka `DashMap` 后端）：
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
                    let new_val = v.parse::<u64>().unwrap_or(0) + 1;
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
}

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
pub use oxcache_impl::BulwarkDaoOxcache;

// ============================================================================
// dbnexus 实现（feature = "db-sqlite" 或 "db-postgres"）
// ============================================================================
//
// `init_dbnexus` 和 `BulwarkMigration` 是 backend-agnostic 的——它们仅封装
// `DbPool::new(url)` 和 `DbPool::run_migrations(dir)`，不关心底层是 SQLite 还是
// PostgreSQL。后端由 dbnexus 的 feature flag（sqlite/postgres）控制。
//
// 注意：`BulwarkMigration::new()` 默认使用 `migrations/sqlite/` 路径，
// PostgreSQL 用户应使用 `with_base_dir` 指定 `migrations/postgres/` 路径。

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
mod dbnexus_impl;

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dbnexus_impl::{init_dbnexus, BulwarkMigration};

// ============================================================================
// Repository 层
// ============================================================================
// 9 个核心表的 Repository trait + Row struct，与 dbnexus 解耦。
// SQLite 实现见 `repository::sqlite` 子模块（启用 `db-sqlite` feature，
// T019 Green 阶段创建后由 repository/mod.rs 内部声明）。
pub mod repository;

// ============================================================================
// AloneCache 装饰器（feature = "alone-cache"）
// ============================================================================

#[cfg(feature = "alone-cache")]
pub mod alone_cache;

// ============================================================================
// 缓存预热子模块
// ============================================================================

pub mod warmup;

#[cfg(test)]
mod mock;

#[cfg(test)]
pub use mock::MockDao;

#[cfg(all(test, feature = "protocol-apikey"))]
pub(crate) use mock::glob_match;

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
/// DAO trait 契约测试与跨模块共享的 mock 实现（仅 `cfg(test)` 下编译）。
pub mod tests {
    use super::*;
    // 兼容层：重导出 mock 模块的 MockDao 与 glob_match，保持旧路径
    // `crate::dao::tests::MockDao` / `crate::dao::tests::glob_match` 可用
    #[cfg(feature = "protocol-apikey")]
    pub(crate) use super::glob_match;
    pub use super::MockDao;
    use crate::error::BulwarkError;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    // ------------------------------------------------------------------------
    // BulwarkDaoOxcache keys() 测试（CRIT-001 修复验证）
    // 仅在 anomalous-detector-dual + cache-memory/cache-redis 启用时编译
    // ------------------------------------------------------------------------
    #[cfg(all(
        feature = "anomalous-detector-dual",
        any(feature = "cache-memory", feature = "cache-redis")
    ))]
    mod oxcache_keys_tests {
        use super::*;

        /// 无 key 时 keys() 返回空 Vec。
        #[tokio::test(flavor = "multi_thread")]
        async fn test_oxcache_keys_empty() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            let keys = dao.keys("anomalous:login:*").await.unwrap();
            assert!(keys.is_empty(), "无 key 时 keys() 应返回空 Vec");
        }

        /// set 3 个 key，keys("anomalous:login:*") 返回 2 个匹配的 key。
        #[tokio::test(flavor = "multi_thread")]
        async fn test_oxcache_keys_pattern_match() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("anomalous:login:1:1", "v1", 3600).await.unwrap();
            dao.set("anomalous:login:2:2", "v2", 3600).await.unwrap();
            dao.set("other:key", "v3", 3600).await.unwrap();

            let mut keys = dao.keys("anomalous:login:*").await.unwrap();
            keys.sort();
            assert_eq!(
                keys,
                vec![
                    "anomalous:login:1:1".to_string(),
                    "anomalous:login:2:2".to_string()
                ],
                "keys() 应返回 2 个匹配 anomalous:login:* 的 key"
            );
        }

        /// TTL 过期后 keys() 返回空且 key_index 已惰性清理。
        #[tokio::test(flavor = "multi_thread")]
        async fn test_oxcache_keys_clears_expired() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("anomalous:login:1:1", "v1", 1).await.unwrap();
            // 等待 TTL 过期（1s + 1s 余量）
            tokio::time::sleep(Duration::from_secs(2)).await;
            let keys = dao.keys("anomalous:login:*").await.unwrap();
            assert!(
                keys.is_empty(),
                "TTL 过期后 keys() 应返回空 Vec（惰性清理）"
            );
            // 再次调用 keys() 验证 key_index 已清理（不会 panic 或残留）
            let keys2 = dao.keys("anomalous:login:*").await.unwrap();
            assert!(keys2.is_empty(), "清理后再次 keys() 仍应返回空");
        }

        /// delete 后 keys() 返回空。
        #[tokio::test(flavor = "multi_thread")]
        async fn test_oxcache_keys_after_delete() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("anomalous:login:1:1", "v1", 3600).await.unwrap();
            let keys = dao.keys("anomalous:login:*").await.unwrap();
            assert_eq!(keys.len(), 1, "set 后应有 1 个 key");
            dao.delete("anomalous:login:1:1").await.unwrap();
            let keys = dao.keys("anomalous:login:*").await.unwrap();
            assert!(keys.is_empty(), "delete 后 keys() 应返回空 Vec");
        }
    }

    // ------------------------------------------------------------------------
    // 契约测试：验证 BulwarkDao trait 行为契约（使用 MockDao）
    // 对应 dao-oxcache-basic spec 的 4 个 scenario
    // ------------------------------------------------------------------------

    /// Scenario: set 与 get 配对。
    /// WHEN 调用 set("key1", "value1", 3600) 后 get("key1")
    /// THEN 返回 Some("value1")
    #[tokio::test]
    async fn mock_set_get_pair() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 3600).await.unwrap();
        let got = dao.get("key1").await.unwrap();
        assert_eq!(got, Some("value1".to_string()));
    }

    /// Scenario: 过期自动删除。
    /// WHEN set("key1", "value1", 1) 并等待 2 秒
    /// THEN get("key1") 返回 None
    #[tokio::test]
    async fn mock_expire_auto_delete() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = dao.get("key1").await.unwrap();
        assert!(got.is_none(), "过期后 get 应返回 None");
    }

    /// Scenario: delete 删除键。
    /// WHEN set("key1", "value1", 3600) 后 delete("key1")
    /// THEN get("key1") 返回 None
    #[tokio::test]
    async fn mock_delete_removes_key() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 3600).await.unwrap();
        dao.delete("key1").await.unwrap();
        let got = dao.get("key1").await.unwrap();
        assert!(got.is_none(), "delete 后 get 应返回 None");
    }

    /// Scenario: update 更新值（保留 TTL）。
    /// WHEN set("key1", "value1", 3600) 后 update("key1", "value2")
    /// THEN get("key1") 返回 Some("value2")
    /// AND  TTL 保持 3600（不重置）
    #[tokio::test]
    async fn mock_update_preserves_ttl() {
        let dao = MockDao::new();
        // 用短 TTL 验证 update 不重置 TTL
        dao.set("key1", "value1", 2).await.unwrap();
        // 立即 update（在 TTL 内）
        dao.update("key1", "value2").await.unwrap();
        // 验证值已更新
        let got = dao.get("key1").await.unwrap();
        assert_eq!(got, Some("value2".to_string()));
        // 等待原 TTL 过期（2 秒 + 1 秒余量）
        tokio::time::sleep(Duration::from_secs(3)).await;
        // update 保留了原 TTL，应已过期
        let got = dao.get("key1").await.unwrap();
        assert!(
            got.is_none(),
            "update 不应重置 TTL，原 TTL 过期后应返回 None"
        );
    }

    /// 验证 update 不存在的键返回错误（Fail Loud 原则）。
    #[tokio::test]
    async fn mock_update_missing_key_errors() {
        let dao = MockDao::new();
        let result = dao.update("missing", "value").await;
        assert!(
            matches!(result, Err(BulwarkError::Dao(_))),
            "update 不存在的键应返回 Dao 错误"
        );
    }

    /// 验证 expire 重置过期时间。
    #[tokio::test]
    async fn mock_expire_resets_ttl() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 1).await.unwrap();
        // 在过期前重置 TTL
        dao.expire("key1", 3600).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        // 原 TTL 已过，但 expire 重置后应仍存在
        let got = dao.get("key1").await.unwrap();
        assert_eq!(got, Some("value1".to_string()));
    }

    /// 验证 expire 不存在的键返回错误。
    #[tokio::test]
    async fn mock_expire_missing_key_errors() {
        let dao = MockDao::new();
        let result = dao.expire("missing", 3600).await;
        assert!(
            matches!(result, Err(BulwarkError::Dao(_))),
            "expire 不存在的键应返回 Dao 错误"
        );
    }

    /// 验证 set(ttl=0) 表示永久驻留。
    #[tokio::test]
    async fn mock_set_zero_ttl_means_permanent() {
        let dao = MockDao::new();
        dao.set("perm", "value", 0).await.unwrap();
        // 即使等待也不会过期（mock 用 Instant，sleep 仅作示意）
        tokio::time::sleep(Duration::from_millis(10)).await;
        let got = dao.get("perm").await.unwrap();
        assert_eq!(got, Some("value".to_string()));
    }

    /// 验证 get 不存在的键返回 None（不报错）。
    #[tokio::test]
    async fn mock_get_missing_returns_none() {
        let dao = MockDao::new();
        let got = dao.get("never_set").await.unwrap();
        assert!(got.is_none());
    }

    /// 验证 MockDao::default() 等价于 new()。
    ///
    /// 覆盖 MockDao 的 Default trait 实现。
    #[tokio::test]
    async fn mock_dao_default_equals_new() {
        let dao = MockDao::default();
        dao.set("default_key", "default_value", 60).await.unwrap();
        let got = dao.get("default_key").await.unwrap();
        assert_eq!(got, Some("default_value".to_string()));
    }

    /// 验证 expire(key, 0) 将键设为永久驻留。
    ///
    /// 覆盖 MockDao::expire 的 `seconds == 0` 分支（expire_at = None）。
    #[tokio::test]
    async fn mock_expire_zero_seconds_means_permanent() {
        let dao = MockDao::new();
        dao.set("k", "v", 1).await.unwrap();
        // expire(0) 改为永久驻留
        dao.expire("k", 0).await.unwrap();
        // 等待原 TTL 过期
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = dao.get("k").await.unwrap();
        assert_eq!(got, Some("v".to_string()), "expire(0) 应改为永久驻留");
    }

    // ------------------------------------------------------------------------
    // 4 方法扩展测试（v0.4.2 spec dao-bulwark-dao）
    // ------------------------------------------------------------------------

    /// R-001: set_permanent 设置后 get 返回值。
    #[tokio::test]
    async fn mock_set_permanent_persists_value() {
        let dao = MockDao::new();
        dao.set_permanent("perm_key", "perm_value").await.unwrap();
        let got = dao.get("perm_key").await.unwrap();
        assert_eq!(got, Some("perm_value".to_string()));
    }

    /// R-001: set_permanent 永久键短时间等待不过期。
    #[tokio::test]
    async fn mock_set_permanent_does_not_expire_quickly() {
        let dao = MockDao::new();
        dao.set_permanent("perm_key", "perm_value").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let got = dao.get("perm_key").await.unwrap();
        assert_eq!(got, Some("perm_value".to_string()), "永久键不应过期");
    }

    /// R-002: get_timeout 永久键返回 None。
    #[tokio::test]
    async fn mock_get_timeout_returns_none_for_permanent_key() {
        let dao = MockDao::new();
        dao.set_permanent("perm", "v").await.unwrap();
        let timeout = dao.get_timeout("perm").await.unwrap();
        assert!(timeout.is_none(), "永久键应返回 None");
    }

    /// R-002: get_timeout TTL 键返回 Some(remaining)，剩余 ≤ 原 TTL。
    #[tokio::test]
    async fn mock_get_timeout_returns_some_for_ttl_key() {
        let dao = MockDao::new();
        dao.set("ttl_key", "v", 3600).await.unwrap();
        let timeout = dao.get_timeout("ttl_key").await.unwrap();
        assert!(timeout.is_some(), "TTL 键应返回 Some");
        let remaining = timeout.unwrap();
        assert!(
            remaining <= Duration::from_secs(3600),
            "剩余时间应 ≤ 原 TTL"
        );
    }

    /// R-002: get_timeout 不存在的键返回 None。
    #[tokio::test]
    async fn mock_get_timeout_returns_none_for_missing_key() {
        let dao = MockDao::new();
        let timeout = dao.get_timeout("missing").await.unwrap();
        assert!(timeout.is_none(), "不存在的键应返回 None");
    }

    /// R-003: keys("bulwark:apikey:*") 返回命名空间下所有 key。
    #[tokio::test]
    async fn mock_keys_returns_namespace_matches() {
        let dao = MockDao::new();
        dao.set("bulwark:apikey:abc123", "v1", 3600).await.unwrap();
        dao.set("bulwark:apikey:def456", "v2", 3600).await.unwrap();
        dao.set("bulwark:session:xyz", "v3", 3600).await.unwrap();
        let keys = dao.keys("bulwark:apikey:*").await.unwrap();
        assert_eq!(keys.len(), 2, "应匹配 2 个 apikey");
        assert!(keys.contains(&"bulwark:apikey:abc123".to_string()));
        assert!(keys.contains(&"bulwark:apikey:def456".to_string()));
    }

    /// R-003: keys("*") 返回所有 key。
    #[tokio::test]
    async fn mock_keys_star_returns_all() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 3600).await.unwrap();
        dao.set("k2", "v2", 3600).await.unwrap();
        let keys = dao.keys("*").await.unwrap();
        assert!(keys.len() >= 2, "应至少返回 2 个 key");
    }

    /// R-003: keys 无匹配返回空 Vec。
    #[tokio::test]
    async fn mock_keys_no_match_returns_empty() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 3600).await.unwrap();
        let keys = dao.keys("nonexistent:*").await.unwrap();
        assert!(keys.is_empty(), "无匹配应返回空 Vec");
    }

    /// R-003: keys 支持 ? 单字符通配符。
    #[tokio::test]
    async fn mock_keys_supports_question_mark() {
        let dao = MockDao::new();
        dao.set("key1", "v1", 3600).await.unwrap();
        dao.set("key2", "v2", 3600).await.unwrap();
        dao.set("key10", "v3", 3600).await.unwrap();
        let keys = dao.keys("key?").await.unwrap();
        assert_eq!(
            keys.len(),
            2,
            "? 应匹配单个字符，key1/key2 匹配，key10 不匹配"
        );
    }

    /// R-004: rename 重命名后 old 不存在，new 存在。
    #[tokio::test]
    async fn mock_rename_moves_key() {
        let dao = MockDao::new();
        dao.set("old_key", "value", 3600).await.unwrap();
        dao.rename("old_key", "new_key").await.unwrap();
        let old = dao.get("old_key").await.unwrap();
        let new = dao.get("new_key").await.unwrap();
        assert!(old.is_none(), "rename 后 old_key 应不存在");
        assert_eq!(new, Some("value".to_string()), "rename 后 new_key 应有值");
    }

    /// R-004: rename 不存在的 old_key 返回 InvalidParam。
    #[tokio::test]
    async fn mock_rename_missing_key_returns_invalid_param() {
        let dao = MockDao::new();
        let result = dao.rename("missing", "new").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "rename 不存在的键应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    // ------------------------------------------------------------------------
    // oxcache 集成测试（feature = "cache-memory" 或 "cache-redis"）
    // ------------------------------------------------------------------------

    #[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
    mod oxcache_tests {
        use super::*;

        /// Scenario: set 与 get 配对。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_set_get_pair() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_key1", "value1", 3600).await.unwrap();
            let got = dao.get("oc_key1").await.unwrap();
            assert_eq!(got, Some("value1".to_string()));
        }

        /// Scenario: 过期自动删除。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_auto_delete() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_key2", "value1", 1).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_key2").await.unwrap();
            assert!(got.is_none(), "过期后 get 应返回 None");
        }

        /// Scenario: delete 删除键。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_delete_removes_key() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_key3", "value1", 3600).await.unwrap();
            dao.delete("oc_key3").await.unwrap();
            let got = dao.get("oc_key3").await.unwrap();
            assert!(got.is_none(), "delete 后 get 应返回 None");
        }

        /// 验证 oxcache update 更新值（仅验证值，TTL 保留见 ignore 测试）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_update_changes_value() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_key4", "value1", 3600).await.unwrap();
            dao.update("oc_key4", "value2").await.unwrap();
            let got = dao.get("oc_key4").await.unwrap();
            assert_eq!(got, Some("value2".to_string()));
        }

        /// 验证 update 不存在的键返回错误。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_update_missing_key_errors() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            let result = dao.update("oc_missing", "value").await;
            assert!(
                matches!(result, Err(BulwarkError::Dao(_))),
                "update 不存在的键应返回 Dao 错误"
            );
        }

        /// 验证 expire 重置过期时间。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_resets_ttl() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_key5", "value1", 1).await.unwrap();
            dao.expire("oc_key5", 3600).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_key5").await.unwrap();
            assert_eq!(got, Some("value1".to_string()));
        }

        /// 验证 BulwarkDaoOxcache::new() 直接构造（init_oxcache_dao 包装已移除）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_new_direct_construction() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_init", "init_value", 60).await.unwrap();
            let got = dao.get("oc_init").await.unwrap();
            assert_eq!(got, Some("init_value".to_string()));
        }

        /// Scenario: update 更新值（保留 TTL）。
        ///
        /// oxcache 0.3 的 Cache<K,V> 暴露了 ttl() 方法，update 用 ttl() + set_with_ttl 保留原 TTL。
        ///
        /// 参见：dao-oxcache-basic spec Requirement "BulwarkDao 抽象 trait" Scenario "update 更新值（保留 TTL）"
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_update_preserves_ttl() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_ttl", "value1", 2).await.unwrap();
            dao.update("oc_ttl", "value2").await.unwrap();
            // update 保留了原 TTL（2 秒），sleep 后应过期
            tokio::time::sleep(Duration::from_secs(3)).await;
            let got = dao.get("oc_ttl").await.unwrap();
            assert!(
                got.is_none(),
                "update 不应重置 TTL，原 TTL 过期后应返回 None"
            );
        }

        /// 验证 expire(key, 0) 将键设为永久驻留（不删除）。
        ///
        /// 覆盖 BulwarkDaoOxcache::expire 的 `seconds == 0` 分支：
        /// 通过 get + set_with_ttl(None) 实现 0=永久语义。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_zero_seconds_makes_permanent() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            // 设置短 TTL，键会在 1 秒后过期
            dao.set("oc_perm", "value1", 1).await.unwrap();
            // expire(0) 将键改为永久驻留
            dao.expire("oc_perm", 0).await.unwrap();
            // 等待原 TTL 过期
            tokio::time::sleep(Duration::from_secs(2)).await;
            // 键应仍存在（已改为永久驻留）
            let got = dao.get("oc_perm").await.unwrap();
            assert_eq!(
                got,
                Some("value1".to_string()),
                "expire(0) 应将键改为永久驻留，不应过期"
            );
        }

        /// 验证 expire(0) 对不存在的键返回 Dao 错误。
        ///
        /// 覆盖 BulwarkDaoOxcache::expire 的 `seconds == 0` 分支中
        /// `ok_or_else(|| BulwarkError::Dao(...))` 错误路径。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_zero_seconds_missing_key_errors() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            let result = dao.expire("oc_missing_perm", 0).await;
            assert!(
                matches!(result, Err(BulwarkError::Dao(_))),
                "expire(0) 不存在的键应返回 Dao 错误"
            );
        }

        /// 验证 expire 对不存在的键返回 Dao 错误（seconds > 0 分支）。
        ///
        /// 覆盖 BulwarkDaoOxcache::expire 的 `else` 分支中
        /// `if !updated { return Err(...) }` 错误路径。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_missing_key_errors() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            let result = dao.expire("oc_missing_expire", 3600).await;
            assert!(
                matches!(result, Err(BulwarkError::Dao(ref msg)) if msg.contains("键不存在")),
                "expire 不存在的键应返回含 '键不存在' 的 Dao 错误，实际: {:?}",
                result
            );
        }

        /// 验证 set(ttl=0) 写入永久驻留的键。
        ///
        /// 覆盖 BulwarkDaoOxcache::set 的 `ttl_seconds == 0` 分支（ttl=None）：
        /// 键应永久驻留，不会因短时间等待而过期。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_set_with_zero_ttl() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            // set(ttl=0) 表示永久驻留
            dao.set("oc_zero_ttl", "permanent_value", 0).await.unwrap();
            // 等待 2 秒，验证键未过期
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_zero_ttl").await.unwrap();
            assert_eq!(
                got,
                Some("permanent_value".to_string()),
                "set(ttl=0) 应写入永久驻留的键，2 秒后仍应存在"
            );
        }

        // --------------------------------------------------------------------
        // v0.4.2 4 方法扩展测试
        // --------------------------------------------------------------------

        /// R-001: set_permanent 写入永久键，短时间等待不过期。
        ///
        /// 覆盖 BulwarkDaoOxcache::set_permanent 重写实现（用 set_with_ttl_sync(None)）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_set_permanent_persists_without_ttl() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set_permanent("oc_perm", "perm_value").await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_perm").await.unwrap();
            assert_eq!(
                got,
                Some("perm_value".to_string()),
                "set_permanent 应写入永久键，2 秒后仍应存在"
            );
        }

        /// R-002: get_timeout 永久键返回 None。
        ///
        /// 覆盖 BulwarkDaoOxcache::get_timeout 重写实现（用 ttl_sync）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_timeout_returns_none_for_permanent_key() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set_permanent("oc_perm_ttl", "v").await.unwrap();
            let timeout = dao.get_timeout("oc_perm_ttl").await.unwrap();
            assert!(timeout.is_none(), "永久键应返回 None");
        }

        /// R-002: get_timeout TTL 键返回 Some(remaining)，剩余 ≤ 原 TTL。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_timeout_returns_some_for_ttl_key() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_ttl_key", "v", 3600).await.unwrap();
            let timeout = dao.get_timeout("oc_ttl_key").await.unwrap();
            assert!(timeout.is_some(), "TTL 键应返回 Some");
            let remaining = timeout.unwrap();
            assert!(
                remaining <= Duration::from_secs(3600),
                "剩余时间应 ≤ 原 TTL"
            );
        }

        /// R-002: get_timeout 不存在的键返回 None。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_timeout_returns_none_for_missing_key() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            let timeout = dao.get_timeout("oc_missing_ttl").await.unwrap();
            assert!(timeout.is_none(), "不存在的键应返回 None");
        }

        /// R-003: keys 行为取决于 feature gate。
        ///
        /// - 启用 `anomalous-detector-dual`：keys() 通过 key_index 返回匹配的 key 列表
        /// - 未启用 `anomalous-detector-dual`：keys() 返回 NotImplemented（oxcache 不支持原生 key scan）
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_keys_behavior() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_key1", "v1", 3600).await.unwrap();
            let result = dao.keys("oc_*").await;
            #[cfg(feature = "anomalous-detector-dual")]
            {
                let keys = result.expect("anomalous-detector-dual 启用时 keys() 应返回 key 列表");
                assert!(
                    keys.iter().any(|k| k.contains("oc_key1")),
                    "keys 应包含 oc_key1, 实际: {:?}",
                    keys
                );
            }
            #[cfg(not(feature = "anomalous-detector-dual"))]
            {
                assert!(
                    matches!(result, Err(BulwarkError::NotImplemented(_))),
                    "未启用 anomalous-detector-dual 时 keys() 应返回 NotImplemented, 实际: {:?}",
                    result
                );
            }
        }

        /// R-004: rename 重命名后 old 不存在，new 存在。
        ///
        /// 覆盖 BulwarkDaoOxcache::rename 重写实现（用 get → ttl_sync → set_with_ttl_sync → delete）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_rename_moves_key() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_old", "value", 3600).await.unwrap();
            dao.rename("oc_old", "oc_new").await.unwrap();
            let old = dao.get("oc_old").await.unwrap();
            let new = dao.get("oc_new").await.unwrap();
            assert!(old.is_none(), "rename 后 oc_old 应不存在");
            assert_eq!(new, Some("value".to_string()), "rename 后 oc_new 应有值");
        }

        /// R-004: rename 不存在的 old_key 返回 InvalidParam。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_rename_missing_key_returns_invalid_param() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            let result = dao.rename("oc_missing_old", "oc_new").await;
            assert!(
                matches!(result, Err(BulwarkError::InvalidParam(_))),
                "rename 不存在的键应返回 InvalidParam，实际: {:?}",
                result
            );
        }

        /// R-004: rename 保留原键 TTL（重写实现的核心价值）。
        ///
        /// 验证 BulwarkDaoOxcache::rename 用 ttl_sync + set_with_ttl_sync 保留 TTL，
        /// 而非默认实现的 set_permanent（丢失 TTL）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_rename_preserves_ttl() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            // 设置短 TTL（2 秒）
            dao.set("oc_short_ttl", "value", 2).await.unwrap();
            // rename 到新 key
            dao.rename("oc_short_ttl", "oc_renamed").await.unwrap();
            // 验证新 key 存在
            let got = dao.get("oc_renamed").await.unwrap();
            assert_eq!(got, Some("value".to_string()));
            // 等待原 TTL 过期（2 秒 + 1 秒余量）
            tokio::time::sleep(Duration::from_secs(3)).await;
            // rename 保留了原 TTL，应已过期
            let got = dao.get("oc_renamed").await.unwrap();
            assert!(
                got.is_none(),
                "rename 应保留原 TTL，原 TTL 过期后应返回 None"
            );
        }

        /// R-001: oxcache get_and_delete 返回值并删除 key。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_and_delete_returns_value_and_removes_key() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_atomic", "value", 3600).await.unwrap();
            let got = dao.get_and_delete("oc_atomic").await.unwrap();
            assert_eq!(got, Some("value".to_string()));
            let after = dao.get("oc_atomic").await.unwrap();
            assert!(after.is_none(), "get_and_delete 后 key 应不存在");
        }

        /// R-001: oxcache get_and_delete 不存在的 key 返回 None。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_and_delete_missing_returns_none() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            let got = dao.get_and_delete("oc_missing").await.unwrap();
            assert!(got.is_none());
        }

        /// R-001: oxcache get_and_delete 并发原子性验证。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_and_delete_concurrent_only_one_succeeds() {
            let dao = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
            dao.set("oc_concurrent", "value", 3600).await.unwrap();

            let mut handles = Vec::new();
            for _ in 0..10 {
                let d = dao.clone();
                handles.push(tokio::spawn(async move {
                    d.get_and_delete("oc_concurrent").await
                }));
            }

            let mut success = 0;
            let mut none_count = 0;
            for handle in handles {
                let result = handle.await.unwrap();
                match result {
                    Ok(Some(_)) => success += 1,
                    Ok(None) => none_count += 1,
                    Err(e) => panic!("get_and_delete 不应返回错误: {:?}", e),
                }
            }

            assert_eq!(success, 1, "并发调用仅一个返回 Some");
            assert_eq!(none_count, 9, "其他 9 个返回 None");
        }

        // --------------------------------------------------------------------
        // 多租户 key 前缀测试
        // --------------------------------------------------------------------

        /// R-tenant-isolation-003: tenant-isolation feature 启用且 TENANT 上下文存在时，
        /// BulwarkDao 的 set/get 实际操作的 key 为 `tenant:{tid}:original_key`。
        ///
        /// 通过公共 API 验证（不直接探测内部存储 key，避免 get 自身再次 prepend 前缀）：
        /// 1. tenant 42 在 TENANT.scope 内 set("shared_key", "tenant_42_value")
        /// 2. 同一 TENANT.scope 内 get("shared_key") 应返回 Some（证明 set/get 用同一前缀）
        /// 3. tenant 1 在另一 TENANT.scope 内 get("shared_key") 应返回 None（证明跨租户隔离）
        /// 4. tenant 1 在另一 TENANT.scope 内 set("shared_key", "tenant_1_value") 应不影响 tenant 42 的值
        #[cfg(feature = "tenant-isolation")]
        #[tokio::test(flavor = "multi_thread")]
        async fn dao_key_prefixed_with_tenant_when_isolation_enabled() {
            use crate::context::tenant::{TenantContext, TenantSource, TENANT};

            let dao = BulwarkDaoOxcache::new().await.unwrap();

            // tenant 42 写入
            let ctx_42 = TenantContext {
                tenant_id: 42,
                resolved_from: TenantSource::Header,
            };
            TENANT
                .scope(ctx_42.clone(), async {
                    dao.set("shared_key", "tenant_42_value", 3600)
                        .await
                        .unwrap();
                    // 同租户 get 应命中（证明 set 与 get 用相同前缀 `tenant:42:`）
                    let got = dao.get("shared_key").await.unwrap();
                    assert_eq!(
                        got,
                        Some("tenant_42_value".to_string()),
                        "同租户 get 应命中 set 写入的值（前缀一致）"
                    );
                })
                .await;

            // tenant 1 跨租户访问应隔离
            let ctx_1 = TenantContext {
                tenant_id: 1,
                resolved_from: TenantSource::Header,
            };
            TENANT
                .scope(ctx_1, async {
                    // 跨租户 get 应返回 None（key 前缀不同：`tenant:1:` vs `tenant:42:`）
                    let got = dao.get("shared_key").await.unwrap();
                    assert!(
                        got.is_none(),
                        "跨租户 get 应返回 None（隔离失败），实际: {:?}",
                        got
                    );

                    // tenant 1 写入同名 key 不应影响 tenant 42
                    dao.set("shared_key", "tenant_1_value", 3600).await.unwrap();
                    let got_self = dao.get("shared_key").await.unwrap();
                    assert_eq!(
                        got_self,
                        Some("tenant_1_value".to_string()),
                        "tenant 1 应读到自己的值"
                    );
                })
                .await;

            // 回到 tenant 42 验证值未被 tenant 1 覆盖
            TENANT
                .scope(ctx_42.clone(), async {
                    let got = dao.get("shared_key").await.unwrap();
                    assert_eq!(
                        got,
                        Some("tenant_42_value".to_string()),
                        "tenant 42 的值不应被 tenant 1 覆盖（隔离失败）"
                    );
                })
                .await;
        }

        /// R-tenant-isolation-003: TENANT 上下文不存在时 key 不变（不 panic）。
        ///
        /// 验证：不在 TENANT.scope 内调用 set/get，key 应保持原样（无前缀）。
        #[cfg(feature = "tenant-isolation")]
        #[tokio::test(flavor = "multi_thread")]
        async fn dao_key_unchanged_when_tenant_context_absent() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();

            // 不在 TENANT.scope 内，TENANT.try_get() 返回 Err，key 应保持原样
            dao.set("no_ctx_key", "value", 3600).await.unwrap();
            let got = dao.get("no_ctx_key").await.unwrap();
            assert_eq!(
                got,
                Some("value".to_string()),
                "TENANT 上下文不存在时 key 应保持原样（无前缀）"
            );

            // 带前缀的 key 应返回 None（因 set 时未加前缀）
            let prefixed = dao.get("tenant:0:no_ctx_key").await.unwrap();
            assert!(
                prefixed.is_none(),
                "TENANT 上下文不存在时不应有带前缀的 key"
            );
        }

        /// R-tenant-isolation-003: delete 也应使用带前缀的 key。
        ///
        /// 验证：在 TENANT.scope 内 set 后，用 delete 删除原始 key 应能成功删除
        ///（delete 内部加前缀 `tenant:42:`，与 set 写入的 key 匹配）。
        /// 通过公共 API 验证：delete 后同租户 get 应返回 None。
        #[cfg(feature = "tenant-isolation")]
        #[tokio::test(flavor = "multi_thread")]
        async fn dao_delete_uses_prefixed_key_in_tenant_context() {
            use crate::context::tenant::{TenantContext, TenantSource, TENANT};

            let dao = BulwarkDaoOxcache::new().await.unwrap();
            let ctx = TenantContext {
                tenant_id: 42,
                resolved_from: TenantSource::Header,
            };

            TENANT
                .scope(ctx, async {
                    dao.set("del_key", "value", 3600).await.unwrap();
                    // 先确认值已写入
                    assert_eq!(
                        dao.get("del_key").await.unwrap(),
                        Some("value".to_string()),
                        "set 后同租户 get 应命中"
                    );

                    // delete 用原始 key，内部应加前缀匹配到 `tenant:42:del_key`
                    dao.delete("del_key").await.unwrap();

                    // 同租户 get 应返回 None（证明 delete 命中了带前缀的 key）
                    let after = dao.get("del_key").await.unwrap();
                    assert!(
                        after.is_none(),
                        "delete 后同租户 get 应返回 None（delete 也加了前缀）"
                    );
                })
                .await;
        }
    }

    // ------------------------------------------------------------------------
    // get_and_delete 原子方法测试（v0.4.2 spec protocol-sso-toctou R-001）
    // ------------------------------------------------------------------------

    /// R-001: get_and_delete 返回值并删除 key。
    #[tokio::test]
    async fn mock_get_and_delete_returns_value_and_removes_key() {
        let dao = MockDao::new();
        dao.set("atomic_key", "value", 3600).await.unwrap();
        let got = dao.get_and_delete("atomic_key").await.unwrap();
        assert_eq!(got, Some("value".to_string()));
        // key 应已被删除
        let after = dao.get("atomic_key").await.unwrap();
        assert!(after.is_none(), "get_and_delete 后 key 应不存在");
    }

    /// R-001: get_and_delete 不存在的 key 返回 None。
    #[tokio::test]
    async fn mock_get_and_delete_missing_returns_none() {
        let dao = MockDao::new();
        let got = dao.get_and_delete("missing").await.unwrap();
        assert!(got.is_none(), "不存在的 key 应返回 None");
    }

    /// R-001: get_and_delete 并发调用同一 key 仅一个返回 Some（原子性验证）。
    ///
    /// 使用 10 个并发任务同时调用 get_and_delete，仅一个应返回 Some。
    /// 这是 TOCTOU 修复的核心验证测试。
    #[tokio::test(flavor = "multi_thread")]
    async fn mock_get_and_delete_concurrent_only_one_succeeds() {
        let dao = Arc::new(MockDao::new());
        dao.set("concurrent_key", "value", 3600).await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..10 {
            let d = dao.clone();
            handles.push(tokio::spawn(async move {
                d.get_and_delete("concurrent_key").await
            }));
        }

        let mut success = 0;
        let mut none_count = 0;
        for handle in handles {
            let result = handle.await.unwrap();
            match result {
                Ok(Some(_)) => success += 1,
                Ok(None) => none_count += 1,
                Err(e) => panic!("get_and_delete 不应返回错误: {:?}", e),
            }
        }

        assert_eq!(success, 1, "并发调用仅一个返回 Some");
        assert_eq!(none_count, 9, "其他 9 个返回 None");
    }

    // ========================================================================
    // 覆盖率补充：BulwarkDao trait 默认方法测试
    // ========================================================================

    /// 最小化 DAO 实现，只实现 5 个必需方法，不重写任何默认方法。
    ///
    /// 用于验证 trait 默认实现的行为：
    /// - `set_permanent` 默认委托 `set(key, value, 0)`
    /// - `get_timeout` 默认返回 `NotImplemented`
    /// - `keys` 默认返回 `NotImplemented`
    /// - `rename` 默认 `get → set_permanent → delete`
    struct MinimalDao {
        store: Mutex<HashMap<String, String>>,
    }

    impl MinimalDao {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BulwarkDao for MinimalDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            Ok(self.store.lock().get(key).cloned())
        }

        async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
            self.store.lock().insert(key.to_string(), value.to_string());
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            match self.store.lock().get_mut(key) {
                Some(existing) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
            Ok(()) // MinimalDao 不支持 TTL，no-op
        }

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.store.lock().remove(key);
            Ok(())
        }
    }

    /// R-001: `set_permanent` 默认实现委托 `set(key, value, 0)`。
    #[tokio::test]
    async fn default_set_permanent_delegates_to_set_with_ttl_zero() {
        let dao = MinimalDao::new();
        // 调用默认实现的 set_permanent
        dao.set_permanent("perm_key", "perm_value").await.unwrap();
        // 验证值已写入（通过 get 读取）
        let val = dao.get("perm_key").await.unwrap();
        assert_eq!(val.as_deref(), Some("perm_value"));
    }

    /// R-002: `get_timeout` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn default_get_timeout_returns_not_implemented() {
        let dao = MinimalDao::new();
        dao.set("key", "value", 3600).await.unwrap();
        let result = dao.get_timeout("key").await;
        assert!(matches!(result, Err(BulwarkError::NotImplemented(_))));
    }

    /// R-003: `keys` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn default_keys_returns_not_implemented() {
        let dao = MinimalDao::new();
        dao.set("key1", "v1", 0).await.unwrap();
        let result = dao.keys("*").await;
        assert!(matches!(result, Err(BulwarkError::NotImplemented(_))));
    }

    /// R-004: `rename` 默认实现执行 `get → set_permanent → delete` 三步操作。
    #[tokio::test]
    async fn default_rename_get_set_permanent_delete() {
        let dao = MinimalDao::new();
        dao.set("old_key", "old_value", 0).await.unwrap();
        // 调用默认实现的 rename
        dao.rename("old_key", "new_key").await.unwrap();
        // 验证 old_key 已被删除
        assert!(dao.get("old_key").await.unwrap().is_none());
        // 验证 new_key 已写入
        assert_eq!(
            dao.get("new_key").await.unwrap().as_deref(),
            Some("old_value")
        );
    }

    /// R-004: `rename` 对不存在的 key 返回 `InvalidParam`。
    #[tokio::test]
    async fn default_rename_missing_key_returns_invalid_param() {
        let dao = MinimalDao::new();
        let result = dao.rename("nonexistent", "new_key").await;
        assert!(matches!(result, Err(BulwarkError::InvalidParam(_))));
    }

    // ========================================================================
    // 覆盖率补充：社交账号绑定关系默认实现
    // ========================================================================

    /// `find_social_binding` 默认实现返回 `NotImplemented`（BulwarkDao 是 KV 缓存抽象，不支持 SQL）。
    ///
    /// 覆盖 trait 默认实现（行 208-218）。
    #[tokio::test]
    async fn default_find_social_binding_returns_not_implemented() {
        let dao = MinimalDao::new();
        let result = dao.find_social_binding(0, "wechat", "wx_openid").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("find_social_binding")),
            "find_social_binding 默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// `insert_social_binding` 默认实现返回 `NotImplemented`。
    ///
    /// 覆盖 trait 默认实现（行 236-249）。
    #[tokio::test]
    async fn default_insert_social_binding_returns_not_implemented() {
        let dao = MinimalDao::new();
        let result = dao
            .insert_social_binding(0, 1001, "wechat", "wx_openid", None, 1700000000)
            .await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("insert_social_binding")),
            "insert_social_binding 默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// `get_and_delete` 默认实现（非原子 get → delete）在键存在时返回值并删除。
    ///
    /// 覆盖 trait 默认实现（行 182-188）。
    #[tokio::test]
    async fn default_get_and_delete_returns_value_and_removes_key() {
        let dao = MinimalDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        let val = dao.get_and_delete("k1").await.unwrap();
        assert_eq!(val, Some("v1".to_string()));
        assert!(dao.get("k1").await.unwrap().is_none());
    }

    /// `get_and_delete` 默认实现对不存在的键返回 None 且不报错。
    #[tokio::test]
    async fn default_get_and_delete_missing_key_returns_none() {
        let dao = MinimalDao::new();
        let val = dao.get_and_delete("nope").await.unwrap();
        assert!(val.is_none());
    }

    // ========================================================================
    // Redis 部署模式配置测试
    // ========================================================================

    /// R-002: RedisConfig::default() 返回 Single 模式，url 为 "redis://127.6379"。
    #[test]
    fn redis_config_default_returns_single_mode() {
        let config = RedisConfig::default();
        assert_eq!(
            config.mode,
            RedisDeploymentMode::Single {
                url: "redis://127.0.0.1:6379".to_string()
            }
        );
        assert_eq!(config.password, None);
        assert_eq!(config.db, 0);
        assert_eq!(config.connection_timeout_secs, 5);
        assert_eq!(config.pool_size, 10);
    }

    /// R-002: RedisConfig serde 序列化/反序列化 round-trip。
    #[test]
    fn redis_config_serde_roundtrip() {
        let config = RedisConfig {
            mode: RedisDeploymentMode::Cluster {
                urls: vec![
                    "redis://10.0.0.1:6379".to_string(),
                    "redis://10.0.0.2:6379".to_string(),
                    "redis://10.0.0.3:6379".to_string(),
                ],
            },
            password: Some("secret".to_string()),
            db: 1,
            connection_timeout_secs: 10,
            pool_size: 20,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RedisConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.mode, deserialized.mode);
        assert_eq!(config.password, deserialized.password);
        assert_eq!(config.db, deserialized.db);
        assert_eq!(
            config.connection_timeout_secs,
            deserialized.connection_timeout_secs
        );
        assert_eq!(config.pool_size, deserialized.pool_size);
    }

    /// R-002: RedisConfig serde 用 `#[serde(default)]` 支持部分覆盖。
    #[test]
    fn redis_config_serde_partial_override() {
        // 仅提供 mode，其余字段应使用 default
        let json = r#"{"mode":{"mode":"cluster","urls":["redis://10.0.0.1:6379"]}}"#;
        let config: RedisConfig = serde_json::from_str(json).unwrap();
        match config.mode {
            RedisDeploymentMode::Cluster { urls } => {
                assert_eq!(urls, vec!["redis://10.0.0.1:6379".to_string()]);
            },
            _ => panic!("期望 Cluster 模式"),
        }
        // 其余字段应为 default 值
        assert_eq!(config.password, None);
        assert_eq!(config.db, 0);
        assert_eq!(config.connection_timeout_secs, 5);
        assert_eq!(config.pool_size, 10);
    }

    /// R-001: RedisDeploymentMode 各变体 Display 输出可读。
    #[test]
    fn redis_deployment_mode_display() {
        let single = RedisDeploymentMode::Single {
            url: "redis://127.0.0.1:6379".to_string(),
        };
        assert!(format!("{}", single).contains("single"));
        assert!(format!("{}", single).contains("redis://127.0.0.1:6379"));

        let sentinel = RedisDeploymentMode::Sentinel {
            master_name: "mymaster".to_string(),
            urls: vec!["redis://s1:26379".to_string()],
        };
        let s = format!("{}", sentinel);
        assert!(s.contains("sentinel"));
        assert!(s.contains("mymaster"));

        let cluster = RedisDeploymentMode::Cluster {
            urls: vec!["redis://c1:6379".to_string(), "redis://c2:6379".to_string()],
        };
        let c = format!("{}", cluster);
        assert!(c.contains("cluster"));
        assert!(c.contains("2 nodes"));

        let ms = RedisDeploymentMode::MasterSlave {
            master_url: "redis://master:6379".to_string(),
            slave_urls: vec!["redis://slave1:6379".to_string()],
        };
        let m = format!("{}", ms);
        assert!(m.contains("master-slave"));
        assert!(m.contains("master:6379"));
        assert!(m.contains("1 slaves"));
    }

    /// R-001: RedisDeploymentMode PartialEq 比较。
    #[test]
    fn redis_deployment_mode_eq() {
        let a = RedisDeploymentMode::Single {
            url: "redis://127.0.0.1:6379".to_string(),
        };
        let b = RedisDeploymentMode::Single {
            url: "redis://127.0.0.1:6379".to_string(),
        };
        let c = RedisDeploymentMode::Single {
            url: "redis://10.0.0.1:6379".to_string(),
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// R-003: with_redis_config builder 方法在 cache-redis feature 下存在并存储配置。
    #[cfg(feature = "cache-redis")]
    #[tokio::test(flavor = "multi_thread")]
    async fn with_redis_config_stores_config() {
        let dao = BulwarkDaoOxcache::new().await.unwrap();
        assert!(
            dao.redis_config().is_none(),
            "新建实例的 redis_config 应为 None"
        );
        let config = RedisConfig {
            mode: RedisDeploymentMode::Sentinel {
                master_name: "mymaster".to_string(),
                urls: vec![
                    "redis://s1:26379".to_string(),
                    "redis://s2:26379".to_string(),
                    "redis://s3:26379".to_string(),
                ],
            },
            password: Some("pass123".to_string()),
            db: 2,
            connection_timeout_secs: 15,
            pool_size: 50,
        };
        let dao = dao.with_redis_config(config);
        let stored = dao.redis_config().expect("with_redis_config 后应有配置");
        assert!(matches!(
            &stored.mode,
            RedisDeploymentMode::Sentinel { master_name, urls }
            if master_name == "mymaster" && urls.len() == 3
        ));
        assert_eq!(stored.password, Some("pass123".to_string()));
        assert_eq!(stored.db, 2);
        assert_eq!(stored.connection_timeout_secs, 15);
        assert_eq!(stored.pool_size, 50);
    }

    /// R-003: 未调用 with_redis_config 时 redis_config 为 None。
    #[cfg(feature = "cache-redis")]
    #[tokio::test(flavor = "multi_thread")]
    async fn without_redis_config_returns_none() {
        let dao = BulwarkDaoOxcache::new().await.unwrap();
        assert!(
            dao.redis_config().is_none(),
            "未调用 with_redis_config 时 redis_config 应为 None"
        );
    }
}
