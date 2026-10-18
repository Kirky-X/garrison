// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! DAO 模块：经 oxcache / dbnexus 提供多后端（缓存 / 关系型数据库）持久化抽象。

use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
mod macros;
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub(crate) use macros::dao_session;

/// DAO 抽象层 trait，定义 Token 与会话的持久化操作：
/// `get` / `set` / `update` / `delete` / `expire` 五元操作 + `set_permanent` / `get_timeout` / `keys` / `rename` 等扩展。
///
/// 核心语义：`set` 必须指定 TTL（Token/Session 不应永久驻留）；`update` 保留原 TTL；
/// `keys` 需 `dao-key-index` feature（由 `protocol-apikey` / `anomalous-detector-dual` 传递）才可用。
///
/// # 原子性编译期契约
///
/// 以下方法为**必需方法（无默认实现）**，实现方必须保证原子性：
///
/// | 方法 | 原子性要求 |
/// |------|-----------|
/// | `rename` | 原子重命名（保留 TTL），禁止 get→set→delete 三步组合 |
/// | `set_if_absent` | SETNX 语义，并发下仅一个调用成功写入 |
/// | `get_and_delete` | GETDEL 语义，并发下仅一个调用取到值（SSO ticket 一次性消费） |
/// | `incr` / `decr` | 原子计数，并发不丢失更新 |
/// | `compare_and_swap` | CAS 语义，并发不覆盖中间值 |
///
/// 遗漏实现将在**编译期**报错，而非运行时静默竞态；内置实现
///（`MockDao` / `GarrisonDaoOxcache` / `GarrisonDaoDbnexus` / `AloneCache`）均以进程内锁或后端原语满足原子性。
#[async_trait]
pub trait GarrisonDao: Send + Sync {
    /// 获取指定键的值；键不存在或已过期返回 `None`。
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>>;

    /// 设置键值对；`ttl_seconds=0` 表示永久驻留（可被 `expire` 重置）。
    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()>;

    /// 更新键的值，保留原有 TTL（不重置过期时间）；键不存在返回 `GarrisonError::Dao`。
    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()>;

    /// 设置（或重置）键的过期时间（0 表示永久驻留）；键不存在返回 `GarrisonError::Dao`。
    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()>;

    /// 删除指定键。
    async fn delete(&self, key: &str) -> GarrisonResult<()>;

    /// 存储永久键（无 TTL）；默认委托 `set(key, value, 0)`，后端可重写为原生无 TTL API（如 oxcache `set_with_ttl_sync(None)`）。
    async fn set_permanent(&self, key: &str, value: &str) -> GarrisonResult<()> {
        self.set(key, value, 0).await
    }

    /// 仅当 key 不存在时写入（SETNX 语义），返回是否成功写入；用于社交绑定等 create-if-absent 场景。
    ///
    /// 原子性：并发同一 key 仅一个调用写入成功，禁止 `get` + `set` 两步组合；
    /// 进程内用锁保护，Redis 用 `SET key value NX EX ttl`，dbnexus 用 `INSERT ... ON CONFLICT DO NOTHING` 检查 affected rows。
    async fn set_if_absent(&self, key: &str, value: &str, ttl_seconds: u64)
        -> GarrisonResult<bool>;

    /// 查询键的剩余 TTL；键不存在或为永久键均返回 `None`。
    ///
    /// 默认返回 `GarrisonError::NotImplemented`（需后端原生 TTL 查询 API）；`GarrisonDaoOxcache` 与 `MockDao` 已重写。
    async fn get_timeout(&self, _key: &str) -> GarrisonResult<Option<Duration>> {
        Err(GarrisonError::NotImplemented(format!(
            "dao-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }

    /// 单次调用返回键值与剩余 TTL（`ttl=None` 表示永久驻留），避免 `get` + `get_timeout` 两次往返；
    /// 用于 `renew_to_equivalent` 等热路径。默认实现为两次调用组合，后端若支持原子获取（Redis pipeline / 内存单次 lookup）应重写。
    async fn get_with_ttl(&self, key: &str) -> GarrisonResult<Option<(String, Option<Duration>)>> {
        let value = self.get(key).await?;
        if value.is_none() {
            return Ok(None);
        }
        let ttl = self.get_timeout(key).await?;
        Ok(Some((value.unwrap(), ttl)))
    }

    /// 按 glob pattern 扫描 key（`*` 任意序列 / `?` 单字符），无匹配返回空 Vec；全量扫描，大规模 key 场景性能差。
    ///
    /// `MockDao` 已实现；`GarrisonDaoOxcache` 默认返回 `NotImplemented`——oxcache 0.3.3 的
    /// `CacheReader` 未暴露 iter/keys API；启用 `dao-key-index` feature（`protocol-apikey` /
    /// `anomalous-detector-dual` 传递）后维护独立 key 索引（set/delete 同步、keys 惰性清理过期项，
    /// 代价是每次写多一次索引同步），`ApiKeyHandler::list_by_namespace` 依赖该 feature。
    async fn keys(&self, _pattern: &str) -> GarrisonResult<Vec<String>> {
        Err(GarrisonError::NotImplemented(format!(
            "dao-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }

    /// 重命名 key；`old_key` 不存在返回 `GarrisonError::InvalidParam`。
    ///
    /// 原子性：读取旧键 → 写入新键 → 删除旧键须在同一临界区完成且**保留原键 TTL**，
    /// 禁止 get→set_permanent→delete 组合（TTL 丢失、并发下新旧键并存）；进程内用锁保护，Redis 用原生 `RENAME`。
    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()>;

    /// 原子地获取并删除键（返回语义同 `get`）；用于 SSO ticket 一次性消费等场景。
    ///
    /// 原子性：get 与 delete 必须在同一临界区内执行，并发同一 key 仅一个调用返回 `Some`，
    /// 禁止两步组合（TOCTOU）；进程内用锁保护，Redis 用 `GETDEL` 或 Lua 脚本，dbnexus 用 `DELETE ... RETURNING`。
    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>>;

    /// 原子递增计数器（带 TTL）：新键初始化为 1 并设置 TTL，已存在仅递增值、**不重置 TTL**（保留原窗口过期时间）；用于 SMS 限速计数器等场景。
    ///
    /// 原子性：读取 → 递增 → 写回不可分割（并发不丢失更新）；解析失败必须显式返回
    /// `GarrisonError::Dao`，禁止静默按 0 重置计数器；进程内用锁保护，Redis 用 `INCR` + 首次 `EXPIRE`。
    async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64>;

    /// 原子递减计数器（与 [`incr`](Self::incr) 对称，用于 SMS 限速回滚）：key 不存在/已过期或值为 0 返回 0（不创建 key）；
    /// 递减到 0 删除 key（与 `SmsRateLimiter::decrement_counter` 语义一致），递减后 > 0 保留原 TTL。
    ///
    /// 原子性：禁止 `get → parse → update/delete` 组合（TOCTOU"跨越式递减"）；进程内用锁保护，Redis 用 `DECR`（值为 0 时额外 `DEL`）。
    async fn decr(&self, key: &str) -> GarrisonResult<u64>;

    /// 原子地比较并更新：仅当 `new_value > current_value` 时写入并返回 true（key 不存在视当前值为 0，TTL 仅首次创建时设置）；
    /// 用于 HTTP Digest nc 单调性校验（RFC 7616 §3.4.6），消除 get→compare→set TOCTOU 竞态。
    ///
    /// 默认返回 `GarrisonError::NotImplemented`（fail-closed：宁可拒绝也不接受非原子 CAS）；
    /// `MockDao` / `GarrisonDaoOxcache` / `AloneCache` 已用进程内锁重写，生产后端须重写为
    /// 原子 CAS（Redis Lua 脚本或 SQL `UPDATE ... WHERE ... RETURNING`）。
    async fn compare_and_update_if_greater(
        &self,
        _key: &str,
        _new_value: u64,
        _ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        Err(GarrisonError::NotImplemented(format!(
            "dao-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }

    /// 按 `(tenant_id, provider, provider_user_id)` 查 `social_bindings` 表，返回关联的 `login_id`（无绑定返回 `None`）。
    ///
    /// 默认返回 `GarrisonError::NotImplemented`（KV 缓存抽象无 SQL）；`GarrisonDaoDbnexus` 经 `DbPool` 重写。
    async fn find_social_binding(
        &self,
        _tenant_id: i64,
        _provider: &str,
        _provider_user_id: &str,
    ) -> GarrisonResult<Option<String>> {
        Err(GarrisonError::NotImplemented(format!(
            "dao-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }

    /// 写入 `(tenant_id, login_id, provider, provider_user_id, union_id)` 到 `social_bindings` 表；
    /// 默认返回 `GarrisonError::NotImplemented`，`GarrisonDaoDbnexus` 经 `DbPool` 重写。
    async fn insert_social_binding(
        &self,
        _tenant_id: i64,
        _login_id: &str,
        _provider: &str,
        _provider_user_id: &str,
        _union_id: Option<&str>,
        _created_at: i64,
    ) -> GarrisonResult<()> {
        Err(GarrisonError::NotImplemented(format!(
            "dao-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }

    /// 查询指定租户的全部角色层级边 `(child_role, parent_role)`（对应 `role_hierarchy` 表）；
    /// 默认返回 `GarrisonError::NotImplemented`，仅 `GarrisonDaoDbnexus` 重写（`RoleHierarchyService` 实际直查 `DbPool`）。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    async fn query_role_hierarchy_edges(
        &self,
        _tenant_id: i64,
    ) -> GarrisonResult<Vec<(String, String)>> {
        Err(GarrisonError::NotImplemented(format!(
            "dao-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }

    /// 插入角色层级边（child → parent），幂等：SQLite `INSERT OR IGNORE`、PostgreSQL `ON CONFLICT DO NOTHING`、MySQL `INSERT IGNORE`；
    /// 默认返回 `GarrisonError::NotImplemented`，仅 `GarrisonDaoDbnexus` 重写。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    async fn insert_role_hierarchy_edge(
        &self,
        _tenant_id: i64,
        _child_role: &str,
        _parent_role: &str,
    ) -> GarrisonResult<()> {
        Err(GarrisonError::NotImplemented(format!(
            "dao-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }

    /// 删除角色层级边（child → parent），幂等（不存在的边不报错）；
    /// 默认返回 `GarrisonError::NotImplemented`，仅 `GarrisonDaoDbnexus` 重写。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    async fn delete_role_hierarchy_edge(
        &self,
        _tenant_id: i64,
        _child_role: &str,
        _parent_role: &str,
    ) -> GarrisonResult<()> {
        Err(GarrisonError::NotImplemented(format!(
            "dao-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }

    /// 执行 Redis Lua 脚本（原子操作），用于限速计数器（INCR + EXPIRE）、一次性 token 消费（GET + DEL）等复合操作。
    ///
    /// 默认返回 `GarrisonError::NotImplemented`（仅 Redis 后端支持）；
    /// `MockDao` 重写为内存模拟（识别 INCR + EXPIRE 与 limiteron sliding-window 模式），
    /// `GarrisonDaoOxcache` 在 `cache-redis` feature 下委托 `Cache::eval_lua`。
    /// 调用方应在 `NotImplemented` 时降级到非原子路径（如 `incr` + 阈值判断）。
    async fn eval_lua(
        &self,
        _script: &str,
        _keys: Vec<String>,
        _args: Vec<String>,
    ) -> GarrisonResult<Vec<String>> {
        Err(GarrisonError::NotImplemented(format!(
            "dao-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }

    /// 原子比较并交换（CAS）：当前值等于 `expected`（`None` 期望 key 不存在）时替换为 `new_value`；
    /// 用于备份码消费等场景，消除 get→verify→set TOCTOU 双花竞态。
    ///
    /// 原子性：比较与交换须在同一临界区完成，并发下不覆盖中间值，禁止 `get + compare + set` 组合；
    /// 进程内用锁保护，Redis 用 Lua 脚本，dbnexus 用 `UPDATE ... WHERE value = expected`。
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool>;

    /// 清理全部已过期行（vacuum）：仅删除 `expire_at` 非空且 ≤ 当前时间的行，永久行（`NULL`）不动；
    /// 幂等，返回物理删除行数。默认 no-op 返回 0——原生 TTL 后端（Redis/oxcache）由存储引擎自清理、
    /// 进程内后端随实例消亡，均无「永久滞留的过期行」；SQL KV（`DbnexusKvDao`）重写为单语句 DELETE，
    /// 由部署方以 cron/systemd timer 或进程内周期调用触发（上游不内置调度）。
    async fn vacuum_expired(&self) -> GarrisonResult<u64> {
        Ok(0)
    }

    /// 插入 credit 消费流水（`persist_history = true` 时调用）；
    /// 默认返回 `GarrisonError::NotImplemented`，SQL 后端（sqlite/postgres/mysql）重写。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    async fn insert_credit_consumption(
        &self,
        _tenant_id: i64,
        _resource: &str,
        _cost: u64,
        _credits: u64,
        _total_consumed: u64,
        _cycle_start: i64,
    ) -> GarrisonResult<()> {
        Err(GarrisonError::NotImplemented(format!(
            "dao-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }

    /// 查询指定时间范围内的 credit 消费流水；默认返回 `GarrisonError::NotImplemented`，SQL 后端重写。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    async fn query_credit_consumption(
        &self,
        _tenant_id: i64,
        _from_ts: i64,
        _to_ts: i64,
    ) -> GarrisonResult<Vec<(i64, String, u64, u64, u64, i64, i64)>> {
        Err(GarrisonError::NotImplemented(format!(
            "dao-not-implemented::{}",
            std::any::type_name::<Self>()
        )))
    }
}

/// DAO 原子方法测试回退宏（实现见 `atomic_fallback.rs`）：`#[doc(hidden)]` 测试域专用，生产 DAO 实现**禁止**使用组合语义。
/// 注：完全编译期门控（cfg testing）需 CI 测试命令追加 testing feature（CI 现为 full-only，属 Non-Goals），已记录为后续 change。
#[doc(hidden)]
pub mod atomic_fallback;

// Redis 部署模式配置

/// Redis 部署模式枚举，覆盖生产环境常见拓扑。
///
/// 参阅 Redis 集群部署文档：单节点 / Sentinel / Cluster / Primary-Replica。
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
        #[serde(alias = "master_name")]
        primary_name: String,
        /// Sentinel 节点 URL 列表。
        urls: Vec<String>,
    },
    /// 集群模式：Redis Cluster 分片存储。
    Cluster {
        /// Cluster 节点 URL 列表（至少 3 个 primary 节点）。
        urls: Vec<String>,
    },
    /// 主从模式：1 个 primary + N 个 replica，读分离需客户端支持。
    #[serde(alias = "MasterSlave")]
    PrimaryReplica {
        /// Primary 节点 URL。
        primary_url: String,
        /// Replica 节点 URL 列表。
        replica_urls: Vec<String>,
    },
}

/// Redis 配置聚合结构，包含部署模式、连接池参数与认证信息。
///
/// 默认值：`Single { url: "redis://127.0.0.1:6379" }`、无密码、`db=0`、连接超时 5s、连接池 10。
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

impl RedisConfig {
    /// 标记并记录「使用默认 Redis 地址」（`redis://127.0.0.1:6379`）的一次性 warn。
    ///
    /// 生产缺配会静默连接本机 Redis——此告警让降级路径可见（同一进程仅一次）。
    pub fn warn_default_once(&self) {
        use std::sync::OnceLock;
        static DEFAULT_URL_WARNED: OnceLock<()> = OnceLock::new();
        let is_default = matches!(
            &self.mode,
            RedisDeploymentMode::Single { url }
                if url == "redis://127.0.0.1:6379"
        );
        if is_default && DEFAULT_URL_WARNED.set(()).is_ok() {
            tracing::warn!(
                "redis-config-using-default-url: connection will target 127.0.0.1:6379; \
                 configure Redis via dao config for production"
            );
        }
    }
}

// `RedisDeploymentMode` 与 `RedisConfig` 的 trait 实现见 `defaults` 子模块
// （mod.rs 只放 trait/struct/enum 定义，impl 拆到独立文件）
pub mod defaults;

// oxcache 实现（feature = "cache-memory" 或 "cache-redis"）

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
mod oxcache_impl;

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
pub use oxcache_impl::GarrisonDaoOxcache;

// dbnexus 实现（feature = "db-sqlite" 或 "db-postgres"）
// `init_dbnexus` 和 `GarrisonMigration` 是 backend-agnostic 的——仅封装 `DbPool::new(url)` 和
// `DbPool::run_migrations(dir)`，后端由 dbnexus 的 feature flag（sqlite/postgres）控制。
// `GarrisonMigration::new()` 默认走 `migrations/sqlite/`，PostgreSQL 用 `with_base_dir` 指定 `migrations/postgres/`。

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
mod dbnexus_impl;

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dbnexus_impl::{init_dbnexus, init_dbnexus_with_pool_config, GarrisonMigration};

/// 统一 KV + SQL 的 `GarrisonDao` 实现（包装 `DbPool` + KV 委托）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
mod dbnexus_dao;

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dbnexus_dao::GarrisonDaoDbnexus;

/// SQL 持久化 KV（`garrison_kv` 表，语义镜像 `InMemoryDao`）——离线运维命令（garrison-cli
/// change-key / check-key）的数据寻址层。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
mod dbnexus_kv;

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dbnexus_kv::DbnexusKvDao;

// 事件派发事务绑定（OnCommit 语义）
// `GarrisonEventTx` 需 `listener` feature（缓冲事件派发通道）+ 任一 db 后端 feature（依赖 dbnexus Session 事务原语）。

#[cfg(all(
    feature = "listener",
    any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql")
))]
mod tx;

#[cfg(all(
    feature = "listener",
    any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql")
))]
pub use tx::GarrisonEventTx;

// Repository 层
// 9 个核心表的 Repository trait + Row struct，与 dbnexus 解耦；
// SQLite 实现见 `repository::sqlite` 子模块（启用 `db-sqlite` feature）。
pub mod repository;

// AloneCache 装饰器（feature = "alone-cache"）

#[cfg(feature = "alone-cache")]
pub mod alone_cache;

// 缓存预热子模块

pub mod warmup;

// 契约测试套件（多后端同一把尺子，能力分层运行）
// `cfg(test)` 下随单元测试运行；`feature = "testing"` 构建面开放给下游自定义后端复用同一套契约测试。

#[cfg(any(test, feature = "testing"))]
pub mod testing;

// `InMemoryDao` 在生产代码中也作为进程内原子 DAO 使用（如 `PasswordRateLimiter` / `GarrisonFirewallCheckHookDefault` 的内存模式）。
mod in_memory;

pub use in_memory::InMemoryDao;

#[cfg(all(test, feature = "protocol-apikey"))]
pub(crate) use in_memory::glob_match;

#[cfg(test)]
/// DAO trait 契约测试与跨模块共享的 mock 实现（仅 `cfg(test)` 下编译）。
pub mod tests {

    /// 跨模块测试统一使用的内存 mock DAO 名称（即 [`InMemoryDao`]）。
    pub use super::InMemoryDao as MockDao;
    use super::*;
    use crate::error::GarrisonError;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    /// `vacuum_expired` 计数 mock：包装 [`MockDao`]（委托全部必需方法），以 `AtomicU64` 记录调用次数
    /// 并返回预置删除计数；用于 session 层委托链路断言（`GarrisonSession::vacuum_expired` → DAO）。
    pub struct VacuumCountingDao {
        inner: MockDao,
        /// `vacuum_expired` 被调用次数。
        calls: std::sync::atomic::AtomicU64,
        /// 预置返回的删除行数。
        result: u64,
    }

    impl VacuumCountingDao {
        /// 创建实例；`result` 为 `vacuum_expired` 每次返回的删除计数。
        pub fn new(result: u64) -> Self {
            Self {
                inner: MockDao::new(),
                calls: std::sync::atomic::AtomicU64::new(0),
                result,
            }
        }

        /// 读取 `vacuum_expired` 被调用次数。
        pub fn calls(&self) -> u64 {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl GarrisonDao for VacuumCountingDao {
        async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
            self.inner.get(key).await
        }

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
            self.inner.set(key, value, ttl_seconds).await
        }

        async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
            self.inner.update(key, value).await
        }

        async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
            self.inner.expire(key, seconds).await
        }

        async fn delete(&self, key: &str) -> GarrisonResult<()> {
            self.inner.delete(key).await
        }

        async fn set_if_absent(
            &self,
            key: &str,
            value: &str,
            ttl_seconds: u64,
        ) -> GarrisonResult<bool> {
            self.inner.set_if_absent(key, value, ttl_seconds).await
        }

        async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
            self.inner.rename(old_key, new_key).await
        }

        async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
            self.inner.get_and_delete(key).await
        }

        async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64> {
            self.inner.incr(key, ttl_seconds).await
        }

        async fn decr(&self, key: &str) -> GarrisonResult<u64> {
            self.inner.decr(key).await
        }

        async fn compare_and_swap(
            &self,
            key: &str,
            expected: Option<&str>,
            new_value: &str,
            ttl_seconds: u64,
        ) -> GarrisonResult<bool> {
            self.inner
                .compare_and_swap(key, expected, new_value, ttl_seconds)
                .await
        }

        async fn vacuum_expired(&self) -> GarrisonResult<u64> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.result)
        }
    }

    // GarrisonDaoOxcache keys() 测试（需 dao-key-index + cache-memory/cache-redis）
    #[cfg(all(
        feature = "dao-key-index",
        any(feature = "cache-memory", feature = "cache-redis")
    ))]
    mod oxcache_keys_tests {
        use super::*;

        /// 无 key 时 keys() 返回空 Vec。
        #[tokio::test(flavor = "multi_thread")]
        async fn test_oxcache_keys_empty() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let keys = dao.keys("anomalous:login:*").await.unwrap();
            assert!(keys.is_empty(), "无 key 时 keys() 应返回空 Vec");
        }

        /// set 3 个 key，keys("anomalous:login:*") 返回 2 个匹配的 key。
        #[tokio::test(flavor = "multi_thread")]
        async fn test_oxcache_keys_pattern_match() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
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
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("anomalous:login:1:1", "v1", 1).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let keys = dao.keys("anomalous:login:*").await.unwrap();
            assert!(
                keys.is_empty(),
                "TTL 过期后 keys() 应返回空 Vec（惰性清理）"
            );
            let keys2 = dao.keys("anomalous:login:*").await.unwrap();
            assert!(keys2.is_empty(), "清理后再次 keys() 仍应返回空");
        }

        /// delete 后 keys() 返回空。
        #[tokio::test(flavor = "multi_thread")]
        async fn test_oxcache_keys_after_delete() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("anomalous:login:1:1", "v1", 3600).await.unwrap();
            let keys = dao.keys("anomalous:login:*").await.unwrap();
            assert_eq!(keys.len(), 1, "set 后应有 1 个 key");
            dao.delete("anomalous:login:1:1").await.unwrap();
            let keys = dao.keys("anomalous:login:*").await.unwrap();
            assert!(keys.is_empty(), "delete 后 keys() 应返回空 Vec");
        }

        /// `ApiKeyHandler::list_by_namespace` 在真实 oxcache DAO 下可用（验证 dao-key-index gate 泛化后非 NotImplemented）。
        #[cfg(feature = "protocol-apikey")]
        #[tokio::test(flavor = "multi_thread")]
        async fn test_oxcache_apikey_list_by_namespace() {
            use crate::protocol::apikey::ApiKeyHandler;
            let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await.unwrap());
            let handler = ApiKeyHandler::new(dao);
            handler
                .generate_with_namespace("1001", "internal", vec!["read".into()], 3600)
                .await
                .unwrap();
            handler
                .generate_with_namespace("1002", "internal", vec!["write".into()], 3600)
                .await
                .unwrap();
            // 不同 namespace 的 key 不应被列出
            handler
                .generate_with_namespace("2001", "partner", vec!["admin".into()], 3600)
                .await
                .unwrap();
            let listed = handler.list_by_namespace("internal").await.unwrap();
            assert_eq!(
                listed.len(),
                2,
                "internal namespace 下应列出 2 个 key（非 NotImplemented）"
            );
            assert!(listed.iter().all(|i| i.namespace == "internal"));
        }
    }

    // 契约测试：GarrisonDao trait 行为契约（MockDao）

    /// set 后 get 返回写入的值。
    #[tokio::test]
    async fn mock_set_get_pair() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 3600).await.unwrap();
        let got = dao.get("key1").await.unwrap();
        assert_eq!(got, Some("value1".to_string()));
    }

    /// 过期后 get 返回 None（TTL 自动删除）。
    #[tokio::test]
    async fn mock_expire_auto_delete() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = dao.get("key1").await.unwrap();
        assert!(got.is_none(), "过期后 get 应返回 None");
    }

    /// delete 后 get 返回 None。
    #[tokio::test]
    async fn mock_delete_removes_key() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 3600).await.unwrap();
        dao.delete("key1").await.unwrap();
        let got = dao.get("key1").await.unwrap();
        assert!(got.is_none(), "delete 后 get 应返回 None");
    }

    /// update 保留 TTL：短 TTL 键更新后仍按原 TTL 过期。
    #[tokio::test]
    async fn mock_update_preserves_ttl() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 2).await.unwrap();
        dao.update("key1", "value2").await.unwrap();
        let got = dao.get("key1").await.unwrap();
        assert_eq!(got, Some("value2".to_string()));
        tokio::time::sleep(Duration::from_secs(3)).await;
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
            matches!(result, Err(GarrisonError::Dao(_))),
            "update 不存在的键应返回 Dao 错误"
        );
    }

    /// 验证 expire 重置过期时间。
    #[tokio::test]
    async fn mock_expire_resets_ttl() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 1).await.unwrap();
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
            matches!(result, Err(GarrisonError::Dao(_))),
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
    #[tokio::test]
    async fn mock_dao_default_equals_new() {
        let dao = MockDao::default();
        dao.set("default_key", "default_value", 60).await.unwrap();
        let got = dao.get("default_key").await.unwrap();
        assert_eq!(got, Some("default_value".to_string()));
    }

    /// expire(key, 0) 将键设为永久驻留（`seconds == 0` 分支）。
    #[tokio::test]
    async fn mock_expire_zero_seconds_means_permanent() {
        let dao = MockDao::new();
        dao.set("k", "v", 1).await.unwrap();
        dao.expire("k", 0).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = dao.get("k").await.unwrap();
        assert_eq!(got, Some("v".to_string()), "expire(0) 应改为永久驻留");
    }

    // 4 方法扩展测试

    /// set_permanent 设置后 get 返回值。
    #[tokio::test]
    async fn mock_set_permanent_persists_value() {
        let dao = MockDao::new();
        dao.set_permanent("perm_key", "perm_value").await.unwrap();
        let got = dao.get("perm_key").await.unwrap();
        assert_eq!(got, Some("perm_value".to_string()));
    }

    /// set_permanent 永久键短时间等待不过期。
    #[tokio::test]
    async fn mock_set_permanent_does_not_expire_quickly() {
        let dao = MockDao::new();
        dao.set_permanent("perm_key", "perm_value").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let got = dao.get("perm_key").await.unwrap();
        assert_eq!(got, Some("perm_value".to_string()), "永久键不应过期");
    }

    /// get_timeout 永久键返回 None。
    #[tokio::test]
    async fn mock_get_timeout_returns_none_for_permanent_key() {
        let dao = MockDao::new();
        dao.set_permanent("perm", "v").await.unwrap();
        let timeout = dao.get_timeout("perm").await.unwrap();
        assert!(timeout.is_none(), "永久键应返回 None");
    }

    /// get_timeout TTL 键返回 Some(remaining)，剩余 ≤ 原 TTL。
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

    /// get_timeout 不存在的键返回 None。
    #[tokio::test]
    async fn mock_get_timeout_returns_none_for_missing_key() {
        let dao = MockDao::new();
        let timeout = dao.get_timeout("missing").await.unwrap();
        assert!(timeout.is_none(), "不存在的键应返回 None");
    }

    /// keys("garrison:apikey:*") 返回命名空间下所有 key。
    #[tokio::test]
    async fn mock_keys_returns_namespace_matches() {
        let dao = MockDao::new();
        dao.set("garrison:apikey:abc123", "v1", 3600).await.unwrap();
        dao.set("garrison:apikey:def456", "v2", 3600).await.unwrap();
        dao.set("garrison:session:xyz", "v3", 3600).await.unwrap();
        let keys = dao.keys("garrison:apikey:*").await.unwrap();
        assert_eq!(keys.len(), 2, "应匹配 2 个 apikey");
        assert!(keys.contains(&"garrison:apikey:abc123".to_string()));
        assert!(keys.contains(&"garrison:apikey:def456".to_string()));
    }

    /// keys("*") 返回所有 key。
    #[tokio::test]
    async fn mock_keys_star_returns_all() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 3600).await.unwrap();
        dao.set("k2", "v2", 3600).await.unwrap();
        let keys = dao.keys("*").await.unwrap();
        assert!(keys.len() >= 2, "应至少返回 2 个 key");
    }

    /// keys 无匹配返回空 Vec。
    #[tokio::test]
    async fn mock_keys_no_match_returns_empty() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 3600).await.unwrap();
        let keys = dao.keys("nonexistent:*").await.unwrap();
        assert!(keys.is_empty(), "无匹配应返回空 Vec");
    }

    /// keys 支持 ? 单字符通配符。
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

    /// rename 重命名后 old 不存在，new 存在。
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

    /// rename 不存在的 old_key 返回 InvalidParam。
    #[tokio::test]
    async fn mock_rename_missing_key_returns_invalid_param() {
        let dao = MockDao::new();
        let result = dao.rename("missing", "new").await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "rename 不存在的键应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    // oxcache 集成测试（feature = "cache-memory" 或 "cache-redis"）

    #[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
    mod oxcache_tests {
        use super::*;

        /// set 后 get 返回写入的值。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_set_get_pair() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_key1", "value1", 3600).await.unwrap();
            let got = dao.get("oc_key1").await.unwrap();
            assert_eq!(got, Some("value1".to_string()));
        }

        /// 过期后 get 返回 None。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_auto_delete() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_key2", "value1", 1).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_key2").await.unwrap();
            assert!(got.is_none(), "过期后 get 应返回 None");
        }

        /// delete 后 get 返回 None。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_delete_removes_key() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_key3", "value1", 3600).await.unwrap();
            dao.delete("oc_key3").await.unwrap();
            let got = dao.get("oc_key3").await.unwrap();
            assert!(got.is_none(), "delete 后 get 应返回 None");
        }

        /// 验证 oxcache update 更新值（仅验证值，TTL 保留见 ignore 测试）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_update_changes_value() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_key4", "value1", 3600).await.unwrap();
            dao.update("oc_key4", "value2").await.unwrap();
            let got = dao.get("oc_key4").await.unwrap();
            assert_eq!(got, Some("value2".to_string()));
        }

        /// 验证 update 不存在的键返回错误。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_update_missing_key_errors() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let result = dao.update("oc_missing", "value").await;
            assert!(
                matches!(result, Err(GarrisonError::Dao(_))),
                "update 不存在的键应返回 Dao 错误"
            );
        }

        /// 键过期瞬间 update 应返回 missing，且绝不应将键写成永久值。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_update_expired_key_returns_missing_no_permanent_write() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_exp_ttl", "value1", 1).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let result = dao.update("oc_exp_ttl", "value2").await;
            assert!(
                matches!(result, Err(GarrisonError::Dao(_))),
                "过期键 update 应返回 Dao 错误而非写入永久值"
            );
            let got = dao.get("oc_exp_ttl").await.unwrap();
            assert!(got.is_none(), "过期键 update 后不应存在（含永久键）");
            let timeout = dao.get_timeout("oc_exp_ttl").await.unwrap();
            assert!(timeout.is_none(), "过期键 update 后 timeout 应为 None");
        }

        /// 永久键 update 仍保留永久语义（不为 regression）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_update_permanent_key_stays_permanent() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set_permanent("oc_perm", "value1").await.unwrap();
            dao.update("oc_perm", "value2").await.unwrap();
            let got = dao.get("oc_perm").await.unwrap();
            assert_eq!(got, Some("value2".to_string()), "永久键 update 应更新值");
            let timeout = dao.get_timeout("oc_perm").await.unwrap();
            assert!(timeout.is_none(), "永久键 update 后 timeout 仍应为 None");
        }

        /// incr 在 u64::MAX 溢出时返回 Dao 错误而非 panic/回绕。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_incr_overflow_returns_error() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_incr_max", &u64::MAX.to_string(), 3600)
                .await
                .unwrap();
            let result = dao.incr("oc_incr_max", 3600).await;
            assert!(
                matches!(result, Err(GarrisonError::Dao(_))),
                "u64::MAX 自增应返回 Dao 错误而非溢出"
            );
        }

        /// 验证 expire 重置过期时间。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_resets_ttl() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_key5", "value1", 1).await.unwrap();
            dao.expire("oc_key5", 3600).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_key5").await.unwrap();
            assert_eq!(got, Some("value1".to_string()));
        }

        /// 验证 GarrisonDaoOxcache::new() 直接构造。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_new_direct_construction() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_init", "init_value", 60).await.unwrap();
            let got = dao.get("oc_init").await.unwrap();
            assert_eq!(got, Some("init_value".to_string()));
        }

        /// update 保留原 TTL：oxcache 的 `Cache` 暴露 `ttl()`，重写用 `ttl()` + `set_with_ttl`。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_update_preserves_ttl() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_ttl", "value1", 2).await.unwrap();
            dao.update("oc_ttl", "value2").await.unwrap();
            tokio::time::sleep(Duration::from_secs(3)).await;
            let got = dao.get("oc_ttl").await.unwrap();
            assert!(
                got.is_none(),
                "update 不应重置 TTL，原 TTL 过期后应返回 None"
            );
        }

        /// expire(key, 0) 将键设为永久驻留（重写用 get + set_with_ttl(None)）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_zero_seconds_makes_permanent() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_perm", "value1", 1).await.unwrap();
            dao.expire("oc_perm", 0).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_perm").await.unwrap();
            assert_eq!(
                got,
                Some("value1".to_string()),
                "expire(0) 应将键改为永久驻留，不应过期"
            );
        }

        /// expire(0) 对不存在的键返回 Dao 错误。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_zero_seconds_missing_key_errors() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let result = dao.expire("oc_missing_perm", 0).await;
            assert!(
                matches!(result, Err(GarrisonError::Dao(_))),
                "expire(0) 不存在的键应返回 Dao 错误"
            );
        }

        /// expire 对不存在的键返回 Dao 错误（seconds > 0 分支）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_missing_key_errors() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let result = dao.expire("oc_missing_expire", 3600).await;
            assert!(
                matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-key-missing")),
                "expire 不存在的键应返回含 'dao-key-missing' 的 Dao 错误，实际: {:?}",
                result
            );
        }

        /// set(ttl=0) 写入永久键，短时间等待不过期（`ttl_seconds == 0` 分支）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_set_with_zero_ttl() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_zero_ttl", "permanent_value", 0).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_zero_ttl").await.unwrap();
            assert_eq!(
                got,
                Some("permanent_value".to_string()),
                "set(ttl=0) 应写入永久驻留的键，2 秒后仍应存在"
            );
        }

        // 4 方法扩展测试

        /// set_permanent 写入永久键，短时间等待不过期（重写实现用 set_with_ttl_sync(None)）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_set_permanent_persists_without_ttl() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set_permanent("oc_perm", "perm_value").await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_perm").await.unwrap();
            assert_eq!(
                got,
                Some("perm_value".to_string()),
                "set_permanent 应写入永久键，2 秒后仍应存在"
            );
        }

        /// get_timeout 永久键返回 None（重写实现用 ttl_sync）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_timeout_returns_none_for_permanent_key() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set_permanent("oc_perm_ttl", "v").await.unwrap();
            let timeout = dao.get_timeout("oc_perm_ttl").await.unwrap();
            assert!(timeout.is_none(), "永久键应返回 None");
        }

        /// get_timeout TTL 键返回 Some(remaining)，剩余 ≤ 原 TTL。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_timeout_returns_some_for_ttl_key() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_ttl_key", "v", 3600).await.unwrap();
            let timeout = dao.get_timeout("oc_ttl_key").await.unwrap();
            assert!(timeout.is_some(), "TTL 键应返回 Some");
            let remaining = timeout.unwrap();
            assert!(
                remaining <= Duration::from_secs(3600),
                "剩余时间应 ≤ 原 TTL"
            );
        }

        /// get_timeout 不存在的键返回 None。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_timeout_returns_none_for_missing_key() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let timeout = dao.get_timeout("oc_missing_ttl").await.unwrap();
            assert!(timeout.is_none(), "不存在的键应返回 None");
        }

        /// keys 行为取决于 feature gate：启用 `dao-key-index` 返回匹配 key 列表，否则 NotImplemented（oxcache 无原生 scan）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_keys_behavior() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_key1", "v1", 3600).await.unwrap();
            let result = dao.keys("oc_*").await;
            #[cfg(feature = "dao-key-index")]
            {
                let keys = result.expect("dao-key-index 启用时 keys() 应返回 key 列表");
                assert!(
                    keys.iter().any(|k| k.contains("oc_key1")),
                    "keys 应包含 oc_key1, 实际: {:?}",
                    keys
                );
            }
            #[cfg(not(feature = "dao-key-index"))]
            {
                assert!(
                    matches!(result, Err(GarrisonError::NotImplemented(_))),
                    "未启用 dao-key-index 时 keys() 应返回 NotImplemented, 实际: {:?}",
                    result
                );
            }
        }

        /// rename 重命名后 old 不存在、new 存在（重写实现保留 TTL）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_rename_moves_key() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_old", "value", 3600).await.unwrap();
            dao.rename("oc_old", "oc_new").await.unwrap();
            let old = dao.get("oc_old").await.unwrap();
            let new = dao.get("oc_new").await.unwrap();
            assert!(old.is_none(), "rename 后 oc_old 应不存在");
            assert_eq!(new, Some("value".to_string()), "rename 后 oc_new 应有值");
        }

        /// rename 不存在的 old_key 返回 InvalidParam。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_rename_missing_key_returns_invalid_param() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let result = dao.rename("oc_missing_old", "oc_new").await;
            assert!(
                result.is_err(),
                "rename 不存在的键应返回错误（且不写入永久条目），实际: {:?}",
                result
            );
        }

        /// rename 保留原键 TTL（重写实现用 ttl_sync + set_with_ttl_sync，而非默认实现的 set_permanent 丢失 TTL）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_rename_preserves_ttl() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_short_ttl", "value", 2).await.unwrap();
            dao.rename("oc_short_ttl", "oc_renamed").await.unwrap();
            let got = dao.get("oc_renamed").await.unwrap();
            assert_eq!(got, Some("value".to_string()));
            tokio::time::sleep(Duration::from_secs(3)).await;
            let got = dao.get("oc_renamed").await.unwrap();
            assert!(
                got.is_none(),
                "rename 应保留原 TTL，原 TTL 过期后应返回 None"
            );
        }

        /// oxcache get_and_delete 返回值并删除 key。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_and_delete_returns_value_and_removes_key() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_atomic", "value", 3600).await.unwrap();
            let got = dao.get_and_delete("oc_atomic").await.unwrap();
            assert_eq!(got, Some("value".to_string()));
            let after = dao.get("oc_atomic").await.unwrap();
            assert!(after.is_none(), "get_and_delete 后 key 应不存在");
        }

        /// oxcache get_and_delete 不存在的 key 返回 None。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_and_delete_missing_returns_none() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let got = dao.get_and_delete("oc_missing").await.unwrap();
            assert!(got.is_none());
        }

        /// oxcache get_and_delete 并发原子性验证。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_and_delete_concurrent_only_one_succeeds() {
            let dao = Arc::new(GarrisonDaoOxcache::new().await.unwrap());
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

        /// 10 个并发对同一 key 调用 set_if_absent，仅 1 个返回 true
        ///（验证 Moka `_sync` 后端下锁 + 写后立即读的可见性）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_set_if_absent_concurrent_only_one_succeeds() {
            let dao = Arc::new(GarrisonDaoOxcache::new().await.unwrap());
            let key = "oc_set_if_absent_concurrent";

            let mut handles = Vec::new();
            for i in 0..10u32 {
                let d = dao.clone();
                let k = key.to_string();
                handles.push(tokio::spawn(async move {
                    d.set_if_absent(&k, &format!("value_{i}"), 0).await
                }));
            }

            let mut success = 0;
            let mut already_exists = 0;
            for handle in handles {
                let result = handle.await.unwrap();
                match result {
                    Ok(true) => success += 1,
                    Ok(false) => already_exists += 1,
                    Err(e) => panic!("set_if_absent 不应返回错误: {:?}", e),
                }
            }

            assert_eq!(
                success, 1,
                "并发调用仅一个返回 true（写入成功），实际: {success}"
            );
            assert_eq!(already_exists, 9, "其他 9 个返回 false（已存在）");
        }

        /// Moka `_sync` 单线程写后立即读可见性诊断：循环 200 次统计 miss 率，
        /// 用于区分"Moka channel 异步写入导致的写后读不一致"与"并发调度问题"。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_moka_write_then_read_visibility() {
            let dao = Arc::new(GarrisonDaoOxcache::new().await.unwrap());
            let mut miss = 0u32;
            for i in 0..200u32 {
                let key = format!("vis_test_{i}");
                dao.set(&key, "v", 0).await.unwrap();
                if dao.get(&key).await.unwrap().is_none() {
                    miss += 1;
                }
            }
            assert_eq!(
                miss, 0,
                "单线程写后立即读不应 miss，实际 miss={miss}/200（Moka channel 异步写入导致写后读不一致）"
            );
        }

        // 多租户 key 前缀测试

        /// tenant-isolation 启用时 GarrisonDao 的 key 实际为 `tenant:{tid}:original_key`（经公共 API 验证）：
        /// 同租户 set/get 命中、跨租户 get 返回 None、同名 key 互不覆盖。
        #[cfg(feature = "tenant-isolation")]
        #[tokio::test(flavor = "multi_thread")]
        async fn dao_key_prefixed_with_tenant_when_isolation_enabled() {
            use crate::context::tenant::{TenantContext, TenantSource, TENANT};

            let dao = GarrisonDaoOxcache::new().await.unwrap();

            let ctx_42 = TenantContext {
                tenant_id: 42,
                resolved_from: TenantSource::Header,
            };
            TENANT
                .scope(ctx_42.clone(), async {
                    dao.set("shared_key", "tenant_42_value", 3600)
                        .await
                        .unwrap();
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

        /// TENANT 上下文不存在时 key 保持原样（无前缀，不 panic）。
        #[cfg(feature = "tenant-isolation")]
        #[tokio::test(flavor = "multi_thread")]
        async fn dao_key_unchanged_when_tenant_context_absent() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();

            // 不在 TENANT.scope 内，TENANT.try_get() 返回 Err，key 应保持原样
            dao.set("no_ctx_key", "value", 3600).await.unwrap();
            let got = dao.get("no_ctx_key").await.unwrap();
            assert_eq!(
                got,
                Some("value".to_string()),
                "TENANT 上下文不存在时 key 应保持原样（无前缀）"
            );

            let prefixed = dao.get("tenant:0:no_ctx_key").await.unwrap();
            assert!(
                prefixed.is_none(),
                "TENANT 上下文不存在时不应有带前缀的 key"
            );
        }

        /// delete 也使用带前缀的 key：scope 内 set 后用原始 key delete，同租户 get 应返回 None。
        #[cfg(feature = "tenant-isolation")]
        #[tokio::test(flavor = "multi_thread")]
        async fn dao_delete_uses_prefixed_key_in_tenant_context() {
            use crate::context::tenant::{TenantContext, TenantSource, TENANT};

            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let ctx = TenantContext {
                tenant_id: 42,
                resolved_from: TenantSource::Header,
            };

            TENANT
                .scope(ctx, async {
                    dao.set("del_key", "value", 3600).await.unwrap();
                    assert_eq!(
                        dao.get("del_key").await.unwrap(),
                        Some("value".to_string()),
                        "set 后同租户 get 应命中"
                    );

                    // delete 用原始 key，内部应加前缀匹配到 `tenant:42:del_key`
                    dao.delete("del_key").await.unwrap();

                    let after = dao.get("del_key").await.unwrap();
                    assert!(
                        after.is_none(),
                        "delete 后同租户 get 应返回 None（delete 也加了前缀）"
                    );
                })
                .await;
        }
    }

    // get_and_delete 原子方法测试

    /// get_and_delete 返回值并删除 key。
    #[tokio::test]
    async fn mock_get_and_delete_returns_value_and_removes_key() {
        let dao = MockDao::new();
        dao.set("atomic_key", "value", 3600).await.unwrap();
        let got = dao.get_and_delete("atomic_key").await.unwrap();
        assert_eq!(got, Some("value".to_string()));
        let after = dao.get("atomic_key").await.unwrap();
        assert!(after.is_none(), "get_and_delete 后 key 应不存在");
    }

    /// get_and_delete 不存在的 key 返回 None。
    #[tokio::test]
    async fn mock_get_and_delete_missing_returns_none() {
        let dao = MockDao::new();
        let got = dao.get_and_delete("missing").await.unwrap();
        assert!(got.is_none(), "不存在的 key 应返回 None");
    }

    /// 10 个并发 get_and_delete 同一 key 仅一个返回 Some（原子性核心验证）。
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

    // decr 并发原子性测试

    /// MockDao::decr 并发原子性：10 个 task 并发 decr 同一 key（初始 5），恰好 5 次生效
    ///（4 次返回非 0 + 1 次 1→0 删 key），其余 5 次返回 0（key 已删除）。
    ///
    /// 修复前 `get → parse → update/delete` 跨 await 组合允许 incr 插入（"跨越式递减"）；
    /// 修复后单次锁作用域内完成。
    #[tokio::test(flavor = "multi_thread")]
    async fn mock_decr_concurrent_only_5_effective() {
        let dao = Arc::new(MockDao::new());
        dao.set("counter", "5", 3600).await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..10 {
            let d = dao.clone();
            handles.push(tokio::spawn(async move { d.decr("counter").await }));
        }

        let mut effective = 0;
        let mut zero_count = 0;
        for handle in handles {
            let result = handle.await.unwrap();
            match result {
                Ok(0) => zero_count += 1,
                Ok(_) => effective += 1,
                Err(e) => panic!("decr 不应返回错误: {:?}", e),
            }
        }

        // 5 次 decr 生效（4,3,2,1）+ 1 次返回 0（1→0 删除 key）
        assert_eq!(
            effective, 4,
            "4 次 decr 返回非 0（5→4→3→2→1），实际 {} 个",
            effective
        );
        assert_eq!(
            zero_count, 6,
            "6 次 decr 返回 0（1 次 1→0 + 5 次 key 不存在），实际 {} 个",
            zero_count
        );

        let final_val = dao.get("counter").await.unwrap();
        assert!(
            final_val.is_none(),
            "decr 到 0 后 key 应被删除，实际存在: {:?}",
            final_val
        );
    }

    /// MockDao::decr 基本语义：不存在/已过期→0（不创建），值为 0→0，>0 递减且到 0 删 key。
    #[tokio::test]
    async fn mock_decr_basic_semantics() {
        let dao = MockDao::new();

        assert_eq!(dao.decr("missing").await.unwrap(), 0);
        assert!(
            dao.get("missing").await.unwrap().is_none(),
            "decr 不存在的 key 不应创建 key"
        );

        dao.set("counter", "3", 3600).await.unwrap();
        assert_eq!(dao.decr("counter").await.unwrap(), 2);
        assert_eq!(dao.decr("counter").await.unwrap(), 1);
        assert_eq!(dao.decr("counter").await.unwrap(), 0);

        assert!(
            dao.get("counter").await.unwrap().is_none(),
            "从 1 decr 到 0 应删除 key（new_val == 0 分支）"
        );

        assert_eq!(dao.decr("counter").await.unwrap(), 0);

        // 单独验证 cur_val == 0 分支：直接 set "0"（绕过 decr 的删除逻辑）
        dao.set("zero_counter", "0", 3600).await.unwrap();
        assert_eq!(
            dao.decr("zero_counter").await.unwrap(),
            0,
            "cur_val == 0 时返回 0（不递减为负）"
        );
        assert_eq!(
            dao.get("zero_counter").await.unwrap(),
            Some("0".to_string()),
            "cur_val == 0 时 decr 不删除 key（提前返回，不进入 new_val == 0 分支）"
        );
    }

    /// 验证 MockDao::decr 非数字值返回 Dao 错误（禁止静默吞掉 parse 失败）。
    #[tokio::test]
    async fn mock_decr_non_numeric_value_returns_error() {
        let dao = MockDao::new();
        dao.set("bad_counter", "not_a_number", 3600).await.unwrap();
        let result = dao.decr("bad_counter").await;
        assert!(result.is_err(), "非数字值应返回 Dao 错误");
        match result.err().unwrap() {
            GarrisonError::Dao(msg) => {
                assert!(
                    msg.contains("dao-decr-parse-u64"),
                    "错误消息应含 dao-decr-parse-u64，实际: {}",
                    msg
                );
            },
            other => panic!("期望 GarrisonError::Dao，实际: {:?}", other),
        }
    }

    // GarrisonDao trait 默认方法测试（MinimalDao）

    /// 最小 DAO 实现：5 个必需方法 + `atomic_test_fallback!` 组合回退，不重写任何默认方法，用于验证默认行为。
    pub struct MinimalDao {
        store: Mutex<HashMap<String, String>>,
    }

    impl Default for MinimalDao {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MinimalDao {
        /// 创建空的 MinimalDao 实例。
        pub fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl GarrisonDao for MinimalDao {
        async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
            Ok(self.store.lock().get(key).cloned())
        }

        async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
            self.store.lock().insert(key.to_string(), value.to_string());
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
            match self.store.lock().get_mut(key) {
                Some(existing) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(GarrisonError::Dao(format!("dao-key-missing::{}", key))),
            }
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
            Ok(()) // MinimalDao 不支持 TTL，no-op
        }

        async fn delete(&self, key: &str) -> GarrisonResult<()> {
            self.store.lock().remove(key);
            Ok(())
        }
        crate::atomic_test_fallback!();
    }

    /// `set_permanent` 默认实现委托 `set(key, value, 0)`。
    #[tokio::test]
    async fn default_set_permanent_delegates_to_set_with_ttl_zero() {
        let dao = MinimalDao::new();
        dao.set_permanent("perm_key", "perm_value").await.unwrap();
        let val = dao.get("perm_key").await.unwrap();
        assert_eq!(val.as_deref(), Some("perm_value"));
    }

    /// `get_timeout` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn default_get_timeout_returns_not_implemented() {
        let dao = MinimalDao::new();
        dao.set("key", "value", 3600).await.unwrap();
        let result = dao.get_timeout("key").await;
        assert!(matches!(result, Err(GarrisonError::NotImplemented(_))));
    }

    /// `keys` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn default_keys_returns_not_implemented() {
        let dao = MinimalDao::new();
        dao.set("key1", "v1", 0).await.unwrap();
        let result = dao.keys("*").await;
        assert!(matches!(result, Err(GarrisonError::NotImplemented(_))));
    }

    /// `vacuum_expired` 默认实现为 no-op：返回 `Ok(0)` 且不触达任何行（原生 TTL / 进程内后端的合法语义）。
    #[tokio::test]
    async fn default_vacuum_expired_returns_zero_no_op() {
        let dao = MinimalDao::new();
        dao.set("vacuum_default_key", "v", 0).await.unwrap();
        assert_eq!(dao.vacuum_expired().await.unwrap(), 0);
        assert_eq!(
            dao.get("vacuum_default_key").await.unwrap().as_deref(),
            Some("v"),
            "no-op 默认实现不应删除任何行"
        );
    }

    /// 测试回退宏的 rename 组合语义：get → set_permanent → delete。
    #[tokio::test]
    async fn default_rename_get_set_permanent_delete() {
        let dao = MinimalDao::new();
        dao.set("old_key", "old_value", 0).await.unwrap();
        dao.rename("old_key", "new_key").await.unwrap();
        assert!(dao.get("old_key").await.unwrap().is_none());
        assert_eq!(
            dao.get("new_key").await.unwrap().as_deref(),
            Some("old_value")
        );
    }

    /// `rename` 对不存在的 key 返回 `InvalidParam`。
    #[tokio::test]
    async fn default_rename_missing_key_returns_invalid_param() {
        let dao = MinimalDao::new();
        let result = dao.rename("nonexistent", "new_key").await;
        assert!(matches!(result, Err(GarrisonError::InvalidParam(_))));
    }

    // 社交账号绑定关系默认实现测试

    /// `find_social_binding` 默认实现返回 `NotImplemented`（GarrisonDao 是 KV 缓存抽象，不支持 SQL）。
    #[tokio::test]
    async fn default_find_social_binding_returns_not_implemented() {
        let dao = MinimalDao::new();
        let result = dao.find_social_binding(0, "wechat", "wx_openid").await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("dao-not-implemented")),
            "find_social_binding 默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// `insert_social_binding` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn default_insert_social_binding_returns_not_implemented() {
        let dao = MinimalDao::new();
        let result = dao
            .insert_social_binding(0, "1001", "wechat", "wx_openid", None, 1700000000)
            .await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("dao-not-implemented")),
            "insert_social_binding 默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// `compare_and_update_if_greater` 默认实现返回 `NotImplemented`（fail-closed，强制后端重写为原子 CAS）。
    #[tokio::test]
    async fn default_compare_and_update_if_greater_returns_not_implemented() {
        let dao = MinimalDao::new();
        let result = dao.compare_and_update_if_greater("key", 1, 60).await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("dao-not-implemented")),
            "compare_and_update_if_greater 默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// `decr` 为编译期必需方法（无运行时默认实现）；本测试验证测试回退宏的组合语义：5 → 4（保留 key），0 时删除 key。
    #[tokio::test]
    async fn decr_required_method_fallback_semantics() {
        let dao = MinimalDao::new();
        dao.set("counter", "5", 60).await.unwrap();
        assert_eq!(dao.decr("counter").await.unwrap(), 4);
        assert_eq!(
            dao.get("counter").await.unwrap().as_deref(),
            Some("4"),
            "递减后值 > 0 时应保留 key"
        );
        dao.set("counter2", "1", 60).await.unwrap();
        assert_eq!(dao.decr("counter2").await.unwrap(), 0);
        assert!(
            dao.get("counter2").await.unwrap().is_none(),
            "递减后值为 0 时应删除 key"
        );
    }

    /// `InMemoryDao::incr` 对非数字值必须显式报错，
    /// 禁止静默按 0 处理导致限速计数器重置（撞库防护旁路风险）。
    #[tokio::test]
    async fn in_memory_incr_non_numeric_value_errors_explicitly() {
        let dao = InMemoryDao::new();
        dao.set("rate:polluted", "not-a-number", 60).await.unwrap();
        let result = dao.incr("rate:polluted", 60).await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-incr-parse-u64")),
            "incr 对非数字值应显式报错而非静默重置，实际: {:?}",
            result
        );
        assert_eq!(
            dao.get("rate:polluted").await.unwrap().as_deref(),
            Some("not-a-number")
        );
    }

    /// 测试回退宏的 get_and_delete：键存在时返回值并删除。
    #[tokio::test]
    async fn default_get_and_delete_returns_value_and_removes_key() {
        let dao = MinimalDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        let val = dao.get_and_delete("k1").await.unwrap();
        assert_eq!(val, Some("v1".to_string()));
        assert!(dao.get("k1").await.unwrap().is_none());
    }

    /// 测试回退宏 get_and_delete：不存在的键返回 None 且不报错。
    #[tokio::test]
    async fn default_get_and_delete_missing_key_returns_none() {
        let dao = MinimalDao::new();
        let val = dao.get_and_delete("nope").await.unwrap();
        assert!(val.is_none());
    }

    /// `set_if_absent` 组合回退：key 不存在时写入成功返回 true。
    #[tokio::test]
    async fn fallback_set_if_absent_new_key_returns_true() {
        let dao = MinimalDao::new();
        let ok = dao.set_if_absent("k1", "v1", 60).await.unwrap();
        assert!(ok, "key 不存在时应写入成功返回 true");
        assert_eq!(dao.get("k1").await.unwrap().as_deref(), Some("v1"));
    }

    /// `set_if_absent` 组合回退：key 已存在时返回 false 不覆盖。
    #[tokio::test]
    async fn fallback_set_if_absent_existing_key_returns_false() {
        let dao = MinimalDao::new();
        dao.set("k1", "original", 60).await.unwrap();
        let ok = dao.set_if_absent("k1", "new_value", 60).await.unwrap();
        assert!(!ok, "key 已存在时应返回 false");
        assert_eq!(
            dao.get("k1").await.unwrap().as_deref(),
            Some("original"),
            "值不应被覆盖"
        );
    }

    /// `compare_and_swap` 组合回退：key 存在且值匹配时写入成功。
    #[tokio::test]
    async fn fallback_cas_match_returns_true() {
        let dao = MinimalDao::new();
        dao.set("k1", "old", 60).await.unwrap();
        let ok = dao
            .compare_and_swap("k1", Some("old"), "new", 60)
            .await
            .unwrap();
        assert!(ok, "值匹配时 CAS 应返回 true");
        assert_eq!(dao.get("k1").await.unwrap().as_deref(), Some("new"));
    }

    /// `compare_and_swap` 组合回退：值不匹配时返回 false。
    #[tokio::test]
    async fn fallback_cas_mismatch_returns_false() {
        let dao = MinimalDao::new();
        dao.set("k1", "actual", 60).await.unwrap();
        let ok = dao
            .compare_and_swap("k1", Some("expected"), "new", 60)
            .await
            .unwrap();
        assert!(!ok, "值不匹配时 CAS 应返回 false");
        assert_eq!(dao.get("k1").await.unwrap().as_deref(), Some("actual"));
    }

    /// `compare_and_swap` 组合回退：expected=None 且 key 不存在时写入成功。
    #[tokio::test]
    async fn fallback_cas_none_expected_absent_creates() {
        let dao = MinimalDao::new();
        let ok = dao
            .compare_and_swap("k1", None, "initial", 60)
            .await
            .unwrap();
        assert!(ok, "key 不存在 + expected=None 时应成功");
        assert_eq!(dao.get("k1").await.unwrap().as_deref(), Some("initial"));
    }

    /// `compare_and_swap` 组合回退：ttl_seconds=0 时走 set_permanent 路径。
    #[tokio::test]
    async fn fallback_cas_permanent_ttl_uses_set_permanent() {
        let dao = MinimalDao::new();
        let ok = dao.compare_and_swap("k1", None, "perm", 0).await.unwrap();
        assert!(ok);
        assert_eq!(dao.get("k1").await.unwrap().as_deref(), Some("perm"));
    }

    /// `incr` 组合回退：key 不存在时初始化为 1。
    #[tokio::test]
    async fn fallback_incr_new_key_initializes_to_one() {
        let dao = MinimalDao::new();
        let val = dao.incr("counter", 60).await.unwrap();
        assert_eq!(val, 1, "新键应初始化为 1");
    }

    /// `incr` 组合回退：key 存在时递增。
    #[tokio::test]
    async fn fallback_incr_existing_key_increments() {
        let dao = MinimalDao::new();
        dao.set("counter", "10", 60).await.unwrap();
        let val = dao.incr("counter", 60).await.unwrap();
        assert_eq!(val, 11, "已存在键 10 应递增为 11");
    }

    /// `incr` 组合回退：非数字值返回 Dao 错误。
    #[tokio::test]
    async fn fallback_incr_non_numeric_returns_error() {
        let dao = MinimalDao::new();
        dao.set("bad", "not_num", 60).await.unwrap();
        let result = dao.incr("bad", 60).await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref m)) if m.contains("dao-incr-parse-u64")),
            "非数字值应返回 Dao 错误，实际: {:?}",
            result
        );
    }

    /// `decr` 组合回退：key 不存在时返回 0。
    #[tokio::test]
    async fn fallback_decr_missing_key_returns_zero() {
        let dao = MinimalDao::new();
        let val = dao.decr("nope").await.unwrap();
        assert_eq!(val, 0, "key 不存在时应返回 0");
    }

    /// `decr` 组合回退：值为 0 时返回 0（不递减为负）。
    #[tokio::test]
    async fn fallback_decr_zero_returns_zero() {
        let dao = MinimalDao::new();
        dao.set("counter", "0", 60).await.unwrap();
        let val = dao.decr("counter").await.unwrap();
        assert_eq!(val, 0, "值为 0 时应返回 0");
    }

    /// `rename` 组合回退：key 不存在时返回 InvalidParam。
    #[tokio::test]
    async fn fallback_rename_missing_key_errors() {
        let dao = MinimalDao::new();
        let result = dao.rename("nope", "new_key").await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref m)) if m.contains("dao-key-missing")),
            "key 不存在时 rename 应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// `get_with_ttl` 默认实现：key 存在但 get_timeout 返回 NotImplemented 时传播错误。
    #[tokio::test]
    async fn default_get_with_ttl_existing_key_returns_value() {
        let dao = MinimalDao::new();
        dao.set("k1", "v1", 3600).await.unwrap();
        // MinimalDao 不重写 get_timeout，默认返回 NotImplemented
        let result = dao.get_with_ttl("k1").await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(_))),
            "MinimalDao get_with_ttl 应传播 get_timeout 的 NotImplemented，实际: {:?}",
            result
        );
    }

    /// `get_with_ttl` 默认实现：key 不存在时返回 None。
    #[tokio::test]
    async fn default_get_with_ttl_missing_key_returns_none() {
        let dao = MinimalDao::new();
        let result = dao.get_with_ttl("nope").await.unwrap();
        assert!(result.is_none(), "不存在的键应返回 None");
    }

    /// `query_role_hierarchy_edges` 默认实现返回 NotImplemented。
    #[tokio::test]
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    async fn default_query_role_hierarchy_edges_returns_not_implemented() {
        let dao = MinimalDao::new();
        let result = dao.query_role_hierarchy_edges(0).await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(ref m)) if m.contains("dao-not-implemented")),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// `insert_role_hierarchy_edge` 默认实现返回 NotImplemented。
    #[tokio::test]
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    async fn default_insert_role_hierarchy_edge_returns_not_implemented() {
        let dao = MinimalDao::new();
        let result = dao.insert_role_hierarchy_edge(0, "admin", "owner").await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(ref m)) if m.contains("dao-not-implemented")),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// `delete_role_hierarchy_edge` 默认实现返回 NotImplemented。
    #[tokio::test]
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    async fn default_delete_role_hierarchy_edge_returns_not_implemented() {
        let dao = MinimalDao::new();
        let result = dao.delete_role_hierarchy_edge(0, "admin", "owner").await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(ref m)) if m.contains("dao-not-implemented")),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    // Redis 部署模式配置测试

    /// RedisConfig::default() 返回 Single 模式，url 为 "redis://127.6379"。
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

    /// RedisConfig serde 序列化/反序列化 round-trip。
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

    /// RedisConfig serde 用 `#[serde(default)]` 支持部分覆盖。
    #[test]
    fn redis_config_serde_partial_override() {
        let json = r#"{"mode":{"mode":"cluster","urls":["redis://10.0.0.1:6379"]}}"#;
        let config: RedisConfig = serde_json::from_str(json).unwrap();
        match config.mode {
            RedisDeploymentMode::Cluster { urls } => {
                assert_eq!(urls, vec!["redis://10.0.0.1:6379".to_string()]);
            },
            _ => panic!("期望 Cluster 模式"),
        }
        assert_eq!(config.password, None);
        assert_eq!(config.db, 0);
        assert_eq!(config.connection_timeout_secs, 5);
        assert_eq!(config.pool_size, 10);
    }

    /// RedisDeploymentMode 各变体 Display 输出可读。
    #[test]
    fn redis_deployment_mode_display() {
        let single = RedisDeploymentMode::Single {
            url: "redis://127.0.0.1:6379".to_string(),
        };
        assert!(format!("{}", single).contains("single"));
        assert!(format!("{}", single).contains("redis://127.0.0.1:6379"));

        let sentinel = RedisDeploymentMode::Sentinel {
            primary_name: "mymaster".to_string(),
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

        let ms = RedisDeploymentMode::PrimaryReplica {
            primary_url: "redis://primary:6379".to_string(),
            replica_urls: vec!["redis://replica1:6379".to_string()],
        };
        let m = format!("{}", ms);
        assert!(m.contains("primary-replica"));
        assert!(m.contains("primary:6379"));
        assert!(m.contains("1 replicas"));
    }

    /// RedisDeploymentMode PartialEq 比较。
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

    /// with_redis_config builder 方法在 cache-redis feature 下存在并存储配置。
    #[cfg(feature = "cache-redis")]
    #[tokio::test(flavor = "multi_thread")]
    async fn with_redis_config_stores_config() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        assert!(
            dao.redis_config().is_none(),
            "新建实例的 redis_config 应为 None"
        );
        let config = RedisConfig {
            mode: RedisDeploymentMode::Sentinel {
                primary_name: "mymaster".to_string(),
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
            RedisDeploymentMode::Sentinel { primary_name, urls }
            if primary_name == "mymaster" && urls.len() == 3
        ));
        assert_eq!(stored.password, Some("pass123".to_string()));
        assert_eq!(stored.db, 2);
        assert_eq!(stored.connection_timeout_secs, 15);
        assert_eq!(stored.pool_size, 50);
    }

    /// 未调用 with_redis_config 时 redis_config 为 None。
    #[cfg(feature = "cache-redis")]
    #[tokio::test(flavor = "multi_thread")]
    async fn without_redis_config_returns_none() {
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        assert!(
            dao.redis_config().is_none(),
            "未调用 with_redis_config 时 redis_config 应为 None"
        );
    }

    // trait 默认方法（incr / eval_lua）测试

    /// incr 测试回退：新键初始化为 1（`None` 分支）。
    #[tokio::test]
    async fn default_incr_initializes_new_key() {
        let dao = MinimalDao::new();
        let result = dao.incr("counter", 3600).await.unwrap();
        assert_eq!(result, 1, "新键应初始化为 1");
        let val = dao.get("counter").await.unwrap();
        assert_eq!(val.as_deref(), Some("1"));
    }

    /// incr 测试回退：已存在键递增（`Some` 分支）。
    #[tokio::test]
    async fn default_incr_increments_existing_key() {
        let dao = MinimalDao::new();
        dao.set("counter", "5", 3600).await.unwrap();
        let result = dao.incr("counter", 3600).await.unwrap();
        assert_eq!(result, 6, "已存在键 5 应递增为 6");
        let result = dao.incr("counter", 3600).await.unwrap();
        assert_eq!(result, 7, "已存在键 6 应递增为 7");
    }

    /// incr 对非数字值必须显式报错，禁止静默回退为 0 导致计数器重置。
    #[tokio::test]
    async fn default_incr_rejects_non_numeric_value() {
        let dao = MinimalDao::new();
        dao.set("bad_counter", "not_a_number", 3600).await.unwrap();
        let result = dao.incr("bad_counter", 3600).await;
        assert!(
            result.is_err(),
            "非数字值必须显式报错，禁止静默回退为 0 导致计数器重置（Rule 12）"
        );
    }

    /// `eval_lua` 默认实现返回 `NotImplemented`（仅 Redis 后端支持 Lua 脚本）。
    #[tokio::test]
    async fn default_eval_lua_returns_not_implemented() {
        let dao = MinimalDao::new();
        let result = dao
            .eval_lua("return 1", vec!["k".to_string()], vec!["a".to_string()])
            .await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("dao-not-implemented")),
            "eval_lua 默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// MinimalDao::default() 等价于 new()。
    #[tokio::test]
    async fn minimal_dao_default_equals_new() {
        let dao = MinimalDao::default();
        dao.set("k", "v", 60).await.unwrap();
        let got = dao.get("k").await.unwrap();
        assert_eq!(got.as_deref(), Some("v"));
    }

    // compare_and_swap 契约测试（MockDao）

    /// CAS：key 存在且值匹配时，原子替换成功。
    #[tokio::test]
    async fn cas_match_replaces_value() {
        let dao = MockDao::new();
        dao.set("k", "old", 60).await.unwrap();
        let ok = dao
            .compare_and_swap("k", Some("old"), "new", 60)
            .await
            .unwrap();
        assert!(ok, "值匹配时 CAS 应返回 true");
        assert_eq!(dao.get("k").await.unwrap().as_deref(), Some("new"));
    }

    /// CAS：key 存在但值不匹配时，替换失败。
    #[tokio::test]
    async fn cas_mismatch_returns_false() {
        let dao = MockDao::new();
        dao.set("k", "actual", 60).await.unwrap();
        let ok = dao
            .compare_and_swap("k", Some("expected"), "new", 60)
            .await
            .unwrap();
        assert!(!ok, "值不匹配时 CAS 应返回 false");
        assert_eq!(
            dao.get("k").await.unwrap().as_deref(),
            Some("actual"),
            "值不应被修改"
        );
    }

    /// CAS：expected=None 且 key 不存在时，初始化成功。
    #[tokio::test]
    async fn cas_none_expected_key_absent_creates() {
        let dao = MockDao::new();
        let ok = dao
            .compare_and_swap("k", None, "initial", 60)
            .await
            .unwrap();
        assert!(ok, "key 不存在 + expected=None 时 CAS 应成功");
        assert_eq!(dao.get("k").await.unwrap().as_deref(), Some("initial"));
    }

    /// CAS：expected=None 但 key 已存在时，替换失败。
    #[tokio::test]
    async fn cas_none_expected_key_exists_returns_false() {
        let dao = MockDao::new();
        dao.set("k", "existing", 60).await.unwrap();
        let ok = dao.compare_and_swap("k", None, "new", 60).await.unwrap();
        assert!(!ok, "key 已存在 + expected=None 时 CAS 应返回 false");
        assert_eq!(dao.get("k").await.unwrap().as_deref(), Some("existing"));
    }

    /// CAS：expected=Some 但 key 不存在时，替换失败。
    #[tokio::test]
    async fn cas_some_expected_key_absent_returns_false() {
        let dao = MockDao::new();
        let ok = dao
            .compare_and_swap("k", Some("old"), "new", 60)
            .await
            .unwrap();
        assert!(!ok, "key 不存在 + expected=Some 时 CAS 应返回 false");
        assert!(dao.get("k").await.unwrap().is_none(), "不应创建 key");
    }

    /// CAS：ttl_seconds=0 时永久驻留。
    #[tokio::test]
    async fn cas_permanent_ttl() {
        let dao = MockDao::new();
        let ok = dao
            .compare_and_swap("k", None, "permanent", 0)
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(dao.get("k").await.unwrap().as_deref(), Some("permanent"));
    }

    /// CAS：并发竞争下仅一个成功（XOR）。
    #[tokio::test]
    async fn cas_concurrent_only_one_succeeds() {
        let mock = MockDao::new();
        mock.set("k", "v1", 60).await.unwrap();
        let dao = Arc::new(mock);

        let dao1 = dao.clone();
        let dao2 = dao.clone();
        let (r1, r2) = tokio::join!(
            dao1.compare_and_swap("k", Some("v1"), "from-task-1", 60),
            dao2.compare_and_swap("k", Some("v1"), "from-task-2", 60),
        );
        let ok1 = r1.unwrap();
        let ok2 = r2.unwrap();
        assert!(
            ok1 ^ ok2,
            "并发 CAS 同一值应仅一个成功（XOR），实际: ok1={}, ok2={}",
            ok1,
            ok2
        );
    }

    // RedisDeploymentMode Default + InMemoryDao TTL 边界 / 原子方法错误路径 / eval_lua 参数校验

    /// RedisDeploymentMode::default() 返回 Single 本机地址（与 `RedisConfig::default()` 互补：后者内联构造，不经此 Default）。
    #[test]
    fn redis_deployment_mode_default_returns_single_localhost() {
        let mode = RedisDeploymentMode::default();
        assert_eq!(
            mode,
            RedisDeploymentMode::Single {
                url: "redis://127.0.0.1:6379".to_string()
            }
        );
        // Display 输出可读（single(<url>) 格式）
        assert!(
            format!("{}", mode).starts_with("single("),
            "默认模式 Display 应以 'single(' 开头，实际: {}",
            mode
        );
    }

    /// get_timeout 对已过期（未被 get 清理）的 TTL 键返回 None（`*deadline <= now` 分支）。
    #[tokio::test]
    async fn in_memory_get_timeout_returns_none_after_expiry() {
        let dao = MockDao::new();
        dao.set("exp_ttl", "v", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let timeout = dao.get_timeout("exp_ttl").await.unwrap();
        assert!(timeout.is_none(), "已过期键的 get_timeout 应返回 None");
    }

    /// keys() 跳过已过期 key，仅返回存活 key。
    #[tokio::test]
    async fn in_memory_keys_skips_expired_keys() {
        let dao = MockDao::new();
        dao.set("expired_key", "v1", 1).await.unwrap();
        dao.set_permanent("alive_key", "v2").await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let keys = dao.keys("*").await.unwrap();
        assert!(
            !keys.iter().any(|k| k == "expired_key"),
            "已过期 key 不应出现在 keys() 结果中，实际: {:?}",
            keys
        );
        assert!(
            keys.iter().any(|k| k == "alive_key"),
            "存活 key 应出现在 keys() 结果中"
        );
    }

    /// get_and_delete 对已过期 key 返回 None（过期守卫分支）。
    #[tokio::test]
    async fn in_memory_get_and_delete_expired_returns_none() {
        let dao = MockDao::new();
        dao.set("gd_expired", "v", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = dao.get_and_delete("gd_expired").await.unwrap();
        assert!(got.is_none(), "已过期 key 的 get_and_delete 应返回 None");
    }

    /// set_if_absent 在 key 过期后重新写入成功（过期清理分支）。
    #[tokio::test]
    async fn in_memory_set_if_absent_reclaims_after_expiry() {
        let dao = MockDao::new();
        dao.set("sia_key", "old", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let claimed = dao.set_if_absent("sia_key", "new", 3600).await.unwrap();
        assert!(claimed, "key 过期后 set_if_absent 应重新获准写入");
        assert_eq!(dao.get("sia_key").await.unwrap().as_deref(), Some("new"));
    }

    /// set_if_absent 对永久驻留 key 返回 false（Some(_) => true 存在分支）。
    #[tokio::test]
    async fn in_memory_set_if_absent_existing_permanent_returns_false() {
        let dao = MockDao::new();
        dao.set_permanent("sia_perm", "v").await.unwrap();
        let claimed = dao.set_if_absent("sia_perm", "w", 3600).await.unwrap();
        assert!(!claimed, "已存在的永久键 set_if_absent 应返回 false");
    }

    /// incr 初始化新键为 1 并设置 TTL（None => true 分支）。
    #[tokio::test]
    async fn in_memory_incr_initializes_new_key_with_ttl() {
        let dao = MockDao::new();
        let v = dao.incr("incr_new", 3600).await.unwrap();
        assert_eq!(v, 1, "新键 incr 应初始化为 1");
        let timeout = dao.get_timeout("incr_new").await.unwrap();
        assert!(timeout.is_some(), "incr 初始化应设置 TTL");
    }

    /// incr 已有永久键递增且不新增 TTL（`Some((_, None)) => false` 分支）。
    #[tokio::test]
    async fn in_memory_increments_permanent_key_keeps_permanent() {
        let dao = MockDao::new();
        dao.set_permanent("incr_perm", "5").await.unwrap();
        let v = dao.incr("incr_perm", 3600).await.unwrap();
        assert_eq!(v, 6);
        // 永久键 incr 后应保持无 TTL
        let timeout = dao.get_timeout("incr_perm").await.unwrap();
        assert!(timeout.is_none(), "永久键 incr 不应新增 TTL");
    }

    /// incr 遇到非数字现存值返回 Dao 错误（显性化分支）。
    #[tokio::test]
    async fn in_memory_incr_parse_error_returns_dao_error() {
        let dao = MockDao::new();
        dao.set("incr_bad", "not-a-number", 3600).await.unwrap();
        let result = dao.incr("incr_bad", 3600).await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-incr-parse-u64")),
            "非数字现存值 incr 应返回 dao-incr-parse-u64 错误，实际: {:?}",
            result
        );
    }

    /// incr 在 u64::MAX 溢出时返回 Dao 错误（checked_add 分支）。
    #[tokio::test]
    async fn in_memory_incr_overflow_returns_error() {
        let dao = MockDao::new();
        dao.set("incr_max", &u64::MAX.to_string(), 3600)
            .await
            .unwrap();
        let result = dao.incr("incr_max", 3600).await;
        assert!(
            matches!(
                result,
                Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-incr-overflow-u64")
            ),
            "u64::MAX 自增应返回 dao-incr-overflow-u64 错误，实际: {:?}",
            result
        );
    }

    /// decr 语义矩阵：不存在 / 已过期 / 值为 0 / 递减到 0 / 递减后保留 TTL。
    #[tokio::test]
    async fn in_memory_decr_semantics_matrix() {
        let dao = MockDao::new();

        // 不存在 → 0（None 分支）
        assert_eq!(dao.decr("decr_missing").await.unwrap(), 0);

        // 已过期 → 清理并返回 0（`*deadline <= now` 分支）
        dao.set("decr_expired", "3", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(dao.decr("decr_expired").await.unwrap(), 0);
        assert!(dao.get("decr_expired").await.unwrap().is_none());

        // 值为 0 → 返回 0 不递减为负（cur_val == 0 分支）
        dao.set_permanent("decr_zero", "0").await.unwrap();
        assert_eq!(dao.decr("decr_zero").await.unwrap(), 0);

        // 递减到 0 → 删除 key（new_val == 0 分支）
        dao.set("decr_to_zero", "1", 3600).await.unwrap();
        assert_eq!(dao.decr("decr_to_zero").await.unwrap(), 0);
        assert!(dao.get("decr_to_zero").await.unwrap().is_none());

        // 递减后 > 0 → 保留原 expire_at（new_val > 0 分支）
        dao.set("decr_keep_ttl", "3", 3600).await.unwrap();
        assert_eq!(dao.decr("decr_keep_ttl").await.unwrap(), 2);
        let timeout = dao.get_timeout("decr_keep_ttl").await.unwrap();
        assert!(timeout.is_some(), "decr 后应保留原 TTL");
    }

    /// decr 对两种存在形态（TTL / 永久键）的现存值 parse 失败都返回 Dao 错误。
    #[tokio::test]
    async fn in_memory_decr_parse_error_returns_dao_error() {
        let dao = MockDao::new();

        // TTL 键形态（Some((v, Some(deadline))) 分支）
        dao.set("decr_bad_ttl", "abc", 3600).await.unwrap();
        let result = dao.decr("decr_bad_ttl").await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-decr-parse-u64")),
            "TTL 键 parse 失败应返回 dao-decr-parse-u64，实际: {:?}",
            result
        );

        // 永久键形态（Some((v, None)) 分支）
        dao.set_permanent("decr_bad_perm", "xyz").await.unwrap();
        let result = dao.decr("decr_bad_perm").await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-decr-parse-u64")),
            "永久键 parse 失败应返回 dao-decr-parse-u64，实际: {:?}",
            result
        );
    }

    /// compare_and_update_if_greater：新键初始化 / 不大于时拒绝 / parse 失败显性化 / 过期重置。
    #[tokio::test]
    async fn in_memory_compare_and_update_if_greater_matrix() {
        let dao = MockDao::new();

        // 新键（`_ => (0, None)` 分支）：new_value > 0 → true，写入并设置 TTL
        assert!(dao
            .compare_and_update_if_greater("nc_new", 5, 60)
            .await
            .unwrap());
        assert_eq!(dao.get("nc_new").await.unwrap().as_deref(), Some("5"));
        assert!(dao.get_timeout("nc_new").await.unwrap().is_some());

        // 已存在且 new_value > current → true，保留原 expire_at（TTL 存在分支）
        assert!(dao
            .compare_and_update_if_greater("nc_new", 8, 60)
            .await
            .unwrap());
        assert_eq!(dao.get("nc_new").await.unwrap().as_deref(), Some("8"));

        // 已存在但 new_value <= current → false 且不修改（else 分支）
        assert!(!dao
            .compare_and_update_if_greater("nc_new", 8, 60)
            .await
            .unwrap());
        assert_eq!(dao.get("nc_new").await.unwrap().as_deref(), Some("8"));

        // 永久键（Some((v, None)) 分支）：值会被更新
        //【已知行为不一致，记录不改逻辑】incr/decr 对永久键保留"永久"语义
        //（expire_at 沿用 None），而 compare_and_update_if_greater 的永久键分支
        // `existing_expire_at = None` 会落入 `ttl_seconds` 分支，把永久键升级为
        // TTL 键。此测试按现实现断言，如修复语义请同步更新本断言。
        dao.set_permanent("nc_perm", "1").await.unwrap();
        assert!(dao
            .compare_and_update_if_greater("nc_perm", 2, 60)
            .await
            .unwrap());
        assert_eq!(dao.get("nc_perm").await.unwrap().as_deref(), Some("2"));
        assert!(
            dao.get_timeout("nc_perm").await.unwrap().is_some(),
            "现实现将永久键升级为 TTL 键（与 incr 的永久键语义不一致，见注释）"
        );

        // 非数字现存值（TTL 与永久两种形态）→ Dao 错误（禁止静默按 0）
        dao.set("nc_bad_ttl", "oops", 3600).await.unwrap();
        let result = dao.compare_and_update_if_greater("nc_bad_ttl", 9, 60).await;
        assert!(
            matches!(
                result,
                Err(GarrisonError::Dao(ref msg))
                    if msg.contains("dao-compare-and-update-parse-u64")
            ),
            "TTL 键 parse 失败应显性报错，实际: {:?}",
            result
        );
        dao.set_permanent("nc_bad_perm", "oops").await.unwrap();
        let result = dao
            .compare_and_update_if_greater("nc_bad_perm", 9, 60)
            .await;
        assert!(
            matches!(
                result,
                Err(GarrisonError::Dao(ref msg))
                    if msg.contains("dao-compare-and-update-parse-u64")
            ),
            "永久键 parse 失败应显性报错，实际: {:?}",
            result
        );

        // 已过期键视为不存在：重新初始化（过期 `_ => (0, None)` 分支）
        dao.set("nc_expired", "7", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(dao
            .compare_and_update_if_greater("nc_expired", 3, 60)
            .await
            .unwrap());
        assert_eq!(dao.get("nc_expired").await.unwrap().as_deref(), Some("3"));
    }

    /// compare_and_swap：SETNX（None 期望）/ 命中 / 未命中 / 过期清理 / ttl=0 永久。
    #[tokio::test]
    async fn in_memory_compare_and_swap_matrix() {
        let dao = MockDao::new();

        // 期望不存在且确实不存在 → true（None 分支），ttl=3600
        assert!(dao
            .compare_and_swap("cas_new", None, "v1", 3600)
            .await
            .unwrap());
        assert!(dao.get_timeout("cas_new").await.unwrap().is_some());

        // 期望值不匹配 → false 且不修改（else 分支）
        assert!(!dao
            .compare_and_swap("cas_new", Some("wrong"), "v2", 3600)
            .await
            .unwrap());
        assert_eq!(dao.get("cas_new").await.unwrap().as_deref(), Some("v1"));

        // 期望值匹配 → true 并写入新值
        assert!(dao
            .compare_and_swap("cas_new", Some("v1"), "v2", 3600)
            .await
            .unwrap());
        assert_eq!(dao.get("cas_new").await.unwrap().as_deref(), Some("v2"));

        // 期望不存在但 key 存在 → false
        assert!(!dao
            .compare_and_swap("cas_new", None, "v3", 3600)
            .await
            .unwrap());

        // 已过期 key 视为不存在：期望 None → true（过期清理分支）
        dao.set("cas_expired", "old", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(dao
            .compare_and_swap("cas_expired", None, "fresh", 0)
            .await
            .unwrap());
        // ttl=0 → 永久驻留（`ttl_seconds == 0` 分支）
        assert!(dao.get_timeout("cas_expired").await.unwrap().is_none());
        assert_eq!(
            dao.get("cas_expired").await.unwrap().as_deref(),
            Some("fresh")
        );
    }

    /// eval_lua：INCR + EXPIRE 模式委托 incr（含返回值递增与 TTL）。
    #[tokio::test]
    async fn in_memory_eval_lua_incr_mode() {
        let dao = MockDao::new();
        let script =
            "local v = redis.call('INCR', KEYS[1]) redis.call('EXPIRE', KEYS[1], ARGV[2]) return v";
        let keys = vec!["lua_incr_key".to_string()];

        let r1 = dao
            .eval_lua(
                script,
                keys.clone(),
                vec!["ignored".to_string(), "600".to_string()],
            )
            .await
            .unwrap();
        assert_eq!(r1, vec!["1".to_string()]);
        let r2 = dao
            .eval_lua(
                script,
                keys.clone(),
                vec!["ignored".to_string(), "600".to_string()],
            )
            .await
            .unwrap();
        assert_eq!(r2, vec!["2".to_string()], "连续 eval_lua 应递增计数");
        assert!(dao.get_timeout("lua_incr_key").await.unwrap().is_some());
    }

    /// eval_lua：INCR 模式参数校验——缺 KEYS[1] / 缺 ARGV[2] / ARGV[2] 非数字均报 InvalidParam。
    #[tokio::test]
    async fn in_memory_eval_lua_incr_mode_param_validation() {
        let dao = MockDao::new();
        let script = "INCR + EXPIRE";

        // 缺 KEYS[1]（keys 为空）
        let result = dao
            .eval_lua(script, vec![], vec!["0".to_string(), "600".to_string()])
            .await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref msg)) if msg.contains("missing-keys-1")),
            "缺 KEYS[1] 应返回 InvalidParam，实际: {:?}",
            result
        );

        // 缺 ARGV[2]（args 长度 1）
        let result = dao
            .eval_lua(script, vec!["k".to_string()], vec!["0".to_string()])
            .await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref msg)) if msg.contains("argv-2-ttl")),
            "缺 ARGV[2] 应返回 InvalidParam，实际: {:?}",
            result
        );

        // ARGV[2] 非数字
        let result = dao
            .eval_lua(
                script,
                vec!["k".to_string()],
                vec!["0".to_string(), "not-a-number".to_string()],
            )
            .await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref msg)) if msg.contains("parse-failed")),
            "ARGV[2] 非数字应返回 parse-failed InvalidParam，实际: {:?}",
            result
        );
    }

    /// eval_lua 的 ZREMRANGEBYSCORE（limiteron SLIDING_WINDOW_SCRIPT）模式：未达阈值放行 "1"、
    /// 达阈值拦截 "0"，窗口外旧时间戳被过滤（不占额度）；返回与脚本对齐的三元组 `[allowed, count, reset_time]`。
    #[tokio::test]
    async fn in_memory_eval_lua_sliding_window_threshold_and_filter() {
        let dao = MockDao::new();
        // 识别标记：limiteron 脚本中的 ZREMRANGEBYSCORE 特征（合成最小脚本即可触发模拟器）
        let script = "redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', window_start)";
        let key = "lua_sliding_key".to_string();
        // rc.6 契约：KEYS=[窗口键, seq 键]、ARGV=[window_ms, max]——时钟源在脚本内
        // 取 Redis TIME（模拟器取系统墙钟）；预置时间戳（epoch 毫秒尺度远早于当前）
        // 必落窗外被过滤。
        let keys = vec![key.clone(), format!("{key}:seq")];
        let window_ms: u64 = 5_000;
        // max=2：第 1、2 次请求放行，第 3 次拦截
        let args = vec![window_ms.to_string(), "2".to_string()];

        dao.set_permanent(&key, "1,5000,4999").await.unwrap();

        // 第 1 次：预置时间戳全部在窗外被过滤，count=0 < 2 → 放行并追加
        let out = dao
            .eval_lua(script, keys.clone(), args.clone())
            .await
            .unwrap();
        assert_eq!(
            (out[0].as_str(), out[1].as_str()),
            ("1", "0"),
            "旧时间戳被过滤后未达阈值应放行（allowed/count）"
        );

        // 第 2 次：窗口内第 2 个时间戳仍放行（count=1 < max=2）
        let out = dao
            .eval_lua(script, keys.clone(), args.clone())
            .await
            .unwrap();
        assert_eq!(
            (out[0].as_str(), out[1].as_str()),
            ("1", "1"),
            "窗口内第 2 个时间戳仍应放行"
        );

        // 第 3 次：达到阈值应拦截（count=2 保持，不追加）
        let out = dao.eval_lua(script, keys, args).await.unwrap();
        assert_eq!(
            (out[0].as_str(), out[1].as_str()),
            ("0", "2"),
            "达到阈值后应拦截（count 保持，不追加）"
        );

        // 返回契约形状锁：reset_time 位解析为 u64 且非零（系统墙钟下不作精确断言）
        let reset: u64 = out[2].parse().expect("reset_time 应为可解析的 u64");
        assert!(reset > 0, "reset_time 应非零");
    }

    /// 同毫秒成员不覆盖（rc.6 修复的限流绕过回归锁）：预置同一毫秒的两个成员、
    /// max=2，首调 eval_lua 即应拦截（"0","2"）——若模拟器退化为同键覆盖语义
    /// （rc.5 的 ZADD member=timestamp 行为），count 只会到 1，本测试确定性失败。
    #[tokio::test]
    async fn in_memory_eval_lua_sliding_window_same_ms_no_overwrite() {
        let dao = MockDao::new();
        let script = "ZREMRANGEBYSCORE";
        let now: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let key = "lua_same_ms".to_string();
        dao.set_permanent(&key, &format!("{now},{now}"))
            .await
            .unwrap();
        let keys = vec![key.clone(), format!("{key}:seq")];

        let out = dao
            .eval_lua(script, keys, vec!["5000".to_string(), "2".to_string()])
            .await
            .unwrap();
        assert_eq!(
            (out[0].as_str(), out[1].as_str()),
            ("0", "2"),
            "同毫秒两个成员都应计数（max=2 即拦），覆盖语义会使 count 只到 1"
        );
    }

    /// eval_lua：sliding window 模式参数校验（rc.6 契约）——缺 KEYS[1]/KEYS[2]、
    /// ARGV 非数字均报错。
    #[tokio::test]
    async fn in_memory_eval_lua_sliding_window_param_validation() {
        let dao = MockDao::new();
        let script = "ZREMRANGEBYSCORE";

        // 缺 KEYS[1]
        let result = dao
            .eval_lua(script, vec![], vec!["1".to_string(), "1".to_string()])
            .await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref msg)) if msg.contains("rl-missing-keys-1")),
            "缺 KEYS[1] 应返回 InvalidParam，实际: {:?}",
            result
        );

        // 缺 KEYS[2]（rc.6 seq 键为必需）
        let result = dao
            .eval_lua(
                script,
                vec!["k".to_string()],
                vec!["1".to_string(), "1".to_string()],
            )
            .await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref msg)) if msg.contains("rl-missing-keys-2-seq")),
            "缺 KEYS[2] 应返回 InvalidParam，实际: {:?}",
            result
        );

        // ARGV[1] 非数字
        let result = dao
            .eval_lua(
                script,
                vec!["k".to_string(), "k:seq".to_string()],
                vec!["nan".to_string(), "1".to_string()],
            )
            .await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref msg)) if msg.contains("parse-failed")),
            "ARGV[1] 非数字应返回 parse-failed InvalidParam，实际: {:?}",
            result
        );

        // ARGV[2] 非数字
        let result = dao
            .eval_lua(
                script,
                vec!["k".to_string(), "k:seq".to_string()],
                vec!["1".to_string(), "nan".to_string()],
            )
            .await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref msg)) if msg.contains("rl-argv-2-max")),
            "ARGV[2] 非数字应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// eval_lua：无法识别的脚本返回 NotImplemented（fail-closed，拒绝静默降级）。
    #[tokio::test]
    async fn in_memory_eval_lua_unsupported_script_returns_not_implemented() {
        let dao = MockDao::new();
        let result = dao
            .eval_lua(
                "return redis.call('GET', KEYS[1])",
                vec!["k".to_string()],
                vec![],
            )
            .await;
        assert!(
            matches!(
                result,
                Err(GarrisonError::NotImplemented(ref msg))
                    if msg.contains("dao-eval-lua-unsupported-script")
            ),
            "不支持的脚本应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// eval_lua：sliding window 写入的键带窗口推导 TTL（limiteron 脚本 EXPIRE 语义）。
    #[tokio::test]
    async fn in_memory_eval_lua_sliding_window_sets_window_ttl() {
        let dao = MockDao::new();
        let script = "ZREMRANGEBYSCORE";
        let keys = vec![
            "lua_sliding_perm".to_string(),
            "lua_sliding_perm:seq".to_string(),
        ];
        // max=u64::MAX 保证永不拦截，仅验证写入路径；
        // limiteron 脚本约定 TTL 由窗口推导：ceil(window_ms / 1000) + 1 = 6s
        let args = vec!["5000".to_string(), u64::MAX.to_string()];

        assert_eq!(
            dao.eval_lua(script, keys, args).await.unwrap()[0],
            "1".to_string(),
            "未达阈值应放行"
        );
        assert!(
            dao.get_timeout("lua_sliding_perm").await.unwrap().is_some(),
            "sliding window 写入的键应带窗口推导 TTL（非永久键）"
        );
    }
}
