//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DAO 模块，定义持久化数据访问抽象层。
//!
//! 对应 `SaTokenDao`，
//! 通过 oxcache / dbnexus 提供多后端（缓存 / 关系型数据库）支持。

use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
mod macros;
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub(crate) use macros::dao_session;

/// DAO 抽象层 trait，定义 Token 与会话的持久化操作。
///
/// 对应 `SaTokenDao`，提供 get / set / update / delete / expire 五元操作
/// + set_permanent / get_timeout / keys / rename 四个扩展方法。
///
/// - `set` 必须指定 TTL（Token/Session 不应永久驻留，与 既有语义一致）
/// - `update` 更新值时保留原有 TTL（不重置过期时间）
/// - `expire` 重置键的过期时间
/// - `set_permanent` 存储永久键（无 TTL，默认实现委托 `set(key, value, 0)`）
/// - `get_timeout` 查询剩余 TTL（默认返回 `NotImplemented`，需后端重写）
/// - `keys` 按 glob pattern 扫描 key（默认返回 `NotImplemented`；`MockDao` 已实现；`GarrisonDaoOxcache` 在 `dao-key-index` feature 启用时通过维护 key 索引实现，由 `protocol-apikey` / `anomalous-detector-dual` 传递启用）
/// - `rename` 重命名 key（原子必需方法）
///
/// # 原子性编译期契约（Issues 51-54，acceptance-overhaul T012 收严）
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
/// 此前这些方法提供非原子的组合默认实现（TOCTOU 竞态仅靠文档约束），
/// 现已移除默认实现——遗漏实现将在**编译期**报错，而非运行时静默竞态。
/// 内置实现（`MockDao` / `GarrisonDaoOxcache` / `GarrisonDaoDbnexus` / `AloneCache`）
/// 均以进程内锁或后端原语满足原子性。
#[async_trait]
pub trait GarrisonDao: Send + Sync {
    /// 获取指定键的值。
    ///
    /// # 参数
    /// - `key`: 存储键。
    ///
    /// # 返回
    /// - `Some(value)`: 键存在且未过期。
    /// - `None`: 键不存在或已过期。
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>>;

    /// 设置键值对，附带 TTL。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `value`: 存储值。
    /// - `ttl_seconds`: 过期秒数（0 表示永久驻留；可被 `expire` 重置）。
    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()>;

    /// 更新键的值，保留原有 TTL（不重置过期时间）。
    ///
    /// # 参数
    /// - `key`: 存储键（必须已存在）。
    /// - `value`: 新值。
    ///
    /// # 错误
    /// - 若键不存在，返回 `GarrisonError::Dao`。
    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()>;

    /// 设置（或重置）键的过期时间。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `seconds`: 过期秒数（0 表示永久驻留）。
    ///
    /// # 错误
    /// - 若键不存在，返回 `GarrisonError::Dao`。
    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()>;

    /// 删除指定键。
    ///
    /// # 参数
    /// - `key`: 存储键。
    async fn delete(&self, key: &str) -> GarrisonResult<()>;

    /// 存储永久键（无 TTL）。
    ///
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `value`: 存储值。
    ///
    /// # 默认实现
    /// 委托 `self.set(key, value, 0)`。
    /// 后端可重写以使用原生"无 TTL"API（如 oxcache `set_with_ttl_sync(None)`）。
    async fn set_permanent(&self, key: &str, value: &str) -> GarrisonResult<()> {
        self.set(key, value, 0).await
    }

    /// 仅当 key 不存在时写入（SETNX 语义），返回是否成功写入。
    ///
    /// 用于需要原子"create-if-absent"语义的场景（如社交账号绑定：
    /// 并发回调同一社交用户时，仅第一个请求创建绑定，后续请求读取已存在的值）。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `value`: 存储值。
    /// - `ttl_seconds`: TTL 秒数（0 表示永久驻留）。
    ///
    /// # 返回
    /// - `Ok(true)`: key 不存在，已成功写入。
    /// - `Ok(false)`: key 已存在，未写入。
    ///
    /// # 原子性要求（必需方法）
    ///
    /// 实现必须保证 SETNX 原子性：并发调用同一 key 时**仅一个调用成功写入**。
    /// 禁止 `get` + `set` 两步组合（TOCTOU 竞态：并发下多个调用都可能读到
    /// `None` 并写入）。进程内实现用锁保护，Redis 用 `SET key value NX EX ttl`，
    /// dbnexus 用 `INSERT ... ON CONFLICT DO NOTHING` 检查 affected rows。
    async fn set_if_absent(&self, key: &str, value: &str, ttl_seconds: u64)
        -> GarrisonResult<bool>;

    /// 查询键的剩余 TTL。
    ///
    ///
    /// # 参数
    /// - `key`: 存储键。
    ///
    /// # 返回
    /// - `Ok(Some(remaining))`: 键存在且设置了 TTL，返回剩余存活时间。
    /// - `Ok(None)`: 键不存在，或键存在但未设置 TTL（永久驻留）。
    ///
    /// # 默认实现
    /// 返回 `GarrisonError::NotImplemented`（需后端原生 TTL 查询 API 支持）。
    /// `GarrisonDaoOxcache` 与 `MockDao` 已重写。
    async fn get_timeout(&self, _key: &str) -> GarrisonResult<Option<Duration>> {
        Err(GarrisonError::NotImplemented(format!(
            "get_timeout 未实现：{} 后端不支持 TTL 查询",
            std::any::type_name::<Self>()
        )))
    }

    /// 原子地获取键值与剩余 TTL（性能优化接口）。
    ///
    /// 单次 DAO 调用同时返回 value 与 TTL，避免 `get` + `get_timeout` 两次调用。
    /// 用于 `renew_to_equivalent` 等热路径，减少 DAO 往返次数。
    ///
    /// # 参数
    /// - `key`: 存储键。
    ///
    /// # 返回
    /// - `Ok(Some((value, ttl)))`: 键存在。`ttl` 为 `Some(d)` 表示设置了 TTL，`None` 表示永久驻留。
    /// - `Ok(None)`: 键不存在或已过期。
    ///
    /// # 默认实现
    /// 委托 `self.get(key)` + `self.get_timeout(key)` 两次调用（向后兼容）。
    /// 后端若支持原子获取 value + TTL（如 Redis pipeline / 内存 HashMap 单次 lookup），
    /// 应重写此方法以减少 DAO 往返。
    async fn get_with_ttl(&self, key: &str) -> GarrisonResult<Option<(String, Option<Duration>)>> {
        let value = self.get(key).await?;
        if value.is_none() {
            return Ok(None);
        }
        let ttl = self.get_timeout(key).await?;
        Ok(Some((value.unwrap(), ttl)))
    }

    /// 按 glob pattern 扫描 key。
    ///
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
    /// `GarrisonDaoOxcache` 在 `dao-key-index` feature 关闭时走默认 `NotImplemented`，原因：
    /// - oxcache 0.3.3 的 `CacheReader`/`CacheBackend` trait 未暴露 iter/keys/scan API（2026-07-08 验证）
    /// - `Cache.backend` 字段为 `pub(crate)`，外部无法访问底层 `DashMap`
    /// - `CacheReader` trait 仅有 `get`/`exists`/`ttl`/`len`/`is_empty`/`capacity`/`stats`/`get_many`，无 iter/keys 方法
    ///
    /// **业务方案**：启用 `dao-key-index` feature（`protocol-apikey` / `anomalous-detector-dual` 自动传递），
    /// `GarrisonDaoOxcache` 会维护独立 key 索引（`RwLock<HashSet<String>>`），set/delete 同步索引，
    /// `keys()` 遍历索引并惰性清理过期项。代价是每次 set/delete 需同步索引（内存 + 一致性开销），
    /// 仅在需要 `keys()` 的场景启用。
    ///
    /// **业务影响**：`ApiKeyHandler::list_by_namespace` 需 `dao-key-index`（由 `protocol-apikey` 传递）才可用。
    ///
    /// # 默认实现
    /// 返回 `GarrisonError::NotImplemented`。
    async fn keys(&self, _pattern: &str) -> GarrisonResult<Vec<String>> {
        Err(GarrisonError::NotImplemented(format!(
            "keys 未实现：{} 后端不支持 key scan（待 oxcache 提供原生 iter API）",
            std::any::type_name::<Self>()
        )))
    }

    /// 重命名 key。
    ///
    ///
    /// # 参数
    /// - `old_key`: 原 key（必须已存在）。
    /// - `new_key`: 新 key。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidParam`: `old_key` 不存在。
    ///
    /// # 原子性要求（必需方法）
    ///
    /// 实现必须原子完成「读取旧键 → 写入新键 → 删除旧键」，且**保留原键 TTL**
    /// （禁止 get→set_permanent→delete 三步组合：TTL 丢失且并发下 old_key 与
    /// new_key 可能同时存在）。进程内实现用锁保护，Redis 用原生 `RENAME`。
    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()>;

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
    /// # 原子性要求（必需方法）
    ///
    /// get 与 delete 必须在同一临界区内执行：并发调用同一 key 时**仅一个调用
    /// 返回 `Some`**（SSO ticket 一次性消费等场景依赖此语义）。禁止
    /// `get` → `delete` 两步组合（TOCTOU：并发下多个调用都可能返回 `Some`）。
    /// 进程内实现用锁保护，Redis 用 `GETDEL` 或 Lua 脚本，dbnexus 用
    /// `DELETE ... RETURNING`。
    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>>;

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
    /// # 原子性要求（必需方法）
    ///
    /// 实现必须原子完成「读取 → 递增 → 写回」：并发调用不丢失更新。
    /// key 已存在时**不重置 TTL**（保留原窗口过期时间）；解析失败必须显式
    /// 返回 `GarrisonError::Dao`，禁止静默返回 0 导致计数器重置（Rule 12）。
    /// 进程内实现用锁保护，Redis 用 `INCR` + 首次 `EXPIRE`。
    async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64>;

    /// 原子递减计数器（与 [`incr`](Self::incr) 对称）。
    ///
    /// 将 key 的值递减 1。语义：
    /// - key 不存在或已过期：返回 0（不报错，不创建 key）
    /// - 当前值为 0：返回 0（不递减为负）
    /// - 当前值 > 0：递减 1；递减后值为 0 时删除 key（与 `SmsRateLimiter::decrement_counter` 语义一致）；
    ///   递减后值 > 0 时保留原 TTL（不重置窗口）
    ///
    /// 用于 SMS 限速计数器回滚（`SmsRateLimiter::decrement_counter`）等场景，
    /// 消除 `get → parse → update/delete` 三步组合的 TOCTOU 竞态。
    ///
    /// # 参数
    /// - `key`: 计数器键。
    ///
    /// # 返回
    /// - `Ok(new_value)`: 递减后的新值（key 不存在/已过期/值为 0 时返回 0）。
    ///
    /// # 原子性要求（必需方法）
    ///
    /// 语义与原子性：key 不存在或已过期返回 0（不创建 key）；当前值为 0 返回 0
    /// （不递减为负）；递减后为 0 时删除 key（与 `SmsRateLimiter::decrement_counter`
    /// 语义一致）；递减后 > 0 时保留原 TTL。禁止 `get → parse → update/delete`
    /// 组合（TOCTOU：并发"跨越式递减"，曾致 SMS 限速 flaky test）。
    /// 此方法用于 SMS 限速等安全敏感场景。进程内实现用锁保护，Redis 用
    /// `DECR`（值为 0 时额外 `DEL`）。
    async fn decr(&self, key: &str) -> GarrisonResult<u64>;

    /// 原子地比较并更新（仅当新值大于当前值时）。
    ///
    /// 读取当前值（解析为 u64），若 `new_value > current_value` 则更新为 `new_value` 并返回 true；
    /// 否则不修改，返回 false。键不存在时 current_value 视为 0。
    ///
    /// 用于 HTTP Digest nc 单调性校验（RFC 7616 §3.4.6），消除 get→compare→set TOCTOU 竞态。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `new_value`: 待比较并写入的新值。
    /// - `ttl_seconds`: TTL 秒数（仅 key 首次创建时设置，已存在时不重置 TTL）。
    ///
    /// # 返回
    /// - `Ok(true)`: new_value > current_value，已更新。
    /// - `Ok(false)`: new_value <= current_value，未更新。
    ///
    /// # 默认实现（返回 NotImplemented）
    /// 默认实现返回 `GarrisonError::NotImplemented`（M2 修复，消除 TOCTOU 竞态）：
    /// 原默认实现为 get → parse → compare → set 四步操作，存在 TOCTOU 竞态，
    /// 在并发场景下多个调用可能同时读到旧值并各自执行 set，破坏 nc 单调性。
    /// 此方法用于 HTTP Digest nc 单调性校验等安全敏感场景，必须由后端用原子 CAS 实现。
    ///
    /// # 已重写的实现
    /// - `MockDao`：`parking_lot::Mutex` 保护，进程内原子
    /// - `GarrisonDaoOxcache`：`atomic_state`（`tokio::sync::Mutex<AtomicTracker>`）+ oxcache set_with_ttl 保护，进程内原子
    /// - `AloneCache`：委托内部 dao
    ///
    /// # 生产实现警告
    ///
    /// **生产部署必须重写此方法**，使用后端原子的 CAS / Lua 脚本：
    /// - `GarrisonDaoOxcache`：已重写，用 `atomic_state`（含 `AtomicTracker.counters`）保护（进程内原子）
    /// - `MockDao`：已重写，用 `parking_lot::Mutex` 保护（进程内原子）
    /// - Redis 后端：应重写为 Lua 脚本（GET + COMPARE + SET 原子执行）
    /// - dbnexus 后端：应重写为 SQL `UPDATE ... WHERE ... RETURNING` 语句
    ///
    /// 使用默认实现（如 `MinimalDao`）会返回 `NotImplemented` 错误，
    /// fail-closed 语义：宁可拒绝所有请求也不接受非原子 CAS。
    async fn compare_and_update_if_greater(
        &self,
        _key: &str,
        _new_value: u64,
        _ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        Err(GarrisonError::NotImplemented(format!(
            "compare_and_update_if_greater 未实现：{} 后端不支持原子 CAS（HTTP Digest nc 单调性校验必须重写）",
            std::any::type_name::<Self>()
        )))
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
    /// - `Ok(Some(login_id))`: 绑定关系存在，返回关联的 login_id（String，UUID）。
    /// - `Ok(None)`: 绑定关系不存在（首次登录）。
    ///
    /// # 默认实现
    /// 返回 `GarrisonError::NotImplemented`（GarrisonDao 是 KV 缓存抽象，不支持 SQL SELECT）。
    /// `GarrisonDaoDbnexus` 重写此方法通过 `DbPool` 实现 SQL 查询。
    async fn find_social_binding(
        &self,
        _tenant_id: i64,
        _provider: &str,
        _provider_user_id: &str,
    ) -> GarrisonResult<Option<String>> {
        Err(GarrisonError::NotImplemented(format!(
            "find_social_binding 未实现：{} 后端不支持 SQL 查询",
            std::any::type_name::<Self>()
        )))
    }

    /// 插入社交账号绑定关系。
    ///
    /// 将 `(tenant_id, login_id, provider, provider_user_id, union_id)` 写入 `social_bindings` 表。
    ///
    /// # 参数
    /// - `tenant_id`: 租户 ID（0=默认租户）。
    /// - `login_id`: Garrison 内部用户 ID（String，UUID，由调用方生成）。
    /// - `provider`: 社交平台标识（`"wechat"` / `"alipay"` / `"wechat_mini_app"`）。
    /// - `provider_user_id`: 第三方平台用户唯一 ID。
    /// - `union_id`: 跨应用统一 ID（微信 unionid，可空）。
    /// - `created_at`: 创建时间戳（Unix 秒）。
    ///
    /// # 默认实现
    /// 返回 `GarrisonError::NotImplemented`（GarrisonDao 是 KV 缓存抽象，不支持 SQL INSERT）。
    /// `GarrisonDaoDbnexus` 重写此方法通过 `DbPool` 实现 SQL 插入。
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
            "insert_social_binding 未实现：{} 后端不支持 SQL 插入",
            std::any::type_name::<Self>()
        )))
    }

    /// 查询指定租户的所有角色层级边（child_role → parent_role）。
    ///
    /// 返回 `Vec<(child_role, parent_role)>`，对应 `role_hierarchy` 表中
    /// `tenant_id` 匹配的所有记录。
    ///
    /// # 参数
    /// - `tenant_id`: 租户 ID（0=默认租户）。
    ///
    /// # 默认实现
    /// 返回 `GarrisonError::NotImplemented`（仅 `GarrisonDaoDbnexus` 支持 SQL 查询）。
    /// `RoleHierarchyService` 实际用 `DbPool` 查 SQL，不调用此方法。
    /// 此方法为满足 spec trait 契约，供 `GarrisonDaoDbnexus` 重写。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    async fn query_role_hierarchy_edges(
        &self,
        _tenant_id: i64,
    ) -> GarrisonResult<Vec<(String, String)>> {
        Err(GarrisonError::NotImplemented(format!(
            "query_role_hierarchy_edges 未实现：{} 后端不支持 SQL 查询",
            std::any::type_name::<Self>()
        )))
    }

    /// 插入角色层级边（child_role → parent_role）。
    ///
    /// 幂等：重复插入相同边不报错（后端自适应：SQLite `INSERT OR IGNORE`，
    /// PostgreSQL `ON CONFLICT DO NOTHING`，MySQL `INSERT IGNORE`）。
    ///
    /// # 参数
    /// - `tenant_id`: 租户 ID（0=默认租户）。
    /// - `child_role`: 子角色编码（继承方）。
    /// - `parent_role`: 父角色编码（被继承方）。
    ///
    /// # 默认实现
    /// 返回 `GarrisonError::NotImplemented`（仅 `GarrisonDaoDbnexus` 支持 SQL 插入）。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    async fn insert_role_hierarchy_edge(
        &self,
        _tenant_id: i64,
        _child_role: &str,
        _parent_role: &str,
    ) -> GarrisonResult<()> {
        Err(GarrisonError::NotImplemented(format!(
            "insert_role_hierarchy_edge 未实现：{} 后端不支持 SQL 插入",
            std::any::type_name::<Self>()
        )))
    }

    /// 删除角色层级边（child_role → parent_role）。
    ///
    /// 幂等：删除不存在的边不报错。
    ///
    /// # 参数
    /// - `tenant_id`: 租户 ID（0=默认租户）。
    /// - `child_role`: 子角色编码（继承方）。
    /// - `parent_role`: 父角色编码（被继承方）。
    ///
    /// # 默认实现
    /// 返回 `GarrisonError::NotImplemented`（仅 `GarrisonDaoDbnexus` 支持 SQL 删除）。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    async fn delete_role_hierarchy_edge(
        &self,
        _tenant_id: i64,
        _child_role: &str,
        _parent_role: &str,
    ) -> GarrisonResult<()> {
        Err(GarrisonError::NotImplemented(format!(
            "delete_role_hierarchy_edge 未实现：{} 后端不支持 SQL 删除",
            std::any::type_name::<Self>()
        )))
    }

    /// 执行 Redis Lua 脚本（原子操作）。
    ///
    /// 用于实现原子 check-and-increment 等复合操作，消除多步操作间的竞态窗口。
    /// 典型场景：限速计数器（INCR + EXPIRE 原子化）、一次性 token 消费（GET + DEL 原子化）。
    ///
    /// # 参数
    /// - `script`: Lua 脚本字符串（Redis EVAL 语法）。
    /// - `keys`: KEYS 数组（脚本中通过 `KEYS[1]`、`KEYS[2]`... 访问）。
    /// - `args`: ARGV 数组（脚本中通过 `ARGV[1]`、`ARGV[2]`... 访问）。
    ///
    /// # 返回
    /// - `Ok(Vec<String>)`: 脚本返回值（每个元素对应一个返回值）。
    ///
    /// # 默认实现
    /// 返回 `GarrisonError::NotImplemented`（仅 Redis 后端支持 Lua 脚本）。
    /// `MockDao` 重写为内存模拟（识别 INCR + EXPIRE 模式，委托 `incr` 实现）。
    /// `GarrisonDaoOxcache` 在 `cache-redis` feature 启用时重写，委托 `Cache::eval_lua`。
    ///
    /// # 降级策略
    /// 调用方应在 `eval_lua` 返回 `NotImplemented` 时降级到非原子路径
    /// （如 `incr` + 阈值判断，进程内原子但跨进程非原子）。
    async fn eval_lua(
        &self,
        _script: &str,
        _keys: Vec<String>,
        _args: Vec<String>,
    ) -> GarrisonResult<Vec<String>> {
        Err(GarrisonError::NotImplemented(format!(
            "eval_lua 未实现：{} 后端不支持 Lua 脚本（仅 Redis 后端支持）",
            std::any::type_name::<Self>()
        )))
    }

    /// 原子比较并交换（Compare-And-Swap）。
    ///
    /// 当 key 的当前值等于 `expected` 时，原子替换为 `new_value`。
    /// 用于备份码消费（消除 get→verify→set TOCTOU 双花竞态）等场景。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `expected`: 期望的当前值（`None` 表示期望 key 不存在）。
    /// - `new_value`: 新值。
    /// - `ttl_seconds`: TTL 秒数（0 表示永久驻留）。
    ///
    /// # 返回
    /// - `Ok(true)`: CAS 成功（当前值匹配 expected，已写入 new_value）。
    /// - `Ok(false)`: CAS 失败（当前值不匹配 expected，未写入）。
    ///
    /// # 原子性要求（必需方法）
    ///
    /// 实现必须原子完成「比较 → 交换」：并发下不覆盖中间值（备份码消费等
    /// 场景依赖此语义消除 get→verify→set TOCTOU 双花竞态）。禁止
    /// `get + compare + set` 组合。进程内实现用锁保护，Redis 用 Lua 脚本，
    /// dbnexus 用 `UPDATE ... WHERE value = expected`。
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool>;

    /// 插入 credit 消费流水记录（SQL）。
    ///
    /// 用于 credit 消费历史的异步持久化（`persist_history = true` 时调用）。
    /// 默认实现返回 `NotImplemented`，SQL 后端（sqlite/postgres/mysql）覆盖实现。
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
            "insert_credit_consumption 未实现：{} 后端不支持 SQL 插入",
            std::any::type_name::<Self>()
        )))
    }

    /// 查询 credit 消费流水（SQL）。
    ///
    /// 返回指定时间范围内的消费记录列表。
    /// 默认实现返回 `NotImplemented`，SQL 后端覆盖实现。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    async fn query_credit_consumption(
        &self,
        _tenant_id: i64,
        _from_ts: i64,
        _to_ts: i64,
    ) -> GarrisonResult<Vec<(i64, String, u64, u64, u64, i64, i64)>> {
        Err(GarrisonError::NotImplemented(format!(
            "query_credit_consumption 未实现：{} 后端不支持 SQL 查询",
            std::any::type_name::<Self>()
        )))
    }
}

/// 仅供**测试 mock**：以非原子组合实现 6 个原子必需方法（T012 编译期契约的测试回退）。
///
/// `GarrisonDao` 的 `rename` / `set_if_absent` / `get_and_delete` / `incr` /
/// `decr` / `compare_and_swap` 为必需方法（无默认实现），遗漏实现编译期报错。
/// 全仓约 40 个内联测试 mock 只用到 5 个基础方法，为避免逐个手写 240 个方法，
/// 本宏以 trait 原有的组合语义展开这 6 个方法——**与生产实现的差异**：
/// 组合实现存在 TOCTOU 竞态，仅适用于单线程/串行（`serial_test`）测试环境。
///
/// # 用法
/// 在 `#[async_trait] impl GarrisonDao for XxxMockDao` 块尾部展开一行：
/// - garrison crate 内部：`crate::atomic_test_fallback!();`
/// - 外部集成测试 / bench：`garrison::atomic_test_fallback!();`
///
/// 展开体为 `async_trait` 脱糖后的签名（`Pin<Box<dyn Future>>` + 生命周期
/// 约束），与 trait 声明结构一致——属性宏先于块内 `macro_rules!` 调用展开，
/// 因此本宏**不能**使用普通 `async fn` 形式。
///
/// 生产后端**禁止**使用本宏——必须用进程内锁或后端原语实现真原子
/// （参阅 [`GarrisonDao`] trait 文档「原子性编译期契约」）。
#[macro_export]
#[doc(hidden)]
macro_rules! atomic_test_fallback {
    () => {
        #[allow(clippy::type_complexity)]
        fn set_if_absent<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            key: &'life1 str,
            value: &'life2 str,
            ttl_seconds: u64,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = $crate::error::GarrisonResult<bool>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: ::core::marker::Sync + 'async_trait,
        {
            Box::pin(async move {
                if self.get(key).await?.is_some() {
                    return Ok(false);
                }
                self.set(key, value, ttl_seconds).await?;
                Ok(true)
            })
        }

        #[allow(clippy::type_complexity)]
        fn rename<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            old_key: &'life1 str,
            new_key: &'life2 str,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = $crate::error::GarrisonResult<()>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: ::core::marker::Sync + 'async_trait,
        {
            Box::pin(async move {
                let value = self.get(old_key).await?.ok_or_else(|| {
                    $crate::error::GarrisonError::InvalidParam(format!(
                        "dao-key-missing::{}",
                        old_key
                    ))
                })?;
                self.set_permanent(new_key, &value).await?;
                self.delete(old_key).await
            })
        }

        #[allow(clippy::type_complexity)]
        fn get_and_delete<'life0, 'life1, 'async_trait>(
            &'life0 self,
            key: &'life1 str,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = $crate::error::GarrisonResult<Option<String>>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: ::core::marker::Sync + 'async_trait,
        {
            Box::pin(async move {
                let value = self.get(key).await?;
                if value.is_some() {
                    self.delete(key).await?;
                }
                Ok(value)
            })
        }

        #[allow(clippy::type_complexity)]
        fn incr<'life0, 'life1, 'async_trait>(
            &'life0 self,
            key: &'life1 str,
            ttl_seconds: u64,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = $crate::error::GarrisonResult<u64>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: ::core::marker::Sync + 'async_trait,
        {
            Box::pin(async move {
                match self.get(key).await? {
                    Some(v) => {
                        let cur_val: u64 = v.parse().map_err(|_| {
                            $crate::error::GarrisonError::Dao(format!(
                                "dao-incr-parse-u64::{}::{}",
                                key, v
                            ))
                        })?;
                        let new_val = cur_val + 1;
                        self.update(key, &new_val.to_string()).await?;
                        Ok(new_val)
                    },
                    None => {
                        self.set(key, "1", ttl_seconds).await?;
                        Ok(1)
                    },
                }
            })
        }

        #[allow(clippy::type_complexity)]
        fn decr<'life0, 'life1, 'async_trait>(
            &'life0 self,
            key: &'life1 str,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = $crate::error::GarrisonResult<u64>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: ::core::marker::Sync + 'async_trait,
        {
            Box::pin(async move {
                match self.get(key).await? {
                    Some(v) => {
                        let cur_val: u64 = v.parse().map_err(|_| {
                            $crate::error::GarrisonError::Dao(format!(
                                "dao-decr-parse-u64::{}::{}",
                                key, v
                            ))
                        })?;
                        if cur_val == 0 {
                            return Ok(0);
                        }
                        let new_val = cur_val - 1;
                        if new_val == 0 {
                            self.delete(key).await?;
                        } else {
                            self.update(key, &new_val.to_string()).await?;
                        }
                        Ok(new_val)
                    },
                    None => Ok(0),
                }
            })
        }

        #[allow(clippy::type_complexity)]
        fn compare_and_swap<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            key: &'life1 str,
            expected: Option<&'life2 str>,
            new_value: &'life3 str,
            ttl_seconds: u64,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = $crate::error::GarrisonResult<bool>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: ::core::marker::Sync + 'async_trait,
        {
            Box::pin(async move {
                let current = self.get(key).await?;
                if current.as_deref() == expected {
                    if ttl_seconds == 0 {
                        self.set_permanent(key, new_value).await?;
                    } else {
                        self.set(key, new_value, ttl_seconds).await?;
                    }
                    Ok(true)
                } else {
                    Ok(false)
                }
            })
        }
    };
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

// ============================================================================
// `RedisDeploymentMode` 与 `RedisConfig` 的 trait 实现分离至 `defaults` 子模块
// （规则 25：mod.rs 只放 trait/struct/enum 定义，impl 块拆到独立文件）
// ============================================================================
pub mod defaults;

// ============================================================================
// oxcache 实现（feature = "cache-memory" 或 "cache-redis"）
// ============================================================================

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
mod oxcache_impl;

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
pub use oxcache_impl::GarrisonDaoOxcache;

// ============================================================================
// dbnexus 实现（feature = "db-sqlite" 或 "db-postgres"）
// ============================================================================
//
// `init_dbnexus` 和 `GarrisonMigration` 是 backend-agnostic 的——它们仅封装
// `DbPool::new(url)` 和 `DbPool::run_migrations(dir)`，不关心底层是 SQLite 还是
// PostgreSQL。后端由 dbnexus 的 feature flag（sqlite/postgres）控制。
//
// 注意：`GarrisonMigration::new()` 默认使用 `migrations/sqlite/` 路径，
// PostgreSQL 用户应使用 `with_base_dir` 指定 `migrations/postgres/` 路径。

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
mod dbnexus_impl;

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dbnexus_impl::{init_dbnexus, GarrisonMigration};

/// 统一 KV + SQL 的 `GarrisonDao` 实现（包装 `DbPool` + KV 委托）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
mod dbnexus_dao;

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dbnexus_dao::GarrisonDaoDbnexus;

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

// `InMemoryDao` 在生产代码中也作为进程内原子 DAO 使用
// （如 `PasswordRateLimiter` / `GarrisonFirewallCheckHookDefault` 的内存模式）。
mod in_memory;

pub use in_memory::InMemoryDao;

/// 旧名兼容别名（正名 `InMemoryDao`；依赖 `MockDao` 的下游请迁移，下版本移除）。
#[deprecated(note = "renamed to InMemoryDao")]
pub type MockDao = InMemoryDao;

#[cfg(all(test, feature = "protocol-apikey"))]
pub(crate) use in_memory::glob_match;

#[cfg(test)]
/// DAO trait 契约测试与跨模块共享的 mock 实现（仅 `cfg(test)` 下编译）。
pub mod tests {
    use super::*;
    // 兼容层：重导出 mock 模块的 MockDao 与 glob_match，保持旧路径
    // `crate::dao::tests::MockDao` / `crate::dao::tests::glob_match` 可用
    #[cfg(feature = "protocol-apikey")]
    pub(crate) use super::glob_match;
    // 兼容层：重导出 InMemoryDao（测试内部以 MockDao 名使用，不触发 deprecated）
    pub use super::InMemoryDao as MockDao;
    use crate::error::GarrisonError;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    // ------------------------------------------------------------------------
    // GarrisonDaoOxcache keys() 测试（CRIT-001 修复验证）
    // 仅在 dao-key-index（由 protocol-apikey / anomalous-detector-dual 传递）
    // + cache-memory/cache-redis 启用时编译
    // ------------------------------------------------------------------------
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
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("anomalous:login:1:1", "v1", 3600).await.unwrap();
            let keys = dao.keys("anomalous:login:*").await.unwrap();
            assert_eq!(keys.len(), 1, "set 后应有 1 个 key");
            dao.delete("anomalous:login:1:1").await.unwrap();
            let keys = dao.keys("anomalous:login:*").await.unwrap();
            assert!(keys.is_empty(), "delete 后 keys() 应返回空 Vec");
        }

        /// #7-a 端到端：`ApiKeyHandler::list_by_namespace` 在真实 oxcache DAO 下可用
        /// （验证 dao-key-index gate 泛化后生产可用，而非 NotImplemented）。
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

    // ------------------------------------------------------------------------
    // 契约测试：验证 GarrisonDao trait 行为契约（使用 MockDao）
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
            matches!(result, Err(GarrisonError::Dao(_))),
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
    // 4 方法扩展测试（v0.4.2 spec dao-garrison-dao）
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

    /// R-003: keys("garrison:apikey:*") 返回命名空间下所有 key。
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
            matches!(result, Err(GarrisonError::InvalidParam(_))),
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
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_key1", "value1", 3600).await.unwrap();
            let got = dao.get("oc_key1").await.unwrap();
            assert_eq!(got, Some("value1".to_string()));
        }

        /// Scenario: 过期自动删除。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_auto_delete() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_key2", "value1", 1).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_key2").await.unwrap();
            assert!(got.is_none(), "过期后 get 应返回 None");
        }

        /// Scenario: delete 删除键。
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

        /// T025：键过期瞬间 update 应返回 missing，且绝不应将键写成永久值。
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

        /// T025：永久键 update 仍保留永久语义（不为 regression）。
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

        /// T035：incr 在 u64::MAX 溢出时返回 Dao 错误而非 panic/回绕。
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

        /// 验证 GarrisonDaoOxcache::new() 直接构造（init_oxcache_dao 包装已移除）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_new_direct_construction() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_init", "init_value", 60).await.unwrap();
            let got = dao.get("oc_init").await.unwrap();
            assert_eq!(got, Some("init_value".to_string()));
        }

        /// Scenario: update 更新值（保留 TTL）。
        ///
        /// oxcache 0.3 的 Cache<K,V> 暴露了 ttl() 方法，update 用 ttl() + set_with_ttl 保留原 TTL。
        ///
        /// 参见：dao-oxcache-basic spec Requirement "GarrisonDao 抽象 trait" Scenario "update 更新值（保留 TTL）"
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_update_preserves_ttl() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
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
        /// 覆盖 GarrisonDaoOxcache::expire 的 `seconds == 0` 分支：
        /// 通过 get + set_with_ttl(None) 实现 0=永久语义。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_zero_seconds_makes_permanent() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
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
        /// 覆盖 GarrisonDaoOxcache::expire 的 `seconds == 0` 分支中
        /// `ok_or_else(|| GarrisonError::Dao(...))` 错误路径。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_zero_seconds_missing_key_errors() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let result = dao.expire("oc_missing_perm", 0).await;
            assert!(
                matches!(result, Err(GarrisonError::Dao(_))),
                "expire(0) 不存在的键应返回 Dao 错误"
            );
        }

        /// 验证 expire 对不存在的键返回 Dao 错误（seconds > 0 分支）。
        ///
        /// 覆盖 GarrisonDaoOxcache::expire 的 `else` 分支中
        /// `if !updated { return Err(...) }` 错误路径。
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

        /// 验证 set(ttl=0) 写入永久驻留的键。
        ///
        /// 覆盖 GarrisonDaoOxcache::set 的 `ttl_seconds == 0` 分支（ttl=None）：
        /// 键应永久驻留，不会因短时间等待而过期。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_set_with_zero_ttl() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
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
        /// 覆盖 GarrisonDaoOxcache::set_permanent 重写实现（用 set_with_ttl_sync(None)）。
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

        /// R-002: get_timeout 永久键返回 None。
        ///
        /// 覆盖 GarrisonDaoOxcache::get_timeout 重写实现（用 ttl_sync）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_timeout_returns_none_for_permanent_key() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set_permanent("oc_perm_ttl", "v").await.unwrap();
            let timeout = dao.get_timeout("oc_perm_ttl").await.unwrap();
            assert!(timeout.is_none(), "永久键应返回 None");
        }

        /// R-002: get_timeout TTL 键返回 Some(remaining)，剩余 ≤ 原 TTL。
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

        /// R-002: get_timeout 不存在的键返回 None。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_timeout_returns_none_for_missing_key() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let timeout = dao.get_timeout("oc_missing_ttl").await.unwrap();
            assert!(timeout.is_none(), "不存在的键应返回 None");
        }

        /// R-003: keys 行为取决于 feature gate。
        ///
        /// - 启用 `dao-key-index`（protocol-apikey / anomalous-detector-dual 传递）：keys() 通过 key_index 返回匹配的 key 列表
        /// - 未启用 `dao-key-index`：keys() 返回 NotImplemented（oxcache 不支持原生 key scan）
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

        /// R-004: rename 重命名后 old 不存在，new 存在。
        ///
        /// 覆盖 GarrisonDaoOxcache::rename 重写实现（用 get → ttl_sync → set_with_ttl_sync → delete）。
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

        /// R-004: rename 不存在的 old_key 返回 InvalidParam。
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

        /// R-004: rename 保留原键 TTL（重写实现的核心价值）。
        ///
        /// 验证 GarrisonDaoOxcache::rename 用 ttl_sync + set_with_ttl_sync 保留 TTL，
        /// 而非默认实现的 set_permanent（丢失 TTL）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_rename_preserves_ttl() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
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
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            dao.set("oc_atomic", "value", 3600).await.unwrap();
            let got = dao.get_and_delete("oc_atomic").await.unwrap();
            assert_eq!(got, Some("value".to_string()));
            let after = dao.get("oc_atomic").await.unwrap();
            assert!(after.is_none(), "get_and_delete 后 key 应不存在");
        }

        /// R-001: oxcache get_and_delete 不存在的 key 返回 None。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_get_and_delete_missing_returns_none() {
            let dao = GarrisonDaoOxcache::new().await.unwrap();
            let got = dao.get_and_delete("oc_missing").await.unwrap();
            assert!(got.is_none());
        }

        /// R-001: oxcache get_and_delete 并发原子性验证。
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

        /// R-002: oxcache set_if_absent 并发原子性验证。
        ///
        /// 10 个并发对同一 key（预先不存在）调用 set_if_absent，仅 1 个返回 true。
        /// 验证 Moka `_sync` 后端下 `parking_lot::Mutex` + `get_sync` + `set_with_ttl_sync`
        /// 组合的原子性（写入后立即读可见性）。
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

        /// R-003: Moka `_sync` 单线程写后立即读可见性诊断。
        ///
        /// 循环 200 次 set_with_ttl_sync → get_sync，统计 miss 率。
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

        // --------------------------------------------------------------------
        // 多租户 key 前缀测试
        // --------------------------------------------------------------------

        /// R-tenant-isolation-003: tenant-isolation feature 启用且 TENANT 上下文存在时，
        /// GarrisonDao 的 set/get 实际操作的 key 为 `tenant:{tid}:original_key`。
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

            let dao = GarrisonDaoOxcache::new().await.unwrap();

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
            let dao = GarrisonDaoOxcache::new().await.unwrap();

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

            let dao = GarrisonDaoOxcache::new().await.unwrap();
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
    // decr 并发原子性测试（fix-refresh-race-and-test-contracts / T011-T012）
    // ========================================================================

    /// 验证 MockDao::decr 并发原子性：10 个 task 并发 decr 同一 key（初始值 5），
    /// 恰好 5 次 decr 实际生效（5→4→3→2→1→0）+ 5 次返回 0（key 已删除）。
    ///
    /// 返回值分类：
    /// - 4 个返回非 0（4,3,2,1）：归入 effective
    /// - 1 个返回 0（1→0，new_val==0 删除 key）：归入 zero_count（返回值无法区分"递减到 0"与"key 不存在"）
    /// - 5 个返回 0（key 已删除）：归入 zero_count
    ///
    /// 修复前：`SmsRateLimiter::decrement_counter` 用 `dao.get → parse → dao.update/delete`
    /// 三步组合，跨越 await 间隙允许其他 task 的 `incr` 插入，导致 update 基于过时 get 值
    /// 覆盖 incr 结果，产生"跨越式递减"（实际递减量大于 1）。
    ///
    /// 修复后：MockDao::decr 在单次 `parking_lot::Mutex` lock 作用域内完成 get→parse→update/delete，
    /// 消除 TOCTOU 竞态。10 个并发 task decr 同一 key（初始值 5），恰好 5 次 decr 生效（4 个返回非 0 + 1 个返回 0）+ 5 次返回 0。
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

        // 5 次 decr 生效：4 次返回非 0（4,3,2,1）+ 1 次返回 0（1→0 删除 key）
        assert_eq!(
            effective, 4,
            "4 次 decr 返回非 0（5→4→3→2→1），实际 {} 个",
            effective
        );
        // 6 次返回 0：1 次（1→0）+ 5 次（key 已删除）
        assert_eq!(
            zero_count, 6,
            "6 次 decr 返回 0（1 次 1→0 + 5 次 key 不存在），实际 {} 个",
            zero_count
        );

        // 计数器最终应为 0（已被删除）
        let final_val = dao.get("counter").await.unwrap();
        assert!(
            final_val.is_none(),
            "decr 到 0 后 key 应被删除，实际存在: {:?}",
            final_val
        );
    }

    /// 验证 MockDao::decr 单线程基本语义（覆盖率补充）。
    ///
    /// 语义（与 trait 默认实现 + incr 对称）：
    /// - key 不存在或已过期：返回 0（不创建 key）
    /// - cur_val == 0：返回 0（不递减为负，不删除 key）
    /// - cur_val > 0：递减 1；new_val == 0 时删除 key；new_val > 0 时保留原 TTL
    #[tokio::test]
    async fn mock_decr_basic_semantics() {
        let dao = MockDao::new();

        // key 不存在 → 返回 0（不创建 key）
        assert_eq!(dao.decr("missing").await.unwrap(), 0);
        assert!(
            dao.get("missing").await.unwrap().is_none(),
            "decr 不存在的 key 不应创建 key"
        );

        // 设置初始值 3，递减 3 → 2 → 1 → 0
        dao.set("counter", "3", 3600).await.unwrap();
        assert_eq!(dao.decr("counter").await.unwrap(), 2);
        assert_eq!(dao.decr("counter").await.unwrap(), 1);
        assert_eq!(dao.decr("counter").await.unwrap(), 0);

        // 从 1 decr 到 0 时（new_val == 0）应删除 key（与默认实现一致）
        assert!(
            dao.get("counter").await.unwrap().is_none(),
            "从 1 decr 到 0 应删除 key（new_val == 0 分支）"
        );

        // key 已删除后 decr 返回 0（key 不存在分支）
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

    /// 验证 MockDao::decr 非数字值返回 Dao 错误（Rule 12：禁止静默吞掉 parse 失败）。
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

    // ========================================================================
    // 覆盖率补充：GarrisonDao trait 默认方法测试
    // ========================================================================

    /// 最小化 DAO 实现，只实现 5 个必需方法，不重写任何默认方法。
    ///
    /// 用于验证 trait 默认实现的行为：
    /// - `set_permanent` 默认委托 `set(key, value, 0)`
    /// - `get_timeout` 默认返回 `NotImplemented`
    /// - `keys` 默认返回 `NotImplemented`
    /// - `rename` 默认 `get → set_permanent → delete`
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
        assert!(matches!(result, Err(GarrisonError::NotImplemented(_))));
    }

    /// R-003: `keys` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn default_keys_returns_not_implemented() {
        let dao = MinimalDao::new();
        dao.set("key1", "v1", 0).await.unwrap();
        let result = dao.keys("*").await;
        assert!(matches!(result, Err(GarrisonError::NotImplemented(_))));
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
        assert!(matches!(result, Err(GarrisonError::InvalidParam(_))));
    }

    // ========================================================================
    // 覆盖率补充：社交账号绑定关系默认实现
    // ========================================================================

    /// `find_social_binding` 默认实现返回 `NotImplemented`（GarrisonDao 是 KV 缓存抽象，不支持 SQL）。
    ///
    /// 覆盖 trait 默认实现（行 208-218）。
    #[tokio::test]
    async fn default_find_social_binding_returns_not_implemented() {
        let dao = MinimalDao::new();
        let result = dao.find_social_binding(0, "wechat", "wx_openid").await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("find_social_binding")),
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
            .insert_social_binding(0, "1001", "wechat", "wx_openid", None, 1700000000)
            .await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("insert_social_binding")),
            "insert_social_binding 默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// `compare_and_update_if_greater` 默认实现返回 `NotImplemented`（M2 修复）。
    ///
    /// 默认实现原为 get → parse → compare → set 四步操作，存在 TOCTOU 竞态。
    /// M2 修复：改为返回 `NotImplemented`（fail-closed），强制后端重写以使用原子 CAS。
    /// 此测试验证 MinimalDao（不重写任何默认方法）调用时返回 NotImplemented。
    #[tokio::test]
    async fn default_compare_and_update_if_greater_returns_not_implemented() {
        let dao = MinimalDao::new();
        let result = dao.compare_and_update_if_greater("key", 1, 60).await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("compare_and_update_if_greater")),
            "compare_and_update_if_greater 默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// `decr` 为编译期必需方法（T012 收严，取代 M2 的运行时 NotImplemented 默认）。
    ///
    /// 默认实现原为 get → parse → update/delete 三步组合（TOCTOU"跨越式递减"，
    /// 曾致 `concurrent_send_does_not_exceed_limit` flaky），M2 改为 NotImplemented
    /// 运行时 fail-closed；acceptance-overhaul T012 进一步收严：**移除默认实现**，
    /// 遗漏实现编译期报错（E0046），不再存在运行期"缺省"路径可供测试。
    /// 本测试改验 MinimalDao 组合回退语义正确：5 → 4（保留 key），0 时删除 key。
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
        let dao = GarrisonDaoOxcache::new().await.unwrap();
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
        let dao = GarrisonDaoOxcache::new().await.unwrap();
        assert!(
            dao.redis_config().is_none(),
            "未调用 with_redis_config 时 redis_config 应为 None"
        );
    }

    // ========================================================================
    // 覆盖率补充：GarrisonDao trait 默认方法（incr / eval_lua）
    // ========================================================================

    /// `incr` 默认实现初始化新键为 1。
    ///
    /// 覆盖 trait 默认实现中 `None` 分支（键不存在时 set 初始值 1）。
    #[tokio::test]
    async fn default_incr_initializes_new_key() {
        let dao = MinimalDao::new();
        let result = dao.incr("counter", 3600).await.unwrap();
        assert_eq!(result, 1, "新键应初始化为 1");
        // 验证值已写入
        let val = dao.get("counter").await.unwrap();
        assert_eq!(val.as_deref(), Some("1"));
    }

    /// `incr` 默认实现递增已存在键的值。
    ///
    /// 覆盖 trait 默认实现中 `Some` 分支（键存在时 parse + update）。
    #[tokio::test]
    async fn default_incr_increments_existing_key() {
        let dao = MinimalDao::new();
        dao.set("counter", "5", 3600).await.unwrap();
        let result = dao.incr("counter", 3600).await.unwrap();
        assert_eq!(result, 6, "已存在键 5 应递增为 6");
        // 再次递增
        let result = dao.incr("counter", 3600).await.unwrap();
        assert_eq!(result, 7, "已存在键 6 应递增为 7");
    }

    /// `incr` 默认实现对非数字值回退为 0 后递增。
    ///
    /// 覆盖 Rule 12：非数字值必须显式报错，禁止静默回退为 0 导致计数器重置。
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

    /// `eval_lua` 默认实现返回 `NotImplemented`。
    ///
    /// 覆盖 trait 默认实现（仅 Redis 后端支持 Lua 脚本）。
    #[tokio::test]
    async fn default_eval_lua_returns_not_implemented() {
        let dao = MinimalDao::new();
        let result = dao
            .eval_lua("return 1", vec!["k".to_string()], vec!["a".to_string()])
            .await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("eval_lua")),
            "eval_lua 默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// MinimalDao::default() 等价于 new()。
    ///
    /// 覆盖 MinimalDao 的 Default trait 实现。
    #[tokio::test]
    async fn minimal_dao_default_equals_new() {
        let dao = MinimalDao::default();
        dao.set("k", "v", 60).await.unwrap();
        let got = dao.get("k").await.unwrap();
        assert_eq!(got.as_deref(), Some("v"));
    }

    // ========================================================================
    // compare_and_swap 契约测试（MockDao）
    // ========================================================================

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
}
