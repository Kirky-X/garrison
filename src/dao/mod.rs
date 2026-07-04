//! DAO 模块，定义持久化数据访问抽象层。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaTokenDao`，
//! 通过 oxcache / dbnexus 提供多后端（缓存 / 关系型数据库）支持。

use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use std::time::Duration;

/// DAO 抽象层 trait，定义 Token 与会话的持久化操作。
///
/// [借鉴 Sa-Token] 对应 `SaTokenDao`，提供 get / set / update / delete / expire 五元操作
/// + v0.4.2 新增 set_permanent / get_timeout / keys / rename 四个扩展方法（依据 spec dao-bulwark-dao）。
///
/// - `set` 必须指定 TTL（Token/Session 不应永久驻留，与 Sa-Token 语义一致）
/// - `update` 更新值时保留原有 TTL（不重置过期时间）
/// - `expire` 重置键的过期时间
/// - `set_permanent` 存储永久键（无 TTL，默认实现委托 `set(key, value, 0)`）
/// - `get_timeout` 查询剩余 TTL（默认返回 `NotImplemented`，需后端重写）
/// - `keys` 按 glob pattern 扫描 key（默认返回 `NotImplemented`，需后端重写）
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
    /// v0.4.2 新增（依据 spec dao-bulwark-dao R-001）。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `value`: 存储值。
    ///
    /// # 默认实现
    /// 委托 `self.set(key, value, 0)`（依据 spec 语义：ttl=0 表示永久驻留）。
    /// 后端可重写以使用原生"无 TTL"API（如 oxcache `set_with_ttl_sync(None)`）。
    async fn set_permanent(&self, key: &str, value: &str) -> BulwarkResult<()> {
        self.set(key, value, 0).await
    }

    /// 查询键的剩余 TTL。
    ///
    /// v0.4.2 新增（依据 spec dao-bulwark-dao R-002）。
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
    /// v0.4.2 新增（依据 spec dao-bulwark-dao R-003）。
    ///
    /// # 参数
    /// - `pattern`: glob 模式，支持 `*`（任意字符序列）与 `?`（单字符）。
    ///
    /// # 返回
    /// - `Ok(Vec<String>)`: 匹配的 key 列表（无序），无匹配返回空 Vec。
    ///
    /// # 性能警告
    /// - 大规模 key 场景下性能差（需全量扫描 + 过滤）
    /// - `BulwarkDaoOxcache` 当前返回 `NotImplemented`（oxcache 0.3 不支持 key scan，待 v0.5.0+ 升级）
    ///
    /// # 默认实现
    /// 返回 `BulwarkError::NotImplemented`。
    async fn keys(&self, _pattern: &str) -> BulwarkResult<Vec<String>> {
        Err(BulwarkError::NotImplemented(format!(
            "keys 未实现：{} 后端不支持 key scan",
            std::any::type_name::<Self>()
        )))
    }

    /// 重命名 key。
    ///
    /// v0.4.2 新增（依据 spec dao-bulwark-dao R-004）。
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
}

// ============================================================================
// oxcache 实现（feature = "cache-memory" 或 "cache-redis"）
// ============================================================================

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
mod oxcache_impl {
    use super::BulwarkDao;
    use crate::error::{BulwarkError, BulwarkResult};
    use async_trait::async_trait;
    use oxcache::Cache;
    use std::time::Duration;

    /// oxcache 0.3 默认实现，包装 `oxcache::Cache<String, String>`。
    ///
    /// - L1（moka）+ L2（redis）由 oxcache 0.3 自动管理（0.3 起 moka 后端支持 per-entry TTL）。
    /// - Bulwark 自身不实现任何缓存逻辑，全部委托给 oxcache。
    /// - 启用 `sync_mode(true)` 后使用 `_sync` API（依据 codebase-hardening Task 2），
    ///   要求调用方在 multi_thread tokio runtime 中执行。
    ///
    /// # TTL 保留
    /// - `update` 通过 `cache.ttl_sync()` 读取剩余 TTL，用 `set_with_ttl_sync` 保留原 TTL（不重置过期时间）
    /// - `expire` 通过 `cache.expire_sync()` 原子更新 TTL（不触碰 value）
    /// - 依赖本地 oxcache 仓库（crates.io 0.3.0 未暴露 `Cache<K,V>::ttl_sync()`，本地仓库已暴露）
    pub struct BulwarkDaoOxcache {
        cache: Cache<String, String>,
    }

    impl BulwarkDaoOxcache {
        /// 创建默认的 oxcache DAO 实例。
        ///
        /// 启用 `sync_mode(true)` 以支持 `_sync` API（依据 codebase-hardening Task 2.1）。
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
            Ok(Self { cache })
        }
    }

    #[async_trait]
    impl BulwarkDao for BulwarkDaoOxcache {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            self.cache
                .get_sync(&key.to_string())
                .map_err(|e| BulwarkError::Dao(format!("oxcache get_sync 失败: {}", e)))
        }

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            let ttl = if ttl_seconds == 0 {
                None
            } else {
                Some(Duration::from_secs(ttl_seconds))
            };
            self.cache
                .set_with_ttl_sync(&key.to_string(), &value.to_string(), ttl)
                .map_err(|e| BulwarkError::Dao(format!("oxcache set_with_ttl_sync 失败: {}", e)))
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            // 通过 cache.ttl_sync() 读取剩余 TTL，用 set_with_ttl_sync 保留原 TTL（不重置过期时间）。
            // ttl_sync() 返回 None 表示永久驻留（set_with_ttl_sync 接受 None 表示无 TTL）。
            // 但 None 也可能表示键不存在，需要先检查键存在性。
            if !self
                .cache
                .exists_sync(&key.to_string())
                .map_err(|e| BulwarkError::Dao(format!("oxcache exists_sync 失败: {}", e)))?
            {
                return Err(BulwarkError::Dao(format!("键不存在: {}", key)));
            }
            let remaining_ttl = self
                .cache
                .ttl_sync(&key.to_string())
                .map_err(|e| BulwarkError::Dao(format!("oxcache ttl_sync 失败: {}", e)))?;
            self.cache
                .set_with_ttl_sync(&key.to_string(), &value.to_string(), remaining_ttl)
                .map_err(|e| {
                    BulwarkError::Dao(format!("oxcache update (set_with_ttl_sync) 失败: {}", e))
                })
        }

        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            // oxcache 0.3 的 Cache<K,V> 暴露了 expire_sync(key, ttl) 方法（原子更新 TTL，不触碰 value）。
            // expire_sync 返回 bool：true=更新成功，false=键不存在。
            // 注意：seconds=0 表示永久驻留，需要用 get_sync + set_with_ttl_sync(None) 实现
            // （cache.expire_sync(key, Duration::from_secs(0)) 会让键立即过期，不符合 spec 的 0=永久语义）。
            if seconds == 0 {
                let value = self
                    .cache
                    .get_sync(&key.to_string())
                    .map_err(|e| BulwarkError::Dao(format!("oxcache get_sync 失败: {}", e)))?
                    .ok_or_else(|| BulwarkError::Dao(format!("键不存在: {}", key)))?;
                self.cache
                    .set_with_ttl_sync(&key.to_string(), &value, None)
                    .map_err(|e| {
                        BulwarkError::Dao(format!("oxcache expire (set_with_ttl_sync) 失败: {}", e))
                    })
            } else {
                let updated = self
                    .cache
                    .expire_sync(&key.to_string(), Duration::from_secs(seconds))
                    .map_err(|e| BulwarkError::Dao(format!("oxcache expire_sync 失败: {}", e)))?;
                if !updated {
                    return Err(BulwarkError::Dao(format!("键不存在: {}", key)));
                }
                Ok(())
            }
        }

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.cache
                .delete_sync(&key.to_string())
                .map_err(|e| BulwarkError::Dao(format!("oxcache delete_sync 失败: {}", e)))
        }

        /// v0.4.2: set_permanent 用 set_with_ttl_sync(None) 写入永久键（依据 spec dao-bulwark-dao R-001）。
        ///
        /// 重写默认实现以使用 oxcache 原生"无 TTL"API（避免 ttl=0 歧义）。
        async fn set_permanent(&self, key: &str, value: &str) -> BulwarkResult<()> {
            self.cache
                .set_with_ttl_sync(&key.to_string(), &value.to_string(), None)
                .map_err(|e| BulwarkError::Dao(format!("oxcache set_with_ttl_sync 失败: {}", e)))
        }

        /// v0.4.2: get_timeout 用 ttl_sync 查询剩余 TTL（依据 spec dao-bulwark-dao R-002）。
        ///
        /// oxcache 0.3 的 `ttl_sync(key)` 返回 `Option<Duration>`：
        /// - `Some(remaining)`: 键存在且设置了 TTL
        /// - `None`: 键不存在，或键存在但未设置 TTL（永久驻留）
        async fn get_timeout(&self, key: &str) -> BulwarkResult<Option<Duration>> {
            self.cache
                .ttl_sync(&key.to_string())
                .map_err(|e| BulwarkError::Dao(format!("oxcache ttl_sync 失败: {}", e)))
        }

        /// v0.4.2: rename 用 get → ttl_sync → set_with_ttl_sync → delete 四步（依据 spec dao-bulwark-dao R-004）。
        ///
        /// 重写默认实现以保留原键 TTL（用 `ttl_sync` 读取剩余 TTL，用 `set_with_ttl_sync` 写入）。
        /// 仍是**非原子**操作（oxcache 0.3 无原子 rename API，待 v0.5.0+ 升级）。
        async fn rename(&self, old_key: &str, new_key: &str) -> BulwarkResult<()> {
            let value = self
                .cache
                .get_sync(&old_key.to_string())
                .map_err(|e| BulwarkError::Dao(format!("oxcache get_sync 失败: {}", e)))?
                .ok_or_else(|| BulwarkError::InvalidParam(format!("键不存在: {}", old_key)))?;
            let remaining_ttl = self
                .cache
                .ttl_sync(&old_key.to_string())
                .map_err(|e| BulwarkError::Dao(format!("oxcache ttl_sync 失败: {}", e)))?;
            self.cache
                .set_with_ttl_sync(&new_key.to_string(), &value, remaining_ttl)
                .map_err(|e| BulwarkError::Dao(format!("oxcache set_with_ttl_sync 失败: {}", e)))?;
            self.cache
                .delete_sync(&old_key.to_string())
                .map_err(|e| BulwarkError::Dao(format!("oxcache delete_sync 失败: {}", e)))
        }
    }
}

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
pub use oxcache_impl::BulwarkDaoOxcache;

// ============================================================================
// dbnexus 实现（feature = "db-sqlite")
// ============================================================================

#[cfg(feature = "db-sqlite")]
mod dbnexus_impl;

#[cfg(feature = "db-sqlite")]
pub use dbnexus_impl::{init_dbnexus, BulwarkMigration};

// ============================================================================
// Repository 层（v0.4.2 新增，依据 spec repository-layer）
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
// 测试
// ============================================================================

#[cfg(test)]
/// DAO trait 契约测试与跨模块共享的 mock 实现（仅 `cfg(test)` 下编译）。
pub mod tests {
    use super::*;
    use crate::error::BulwarkError;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    // ------------------------------------------------------------------------
    // Mock 实现：基于 HashMap + Instant 模拟 TTL，严格按 spec 语义
    // ------------------------------------------------------------------------

    /// 测试用 mock DAO，用于验证 trait 契约本身（与具体后端无关）。
    ///
    /// 语义：
    /// - `set(ttl=0)`: 永久驻留（expire_at = None）
    /// - `set(ttl=N)`: N 秒后过期（expire_at = Some(now + N)）
    /// - `update`: 保留原 expire_at，仅更新 value
    /// - `expire`: 重置 expire_at
    ///
    /// `pub` 供跨模块测试（如 `strategy::hooks`）复用，仅在 `cfg(test)` 下编译。
    pub struct MockDao {
        store: Mutex<HashMap<String, (String, Option<Instant>)>>,
    }

    impl Default for MockDao {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockDao {
        /// 创建空的 mock DAO 实例（无任何键值）。
        pub fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BulwarkDao for MockDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            let mut store = self.store.lock();
            match store.get(key) {
                Some((value, expire_at)) => {
                    if let Some(deadline) = expire_at {
                        if Instant::now() >= *deadline {
                            store.remove(key);
                            return Ok(None);
                        }
                    }
                    Ok(Some(value.clone()))
                },
                None => Ok(None),
            }
        }

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            let expire_at = if ttl_seconds == 0 {
                None
            } else {
                Some(Instant::now() + Duration::from_secs(ttl_seconds))
            };
            self.store
                .lock()
                .insert(key.to_string(), (value.to_string(), expire_at));
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((existing, _)) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((_, expire_at)) => {
                    *expire_at = if seconds == 0 {
                        None
                    } else {
                        Some(Instant::now() + Duration::from_secs(seconds))
                    };
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.store.lock().remove(key);
            Ok(())
        }

        /// v0.4.2: set_permanent 设置 expire_at = None（永久驻留）。
        async fn set_permanent(&self, key: &str, value: &str) -> BulwarkResult<()> {
            self.store
                .lock()
                .insert(key.to_string(), (value.to_string(), None));
            Ok(())
        }

        /// v0.4.2: get_timeout 返回剩余 TTL。
        ///
        /// - `Some(remaining)`: 键存在且设置了 TTL（expire_at - now）
        /// - `None`: 键不存在，或永久键（expire_at = None）
        async fn get_timeout(&self, key: &str) -> BulwarkResult<Option<Duration>> {
            let store = self.store.lock();
            match store.get(key) {
                Some((_, Some(deadline))) => {
                    let now = Instant::now();
                    if *deadline <= now {
                        // 已过期（但还未被 get 清理）
                        Ok(None)
                    } else {
                        Ok(Some(*deadline - now))
                    }
                },
                _ => Ok(None),
            }
        }

        /// v0.4.2: keys 按 glob pattern 扫描 key（支持 `*` 与 `?`）。
        ///
        /// 遍历所有 key，过滤已过期的，然后用 glob_match 匹配 pattern。
        async fn keys(&self, pattern: &str) -> BulwarkResult<Vec<String>> {
            let mut result = Vec::new();
            let now = Instant::now();
            let store = self.store.lock();
            for (key, (_, expire_at)) in store.iter() {
                // 跳过已过期的 key
                if let Some(deadline) = expire_at {
                    if *deadline <= now {
                        continue;
                    }
                }
                if glob_match(pattern, key) {
                    result.push(key.clone());
                }
            }
            Ok(result)
        }

        /// v0.4.2: rename 重命名 key，保留原 TTL（非原子）。
        async fn rename(&self, old_key: &str, new_key: &str) -> BulwarkResult<()> {
            let mut store = self.store.lock();
            match store.get(old_key).cloned() {
                Some((value, expire_at)) => {
                    store.insert(new_key.to_string(), (value, expire_at));
                    store.remove(old_key);
                    Ok(())
                },
                None => Err(BulwarkError::InvalidParam(format!("键不存在: {}", old_key))),
            }
        }
    }

    // ------------------------------------------------------------------------
    // glob 匹配 helper（用于 keys 方法，支持 `*` 与 `?`）
    // ------------------------------------------------------------------------

    /// 简单 glob 匹配：`*` 匹配 0+ 字符，`?` 匹配 1 字符。
    ///
    /// 使用经典双指针算法（O(n+m) 时间复杂度）。
    fn glob_match(pattern: &str, text: &str) -> bool {
        let pattern: Vec<char> = pattern.chars().collect();
        let text: Vec<char> = text.chars().collect();
        let mut p = 0; // pattern index
        let mut t = 0; // text index
        let mut star_p: Option<usize> = None; // 上一个 '*' 在 pattern 中的位置
        let mut star_t = 0; // 上一个 '*' 匹配开始时的 text 位置

        while t < text.len() {
            if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
                p += 1;
                t += 1;
            } else if p < pattern.len() && pattern[p] == '*' {
                star_p = Some(p);
                star_t = t;
                p += 1;
            } else if let Some(sp) = star_p {
                // 回溯：让上一个 '*' 多匹配一个字符
                p = sp + 1;
                star_t += 1;
                t = star_t;
            } else {
                return false;
            }
        }

        // 跳过 pattern 末尾的 '*'
        while p < pattern.len() && pattern[p] == '*' {
            p += 1;
        }
        p == pattern.len()
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

    /// R-001: set_permanent 设置后 get 返回值（依据 spec dao-bulwark-dao R-001）。
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

    /// R-002: get_timeout 永久键返回 None（依据 spec dao-bulwark-dao R-002）。
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

    /// R-003: keys("bulwark:apikey:*") 返回命名空间下所有 key（依据 spec dao-bulwark-dao R-003）。
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

    /// R-004: rename 重命名后 old 不存在，new 存在（依据 spec dao-bulwark-dao R-004）。
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

        /// 验证 set(ttl=0) 写入永久驻留的键（依据 codebase-hardening Task 3.7）。
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
        // v0.4.2 4 方法扩展测试（依据 spec dao-bulwark-dao）
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

        /// R-003: keys 在 oxcache 0.3 返回 NotImplemented（oxcache 不支持 key scan）。
        ///
        /// 验证 design D2 偏差：BulwarkDaoOxcache::keys 使用默认实现返回 NotImplemented，
        /// 因为 oxcache 0.3 不支持 key scan API（待 v0.5.0+ oxcache 升级）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_keys_returns_not_implemented() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_key1", "v1", 3600).await.unwrap();
            let result = dao.keys("oc_*").await;
            assert!(
                matches!(result, Err(BulwarkError::NotImplemented(_))),
                "oxcache 0.3 不支持 keys scan，应返回 NotImplemented，实际: {:?}",
                result
            );
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
    }
}
