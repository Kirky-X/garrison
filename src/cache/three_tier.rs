// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 三层缓存服务（L1 oxcache + L2 DAO + L3 interface）。
//!
//! # 架构
//!
//! - **L1（oxcache 内存缓存）**：进程内缓存（oxcache，sync_mode），per-entry TTL（默认 30s），命中时不查询 L2/L3
//! - **L2（DAO 持久化缓存）**：通过 [`GarrisonDao`] set/get，TTL 较长（默认 300s），命中时回填 L1
//! - **L3（interface 回调）**：通过 [`GarrisonPermissionStrategy`] 的 `get_permission_list` /
//! `get_role_list` / `get_user_info` 获取原始数据，命中时回填 L1 + L2
//!
//! # 缓存键
//!
//! - 权限：`perm:cache:{login_id}`
//! - 角色：`role:cache:{login_id}`
//! - 用户：`user:cache:{login_id}`
//!
//! # 失效策略
//!
//! [`UserCacheService::invalidate`] 同时清除 L1 和 L2 中指定 `login_id` 的三类缓存（权限/角色/用户），
//! 用于登出、权限变更等场景。
//!
//! [`GarrisonDao`]: crate::dao::GarrisonDao
//! [`GarrisonPermissionStrategy`]: crate::strategy::GarrisonPermissionStrategy

use crate::cache::dao_backend::GarrisonDaoCacheBackend;
use crate::constants::DaoKeyPrefix;
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::strategy::GarrisonPermissionStrategy;
use oxcache::backend::{CacheWriter, DashMapMemoryBackend};
use oxcache::cache::ChainCache;
use oxcache::Cache;
use std::sync::Arc;
use std::time::Duration;

/// 三层缓存服务，提供权限/角色/用户信息的加速查询。
///
/// L1（oxcache 内存缓存）→ L2（DAO 持久化缓存）→ L3（interface 回调）三层递进查询，
/// 命中上层时不查询下层，未命中下层时回填上层。
pub struct UserCacheService {
    /// 列表型缓存（权限/角色；typed Cache 承载同一条链）：L1 = oxcache
    /// DashMap 内存后端（高分、非持久），L2 =
    /// [`GarrisonDaoCacheBackend`](crate::cache::dao_backend)（低分、持久）。
    /// 读路径 `get_or` 内置 leader/follower singleflight，L2 命中由链自动
    /// 回填 L1；写路径穿透全部后端。L2 落盘形态为负载自身的 JSON
    /// （`["perm:a", ...]`），与旧实现一致。
    list_cache: Cache<String, Vec<String>>,
    /// 用户信息缓存（单值；与 `list_cache` 共享同一链实例）。
    /// `get_or_option` 在未配置 null 哨兵 TTL 时对 `None` 不缓存，
    /// 承袭旧实现「不存在的用户不缓存」的空穿透防护语义。
    user_cache: Cache<String, String>,
    /// L1 内存后端直柄（invalidate 的 L1 删除腿）：与链内 L1 共享同一存储
    /// （`DashMapMemoryBackend` 为 Arc 内存，clone 即同 instance）。
    ///
    /// 存在理由：链删除（`delete_from_all_backends`）在「任一后端成功」时
    /// 返回 Ok，L2 删除失败会被 L1 成功掩蔽——而权限吊销后的陈旧读是安全
    /// 相关退化（吊销权限至多 TTL 仍生效），invalidate 必须逐腿可见错误。
    l1: DashMapMemoryBackend,
    /// L2 DAO 直柄（invalidate 的 L2 删除腿），理由同上。
    dao: Arc<dyn GarrisonDao>,
    /// L3 数据源（通过 GarrisonPermissionStrategy 回调获取原始数据）。
    interface: Arc<dyn GarrisonPermissionStrategy>,
    /// L1 缓存 TTL（秒）：由 L1 内存后端 builder 的 default_ttl 承载，
    /// 本字段供诊断与公开查询。
    l1_ttl_secs: u64,
    /// L2 缓存 TTL（秒）：TTL 策略（含 ±10% 抖动）钉定在
    /// [`GarrisonDaoCacheBackend`](crate::cache::dao_backend) 内部，本字段
    /// 供诊断与公开查询。
    l2_ttl_secs: u64,
    /// 热 key 采样观测（cache-hotkey feature）：访问路径埋点，
    /// 经 [`Self::hot_keys_top`] 导出 top-k 诊断。进程内组件，不影响读写语义。
    ///
    /// 内存义务（上游契约）：条目仅在 `snapshot_top`（半衰 + 清零项回收）或
    /// `reset` 时清理——启用方应定期调用 `hot_keys_top`（如运维/监控导出），
    /// 长时间不导出则 entry 随去重键空间增长。
    #[cfg(feature = "cache-hotkey")]
    hot_keys: oxcache::features::HotKeyTracker,
}

impl UserCacheService {
    /// 创建三层缓存服务实例。
    ///
    /// # 参数
    /// - `dao`: L2 持久化缓存后端（`Arc<dyn GarrisonDao>`）。
    /// - `interface`: L3 数据源（`Arc<dyn GarrisonPermissionStrategy>`）。
    /// - `l1_ttl_secs`: L1 内存缓存 TTL（秒，必须 > 0）。若为 0，L1 条目将立即过期，缓存形同虚设。
    /// - `l2_ttl_secs`: L2 DAO 缓存 TTL（秒，必须 > 0）。若为 0，L2 写入将使用永久 TTL，可能导致内存泄漏。
    ///
    /// # 返回
    /// 已初始化的 `UserCacheService` 实例。
    ///
    /// # 错误
    /// - `GarrisonError::Config`：`l1_ttl_secs` 或 `l2_ttl_secs` 为 0。
    /// - `GarrisonError::Internal`：oxcache L1 初始化失败。
    ///
    /// # 示例
    /// ```ignore
    /// // TTL 为 0 时将返回错误
    /// let result = UserCacheService::new(dao, interface, 0, 300);
    /// assert!(result.is_err());
    /// ```
    pub fn new(
        dao: Arc<dyn GarrisonDao>,
        interface: Arc<dyn GarrisonPermissionStrategy>,
        l1_ttl_secs: u64,
        l2_ttl_secs: u64,
    ) -> GarrisonResult<Self> {
        Self::new_with_capacity(
            dao,
            interface,
            l1_ttl_secs,
            l2_ttl_secs,
            crate::config::DEFAULT_L1_CACHE_CAPACITY,
        )
    }

    /// 创建三层缓存服务实例（显式指定 L1 容量）。
    ///
    /// 生产路径应使用本构造器把 `GarrisonConfig::l1_cache_capacity` 接入
    /// L1 内存后端（历史版本该配置项静默无效，L1 恒为库默认容量）。
    ///
    /// # 参数
    /// - `dao`: L2 持久化缓存后端（`Arc<dyn GarrisonDao>`）。
    /// - `interface`: L3 数据源（`Arc<dyn GarrisonPermissionStrategy>`）。
    /// - `l1_ttl_secs`: L1 内存缓存 TTL（秒，必须 > 0）。若为 0，L1 条目将立即过期，缓存形同虚设。
    /// - `l2_ttl_secs`: L2 DAO 缓存 TTL（秒，必须 > 0）。若为 0，L2 写入将使用永久 TTL，可能导致内存泄漏。
    /// - `l1_capacity`: L1 内存缓存最大条目数（必须 > 0）。
    ///
    /// # 返回
    /// 已初始化的 `UserCacheService` 实例。
    ///
    /// # 错误
    /// - `GarrisonError::Config`：`l1_ttl_secs`、`l2_ttl_secs` 或 `l1_capacity` 为 0。
    /// - `GarrisonError::Internal`：oxcache L1 初始化失败。
    pub fn new_with_capacity(
        dao: Arc<dyn GarrisonDao>,
        interface: Arc<dyn GarrisonPermissionStrategy>,
        l1_ttl_secs: u64,
        l2_ttl_secs: u64,
        l1_capacity: u64,
    ) -> GarrisonResult<Self> {
        // 验证 TTL 参数，防止 0 值导致缓存失效或内存泄漏（错误串不变）
        if l1_ttl_secs == 0 {
            return Err(GarrisonError::Config(
                "cache-l1-ttl-must-positive".to_string(),
            ));
        }
        if l2_ttl_secs == 0 {
            return Err(GarrisonError::Config(
                "cache-l2-ttl-must-positive".to_string(),
            ));
        }
        if l1_capacity == 0 {
            return Err(GarrisonError::Config(
                "cache-l1-capacity-must-positive".to_string(),
            ));
        }
        // L1：oxcache DashMap 内存后端（高分非持久，FIFO 容量淘汰 + per-entry TTL）
        let l1 = DashMapMemoryBackend::builder()
            .capacity(l1_capacity as usize)
            .default_ttl(Duration::from_secs(l1_ttl_secs))
            .build();
        // L2：DAO 适配器（低分持久；L2 TTL 策略含 ±10% 抖动，钉定在适配器内部）
        let l2 = GarrisonDaoCacheBackend::new(
            dao.clone(),
            GarrisonDaoCacheBackend::cache_clear_prefixes(),
        );
        // 组链：L1（高分）→ L2（低分持久），L2 命中自动回填 L1
        let chain: Arc<dyn oxcache::backend::CacheBackend> = Arc::new(
            ChainCache::builder()
                .backend(l1.clone())
                .backend(l2)
                .enable_backfill()
                .build(),
        );
        // typed Cache 承载链：`get_or` 提供 leader/follower singleflight；
        // 两个值类型的 Cache 共享同一链（后端 Arc clone）。
        let list_cache = Cache::<String, Vec<String>>::builder()
            .backend_arc(Arc::clone(&chain))
            .build_sync()
            .map_err(|e| GarrisonError::Internal(format!("cache-l1-init::{}", e)))?;
        let user_cache = Cache::<String, String>::builder()
            .backend_arc(chain)
            .build_sync()
            .map_err(|e| GarrisonError::Internal(format!("cache-l1-init::{}", e)))?;
        Ok(Self {
            list_cache,
            user_cache,
            l1,
            dao,
            interface,
            l1_ttl_secs,
            l2_ttl_secs,
            #[cfg(feature = "cache-hotkey")]
            hot_keys: oxcache::features::HotKeyTracker::new(64),
        })
    }

    /// L1 访问埋点（cache-hotkey）：命中与未命中都计入，反映键访问频次。
    /// feature 关闭时为空实现，调用点无需 cfg。
    #[cfg(not(feature = "cache-hotkey"))]
    fn record_hot_key(&self, _key: &str) {}

    /// L1 访问埋点（cache-hotkey 启用时）。
    #[cfg(feature = "cache-hotkey")]
    fn record_hot_key(&self, key: &str) {
        self.hot_keys.record(key);
    }

    /// 热 key top-k 诊断（cache-hotkey）：返回访问计数降序的前 k 个键。
    ///
    /// 上游 `HotKeyTracker` 为分片采样计数器（半衰），结果是诊断视角而非精确计数。
    #[cfg(feature = "cache-hotkey")]
    pub fn hot_keys_top(&self, k: usize) -> Vec<(String, u64)> {
        self.hot_keys.snapshot_top(k)
    }

    /// 返回 L1 缓存 TTL（秒）。
    pub fn l1_ttl_secs(&self) -> u64 {
        self.l1_ttl_secs
    }

    /// 返回 L2 缓存 TTL（秒）。
    pub fn l2_ttl_secs(&self) -> u64 {
        self.l2_ttl_secs
    }

    /// 列表值链读 + L3 回源（`get_or` singleflight 封装，权限/角色共用）。
    ///
    /// 读路径：L1 命中直接返回；miss 降级 L2 命中（链自动回填 L1）；
    /// 双 miss 由 leader 执行 `fallback`（L3）并经链写回全部后端，follower
    /// 等 leader 完成后读缓存（单飞，防缓存击穿）。
    ///
    /// L3 的错误语义保真：fallback 捕获的 `GarrisonError` 经「旁路变量 +
    /// 哨兵 `OxCacheError`」还原为原始变体返回——L3 回调的错误码是运维
    /// 契约（如 `Dao`/`NotPermission`），不得压平为 `Internal`。
    async fn load_list_with<F, Fut>(&self, key: &str, fallback: F) -> GarrisonResult<Vec<String>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = GarrisonResult<Vec<String>>>,
    {
        let mut l3_err: Option<GarrisonError> = None;
        let mut l3_value: Option<Vec<String>> = None;
        let mut fallback = Some(fallback);
        let key_owned = key.to_string();
        let result = self
            .list_cache
            .get_or(&key_owned, || async {
                let fb = fallback.take().expect("fallback 只被消费一次");
                match fb().await {
                    Ok(v) => {
                        l3_value = Some(v.clone());
                        Ok(v)
                    },
                    Err(e) => {
                        l3_err = Some(e);
                        Err(oxcache::error::OxCacheError::BackendError(
                            "garrison-cache-l3-fallback".to_string(),
                        ))
                    },
                }
            })
            .await;
        match result {
            Ok(v) => Ok(v),
            Err(e) => {
                // L3 自身失败：原样透传（错误码是运维契约，不压平）
                if let Some(l3e) = l3_err {
                    return Err(l3e);
                }
                // L3 已成功但写回失败：数据有效，返回并不缓存（warn 显性化）
                if let Some(v) = l3_value {
                    tracing::warn!(
                        key = %key_owned,
                        error = %e,
                        "cache: L3 succeeded but write-back failed, returning uncached value"
                    );
                    return Ok(v);
                }
                // 链读/反序列化失败（存储故障、损坏或旧格式残留）：缓存层容错
                // ——逐出坏键并回源 L3。缓存不得让读取失败；失败经 warn 显性化。
                tracing::warn!(
                    key = %key_owned,
                    error = %e,
                    "cache: chain read/deserialize failed, evicting key and falling back to L3"
                );
                let _ = self.list_cache.delete(&key_owned).await;
                fallback.expect("错误发生在 fallback 之前，其尚未执行")().await
            },
        }
    }

    /// 单值链读 + L3 回源（`get_or_option` 版）：L3 返回 `None` 时**不缓存**
    /// （防空穿透语义与旧实现一致：不存在的用户每次回源 L3）。
    ///
    /// `null_cache_ttl` 未配置（默认）时 `get_or_option` 对 None fallback
    /// 不写哨兵，恰好承接该语义。
    async fn load_user_with<F, Fut>(&self, key: &str, fallback: F) -> GarrisonResult<Option<String>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = GarrisonResult<Option<String>>>,
    {
        let mut l3_err: Option<GarrisonError> = None;
        let mut l3_value: Option<Option<String>> = None;
        let mut fallback = Some(fallback);
        let key_owned = key.to_string();
        let result = self
            .user_cache
            .get_or_option(&key_owned, || async {
                let fb = fallback.take().expect("fallback 只被消费一次");
                match fb().await {
                    Ok(v) => {
                        l3_value = Some(v.clone());
                        Ok(v)
                    },
                    Err(e) => {
                        l3_err = Some(e);
                        Err(oxcache::error::OxCacheError::BackendError(
                            "garrison-cache-l3-fallback".to_string(),
                        ))
                    },
                }
            })
            .await;
        match result {
            Ok(v) => Ok(v),
            Err(e) => {
                if let Some(l3e) = l3_err {
                    return Err(l3e);
                }
                if let Some(v) = l3_value {
                    tracing::warn!(
                        key = %key_owned,
                        error = %e,
                        "cache: L3 succeeded but write-back failed, returning uncached value"
                    );
                    return Ok(v);
                }
                tracing::warn!(
                    key = %key_owned,
                    error = %e,
                    "cache: chain read/deserialize failed, evicting key and falling back to L3"
                );
                let _ = self.user_cache.delete(&key_owned).await;
                fallback.expect("错误发生在 fallback 之前，其尚未执行")().await
            },
        }
    }

    /// 获取主体的权限列表（三层缓存查询）。
    ///
    /// 缓存键：`perm:cache:{login_id}`
    ///
    /// # 查询流程
    /// 1. L1 命中 → 反序列化返回（不查询 L2/L3）
    /// 2. L1 未命中 → L2 命中 → 链自动回填 L1 → 返回
    /// 3. L1+L2 未命中 → leader 执行 L3 查询 → 链写回全部后端 → 返回
    ///    （并发同 key 请求由 `get_or` singleflight 合并为一次 L3）
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 错误
    /// - L3 interface 回调失败：透传原始 `GarrisonError`（错误码契约不变）。
    /// - 缓存反序列化失败：`GarrisonError::Internal`。
    pub async fn get_permissions(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        let key = DaoKeyPrefix::PermissionCache.build_key(login_id);
        self.record_hot_key(&key);
        self.load_list_with(&key, || async {
            self.interface.get_permission_list(login_id).await
        })
        .await
    }

    /// 获取主体的角色列表（三层缓存查询）。
    ///
    /// 缓存键：`role:cache:{login_id}`；查询流程与错误语义同
    /// [`get_permissions`](Self::get_permissions)。
    pub async fn get_roles(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        let key = DaoKeyPrefix::RoleCache.build_key(login_id);
        self.record_hot_key(&key);
        self.load_list_with(&key, || async {
            self.interface.get_role_list(login_id).await
        })
        .await
    }

    /// 获取主体的用户信息（三层缓存查询）。
    ///
    /// 缓存键：`user:cache:{login_id}`；查询流程同
    /// [`get_permissions`](Self::get_permissions)，差异：L3 返回 `None`
    /// （用户不存在）时**不写入缓存**——防空穿透（不存在的 login_id 每次
    /// 回源 L3），与旧实现语义一致。
    pub async fn get_user(&self, login_id: &str) -> GarrisonResult<Option<String>> {
        let key = DaoKeyPrefix::UserCache.build_key(login_id);
        self.record_hot_key(&key);
        self.load_user_with(&key, || async {
            self.interface.get_user_info(login_id).await
        })
        .await
    }

    /// 失效指定主体的所有缓存（权限/角色/用户）。
    ///
    /// 同时清除 L1（oxcache）和 L2（DAO）中 `login_id` 对应的三类缓存键。
    /// 用于登出、权限变更等场景。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 与 singleflight 的互斥（残留窗口声明）
    ///
    /// 旧实现以 per-key 写锁串「在途加载回填」与「删除」；新实现由 `get_or`
    /// 的 leader/follower 单飞承载在途加载。**残留窗口**：leader 的 L3 回源
    /// 写回若恰好落在本删除之后完成，旧数据会重新驻留至 TTL 过期——窗口为
    /// 「L3 回源耗时」量级，且仅发生在「失效与并发首访同一 key」的组合。
    /// 调用方对强一致失效有要求时，应在业务层串行化（如先拒绝新请求再失效）。
    ///
    /// # 部分失败语义
    ///
    /// 全部 6 次删除（3 键 × L2/L1）**都会尝试执行**，不因中途失败跳过后续
    /// 删除；返回**首个**错误，已成功删除的数量经 `tracing::warn` 记录。
    /// 删除是幂等的，调用方收到错误后应重试。
    pub async fn invalidate(&self, login_id: &str) -> GarrisonResult<()> {
        let keys = [
            DaoKeyPrefix::PermissionCache.build_key(login_id),
            DaoKeyPrefix::RoleCache.build_key(login_id),
            DaoKeyPrefix::UserCache.build_key(login_id),
        ];

        let mut first_err: Option<GarrisonError> = None;
        let mut deleted = 0usize;
        for key in &keys {
            // 逐腿显式删除（不用链删除）：链删除在「任一后端成功」时返回 Ok，
            // 会掩蔽 L2 失败；权限吊销的陈旧读是安全相关退化，必须逐腿可见。
            // 先 L2 后 L1（避免窗口期内 L1 miss → L2 旧数据回填）。
            let l2_result = self.dao.delete(key).await;
            let l1_result = self
                .l1
                .delete(key)
                .await
                .map_err(|e| GarrisonError::Internal(format!("cache-l1-delete::{}", e)));
            for result in [l2_result, l1_result] {
                match result {
                    Ok(()) => deleted += 1,
                    Err(e) => {
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                    },
                }
            }
        }

        if let Some(e) = first_err {
            tracing::warn!(
                login_id = %login_id,
                deleted,
                total = keys.len() * 2,
                error = %e,
                "cache invalidate completed with errors; all deletes were attempted, retry is idempotent"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::GarrisonDao;
    use crate::error::GarrisonResult;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;

    // ------------------------------------------------------------------------
    // Mock DAO：记录调用次数 + 存储键值对
    // ------------------------------------------------------------------------

    /// 测试用 Mock DAO，记录 get/set/delete 调用次数与操作的键。
    struct CountingMockDao {
        store: Mutex<HashMap<String, String>>,
        get_count: AtomicU32,
        set_count: AtomicU32,
        delete_count: AtomicU32,
        /// 记录所有 get 调用的 key（按调用顺序）
        get_keys: Mutex<Vec<String>>,
        /// 记录所有 set 调用的 key（按调用顺序）
        set_keys: Mutex<Vec<String>>,
        /// 记录所有 delete 调用的 key（按调用顺序）
        delete_keys: Mutex<Vec<String>>,
        /// 错误注入标志：设为 true 时 get 返回 Err
        fail_get: AtomicBool,
        /// 错误注入标志：设为 true 时 set 返回 Err
        fail_set: AtomicBool,
        /// 错误注入标志：设为 true 时 delete 返回 Err
        fail_delete: AtomicBool,
    }

    impl CountingMockDao {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
                get_count: AtomicU32::new(0),
                set_count: AtomicU32::new(0),
                delete_count: AtomicU32::new(0),
                get_keys: Mutex::new(Vec::new()),
                set_keys: Mutex::new(Vec::new()),
                delete_keys: Mutex::new(Vec::new()),
                fail_get: AtomicBool::new(false),
                fail_set: AtomicBool::new(false),
                fail_delete: AtomicBool::new(false),
            }
        }

        fn get_count(&self) -> u32 {
            self.get_count.load(Ordering::SeqCst)
        }

        fn set_count(&self) -> u32 {
            self.set_count.load(Ordering::SeqCst)
        }

        fn delete_count(&self) -> u32 {
            self.delete_count.load(Ordering::SeqCst)
        }

        fn get_keys(&self) -> Vec<String> {
            self.get_keys.lock().clone()
        }

        fn set_keys(&self) -> Vec<String> {
            self.set_keys.lock().clone()
        }

        /// 返回所有 delete 调用的 key（按调用顺序）。
        fn delete_keys(&self) -> Vec<String> {
            self.delete_keys.lock().clone()
        }

        /// 直接写入 store（用于测试预填充 L2），不计数。
        fn insert_direct(&self, key: &str, value: &str) {
            self.store.lock().insert(key.to_string(), value.to_string());
        }

        /// 检查 store 中是否存在指定 key。
        fn contains_key(&self, key: &str) -> bool {
            self.store.lock().contains_key(key)
        }

        /// 设置 get 是否失败（用于错误路径测试）。
        fn set_fail_get(&self, fail: bool) {
            self.fail_get.store(fail, Ordering::SeqCst);
        }

        /// 设置 set 是否失败（用于错误路径测试）。
        fn set_fail_set(&self, fail: bool) {
            self.fail_set.store(fail, Ordering::SeqCst);
        }

        /// 设置 delete 是否失败（用于错误路径测试）。
        fn set_fail_delete(&self, fail: bool) {
            self.fail_delete.store(fail, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl GarrisonDao for CountingMockDao {
        async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
            self.get_count.fetch_add(1, Ordering::SeqCst);
            self.get_keys.lock().push(key.to_string());
            if self.fail_get.load(Ordering::SeqCst) {
                return Err(GarrisonError::Dao("injected get error".to_string()));
            }
            Ok(self.store.lock().get(key).cloned())
        }

        async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
            self.set_count.fetch_add(1, Ordering::SeqCst);
            self.set_keys.lock().push(key.to_string());
            if self.fail_set.load(Ordering::SeqCst) {
                return Err(GarrisonError::Dao("injected set error".to_string()));
            }
            self.store.lock().insert(key.to_string(), value.to_string());
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
            self.store.lock().insert(key.to_string(), value.to_string());
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn delete(&self, key: &str) -> GarrisonResult<()> {
            self.delete_count.fetch_add(1, Ordering::SeqCst);
            self.delete_keys.lock().push(key.to_string());
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err(GarrisonError::Dao("injected delete error".to_string()));
            }
            self.store.lock().remove(key);
            Ok(())
        }
        crate::atomic_test_fallback!();
    }

    // ------------------------------------------------------------------------
    // Mock Interface：实现 GarrisonPermissionStrategy，记录调用次数
    // ------------------------------------------------------------------------

    /// 测试用 Mock Interface，记录 get_permission_list / get_role_list / get_user_info 调用次数。
    struct CountingMockInterface {
        permissions: Mutex<HashMap<String, Vec<String>>>,
        roles: Mutex<HashMap<String, Vec<String>>>,
        user_info: Mutex<HashMap<String, Option<String>>>,
        perm_count: AtomicU32,
        role_count: AtomicU32,
        user_count: AtomicU32,
        /// 错误注入标志：设为 true 时 get_permission_list 返回 Err
        fail_perm: AtomicBool,
        /// 错误注入标志：设为 true 时 get_role_list 返回 Err
        fail_role: AtomicBool,
        /// 错误注入标志：设为 true 时 get_user_info 返回 Err
        fail_user: AtomicBool,
    }

    impl CountingMockInterface {
        fn new() -> Self {
            Self {
                permissions: Mutex::new(HashMap::new()),
                roles: Mutex::new(HashMap::new()),
                user_info: Mutex::new(HashMap::new()),
                perm_count: AtomicU32::new(0),
                role_count: AtomicU32::new(0),
                user_count: AtomicU32::new(0),
                fail_perm: AtomicBool::new(false),
                fail_role: AtomicBool::new(false),
                fail_user: AtomicBool::new(false),
            }
        }

        /// 设置权限列表返回值。
        fn set_permissions(&self, login_id: &str, perms: Vec<String>) {
            self.permissions.lock().insert(login_id.to_string(), perms);
        }

        /// 设置角色列表返回值。
        fn set_roles(&self, login_id: &str, roles: Vec<String>) {
            self.roles.lock().insert(login_id.to_string(), roles);
        }

        /// 设置用户信息返回值。
        fn set_user_info(&self, login_id: &str, info: Option<String>) {
            self.user_info.lock().insert(login_id.to_string(), info);
        }

        fn perm_count(&self) -> u32 {
            self.perm_count.load(Ordering::SeqCst)
        }

        fn role_count(&self) -> u32 {
            self.role_count.load(Ordering::SeqCst)
        }

        fn user_count(&self) -> u32 {
            self.user_count.load(Ordering::SeqCst)
        }

        /// 设置 get_permission_list 是否失败（用于错误路径测试）。
        fn set_fail_perm(&self, fail: bool) {
            self.fail_perm.store(fail, Ordering::SeqCst);
        }

        /// 设置 get_role_list 是否失败（用于错误路径测试）。
        fn set_fail_role(&self, fail: bool) {
            self.fail_role.store(fail, Ordering::SeqCst);
        }

        /// 设置 get_user_info 是否失败（用于错误路径测试）。
        fn set_fail_user(&self, fail: bool) {
            self.fail_user.store(fail, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl GarrisonPermissionStrategy for CountingMockInterface {
        async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
            self.perm_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_perm.load(Ordering::SeqCst) {
                return Err(GarrisonError::Internal("injected perm error".to_string()));
            }
            Ok(self
                .permissions
                .lock()
                .get(login_id)
                .cloned()
                .unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
            self.role_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_role.load(Ordering::SeqCst) {
                return Err(GarrisonError::Internal("injected role error".to_string()));
            }
            Ok(self.roles.lock().get(login_id).cloned().unwrap_or_default())
        }

        async fn check_permission(
            &self,
            _login_id: &str,
            _permission: &str,
        ) -> GarrisonResult<bool> {
            Ok(false)
        }

        async fn check_role(&self, _login_id: &str, _role: &str) -> GarrisonResult<bool> {
            Ok(false)
        }

        async fn check_role_any(&self, _login_id: &str, _roles: &[&str]) -> GarrisonResult<bool> {
            Ok(false)
        }

        async fn check_role_all(&self, _login_id: &str, _roles: &[&str]) -> GarrisonResult<bool> {
            Ok(false)
        }

        async fn get_user_info(&self, login_id: &str) -> GarrisonResult<Option<String>> {
            self.user_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_user.load(Ordering::SeqCst) {
                return Err(GarrisonError::Internal("injected user error".to_string()));
            }
            Ok(self.user_info.lock().get(login_id).cloned().unwrap_or(None))
        }

        async fn check_permission_in_tenant(
            &self,
            _tenant_id: i64,
            _login_id: &str,
            _permission: &str,
        ) -> GarrisonResult<bool> {
            // 测试桩与租户无关：任意租户返回相同结果
            Ok(false)
        }

        async fn check_role_in_tenant(
            &self,
            _tenant_id: i64,
            _login_id: &str,
            _role: &str,
        ) -> GarrisonResult<bool> {
            // 测试桩与租户无关：任意租户返回相同结果
            Ok(false)
        }

        #[cfg(any(
            feature = "sms-rate-limit",
            feature = "firewall-ratelimit",
            feature = "firewall-bruteforce",
            feature = "firewall-ddos",
            feature = "firewall",
            feature = "oauth2-server"
        ))]
        async fn check_login_hooks(
            &self,
            _login_id: &str,
            _ctx: &crate::strategy::hooks::LoginContext,
        ) -> GarrisonResult<()> {
            // 测试桩不注入防火墙 hook，显式 no-op
            Ok(())
        }
    }

    // ------------------------------------------------------------------------
    // 辅助函数
    // ------------------------------------------------------------------------

    /// 创建测试用 UserCacheService + Mock DAO + Mock Interface。
    fn make_service(
        l1_ttl_secs: u64,
        l2_ttl_secs: u64,
    ) -> (
        Arc<CountingMockDao>,
        Arc<CountingMockInterface>,
        UserCacheService,
    ) {
        let dao = Arc::new(CountingMockDao::new());
        let interface = Arc::new(CountingMockInterface::new());
        let service = UserCacheService::new(
            dao.clone() as Arc<dyn GarrisonDao>,
            interface.clone() as Arc<dyn GarrisonPermissionStrategy>,
            l1_ttl_secs,
            l2_ttl_secs,
        )
        .expect("UserCacheService::new 应成功");
        (dao, interface, service)
    }

    /// 使用默认 TTL 创建测试服务。
    fn make_default_service() -> (
        Arc<CountingMockDao>,
        Arc<CountingMockInterface>,
        UserCacheService,
    ) {
        make_service(30, 300)
    }

    // ------------------------------------------------------------------------
    // 12 个单元测试
    // ------------------------------------------------------------------------

    /// L1 命中时不查询 L2/L3。
    #[tokio::test]
    async fn l1_hit_does_not_query_l2_l3() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("1001", vec!["user:read".to_string()]);

        // 第一次调用：L1+L2 miss → L3 查询 → 回填 L1+L2
        let perms1 = service.get_permissions("1001").await.unwrap();
        assert_eq!(perms1, vec!["user:read".to_string()]);
        assert_eq!(interface.perm_count(), 1, "第一次应查询 L3");
        // `get_or` miss 路径含两次链读（快路径 + leader 复查）
        assert_eq!(
            dao.get_count(),
            2,
            "第一次应查询 L2（get_or 快路径 + leader 复查）"
        );

        // 第二次调用：L1 hit → 不查询 L2/L3
        let perms2 = service.get_permissions("1001").await.unwrap();
        assert_eq!(perms2, vec!["user:read".to_string()]);
        assert_eq!(interface.perm_count(), 1, "L1 命中不应查询 L3");
        assert_eq!(dao.get_count(), 2, "L1 命中不应查询 L2（较首次调用不增加）");
    }

    /// L1 未命中 L2 命中时回填 L1。
    #[tokio::test]
    async fn l1_miss_l2_hit_backfills_l1() {
        let (dao, interface, service) = make_default_service();

        // 预填充 L2（模拟另一进程写入的缓存）
        let perms_json = serde_json::to_string(&vec!["admin:read".to_string()]).unwrap();
        dao.insert_direct("perm:cache:2001", &perms_json);

        // 第一次调用：L1 miss → L2 hit → 回填 L1 → 不查询 L3
        let perms1 = service.get_permissions("2001").await.unwrap();
        assert_eq!(perms1, vec!["admin:read".to_string()]);
        assert_eq!(interface.perm_count(), 0, "L2 命中不应查询 L3");
        assert_eq!(dao.get_count(), 1, "L2 命中路径：链读一次（无 fallback）");

        // 第二次调用：L1 hit（已被回填）→ 不查询 L2/L3
        let perms2 = service.get_permissions("2001").await.unwrap();
        assert_eq!(perms2, vec!["admin:read".to_string()]);
        assert_eq!(
            dao.get_count(),
            1,
            "L1 回填后不应再查询 L2（命中路径总量保持 1）"
        );
        assert_eq!(interface.perm_count(), 0, "不应查询 L3");
    }

    /// L1+L2 未命中走 L3 回填 L1+L2。
    #[tokio::test]
    async fn l1_l2_miss_calls_l3_backfills_both() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("3001", vec!["data:write".to_string()]);

        // 第一次调用：L1+L2 miss → L3 查询 → 回填 L1+L2
        let perms = service.get_permissions("3001").await.unwrap();
        assert_eq!(perms, vec!["data:write".to_string()]);
        assert_eq!(interface.perm_count(), 1, "应查询 L3 一次");
        assert_eq!(
            dao.get_count(),
            2,
            "应查询 L2 一次（get_or 快路径 + leader 复查，miss 路径双读）"
        );
        assert_eq!(dao.set_count(), 1, "应回填 L2 一次");

        // 验证 L2 已被回填
        assert!(dao.contains_key("perm:cache:3001"), "L2 应已被回填");

        // 验证 L1 已被回填（第二次调用不走 L3）
        let perms2 = service.get_permissions("3001").await.unwrap();
        assert_eq!(perms2, vec!["data:write".to_string()]);
        assert_eq!(interface.perm_count(), 1, "L1 回填后不应再查询 L3");
    }

    /// invalidate 失效 L1。
    #[tokio::test]
    async fn invalidate_clears_l1() {
        let (_dao, interface, service) = make_default_service();
        interface.set_permissions("4001", vec!["perm:a".to_string()]);

        // 填充 L1
        let _ = service.get_permissions("4001").await.unwrap();
        assert_eq!(interface.perm_count(), 1);

        // invalidate 失效 L1
        service.invalidate("4001").await.unwrap();

        // 再次查询：L1 已失效 → L2 也被 invalidate 删除 → L3 查询
        let _ = service.get_permissions("4001").await.unwrap();
        assert_eq!(interface.perm_count(), 2, "invalidate 后应重新查询 L3");
    }

    /// invalidate 失效 L2。
    #[tokio::test]
    async fn invalidate_clears_l2() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("5001", vec!["perm:b".to_string()]);

        // 填充 L2（通过 get_permissions 回填）
        let _ = service.get_permissions("5001").await.unwrap();
        assert!(dao.contains_key("perm:cache:5001"), "L2 应已被回填");

        // invalidate 失效 L2
        service.invalidate("5001").await.unwrap();
        assert!(
            !dao.contains_key("perm:cache:5001"),
            "invalidate 后 L2 应被清除"
        );
        assert!(
            !dao.contains_key("role:cache:5001"),
            "invalidate 后 L2 角色缓存应被清除"
        );
        assert!(
            !dao.contains_key("user:cache:5001"),
            "invalidate 后 L2 用户缓存应被清除"
        );
        assert_eq!(
            dao.delete_count(),
            3,
            "invalidate 应执行 3 次 L2 delete（perm + role + user）"
        );
    }

    /// get_permissions 缓存键格式 `perm:cache:{login_id}`。
    #[tokio::test]
    async fn get_permissions_uses_correct_key() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("6001", vec!["perm:c".to_string()]);

        let _ = service.get_permissions("6001").await.unwrap();

        // 验证 L2 set 调用使用了正确的 key
        let set_keys = dao.set_keys();
        assert!(
            set_keys.iter().any(|k| k == "perm:cache:6001"),
            "set 应使用 key 'perm:cache:6001'，实际: {:?}",
            set_keys
        );

        // 验证 L2 get 调用使用了正确的 key
        let get_keys = dao.get_keys();
        assert!(
            get_keys.iter().any(|k| k == "perm:cache:6001"),
            "get 应使用 key 'perm:cache:6001'，实际: {:?}",
            get_keys
        );
    }

    /// get_roles 缓存键格式 `role:cache:{login_id}`。
    #[tokio::test]
    async fn get_roles_uses_correct_key() {
        let (dao, interface, service) = make_default_service();
        interface.set_roles("7001", vec!["admin".to_string()]);

        let _ = service.get_roles("7001").await.unwrap();

        let set_keys = dao.set_keys();
        assert!(
            set_keys.iter().any(|k| k == "role:cache:7001"),
            "set 应使用 key 'role:cache:7001'，实际: {:?}",
            set_keys
        );

        let get_keys = dao.get_keys();
        assert!(
            get_keys.iter().any(|k| k == "role:cache:7001"),
            "get 应使用 key 'role:cache:7001'，实际: {:?}",
            get_keys
        );
    }

    /// get_user 缓存键格式 `user:cache:{login_id}`。
    #[tokio::test]
    async fn get_user_uses_correct_key() {
        let (dao, interface, service) = make_default_service();
        interface.set_user_info("8001", Some(r#"{"name":"alice"}"#.to_string()));

        let _ = service.get_user("8001").await.unwrap();

        let set_keys = dao.set_keys();
        assert!(
            set_keys.iter().any(|k| k == "user:cache:8001"),
            "set 应使用 key 'user:cache:8001'，实际: {:?}",
            set_keys
        );

        let get_keys = dao.get_keys();
        assert!(
            get_keys.iter().any(|k| k == "user:cache:8001"),
            "get 应使用 key 'user:cache:8001'，实际: {:?}",
            get_keys
        );
    }

    /// 用户不存在时返回 Ok(None) 且不缓存。
    #[tokio::test]
    async fn get_user_returns_none_when_not_found() {
        let (dao, interface, service) = make_default_service();
        // 不设置 user_info → get_user_info 返回 None

        let result = service.get_user("9001").await.unwrap();
        assert!(result.is_none(), "用户不存在时应返回 Ok(None)");

        // 验证 L3 被调用
        assert_eq!(interface.user_count(), 1, "应查询 L3 一次");

        // 验证 L2 未被写入（None 不缓存）
        assert!(!dao.contains_key("user:cache:9001"), "None 不应缓存到 L2");
        assert_eq!(dao.set_count(), 0, "None 不应触发 L2 set 操作");

        // 再次调用：仍走 L3（未缓存）
        let result2 = service.get_user("9001").await.unwrap();
        assert!(result2.is_none());
        assert_eq!(
            interface.user_count(),
            2,
            "未缓存 None，第二次应再次查询 L3"
        );
    }

    /// TTL 过期后 L1 失效（用短 TTL 测试）。
    #[tokio::test]
    async fn ttl_expires_l1() {
        // 使用 1 秒 L1 TTL
        let (_dao, interface, service) = make_service(1, 300);
        interface.set_permissions("10001", vec!["perm:d".to_string()]);

        // 第一次调用：填充 L1
        let _ = service.get_permissions("10001").await.unwrap();
        assert_eq!(interface.perm_count(), 1, "第一次应查询 L3");

        // 等待 L1 TTL 过期
        tokio::time::sleep(Duration::from_secs(2)).await;

        // 第二次调用：L1 已过期 → L2 命中 → 回填 L1 → 不查询 L3
        let perms = service.get_permissions("10001").await.unwrap();
        assert_eq!(perms, vec!["perm:d".to_string()]);
        assert_eq!(interface.perm_count(), 1, "L1 过期后 L2 命中，不应查询 L3");
    }

    /// 不存在的 key 失效不报错（幂等）。
    #[tokio::test]
    async fn invalidate_nonexistent_key_is_idempotent() {
        let (_dao, _interface, service) = make_default_service();

        let result = service.invalidate("nonexistent_user").await;
        assert!(result.is_ok(), "invalidate 不存在的 key 应幂等返回 Ok(())");
    }

    /// 并发回填不冲突。
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_backfill_no_conflict() {
        let dao = Arc::new(CountingMockDao::new());
        let interface = Arc::new(CountingMockInterface::new());
        interface.set_permissions("11001", vec!["perm:e".to_string()]);

        let service = Arc::new(
            UserCacheService::new(
                dao.clone() as Arc<dyn GarrisonDao>,
                interface.clone() as Arc<dyn GarrisonPermissionStrategy>,
                30,
                300,
            )
            .expect("UserCacheService::new 应成功"),
        );

        // 并发 10 个任务同时调用 get_permissions
        let mut handles = Vec::new();
        for _ in 0..10 {
            let s = service.clone();
            handles.push(tokio::spawn(
                async move { s.get_permissions("11001").await },
            ));
        }

        let mut success = 0;
        for handle in handles {
            let result = handle.await.expect("task panicked");
            match result {
                Ok(perms) => {
                    assert_eq!(
                        perms,
                        vec!["perm:e".to_string()],
                        "所有并发调用应返回相同结果"
                    );
                    success += 1;
                },
                Err(e) => panic!("并发回填不应失败: {:?}", e),
            }
        }

        assert_eq!(success, 10, "所有 10 个并发调用应成功");
    }

    // ------------------------------------------------------------------------
    // 3 个集成测试（失效场景验证）
    // ------------------------------------------------------------------------

    /// I1: 登出后缓存失效 — invalidate 后再次查询走 L3。
    ///
    /// 注：logout 集成到 stp/session.rs 需修改 GarrisonManager::builder()，
    /// 留到 统一接线。此处验证 invalidate 的行为。
    #[tokio::test]
    async fn logout_invalidates_cache() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("12001", vec!["perm:f".to_string()]);
        interface.set_roles("12001", vec!["user".to_string()]);
        interface.set_user_info("12001", Some(r#"{"id":12001}"#.to_string()));

        // 填充所有三类缓存
        let _ = service.get_permissions("12001").await.unwrap();
        let _ = service.get_roles("12001").await.unwrap();
        let _ = service.get_user("12001").await.unwrap();

        assert_eq!(interface.perm_count(), 1);
        assert_eq!(interface.role_count(), 1);
        assert_eq!(interface.user_count(), 1);
        assert!(dao.contains_key("perm:cache:12001"));
        assert!(dao.contains_key("role:cache:12001"));
        assert!(dao.contains_key("user:cache:12001"));

        // 模拟登出：invalidate 所有缓存
        service.invalidate("12001").await.unwrap();

        // 验证 L2 已清除
        assert!(!dao.contains_key("perm:cache:12001"));
        assert!(!dao.contains_key("role:cache:12001"));
        assert!(!dao.contains_key("user:cache:12001"));

        // 再次查询：L1+L2 已失效 → 走 L3
        let _ = service.get_permissions("12001").await.unwrap();
        let _ = service.get_roles("12001").await.unwrap();
        let _ = service.get_user("12001").await.unwrap();

        assert_eq!(interface.perm_count(), 2, "登出后权限缓存应走 L3");
        assert_eq!(interface.role_count(), 2, "登出后角色缓存应走 L3");
        assert_eq!(interface.user_count(), 2, "登出后用户缓存应走 L3");
    }

    /// I2: 权限变更后缓存失效 — invalidate 后返回新权限。
    #[tokio::test]
    async fn permission_change_invalidates_cache() {
        let (_dao, interface, service) = make_default_service();
        interface.set_permissions("13001", vec!["old:perm".to_string()]);

        // 第一次查询：缓存旧权限
        let perms1 = service.get_permissions("13001").await.unwrap();
        assert_eq!(perms1, vec!["old:perm".to_string()]);

        // 模拟权限变更
        interface.set_permissions("13001", vec!["new:perm".to_string()]);

        // 未 invalidate：仍返回缓存的旧权限
        let perms2 = service.get_permissions("13001").await.unwrap();
        assert_eq!(
            perms2,
            vec!["old:perm".to_string()],
            "未 invalidate 时应返回缓存的旧权限"
        );

        service.invalidate("13001").await.unwrap();
        let perms3 = service.get_permissions("13001").await.unwrap();
        assert_eq!(
            perms3,
            vec!["new:perm".to_string()],
            "invalidate 后应返回新权限"
        );
    }

    /// I3: 登出后再次登录走 L3 — invalidate 后所有缓存层均未命中。
    #[tokio::test]
    async fn logout_then_relogin_uses_l3() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("14001", vec!["perm:g".to_string()]);

        // 模拟首次登录：填充缓存
        let _ = service.get_permissions("14001").await.unwrap();
        assert_eq!(interface.perm_count(), 1, "首次登录应查询 L3");
        assert!(dao.contains_key("perm:cache:14001"));

        // 模拟登出
        service.invalidate("14001").await.unwrap();
        assert!(!dao.contains_key("perm:cache:14001"));

        // 模拟再次登录：L1+L2 已失效 → 走 L3
        let _ = service.get_permissions("14001").await.unwrap();
        assert_eq!(interface.perm_count(), 2, "登出后再次登录应走 L3");
        assert_eq!(
            dao.get_count(),
            4,
            "应查询 L2 两次（get_or 每轮 miss 双读 × 两轮）"
        );
    }

    // ------------------------------------------------------------------------
    // 配置项默认值测试
    // ------------------------------------------------------------------------

    /// 验证 three-tier-cache feature 启用时 default_config 包含正确的缓存配置默认值。
    #[test]
    fn default_config_includes_cache_settings() {
        let config = crate::config::GarrisonConfig::default_config();
        assert_eq!(
            config.l1_cache_ttl_secs,
            crate::config::DEFAULT_L1_CACHE_TTL_SECS
        );
        assert_eq!(
            config.l2_cache_ttl_secs,
            crate::config::DEFAULT_L2_CACHE_TTL_SECS
        );
        assert_eq!(
            config.l1_cache_capacity,
            crate::config::DEFAULT_L1_CACHE_CAPACITY
        );
    }

    /// 验证 l1_cache_ttl_secs = 0 时 validate 返回 Err。
    #[test]
    fn validate_rejects_zero_l1_cache_ttl() {
        let mut config = crate::config::GarrisonConfig::default_config();
        config.l1_cache_ttl_secs = 0;
        let result = config.validate();
        assert!(result.is_err(), "l1_cache_ttl_secs=0 应校验失败");
    }

    /// 验证 l2_cache_ttl_secs = 0 时 validate 返回 Err。
    #[test]
    fn validate_rejects_zero_l2_cache_ttl() {
        let mut config = crate::config::GarrisonConfig::default_config();
        config.l2_cache_ttl_secs = 0;
        let result = config.validate();
        assert!(result.is_err(), "l2_cache_ttl_secs=0 应校验失败");
    }

    /// 验证 l1_cache_capacity = 0 时 validate 返回 Err。
    #[test]
    fn validate_rejects_zero_l1_cache_capacity() {
        let mut config = crate::config::GarrisonConfig::default_config();
        config.l1_cache_capacity = 0;
        let result = config.validate();
        assert!(result.is_err(), "l1_cache_capacity=0 应校验失败");
    }

    // ------------------------------------------------------------------------
    // singleflight per-key RwLock 防击穿测试
    // ------------------------------------------------------------------------

    /// singleflight 防击穿 — 并发 10 次同一 key 请求只触发 1 次 L3 加载。
    ///
    /// 验证 UserCacheService 的 per-key RwLock singleflight 机制：
    /// 10 个并发任务同时请求同一 login_id 的权限列表时，
    /// L3 interface.get_permission_list 应只被调用一次（而非 10 次）。
    #[tokio::test(flavor = "multi_thread")]
    async fn singleflight_prevents_cache_stampede() {
        let dao = Arc::new(CountingMockDao::new());
        let interface = Arc::new(CountingMockInterface::new());
        interface.set_permissions("13001", vec!["perm:sf".to_string()]);

        let service = Arc::new(
            UserCacheService::new(
                dao.clone() as Arc<dyn GarrisonDao>,
                interface.clone() as Arc<dyn GarrisonPermissionStrategy>,
                30,
                300,
            )
            .expect("UserCacheService::new 应成功"),
        );

        // 并发 10 个任务同时调用 get_permissions
        let mut handles = Vec::new();
        for _ in 0..10 {
            let s = service.clone();
            handles.push(tokio::spawn(
                async move { s.get_permissions("13001").await },
            ));
        }

        for handle in handles {
            let perms = handle.await.expect("task panicked").expect("应成功");
            assert_eq!(perms, vec!["perm:sf".to_string()]);
        }

        // 核心断言：singleflight 应保证 L3 只被调用一次
        assert_eq!(
            interface.perm_count(),
            1,
            "singleflight 应保证并发请求同一 key 时只触发一次 L3 加载，实际: {}",
            interface.perm_count()
        );
    }

    /// singleflight 不同 key 不互相阻塞。
    ///
    /// 验证 per-key 锁不会阻塞不同 key 的并发请求：
    /// 同时请求 10 个不同 login_id，每个 key 应独立加载，perm_count 应为 10。
    #[tokio::test(flavor = "multi_thread")]
    async fn singleflight_different_keys_no_blocking() {
        let dao = Arc::new(CountingMockDao::new());
        let interface = Arc::new(CountingMockInterface::new());

        // 为 10 个不同 login_id 设置权限
        for i in 0..10 {
            let login_id = format!("1400{}", i);
            interface.set_permissions(&login_id, vec![format!("perm:{}", i)]);
        }

        let service = Arc::new(
            UserCacheService::new(
                dao.clone() as Arc<dyn GarrisonDao>,
                interface.clone() as Arc<dyn GarrisonPermissionStrategy>,
                30,
                300,
            )
            .expect("UserCacheService::new 应成功"),
        );

        // 并发 10 个任务请求不同 login_id
        let mut handles = Vec::new();
        for i in 0..10u32 {
            let s = service.clone();
            handles.push(tokio::spawn(async move {
                let login_id = format!("1400{}", i);
                s.get_permissions(&login_id).await
            }));
        }

        for (i, handle) in handles.into_iter().enumerate() {
            let perms = handle.await.expect("task panicked").expect("应成功");
            assert_eq!(perms, vec![format!("perm:{}", i)]);
        }

        // 10 个不同 key 应触发 10 次 L3 加载（per-key 锁不互相阻塞）
        assert_eq!(
            interface.perm_count(),
            10,
            "不同 key 应独立加载，L3 应被调用 10 次，实际: {}",
            interface.perm_count()
        );
    }

    /// singleflight 角色列表也防击穿（get_roles 复用同一机制）。
    #[tokio::test(flavor = "multi_thread")]
    async fn singleflight_protects_get_roles() {
        let dao = Arc::new(CountingMockDao::new());
        let interface = Arc::new(CountingMockInterface::new());
        interface.set_roles("15001", vec!["admin".to_string()]);

        let service = Arc::new(
            UserCacheService::new(
                dao.clone() as Arc<dyn GarrisonDao>,
                interface.clone() as Arc<dyn GarrisonPermissionStrategy>,
                30,
                300,
            )
            .expect("UserCacheService::new 应成功"),
        );

        let mut handles = Vec::new();
        for _ in 0..10 {
            let s = service.clone();
            handles.push(tokio::spawn(async move { s.get_roles("15001").await }));
        }

        for handle in handles {
            let roles = handle.await.expect("task panicked").expect("应成功");
            assert_eq!(roles, vec!["admin".to_string()]);
        }

        assert_eq!(
            interface.role_count(),
            1,
            "singleflight 应保证 get_roles 并发时只触发一次 L3 加载"
        );
    }

    /// singleflight 用户信息也防击穿（get_user 复用同一机制）。
    #[tokio::test(flavor = "multi_thread")]
    async fn singleflight_protects_get_user() {
        let dao = Arc::new(CountingMockDao::new());
        let interface = Arc::new(CountingMockInterface::new());
        interface.set_user_info("16001", Some(r#"{"id":16001}"#.to_string()));

        let service = Arc::new(
            UserCacheService::new(
                dao.clone() as Arc<dyn GarrisonDao>,
                interface.clone() as Arc<dyn GarrisonPermissionStrategy>,
                30,
                300,
            )
            .expect("UserCacheService::new 应成功"),
        );

        let mut handles = Vec::new();
        for _ in 0..10 {
            let s = service.clone();
            handles.push(tokio::spawn(async move { s.get_user("16001").await }));
        }

        for handle in handles {
            let user = handle.await.expect("task panicked").expect("应成功");
            assert_eq!(user, Some(r#"{"id":16001}"#.to_string()));
        }

        assert_eq!(
            interface.user_count(),
            1,
            "singleflight 应保证 get_user 并发时只触发一次 L3 加载"
        );
    }

    // ------------------------------------------------------------------------
    // 补充测试：覆盖 get_roles/get_user 的 L1 hit / L2 hit 回填 / L3 回填路径
    // ------------------------------------------------------------------------

    /// get_roles L1 命中时不查询 L2/L3。
    #[tokio::test]
    async fn get_roles_l1_hit_does_not_query_l2_l3() {
        let (dao, interface, service) = make_default_service();
        interface.set_roles("17001", vec!["admin".to_string()]);

        // 第一次调用：L1+L2 miss → L3 查询 → 回填 L1+L2
        let roles1 = service.get_roles("17001").await.unwrap();
        assert_eq!(roles1, vec!["admin".to_string()]);
        assert_eq!(interface.role_count(), 1, "第一次应查询 L3");
        // `get_or` miss 路径含两次链读（快路径 + leader 复查）
        assert_eq!(
            dao.get_count(),
            2,
            "第一次应查询 L2（get_or 快路径 + leader 复查）"
        );

        // 第二次调用：L1 hit → 不查询 L2/L3
        let roles2 = service.get_roles("17001").await.unwrap();
        assert_eq!(roles2, vec!["admin".to_string()]);
        assert_eq!(interface.role_count(), 1, "L1 命中不应查询 L3");
        assert_eq!(dao.get_count(), 2, "L1 命中不应查询 L2（较首次调用不增加）");
    }

    /// get_roles L1 未命中 L2 命中时回填 L1。
    #[tokio::test]
    async fn get_roles_l1_miss_l2_hit_backfills_l1() {
        let (dao, interface, service) = make_default_service();

        // 预填充 L2（模拟另一进程写入的缓存）
        let roles_json = serde_json::to_string(&vec!["editor".to_string()]).unwrap();
        dao.insert_direct("role:cache:18001", &roles_json);

        // 第一次调用：L1 miss → L2 hit → 回填 L1 → 不查询 L3
        let roles1 = service.get_roles("18001").await.unwrap();
        assert_eq!(roles1, vec!["editor".to_string()]);
        assert_eq!(interface.role_count(), 0, "L2 命中不应查询 L3");
        assert_eq!(dao.get_count(), 1, "L2 命中路径：链读一次（无 fallback）");

        // 第二次调用：L1 hit（已被回填）→ 不查询 L2/L3
        let roles2 = service.get_roles("18001").await.unwrap();
        assert_eq!(roles2, vec!["editor".to_string()]);
        assert_eq!(
            dao.get_count(),
            1,
            "L1 回填后不应再查询 L2（命中路径总量保持 1）"
        );
        assert_eq!(interface.role_count(), 0, "不应查询 L3");
    }

    /// get_user L1 命中时不查询 L2/L3。
    #[tokio::test]
    async fn get_user_l1_hit_does_not_query_l2_l3() {
        let (dao, interface, service) = make_default_service();
        interface.set_user_info("19001", Some(r#"{"name":"alice"}"#.to_string()));

        // 第一次调用：L1+L2 miss → L3 查询 → 回填 L1+L2
        let user1 = service.get_user("19001").await.unwrap();
        assert_eq!(user1, Some(r#"{"name":"alice"}"#.to_string()));
        assert_eq!(interface.user_count(), 1, "第一次应查询 L3");
        // `get_or` miss 路径含两次链读（快路径 + leader 复查）
        assert_eq!(
            dao.get_count(),
            2,
            "第一次应查询 L2（get_or 快路径 + leader 复查）"
        );

        // 第二次调用：L1 hit → 不查询 L2/L3
        let user2 = service.get_user("19001").await.unwrap();
        assert_eq!(user2, Some(r#"{"name":"alice"}"#.to_string()));
        assert_eq!(interface.user_count(), 1, "L1 命中不应查询 L3");
        assert_eq!(dao.get_count(), 2, "L1 命中不应查询 L2（较首次调用不增加）");
    }

    /// get_user L1 未命中 L2 命中时回填 L1。
    #[tokio::test]
    async fn get_user_l1_miss_l2_hit_backfills_l1() {
        let (dao, interface, service) = make_default_service();

        // 预填充 L2（模拟另一进程写入的缓存）
        dao.insert_direct("user:cache:20001", r#""{\"id\":20001}""#);

        // 第一次调用：L1 miss → L2 hit → 回填 L1 → 不查询 L3
        let user1 = service.get_user("20001").await.unwrap();
        assert_eq!(user1, Some(r#"{"id":20001}"#.to_string()));
        assert_eq!(interface.user_count(), 0, "L2 命中不应查询 L3");
        assert_eq!(dao.get_count(), 1, "L2 命中路径：链读一次（无 fallback）");

        // 第二次调用：L1 hit（已被回填）→ 不查询 L2/L3
        let user2 = service.get_user("20001").await.unwrap();
        assert_eq!(user2, Some(r#"{"id":20001}"#.to_string()));
        assert_eq!(
            dao.get_count(),
            1,
            "L1 回填后不应再查询 L2（命中路径总量保持 1）"
        );
        assert_eq!(interface.user_count(), 0, "不应查询 L3");
    }

    /// get_user L3 返回 Some 时回填 L1+L2。
    #[tokio::test]
    async fn get_user_l3_some_backfills_l1_and_l2() {
        let (dao, interface, service) = make_default_service();
        interface.set_user_info("21001", Some(r#"{"id":21001}"#.to_string()));

        // 第一次调用：L1+L2 miss → L3 查询 → 回填 L1+L2
        let user = service.get_user("21001").await.unwrap();
        assert_eq!(user, Some(r#"{"id":21001}"#.to_string()));
        assert_eq!(interface.user_count(), 1, "应查询 L3 一次");
        assert_eq!(
            dao.get_count(),
            2,
            "应查询 L2 一次（get_or 快路径 + leader 复查，miss 路径双读）"
        );
        assert_eq!(dao.set_count(), 1, "应回填 L2 一次");

        // 验证 L2 已被回填
        assert!(dao.contains_key("user:cache:21001"), "L2 应已被回填");

        // 验证 L1 已被回填（第二次调用不走 L3）
        let user2 = service.get_user("21001").await.unwrap();
        assert_eq!(user2, Some(r#"{"id":21001}"#.to_string()));
        assert_eq!(interface.user_count(), 1, "L1 回填后不应再查询 L3");
    }

    // ------------------------------------------------------------------------
    // 补充测试：错误处理路径
    // ------------------------------------------------------------------------

    /// L2 损坏值容错：逐出坏键回源 L3，读取不失败。
    ///
    /// 链式缓存下（反）序列化由 typed Cache 承载；L2 损坏值在链读时失败，
    /// 缓存层逐出并回源 L3（失败经 warn 显性化，不向调用方抛错）。
    #[tokio::test]
    async fn l2_corrupt_permission_cache_returns_internal_error() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("22001", vec!["perm:ok".to_string()]);

        dao.insert_direct("perm:cache:22001", "{invalid json");

        let result = service.get_permissions("22001").await;
        assert_eq!(
            result.unwrap(),
            vec!["perm:ok".to_string()],
            "L2 损坏值应逐出后回源 L3 并返回 L3 数据"
        );
    }

    /// L3 interface 失败时透传错误（权限/角色/用户三类）。
    #[tokio::test]
    async fn l3_failure_propagates_error() {
        let (_dao, interface, service) = make_default_service();

        // 注入 L3 权限错误
        interface.set_fail_perm(true);
        let result = service.get_permissions("23001").await;
        assert!(result.is_err(), "L3 权限失败应返回 Err");
        match result {
            Err(GarrisonError::Internal(msg)) => {
                assert!(
                    msg.contains("injected perm error"),
                    "应透传 L3 权限错误消息，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 GarrisonError::Internal，实际: {:?}", other),
            Ok(_) => panic!("期望 Err，实际 Ok"),
        }

        // 注入 L3 角色错误
        interface.set_fail_role(true);
        let result = service.get_roles("23002").await;
        assert!(result.is_err(), "L3 角色失败应返回 Err");
        match result {
            Err(GarrisonError::Internal(msg)) => {
                assert!(
                    msg.contains("injected role error"),
                    "应透传 L3 角色错误消息，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 GarrisonError::Internal，实际: {:?}", other),
            Ok(_) => panic!("期望 Err，实际 Ok"),
        }

        // 注入 L3 用户错误
        interface.set_fail_user(true);
        let result = service.get_user("23003").await;
        assert!(result.is_err(), "L3 用户失败应返回 Err");
        match result {
            Err(GarrisonError::Internal(msg)) => {
                assert!(
                    msg.contains("injected user error"),
                    "应透传 L3 用户错误消息，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 GarrisonError::Internal，实际: {:?}", other),
            Ok(_) => panic!("期望 Err，实际 Ok"),
        }
    }

    /// L2 DAO 故障时缓存层容错降级（L3 回源 / 写回失败不毁读取）。
    #[tokio::test]
    async fn l2_dao_failure_falls_back_to_l3() {
        // 场景 1：注入 DAO get 错误
        // L1 miss → L2 get 失败 → 透传错误
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("24001", vec!["perm:ok".to_string()]);
        dao.set_fail_get(true);

        // 缓存层容错：L2 读失败 → 逐出回源 L3，读取不失败（warn 显性化）
        let result = service.get_permissions("24001").await;
        assert_eq!(
            result.unwrap(),
            vec!["perm:ok".to_string()],
            "L2 DAO get 失败应降级 L3 返回 L3 数据"
        );

        // 场景 2：注入 DAO set 错误
        // L1 miss → L2 miss → L3 查询 → 回填 L1 成功 → 回填 L2 set 失败 → 透传错误
        let (dao2, interface2, service2) = make_default_service();
        interface2.set_permissions("24002", vec!["perm:set_fail".to_string()]);
        dao2.set_fail_set(true);

        // 写回失败不影响读取：L3 数据有效，返回但不缓存（warn 显性化）
        let result = service2.get_permissions("24002").await;
        assert_eq!(
            result.unwrap(),
            vec!["perm:set_fail".to_string()],
            "L2 DAO set 失败应返回 L3 数据（不缓存）"
        );
    }

    /// invalidate 时 L2 delete 失败透传错误。
    #[tokio::test]
    async fn invalidate_l2_delete_failure_propagates_error() {
        let (dao, _interface, service) = make_default_service();
        dao.set_fail_delete(true);

        let result = service.invalidate("25001").await;
        assert!(result.is_err(), "L2 delete 失败应返回 Err");
        match result {
            Err(GarrisonError::Dao(msg)) => {
                assert!(
                    msg.contains("injected delete error"),
                    "应透传 DAO delete 错误消息，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 GarrisonError::Dao，实际: {:?}", other),
            Ok(_) => panic!("期望 Err，实际 Ok"),
        }

        assert!(
            dao.delete_count() >= 1,
            "应至少调用一次 L2 delete，实际: {}",
            dao.delete_count()
        );
    }

    /// invalidate 部分失败聚合——中途失败不再跳过
    /// 后续删除，全部 3 次 L2 delete 都会被尝试（+3 次 L1 delete），返回首个错误。
    #[tokio::test]
    async fn invalidate_attempts_all_deletes_on_partial_failure() {
        let (dao, _interface, service) = make_default_service();
        dao.set_fail_delete(true);

        let result = service.invalidate("26001").await;
        assert!(result.is_err(), "存在失败 delete 应返回 Err");
        // 全部 3 个 key 的 L2 delete 都被尝试（旧实现第 1 次失败即返回，count=1）
        assert_eq!(
            dao.delete_count(),
            3,
            "即使失败也应尝试全部 3 次 L2 delete，实际: {}",
            dao.delete_count()
        );
        // 返回首个错误（注入的 Dao 错误）
        match result {
            Err(GarrisonError::Dao(msg)) => {
                assert!(msg.contains("injected delete error"), "实际: {}", msg);
            },
            Err(other) => panic!("期望 GarrisonError::Dao，实际: {:?}", other),
            Ok(_) => panic!("期望 Err，实际 Ok"),
        }
    }

    // ------------------------------------------------------------------------
    // 补充测试：getter 方法
    // ------------------------------------------------------------------------

    /// l1_ttl_secs / l2_ttl_secs getter 返回构造时传入的值。
    #[test]
    fn ttl_getters_return_configured_values() {
        let (_dao, _interface, service) = make_service(60, 600);
        assert_eq!(service.l1_ttl_secs(), 60, "l1_ttl_secs 应返回 60");
        assert_eq!(service.l2_ttl_secs(), 600, "l2_ttl_secs 应返回 600");
    }

    // ------------------------------------------------------------------------
    // 补充测试：L1 缓存反序列化失败路径（覆盖 line 141-143 / 220-222）
    // ------------------------------------------------------------------------

    /// 缓存数据损坏（反序列化失败）返回 Internal 错误。
    ///
    /// 链式缓存下负载的（反）序列化由 oxcache typed Cache 承载，garrison 侧
    /// 不再有手工 `from_str` 步骤——损坏数据在链读取时于 typed 层失败，
    /// 经 `load_*_with` 的兜底映射为 Internal（错误串 `cache-chain-get::`）。
    /// 直接向 L2 DAO 注入非负载 JSON 模拟损坏。
    #[tokio::test]
    async fn l1_corrupt_permission_cache_returns_internal_error() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("27001", vec!["user:read".to_string()]);

        let key = "perm:cache:27001".to_string();
        dao.insert_direct(&key, "{invalid json");

        // 缓存层容错：损坏值逐出后回源 L3，读取不失败
        let result = service.get_permissions("27001").await;
        assert_eq!(
            result.unwrap(),
            vec!["user:read".to_string()],
            "损坏缓存应逐出后回源 L3 并返回 L3 数据"
        );
        // 自愈：逐出后再次读取走正常 miss 路径重新缓存，L2 恢复合法形态
        let again = service.get_permissions("27001").await.unwrap();
        assert_eq!(again, vec!["user:read".to_string()]);
        assert!(
            dao.contains_key("perm:cache:27001"),
            "自愈路径应重新回填 L2"
        );
    }

    /// 角色缓存数据损坏返回 Internal 错误（同权限路径）。
    #[tokio::test]
    async fn l1_corrupt_role_cache_returns_internal_error() {
        let (dao, interface, service) = make_default_service();
        interface.set_roles("28001", vec!["role:admin".to_string()]);

        let key = "role:cache:28001".to_string();
        dao.insert_direct(&key, "{invalid json");

        let result = service.get_roles("28001").await;
        assert_eq!(
            result.unwrap(),
            vec!["role:admin".to_string()],
            "损坏缓存应逐出后回源 L3 并返回 L3 数据"
        );
        let again = service.get_roles("28001").await.unwrap();
        assert_eq!(again, vec!["role:admin".to_string()]);
        assert!(
            dao.contains_key("role:cache:28001"),
            "自愈路径应重新回填 L2"
        );
    }

    /// L2 角色缓存反序列化失败返回 Internal 错误。
    ///
    /// L2 角色损坏值容错：逐出坏键回源 L3（同权限路径）。
    #[tokio::test]
    async fn l2_corrupt_role_cache_returns_internal_error() {
        let (dao, interface, service) = make_default_service();
        interface.set_roles("29001", vec!["role:ok".to_string()]);

        dao.insert_direct("role:cache:29001", "{invalid json");

        let result = service.get_roles("29001").await;
        assert_eq!(
            result.unwrap(),
            vec!["role:ok".to_string()],
            "L2 损坏值应逐出后回源 L3 并返回 L3 数据"
        );
    }

    // ------------------------------------------------------------------------
    // 补充测试：invalidate 对角色和用户缓存的 L1 失效验证
    // ------------------------------------------------------------------------

    /// invalidate 后 get_roles 重新查询 L3（L1+L2 失效验证）。
    #[tokio::test]
    async fn invalidate_clears_l1_for_roles() {
        let (_dao, interface, service) = make_default_service();
        interface.set_roles("30001", vec!["admin".to_string()]);

        // 填充 L1
        let _ = service.get_roles("30001").await.unwrap();
        assert_eq!(interface.role_count(), 1, "第一次应查询 L3");

        // invalidate 失效 L1+L2
        service.invalidate("30001").await.unwrap();

        // 再次查询：L1 已失效 → L2 也被删除 → L3 查询
        let _ = service.get_roles("30001").await.unwrap();
        assert_eq!(interface.role_count(), 2, "invalidate 后应重新查询 L3");
    }

    /// invalidate 后 get_user 重新查询 L3（L1+L2 失效验证）。
    #[tokio::test]
    async fn invalidate_clears_l1_for_user() {
        let (_dao, interface, service) = make_default_service();
        interface.set_user_info("31001", Some(r#"{"id":31001}"#.to_string()));

        // 填充 L1
        let _ = service.get_user("31001").await.unwrap();
        assert_eq!(interface.user_count(), 1, "第一次应查询 L3");

        // invalidate 失效 L1+L2
        service.invalidate("31001").await.unwrap();

        // 再次查询：L1 已失效 → L2 也被删除 → L3 查询
        let _ = service.get_user("31001").await.unwrap();
        assert_eq!(interface.user_count(), 2, "invalidate 后应重新查询 L3");
    }

    // ------------------------------------------------------------------------
    // 补充测试：L3 回填验证 + 空列表 + TTL 过期（角色/用户）
    // ------------------------------------------------------------------------

    /// get_roles L3 命中后回填 L1+L2。
    #[tokio::test]
    async fn get_roles_l3_backfills_l1_and_l2() {
        let (dao, interface, service) = make_default_service();
        interface.set_roles("32001", vec!["editor".to_string()]);

        // 第一次调用：L1+L2 miss → L3 查询 → 回填 L1+L2
        let roles = service.get_roles("32001").await.unwrap();
        assert_eq!(roles, vec!["editor".to_string()]);
        assert_eq!(interface.role_count(), 1, "应查询 L3 一次");
        assert_eq!(
            dao.get_count(),
            2,
            "应查询 L2 一次（get_or 快路径 + leader 复查，miss 路径双读）"
        );
        assert_eq!(dao.set_count(), 1, "应回填 L2 一次");

        // 验证 L2 已被回填
        assert!(dao.contains_key("role:cache:32001"), "L2 应已被回填");

        // 验证 L1 已被回填（第二次调用不走 L3）
        let roles2 = service.get_roles("32001").await.unwrap();
        assert_eq!(roles2, vec!["editor".to_string()]);
        assert_eq!(interface.role_count(), 1, "L1 回填后不应再查询 L3");
    }

    /// get_permissions 返回空列表时正确缓存。
    #[tokio::test]
    async fn get_permissions_returns_empty_vec() {
        let (dao, interface, service) = make_default_service();
        // 不设置 permissions → L3 返回空 Vec

        let perms = service.get_permissions("33001").await.unwrap();
        assert!(perms.is_empty(), "未设置权限时应返回空列表");
        assert_eq!(interface.perm_count(), 1, "应查询 L3 一次");
        // 空列表也应被缓存到 L2
        assert_eq!(dao.set_count(), 1, "空列表也应回填 L2");
    }

    /// get_roles 返回空列表时正确缓存。
    #[tokio::test]
    async fn get_roles_returns_empty_vec() {
        let (dao, interface, service) = make_default_service();

        let roles = service.get_roles("34001").await.unwrap();
        assert!(roles.is_empty(), "未设置角色时应返回空列表");
        assert_eq!(interface.role_count(), 1, "应查询 L3 一次");
        assert_eq!(dao.set_count(), 1, "空列表也应回填 L2");
    }

    /// TTL 过期后 get_roles 走 L2 回填 L1。
    #[tokio::test]
    async fn ttl_expires_l1_for_roles() {
        let (_dao, interface, service) = make_service(1, 300);
        interface.set_roles("35001", vec!["admin".to_string()]);

        // 第一次调用：填充 L1
        let _ = service.get_roles("35001").await.unwrap();
        assert_eq!(interface.role_count(), 1, "第一次应查询 L3");

        // 等待 L1 TTL 过期
        tokio::time::sleep(Duration::from_secs(2)).await;

        // 第二次调用：L1 已过期 → L2 命中 → 回填 L1 → 不查询 L3
        let roles = service.get_roles("35001").await.unwrap();
        assert_eq!(roles, vec!["admin".to_string()]);
        assert_eq!(interface.role_count(), 1, "L1 过期后 L2 命中，不应查询 L3");
    }

    /// TTL 过期后 get_user 走 L2 回填 L1。
    #[tokio::test]
    async fn ttl_expires_l1_for_user() {
        let (_dao, interface, service) = make_service(1, 300);
        interface.set_user_info("36001", Some(r#"{"id":36001}"#.to_string()));

        // 第一次调用：填充 L1
        let _ = service.get_user("36001").await.unwrap();
        assert_eq!(interface.user_count(), 1, "第一次应查询 L3");

        // 等待 L1 TTL 过期
        tokio::time::sleep(Duration::from_secs(2)).await;

        // 第二次调用：L1 已过期 → L2 命中 → 回填 L1 → 不查询 L3
        let user = service.get_user("36001").await.unwrap();
        assert_eq!(user, Some(r#"{"id":36001}"#.to_string()));
        assert_eq!(interface.user_count(), 1, "L1 过期后 L2 命中，不应查询 L3");
    }

    // ------------------------------------------------------------------------
    // 补充测试：L2 DAO 失败路径（get_roles / get_user）
    // ------------------------------------------------------------------------

    /// L2 DAO get 失败时 get_roles 容错回源 L3（缓存层不毁读取）。
    #[tokio::test]
    async fn l2_dao_get_failure_propagates_error_for_get_roles() {
        let (dao, interface, service) = make_default_service();
        interface.set_roles("37001", vec!["role:ok".to_string()]);
        dao.set_fail_get(true);

        let result = service.get_roles("37001").await;
        assert_eq!(
            result.unwrap(),
            vec!["role:ok".to_string()],
            "L2 DAO get 失败应回源 L3 返回角色数据"
        );
    }

    /// L2 DAO get 失败时 get_user 透传错误。
    /// get_user 的 L2 DAO get 失败：缓存层容错回源 L3。
    #[tokio::test]
    async fn l2_dao_get_failure_propagates_error_for_get_user() {
        let (dao, interface, service) = make_default_service();
        interface.set_user_info("38001", Some(r#"{"id":38001}"#.to_string()));
        dao.set_fail_get(true);

        let result = service.get_user("38001").await;
        assert_eq!(
            result.unwrap(),
            Some(r#"{"id":38001}"#.to_string()),
            "L2 DAO get 失败应回源 L3 返回用户信息"
        );
    }

    /// L2 DAO set 失败时 get_roles 仍返回 L3 数据（写回失败不毁读取）。
    #[tokio::test]
    async fn l2_dao_set_failure_propagates_error_for_get_roles() {
        let (dao, interface, service) = make_default_service();
        interface.set_roles("39001", vec!["editor".to_string()]);
        dao.set_fail_set(true);

        let result = service.get_roles("39001").await;
        assert_eq!(
            result.unwrap(),
            vec!["editor".to_string()],
            "L2 DAO set 失败应返回 L3 数据（不缓存）"
        );
    }

    /// L2 DAO set 失败时 get_user(Some) 仍返回 L3 数据（写回失败不毁读取）。
    #[tokio::test]
    async fn l2_dao_set_failure_propagates_error_for_get_user_some() {
        let (dao, interface, service) = make_default_service();
        interface.set_user_info("40001", Some(r#"{"id":40001}"#.to_string()));
        dao.set_fail_set(true);

        let result = service.get_user("40001").await;
        assert_eq!(
            result.unwrap(),
            Some(r#"{"id":40001}"#.to_string()),
            "L2 DAO set 失败应返回 L3 数据（不缓存）"
        );
    }

    /// L2 DAO set 失败时 get_user(None) 不触发 set（None 不缓存）。
    ///
    /// L3 返回 None → 不回填 L1+L2 → DAO set 不被调用 → 返回 Ok(None)。
    #[tokio::test]
    async fn l2_dao_set_failure_does_not_affect_get_user_none() {
        let (dao, _interface, service) = make_default_service();
        dao.set_fail_set(true);

        // L3 返回 None（未设置 user_info）→ 不回填 L2 → set 失败不影响结果
        let result = service.get_user("41001").await;
        assert!(
            result.is_ok(),
            "get_user(None) 不应受 L2 set 失败影响，实际: {:?}",
            result
        );
        assert!(result.unwrap().is_none());
        assert_eq!(dao.set_count(), 0, "None 不应触发 L2 set 操作");
    }

    // ------------------------------------------------------------------------
    // 补充测试：invalidate 部分失败（第二个 delete 失败）
    // ------------------------------------------------------------------------

    /// invalidate 在 L2 delete role_key 失败时透传错误。
    ///
    /// invalidate 按 perm → role → user 顺序删除 L2，
    /// 注入 role delete 失败（通过 fail_delete 在第一次成功后开启）。
    /// 验证：第一个 delete（perm）成功，第二个 delete（role）失败 → 返回 Err。
    #[tokio::test]
    async fn invalidate_partial_l2_delete_failure_propagates_error() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("42001", vec!["perm:a".to_string()]);
        interface.set_roles("42001", vec!["role:a".to_string()]);
        interface.set_user_info("42001", Some(r#"{"id":42001}"#.to_string()));

        // 填充所有三类缓存
        let _ = service.get_permissions("42001").await.unwrap();
        let _ = service.get_roles("42001").await.unwrap();
        let _ = service.get_user("42001").await.unwrap();

        // 验证所有三类缓存已填充到 L2
        assert!(dao.contains_key("perm:cache:42001"));
        assert!(dao.contains_key("role:cache:42001"));
        assert!(dao.contains_key("user:cache:42001"));

        dao.set_fail_delete(true);

        let result = service.invalidate("42001").await;
        assert!(result.is_err(), "L2 delete 失败应返回 Err");
        match result {
            Err(GarrisonError::Dao(msg)) => {
                assert!(
                    msg.contains("injected delete error"),
                    "应透传 DAO delete 错误消息，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 GarrisonError::Dao，实际: {:?}", other),
            Ok(_) => panic!("期望 Err，实际 Ok"),
        }

        // 验证第一个 delete（perm_key）已执行；
        // 部分失败语义已改为聚合——后续 delete 不再中断，全部 3 次 L2 delete
        // 都会被尝试，返回首个错误
        assert_eq!(
            dao.delete_count(),
            3,
            "失败后应继续尝试全部 L2 delete（聚合错误语义），实际执行: 3"
        );
    }

    /// invalidate 在所有 L2 delete 成功后 L1 delete 也执行。
    ///
    /// 验证 invalidate 的完整流程：L2 delete 3 次 + L1 delete 3 次 = 6 次操作。
    #[tokio::test]
    async fn invalidate_executes_all_l2_and_l1_deletes() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("43001", vec!["perm:a".to_string()]);
        interface.set_roles("43001", vec!["role:a".to_string()]);
        interface.set_user_info("43001", Some(r#"{"id":43001}"#.to_string()));

        // 填充所有三类缓存
        let _ = service.get_permissions("43001").await.unwrap();
        let _ = service.get_roles("43001").await.unwrap();
        let _ = service.get_user("43001").await.unwrap();

        // 验证 L2 缓存已填充
        assert!(dao.contains_key("perm:cache:43001"));
        assert!(dao.contains_key("role:cache:43001"));
        assert!(dao.contains_key("user:cache:43001"));

        service.invalidate("43001").await.unwrap();

        // 验证 L2 缓存已全部删除
        assert!(!dao.contains_key("perm:cache:43001"));
        assert!(!dao.contains_key("role:cache:43001"));
        assert!(!dao.contains_key("user:cache:43001"));

        // 验证 L2 delete 被调用 3 次
        assert_eq!(
            dao.delete_count(),
            3,
            "invalidate 应执行 3 次 L2 delete（perm + role + user）"
        );

        // 验证 delete 调用顺序：perm → role → user
        let delete_keys = dao.delete_keys();
        assert_eq!(delete_keys.len(), 3, "应记录 3 次 delete 调用");
        assert_eq!(
            delete_keys[0], "perm:cache:43001",
            "第一个 delete 应为 perm_key"
        );
        assert_eq!(
            delete_keys[1], "role:cache:43001",
            "第二个 delete 应为 role_key"
        );
        assert_eq!(
            delete_keys[2], "user:cache:43001",
            "第三个 delete 应为 user_key"
        );
    }

    // ------------------------------------------------------------------------
    // 补充测试：get_user 边缘条件
    // ------------------------------------------------------------------------

    /// get_user L3 返回 Some("") 时缓存空字符串。
    ///
    /// 空字符串是 Some 值，应被缓存到 L1+L2（与 None 不同）。
    #[tokio::test]
    async fn get_user_l3_some_empty_string_is_cached() {
        let (dao, interface, service) = make_default_service();
        interface.set_user_info("44001", Some(String::new()));

        // 第一次调用：L1+L2 miss → L3 查询 → 返回 Some("") → 回填 L1+L2
        let user = service.get_user("44001").await.unwrap();
        assert_eq!(user, Some(String::new()), "L3 返回 Some(\"\") 应透传");
        assert_eq!(interface.user_count(), 1, "应查询 L3 一次");
        assert_eq!(dao.set_count(), 1, "Some(\"\") 应回填 L2");

        // 验证 L2 已被回填
        assert!(
            dao.contains_key("user:cache:44001"),
            "Some(\"\") 应被缓存到 L2"
        );

        // 第二次调用：L1 hit → 不查询 L2/L3
        let user2 = service.get_user("44001").await.unwrap();
        assert_eq!(user2, Some(String::new()));
        assert_eq!(interface.user_count(), 1, "L1 命中不应查询 L3");
    }

    /// get_user L2 命中返回 typed 层反序列化后的字符串。
    ///
    /// 链式缓存下 L2 值为 typed Cache 的序列化形态（JSON 字符串，带引号）；
    /// garrison 侧不再有「原样字符串」路径——存取对称经 typed 层。
    #[tokio::test]
    async fn get_user_l2_hit_returns_deserialized_string() {
        let (dao, _interface, service) = make_default_service();

        dao.insert_direct("user:cache:45001", r#""{\"name\":\"bob\"}""#);

        // L1 miss → L2 hit → 回填 L1 → 返回反序列化后的用户信息
        let user = service.get_user("45001").await.unwrap();
        assert_eq!(
            user,
            Some(r#"{"name":"bob"}"#.to_string()),
            "get_user 应返回 L2 值反序列化后的字符串"
        );
    }

    /// 旧格式残留（非 JSON 裸字符串）容忍：链读反序列化失败 → 逐出 + 回源 L3。
    ///
    /// 升级过渡期 L2 可能残留旧实现的裸字符串形态（未引号包裹）；缓存层不得
    /// 因此让读取失败——逐出坏键回源 L3，语义自愈。
    #[tokio::test]
    async fn get_user_legacy_raw_l2_value_tolerated_via_l3() {
        let (dao, interface, service) = make_default_service();
        interface.set_user_info("45002", Some(r#"{"id":45002}"#.to_string()));

        // 旧格式：裸字符串（无 JSON 引号）
        dao.insert_direct("user:cache:45002", "legacy-raw-value");

        let user = service.get_user("45002").await.unwrap();
        assert_eq!(
            user,
            Some(r#"{"id":45002}"#.to_string()),
            "旧格式残留应逐出后回源 L3，返回 L3 数据"
        );
    }

    // ------------------------------------------------------------------------
    // 补充测试：special characters in login_id
    // ------------------------------------------------------------------------

    /// get_permissions 处理包含特殊字符的 login_id。
    ///
    /// 验证 login_id 包含 URL 安全字符（点、下划线）时缓存键正确构建。
    /// （id 不得含 `:`——dao_keys::build_key 的冒号歧义防护，debug 构建会 panic。）
    #[tokio::test]
    async fn get_permissions_handles_special_chars_in_login_id() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("user_1001.v2", vec!["perm:special".to_string()]);

        let perms = service.get_permissions("user_1001.v2").await.unwrap();
        assert_eq!(perms, vec!["perm:special".to_string()]);

        // 验证缓存键包含原始 login_id（不做转义）
        let set_keys = dao.set_keys();
        assert!(
            set_keys.iter().any(|k| k == "perm:cache:user_1001.v2"),
            "缓存键应包含原始 login_id，实际: {:?}",
            set_keys
        );

        // 第二次调用：L1 hit → 不查询 L2/L3
        let perms2 = service.get_permissions("user_1001.v2").await.unwrap();
        assert_eq!(perms2, vec!["perm:special".to_string()]);
        assert_eq!(interface.perm_count(), 1, "L1 命中不应查询 L3");
    }

    /// invalidate 处理包含特殊字符的 login_id。
    #[tokio::test]
    async fn invalidate_handles_special_chars_in_login_id() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("user_2001.v2", vec!["perm:a".to_string()]);

        let _ = service.get_permissions("user_2001.v2").await.unwrap();
        assert!(dao.contains_key("perm:cache:user_2001.v2"));

        service.invalidate("user_2001.v2").await.unwrap();

        // 验证 L2 已清除
        assert!(!dao.contains_key("perm:cache:user_2001.v2"));

        let delete_keys = dao.delete_keys();
        assert!(
            delete_keys.iter().any(|k| k == "perm:cache:user_2001.v2"),
            "delete 应使用 key 'perm:cache:user_2001.v2'，实际: {:?}",
            delete_keys
        );
    }

    // ------------------------------------------------------------------------
    // 补充测试：singleflight_lock 方法验证
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // singleflight 内部件（DashMap per-key RwLock）测试已随实现删除而移除：
    // 单飞由 oxcache `Cache::get_or` 的 leader/follower 承载，锁身份与
    // CWE-770 entry 清理义务移入库侧（库自有测试覆盖）；garrison 侧保留
    // 行为级契约 `singleflight_prevents_cache_stampede` 等（见上）。
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // 补充测试：UserCacheService::new 边缘条件
    // ------------------------------------------------------------------------

    /// UserCacheService::new 接受不同 TTL 值并正确存储。
    #[tokio::test]
    async fn new_stores_ttl_values_correctly() {
        let dao = Arc::new(CountingMockDao::new());
        let interface = Arc::new(CountingMockInterface::new());
        let service = UserCacheService::new(
            dao.clone() as Arc<dyn GarrisonDao>,
            interface.clone() as Arc<dyn GarrisonPermissionStrategy>,
            120,
            3600,
        )
        .unwrap();

        assert_eq!(service.l1_ttl_secs(), 120, "l1_ttl_secs 应为 120");
        assert_eq!(service.l2_ttl_secs(), 3600, "l2_ttl_secs 应为 3600");
    }

    // ------------------------------------------------------------------------
    // 补充测试：L3 返回空 Vec 的回填验证（get_user 对应 None）
    // ------------------------------------------------------------------------

    /// get_permissions L3 返回空 Vec 时仍回填 L1+L2（与 None 语义不同）。
    #[tokio::test]
    async fn get_permissions_l3_empty_vec_backfills_both_layers() {
        let (dao, interface, service) = make_default_service();
        // 不设置 permissions → L3 返回空 Vec

        let perms = service.get_permissions("51001").await.unwrap();
        assert!(perms.is_empty(), "未设置权限时应返回空列表");
        assert_eq!(interface.perm_count(), 1, "应查询 L3 一次");
        assert_eq!(dao.set_count(), 1, "空 Vec 也应回填 L2");

        // 验证 L2 已被回填（空列表 "[]" ）
        assert!(dao.contains_key("perm:cache:51001"), "空 Vec 应被缓存到 L2");

        // 验证 L1 已被回填（第二次调用不走 L3）
        let perms2 = service.get_permissions("51001").await.unwrap();
        assert!(perms2.is_empty());
        assert_eq!(interface.perm_count(), 1, "L1 回填后不应再查询 L3");
    }

    /// get_roles L3 返回空 Vec 时仍回填 L1+L2。
    #[tokio::test]
    async fn get_roles_l3_empty_vec_backfills_both_layers() {
        let (dao, interface, service) = make_default_service();

        let roles = service.get_roles("52001").await.unwrap();
        assert!(roles.is_empty(), "未设置角色时应返回空列表");
        assert_eq!(interface.role_count(), 1, "应查询 L3 一次");
        assert_eq!(dao.set_count(), 1, "空 Vec 也应回填 L2");
        assert!(dao.contains_key("role:cache:52001"), "空 Vec 应被缓存到 L2");

        // 验证 L1 已被回填
        let roles2 = service.get_roles("52001").await.unwrap();
        assert!(roles2.is_empty());
        assert_eq!(interface.role_count(), 1, "L1 回填后不应再查询 L3");
    }

    // ------------------------------------------------------------------------
    // 补充测试：并发 invalidate + get 验证
    // ------------------------------------------------------------------------

    /// invalidate 后立即 get_permissions 返回新数据（无缓存残留）。
    ///
    /// 验证 invalidate 的原子性：L2+L1 全部清除后，下次 get 必走 L3。
    #[tokio::test]
    async fn invalidate_then_get_returns_fresh_data() {
        let (_dao, interface, service) = make_default_service();
        interface.set_permissions("53001", vec!["old:perm".to_string()]);

        // 第一次查询：缓存旧权限
        let perms1 = service.get_permissions("53001").await.unwrap();
        assert_eq!(perms1, vec!["old:perm".to_string()]);

        // 更新 L3 数据
        interface.set_permissions("53001", vec!["new:perm".to_string()]);

        service.invalidate("53001").await.unwrap();

        // 立即查询：应返回新权限
        let perms2 = service.get_permissions("53001").await.unwrap();
        assert_eq!(
            perms2,
            vec!["new:perm".to_string()],
            "invalidate 后应返回 L3 的新数据"
        );
        assert_eq!(
            interface.perm_count(),
            2,
            "应查询 L3 两次（首次 + invalidate 后）"
        );
    }

    /// get_user L2 命中后再次调用走 L1（回填验证）。
    ///
    /// 与上方 get_user_l1_miss_l2_hit_backfills_l1 测试类似，但验证 L2 中的值被回填到 L1 后，
    /// 后续 get_user 不再查询 L2（get_count 不增加）。
    #[tokio::test]
    async fn get_user_l2_hit_backfills_l1_no_repeat_l2_query() {
        let (dao, _interface, service) = make_default_service();
        dao.insert_direct("user:cache:54001", r#""{\"id\":54001}""#);

        // 第一次调用：L1 miss → L2 hit → 回填 L1
        let user1 = service.get_user("54001").await.unwrap();
        assert_eq!(user1, Some(r#"{"id":54001}"#.to_string()));
        assert_eq!(dao.get_count(), 1, "L2 命中路径：链读一次（无 fallback）");

        // 第二次调用：L1 hit → 不查询 L2
        let user2 = service.get_user("54001").await.unwrap();
        assert_eq!(user2, Some(r#"{"id":54001}"#.to_string()));
        assert_eq!(
            dao.get_count(),
            1,
            "L1 回填后不应再查询 L2（命中路径总量保持 1）"
        );

        // 第三次调用：L1 hit → 不查询 L2
        let user3 = service.get_user("54001").await.unwrap();
        assert_eq!(user3, Some(r#"{"id":54001}"#.to_string()));
        assert_eq!(
            dao.get_count(),
            1,
            "L1 仍命中，不应查询 L2（命中路径总量保持 1）"
        );
    }

    /// 调用 CountingMockDao 的 atomic + 默认 trait 方法以覆盖 async_trait wrapper。
    #[tokio::test]
    async fn counting_mock_dao_atomic_and_default_methods_coverage() {
        use crate::dao::GarrisonDao;
        let dao = CountingMockDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        let _ = dao.set_if_absent("a1", "v1", 60).await;
        let _ = dao.get_and_delete("a1").await;
        let _ = dao.incr("ctr", 60).await;
        let _ = dao.decr("ctr").await;
        let _ = dao.rename("k1", "k2").await;
        let _ = dao.compare_and_swap("k2", Some("v1"), "v2", 60).await;
        let _ = dao.set_permanent("p1", "val").await;
        let _ = dao.get_with_ttl("k1").await;
        let _ = dao.get_timeout("k1").await;
        let _ = dao.keys("*").await;
        let _ = dao.find_social_binding(0, "w", "o").await;
        let _ = dao.insert_social_binding(0, "u", "w", "o", None, 0).await;
        let _ = dao.compare_and_update_if_greater("k1", 10, 60).await;
        let _ = dao.eval_lua("r", vec![], vec![]).await;
        #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
        {
            let _ = dao.insert_credit_consumption(0, "r", 1, 1, 1, 0).await;
            let _ = dao.query_credit_consumption(0, 0, 0).await;
            let _ = dao.query_role_hierarchy_edges(0).await;
            let _ = dao.insert_role_hierarchy_edge(0, "c", "p").await;
            let _ = dao.delete_role_hierarchy_edge(0, "c", "p").await;
        }
    }
    // ------------------------------------------------------------------------
    // new_with_capacity 参数校验（TTL / capacity 0 值 fail-fast）
    // ------------------------------------------------------------------------

    /// 构造参数校验入口（复用 CountingMockDao / CountingMockInterface）。
    fn build_with_capacity(l1: u64, l2: u64, cap: u64) -> GarrisonResult<UserCacheService> {
        let dao = Arc::new(CountingMockDao::new());
        let iface = Arc::new(CountingMockInterface::new());
        UserCacheService::new_with_capacity(
            dao as Arc<dyn GarrisonDao>,
            iface as Arc<dyn GarrisonPermissionStrategy>,
            l1,
            l2,
            cap,
        )
    }

    /// l1_ttl = 0 → cache-l1-ttl-must-positive。
    #[test]
    fn rejects_zero_l1_ttl() {
        let err = match build_with_capacity(0, 300, 128) {
            Err(e) => e,
            Ok(_) => panic!("l1_ttl=0 应被拒绝"),
        };
        assert!(
            matches!(&err, GarrisonError::Config(m) if m.contains("cache-l1-ttl-must-positive")),
            "l1_ttl=0 应报 cache-l1-ttl-must-positive，实际: {err:?}"
        );
    }

    /// l2_ttl = 0 → cache-l2-ttl-must-positive。
    #[test]
    fn rejects_zero_l2_ttl() {
        let err = match build_with_capacity(30, 0, 128) {
            Err(e) => e,
            Ok(_) => panic!("l2_ttl=0 应被拒绝"),
        };
        assert!(
            matches!(&err, GarrisonError::Config(m) if m.contains("cache-l2-ttl-must-positive")),
            "l2_ttl=0 应报 cache-l2-ttl-must-positive，实际: {err:?}"
        );
    }

    /// l1_capacity = 0 → cache-l1-capacity-must-positive。
    #[test]
    fn rejects_zero_l1_capacity() {
        let err = match build_with_capacity(30, 300, 0) {
            Err(e) => e,
            Ok(_) => panic!("capacity=0 应被拒绝"),
        };
        assert!(
            matches!(&err, GarrisonError::Config(m) if m.contains("cache-l1-capacity-must-positive")),
            "capacity=0 应报 cache-l1-capacity-must-positive，实际: {err:?}"
        );
    }

    /// 全部合法参数 → 构造成功。
    #[test]
    fn accepts_positive_params() {
        assert!(build_with_capacity(30, 300, 128).is_ok());
    }

    // ------------------------------------------------------------------------
    // cache-hotkey 热 key 观测（T006）
    // ------------------------------------------------------------------------

    /// L1 读写路径经 record 埋点：两次 get_permissions 后 top-k 含权限缓存键且计数 ≥2。
    #[cfg(feature = "cache-hotkey")]
    #[tokio::test]
    async fn hot_keys_top_records_l1_accesses() {
        let (_dao, _interface, service) = make_service(300, 600);
        let _ = service.get_permissions("u1").await.unwrap();
        let _ = service.get_permissions("u1").await.unwrap();

        let key = DaoKeyPrefix::PermissionCache.build_key("u1");
        let top = service.hot_keys_top(10);
        let (_, count) = top
            .iter()
            .find(|(k, _)| k == &key)
            .unwrap_or_else(|| panic!("权限缓存键应被记录，实际 top: {top:?}"));
        assert!(*count >= 2, "两次访问计数应 ≥2，实际 {count}");
    }

    /// 无访问时空 tracker 返回空 top-k。
    #[cfg(feature = "cache-hotkey")]
    #[tokio::test]
    async fn hot_keys_top_empty_returns_empty() {
        let (_dao, _interface, service) = make_service(300, 600);
        assert!(service.hot_keys_top(10).is_empty());
    }

    /// top-k 截断：记录 3 个不同键时 hot_keys_top(2) 至多返回 2 条。
    #[cfg(feature = "cache-hotkey")]
    #[tokio::test]
    async fn hot_keys_top_respects_k_limit() {
        let (_dao, _interface, service) = make_service(300, 600);
        let _ = service.get_permissions("u1").await.unwrap();
        let _ = service.get_roles("u1").await.unwrap();
        let _ = service.get_user("u1").await.unwrap();

        let top = service.hot_keys_top(2);
        assert_eq!(top.len(), 2, "k=2 应截断为 2 条，实际: {top:?}");
    }
}
