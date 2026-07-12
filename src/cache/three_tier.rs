//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 三层缓存服务（L1 moka + L2 DAO + L3 interface）。
//!
//! # 架构
//!
//! - **L1（moka 内存缓存）**：进程内 LRU + TTL 缓存，TTL 较短（默认 30s），命中时不查询 L2/L3
//! - **L2（DAO 持久化缓存）**：通过 [`BulwarkDao`] set/get，TTL 较长（默认 300s），命中时回填 L1
//! - **L3（interface 回调）**：通过 [`BulwarkPermissionStrategy`] 的 `get_permission_list` /
//!   `get_role_list` / `get_user_info` 获取原始数据，命中时回填 L1 + L2
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
//! [`BulwarkDao`]: crate::dao::BulwarkDao
//! [`BulwarkPermissionStrategy`]: crate::strategy::BulwarkPermissionStrategy

use crate::constants::DaoKeyPrefix;
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::strategy::BulwarkPermissionStrategy;
use std::sync::Arc;
use std::time::Duration;

/// 三层缓存服务，提供权限/角色/用户信息的加速查询。
///
/// L1（moka 内存缓存）→ L2（DAO 持久化缓存）→ L3（interface 回调）三层递进查询，
/// 命中上层时不查询下层，未命中下层时回填上层。
pub struct UserCacheService {
    /// L1 内存缓存（moka future::Cache，支持 per-entry TTL + LRU 淘汰）
    l1: moka::future::Cache<String, String>,
    /// L2 持久化缓存（通过 BulwarkDao 抽象，支持 oxcache / dbnexus 等后端）
    dao: Arc<dyn BulwarkDao>,
    /// L3 数据源（通过 BulwarkPermissionStrategy 回调获取原始数据）
    interface: Arc<dyn BulwarkPermissionStrategy>,
    /// L1 缓存 TTL（秒），用于诊断与日志
    l1_ttl_secs: u64,
    /// L2 缓存 TTL（秒），写入 DAO 时使用
    l2_ttl_secs: u64,
}

impl UserCacheService {
    /// 创建三层缓存服务实例。
    ///
    /// # 参数
    /// - `dao`: L2 持久化缓存后端（`Arc<dyn BulwarkDao>`）。
    /// - `interface`: L3 数据源（`Arc<dyn BulwarkPermissionStrategy>`）。
    /// - `l1_ttl_secs`: L1 内存缓存 TTL（秒，必须 > 0）。
    /// - `l2_ttl_secs`: L2 DAO 缓存 TTL（秒，必须 > 0）。
    /// - `l1_capacity`: L1 缓存最大容量（条目数，必须 > 0）。
    ///
    /// # 返回
    /// 已初始化的 `UserCacheService` 实例。
    pub fn new(
        dao: Arc<dyn BulwarkDao>,
        interface: Arc<dyn BulwarkPermissionStrategy>,
        l1_ttl_secs: u64,
        l2_ttl_secs: u64,
        l1_capacity: u64,
    ) -> Self {
        let l1 = moka::future::Cache::builder()
            .time_to_live(Duration::from_secs(l1_ttl_secs))
            .max_capacity(l1_capacity)
            .build();
        Self {
            l1,
            dao,
            interface,
            l1_ttl_secs,
            l2_ttl_secs,
        }
    }

    /// 返回 L1 缓存 TTL（秒）。
    pub fn l1_ttl_secs(&self) -> u64 {
        self.l1_ttl_secs
    }

    /// 返回 L2 缓存 TTL（秒）。
    pub fn l2_ttl_secs(&self) -> u64 {
        self.l2_ttl_secs
    }

    /// 获取主体的权限列表（三层缓存查询）。
    ///
    /// 缓存键：`perm:cache:{login_id}`
    ///
    /// # 查询流程
    /// 1. L1 命中 → 反序列化返回（不查询 L2/L3）
    /// 2. L1 未命中 → L2 命中 → 回填 L1 → 返回
    /// 3. L1+L2 未命中 → L3 查询 → 回填 L1+L2 → 返回
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 错误
    /// - L2 DAO 查询失败：透传 `BulwarkError`。
    /// - L3 interface 回调失败：透传 `BulwarkError`。
    /// - 缓存反序列化失败：`BulwarkError::Internal`。
    pub async fn get_permissions(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        let key = DaoKeyPrefix::PermissionCache.build_key(login_id);

        // L1 check
        if let Some(cached) = self.l1.get(&key).await {
            let perms: Vec<String> = serde_json::from_str(&cached)
                .map_err(|e| BulwarkError::Internal(format!("L1 权限缓存反序列化失败: {}", e)))?;
            return Ok(perms);
        }

        // L2 check
        if let Some(cached) = self.dao.get(&key).await? {
            // Backfill L1
            self.l1.insert(key.clone(), cached.clone()).await;
            let perms: Vec<String> = serde_json::from_str(&cached)
                .map_err(|e| BulwarkError::Internal(format!("L2 权限缓存反序列化失败: {}", e)))?;
            return Ok(perms);
        }

        // L3 query
        let perms = self.interface.get_permission_list(login_id).await?;
        let serialized = serde_json::to_string(&perms)
            .map_err(|e| BulwarkError::Internal(format!("权限列表序列化失败: {}", e)))?;
        // Backfill L1 + L2
        self.l1.insert(key.clone(), serialized.clone()).await;
        self.dao.set(&key, &serialized, self.l2_ttl_secs).await?;

        Ok(perms)
    }

    /// 获取主体的角色列表（三层缓存查询）。
    ///
    /// 缓存键：`role:cache:{login_id}`
    ///
    /// # 查询流程
    /// 1. L1 命中 → 反序列化返回（不查询 L2/L3）
    /// 2. L1 未命中 → L2 命中 → 回填 L1 → 返回
    /// 3. L1+L2 未命中 → L3 查询 → 回填 L1+L2 → 返回
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 错误
    /// - L2 DAO 查询失败：透传 `BulwarkError`。
    /// - L3 interface 回调失败：透传 `BulwarkError`。
    /// - 缓存反序列化失败：`BulwarkError::Internal`。
    pub async fn get_roles(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        let key = DaoKeyPrefix::RoleCache.build_key(login_id);

        // L1 check
        if let Some(cached) = self.l1.get(&key).await {
            let roles: Vec<String> = serde_json::from_str(&cached)
                .map_err(|e| BulwarkError::Internal(format!("L1 角色缓存反序列化失败: {}", e)))?;
            return Ok(roles);
        }

        // L2 check
        if let Some(cached) = self.dao.get(&key).await? {
            // Backfill L1
            self.l1.insert(key.clone(), cached.clone()).await;
            let roles: Vec<String> = serde_json::from_str(&cached)
                .map_err(|e| BulwarkError::Internal(format!("L2 角色缓存反序列化失败: {}", e)))?;
            return Ok(roles);
        }

        // L3 query
        let roles = self.interface.get_role_list(login_id).await?;
        let serialized = serde_json::to_string(&roles)
            .map_err(|e| BulwarkError::Internal(format!("角色列表序列化失败: {}", e)))?;
        // Backfill L1 + L2
        self.l1.insert(key.clone(), serialized.clone()).await;
        self.dao.set(&key, &serialized, self.l2_ttl_secs).await?;

        Ok(roles)
    }

    /// 获取用户基本信息（三层缓存查询）。
    ///
    /// 缓存键：`user:cache:{login_id}`
    ///
    /// # 查询流程
    /// 1. L1 命中 → 返回 `Some(value)`（不查询 L2/L3）
    /// 2. L1 未命中 → L2 命中 → 回填 L1 → 返回 `Some(value)`
    /// 3. L1+L2 未命中 → L3 查询 → `Some` 时回填 L1+L2 → 返回；`None` 时不缓存
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// - `Ok(Some(user_info))`: 用户信息字符串。
    /// - `Ok(None)`: 用户不存在或 interface 未实现 `get_user_info`。
    ///
    /// # 错误
    /// - L2 DAO 查询失败：透传 `BulwarkError`。
    /// - L3 interface 回调失败：透传 `BulwarkError`。
    pub async fn get_user(&self, login_id: &str) -> BulwarkResult<Option<String>> {
        let key = DaoKeyPrefix::UserCache.build_key(login_id);

        // L1 check
        if let Some(cached) = self.l1.get(&key).await {
            return Ok(Some(cached));
        }

        // L2 check
        if let Some(cached) = self.dao.get(&key).await? {
            // Backfill L1
            self.l1.insert(key.clone(), cached.clone()).await;
            return Ok(Some(cached));
        }

        // L3 query
        let user_info = self.interface.get_user_info(login_id).await?;
        if let Some(ref info) = user_info {
            // Backfill L1 + L2 (only when Some, None is not cached)
            self.l1.insert(key.clone(), info.clone()).await;
            self.dao.set(&key, info, self.l2_ttl_secs).await?;
        }
        Ok(user_info)
    }

    /// 失效指定主体的所有缓存（权限/角色/用户）。
    ///
    /// 同时清除 L1（moka）和 L2（DAO）中 `login_id` 对应的三类缓存键。
    /// 用于登出、权限变更等场景。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 错误
    /// - L2 DAO 删除失败：透传 `BulwarkError`。
    pub async fn invalidate(&self, login_id: &str) -> BulwarkResult<()> {
        let perm_key = DaoKeyPrefix::PermissionCache.build_key(login_id);
        let role_key = DaoKeyPrefix::RoleCache.build_key(login_id);
        let user_key = DaoKeyPrefix::UserCache.build_key(login_id);

        // Invalidate L1
        self.l1.invalidate(&perm_key).await;
        self.l1.invalidate(&role_key).await;
        self.l1.invalidate(&user_key).await;

        // Invalidate L2
        self.dao.delete(&perm_key).await?;
        self.dao.delete(&role_key).await?;
        self.dao.delete(&user_key).await?;

        Ok(())
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::BulwarkDao;
    use crate::error::BulwarkResult;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
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

        /// 直接写入 store（用于测试预填充 L2），不计数。
        fn insert_direct(&self, key: &str, value: &str) {
            self.store.lock().insert(key.to_string(), value.to_string());
        }

        /// 检查 store 中是否存在指定 key。
        fn contains_key(&self, key: &str) -> bool {
            self.store.lock().contains_key(key)
        }
    }

    #[async_trait]
    impl BulwarkDao for CountingMockDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            self.get_count.fetch_add(1, Ordering::SeqCst);
            self.get_keys.lock().push(key.to_string());
            Ok(self.store.lock().get(key).cloned())
        }

        async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
            self.set_count.fetch_add(1, Ordering::SeqCst);
            self.set_keys.lock().push(key.to_string());
            self.store.lock().insert(key.to_string(), value.to_string());
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            self.store.lock().insert(key.to_string(), value.to_string());
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.delete_count.fetch_add(1, Ordering::SeqCst);
            self.delete_keys.lock().push(key.to_string());
            self.store.lock().remove(key);
            Ok(())
        }
    }

    // ------------------------------------------------------------------------
    // Mock Interface：实现 BulwarkPermissionStrategy，记录调用次数
    // ------------------------------------------------------------------------

    /// 测试用 Mock Interface，记录 get_permission_list / get_role_list / get_user_info 调用次数。
    struct CountingMockInterface {
        permissions: Mutex<HashMap<String, Vec<String>>>,
        roles: Mutex<HashMap<String, Vec<String>>>,
        user_info: Mutex<HashMap<String, Option<String>>>,
        perm_count: AtomicU32,
        role_count: AtomicU32,
        user_count: AtomicU32,
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
    }

    #[async_trait]
    impl BulwarkPermissionStrategy for CountingMockInterface {
        async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
            self.perm_count.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .permissions
                .lock()
                .get(login_id)
                .cloned()
                .unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
            self.role_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.roles.lock().get(login_id).cloned().unwrap_or_default())
        }

        async fn check_permission(
            &self,
            _login_id: &str,
            _permission: &str,
        ) -> BulwarkResult<bool> {
            Ok(false)
        }

        async fn check_role(&self, _login_id: &str, _role: &str) -> BulwarkResult<bool> {
            Ok(false)
        }

        async fn check_role_any(&self, _login_id: &str, _roles: &[&str]) -> BulwarkResult<bool> {
            Ok(false)
        }

        async fn check_role_all(&self, _login_id: &str, _roles: &[&str]) -> BulwarkResult<bool> {
            Ok(false)
        }

        async fn get_user_info(&self, login_id: &str) -> BulwarkResult<Option<String>> {
            self.user_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.user_info.lock().get(login_id).cloned().unwrap_or(None))
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
            dao.clone() as Arc<dyn BulwarkDao>,
            interface.clone() as Arc<dyn BulwarkPermissionStrategy>,
            l1_ttl_secs,
            l2_ttl_secs,
            10_000,
        );
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

    /// T1: L1 命中时不查询 L2/L3。
    #[tokio::test]
    async fn l1_hit_does_not_query_l2_l3() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("1001", vec!["user:read".to_string()]);

        // 第一次调用：L1+L2 miss → L3 查询 → 回填 L1+L2
        let perms1 = service.get_permissions("1001").await.unwrap();
        assert_eq!(perms1, vec!["user:read".to_string()]);
        assert_eq!(interface.perm_count(), 1, "第一次应查询 L3");
        assert_eq!(dao.get_count(), 1, "第一次应查询 L2");

        // 第二次调用：L1 hit → 不查询 L2/L3
        let perms2 = service.get_permissions("1001").await.unwrap();
        assert_eq!(perms2, vec!["user:read".to_string()]);
        assert_eq!(interface.perm_count(), 1, "L1 命中不应查询 L3");
        assert_eq!(dao.get_count(), 1, "L1 命中不应查询 L2");
    }

    /// T2: L1 未命中 L2 命中时回填 L1。
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
        assert_eq!(dao.get_count(), 1, "应查询 L2 一次");

        // 第二次调用：L1 hit（已被回填）→ 不查询 L2/L3
        let perms2 = service.get_permissions("2001").await.unwrap();
        assert_eq!(perms2, vec!["admin:read".to_string()]);
        assert_eq!(dao.get_count(), 1, "L1 回填后不应再查询 L2");
        assert_eq!(interface.perm_count(), 0, "不应查询 L3");
    }

    /// T3: L1+L2 未命中走 L3 回填 L1+L2。
    #[tokio::test]
    async fn l1_l2_miss_calls_l3_backfills_both() {
        let (dao, interface, service) = make_default_service();
        interface.set_permissions("3001", vec!["data:write".to_string()]);

        // 第一次调用：L1+L2 miss → L3 查询 → 回填 L1+L2
        let perms = service.get_permissions("3001").await.unwrap();
        assert_eq!(perms, vec!["data:write".to_string()]);
        assert_eq!(interface.perm_count(), 1, "应查询 L3 一次");
        assert_eq!(dao.get_count(), 1, "应查询 L2 一次");
        assert_eq!(dao.set_count(), 1, "应回填 L2 一次");

        // 验证 L2 已被回填
        assert!(dao.contains_key("perm:cache:3001"), "L2 应已被回填");

        // 验证 L1 已被回填（第二次调用不走 L3）
        let perms2 = service.get_permissions("3001").await.unwrap();
        assert_eq!(perms2, vec!["data:write".to_string()]);
        assert_eq!(interface.perm_count(), 1, "L1 回填后不应再查询 L3");
    }

    /// T4: invalidate 失效 L1。
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

    /// T5: invalidate 失效 L2。
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

    /// T6: get_permissions 缓存键格式 `perm:cache:{login_id}`。
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

    /// T7: get_roles 缓存键格式 `role:cache:{login_id}`。
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

    /// T8: get_user 缓存键格式 `user:cache:{login_id}`。
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

    /// T9: 用户不存在时返回 Ok(None) 且不缓存。
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

    /// T10: TTL 过期后 L1 失效（用短 TTL 测试）。
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

    /// T11: 不存在的 key 失效不报错（幂等）。
    #[tokio::test]
    async fn invalidate_nonexistent_key_is_idempotent() {
        let (_dao, _interface, service) = make_default_service();

        // invalidate 一个从未缓存过的 login_id，不应报错
        let result = service.invalidate("nonexistent_user").await;
        assert!(result.is_ok(), "invalidate 不存在的 key 应幂等返回 Ok(())");
    }

    /// T12: 并发回填不冲突。
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_backfill_no_conflict() {
        let dao = Arc::new(CountingMockDao::new());
        let interface = Arc::new(CountingMockInterface::new());
        interface.set_permissions("11001", vec!["perm:e".to_string()]);

        let service = Arc::new(UserCacheService::new(
            dao.clone() as Arc<dyn BulwarkDao>,
            interface.clone() as Arc<dyn BulwarkPermissionStrategy>,
            30,
            300,
            10_000,
        ));

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
    // 3 个集成测试（T014: 失效场景验证）
    // ------------------------------------------------------------------------

    /// I1: 登出后缓存失效 — invalidate 后再次查询走 L3。
    ///
    /// 注：logout 集成到 stp/session.rs 需修改 BulwarkManager::init，
    /// 留到 Phase 6 统一接线。此处验证 invalidate 的行为。
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

        // invalidate 后返回新权限
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
            2,
            "应查询 L2 两次（首次填充 miss + 登出后再次查询 miss）"
        );
    }

    // ------------------------------------------------------------------------
    // 配置项默认值测试
    // ------------------------------------------------------------------------

    /// 验证 three-tier-cache feature 启用时 default_config 包含正确的缓存配置默认值。
    #[test]
    fn default_config_includes_cache_settings() {
        let config = crate::config::BulwarkConfig::default_config();
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
        let mut config = crate::config::BulwarkConfig::default_config();
        config.l1_cache_ttl_secs = 0;
        let result = config.validate();
        assert!(result.is_err(), "l1_cache_ttl_secs=0 应校验失败");
    }

    /// 验证 l2_cache_ttl_secs = 0 时 validate 返回 Err。
    #[test]
    fn validate_rejects_zero_l2_cache_ttl() {
        let mut config = crate::config::BulwarkConfig::default_config();
        config.l2_cache_ttl_secs = 0;
        let result = config.validate();
        assert!(result.is_err(), "l2_cache_ttl_secs=0 应校验失败");
    }

    /// 验证 l1_cache_capacity = 0 时 validate 返回 Err。
    #[test]
    fn validate_rejects_zero_l1_cache_capacity() {
        let mut config = crate::config::BulwarkConfig::default_config();
        config.l1_cache_capacity = 0;
        let result = config.validate();
        assert!(result.is_err(), "l1_cache_capacity=0 应校验失败");
    }
}
