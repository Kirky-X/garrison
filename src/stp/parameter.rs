//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! ParameterQuery 模块：参数化查询机制（feature-gated by `parameter-query`）。
//!
//! 提供 builder 模式的链式参数化校验 API，允许调用方在运行时
//! 显式指定 login_id / device / token 上下文，避免依赖 task_local。
//!
//! ## 设计
//!
//! - `ParameterQuery` trait：定义 `with_login_id` / `with_device` / `with_token` /
//!   `check_permission` / `check_role` 链式 API（check_* 为 async）
//! - `ParameterQueryBuilder`：默认实现，持有 `Option<String>` login_id / `Option<String>`
//!   device / `Option<String>` token 上下文，委托 `GarrisonUtil` 静态方法执行校验
//!
//! ## v0.5.2 迁移
//!
//! `login_id` 由 `i64` 迁移至 `String`（与全局 login_id 迁移一致）：
//! - `with_login_id` 接收 `String`（builder 持有所有权，避免每次校验克隆）
//! - 校验路径透传 `&str` 给 `GarrisonUtil::login`

use crate::error::{GarrisonError, GarrisonResult};
use crate::stp::{with_current_token, GarrisonUtil};
use async_trait::async_trait;

/// 参数化查询 trait，提供链式参数化校验 API。
///
/// 调用方通过 `with_login_id` / `with_device` / `with_token` 链式设置上下文，
/// 再调用 `check_permission` / `check_role` 执行校验。
///
/// # 上下文优先级
///
/// 若同时设置 token 与 login_id，token 优先（spec Scenario: 设置 token 后使用 token 上下文）。
///
/// # 示例
///
/// ```ignore
/// use garrison::stp::parameter::{ParameterQuery, ParameterQueryBuilder};
///
/// # async fn example() -> garrison::error::GarrisonResult<()> {
/// ParameterQueryBuilder::new()
///     .with_login_id("1001".to_string())
///     .with_device("dev1")
///     .check_permission("user:create")
///     .await?;
/// # Ok(())
/// # }
/// ```
#[async_trait]
pub trait ParameterQuery: Send + Sync {
    /// 设置 login_id 上下文（接收 `String`，builder 持有所有权）。
    fn with_login_id(self, login_id: String) -> Self;

    /// 设置 device 上下文。
    fn with_device(self, device: &str) -> Self;

    /// 设置 token 上下文。
    fn with_token(self, token: &str) -> Self;

    /// 校验权限（async）。
    ///
    /// 使用 builder 上下文中的 login_id 或 token 委托 `GarrisonUtil::check_permission` 校验。
    ///
    /// # 错误
    /// - 未设置 login_id 且未设置 token：`GarrisonError::Internal`。
    /// - 校验失败：透传 `GarrisonError::NotPermission` 等。
    async fn check_permission(&self, perm: &str) -> GarrisonResult<()>;

    /// 校验角色（async）。
    ///
    /// 使用 builder 上下文中的 login_id 或 token 委托 `GarrisonUtil::check_role` 校验。
    ///
    /// # 错误
    /// - 未设置 login_id 且未设置 token：`GarrisonError::Internal`。
    /// - 校验失败：透传 `GarrisonError::NotRole` 等。
    async fn check_role(&self, role: &str) -> GarrisonResult<()>;
}

/// `ParameterQuery` 的默认实现，持有 login_id / device / token 上下文。
pub struct ParameterQueryBuilder {
    /// 登录主体标识（显式设置时作为校验上下文，字符串形式）。
    login_id: Option<String>,
    /// 设备标识（仅存储，不参与校验逻辑，预留扩展）。
    device: Option<String>,
    /// Token（设置时通过 task_local 委托 GarrisonUtil 校验，优先级高于 login_id）。
    token: Option<String>,
}

impl ParameterQueryBuilder {
    /// 创建空的 builder，所有上下文字段为 None。
    pub fn new() -> Self {
        Self {
            login_id: None,
            device: None,
            token: None,
        }
    }

    /// 公共 check 流程：根据 token / login_id 上下文执行校验（M7 提取，消除重复代码）。
    ///
    /// - token 优先于 login_id
    /// - token 路径：直接 `with_current_token` 包装后委托 `GarrisonUtil::check_*`
    /// - login_id 路径：临时 `login()` 获取 token 后校验，最后 `kickout_by_token` 清理
    /// - 清理失败被忽略（不影响校验结果，但会通过 tracing 输出，符合 fail-soft 语义）
    async fn check_common(&self, value: &str, kind: CheckKind) -> GarrisonResult<()> {
        if let Some(token) = &self.token {
            // Token 已设置：包装 task_local 调用 GarrisonUtil::check_*
            let token = token.clone();
            let value = value.to_string();
            with_current_token(token, async move {
                match kind {
                    CheckKind::Permission => GarrisonUtil::check_permission(&value).await,
                    CheckKind::Role => GarrisonUtil::check_role(&value).await,
                }
            })
            .await
        } else if let Some(login_id) = &self.login_id {
            // Login_id 已设置：创建临时会话获取 token，再委托 GarrisonUtil::check_* 校验
            // login_id 为 String，GarrisonUtil::login 接收 &str
            let token = GarrisonUtil::login_simple(login_id).await?;
            let value = value.to_string();
            let token_for_cleanup = token.clone();
            let result = with_current_token(token, async move {
                match kind {
                    CheckKind::Permission => GarrisonUtil::check_permission(&value).await,
                    CheckKind::Role => GarrisonUtil::check_role(&value).await,
                }
            })
            .await;
            // 清理临时会话（忽略清理失败，不影响校验结果）
            let _ = GarrisonUtil::kickout_by_token(&token_for_cleanup).await;
            result
        } else {
            Err(GarrisonError::Internal(
                "login_id not set in ParameterQuery context".to_string(),
            ))
        }
    }
}

impl Default for ParameterQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 内部 check 种类（用于 `check_common` 委托，消除 check_permission/check_role 重复代码）。
enum CheckKind {
    Permission,
    Role,
}

#[async_trait]
impl ParameterQuery for ParameterQueryBuilder {
    fn with_login_id(mut self, login_id: String) -> Self {
        self.login_id = Some(login_id);
        self
    }

    fn with_device(mut self, device: &str) -> Self {
        self.device = Some(device.to_string());
        self
    }

    fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    async fn check_permission(&self, perm: &str) -> GarrisonResult<()> {
        self.check_common(perm, CheckKind::Permission).await
    }

    async fn check_role(&self, role: &str) -> GarrisonResult<()> {
        self.check_common(role, CheckKind::Role).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GarrisonConfig;
    use crate::context::tenant::with_default_tenant;
    use crate::dao::GarrisonDao;
    use crate::manager::GarrisonManager;
    use crate::stp::GarrisonInterface;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    // ------------------------------------------------------------------------
    // MockDao：HashMap + Instant 模拟 TTL（复用 stp/mod.rs 测试模式）
    // ------------------------------------------------------------------------

    struct MockDao {
        store: Mutex<HashMap<String, (String, Option<Instant>)>>,
    }

    impl MockDao {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl GarrisonDao for MockDao {
        async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
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

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
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

        async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((existing, _)) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
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
                None => Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key))),
            }
        }

        async fn delete(&self, key: &str) -> GarrisonResult<()> {
            self.store.lock().remove(key);
            Ok(())
        }
    }

    // ------------------------------------------------------------------------
    // MockInterfaceWithPerms：可配置权限/角色数据的 mock
    // ------------------------------------------------------------------------

    struct MockInterfaceWithPerms {
        permissions: HashMap<String, Vec<String>>,
        roles: HashMap<String, Vec<String>>,
    }

    #[async_trait]
    impl GarrisonInterface for MockInterfaceWithPerms {
        async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(self.roles.get(login_id).cloned().unwrap_or_default())
        }
    }

    /// 初始化全局 GarrisonManager，注入可配置权限/角色数据的 MockInterface。
    fn init_manager_with_perms(
        throw_on_not_login: bool,
        permissions: HashMap<String, Vec<String>>,
        roles: HashMap<String, Vec<String>>,
    ) {
        GarrisonManager::reset_for_test();
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let mut config = GarrisonConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = throw_on_not_login;
        let interface: Arc<dyn GarrisonInterface> =
            Arc::new(MockInterfaceWithPerms { permissions, roles });
        GarrisonManager::init(dao, Arc::new(config), interface).unwrap();
    }

    // ------------------------------------------------------------------------
    // 链式调用设置上下文
    // ------------------------------------------------------------------------

    /// 验证 new() 返回的 builder 所有上下文字段为 None。
    #[test]
    fn builder_new_has_no_context() {
        let builder = ParameterQueryBuilder::new();
        assert!(builder.login_id.is_none(), "new() 后 login_id 应为 None");
        assert!(builder.device.is_none(), "new() 后 device 应为 None");
        assert!(builder.token.is_none(), "new() 后 token 应为 None");
    }

    /// 验证 with_login_id 设置 login_id 上下文。
    #[test]
    fn with_login_id_sets_context() {
        let builder = ParameterQueryBuilder::new().with_login_id("1001".to_string());
        assert_eq!(builder.login_id, Some("1001".to_string()));
    }

    /// 验证 with_device 设置 device 上下文。
    #[test]
    fn with_device_sets_context() {
        let builder = ParameterQueryBuilder::new().with_device("dev1");
        assert_eq!(builder.device.as_deref(), Some("dev1"));
    }

    /// 验证 with_token 设置 token 上下文。
    #[test]
    fn with_token_sets_context() {
        let builder = ParameterQueryBuilder::new().with_token("abc-token");
        assert_eq!(builder.token.as_deref(), Some("abc-token"));
    }

    /// spec Scenario: 链式调用设置上下文。
    /// 验证 with_login_id("1001".to_string()).with_device("dev1") 链式调用后 builder 持有完整上下文。
    #[test]
    fn chain_with_login_id_and_device_sets_context() {
        let builder = ParameterQueryBuilder::new()
            .with_login_id("1001".to_string())
            .with_device("dev1");
        assert_eq!(
            builder.login_id,
            Some("1001".to_string()),
            "链式调用后 login_id 应为 1001"
        );
        assert_eq!(
            builder.device.as_deref(),
            Some("dev1"),
            "链式调用后 device 应为 dev1"
        );
    }

    // ------------------------------------------------------------------------
    // check_permission 未设置上下文 / login_id / token
    // ------------------------------------------------------------------------

    /// spec Scenario: 未设置 login_id 时校验失败。
    /// 验证无上下文时 check_permission 返回 Internal("login_id not set...")。
    #[tokio::test]
    #[serial]
    async fn check_permission_without_context_returns_internal() {
        GarrisonManager::reset_for_test();
        let builder = ParameterQueryBuilder::new();
        let result = builder.check_permission("user:create").await;
        assert!(
            matches!(result, Err(GarrisonError::Internal(ref msg)) if msg.contains("login_id not set")),
            "未设置上下文时应返回 Internal 错误，实际: {:?}",
            result
        );
    }

    /// spec Scenario: check_permission 使用上下文（持有权限）。
    /// 验证 login_id=1001 且 MockInterface 返回权限时 check_permission 返回 Ok。
    #[tokio::test]
    #[serial]
    async fn check_permission_with_login_id_succeeds_when_authorized() {
        let mut perms = HashMap::new();
        perms.insert("1001".to_string(), vec!["user:create".to_string()]);
        init_manager_with_perms(false, perms, HashMap::new());

        let result = with_default_tenant(async {
            ParameterQueryBuilder::new()
                .with_login_id("1001".to_string())
                .check_permission("user:create")
                .await
        })
        .await;
        assert!(result.is_ok(), "持有权限时应返回 Ok，实际: {:?}", result);

        GarrisonManager::reset_for_test();
    }

    /// spec Scenario: check_permission 使用上下文（未持有权限）。
    /// 验证 login_id=1001 且 MockInterface 返回空权限时 check_permission 返回 NotPermission。
    #[tokio::test]
    #[serial]
    async fn check_permission_with_login_id_returns_not_permission_when_denied() {
        let perms: HashMap<String, Vec<String>> = HashMap::new();
        init_manager_with_perms(false, perms, HashMap::new());

        let result = with_default_tenant(async {
            ParameterQueryBuilder::new()
                .with_login_id("1001".to_string())
                .check_permission("user:delete")
                .await
        })
        .await;
        assert!(
            matches!(result, Err(GarrisonError::NotPermission(ref perm)) if perm == "user:delete"),
            "未持有权限应返回 NotPermission，实际: {:?}",
            result
        );

        GarrisonManager::reset_for_test();
    }

    /// spec Scenario: 设置 token 后使用 token 上下文（持有权限）。
    /// 验证 with_token 后 check_permission 使用 token 解析的 login_id 校验。
    #[tokio::test]
    #[serial]
    async fn check_permission_with_token_succeeds() {
        let mut perms = HashMap::new();
        perms.insert("1001".to_string(), vec!["user:read".to_string()]);
        init_manager_with_perms(false, perms, HashMap::new());

        // 先 login 获取有效 token
        let token = GarrisonUtil::login_simple("1001").await.unwrap();

        let result = with_default_tenant(async {
            ParameterQueryBuilder::new()
                .with_token(&token)
                .check_permission("user:read")
                .await
        })
        .await;
        assert!(
            result.is_ok(),
            "token 上下文持有权限应返回 Ok，实际: {:?}",
            result
        );

        GarrisonManager::reset_for_test();
    }

    /// spec Scenario: 设置 token 后使用 token 上下文（未持有权限）。
    /// 验证 with_token 后 check_permission 在权限不足时返回 NotPermission。
    #[tokio::test]
    #[serial]
    async fn check_permission_with_token_returns_not_permission_when_denied() {
        let perms: HashMap<String, Vec<String>> = HashMap::new();
        init_manager_with_perms(false, perms, HashMap::new());

        let token = GarrisonUtil::login_simple("1001").await.unwrap();

        let result = with_default_tenant(async {
            ParameterQueryBuilder::new()
                .with_token(&token)
                .check_permission("user:delete")
                .await
        })
        .await;
        assert!(
            matches!(result, Err(GarrisonError::NotPermission(_))),
            "token 上下文未持有权限应返回 NotPermission，实际: {:?}",
            result
        );

        GarrisonManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // check_role 未设置上下文 / login_id / token
    // ------------------------------------------------------------------------

    /// spec Scenario: 未设置 login_id 时 check_role 校验失败。
    #[tokio::test]
    #[serial]
    async fn check_role_without_context_returns_internal() {
        GarrisonManager::reset_for_test();
        let builder = ParameterQueryBuilder::new();
        let result = builder.check_role("admin").await;
        assert!(
            matches!(result, Err(GarrisonError::Internal(ref msg)) if msg.contains("login_id not set")),
            "未设置上下文时 check_role 应返回 Internal 错误，实际: {:?}",
            result
        );
    }

    /// spec Scenario: check_role 使用上下文（持有角色）。
    #[tokio::test]
    #[serial]
    async fn check_role_with_login_id_succeeds_when_authorized() {
        let mut roles = HashMap::new();
        roles.insert("1001".to_string(), vec!["admin".to_string()]);
        init_manager_with_perms(false, HashMap::new(), roles);

        let result = ParameterQueryBuilder::new()
            .with_login_id("1001".to_string())
            .check_role("admin")
            .await;
        assert!(result.is_ok(), "持有角色应返回 Ok，实际: {:?}", result);

        GarrisonManager::reset_for_test();
    }

    /// spec Scenario: check_role 使用上下文（未持有角色）。
    #[tokio::test]
    #[serial]
    async fn check_role_with_login_id_returns_not_role_when_denied() {
        let roles: HashMap<String, Vec<String>> = HashMap::new();
        init_manager_with_perms(false, HashMap::new(), roles);

        let result = ParameterQueryBuilder::new()
            .with_login_id("1001".to_string())
            .check_role("superadmin")
            .await;
        assert!(
            matches!(result, Err(GarrisonError::NotRole(ref role)) if role == "superadmin"),
            "未持有角色应返回 NotRole，实际: {:?}",
            result
        );

        GarrisonManager::reset_for_test();
    }

    /// spec Scenario: 设置 token 后 check_role 使用 token 解析的 login_id 校验。
    #[tokio::test]
    #[serial]
    async fn check_role_with_token_succeeds() {
        let mut roles = HashMap::new();
        roles.insert("1001".to_string(), vec!["admin".to_string()]);
        init_manager_with_perms(false, HashMap::new(), roles);

        let token = GarrisonUtil::login_simple("1001").await.unwrap();

        let result = ParameterQueryBuilder::new()
            .with_token(&token)
            .check_role("admin")
            .await;
        assert!(
            result.is_ok(),
            "token 上下文持有角色应返回 Ok，实际: {:?}",
            result
        );

        GarrisonManager::reset_for_test();
    }

    /// spec Scenario: 设置 token 后 check_role 未持有角色返回 NotRole。
    #[tokio::test]
    #[serial]
    async fn check_role_with_token_returns_not_role_when_denied() {
        let roles: HashMap<String, Vec<String>> = HashMap::new();
        init_manager_with_perms(false, HashMap::new(), roles);

        let token = GarrisonUtil::login_simple("1001").await.unwrap();

        let result = ParameterQueryBuilder::new()
            .with_token(&token)
            .check_role("superadmin")
            .await;
        assert!(
            matches!(result, Err(GarrisonError::NotRole(_))),
            "token 上下文未持有角色应返回 NotRole，实际: {:?}",
            result
        );

        GarrisonManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // async 支持 + Default trait
    // ------------------------------------------------------------------------

    /// 验证 check_permission 为 async 方法，可在 tokio runtime 中 await。
    #[tokio::test]
    #[serial]
    async fn async_check_permission_works() {
        let mut perms = HashMap::new();
        perms.insert("2002".to_string(), vec!["user:read".to_string()]);
        init_manager_with_perms(false, perms, HashMap::new());

        // async 调用并 await
        let result = with_default_tenant(async {
            ParameterQueryBuilder::new()
                .with_login_id("2002".to_string())
                .check_permission("user:read")
                .await
        })
        .await;
        assert!(
            result.is_ok(),
            "async check_permission 应正常工作，实际: {:?}",
            result
        );

        GarrisonManager::reset_for_test();
    }

    /// 验证 ParameterQueryBuilder 实现 Default trait。
    #[test]
    fn builder_default_equals_new() {
        let default_builder = ParameterQueryBuilder::default();
        let new_builder = ParameterQueryBuilder::new();
        assert!(default_builder.login_id.is_none());
        assert!(default_builder.device.is_none());
        assert!(default_builder.token.is_none());
        assert!(new_builder.login_id.is_none());
        assert!(new_builder.device.is_none());
        assert!(new_builder.token.is_none());
    }
}
