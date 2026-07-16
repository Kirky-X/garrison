//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 显式 Manager API。
//!
//! 提供不依赖全局单例的 [`Manager`] struct，通过 `new(logic)` 显式注入 [`BulwarkLogicDefault`]，
//! 便于测试隔离与多实例场景。
//!
//! # 与 [`BulwarkManager`](crate::manager::BulwarkManager) 的区别
//!
//! | 维度 | `BulwarkManager` | `Manager` |
//! |:---|:---|:---|
//! | 依赖注入 | 全局单例，`init()` 静态注入 | 实例化，`new(logic)` 构造注入 |
//! | 生命周期 | 进程级，`Lazy` 懒加载 | 实例级，Drop 时释放 `Arc` |
//! | API 风格 | 静态方法（`BulwarkUtil::login`） | 实例方法（`manager.authorize`） |
//! | 适用场景 | 生产单例（向后兼容） | 测试隔离 / 多实例 / 显式 DI |
//!
//! # `PermissionLogic` trait 与 `Manager` API 的差异
//!
//! `PermissionLogic` trait 的 `check_permission` 签名为
//! `(&self, permission: &str) -> BulwarkResult<()>`（基于 task_local token 上下文获取 login_id），
//! 而 `Manager::check_permission` 要求 `(&self, login_id: &str, permission: &str) -> BulwarkResult<bool>`。
//!
//! 两者无法直接匹配，且 `PermissionLogic` trait 不暴露内部 `BulwarkInterface` / `firewall`。
//! 本模块采用**委托策略**：`Manager` 内部调用 `PermissionLogic::check_permission(permission)`，
//! 将 `Ok(())` 映射为 `true`、`Err(NotPermission)` 映射为 `false`，其他错误透传。
//! `login_id` 参数保留以匹配 API 契约（与 `BulwarkUtil` 同样基于 task_local 鉴权上下文）。

use std::sync::Arc;

use crate::core::permission::{AuthRequest, Decision, DecisionReason};
use crate::error::{BulwarkError, BulwarkResult};
use crate::stp::{BulwarkLogicDefault, PermissionLogic};

/// 显式依赖注入入口。
///
/// 与 [`BulwarkManager`](crate::manager::BulwarkManager) 的区别：
/// - `BulwarkManager`：全局单例，通过 `init()` 初始化，静态 API
/// - `Manager`：实例化注入，构造时传入 `Arc<BulwarkLogicDefault>`，便于测试与多实例
///
/// # 生命周期独立
///
/// `Manager` 持有 `Arc<BulwarkLogicDefault>` 的引用计数副本，Drop 时仅减少引用计数，
/// 不影响 `BulwarkManager` 全局单例（两者共享同一 `BulwarkLogicDefault` 实例时互不干扰）。
///
/// # 鉴权上下文
///
/// `authorize` / `check_permission` 委托 [`PermissionLogic::check_permission`]，
/// 该方法基于 task_local token 上下文获取当前 `login_id`（与 `BulwarkUtil` 一致）。
/// 调用前需通过 web 中间件或 [`with_current_token`](crate::stp::with_current_token) 设置 task_local。
pub struct Manager {
    logic: Arc<BulwarkLogicDefault>,
}

impl Manager {
    /// 创建 Manager 实例，注入 `BulwarkLogicDefault` 实现。
    ///
    /// # 参数
    /// - `logic`: `BulwarkLogicDefault` 实现的 `Arc` 引用（可与 `BulwarkManager::logic()` 共享同一实例）。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use bulwark::manager::explicit::Manager;
    /// use bulwark::prelude::*;
    ///
    /// let logic = BulwarkManager::logic().unwrap();
    /// let manager = Manager::new(logic);
    /// ```
    pub fn new(logic: Arc<BulwarkLogicDefault>) -> Self {
        Self { logic }
    }

    /// 鉴权决策：基于 [`AuthRequest`] 返回完整 [`Decision`]。
    ///
    /// 内部委托 [`PermissionLogic::check_permission`]：
    /// - `Ok(())` → `Decision::allow()`（`ExplicitAllow`）
    /// - `Err(NotPermission)` → `Decision::deny(NoMatchingPermission)`
    /// - 其他错误（未登录 / DAO 故障等）透传
    ///
    /// # trace_id
    ///
    /// `Decision.trace_id` 非空（UUID v7，时间有序）。
    /// 每次调用 `authorize` 都生成新的 UUID v7，便于跨服务追踪与审计关联。
    ///
    /// # 鉴权上下文
    ///
    /// 实际 `login_id` 由 task_local token 上下文决定（与 `BulwarkUtil` 一致），
    /// `req.login_id` 保留在 API 契约中用于未来扩展（如直接 login_id 鉴权路径）。
    ///
    /// # 错误
    ///
    /// - 未登录且 `throw_on_not_login=true`：透传 `BulwarkError::NotLogin`。
    /// - DAO 故障等：透传对应 `BulwarkError`。
    /// - "未持有权限"不是错误，返回 `Ok(Decision { allowed: false, .. })`。
    pub async fn authorize(&self, req: &AuthRequest) -> BulwarkResult<Decision> {
        // trace_id 非空 UUID v7（时间有序）
        let trace_id = Some(uuid::Uuid::now_v7().to_string());
        match self.logic.check_permission(&req.action).await {
            Ok(()) => Ok(Decision {
                trace_id,
                ..Decision::allow()
            }),
            Err(BulwarkError::NotPermission(_)) => Ok(Decision {
                trace_id,
                ..Decision::deny(DecisionReason::NoMatchingPermission)
            }),
            Err(e) => Err(e),
        }
    }

    /// 校验主体是否持有指定权限，返回 `bool`。
    ///
    /// 内部委托 [`PermissionLogic::check_permission`]：
    /// - `Ok(())` → `Ok(true)`
    /// - `Err(NotPermission)` → `Ok(false)`
    /// - 其他错误透传
    ///
    /// # 鉴权上下文
    ///
    /// 实际 `login_id` 由 task_local token 上下文决定（与 `BulwarkUtil` 一致）。
    /// `login_id` 参数保留以匹配 API 契约，便于未来支持直接 login_id 鉴权。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（保留用于 API 契约，实际鉴权使用 task_local 上下文）。
    /// - `permission`: 权限标识字符串。
    ///
    /// # 返回
    /// - `Ok(true)`: 持有权限。
    /// - `Ok(false)`: 未持有权限。
    /// - `Err(_)`: 鉴权过程出错（未登录 / DAO 故障等）。
    pub async fn check_permission(&self, login_id: &str, permission: &str) -> BulwarkResult<bool> {
        let _ = login_id;
        match self.logic.check_permission(permission).await {
            Ok(()) => Ok(true),
            Err(BulwarkError::NotPermission(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BulwarkConfig;
    use crate::context::tenant::with_default_tenant;
    use crate::dao::tests::MockDao;
    use crate::dao::BulwarkDao;
    use crate::manager::BulwarkManager;
    use crate::session::BulwarkSession;
    use crate::stp::{
        with_current_token, BulwarkInterface, BulwarkLogicDefault, BulwarkUtil, LoginParams,
        SessionLogic,
    };
    use crate::strategy::{BulwarkPermissionStrategy, BulwarkPermissionStrategyDefault};
    use async_trait::async_trait;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::future::Future;

    // ------------------------------------------------------------------------
    // MockInterface：权限/角色数据回调（复用 manager/mod.rs 测试模式）
    // ------------------------------------------------------------------------

    struct MockInterface {
        permissions: HashMap<String, Vec<String>>,
        #[allow(dead_code)]
        roles: HashMap<String, Vec<String>>,
    }

    impl MockInterface {
        fn new() -> Self {
            Self {
                permissions: HashMap::new(),
                roles: HashMap::new(),
            }
        }

        fn with_permission(mut self, login_id: &str, perms: &[&str]) -> Self {
            self.permissions.insert(
                login_id.to_string(),
                perms.iter().map(|s| s.to_string()).collect(),
            );
            self
        }
    }

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(self.roles.get(login_id).cloned().unwrap_or_default())
        }
    }

    // ------------------------------------------------------------------------
    // 辅助函数
    // ------------------------------------------------------------------------

    /// 创建默认测试配置（timeout=3600，throw_on_not_login=false 便于断言）。
    fn make_config() -> BulwarkConfig {
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = false;
        config
    }

    /// 构造独立的 `BulwarkLogicDefault`（不依赖全局单例），注入 MockDao + MockInterface。
    fn make_logic(interface: Arc<dyn BulwarkInterface>) -> Arc<BulwarkLogicDefault> {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let timeout = u64::try_from(config.timeout).unwrap();
        let session = Arc::new(BulwarkSession::new(dao, timeout, timeout));
        let firewall: Arc<dyn BulwarkPermissionStrategy> =
            Arc::new(BulwarkPermissionStrategyDefault::new(interface));
        Arc::new(BulwarkLogicDefault::new(session, config, firewall))
    }

    /// 在 task_local 上下文中执行 future（设置当前 token）。
    async fn with_token<R>(token: String, f: impl Future<Output = R>) -> R {
        with_current_token(token, f).await
    }

    // ------------------------------------------------------------------------
    // 测试 1：Manager::new 构造成功
    // ------------------------------------------------------------------------

    /// T078-1: `Manager::new(Arc::new(logic))` 构造成功，logic 引用计数正确。
    ///
    /// 验证 Manager 持有 logic 的 Arc 副本，不消耗原始 Arc。
    #[tokio::test]
    async fn manager_new_construction_succeeds() {
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        let logic = make_logic(interface);
        let strong_count_before = Arc::strong_count(&logic);

        let manager = Manager::new(Arc::clone(&logic));
        // Manager 持有 logic 的 Arc 副本，引用计数 +1
        assert_eq!(
            Arc::strong_count(&logic),
            strong_count_before + 1,
            "Manager::new 应增加 logic 引用计数"
        );

        // Drop manager 后引用计数恢复
        drop(manager);
        assert_eq!(
            Arc::strong_count(&logic),
            strong_count_before,
            "Drop Manager 后引用计数应恢复"
        );
    }

    // ------------------------------------------------------------------------
    // 测试 2：Manager::authorize 返回 Decision
    // ------------------------------------------------------------------------

    /// T078-2: `manager.authorize(&req)` 返回 `Decision`（不 panic / 不返回 Err）。
    ///
    /// 已登录 + 持有权限场景下返回 `Ok(Decision)`。
    #[tokio::test]
    async fn manager_authorize_returns_decision() {
        let interface: Arc<dyn BulwarkInterface> =
            Arc::new(MockInterface::new().with_permission("1001", &["user:read"]));
        let logic = make_logic(interface);
        let manager = Manager::new(Arc::clone(&logic));

        let token = logic.login("1001", &LoginParams::default()).await.unwrap();
        let req = AuthRequest::new("1001", "user:read");
        let result = with_token(token, async {
            with_default_tenant(async { manager.authorize(&req).await }).await
        })
        .await;
        assert!(result.is_ok(), "authorize 应返回 Ok: {:?}", result.err());
        let decision = result.unwrap();
        // 仅断言 Decision 结构正确（allowed/reason 在后续测试细化）
        let _ = decision.allowed;
        let _ = decision.reason;
    }

    // ------------------------------------------------------------------------
    // 测试 3：Manager::authorize allowed=true 场景
    // ------------------------------------------------------------------------

    /// T078-3: 持有权限时 `authorize` 返回 `Decision { allowed: true, reason: ExplicitAllow }`。
    #[tokio::test]
    async fn manager_authorize_with_allowed_returns_true() {
        let interface: Arc<dyn BulwarkInterface> =
            Arc::new(MockInterface::new().with_permission("1001", &["user:read"]));
        let logic = make_logic(interface);
        let manager = Manager::new(Arc::clone(&logic));

        let token = logic.login("1001", &LoginParams::default()).await.unwrap();
        let req = AuthRequest::new("1001", "user:read");
        let decision = with_token(token, async {
            with_default_tenant(async { manager.authorize(&req).await }).await
        })
        .await
        .expect("authorize ok");
        assert!(decision.allowed, "持有权限应 allowed=true");
        assert_eq!(
            decision.reason,
            DecisionReason::ExplicitAllow,
            "持有权限 reason 应为 ExplicitAllow"
        );
    }

    // ------------------------------------------------------------------------
    // 测试 4：Manager::authorize allowed=false 场景
    // ------------------------------------------------------------------------

    /// T078-4: 未持有权限时 `authorize` 返回 `Decision { allowed: false, reason: NoMatchingPermission }`。
    #[tokio::test]
    async fn manager_authorize_with_denied_returns_false() {
        let interface: Arc<dyn BulwarkInterface> =
            Arc::new(MockInterface::new().with_permission("1001", &["user:read"]));
        let logic = make_logic(interface);
        let manager = Manager::new(Arc::clone(&logic));

        let token = logic.login("1001", &LoginParams::default()).await.unwrap();
        let req = AuthRequest::new("1001", "user:delete");
        let decision = with_token(token, async {
            with_default_tenant(async { manager.authorize(&req).await }).await
        })
        .await
        .expect("authorize 应返回 Ok(Decision deny) 而非 Err");
        assert!(!decision.allowed, "未持有权限应 allowed=false");
        assert_eq!(
            decision.reason,
            DecisionReason::NoMatchingPermission,
            "未持有权限 reason 应为 NoMatchingPermission"
        );
    }

    // ------------------------------------------------------------------------
    // 测试 5：Manager::check_permission 委托 PermissionLogic 行为一致
    // ------------------------------------------------------------------------

    /// T078-5: `manager.check_permission(login_id, perm)` 与 `PermissionLogic::check_permission(perm)`
    /// 行为一致（同一 task_local 上下文下返回相同允许/拒绝结果）。
    ///
    /// 验证委托语义：Manager 内部调用 logic.check_permission，返回值映射正确。
    #[tokio::test]
    async fn manager_check_permission_delegates_to_logic() {
        let interface: Arc<dyn BulwarkInterface> =
            Arc::new(MockInterface::new().with_permission("1001", &["user:read"]));
        let logic = make_logic(interface);
        let manager = Manager::new(Arc::clone(&logic));

        let token = logic.login("1001", &LoginParams::default()).await.unwrap();

        // 持有权限：logic.check_permission → Ok(())，manager.check_permission → Ok(true)
        let logic_held = with_token(token.clone(), async {
            with_default_tenant(async { logic.check_permission("user:read").await }).await
        })
        .await;
        let mgr_held = with_token(token.clone(), async {
            with_default_tenant(async { manager.check_permission("1001", "user:read").await }).await
        })
        .await;
        assert!(logic_held.is_ok(), "logic 持有权限应 Ok(())");
        assert!(
            mgr_held.expect("manager check_permission ok"),
            "manager 持有权限应 Ok(true)"
        );

        // 未持有权限：logic.check_permission → Err(NotPermission)，manager.check_permission → Ok(false)
        let logic_denied = with_token(token.clone(), async {
            with_default_tenant(async { logic.check_permission("user:delete").await }).await
        })
        .await;
        let mgr_denied = with_token(token.clone(), async {
            with_default_tenant(async { manager.check_permission("1001", "user:delete").await })
                .await
        })
        .await;
        assert!(
            matches!(logic_denied, Err(BulwarkError::NotPermission(_))),
            "logic 未持有应 Err(NotPermission)"
        );
        assert!(
            !mgr_denied.expect("manager check_permission ok"),
            "manager 未持有应 Ok(false)"
        );
    }

    // ------------------------------------------------------------------------
    // 测试 6：Manager Drop 不影响全局单例
    // ------------------------------------------------------------------------

    /// T078-6: Manager Drop 后 `BulwarkManager` 全局单例状态不受影响（独立生命周期）。
    ///
    /// 验证 Manager 与 BulwarkManager 共享同一 logic 实例时，Drop Manager
    /// 不破坏全局单例（引用计数正确，is_initialized 仍为 true）。
    #[tokio::test]
    #[serial]
    async fn manager_drop_does_not_affect_global_singleton() {
        BulwarkManager::reset_for_test();
        // 初始化全局单例
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao, config, interface).unwrap();
        assert!(BulwarkManager::is_initialized());

        // 从全局单例获取 logic，构造 Manager
        let logic = BulwarkManager::logic().unwrap();
        let strong_count_before = Arc::strong_count(&logic);
        {
            let _manager = Manager::new(Arc::clone(&logic));
            assert_eq!(
                Arc::strong_count(&logic),
                strong_count_before + 1,
                "Manager 构造后引用计数 +1"
            );
            // _manager 在此作用域结束时 Drop，验证引用计数恢复
        }
        assert_eq!(
            Arc::strong_count(&logic),
            strong_count_before,
            "Drop Manager 后引用计数应恢复"
        );

        // 全局单例状态未受影响
        assert!(
            BulwarkManager::is_initialized(),
            "Drop Manager 后全局单例应仍初始化"
        );
        // 全局单例仍可正常 login
        let token = BulwarkUtil::login_simple("2002").await.unwrap();
        assert!(!token.is_empty(), "全局单例 login 仍应正常工作");

        BulwarkManager::reset_for_test();
    }
}
