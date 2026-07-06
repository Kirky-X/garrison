//! 多租户隔离 + 审计日志 + 决策溯源端到端集成测试。
//!
//! 验证租户 42 用户 1001 的权限校验全链路：
//! `check_permission` → `authorize` → `Decision` → 广播 `BulwarkEvent` → `AuditLogListener` 写入。
//!
//! 运行：
//! ```bash
//! cargo test --features "tenant-isolation audit-log db-sqlite decision-trace cache-memory" --test tenant_isolation_integration
//! ```

mod common;

#[cfg(all(
    feature = "tenant-isolation",
    feature = "audit-log",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
mod tenant_audit_decision_e2e {
    use async_trait::async_trait;
    use bulwark::context::tenant::{TenantContext, TenantSource, TENANT};
    use bulwark::core::permission::{
        AuthRequest, DecisionReason, PermissionChecker, PermissionCheckerDefault,
    };
    use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
    use bulwark::error::BulwarkResult;
    use bulwark::listener::audit::{AuditConfig, AuditQuery};
    use bulwark::listener::{BulwarkListener, BulwarkListenerManager};
    use bulwark::session::BulwarkSession;
    use bulwark::stp::{with_current_token, BulwarkInterface, BulwarkLogic, BulwarkLogicDefault};
    use bulwark::AuditLogListener;
    use serial_test::serial;
    use std::sync::Arc;

    use crate::common::setup_db;

    struct MockInterface;

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
            if login_id == 1001 {
                Ok(vec!["user:read".to_string()])
            } else {
                Ok(vec![])
            }
        }

        async fn get_role_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
    }

    /// 验证租户 42 用户 1001 的权限校验全链路：
    /// `check_permission` → `authorize` → `Decision` → 广播 `PermissionCheck` → `AuditLogListener` 写入。
    ///
    /// 断言：
    /// 1. `check_permission("user:read")` 返回 `Ok(())`
    /// 2. `authorize()` 返回 `Decision { allowed: true, reason: ExplicitAllow }`
    /// 3. `audit_logs` 表存在 `tenant_id=42, event_type="permission_check"` 的记录
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn tenant_isolation_with_audit_log_and_decision_trace_e2e() {
        let pool = setup_db().await;

        let dao: Arc<dyn BulwarkDao> = Arc::new(
            BulwarkDaoOxcache::new()
                .await
                .expect("oxcache 初始化应成功"),
        );
        let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));

        let mut config = bulwark::config::BulwarkConfig::default_config();
        config.token_style = "uuid".to_string();
        config.timeout = 3600;
        config.throw_on_not_login = true;

        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
        let pc: Arc<dyn PermissionChecker> =
            Arc::new(PermissionCheckerDefault::new(interface.clone()));

        let firewall = Arc::new(bulwark::strategy::BulwarkPermissionStrategyDefault::new(
            interface,
        ));

        let lm = Arc::new(BulwarkListenerManager::new());
        let audit_config = AuditConfig {
            mask_fields: vec![],
            retain_days: 0,
            async_write: false,
            signing_key: None,
        };
        let audit_listener = Arc::new(AuditLogListener::new(pool.clone(), audit_config));
        lm.register(audit_listener.clone() as Arc<dyn BulwarkListener>);

        let logic = Arc::new(
            BulwarkLogicDefault::new(session, Arc::new(config), firewall)
                .with_permission_checker(pc.clone())
                .with_listener_manager(lm),
        );

        let tenant_ctx = TenantContext {
            tenant_id: 42,
            resolved_from: TenantSource::Header,
        };

        let token = TENANT
            .scope(tenant_ctx.clone(), async {
                logic.login(1001).await.expect("login 应成功")
            })
            .await;
        assert!(!token.is_empty(), "token 不应为空");

        let check_result = TENANT
            .scope(
                tenant_ctx,
                with_current_token(token.clone(), async {
                    logic.check_permission("user:read").await
                }),
            )
            .await;

        assert!(
            check_result.is_ok(),
            "check_permission 应成功: {:?}",
            check_result.err()
        );

        let auth_request = AuthRequest {
            login_id: 1001,
            tenant_id: 42,
            action: "user:read".to_string(),
            resource: None,
            context: serde_json::Value::Null,
        };
        let decision = pc.authorize(&auth_request).await.expect("authorize 应成功");
        assert!(decision.allowed, "Decision.allowed 应为 true");
        assert_eq!(
            decision.reason,
            DecisionReason::ExplicitAllow,
            "Decision.reason 应为 ExplicitAllow"
        );

        let query = AuditQuery {
            tenant_id: Some(42),
            event_type: Some("permission_check".to_string()),
            ..Default::default()
        };
        let logs = audit_listener
            .query_audit_logs(query)
            .await
            .expect("query_audit_logs 应成功");

        assert!(
            !logs.is_empty(),
            "audit_logs 应存在 tenant_id=42, event_type=permission_check 的记录"
        );
        let entry = &logs[0];
        assert_eq!(entry.tenant_id, 42, "audit_logs tenant_id 应为 42");
        assert_eq!(
            entry.event_type, "permission_check",
            "audit_logs event_type 应为 permission_check"
        );
        assert_eq!(entry.login_id, Some(1001), "audit_logs login_id 应为 1001");
    }
}
