//! v0.5.0 综合演示：多租户隔离 + 审计日志 + 决策溯源 + Keycloak OIDC RP + 微信社交登录。
//!
//! 演示 Bulwark v0.5.0 的核心生产能力：
//! 1. 多租户上下文（TENANT task_local + prefixed_key）
//! 2. 审计日志（AuditLogListener 写入 SQLite）
//! 3. 决策溯源（PermissionChecker + DecisionReason）
//! 4. Keycloak OIDC RP 配置（KeycloakConfig/KeycloakProvider 构造）
//! 5. 微信社交登录配置（WechatProvider 构造）
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin v0_5_0_demo --features "tenant-isolation audit-log decision-trace keycloak-oidc social-wechat db-sqlite cache-memory"
//! ```
//!
//! 本示例使用内存 SQLite + oxcache 内存 DAO，无需外部依赖即可运行。

use async_trait::async_trait;
use bulwark::context::tenant::{TenantContext, TenantSource, TENANT};
use bulwark::core::permission::{
    AuthRequest, DecisionReason, PermissionChecker, PermissionCheckerDefault,
};
use bulwark::dao::{init_dbnexus, BulwarkDao, BulwarkDaoOxcache, BulwarkMigration};
use bulwark::error::BulwarkResult;
use bulwark::listener::audit::{AuditConfig, AuditQuery};
use bulwark::listener::{BulwarkListener, BulwarkListenerManager};
use bulwark::session::BulwarkSession;
use bulwark::stp::{with_current_token, BulwarkInterface, BulwarkLogic, BulwarkLogicDefault};
use bulwark::strategy::BulwarkPermissionStrategyDefault;
use bulwark::{KeycloakConfig, WechatProvider};
use std::path::PathBuf;
use std::sync::Arc;

/// Mock 权限接口：为 login_id 1001 返回 ["user:read", "user:write"] 权限。
struct DemoInterface;

#[async_trait]
impl BulwarkInterface for DemoInterface {
    async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        if login_id == 1001 {
            Ok(vec!["user:read".to_string(), "user:write".to_string()])
        } else {
            Ok(vec![])
        }
    }

    async fn get_role_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
        Ok(vec!["admin".to_string()])
    }
}

/// 运行 v0.5.0 综合演示。
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark v0.5.0 生产能力综合演示 ===\n");

    // ====================================================================
    // 1. 初始化基础设施：SQLite + oxcache DAO
    // ====================================================================
    println!("[1] 初始化基础设施...");

    let pool = init_dbnexus("sqlite::memory:").await?;
    let migrations_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("migrations")
        .join("sqlite");
    let migration = BulwarkMigration::with_base_dir(pool.clone(), migrations_dir);
    migration.run_all().await?;

    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await?);
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    println!("    ✓ SQLite in-memory + oxcache DAO 已就绪");

    // ====================================================================
    // 2. 配置审计日志监听器
    // ====================================================================
    println!("[2] 配置审计日志监听器...");

    let lm = Arc::new(BulwarkListenerManager::new());
    let audit_config = AuditConfig {
        mask_fields: vec!["token".to_string()],
        retain_days: 90,
        async_write: false,
    };
    let audit_listener = Arc::new(bulwark::AuditLogListener::new(pool.clone(), audit_config));
    lm.register(audit_listener.clone() as Arc<dyn BulwarkListener>);
    println!("    ✓ AuditLogListener 已注册（掩码字段: token, 保留天数: 90）");

    // ====================================================================
    // 3. 构造 BulwarkLogic（注入 PermissionChecker + ListenerManager）
    // ====================================================================
    println!("[3] 构造 BulwarkLogic（含决策溯源 + 审计日志）...");

    let interface: Arc<dyn BulwarkInterface> = Arc::new(DemoInterface);
    let pc: Arc<dyn PermissionChecker> = Arc::new(PermissionCheckerDefault::new(interface.clone()));
    let firewall = Arc::new(BulwarkPermissionStrategyDefault::new(interface.clone()));

    let mut config = bulwark::BulwarkConfig::default_config();
    config.token_style = "uuid".to_string();
    config.timeout = 3600;
    config.throw_on_not_login = true;

    let logic = Arc::new(
        BulwarkLogicDefault::new(session, Arc::new(config), firewall)
            .with_permission_checker(pc.clone())
            .with_listener_manager(lm),
    );
    println!("    ✓ BulwarkLogicDefault 已构造（PermissionChecker + ListenerManager 已注入）");

    // ====================================================================
    // 4. 多租户隔离：在 TENANT(42) scope 内登录 + 权限校验
    // ====================================================================
    println!("[4] 多租户隔离演示（tenant_id=42, login_id=1001）...");

    let tenant_ctx = TenantContext {
        tenant_id: 42,
        resolved_from: TenantSource::Header,
    };

    // 在 TENANT(42) scope 内登录，确保 session key 带 tenant:42: 前缀
    let token = TENANT
        .scope(tenant_ctx.clone(), async {
            logic.login(1001).await.expect("login 应成功")
        })
        .await;
    println!("    ✓ 登录成功，token: {}...", &token[..8.min(token.len())]);

    // 在 TENANT(42) + current_token 上下文中校验权限
    let check_result = TENANT
        .scope(
            tenant_ctx.clone(),
            with_current_token(token.clone(), async {
                logic.check_permission("user:read").await
            }),
        )
        .await;
    assert!(check_result.is_ok(), "check_permission 应成功");
    println!("    ✓ 权限校验通过：user:read");

    // 决策溯源：验证 Decision 详情
    let auth_request = AuthRequest {
        login_id: 1001,
        tenant_id: 42,
        action: "user:read".to_string(),
        resource: None,
        context: serde_json::Value::Null,
    };
    let decision = pc.authorize(&auth_request).await?;
    println!(
        "    ✓ 决策溯源：allowed={}, reason={:?}",
        decision.allowed, decision.reason
    );
    assert_eq!(decision.reason, DecisionReason::ExplicitAllow);

    // 验证拒绝路径
    let deny_request = AuthRequest {
        login_id: 1001,
        tenant_id: 42,
        action: "system:shutdown".to_string(),
        resource: None,
        context: serde_json::Value::Null,
    };
    let deny_decision = pc.authorize(&deny_request).await?;
    println!(
        "    ✓ 拒绝路径：action=system:shutdown, allowed={}, reason={:?}",
        deny_decision.allowed, deny_decision.reason
    );

    // ====================================================================
    // 5. 查询审计日志
    // ====================================================================
    println!("[5] 查询审计日志...");

    let query = AuditQuery {
        tenant_id: Some(42),
        event_type: Some("permission_check".to_string()),
        ..Default::default()
    };
    let logs = audit_listener.query_audit_logs(query).await?;
    println!(
        "    ✓ 查到 {} 条审计日志（tenant_id=42, event_type=permission_check）",
        logs.len()
    );
    if let Some(entry) = logs.first() {
        println!(
            "      → login_id={:?}, tenant_id={}, event_type={}",
            entry.login_id, entry.tenant_id, entry.event_type
        );
    }

    // ====================================================================
    // 6. Keycloak OIDC RP 配置演示
    // ====================================================================
    println!("[6] Keycloak OIDC RP 配置演示...");

    let kc_config = KeycloakConfig {
        base_url: "https://kc.example.com:8443/realms/myrealm".into(),
        client_id: "bulwark-rp".into(),
        client_secret: Some("client-secret-123".into()),
        redirect_uri: "https://app.example.com/cb".into(),
    };
    println!("    ✓ KeycloakConfig 已构造");
    println!("      → discovery_url: {}", kc_config.discovery_url());
    println!("      → client_id: {}", kc_config.client_id);

    // 构造 KeycloakProvider（不实际调用 discover，仅演示配置）
    let _provider = bulwark::KeycloakProvider::new(kc_config)?;
    println!("    ✓ KeycloakProvider 已构造（discover/exchange_code/verify_id_token 可用）");

    // ====================================================================
    // 7. 微信社交登录配置演示
    // ====================================================================
    println!("[7] 微信社交登录配置演示...");

    let _wechat = WechatProvider::new("wx_app_id", "wx_app_secret");
    println!("    ✓ WechatProvider 已构造（client_id=wx_app_id）");

    // ====================================================================
    // 总结
    // ====================================================================
    println!("\n=== v0.5.0 生产能力演示完成 ===");
    println!("已展示功能：");
    println!("  • 多租户隔离（TENANT task_local + prefixed_key）");
    println!("  • 审计日志（AuditLogListener → SQLite）");
    println!("  • 决策溯源（PermissionChecker + DecisionReason）");
    println!("  • Keycloak OIDC RP（KeycloakConfig/KeycloakProvider）");
    println!("  • 微信社交登录（WechatProvider）");

    Ok(())
}
