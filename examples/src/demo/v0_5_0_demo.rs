//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! v0.5.0 综合演示：多租户隔离 + 审计日志 + 决策溯源 + Keycloak OIDC RP + 微信社交登录。
//!
//! 演示 Garrison v0.5.0 的核心生产能力：
//! 1. 多租户上下文（TENANT task_local + prefixed_key）
//! 2. 审计日志（AuditLogListener 写入 SQLite）
//! 3. 决策溯源（PermissionChecker + DecisionReason）
//! 4. Keycloak OIDC RP 配置（KeycloakConfig/KeycloakProvider 构造）
//! 5. 微信社交登录配置（WechatProvider 构造）
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin v0_5_0_demo --features "tenant-isolation audit-log decision-trace keycloak-oidc social-wechat db-sqlite cache-memory"
//! ```
//!
//! 本示例使用内存 SQLite + oxcache 内存 DAO，无需外部依赖即可运行。

// 占位值，生产环境必须从环境变量/KMS 加载

use async_trait::async_trait;
use dbnexus::DbPool;
use garrison::context::tenant::{TenantContext, TenantSource, TENANT};
use garrison::core::permission::{
    AuthRequest, DecisionReason, PermissionChecker, PermissionCheckerDefault,
};
use garrison::dao::{init_dbnexus, GarrisonDao, GarrisonDaoOxcache, GarrisonMigration};
use garrison::error::GarrisonResult;
use garrison::listener::audit::{AuditConfig, AuditQuery};
use garrison::listener::{GarrisonListener, GarrisonListenerManager};
use garrison::session::GarrisonSession;
use garrison::stp::{
    with_current_token, GarrisonInterface, GarrisonLogicDefault, LoginParams, PermissionLogic,
    SessionLogic,
};
use garrison::strategy::GarrisonPermissionStrategyDefault;
use garrison::{
    AuditLogListener, GarrisonConfig, KeycloakConfig, KeycloakProvider, WechatProvider,
};
use std::path::PathBuf;
use std::sync::Arc;

/// Demo 错误类型（统一 `?` 传播到 `main` 的 `unwrap`）。
type DemoResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Mock 权限接口：为 login_id 1001 返回 ["user:read", "user:write"] 权限。
struct DemoInterface;

#[async_trait]
impl GarrisonInterface for DemoInterface {
    async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        if login_id == "1001" {
            Ok(vec!["user:read".to_string(), "user:write".to_string()])
        } else {
            Ok(vec![])
        }
    }

    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec!["admin".to_string()])
    }
}

/// 初始化基础设施：SQLite in-memory + 迁移 + oxcache DAO + GarrisonSession。
async fn init_infrastructure() -> DemoResult<(DbPool, Arc<dyn GarrisonDao>, Arc<GarrisonSession>)> {
    println!("[1] 初始化基础设施...");

    let pool = init_dbnexus("sqlite::memory:").await?;
    let migrations_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("migrations")
        .join("sqlite");
    let migration = GarrisonMigration::with_base_dir(pool.clone(), migrations_dir);
    migration.run_all().await?;

    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await?);
    // GarrisonSession::new 消费 dao，clone 一份返回给调用方
    let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400));
    println!("    ✓ SQLite in-memory + oxcache DAO 已就绪");

    Ok((pool, dao, session))
}

/// 配置审计日志监听器：注册 AuditLogListener 到 ListenerManager。
async fn setup_audit_listener(
    pool: DbPool,
) -> DemoResult<(Arc<GarrisonListenerManager>, Arc<AuditLogListener>)> {
    println!("[2] 配置审计日志监听器...");

    let lm = Arc::new(GarrisonListenerManager::new());
    let audit_config = AuditConfig {
        mask_fields: vec!["token".to_string()],
        retain_days: 90,
        async_write: false,
        signing_key: None,
        audit_mask_mode: garrison::config::AuditMaskMode::default(),
    };
    let audit_listener = Arc::new(AuditLogListener::new(pool, audit_config));
    lm.register(audit_listener.clone() as Arc<dyn GarrisonListener>);
    println!("    ✓ AuditLogListener 已注册（掩码字段: token, 保留天数: 90）");

    Ok((lm, audit_listener))
}

/// 构造 GarrisonLogicDefault：注入 PermissionChecker + ListenerManager。
fn construct_logic(
    session: Arc<GarrisonSession>,
    interface: Arc<dyn GarrisonInterface>,
    pc: Arc<dyn PermissionChecker>,
    lm: Arc<GarrisonListenerManager>,
) -> Arc<GarrisonLogicDefault> {
    println!("[3] 构造 GarrisonLogicDefault（含决策溯源 + 审计日志）...");

    let firewall = Arc::new(GarrisonPermissionStrategyDefault::new(interface));

    let mut config = GarrisonConfig::default_config();
    config.token_style = "uuid".to_string();
    config.timeout = 3600;
    config.throw_on_not_login = true;

    let logic = Arc::new(
        GarrisonLogicDefault::new(session, Arc::new(config), firewall)
            .with_permission_checker(pc)
            .with_listener_manager(lm),
    );
    println!("    ✓ GarrisonLogicDefault 已构造（PermissionChecker + ListenerManager 已注入）");

    logic
}

/// 多租户隔离演示：在 TENANT(42) scope 内登录 + 权限校验 + 决策溯源。
async fn demo_tenant_isolation(
    logic: Arc<GarrisonLogicDefault>,
    pc: Arc<dyn PermissionChecker>,
) -> DemoResult<()> {
    println!("[4] 多租户隔离演示（tenant_id=42, login_id=1001）...");

    let tenant_ctx = TenantContext {
        tenant_id: 42,
        resolved_from: TenantSource::Header,
    };

    // 在 TENANT(42) scope 内登录，确保 session key 带 tenant:42: 前缀
    let token = TENANT
        .scope(tenant_ctx.clone(), async {
            logic.login("1001", &LoginParams::default()).await
        })
        .await?;
    println!("    ✓ 登录成功，token 长度: {}", token.len());

    // 在 TENANT(42) + current_token 上下文中校验权限
    let check_result = TENANT
        .scope(
            tenant_ctx.clone(),
            with_current_token(token.clone(), async {
                logic.check_permission("user:read").await
            }),
        )
        .await;
    check_result?;
    println!("    ✓ 权限校验通过：user:read");

    // 决策溯源：验证 Decision 详情
    let auth_request = AuthRequest {
        login_id: "1001".to_string(),
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
    if decision.reason != DecisionReason::ExplicitAllow {
        return Err(format!(
            "expected DecisionReason::ExplicitAllow, got {:?}",
            decision.reason
        )
        .into());
    }

    // 验证拒绝路径
    let deny_request = AuthRequest {
        login_id: "1001".to_string(),
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

    Ok(())
}

/// 查询审计日志：验证 AuditLogListener 写入的记录可按条件检索。
async fn query_audit_logs(audit_listener: Arc<AuditLogListener>) -> DemoResult<()> {
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

    Ok(())
}

/// Keycloak OIDC RP 配置演示：构造 KeycloakConfig + KeycloakProvider。
fn demo_keycloak_config() -> DemoResult<()> {
    println!("[6] Keycloak OIDC RP 配置演示...");

    let kc_config = KeycloakConfig {
        base_url: "https://kc.example.com:8443/realms/myrealm".into(),
        client_id: "garrison-rp".into(),
        client_secret: Some("client-secret-123".into()),
        redirect_uri: "https://app.example.com/cb".into(),
        expected_iss: "https://kc.example.com:8443/realms/myrealm".into(),
    };
    println!("    ✓ KeycloakConfig 已构造");
    println!("      → discovery_url: {}", kc_config.discovery_url());
    println!("      → client_id: {}", kc_config.client_id);

    // 构造 KeycloakProvider（不实际调用 discover，仅演示配置）
    let _provider = KeycloakProvider::new(kc_config)?;
    println!("    ✓ KeycloakProvider 已构造（discover/exchange_code/verify_id_token 可用）");

    Ok(())
}

/// 微信社交登录配置演示：构造 WechatProvider。
fn demo_wechat_config() -> DemoResult<()> {
    println!("[7] 微信社交登录配置演示...");

    let _wechat = WechatProvider::new("wx_app_id", "wx_app_secret");
    println!("    ✓ WechatProvider 已构造（client_id=wx_app_id）");

    Ok(())
}

/// 运行 v0.5.0 综合演示。
///
/// 仅做顺序编排：init → audit listener → logic → tenant demo → audit query →
/// keycloak config → wechat config → 总结。每步打印步骤标题。
pub async fn run() -> DemoResult<()> {
    println!("=== Garrison v0.5.0 生产能力综合演示 ===\n");

    let (pool, _dao, session) = init_infrastructure().await?;
    let (lm, audit_listener) = setup_audit_listener(pool).await?;

    let interface: Arc<dyn GarrisonInterface> = Arc::new(DemoInterface);
    let pc: Arc<dyn PermissionChecker> = Arc::new(PermissionCheckerDefault::new(interface.clone()));
    let logic = construct_logic(session, interface, pc.clone(), lm);

    demo_tenant_isolation(logic, pc).await?;
    query_audit_logs(audit_listener).await?;
    demo_keycloak_config()?;
    demo_wechat_config()?;

    println!("\n=== v0.5.0 生产能力演示完成 ===");
    println!("已展示功能：");
    println!("  • 多租户隔离（TENANT task_local + prefixed_key）");
    println!("  • 审计日志（AuditLogListener → SQLite）");
    println!("  • 决策溯源（PermissionChecker + DecisionReason）");
    println!("  • Keycloak OIDC RP（KeycloakConfig/KeycloakProvider）");
    println!("  • 微信社交登录（WechatProvider）");

    Ok(())
}
