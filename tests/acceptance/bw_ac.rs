//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BW-AC 验收标准追溯移植（Phase 4 T043，迁自 `tests/acceptance_criteria.rs`）。
//!
//! 原文件 9 个测试中：BW-AC-001（OIDC 会话创建）、003（设备踢出）、010（锁定）
//! 已有验收矩阵等价场景（ACC-AUTH-011/012、session 域设备场景，见各域文件），
//! 本模块逐字移植其余 6 个（语义保持、可强化未弱化），保留 Gherkin 注释与
//! BW-AC 编号以便追溯。规则 7 冲突说明随原文件保留。

use garrison::dao::InMemoryDao;
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::session::GarrisonSession;
use garrison::stp::{with_current_token, GarrisonInterface, GarrisonUtil};
use garrison::{GarrisonConfig, GarrisonDao, GarrisonManager};
use serial_test::serial;
use std::sync::Arc;

/// 设置默认 TENANT scope（tenant_id=0），避免 tenant-isolation feature 启用时
/// `current_tenant_id_or_error()` 返回 Err(Config) 导致权限校验提前失败。
async fn with_default_tenant<F, R>(f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    use garrison::{TenantContext, TenantSource, TENANT};
    let ctx = TenantContext {
        tenant_id: 0,
        resolved_from: TenantSource::Header,
    };
    TENANT.scope(ctx, f).await
}

/// 可配置权限/角色列表的接口替身（原 acceptance_criteria.rs helper 移入）。
struct MockInterface {
    permissions: Vec<String>,
    roles: Vec<String>,
}

#[async_trait::async_trait]
impl GarrisonInterface for MockInterface {
    async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(self.permissions.clone())
    }
    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(self.roles.clone())
    }
}

/// 初始化全局 GarrisonManager 并返回 InMemoryDao（原 helper 移入，语义不变）。
async fn init_manager(permissions: Vec<String>, roles: Vec<String>) -> Arc<InMemoryDao> {
    let dao = Arc::new(InMemoryDao::new());
    let mut config = GarrisonConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = true;
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface { permissions, roles });
    GarrisonManager::builder()
        .dao(dao.clone() as Arc<dyn GarrisonDao>)
        .config(Arc::new(config))
        .interface(interface)
        .build()
        .await
        .expect("GarrisonManager::builder() 应成功");
    dao
}

// ============================================================================
// BW-AC-002: 受保护 API 访问时 Token-Session TTL 续期
// ============================================================================

/// BW-AC-002：受保护 API 访问时 Token-Session TTL 续期（FRD §8.1 BW-AC-002）。
///
/// # 规则7 冲突
///
/// spec 期望 TTL 续期 30min（1800 秒），但 `GarrisonSession::touch` 重置 TTL 为
/// `config.timeout`（默认 2592000 秒）。本测试验证 touch 操作重置 TTL 的行为。
#[tokio::test]
#[serial]
async fn bw_ac_002_protected_api_renews_token_session_ttl() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let session = GarrisonSession::new(dao.clone(), 3600, 86400, 0);

    session
        .create("user-002", "token-002")
        .await
        .expect("create 应成功");

    let initial_ttl = dao
        .get_timeout("token:session:token-002")
        .await
        .expect("get_timeout 应成功");
    assert!(initial_ttl.is_some(), "初始 TTL 应存在");
    assert!(initial_ttl.unwrap().as_secs() <= 3600);

    session.touch("token-002").await.expect("touch 应成功");

    let renewed_ttl = dao
        .get_timeout("token:session:token-002")
        .await
        .expect("get_timeout 应成功");
    assert!(renewed_ttl.is_some(), "续期后 TTL 应存在");
    let renewed_secs = renewed_ttl.unwrap().as_secs();
    assert!(
        renewed_secs > 3500 && renewed_secs <= 3600,
        "touch 后 TTL 应重置为接近 3600 秒，实际: {}",
        renewed_secs
    );

    assert!(
        session
            .is_valid("token-002")
            .await
            .expect("is_valid 应成功"),
        "token 应仍有效"
    );
}

// ============================================================================
// BW-AC-004/005: 角色/权限校验失败返回 403
// ============================================================================

/// BW-AC-004：无角色访问 `#[check_role("admin")]` 返回 403（FRD §8.1 BW-AC-004）。
#[tokio::test]
#[serial]
async fn bw_ac_004_role_check_returns_403() {
    with_default_tenant(async {
        let _dao = init_manager(vec![], vec!["user".to_string()]).await;
        let token = GarrisonUtil::login_simple("user-004")
            .await
            .expect("login 应成功");

        let result =
            with_current_token(token, async { GarrisonUtil::check_role("admin").await }).await;

        assert!(
            matches!(result, Err(GarrisonError::NotRole(_))),
            "期望 NotRole 错误，实际: {:?}",
            result
        );

        let err = result.unwrap_err();
        let (status, _, _, _) = err.response_parts();
        assert_eq!(status, 403, "NotRole 的 HTTP status 应为 403");
    })
    .await;
}

/// BW-AC-005：无权限访问 `#[check_permission("order:write")]` 返回 403
/// （FRD §8.1 BW-AC-005）。
#[tokio::test]
#[serial]
async fn bw_ac_005_permission_check_returns_403() {
    with_default_tenant(async {
        let _dao = init_manager(vec!["order:read".to_string()], vec![]).await;
        let token = GarrisonUtil::login_simple("user-005")
            .await
            .expect("login 应成功");

        let result = with_current_token(token, async {
            GarrisonUtil::check_permission("order:write").await
        })
        .await;

        assert!(
            matches!(result, Err(GarrisonError::NotPermission(_))),
            "期望 NotPermission 错误，实际: {:?}",
            result
        );

        let err = result.unwrap_err();
        let (status, _, _, _) = err.response_parts();
        assert_eq!(status, 403, "NotPermission 的 HTTP status 应为 403");
    })
    .await;
}

// ============================================================================
// BW-AC-006: oxcache 内存后端完整流程
// ============================================================================

/// BW-AC-006：oxcache 后端切换为 Memory 后功能正常（FRD §8.1 BW-AC-006）。
#[tokio::test]
#[serial]
async fn bw_ac_006_oxcache_memory_backend_works() {
    with_default_tenant(async {
        let dao = init_manager(
            vec!["bench:read".to_string()],
            vec!["bench-user".to_string()],
        )
        .await;
        let dao: Arc<dyn GarrisonDao> = dao;

        let token = GarrisonUtil::login_simple("user-006")
            .await
            .expect("login 应成功");

        // 双模会话在 oxcache DAO 上写入
        let account_key = format!("account:session:{}", "user-006");
        assert!(
            dao.get(&account_key).await.unwrap().is_some(),
            "Account-Session 应写入 oxcache"
        );
        let token_key = format!("token:session:{}", token);
        assert!(
            dao.get(&token_key).await.unwrap().is_some(),
            "Token-Session 应写入 oxcache"
        );

        // 鉴权 → 登出完整流程
        let checked = with_current_token(token.clone(), async {
            GarrisonUtil::check_permission("bench:read").await
        })
        .await;
        assert!(checked.is_ok(), "授权应放行");

        with_current_token(token.clone(), async { GarrisonUtil::logout().await })
            .await
            .expect("logout 应成功");
        assert!(
            dao.get(&token_key).await.unwrap().is_none(),
            "logout 后 Token-Session 应删除"
        );
    })
    .await;
}

// ============================================================================
// BW-AC-007: dbnexus SQLite 后端完整流程（原始 SQL 直插）
// ============================================================================

/// BW-AC-007：dbnexus 后端切换为 SQLite 后功能正常（FRD §8.1 BW-AC-007）。
#[cfg(feature = "db-sqlite")]
#[tokio::test]
#[serial]
async fn bw_ac_007_dbnexus_sqlite_backend_works() {
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};

    let pool = crate::common::setup_db().await;
    let session = pool.get_session("admin").await.expect("获取 admin session");
    let conn = session.connection().expect("获取连接");

    // 插入用户
    let user_id = format!("bw-ac-007-user-{}", uuid::Uuid::new_v4());
    let stmt = Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO app_user (id, username, password_hash, status, tenant_id) VALUES (?, ?, ?, ?, ?)",
        vec![
            Value::String(Some(user_id.clone())),
            Value::String(Some("ac007_user".to_string())),
            Value::String(Some("argon2$mock_hash".to_string())),
            Value::String(Some("active".to_string())),
            Value::BigInt(Some(0)),
        ],
    );
    conn.execute_raw(stmt)
        .await
        .expect("INSERT app_user 应成功");

    // 插入角色
    let role_id = format!("bw-ac-007-role-{}", uuid::Uuid::new_v4());
    let stmt = Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO app_role (id, code, name, tenant_id) VALUES (?, ?, ?, ?)",
        vec![
            Value::String(Some(role_id.clone())),
            Value::String(Some("ac007_admin".to_string())),
            Value::String(Some("AC007 Admin".to_string())),
            Value::BigInt(Some(0)),
        ],
    );
    conn.execute_raw(stmt)
        .await
        .expect("INSERT app_role 应成功");

    // 插入权限
    let perm_id = format!("bw-ac-007-perm-{}", uuid::Uuid::new_v4());
    let stmt = Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO app_permission (id, code, name) VALUES (?, ?, ?)",
        vec![
            Value::String(Some(perm_id.clone())),
            Value::String(Some("ac007:read".to_string())),
            Value::String(Some("AC007 Read".to_string())),
        ],
    );
    conn.execute_raw(stmt)
        .await
        .expect("INSERT app_permission 应成功");

    // Then: 验证数据可读
    let stmt = Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT username FROM app_user WHERE id = ?",
        vec![Value::String(Some(user_id))],
    );
    let row = conn
        .query_one_raw(stmt)
        .await
        .expect("SELECT app_user 应成功")
        .expect("用户记录应存在");
    let username: String = row.try_get("", "username").expect("读取 username 列");
    assert_eq!(username, "ac007_user");

    let stmt = Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT code FROM app_role WHERE id = ?",
        vec![Value::String(Some(role_id))],
    );
    let row = conn
        .query_one_raw(stmt)
        .await
        .expect("SELECT app_role 应成功")
        .expect("角色记录应存在");
    let role_code: String = row.try_get("", "code").expect("读取 code 列");
    assert_eq!(role_code, "ac007_admin");

    let stmt = Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT code FROM app_permission WHERE id = ?",
        vec![Value::String(Some(perm_id))],
    );
    let row = conn
        .query_one_raw(stmt)
        .await
        .expect("SELECT app_permission 应成功")
        .expect("权限记录应存在");
    let perm_code: String = row.try_get("", "code").expect("读取 code 列");
    assert_eq!(perm_code, "ac007:read");
}

// ============================================================================
// BW-AC-009: logout 后 Token 失效
// ============================================================================

/// BW-AC-009：logout() 后原 Token 失效、Token-Session 从 DAO 删除
/// （FRD §8.1 BW-AC-009）。
///
/// # 规则7 冲突
///
/// 1. spec 期望 `GarrisonError::NotLogin`，但实际 `check_login` 在 token session
///    不存在时返回 `GarrisonError::Session("未登录")`；本测试接受任一错误。
/// 2. spec 期望 jti 黑名单，实际 `logout()` 仅删除 Token-Session（注释随原文件）。
#[tokio::test]
#[serial]
async fn bw_ac_009_logout_invalidates_token() {
    let dao = init_manager(vec![], vec![]).await;

    let token = GarrisonUtil::login_simple("user-009")
        .await
        .expect("login 应成功");

    let logged_in =
        with_current_token(token.clone(), async { GarrisonUtil::check_login().await }).await;
    assert!(logged_in.unwrap_or(false), "logout 前应已登录");

    with_current_token(token.clone(), async { GarrisonUtil::logout().await })
        .await
        .expect("logout 应成功");

    let token_key = format!("token:session:{}", token);
    let token_session = dao.get(&token_key).await.expect("DAO get 应成功");
    assert!(token_session.is_none(), "logout 后 Token-Session 应已删除");

    let check_result = with_current_token(token, async { GarrisonUtil::check_login().await }).await;
    assert!(
        check_result.is_err(),
        "logout 后 check_login 应返回错误（token 已失效）"
    );
}
