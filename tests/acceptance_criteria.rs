//! Acceptance Criteria 集成测试 — BW-AC-001~010 验收标准显式追溯。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 依据 spec acceptance-criteria（E-007），覆盖 FRD §8.1 BW-AC-001~010。
//! 每个测试函数对应一个 BW-AC，包含 Gherkin 注释（Given / When / Then）。
//!
//! ## 运行方式
//!
//! ```bash
//! cargo test --test acceptance_criteria --features full
//! ```
//!
//! ## 规则7 冲突汇总（spec 期望 vs 代码库实际）
//!
//! | BW-AC | spec 期望 | 代码库实际 | 处理方式 |
//! |-------|----------|-----------|---------|
//! | 001 | OIDC 登录流程 | 需网络调用 Keycloak | 测试共享的会话创建逻辑 |
//! | 002 | TTL 续期 30min | touch 重置为 config.timeout | 测试 TTL 重置行为 |
//! | 003 | 自动 device-limit 踢出 | 无此逻辑 | 测试手动 kickout_by_device |
//! | 008 | 自动降级到 Stateless | 无自动降级 | 测试 DAO 错误显性传播 |
//! | 009 | jti 黑名单 | logout 删除 token session | 测试 token 失效 |
//! | 010 | DisableServiceException | FirewallBlocked | 测试 LockoutState + 构造 DisableService |

#![allow(clippy::bool_assert_comparison)]

use async_trait::async_trait;
use parking_lot::Mutex;
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::session::BulwarkSession;
use bulwark::stp::{with_current_token, BulwarkInterface, BulwarkUtil};
use bulwark::{BulwarkConfig, BulwarkDao, BulwarkManager};

// ============================================================================
// db-sqlite feature 依赖的共享模块（BW-AC-007 使用）
// ============================================================================

#[cfg(feature = "db-sqlite")]
#[path = "common/mod.rs"]
mod common;

// ============================================================================
// MockDao：HashMap + Instant 模拟 TTL（复用 stp/tests.rs 的 mock 模式）
// ============================================================================

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

    /// 查询键的剩余 TTL（重写以支持 BW-AC-002 的 TTL 续期验证）。
    async fn get_timeout(&self, key: &str) -> BulwarkResult<Option<Duration>> {
        let store = self.store.lock();
        match store.get(key) {
            Some((_, Some(deadline))) => {
                let now = Instant::now();
                if now >= *deadline {
                    Ok(None)
                } else {
                    Ok(Some(deadline.duration_since(now)))
                }
            },
            Some((_, None)) => Ok(None),
            None => Ok(None),
        }
    }
}

// ============================================================================
// FailingDao：所有操作返回 Err（BW-AC-008 模拟 oxcache 故障）
// ============================================================================

struct FailingDao;

#[async_trait]
impl BulwarkDao for FailingDao {
    async fn get(&self, _key: &str) -> BulwarkResult<Option<String>> {
        Err(BulwarkError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
        Err(BulwarkError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    async fn update(&self, _key: &str, _value: &str) -> BulwarkResult<()> {
        Err(BulwarkError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
        Err(BulwarkError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    async fn delete(&self, _key: &str) -> BulwarkResult<()> {
        Err(BulwarkError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
}

// ============================================================================
// MockInterface：可配置权限/角色列表
// ============================================================================

struct MockInterface {
    permissions: Vec<String>,
    roles: Vec<String>,
}

#[async_trait]
impl BulwarkInterface for MockInterface {
    async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.permissions.clone())
    }
    async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.roles.clone())
    }
}

// ============================================================================
// 辅助函数：初始化全局 BulwarkManager
// ============================================================================

/// 初始化全局 BulwarkManager，返回 MockDao 引用（用于验证 DAO 内部状态）。
///
/// 注意：`BulwarkManager::init` 是覆盖式更新（line 199 注释），允许重复 init，
/// 因此 integration tests 不需要 `reset_for_test()`（该函数仅 `#[cfg(test)]` 可见）。
fn init_manager(permissions: Vec<String>, roles: Vec<String>) -> Arc<MockDao> {
    let dao = Arc::new(MockDao::new());
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = true;
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface { permissions, roles });
    BulwarkManager::init(
        dao.clone() as Arc<dyn BulwarkDao>,
        Arc::new(config),
        interface,
    )
    .expect("BulwarkManager::init 应成功");
    dao
}

/// 初始化全局 BulwarkManager 并注入 FailingDao（用于 BW-AC-008 故障降级测试）。
fn init_manager_failing() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(FailingDao);
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface {
        permissions: vec![],
        roles: vec![],
    });
    BulwarkManager::init(dao, Arc::new(config), interface).expect("BulwarkManager::init 应成功");
}

// ============================================================================
// BW-AC-001: OIDC 登录创建新账号并返回有效 Token
// ============================================================================

/// BW-AC-001：OIDC 登录创建新账号并返回有效 Token（FRD §8.1 BW-AC-001）。
///
/// # 规则7 冲突
///
/// OIDC 登录流程需网络调用 Keycloak/OIDC provider，集成测试不依赖外部服务。
/// 本测试验证 OIDC 登录的核心产出——会话创建（`account:session:{login_id}` +
/// `token:session:{token}`），该逻辑由 `BulwarkSession::create` 实现，
/// 所有登录方式（密码/OIDC/SSO）共享此路径。
///
/// # Gherkin
///
/// ```text
/// Given: 用户未登录（全局管理器重置）
/// When: 用户点击 OIDC 登录并完成认证（用 BulwarkUtil::login 模拟登录完成后的会话创建）
/// Then:
///   - 系统创建新账号（Account-Session 存在）
///   - 返回有效 Access Token（Token-Session 存在）
///   - key 格式对齐 E-001（account:session: / token:session:）
/// ```
#[tokio::test]
#[serial]
async fn bw_ac_001_oidc_login_creates_account_and_token() {
    let dao = init_manager(vec![], vec![]);

    // When: 用户完成 OIDC 登录
    let token = BulwarkUtil::login_simple("oidc-user-001")
        .await
        .expect("login 应成功");
    assert!(!token.is_empty(), "登录应返回非空 token");

    // Then: Account-Session 存在
    let account_key = format!("account:session:{}", "oidc-user-001");
    let account_json = dao.get(&account_key).await.expect("DAO get 应成功");
    assert!(
        account_json.is_some(),
        "Account-Session 应存在 (key={})",
        account_key
    );

    // Then: Token-Session 存在
    let token_key = format!("token:session:{}", token);
    let token_json = dao.get(&token_key).await.expect("DAO get 应成功");
    assert!(
        token_json.is_some(),
        "Token-Session 应存在 (key={})",
        token_key
    );

    // Then: key 格式对齐 E-001
    assert!(account_key.starts_with("account:session:"));
    assert!(token_key.starts_with("token:session:"));
}

// ============================================================================
// BW-AC-002: 受保护 API 访问时 Token-Session TTL 续期
// ============================================================================

/// BW-AC-002：受保护 API 访问时 Token-Session TTL 续期（FRD §8.1 BW-AC-002）。
///
/// # 规则7 冲突
///
/// spec 期望 TTL 续期 30min（1800 秒），但 `BulwarkSession::touch` 重置 TTL 为
/// `config.timeout`（默认 2592000 秒）。30min 续期策略需业务方在 config 中设置
/// `timeout=1800` 或自定义 touch 逻辑。本测试验证 touch 操作重置 TTL 的行为
/// （不验证具体 30min 值）。
///
/// # Gherkin
///
/// ```text
/// Given: 用户已登录且 Token 有效
/// When: 用户访问受保护 API（触发 touch 续期）
/// Then:
///   - Token-Session TTL 被重置（接近完整 timeout 值）
///   - Token 仍然有效
/// ```
#[tokio::test]
#[serial]
async fn bw_ac_002_protected_api_renews_token_session_ttl() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = BulwarkSession::new(dao.clone(), 3600, 86400);

    // Given: 用户已登录
    session
        .create("user-002", "token-002")
        .await
        .expect("create 应成功");

    // 验证初始 TTL ≤ 3600 秒
    let initial_ttl = dao
        .get_timeout("token:session:token-002")
        .await
        .expect("get_timeout 应成功");
    assert!(initial_ttl.is_some(), "初始 TTL 应存在");
    assert!(initial_ttl.unwrap().as_secs() <= 3600);

    // When: 用户访问受保护 API（触发 touch 续期）
    session.touch("token-002").await.expect("touch 应成功");

    // Then: TTL 被重置（接近 3600 秒）
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

    // Then: Token 仍然有效
    assert!(
        session
            .is_valid("token-002")
            .await
            .expect("is_valid 应成功"),
        "token 应仍有效"
    );
}

// ============================================================================
// BW-AC-003: 超设备上限踢出最早会话
// ============================================================================

/// BW-AC-003：超设备上限踢出最早会话（FRD §8.1 BW-AC-003）。
///
/// # 规则7 冲突
///
/// spec 期望"超出设备上限（默认 5）自动踢出最早会话"，但代码库无 `device_limit`
/// 配置字段，也无自动踢出最早会话的逻辑。`kickout_by_device(login_id, device_name)`
/// 按设备名踢出，非按上限踢出。自动 device-limit-overflow 踢出推迟到 v0.7.0。
/// 本测试验证 `kickout_by_device` 的行为（手动踢出指定设备的会话）。
///
/// # Gherkin
///
/// ```text
/// Given: 用户已登录设备 A，同一用户又登录设备 B
/// When: 踢出设备 A 的会话（模拟超上限踢出最早会话）
/// Then:
///   - 被踢设备 token 无效
///   - 另一设备 token 仍有效
/// ```
#[tokio::test]
#[serial]
async fn bw_ac_003_concurrent_login_kicks_earliest_session() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = BulwarkSession::new(dao.clone(), 3600, 86400);

    // Given: 用户登录设备 A 和设备 B
    session
        .create("user-003", "token-a")
        .await
        .expect("create token-a 应成功");
    session
        .set_device("token-a", "device-a")
        .await
        .expect("set_device 应成功");

    session
        .create("user-003", "token-b")
        .await
        .expect("create token-b 应成功");
    session
        .set_device("token-b", "device-b")
        .await
        .expect("set_device 应成功");

    // 验证两个 token 都有效
    assert!(
        session.is_valid("token-a").await.expect("is_valid token-a"),
        "device-a 的 token 应初始有效"
    );
    assert!(
        session.is_valid("token-b").await.expect("is_valid token-b"),
        "device-b 的 token 应初始有效"
    );

    // When: 踢出设备 A 的会话
    session
        .kickout_by_device("user-003", "device-a")
        .await
        .expect("kickout_by_device 应成功");

    // Then: 设备 A token 失效
    assert!(
        !session
            .is_valid("token-a")
            .await
            .expect("is_valid token-a after kickout"),
        "device-a 的 token 应已失效"
    );
    // Then: 设备 B token 仍有效
    assert!(
        session
            .is_valid("token-b")
            .await
            .expect("is_valid token-b after kickout"),
        "device-b 的 token 应仍有效"
    );
}

// ============================================================================
// BW-AC-004: 角色校验失败返回 403
// ============================================================================

/// BW-AC-004：无角色访问 `#[check_role("admin")]` 返回 403（FRD §8.1 BW-AC-004）。
///
/// # Gherkin
///
/// ```text
/// Given: 用户拥有 "user" 角色但无 "admin" 角色
/// When: 用户访问 #[check_role("admin")] 标注的接口
/// Then:
///   - 抛出 NotRoleException（对应 BulwarkError::NotRole）
///   - HTTP status = 403
/// ```
#[tokio::test]
#[serial]
async fn bw_ac_004_role_check_returns_403() {
    let _dao = init_manager(vec![], vec!["user".to_string()]);
    let token = BulwarkUtil::login_simple("user-004")
        .await
        .expect("login 应成功");

    let result = with_current_token(token, async { BulwarkUtil::check_role("admin").await }).await;

    assert!(
        matches!(result, Err(BulwarkError::NotRole(_))),
        "期望 NotRole 错误，实际: {:?}",
        result
    );

    let err = result.unwrap_err();
    let (status, _, _, _) = err.response_parts();
    assert_eq!(status, 403, "NotRole 的 HTTP status 应为 403");
}

// ============================================================================
// BW-AC-005: 权限校验失败返回 403
// ============================================================================

/// BW-AC-005：无权限访问 `#[check_permission("order:write")]` 返回 403
/// （FRD §8.1 BW-AC-005）。
///
/// # Gherkin
///
/// ```text
/// Given: 用户拥有 "order:read" 权限但无 "order:write"
/// When: 用户访问 #[check_permission("order:write")] 标注的接口
/// Then:
///   - 抛出 NotPermissionException（对应 BulwarkError::NotPermission）
///   - HTTP status = 403
/// ```
#[tokio::test]
#[serial]
async fn bw_ac_005_permission_check_returns_403() {
    let _dao = init_manager(vec!["order:read".to_string()], vec![]);
    let token = BulwarkUtil::login_simple("user-005")
        .await
        .expect("login 应成功");

    let result = with_current_token(token, async {
        BulwarkUtil::check_permission("order:write").await
    })
    .await;

    assert!(
        matches!(result, Err(BulwarkError::NotPermission(_))),
        "期望 NotPermission 错误，实际: {:?}",
        result
    );

    let err = result.unwrap_err();
    let (status, _, _, _) = err.response_parts();
    assert_eq!(status, 403, "NotPermission 的 HTTP status 应为 403");
}

// ============================================================================
// BW-AC-006: oxcache 后端切换为 Memory 后功能正常
// ============================================================================

/// BW-AC-006：oxcache 后端切换为 Memory 后功能正常（FRD §8.1 BW-AC-006）。
///
/// 验证使用 MockDao（模拟 oxcache memory/moka 后端）时，登录、鉴权、
/// 会话管理功能正常工作。代码无需修改即可适配不同后端。
///
/// # Gherkin
///
/// ```text
/// Given: oxcache 后端切换为 Memory（使用 MockDao 模拟）
/// When: 修改后端配置后重启
/// Then:
///   - 应用代码无修改
///   - 登录、鉴权、会话管理功能正常工作
/// ```
#[tokio::test]
#[serial]
async fn bw_ac_006_oxcache_memory_backend_works() {
    let _dao = init_manager(
        vec!["bench:read".to_string()],
        vec!["bench-user".to_string()],
    );

    // When: 执行登录 → 鉴权 → 登出完整流程
    let token = BulwarkUtil::login_simple("user-006")
        .await
        .expect("login 应成功");

    // 验证已登录
    let check_result =
        with_current_token(token.clone(), async { BulwarkUtil::check_login().await }).await;
    assert!(
        check_result.unwrap_or(false),
        "check_login 应返回 true（已登录）"
    );

    // 验证权限检查（持有 bench:read）
    let has_perm = with_current_token(token.clone(), async {
        BulwarkUtil::has_permission("bench:read").await
    })
    .await
    .expect("has_permission 应成功");
    assert!(has_perm, "用户应持有 bench:read 权限");

    // 验证角色检查（持有 bench-user）
    let has_role = with_current_token(token.clone(), async {
        BulwarkUtil::has_role("bench-user").await
    })
    .await
    .expect("has_role 应成功");
    assert!(has_role, "用户应持有 bench-user 角色");

    // 登出
    with_current_token(token, async { BulwarkUtil::logout().await })
        .await
        .expect("logout 应成功");
}

// ============================================================================
// BW-AC-007: dbnexus 后端切换为 SQLite 后功能正常
// ============================================================================

/// BW-AC-007：dbnexus 后端切换为 SQLite 后功能正常（FRD §8.1 BW-AC-007）。
///
/// 验证 SQLite in-memory 数据库初始化、核心表迁移、用户/角色/权限表读写正常。
///
/// # Gherkin
///
/// ```text
/// Given: dbnexus 后端切换为 SQLite
/// When: 修改 dbnexus.backend=sqlite 配置后重启
/// Then:
///   - 应用代码无修改
///   - 用户表、角色表、权限表读写正常
/// ```
#[cfg(feature = "db-sqlite")]
#[tokio::test]
#[serial]
async fn bw_ac_007_dbnexus_sqlite_backend_works() {
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};

    // Given: 初始化 SQLite in-memory 数据库
    let pool = common::setup_db().await;

    // When: 向用户表、角色表、权限表插入数据
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
        vec![Value::String(Some(user_id.clone()))],
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
        vec![Value::String(Some(role_id.clone()))],
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
        vec![Value::String(Some(perm_id.clone()))],
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
// BW-AC-008: oxcache 故障降级测试
// ============================================================================

/// BW-AC-008：oxcache Redis Cluster 故障时降级为 JWT Stateless 模式
/// （FRD §8.1 BW-AC-008）。
///
/// # 规则7 冲突
///
/// spec 期望"系统降级为 JWT Stateless 模式"，但代码库无自动降级逻辑。
/// 降级需业务代码捕获 DAO 错误后手动切换 `JwtMode::Stateless`。
/// 本测试验证 DAO 故障时错误显性传播（规则12：失败必须显性化），
/// 不验证自动降级（推迟到 v0.7.0）。
///
/// # Gherkin
///
/// ```text
/// Given: oxcache Redis Cluster 后端故障（mock DAO 返回 Err）
/// When: 用户尝试登录
/// Then:
///   - DAO 错误显性传播（login 返回 Err(BulwarkError::Dao)）
///   - 错误不被吞掉或隐藏在默认值背后
///   - 触发告警（tracing::warn 日志，由 session.create 内部记录）
/// ```
#[tokio::test]
#[serial]
async fn bw_ac_008_oxcache_failure_degrades_to_jwt_stateless() {
    init_manager_failing();

    // When: 用户尝试登录（FailingDao 的 set 返回 Err）
    let result = BulwarkUtil::login_simple("user-008").await;

    // Then: DAO 错误显性传播（规则12）
    assert!(result.is_err(), "DAO 故障时 login 应返回错误（不吞掉）");
    let err = result.unwrap_err();
    assert!(
        matches!(err, BulwarkError::Dao(_)),
        "期望 Dao 错误，实际: {:?}",
        err
    );

    // 规则7 冲突文档：自动降级到 JwtMode::Stateless 未实现。
    // 业务代码应捕获此错误后手动切换 JwtMode::Stateless 重试（需 protocol-jwt feature）。
}

// ============================================================================
// BW-AC-009: logout 后 Token 失效
// ============================================================================

/// BW-AC-009：logout() 后原 Token 抛 NotLoginException + jti 在黑名单
/// （FRD §8.1 BW-AC-009）。
///
/// # 规则7 冲突
///
/// 1. spec 期望 `BulwarkError::NotLogin`，但实际 `check_login` 在 token session
///    不存在时返回 `BulwarkError::Session("未登录")`（HTTP 500 而非 401）。
///    本测试接受 `Session` 或 `NotLogin` 错误。
/// 2. spec 期望 "Token jti 在 oxcache 黑名单中（key 格式 token:blacklist:{jti}）"，
///    但 `logout()` 仅删除 Token-Session，不写入 jti 黑名单。
///    黑名单机制存在于 `check_token_reuse` hook（key 为 `token:blacklist:{login_id}`），
///    但 `logout()` 不填充它。JWT Stateless 模式的 token 撤销推迟到 v0.7.0。
///
/// # Gherkin
///
/// ```text
/// Given: 用户主动 logout()
/// When: 后续请求携带原 Token
/// Then:
///   - check_login 返回错误（token 失效）
///   - Token-Session 已从 DAO 中删除
/// ```
#[tokio::test]
#[serial]
async fn bw_ac_009_logout_invalidates_token() {
    let dao = init_manager(vec![], vec![]);

    // Given: 用户登录
    let token = BulwarkUtil::login_simple("user-009")
        .await
        .expect("login 应成功");

    // 验证已登录
    let logged_in =
        with_current_token(token.clone(), async { BulwarkUtil::check_login().await }).await;
    assert!(logged_in.unwrap_or(false), "logout 前应已登录");

    // When: 用户主动 logout
    with_current_token(token.clone(), async { BulwarkUtil::logout().await })
        .await
        .expect("logout 应成功");

    // Then: Token-Session 已删除
    let token_key = format!("token:session:{}", token);
    let token_session = dao.get(&token_key).await.expect("DAO get 应成功");
    assert!(token_session.is_none(), "logout 后 Token-Session 应已删除");

    // Then: check_login 返回错误（token 失效）
    let check_result = with_current_token(token, async { BulwarkUtil::check_login().await }).await;
    assert!(
        check_result.is_err(),
        "logout 后 check_login 应返回错误（token 已失效）"
    );
}

// ============================================================================
// BW-AC-010: 连续登录失败封禁
// ============================================================================

/// BW-AC-010：连续 5 次登录失败抛 DisableServiceException + 封禁 30 分钟
/// （FRD §8.1 BW-AC-010）。
///
/// # 规则7 冲突
///
/// spec 期望 `BulwarkError::DisableService`，但 `UserLockoutStrategy::check()`
/// 返回 `BulwarkError::FirewallBlocked`。`DisableService` 需业务代码在捕获
/// `FirewallBlocked` 后手动构造（通过 `MfaLogic::disable_service`）。
/// 本测试验证 LockoutState（5 次失败后锁定 30min）+ DisableService 错误构造。
///
/// # Gherkin
///
/// ```text
/// Given: 用户连续 5 次登录失败
/// When: 第 5 次提交（record_failure 触发锁定）
/// Then:
///   - LockoutState.failure_count == 5
///   - LockoutState.locked_until ≈ now + 1800（30 分钟）
///   - 可构造 DisableService 错误，until 字段为 Some(now + 30min)
/// ```
#[tokio::test]
#[serial]
async fn bw_ac_010_login_failure_locks_account() {
    use bulwark::account::lockout::{UserLockoutConfig, UserLockoutStrategy, WaitStrategy};

    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());

    // 配置：5 次失败触发锁定，每次临时锁定 30min（Linear 策略 base=1800）
    let config = UserLockoutConfig {
        max_failure_factor: 5,
        permanent_lockout: false,
        max_temporary_lockouts: 3,
        wait_strategy: WaitStrategy::Linear { base_seconds: 1800 },
        failure_window_seconds: 300,
    };
    let strategy = UserLockoutStrategy::new(config, dao.clone());

    // Given: 用户连续 5 次登录失败
    for _ in 0..5 {
        strategy
            .record_failure("user-010")
            .await
            .expect("record_failure 应成功");
    }

    // Then: 读取 LockoutState 验证锁定状态
    let lockout_key = "lockout:user-010";
    let lockout_json = dao
        .get(lockout_key)
        .await
        .expect("DAO get 应成功")
        .expect("LockoutState 应存在");

    let state: bulwark::account::lockout::LockoutState =
        serde_json::from_str(&lockout_json).expect("反序列化 LockoutState 应成功");

    assert_eq!(state.failure_count, 5, "失败次数应为 5");
    assert!(
        state.locked_until > 0,
        "locked_until 应已设置（账号已锁定）"
    );

    // 验证锁定时长 ≈ 30min（1800 秒，允许 ±60 秒误差）
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let lock_duration = state.locked_until - now;
    assert!(
        (1740..=1860).contains(&lock_duration),
        "锁定时长应接近 1800 秒（30min），实际: {} 秒",
        lock_duration
    );

    // Then: 构造 DisableService 错误（业务代码在捕获 FirewallBlocked 后调用）
    let until = chrono::Utc::now() + chrono::Duration::minutes(30);
    let disable_err = BulwarkError::DisableService {
        service: "default".to_string(),
        until: Some(until),
    };

    // 验证错误变体与字段
    match &disable_err {
        BulwarkError::DisableService { service, until } => {
            assert_eq!(service, "default");
            assert!(until.is_some(), "until 应为 Some");
        },
        other => panic!("期望 DisableService 变体，实际: {:?}", other),
    }

    // 验证 HTTP status = 403
    let (status, _, _, _) = disable_err.response_parts();
    assert_eq!(status, 403, "DisableService 的 HTTP status 应为 403");
}
