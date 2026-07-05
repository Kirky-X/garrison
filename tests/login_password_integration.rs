//! 密码登录端到端集成测试（v0.4.2 新增，依据 spec secure-password + auth-password-login）。
//!
//! 验证 `Argon2Hasher` / `BcryptHasher` / `PasswordVerifier` + `BulwarkLogicDefault::login_with_password`
//! 的完整链路：
//! 1. `PasswordHasher::hash` → `PasswordHasher::verify` roundtrip
//! 2. `PasswordVerifier::verify` 自动识别算法
//! 3. `BulwarkLogicDefault::with_password_hasher` + `with_user_repository` 注入
//! 4. `login_with_password` 成功路径（用户存在 + 密码匹配 → 签发 token）
//! 5. `login_with_password` 失败路径（用户不存在 / 密码错误 / 未配置 hasher/repository）
//! 6. listener 广播 LoginFailure 事件（user_not_found / wrong_password）
//!
//! 运行：`cargo test --features "secure-password db-sqlite listener cache-memory" --test login_password_integration`

#![cfg(all(
    feature = "secure-password",
    feature = "db-sqlite",
    feature = "cache-memory"
))]

use async_trait::async_trait;
use bulwark::dao::{
    init_dbnexus,
    repository::{sqlite::SqliteUserRepository, NewUser, UserRepository},
    BulwarkDao, BulwarkDaoOxcache, BulwarkMigration,
};
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::listener::{BulwarkEvent, BulwarkListener, BulwarkListenerManager};
use bulwark::secure::password::{Argon2Hasher, BcryptHasher, PasswordHasher, PasswordVerifier};
use bulwark::session::BulwarkSession;
use bulwark::stp::{BulwarkInterface, BulwarkLogic, BulwarkLogicDefault};
use serial_test::serial;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const TENANT: i64 = 0;

// ============================================================================
// MockInterface：BulwarkFirewallStrategyDefault::new() 必需
// ============================================================================

struct MockInterface;

#[async_trait]
impl BulwarkInterface for MockInterface {
    async fn get_permission_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
}

// ============================================================================
// 全局计数器：记录 listener 事件
// ============================================================================

static LOGIN_FAILURE_NOT_FOUND: AtomicUsize = AtomicUsize::new(0);
static LOGIN_FAILURE_WRONG_PASSWORD: AtomicUsize = AtomicUsize::new(0);

fn reset_listener_counters() {
    LOGIN_FAILURE_NOT_FOUND.store(0, Ordering::SeqCst);
    LOGIN_FAILURE_WRONG_PASSWORD.store(0, Ordering::SeqCst);
}

/// 测试用 listener：根据 login_id 区分 user_not_found (9999) 与 wrong_password (1001)。
///
/// v0.4.2 安全审计 A-014: 实现层 reason 统一为 "invalid_credentials"，
/// listener 无法仅凭 reason 区分两类失败，需借助 login_id（测试场景固定）。
struct PasswordLoginListener;

#[async_trait]
impl BulwarkListener for PasswordLoginListener {
    async fn on_event(&self, event: &BulwarkEvent) -> BulwarkResult<()> {
        if let BulwarkEvent::LoginFailure { login_id, reason } = event {
            // reason 现在统一为 "invalid_credentials"，用 login_id 区分场景
            if reason == "invalid_credentials" {
                if *login_id == 9999 {
                    LOGIN_FAILURE_NOT_FOUND.fetch_add(1, Ordering::SeqCst);
                } else if *login_id == 1001 {
                    LOGIN_FAILURE_WRONG_PASSWORD.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        Ok(())
    }
}

fn password_login_listener_factory() -> Arc<dyn BulwarkListener> {
    Arc::new(PasswordLoginListener)
}

inventory::submit! {
    bulwark::listener::BulwarkListenerEntry { factory: password_login_listener_factory }
}

// ============================================================================
// 辅助：定位迁移目录 + 初始化 SQLite in-memory + 迁移
// ============================================================================

fn project_migrations_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("migrations")
        .join("sqlite")
}

async fn setup_db() -> dbnexus::DbPool {
    let pool = init_dbnexus("sqlite::memory:")
        .await
        .expect("init_dbnexus 应成功");
    let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
    pool
}

// ============================================================================
// 1. PasswordHasher roundtrip（Argon2 + Bcrypt）
// ============================================================================

/// Argon2 hash → verify roundtrip：相同密码匹配，不同密码不匹配。
#[tokio::test]
async fn argon2_hash_verify_roundtrip() {
    let hasher = Argon2Hasher::new();
    let hash = hasher.hash("correct-password").expect("hash 应成功");
    assert!(
        hash.starts_with("$argon2"),
        "Argon2 哈希应以 $argon2 开头，实际: {}",
        &hash[..8.min(hash.len())]
    );

    assert!(
        hasher.verify("correct-password", &hash).unwrap(),
        "相同密码应匹配"
    );
    assert!(
        !hasher.verify("wrong-password", &hash).unwrap(),
        "不同密码应不匹配"
    );
}

/// Bcrypt hash → verify roundtrip。
#[tokio::test]
async fn bcrypt_hash_verify_roundtrip() {
    let hasher = BcryptHasher::with_cost(4); // 低 cost 加速测试
    let hash = hasher.hash("correct-password").expect("hash 应成功");
    assert!(
        hash.starts_with("$2"),
        "Bcrypt 哈希应以 $2 开头，实际: {}",
        &hash[..3.min(hash.len())]
    );

    assert!(
        hasher.verify("correct-password", &hash).unwrap(),
        "相同密码应匹配"
    );
    assert!(
        !hasher.verify("wrong-password", &hash).unwrap(),
        "不同密码应不匹配"
    );
}

/// Argon2 hash 不能被 Bcrypt verify（跨算法校验返回 false 或错误）。
#[tokio::test]
async fn cross_algorithm_verify_fails() {
    let argon2 = Argon2Hasher::new();
    let bcrypt = BcryptHasher::with_cost(4);

    let argon2_hash = argon2.hash("password").unwrap();
    let bcrypt_hash = bcrypt.hash("password").unwrap();

    // Argon2 hash 用 Bcrypt verify：应返回 false 或 Err（格式不匹配）
    let result = bcrypt.verify("password", &argon2_hash);
    assert!(
        !matches!(result, Ok(true)),
        "Argon2 hash 不应被 Bcrypt 验证为 true"
    );

    // Bcrypt hash 用 Argon2 verify：应返回 false 或 Err
    let result = argon2.verify("password", &bcrypt_hash);
    assert!(
        !matches!(result, Ok(true)),
        "Bcrypt hash 不应被 Argon2 验证为 true"
    );
}

/// PasswordVerifier 自动识别算法：Argon2 hash 用 Argon2 校验，Bcrypt hash 用 Bcrypt 校验。
#[tokio::test]
async fn password_verifier_auto_detects_algorithm() {
    let argon2 = Argon2Hasher::new();
    let bcrypt = BcryptHasher::with_cost(4);

    let argon2_hash = argon2.hash("secret").unwrap();
    let bcrypt_hash = bcrypt.hash("secret").unwrap();

    // PasswordVerifier::verify 应自动识别两个 hash 都校验通过
    assert!(
        PasswordVerifier::verify("secret", &argon2_hash).unwrap(),
        "PasswordVerifier 应识别 Argon2 hash 并校验通过"
    );
    assert!(
        PasswordVerifier::verify("secret", &bcrypt_hash).unwrap(),
        "PasswordVerifier 应识别 Bcrypt hash 并校验通过"
    );

    // 错误密码应校验失败
    assert!(
        !PasswordVerifier::verify("wrong", &argon2_hash).unwrap(),
        "Argon2 hash 错误密码应不匹配"
    );
    assert!(
        !PasswordVerifier::verify("wrong", &bcrypt_hash).unwrap(),
        "Bcrypt hash 错误密码应不匹配"
    );
}

// ============================================================================
// 2. login_with_password 端到端集成（真实 SQLite + Argon2 + UserRepository）
// ============================================================================

/// 构造 BulwarkLogicDefault 实例，注入 Argon2Hasher + SqliteUserRepository + ListenerManager。
async fn make_logic_with_password() -> Arc<BulwarkLogicDefault> {
    let pool = setup_db().await;
    let user_repo = Arc::new(SqliteUserRepository::new(pool.clone()));

    // 预置一个用户：username="1001", password_hash=Argon2("secret")
    let hasher = Argon2Hasher::new();
    let hash = hasher.hash("secret").unwrap();
    let new_user = NewUser {
        id: uuid::Uuid::new_v4().to_string(),
        username: "1001".to_string(),
        password_hash: hash,
        status: "active".to_string(),
    };
    user_repo
        .create(TENANT, new_user)
        .await
        .expect("预置用户应成功");

    // 构造 oxcache DAO
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let mut config = bulwark::config::BulwarkConfig::default_config();
    config.token_style = "uuid".to_string();
    config.timeout = 3600;
    config.throw_on_not_login = true;
    let firewall: Arc<dyn bulwark::strategy::BulwarkFirewallStrategy> = Arc::new(
        bulwark::strategy::BulwarkFirewallStrategyDefault::new(Arc::new(MockInterface)),
    );

    // BulwarkListenerManager::new() 自动收集 inventory 注册的 listener
    let lm = Arc::new(BulwarkListenerManager::new());

    Arc::new(
        BulwarkLogicDefault::new(session, Arc::new(config), firewall)
            .with_password_hasher(Arc::new(hasher))
            .with_user_repository(user_repo)
            .with_listener_manager(lm),
    )
}

/// login_with_password 成功路径：用户存在 + 密码匹配 → 返回 token。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn login_with_password_succeeds() {
    reset_listener_counters();
    let logic = make_logic_with_password().await;

    let token = logic.login_with_password(1001, "secret").await;
    assert!(
        token.is_ok(),
        "login_with_password 应成功: {:?}",
        token.err()
    );
    let token = token.unwrap();
    assert!(!token.is_empty(), "返回 token 不应为空");
}

/// login_with_password 用户不存在：返回 InvalidParam("invalid password")，广播 user_not_found。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn login_with_password_user_not_found() {
    reset_listener_counters();
    let logic = make_logic_with_password().await;

    let result = logic.login_with_password(9999, "secret").await;
    assert!(result.is_err(), "用户不存在应返回错误");
    match result.unwrap_err() {
        BulwarkError::InvalidParam(msg) => {
            assert_eq!(
                msg, "invalid password",
                "用户不存在应统一返回 'invalid password'，不泄露真实原因"
            );
        },
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }

    // listener 应广播 LoginFailure { reason: "invalid_credentials", login_id: 9999 }
    assert_eq!(
        LOGIN_FAILURE_NOT_FOUND.load(Ordering::SeqCst),
        1,
        "应广播 1 次 LoginFailure(login_id=9999) 事件"
    );
}

/// login_with_password 密码错误：返回 InvalidParam("invalid password")，广播 wrong_password。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn login_with_password_wrong_password() {
    reset_listener_counters();
    let logic = make_logic_with_password().await;

    let result = logic.login_with_password(1001, "wrong-password").await;
    assert!(result.is_err(), "密码错误应返回错误");
    match result.unwrap_err() {
        BulwarkError::InvalidParam(msg) => {
            assert_eq!(
                msg, "invalid password",
                "密码错误应统一返回 'invalid password'"
            );
        },
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }

    // listener 应广播 LoginFailure { reason: "invalid_credentials", login_id: 1001 }
    assert_eq!(
        LOGIN_FAILURE_WRONG_PASSWORD.load(Ordering::SeqCst),
        1,
        "应广播 1 次 LoginFailure(login_id=1001) 事件"
    );
}

/// login_with_password 未配置 hasher：返回 Config("password hasher not configured")。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn login_with_password_fails_without_hasher() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let mut config = bulwark::config::BulwarkConfig::default_config();
    config.token_style = "uuid".to_string();
    config.timeout = 3600;
    let firewall: Arc<dyn bulwark::strategy::BulwarkFirewallStrategy> = Arc::new(
        bulwark::strategy::BulwarkFirewallStrategyDefault::new(Arc::new(MockInterface)),
    );
    let logic_no_hasher = Arc::new(BulwarkLogicDefault::new(
        session,
        Arc::new(config),
        firewall,
    ));

    let result = logic_no_hasher.login_with_password(1001, "secret").await;
    assert!(result.is_err(), "未配置 hasher 应返回错误");
    match result.unwrap_err() {
        BulwarkError::Config(msg) => {
            assert!(
                msg.contains("password hasher not configured"),
                "错误消息应包含 'password hasher not configured'，实际: {}",
                msg
            );
        },
        other => panic!("期望 Config，实际: {:?}", other),
    }
}

/// login_with_password 未配置 user_repository：返回 Config("user repository not configured")。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn login_with_password_fails_without_user_repository() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let mut config = bulwark::config::BulwarkConfig::default_config();
    config.token_style = "uuid".to_string();
    config.timeout = 3600;
    let firewall: Arc<dyn bulwark::strategy::BulwarkFirewallStrategy> = Arc::new(
        bulwark::strategy::BulwarkFirewallStrategyDefault::new(Arc::new(MockInterface)),
    );
    let logic_no_repo = Arc::new(
        BulwarkLogicDefault::new(session, Arc::new(config), firewall)
            .with_password_hasher(Arc::new(Argon2Hasher::new())),
    );

    let result = logic_no_repo.login_with_password(1001, "secret").await;
    assert!(result.is_err(), "未配置 user_repository 应返回错误");
    match result.unwrap_err() {
        BulwarkError::Config(msg) => {
            assert!(
                msg.contains("user repository not configured"),
                "错误消息应包含 'user repository not configured'，实际: {}",
                msg
            );
        },
        other => panic!("期望 Config，实际: {:?}", other),
    }
}

// ============================================================================
// 3. 备注：BulwarkUtil::login_with_password 通过 BulwarkManager 注入的集成测试
// ============================================================================

// 注：BulwarkManager::init_with_factory_selector 当前为 pub(crate) 可见性，
// 集成测试无法注入自定义 factory 来预置 password_hasher + user_repository。
// 此场景由 src/stp/mod.rs 的单元测试 login_with_password_succeeds（行 2785+）覆盖，
// 该测试通过 BulwarkLogicDefault::new(...).with_password_hasher(...).with_user_repository(...)
// 直接构造 logic 实例验证。
//
// 后续 v0.5.0+ 可暴露 init_with_factory_selector 为 pub，支持集成测试自定义 factory。
