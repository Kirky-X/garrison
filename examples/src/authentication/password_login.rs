//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 密码登录示例（v0.4.2 新增，依据 spec secure-password + auth-password-login）。
//!
//! 演示 `Argon2Hasher` 哈希/校验 + `GarrisonLogicDefault::login_with_password` 端到端流程。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin password_login --features "account-credential db-sqlite cache-memory"
//! ```
//!
//! 本示例使用内存 SQLite 数据库 + oxcache 内存 DAO，无需外部依赖即可运行。

use async_trait::async_trait;
use garrison::account::credential::password::{Argon2Hasher, PasswordHasher};
use garrison::dao::{
    init_dbnexus,
    repository::{sqlite::DbnexusUserRepository, NewUser, UserRepository},
    GarrisonDaoOxcache, GarrisonMigration,
};
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::session::GarrisonSession;
use garrison::stp::{GarrisonInterface, GarrisonLogicDefault, PasswordLogic};
use garrison::strategy::GarrisonPermissionStrategyDefault;
use garrison::GarrisonConfig;
use std::path::PathBuf;
use std::sync::Arc;

const TENANT: i64 = 0;

/// 空权限回调（示例用，业务方应实现真实权限数据源）。
struct NoopInterface;

#[async_trait]
impl GarrisonInterface for NoopInterface {
    async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
}

/// 运行密码登录示例。
///
/// 流程：
/// 1. 初始化 SQLite + oxcache
/// 2. 创建 Argon2Hasher 并预生成用户密码哈希
/// 3. 注入 hasher + user_repository 到 GarrisonLogicDefault
/// 4. 调用 `login_with_password` 验证密码并签发 token
/// 5. 演示错误路径（用户不存在 / 密码错误，统一返回 InvalidParam 防止用户枚举）
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Garrison 密码登录示例 ===\n");

    // 1. 初始化 SQLite + oxcache
    //    examples 为独立 workspace member，CWD 为 examples/，需指向工作区根的 migrations/
    let pool = init_dbnexus("sqlite::memory:").await?;
    let migration =
        GarrisonMigration::with_base_dir(pool.clone(), PathBuf::from("../migrations/sqlite"));
    migration.run_all().await?;
    let dao = Arc::new(GarrisonDaoOxcache::new().await?);

    // 2. 构造 hasher + user_repository
    let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());
    let user_repo: Arc<DbnexusUserRepository> = Arc::new(DbnexusUserRepository::new(pool.clone()));

    // 3. 预创建用户：login_id=1001，username="1001"
    //    login_with_password(login_id, password) 内部调用
    //    find_by_username(0, &login_id.to_string())，故 username 必须等于 login_id 的字符串形式
    let password_plain = "my-secret-password";
    let password_hash = hasher.hash(password_plain)?;
    println!("[1] Argon2 哈希生成");
    println!("    明文: {}", password_plain);
    println!("    哈希: {}...", &password_hash[..30]);

    user_repo
        .create(
            TENANT,
            NewUser {
                username: "1001".to_string(),
                password_hash,
                status: "active".to_string(),
            },
        )
        .await?;
    println!("[2] 用户已创建: login_id=1001, username=1001");

    // 4. 构造 GarrisonLogicDefault，注入 hasher + user_repository
    let config = Arc::new(GarrisonConfig::default_config());
    let timeout = u64::try_from(config.timeout).unwrap_or(3600);
    let session = Arc::new(GarrisonSession::new(dao, timeout, timeout));
    let firewall = Arc::new(GarrisonPermissionStrategyDefault::new(Arc::new(
        NoopInterface,
    )));
    let logic = GarrisonLogicDefault::new(session, config, firewall)
        .with_password_hasher(hasher)
        .with_user_repository(user_repo);

    // 5. 正确密码登录
    let token = logic
        .login_with_password("1001", "my-secret-password")
        .await?;
    println!("\n[3] 登录成功！");
    println!("    login_id: 1001");
    println!("    token: {}...", &token[..std::cmp::min(20, token.len())]);
    assert!(!token.is_empty());

    // 6. 错误密码登录（统一返回 InvalidParam 防止用户枚举）
    let wrong = logic.login_with_password("1001", "wrong-password").await;
    assert!(wrong.is_err(), "错误密码应登录失败");
    match &wrong {
        Err(GarrisonError::InvalidParam(msg)) if msg.contains("invalid password") => {
            println!("\n[4] 错误密码登录失败（预期）");
            println!("    error: InvalidParam(\"{}\")", msg);
            println!("    安全：用户不存在与密码错误返回相同错误，防止用户枚举");
        },
        other => {
            return Err(
                format!("期望 InvalidParam(\"invalid password\")，实际: {:?}", other).into(),
            );
        },
    }

    // 7. 不存在的用户登录（同样返回 InvalidParam 防止枚举）
    let not_exist = logic.login_with_password("9999", "any-password").await;
    assert!(not_exist.is_err());
    println!("\n[5] 不存在的用户登录失败（预期）");
    println!("    error: InvalidParam(\"invalid password\")");
    println!("    安全：与错误密码返回相同错误，无法区分用户是否存在");

    println!("\n=== 示例完成 ===");
    Ok(())
}
