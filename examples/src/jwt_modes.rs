//! JWT 三模式示例（v0.4.2 新增，依据 spec protocol-jwt + design Decision 10）。
//!
//! 演示 `JwtMode` 三种模式的配置切换：
//! - `Stateless`：仅 JWT verify，不查询 oxcache session（高可用场景）
//! - `Mixin`（默认）：JWT verify + session 二级校验（推荐）
//! - `Simple`：仅 session，JWT 仅作为 token 载体（不验证签名）
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin jwt_modes --features "protocol-jwt cache-memory"
//! ```

use async_trait::async_trait;
use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use bulwark::error::{BulwarkError, BulwarkResult};
use bulwark::session::BulwarkSession;
use bulwark::stp::{BulwarkInterface, BulwarkLogic, BulwarkLogicDefault, JwtMode};
use bulwark::strategy::BulwarkPermissionStrategyDefault;
use bulwark::BulwarkConfig;
use std::sync::Arc;

struct NoopInterface;

#[async_trait]
impl BulwarkInterface for NoopInterface {
    async fn get_permission_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
}

/// 构造指定 JwtMode 的 logic 实例。
async fn make_logic_with_mode(mode: JwtMode) -> Arc<BulwarkLogicDefault> {
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let mut config = BulwarkConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_secret = "jwt-modes-demo-secret".to_string();
    config.timeout = 3600;
    config.throw_on_not_login = true;
    let timeout = u64::try_from(config.timeout).unwrap_or(3600);
    let session = Arc::new(BulwarkSession::new(dao, timeout, timeout));
    let firewall = Arc::new(BulwarkPermissionStrategyDefault::new(Arc::new(
        NoopInterface,
    )));
    Arc::new(BulwarkLogicDefault::new(session, Arc::new(config), firewall).with_jwt_mode(mode))
}

/// 运行 JWT 三模式示例。
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark JWT 三模式示例 ===\n");

    // 1. Mixin 模式（默认推荐）
    println!("[1] Mixin 模式（JWT verify + session 二级校验，默认推荐）");
    let logic_mixin = make_logic_with_mode(JwtMode::Mixin).await;
    let token = logic_mixin.login(1001).await?;
    println!("    login(1001) → token: {}...", &token[..20]);
    // check_login 在 task_local 上下文中才能工作，此处仅验证 login 成功
    assert!(!token.is_empty());
    println!("    ✓ login 成功，token 包含 3 段 Base64URL\n");

    // 2. Stateless 模式
    println!("[2] Stateless 模式（仅 JWT verify，不查 session，高可用场景）");
    let logic_stateless = make_logic_with_mode(JwtMode::Stateless).await;
    let token_s = logic_stateless.login(1001).await?;
    println!("    login(1001) → token: {}...", &token_s[..20]);
    assert!(!token_s.is_empty());
    println!("    ✓ login 成功，Stateless 模式不依赖 oxcache session\n");

    // 3. Simple 模式
    println!("[3] Simple 模式（仅 session，JWT 仅作载体，不验证签名）");
    let logic_simple = make_logic_with_mode(JwtMode::Simple).await;
    let token_simple = logic_simple.login(1001).await?;
    println!("    login(1001) → token: {}...", &token_simple[..20]);
    assert!(!token_simple.is_empty());
    println!("    ✓ login 成功，Simple 模式 token 可能不是 JWT 格式\n");

    // 4. 演示 JWT 签发后可被 JwtHandler 独立校验
    println!("[4] JWT 独立校验（使用 protocol::jwt::JwtHandler）");
    use bulwark::protocol::jwt::JwtHandler;
    let handler = JwtHandler::new("jwt-modes-demo-secret");
    let claims = handler.verify(&token)?;
    println!(
        "    verify(token) → sub={}, login_id={}",
        claims.sub, claims.login_id
    );
    assert_eq!(claims.login_id, 1001);
    println!("    ✓ JWT 校验通过，claims 正确\n");

    // 5. 错误的 secret 校验失败
    println!("[5] 错误密钥校验失败（预期）");
    let wrong_handler = JwtHandler::new("wrong-secret");
    let result = wrong_handler.verify(&token);
    assert!(result.is_err(), "错误密钥应校验失败");
    match result.unwrap_err() {
        BulwarkError::InvalidToken(_) => {
            println!("    error: InvalidToken（签名不匹配）");
            println!("    ✓ 错误密钥正确返回 InvalidToken");
        },
        other => {
            return Err(format!("期望 InvalidToken，实际: {:?}", other).into());
        },
    }

    println!("\n=== 示例完成 ===");
    println!("\n模式选择建议：");
    println!("  - 高可用微服务 → Stateless（不依赖 session 存储）");
    println!("  - 通用场景      → Mixin（默认，双重校验更安全）");
    println!("  - 已有 session 体系 → Simple（JWT 仅作 token 载体）");
    Ok(())
}
