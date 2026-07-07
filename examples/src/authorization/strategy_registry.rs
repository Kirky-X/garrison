//! Strategy 注册表示例（v0.4.2 新增，依据 spec strategy-registry）。
//!
//! 演示 `Strategy` 注册表的运行时可插拔策略替换：
//! - `Strategy::new(logic)` 构造（6 个默认策略委托 BulwarkLogic）
//! - `register_*` 替换策略
//! - `getter` 查询当前策略
//! - `remove_*` 恢复默认策略
//! - 替换一个策略不影响其他策略
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin strategy_registry --features cache-memory
//! ```

use async_trait::async_trait;
use bulwark::config::BulwarkConfig;
use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use bulwark::error::BulwarkResult;
use bulwark::session::BulwarkSession;
use bulwark::stp::{BulwarkInterface, BulwarkLogicDefault};
use bulwark::strategy::FirewallLoginContext;
use bulwark::strategy::{
    BulwarkPermissionStrategyDefault, FirewallStrategy, LoginHandler, LogoutHandler, Strategy,
    TokenGenerator,
};
use std::sync::Arc;

struct NoopInterface;

#[async_trait]
impl BulwarkInterface for NoopInterface {
    async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
}

async fn make_logic() -> Arc<BulwarkLogicDefault> {
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await.unwrap());
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(NoopInterface);
    let timeout = u64::try_from(config.timeout).unwrap_or(3600);
    let session = Arc::new(BulwarkSession::new(dao, timeout, timeout));
    let firewall = Arc::new(BulwarkPermissionStrategyDefault::new(interface));
    Arc::new(BulwarkLogicDefault::new(session, config, firewall))
}

// ============================================================================
// 自定义策略实现（演示可插拔）
// ============================================================================

/// 自定义登录策略：返回带前缀的 token。
struct CustomLoginHandler;

#[async_trait]
impl LoginHandler for CustomLoginHandler {
    async fn handle_login(&self, login_id: &str) -> BulwarkResult<String> {
        Ok(format!("custom-login-token-{}", login_id))
    }
}

/// 自定义 token 生成策略：UUID 风格。
struct UuidTokenGenerator;

#[async_trait]
impl TokenGenerator for UuidTokenGenerator {
    async fn generate_token(&self, _login_id: &str) -> BulwarkResult<String> {
        Ok(format!("uuid-{}-{}", chrono_timestamp(), _login_id))
    }
    async fn refresh_token(&self, token: &str) -> BulwarkResult<String> {
        Ok(format!("refreshed-{}", token))
    }
}

fn chrono_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 自定义登出策略：记录日志。
struct LoggingLogoutHandler;

#[async_trait]
impl LogoutHandler for LoggingLogoutHandler {
    async fn handle_logout(&self) -> BulwarkResult<()> {
        println!("    [LoggingLogoutHandler] 用户登出");
        Ok(())
    }
    async fn handle_logout_by_login_id(&self, login_id: &str) -> BulwarkResult<()> {
        println!("    [LoggingLogoutHandler] 用户 {} 登出", login_id);
        Ok(())
    }
}

/// 自定义防火墙策略：始终放行（演示）。
struct AlwaysPassFirewall;

#[async_trait]
impl FirewallStrategy for AlwaysPassFirewall {
    async fn check_login_hooks(
        &self,
        _login_id: &str,
        _ctx: &FirewallLoginContext,
    ) -> BulwarkResult<()> {
        // 实际生产应实现真实的防火墙规则
        Ok(())
    }
}

/// 运行 Strategy 注册表示例。
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark Strategy 注册表示例 ===\n");

    // 1. 构造 Strategy（6 个默认策略委托 BulwarkLogicDefault）
    let logic = make_logic().await;
    let mut strategy = Strategy::new(logic);
    println!("[1] Strategy::new(logic) 构造完成");
    println!("    6 个默认策略：");
    println!("      - LoginHandler       → DefaultLoginHandler（委托 logic.login）");
    println!("      - LogoutHandler      → DefaultLogoutHandler（委托 logic.logout）");
    println!(
        "      - PermissionHandler  → DefaultPermissionHandler（委托 logic.check_permission）"
    );
    println!("      - TokenGenerator     → DefaultTokenGenerator（委托 logic.login）");
    println!("      - SessionCreator     → DefaultSessionCreator（委托 logic.login_with_token）");
    println!("      - FirewallStrategy   → DefaultFirewallStrategy（no-op，返回 Ok）\n");

    // 2. 默认登录策略生成 token
    println!("[2] 默认登录策略生成 token");
    let default_token = strategy.login_handler().handle_login("1001").await?;
    println!(
        "    默认 token: {}...",
        &default_token[..std::cmp::min(20, default_token.len())]
    );
    assert!(!default_token.is_empty());

    // 3. 运行时替换 LoginHandler
    println!("\n[3] 运行时替换 LoginHandler");
    strategy.register_login_handler(Arc::new(CustomLoginHandler));
    let custom_token = strategy.login_handler().handle_login("1001").await?;
    println!("    自定义 token: {}", custom_token);
    assert_eq!(custom_token, "custom-login-token-1001");

    // 4. 替换一个不影响其他（LogoutHandler 仍是默认）
    println!("\n[4] 替换 LoginHandler 不影响 LogoutHandler");
    let logout_result = strategy
        .logout_handler()
        .handle_logout_by_login_id("1001")
        .await;
    println!(
        "    LogoutHandler.handle_logout_by_login_id(1001) → {:?}",
        logout_result.is_ok()
    );
    assert!(logout_result.is_ok(), "LogoutHandler 应仍是默认实现");

    // 5. 同时替换多个策略
    println!("\n[5] 同时替换多个策略");
    strategy.register_token_generator(Arc::new(UuidTokenGenerator));
    strategy.register_logout_handler(Arc::new(LoggingLogoutHandler));
    strategy.register_firewall_strategy(Arc::new(AlwaysPassFirewall));

    let gen_token = strategy.token_generator().generate_token("2002").await?;
    println!("    TokenGenerator.generate_token(2002) → {}", gen_token);
    assert!(gen_token.starts_with("uuid-"));

    let logout_result = strategy.logout_handler().handle_logout().await;
    println!(
        "    LogoutHandler.handle_logout() → {:?}",
        logout_result.is_ok()
    );

    let ctx = FirewallLoginContext::new("1001");
    let firewall_result = strategy
        .firewall_strategy()
        .check_login_hooks("1001", &ctx)
        .await;
    println!(
        "    FirewallStrategy.check_login_hooks() → {:?}",
        firewall_result.is_ok()
    );

    // 6. remove 恢复默认
    println!("\n[6] remove_login_handler 恢复默认");
    strategy.remove_login_handler();
    let restored_token = strategy.login_handler().handle_login("1001").await?;
    println!(
        "    恢复后 token: {}...",
        &restored_token[..std::cmp::min(20, restored_token.len())]
    );
    assert_ne!(
        restored_token, "custom-login-token-1001",
        "remove 后应恢复默认"
    );

    // 7. 全部恢复默认
    println!("\n[7] 全部恢复默认");
    strategy.remove_logout_handler();
    strategy.remove_token_generator();
    strategy.remove_firewall_strategy();
    println!("    6 个策略全部恢复默认实现");

    // 验证恢复后仍可正常工作
    let final_token = strategy.login_handler().handle_login("3003").await?;
    assert!(!final_token.is_empty());
    println!("    验证：login(3003) → token 生成成功");

    println!("\n=== 示例完成 ===");
    println!("\nStrategy 注册表适用场景：");
    println!("  - A/B 测试：运行时切换登录策略（如 token 格式实验）");
    println!("  - 灰度发布：逐步将自定义策略推送给部分流量");
    println!("  - 多租户：不同租户使用不同权限校验策略");
    println!("  - 临时降级：主策略故障时切换到简化策略");
    println!("  - 合规审计：注入日志记录策略，不影响主流程");
    Ok(())
}
