//! 会话管理示例：演示 Account-Session 与 Token-Session 双模会话。
//!
//! 流程：
//! 1. 创建 BulwarkSession（基于 oxcache DAO）
//! 2. 创建会话（login）→ Token-Session + Account-Session 双模记录
//! 3. 查询 Token-Session（get_token_session）
//! 4. 查询 Account-Session（get_account_session）
//! 5. 续期会话（renew）
//! 6. 活跃续期（touch）
//! 7. 会话临时存储（set/get）
//! 8. 校验会话有效性（is_valid）
//! 9. 登出单个 token（logout）
//! 10. 登出整个账号（logout_by_login_id）
//!
//! 运行方式：
//! ```sh
//! cargo run --example session_management --features "cache-memory"
//! ```

use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use bulwark::error::BulwarkResult;
use bulwark::session::BulwarkSession;
use std::sync::Arc;

#[tokio::main]
async fn main() -> BulwarkResult<()> {
    println!("=== Bulwark 会话管理示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 创建 BulwarkSession
    // ----------------------------------------------------------------
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await?);
    // timeout=3600 秒（1小时），active_timeout=86400 秒（1天）
    let session = BulwarkSession::new(dao, 3600, 86400);
    println!("[1] BulwarkSession 创建完成 (timeout=3600s, active_timeout=86400s)\n");

    // ----------------------------------------------------------------
    // 2. 创建会话（login）
    // ----------------------------------------------------------------
    let login_id = 1001;
    let token = "session_token_abc123";
    session.create(login_id, token).await?;
    println!("[2] 会话创建: login_id={}, token={}", login_id, token);
    println!("    Token-Session + Account-Session 双模记录已写入\n");

    // ----------------------------------------------------------------
    // 3. 查询 Token-Session
    // ----------------------------------------------------------------
    let ts = session.get_token_session(token).await?.expect("Token-Session 应存在");
    println!("[3] Token-Session 查询:");
    println!("    login_id = {}", ts.login_id);
    println!("    token = {}", ts.token);
    println!("    创建时间 = {}", ts.created_at);
    println!();

    // ----------------------------------------------------------------
    // 4. 查询 Account-Session
    // ----------------------------------------------------------------
    let as_ = session.get_account_session(login_id).await?.expect("Account-Session 应存在");
    println!("[4] Account-Session 查询:");
    println!("    login_id = {}", as_.login_id);
    println!("    关联 token 数 = {}", as_.tokens.len());
    println!("    tokens = {:?}", as_.tokens);
    println!();

    // ----------------------------------------------------------------
    // 5. 续期会话（renew）— 重置 TTL
    // ----------------------------------------------------------------
    session.renew(token).await?;
    println!("[5] 会话续期完成（TTL 已重置为 {} 秒）", 3600);
    println!();

    // ----------------------------------------------------------------
    // 6. 活跃续期（touch）— 仅更新 active_timeout
    // ----------------------------------------------------------------
    session.touch(token).await?;
    println!("[6] 活跃续期完成（active_timeout 已更新）");
    println!();

    // ----------------------------------------------------------------
    // 7. 会话临时存储（set/get）
    // ----------------------------------------------------------------
    session.set(token, "client_ip", "192.168.1.100").await?;
    let stored = session.get(token, "client_ip").await?;
    println!("[7] 会话临时存储:");
    println!("    set(client_ip, 192.168.1.100)");
    println!("    get(client_ip) = {:?}", stored);
    println!();

    // ----------------------------------------------------------------
    // 8. 校验会话有效性
    // ----------------------------------------------------------------
    let valid = session.is_valid(token).await?;
    println!("[8] 会话有效性校验: is_valid = {}", valid);
    println!();

    // ----------------------------------------------------------------
    // 9. 登出单个 token
    // ----------------------------------------------------------------
    session.logout(token).await?;
    println!("[9] 登出 token={}", token);
    let valid_after = session.is_valid(token).await?;
    println!("    登出后 is_valid = {}", valid_after);
    let ts_after = session.get_token_session(token).await?;
    println!("    登出后 get_token_session = {:?}", ts_after.map(|_| "存在").unwrap_or("None"));
    println!();

    // ----------------------------------------------------------------
    // 10. 多 token 登录 + 登出整个账号
    // ----------------------------------------------------------------
    // 再次登录创建两个 token
    session.create(login_id, "token_one").await?;
    session.create(login_id, "token_two").await?;
    println!("[10] 多 token 登录: token_one + token_two");

    let as_ = session.get_account_session(login_id).await?.expect("Account-Session 应存在");
    println!("     Account-Session token 数 = {}", as_.tokens.len());

    // 登出整个账号
    session.logout_by_login_id(login_id).await?;
    println!("     logout_by_login_id({}) 完成", login_id);

    let as_after = session.get_account_session(login_id).await?;
    println!("     登出后 Account-Session = {:?}", as_after.map(|_| "存在").unwrap_or("None"));

    println!("\n=== 示例执行完成 ===");
    Ok(())
}
