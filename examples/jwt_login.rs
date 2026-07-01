//! JWT 登录示例：演示 `JwtHandler` 签发 / 校验 / 刷新完整流程（依据 spec protocol-jwt）。
//!
//! 运行方式：
//! ```sh
//! cargo run --example jwt_login --features protocol-jwt
//! ```
//!
//! 本示例不依赖 `BulwarkManager` 全局单例，仅展示 `JwtHandler` 的独立用法。
//! 若需将 JWT 接入 Bulwark 会话体系，使用 `BulwarkUtil::login_by_token(token)` 将
//! 外部签发的 JWT 关联到 Bulwark 会话（详见 spec core-auth-api）。

#[cfg(not(feature = "protocol-jwt"))]
fn main() {
    eprintln!("此示例需要启用 protocol-jwt 特性：");
    eprintln!("  cargo run --example jwt_login --features protocol-jwt");
}

#[cfg(feature = "protocol-jwt")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bulwark::protocol::jwt::JwtHandler;

    println!("=== Bulwark JWT 登录示例 ===\n");

    // 1. 创建 JwtHandler，指定签名密钥（生产环境应从配置 / KMS 读取）
    let handler = JwtHandler::new("my-very-secret-key-please-rotate-me")
        .with_device("web-browser-chrome");

    // 2. 签发 JWT（模拟用户 1001 登录，有效期 1 小时）
    let login_id: i64 = 1001;
    let timeout_seconds: i64 = 3600;
    let token = handler.sign(login_id, timeout_seconds)?;
    println!("[签发] login_id={} 的 JWT：{}", login_id, token);

    // 3. 校验 JWT
    let claims = handler.verify(&token)?;
    println!(
        "[校验] 成功：sub={}, login_id={}, exp={}",
        claims.sub, claims.login_id, claims.exp
    );
    println!("       device={:?}", claims.device);

    // 4. 刷新 JWT（生成新 token，新有效期 2 小时）
    let new_token = handler.refresh(&token, 7200)?;
    println!("[刷新] 新 JWT：{}", new_token);
    assert_ne!(token, new_token, "刷新后 token 应为新签发的字符串");

    // 5. 校验新 token 仍有效
    let new_claims = handler.verify(&new_token)?;
    assert_eq!(new_claims.login_id, login_id);
    println!("[校验] 新 token 校验通过，login_id={}", new_claims.login_id);

    // 6. 演示过期 / 非法 token 的错误处理
    let tampered = format!("{}.{}.tampered", token.split('.').next().unwrap(), "");
    match handler.verify(&tampered) {
        Ok(_) => println!("[异常] 不应校验通过"),
        Err(e) => println!("[异常] 篡改的 token 校验失败（预期）：{}", e),
    }

    println!("\n=== 示例完成 ===");
    Ok(())
}
