//! Token 风格示例：演示 UuidTokenStyle / Random64TokenStyle / SimpleTokenStyle 与 TokenStyleFactory。
//!
//! 对应模块：`src/core/token/mod.rs`（always on，无需 feature）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin token_styles --features full
//! ```

use bulwark::core::token::{
    Random64TokenStyle, SimpleTokenStyle, Token, TokenStyleFactory, UuidTokenStyle,
};
use bulwark::error::BulwarkResult;

/// 运行 Token 风格示例。
///
/// 演示 UUID v4 / Random64 / Simple 三种 token 风格的生成与校验，
/// 以及 TokenStyleFactory 按字符串创建对应风格。
pub fn run() -> BulwarkResult<()> {
    println!("=== Bulwark Token 风格示例 ===\n");

    // ----------------------------------------------------------------
    // 1. UUID v4 风格：标准 36 字符 UUID（无 payload，verify 返回 None）
    // ----------------------------------------------------------------
    let uuid_style = UuidTokenStyle;
    let token = uuid_style.generate("1001", 3600)?;
    println!("[1] UuidTokenStyle:");
    println!("    token = {}", token);
    println!("    长度 = {} 字符（8-4-4-4-12 hex）", token.len());
    assert_eq!(token.len(), 36);
    // UUID 无 payload，verify 始终返回 None
    assert_eq!(uuid_style.verify(&token)?, None);
    println!("    verify 返回 None（UUID 无 payload）\n");

    // ----------------------------------------------------------------
    // 2. Random64 风格：64 字符随机十六进制串
    // ----------------------------------------------------------------
    let random_style = Random64TokenStyle;
    let t1 = random_style.generate("1001", 3600)?;
    let t2 = random_style.generate("1001", 3600)?;
    println!("[2] Random64TokenStyle:");
    println!("    token 1 = {}", t1);
    println!("    token 2 = {}", t2);
    println!("    长度 = {} 字符（64 hex）", t1.len());
    assert_eq!(t1.len(), 64);
    assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(t1, t2); // 多次调用返回不同 token
    println!("    ✓ 全 hex 字符 + 多次调用互异\n");

    // ----------------------------------------------------------------
    // 3. Simple 风格：`<login_id>-<uuid>`，可解析 login_id
    // ----------------------------------------------------------------
    let simple_style = SimpleTokenStyle;
    let token = simple_style.generate("2002", 3600)?;
    println!("[3] SimpleTokenStyle:");
    println!("    token = {}", token);
    // verify 解析出 login_id
    let login_id = simple_style.verify(&token)?;
    assert_eq!(login_id, Some("2002".to_string()));
    println!("    verify 解析 login_id = {:?}", login_id);
    // parse 返回 TokenClaims
    let claims = simple_style.parse(&token)?;
    assert_eq!(claims.login_id, "2002");
    println!(
        "    parse 返回 TokenClaims {{ login_id: {} }}\n",
        claims.login_id
    );

    // ----------------------------------------------------------------
    // 4. TokenStyleFactory：按字符串创建对应风格
    // ----------------------------------------------------------------
    println!("[4] TokenStyleFactory 按字符串创建：");
    for style_name in &["uuid", "random_64", "simple"] {
        let handler = TokenStyleFactory::new(style_name, "unused-secret")?;
        let t = handler.generate("42", 60)?;
        println!("    {:>10} → {}", style_name, t);
    }

    // 未知风格返回 Config 错误
    let unknown = TokenStyleFactory::new("unknown", "secret");
    assert!(unknown.is_err());
    println!("\n    未知风格 \"unknown\" → 返回 Config 错误 ✓");

    // jwt 风格需启用 protocol-jwt feature（此处 full 已启用）
    #[cfg(feature = "protocol-jwt")]
    {
        let jwt_handler = TokenStyleFactory::new("jwt", "my-jwt-secret")?;
        let jwt_token = jwt_handler.generate("3003", 3600)?;
        println!("\n    jwt → {}", jwt_token);
        // verify 解析 login_id
        assert_eq!(jwt_handler.verify(&jwt_token)?, Some("3003".to_string()));
        println!("    jwt verify 解析 login_id = Some(3003) ✓");
    }

    println!("\n=== 示例执行完成 ===");
    Ok(())
}
