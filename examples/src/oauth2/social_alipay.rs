//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 支付宝社交登录示例：演示 AlipayProvider 配置与使用。
//!
//! 对应模块：`src/protocol/social/alipay.rs`（`social-alipay` feature 开启时可用）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin social_alipay --features "social-alipay"
//! ```

use garrison::error::GarrisonResult;
use garrison::protocol::social::SocialLoginProvider;
use garrison::{AlipayProvider, SocialLoginService};
use std::sync::Arc;

/// 运行支付宝社交登录示例。
///
/// 演示 AlipayProvider 构造 + SocialLoginService 注册中心使用。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 支付宝社交登录示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 构造 AlipayProvider
    // ----------------------------------------------------------------
    println!("[1] 构造 AlipayProvider:");
    // 占位值，生产环境必须从环境变量/KMS 加载
    // AlipayProvider::new 需要 RSA 私钥 PEM，此处使用占位值演示构造方式
    // 占位值非合法 PEM，AlipayProvider::new 会返回 Err（预期行为）
    let alipay_result = AlipayProvider::new("alipay_app_id", "<PLACEHOLDER_RSA_PRIVATE_KEY_PEM>");
    match &alipay_result {
        Ok(_provider) => {
            println!("    ✓ AlipayProvider 已构造");
        },
        Err(e) => {
            println!(
                "    AlipayProvider 构造失败（预期，占位 RSA 密钥无效）: {}",
                e
            );
            println!("    生产环境请从 KMS/环境变量加载真实 RSA 私钥");
        },
    }
    println!();

    // ----------------------------------------------------------------
    // 2. 注册到 SocialLoginService 注册中心
    // ----------------------------------------------------------------
    println!("[2] SocialLoginService 注册中心:");
    let registry = SocialLoginService::new();

    // 若 AlipayProvider 构造成功则注册
    if let Ok(provider) = alipay_result {
        let provider: Arc<dyn SocialLoginProvider> = Arc::new(provider);
        registry.register("alipay", provider).unwrap();
        println!("    ✓ AlipayProvider 已注册为 \"alipay\"");
    }

    let providers = registry.list();
    println!("    已注册 providers: {:?}", providers);
    println!();

    // ----------------------------------------------------------------
    // 3. 社交登录 Provider 对比
    // ----------------------------------------------------------------
    println!("[3] 内置社交登录 Provider:");
    println!("    • WechatProvider: 微信扫码/小程序登录（social-wechat feature）");
    println!("    • AlipayProvider: 支付宝授权登录（social-alipay feature）");
    println!("    • 自定义 Provider: 实现 SocialLoginProvider trait + registry.register()");
    println!();
    println!("    SocialLoginProvider trait 方法:");
    println!("    • get_authorization_url(state, redirect_uri) → 授权页 URL");
    println!("    • exchange_token(code, state) → SocialUserInfo");
    println!("    • get_user_info(access_token) → SocialUserInfo");
    println!();

    println!("=== 示例执行完成 ===");
    Ok(())
}
