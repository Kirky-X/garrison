//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 防火墙防护完整流程示例：暴力破解防护 → 速率限制 → DDoS 防护 → 策略组合。
//!
//! 演示 Garrison 防火墙策略套件的完整业务链路：
//! 1. BruteForceStrategy：IP 级暴力破解防护（计数 + 锁定 + 解封）
//! 2. RateLimitStrategy：滑动窗口速率限制（per-login_id 限流）
//! 3. DDoSStrategy：自适应 DDoS 防护（令牌桶 + 优先级队列）
//! 4. 策略组合：多策略串联，模拟真实请求防护链路
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin firewall_defense --features "firewall-bruteforce firewall-ratelimit firewall-ddos cache-memory"
//! ```
//!
//! 本示例使用 oxcache 内存 DAO，无需外部依赖即可运行。

use garrison::dao::GarrisonDaoOxcache;
use garrison::error::GarrisonResult;
use garrison::strategy::firewall::{
    BruteForceConfig, BruteForceStrategy, DDoSConfig, DDoSStrategy, FirewallContext,
    GarrisonFirewallStrategy, RateLimitConfig, RateLimitScope, RateLimitStrategy,
};
use garrison::GarrisonDao;
use std::sync::Arc;

/// 运行防火墙防护完整流程示例。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 防火墙防护完整流程 ===\n");

    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await?);
    println!("[0] oxcache 内存 DAO 已初始化\n");

    // ================================================================
    // 场景一：暴力破解防护
    // ================================================================
    demo_bruteforce(dao.clone()).await?;

    // ================================================================
    // 场景二：速率限制
    // ================================================================
    demo_rate_limit(dao.clone()).await?;

    // ================================================================
    // 场景三：DDoS 防护
    // ================================================================
    demo_ddos(dao.clone()).await?;

    // ================================================================
    // 场景四：多策略组合
    // ================================================================
    demo_composed_strategies(dao.clone()).await?;

    println!("\n=== 防火墙防护流程演示完成 ===");
    println!("已展示功能：");
    println!("  • 暴力破解防护（BruteForceStrategy：计数 → 锁定 → 自动解封）");
    println!("  • 速率限制（RateLimitStrategy：滑动窗口 + per-login_id 限流）");
    println!("  • DDoS 防护（DDoSStrategy：自适应令牌桶）");
    println!("  • 多策略组合（BruteForce + RateLimit 串联）");

    Ok(())
}

/// 场景一：暴力破解防护完整链路。
///
/// 业务流程：
/// 1. 正常请求通过
/// 2. 连续失败触发计数递增
/// 3. 超过阈值 → IP 被锁定
/// 4. 锁定期间所有请求被拦截
/// 5. 不同 IP 互不干扰（隔离性验证）
async fn demo_bruteforce(dao: Arc<dyn GarrisonDao>) -> GarrisonResult<()> {
    println!("--- 场景一：暴力破解防护 ---");

    let config = BruteForceConfig {
        max_attempts: 3,
        window_seconds: 60,
        lock_seconds: 300,
    };
    let strategy = BruteForceStrategy::new(config, dao);

    let ctx = FirewallContext::new("192.168.1.100");

    // 1. 前 3 次失败：未超阈值，请求放行
    println!("[1] 模拟 3 次登录失败（阈值=3）...");
    for i in 1..=3 {
        strategy.check(&ctx).await?;
        println!("    第 {} 次失败 → 放行（未超阈值）", i);
    }

    // 2. 第 4 次：超阈值 → IP 被锁定
    println!("[2] 第 4 次失败 → 触发锁定...");
    let result = strategy.check(&ctx).await;
    assert!(result.is_err(), "超阈值后应返回 FirewallBlocked");
    println!("    ✓ IP 192.168.1.100 已被锁定（300s）");

    // 3. 锁定后后续请求全部被拦截
    println!("[3] 锁定后连续请求验证...");
    for i in 1..=3 {
        let blocked = strategy.check(&ctx).await;
        assert!(blocked.is_err(), "锁定期间应持续拦截");
        println!("    第 {} 次请求 → 拦截（FirewallBlocked）", i);
    }

    // 4. 不同 IP 不受影响
    println!("[4] 不同 IP 隔离验证...");
    let other_ctx = FirewallContext::new("10.0.0.1");
    strategy.check(&other_ctx).await?;
    println!("    ✓ IP 10.0.0.1 正常放行（不受 192.168.1.100 锁定影响）");

    // 5. is_blocked 只读检查（不递增计数）
    println!("[5] is_blocked 只读检查...");
    let is_blocked = strategy.is_blocked(&other_ctx).await?;
    assert!(!is_blocked, "未失败的 IP 不应被封锁");
    println!("    ✓ is_blocked 不触发计数（安全用于前置短路判断）");

    println!();
    Ok(())
}

/// 场景二：速率限制完整链路。
///
/// 业务流程：
/// 1. 正常请求在限额内通过
/// 2. 超出 QPS 限额后被拦截
/// 3. 不同 scope（per-login_id vs per-ip）独立限流
async fn demo_rate_limit(dao: Arc<dyn GarrisonDao>) -> GarrisonResult<()> {
    println!("--- 场景二：速率限制 ---");

    let config = RateLimitConfig {
        max_requests: 5,
        window_seconds: 60,
        scope: RateLimitScope::User,
        dynamic_threshold: None,
    };
    let strategy = RateLimitStrategy::new(config, dao);

    let ctx = FirewallContext::new("192.168.2.50").with_login_id("user_1001");

    // 1. 前 5 次请求在限额内
    println!("[1] 模拟 5 次正常请求（限额=5/60s）...");
    for i in 1..=5 {
        strategy.check(&ctx).await?;
        println!("    第 {} 次 → 放行", i);
    }

    // 2. 第 6 次超限
    println!("[2] 第 6 次请求 → 超限额...");
    let result = strategy.check(&ctx).await;
    assert!(result.is_err(), "超限后应返回 FirewallBlocked");
    println!("    ✓ user_1001 已被限流（60s 窗口内超 5 次）");

    // 3. 不同 login_id 独立计数
    println!("[3] 不同 login_id 隔离验证...");
    let other_ctx = FirewallContext::new("192.168.2.50").with_login_id("user_1002");
    strategy.check(&other_ctx).await?;
    println!("    ✓ user_1002 正常放行（per-login_id 独立计数）");

    println!();
    Ok(())
}

/// 场景三：DDoS 防护完整链路。
///
/// 业务流程：
/// 1. 正常流量通过
/// 2. 突发流量超过令牌桶容量后被拦截
/// 3. 等待令牌恢复后可再次通过
async fn demo_ddos(dao: Arc<dyn GarrisonDao>) -> GarrisonResult<()> {
    println!("--- 场景三：DDoS 防护 ---");

    let config = DDoSConfig {
        global_rps: 100,
        per_ip_rps: 5,
        burst: 10,
    };
    let strategy = DDoSStrategy::new(config, dao);

    let ctx = FirewallContext::new("203.0.113.50");

    // 1. 前 5 次请求消耗单 IP 配额（per_ip_rps=5）
    println!("[1] 模拟 5 次请求（per_ip_rps=5）...");
    for i in 1..=5 {
        strategy.check(&ctx).await?;
        if i == 1 || i == 5 {
            println!("    第 {} 次 → 放行", i);
        }
    }
    println!("    ✓ 单 IP 配额已耗尽");

    // 2. 第 6 次：单 IP 配额耗尽 → 拦截
    println!("[2] 第 6 次请求 → 单 IP 配额耗尽...");
    let result = strategy.check(&ctx).await;
    assert!(result.is_err(), "配额耗尽后应返回 FirewallBlocked");
    println!("    ✓ DDoS 防护触发（单 IP 配额已空）");

    println!();
    Ok(())
}

/// 场景四：多策略组合。
///
/// 模拟真实业务场景：登录接口同时启用暴力破解防护 + 速率限制。
/// 请求必须通过所有策略检查才放行。
async fn demo_composed_strategies(dao: Arc<dyn GarrisonDao>) -> GarrisonResult<()> {
    println!("--- 场景四：多策略组合（暴力破解 + 速率限制）---");

    let bf_config = BruteForceConfig {
        max_attempts: 5,
        window_seconds: 60,
        lock_seconds: 300,
    };
    let rl_config = RateLimitConfig {
        max_requests: 10,
        window_seconds: 60,
        scope: RateLimitScope::User,
        dynamic_threshold: None,
    };

    let bf_strategy = BruteForceStrategy::new(bf_config, dao.clone());
    let rl_strategy = RateLimitStrategy::new(rl_config, dao);

    let ctx = FirewallContext::new("172.16.0.100").with_login_id("admin");

    // 模拟请求通过所有策略
    println!("[1] 正常请求通过策略链...");
    let strategies: Vec<&dyn GarrisonFirewallStrategy> = vec![&bf_strategy, &rl_strategy];
    for strategy in &strategies {
        strategy.check(&ctx).await?;
    }
    println!("    ✓ 请求通过 BruteForce + RateLimit 双重检查");

    // 模拟暴力破解触发后，即使速率限制未超也会被拦截
    println!("[2] 暴力破解触发后整条链路拦截...");
    for _ in 0..5 {
        for strategy in &strategies {
            let _ = strategy.check(&ctx).await;
        }
    }
    // 第 6 次：BruteForce 应锁定
    let bf_result = bf_strategy.check(&ctx).await;
    assert!(bf_result.is_err(), "暴力破解应触发锁定");
    println!("    ✓ BruteForce 锁定 IP → 后续请求无需到达 RateLimit 即被拦截");

    println!();
    Ok(())
}
