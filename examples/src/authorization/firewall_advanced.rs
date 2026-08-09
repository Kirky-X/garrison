//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 高级防火墙策略示例：演示异地登录检测 / GeoIP 拦截 / WAF 请求校验。
//!
//! 对应模块：`src/strategy/firewall/`（各 `firewall-*` feature 开启时可用）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin firewall_advanced --features "firewall-anomalous,firewall-geoip,firewall-waf,cache-memory,web-axum"
//! ```

use garrison::error::GarrisonResult;

// ============================================================================
// 1. 异地登录检测（firewall-anomalous）
// ============================================================================

#[cfg(feature = "firewall-anomalous")]
fn demo_anomalous_detection() {
    use garrison::strategy::firewall::AnomalousConfig;

    println!("[1] 异地登录检测 (AnomalousLoginStrategy):");

    let config = AnomalousConfig {
        known_geo_threshold: 500, // 新登录地与历史地距离超 500km 则拦截
    };

    println!("    ✓ AnomalousConfig 已构造");
    println!("    距离阈值: {}km", config.known_geo_threshold);
    println!("    依赖注入:");
    println!("      • dao: Arc<dyn GarrisonDao>（存储用户历史登录 IP 地理坐标）");
    println!("      • geo_lookup: Arc<dyn GeoLookup>（IP → 坐标查询，生产用 maxminddb）");
    println!("    构造: AnomalousLoginStrategy::new(config, dao, geo_lookup)");
    println!("    场景: 用户 10:00 在北京登录，10:15 在上海登录 → 距离 > 500km → 拦截");
    println!();
}

#[cfg(not(feature = "firewall-anomalous"))]
fn demo_anomalous_detection() {
    println!("[1] 异地登录检测示例跳过（需启用 firewall-anomalous feature）\n");
}

// ============================================================================
// 2. GeoIP 地理位置拦截（firewall-geoip）
// ============================================================================

#[cfg(feature = "firewall-geoip")]
fn demo_geoip_blocking() {
    use garrison::strategy::firewall::GeoIPConfig;

    println!("[2] GeoIP 地理位置拦截 (GeoIPStrategy):");

    // 白名单模式
    let whitelist_config = GeoIPConfig {
        allowed_countries: vec!["CN".to_string(), "US".to_string(), "JP".to_string()],
        blocked_countries: vec![],
    };

    println!("    ✓ GeoIPConfig（白名单模式）:");
    println!("      允许国家: {:?}", whitelist_config.allowed_countries);
    println!("      依赖注入: country_lookup: Arc<dyn CountryLookup>");
    println!("      构造: GeoIPStrategy::new(config, country_lookup)");

    // 黑名单模式
    let blacklist_config = GeoIPConfig {
        allowed_countries: vec![],
        blocked_countries: vec!["KP".to_string(), "IR".to_string()],
    };

    println!("    ✓ GeoIPConfig（黑名单模式）:");
    println!("      拦截国家: {:?}", blacklist_config.blocked_countries);
    println!("    场景: 来自未允许国家的请求 → 返回 403 Forbidden");
    println!("    注意: 需要 GeoIP 数据库（firewall-maxminddb feature）提供 IP→国家映射");
    println!();
}

#[cfg(not(feature = "firewall-geoip"))]
fn demo_geoip_blocking() {
    println!("[2] GeoIP 地理位置拦截示例跳过（需启用 firewall-geoip feature）\n");
}

// ============================================================================
// 3. WAF 请求内容校验（firewall-waf）
// ============================================================================

#[cfg(feature = "firewall-waf")]
fn demo_waf_inspection() {
    println!("[3] WAF 请求内容校验 (firewall-waf):");
    println!("    WAF 提供请求内容安全检查能力:");
    println!("    • SQL 注入检测（union select / drop table 等模式）");
    println!("    • XSS 载荷检测（<script> / onerror 等模式）");
    println!("    • 路径遍历检测（../ 等模式）");
    println!("    • 请求体大小限制");
    println!("    集成方式: 作为 axum middleware 拦截请求");
    println!("    场景: POST /api/search body=\"' OR 1=1 --\" → WAF 拦截并返回 403");
    println!();
}

#[cfg(not(feature = "firewall-waf"))]
fn demo_waf_inspection() {
    println!("[3] WAF 请求内容校验示例跳过（需启用 firewall-waf feature）\n");
}

/// 运行高级防火墙策略示例。
///
/// 演示异地登录检测、GeoIP 拦截、WAF 请求校验。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 高级防火墙策略示例 ===\n");

    demo_anomalous_detection();
    demo_geoip_blocking();
    demo_waf_inspection();

    println!("=== 防火墙策略体系总览 ===");
    println!("  • BruteForceStrategy: IP 级暴力破解防护（firewall-bruteforce）");
    println!("  • RateLimitStrategy:  速率限制（firewall-ratelimit）");
    println!("  • DDoSStrategy:       DDoS 自适应限流（firewall-ddos）");
    println!("  • AnomalousLoginStrategy: 异地登录检测（firewall-anomalous）");
    println!("  • GeoIPStrategy:      地理位置拦截（firewall-geoip）");
    println!("  • WafHookChain:       请求内容校验（firewall-waf）");
    println!();

    println!("=== 示例执行完成 ===");
    Ok(())
}
