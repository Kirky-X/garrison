//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! IP 级防火墙策略套件模块。
//!
//! ## 设计
//!
//! - [`GarrisonFirewallStrategy`](crate::strategy::firewall::GarrisonFirewallStrategy) trait：定义 `check(&self, ctx: &FirewallContext) -> GarrisonResult<()>` 契约
//! - [`FirewallContext`](crate::strategy::firewall::FirewallContext)：携带 IP / login_id / tenant_id 供策略决策
//! - [`StrategyRegistration`](crate::strategy::firewall::StrategyRegistration)：inventory 注册项，5 个 strategy 通过 `inventory::submit!` 注册
//!
//! ## 5 个 strategy（各自独立 feature）
//!
//! | Strategy | Feature | 算法 |
//! |----------|---------|------|
//! | `BruteForceStrategy` | `firewall-bruteforce` | oxcache 计数 + 锁定 |
//! | `RateLimitStrategy` | `firewall-ratelimit` | 滑动窗口 |
//! | `AnomalousLoginStrategy` | `firewall-anomalous` | haversine + maxminddb |
//! | `DDoSStrategy` | `firewall-ddos` | token bucket |
//! | `GeoIPStrategy` | `firewall-geoip` | maxminddb 国家码 |
//!
//! ## 与现有 trait 的区分
//!
//! - [`GarrisonPermissionStrategy`](crate::strategy::GarrisonPermissionStrategy)（v0.3.0）：权限/角色校验
//! - [`FirewallStrategy`](crate::strategy::registry::FirewallStrategy)（v0.4.2）：登录前钩子检查
//! - [`GarrisonFirewallStrategy`](crate::strategy::firewall::GarrisonFirewallStrategy)（v0.5.0，本 trait）：IP 级防火墙拦截

use crate::error::GarrisonResult;
use async_trait::async_trait;

/// 异地登录检测策略。
#[cfg(feature = "firewall-anomalous")]
pub mod anomalous;
/// 异常登录定时分析引擎（双引擎的定时部分，与实时引擎 anomalous.rs 互补）。
#[cfg(feature = "anomalous-detector-dual")]
pub mod anomalous_analyzer;
/// 暴力破解防护策略。
#[cfg(feature = "firewall-bruteforce")]
pub mod brute_force;
/// 数学验证码提供商（基础 CAPTCHA 实现）。
#[cfg(feature = "firewall-ratelimit")]
pub mod captcha_provider;
/// DDoS 防护策略。
#[cfg(feature = "firewall-ddos")]
pub mod ddos;
/// IP 地理位置查询抽象（firewall-anomalous / firewall-geoip 共享）。
#[cfg(any(feature = "firewall-anomalous", feature = "firewall-geoip"))]
pub mod geo;
/// GeoIP 地理位置拦截策略。
#[cfg(feature = "firewall-geoip")]
pub mod geoip;
/// 速率限制策略。
#[cfg(feature = "firewall-ratelimit")]
pub mod rate_limit;
/// WAF 级防火墙（策略层 Hook 链 + 9 个内置 Hook）。
#[cfg(feature = "firewall-waf")]
pub mod waf;
/// WAF Hook 实现（9 个内置 Hook）。
#[cfg(feature = "firewall-waf")]
pub mod waf_hooks;

// ============================================================================
// 模块重导出：通过 mod 路径访问子模块类型（避免外部代码引用具体文件路径）
// ============================================================================

#[cfg(feature = "firewall-bruteforce")]
pub use brute_force::{BruteForceConfig, BruteForceStrategy};

#[cfg(feature = "firewall-ratelimit")]
pub use rate_limit::{RateLimitConfig, RateLimitScope, RateLimitStrategy};

#[cfg(feature = "firewall-anomalous")]
pub use anomalous::{AnomalousConfig, AnomalousLoginStrategy};

#[cfg(feature = "firewall-ddos")]
pub use ddos::{DDoSConfig, DDoSStrategy};

#[cfg(feature = "firewall-geoip")]
pub use geoip::{GeoIPConfig, GeoIPStrategy};

#[cfg(any(feature = "firewall-anomalous", feature = "firewall-geoip"))]
pub use geo::{CountryLookup, GeoCoord, GeoLookup};

#[cfg(feature = "anomalous-detector-dual")]
pub use anomalous_analyzer::{AnomalousAnalyzerConfig, AnomalousLoginAnalyzer};

#[cfg(feature = "firewall-waf")]
pub use waf::{WafContext, WafHookChain};

#[cfg(feature = "firewall-waf")]
pub use waf_hooks::{BlackPathHook, DangerCharacterHook};

// ============================================================================
// FirewallContext：防火墙策略上下文
// ============================================================================

/// 防火墙策略上下文，携带请求级信息供策略决策使用。
///
/// # 字段
///
/// - `ip`：请求来源 IP（必须，所有策略依赖）
/// - `login_id`：登录主体标识（可选，AnomalousLogin / RateLimit scope=User 依赖）
/// - `tenant_id`：租户标识（可选，RateLimit scope=Tenant 依赖）
///
/// # 构造
///
/// ```ignore
/// use garrison::strategy::firewall::FirewallContext;
///
/// let ctx = FirewallContext::new("192.168.1.1")
///     .with_login_id("1001")
///     .with_tenant_id(0);
/// ```
#[derive(Debug, Clone)]
pub struct FirewallContext {
    /// 请求来源 IP（必须，所有策略依赖）。
    pub ip: String,
    /// 登录主体标识（可选，登录后策略如 AnomalousLogin / RateLimit scope=User 依赖）。
    pub login_id: Option<String>,
    /// 租户标识（可选，RateLimit scope=Tenant 依赖）。
    pub tenant_id: Option<i64>,
}

mod context_impl;

// ============================================================================
// GarrisonFirewallStrategy trait：IP 级防火墙策略契约
// ============================================================================

/// IP 级防火墙策略 trait，定义请求级安全检查的可插拔契约。
///
/// 5 个实现（各自独立 feature）：
/// - `BruteForceStrategy`：暴力破解防护（oxcache 计数 + 锁定）
/// - `RateLimitStrategy`：速率限制（滑动窗口）
/// - `AnomalousLoginStrategy`：异地登录检测（haversine + maxminddb）
/// - `DDoSStrategy`：DDoS 防护（token bucket）
/// - `GeoIPStrategy`：地理位置拦截（maxminddb）
///
/// # 返回
///
/// - `Ok(())`：检查通过，允许请求。
/// - `Err(GarrisonError::FirewallBlocked)`：检查未通过，拦截请求。
/// - `Err(other)`：内部错误（如 DAO 故障）。
#[async_trait]
pub trait GarrisonFirewallStrategy: Send + Sync {
    /// 执行防火墙安全检查。
    ///
    /// # 参数
    /// - `ctx`: 防火墙上下文（IP / login_id / tenant_id）。
    async fn check(&self, ctx: &FirewallContext) -> GarrisonResult<()>;
}

// ============================================================================
// CaptchaChallenge trait：验证码挑战契约
// ============================================================================

/// 验证码挑战 trait，定义"接近阈值时触发挑战 + 验证答案"的可插拔契约。
///
/// 实现方（如 [`RateLimitStrategy`])
/// 根据自身状态决定何时触发挑战，并在 `verify_challenge` 中验证用户提交的答案。
///
/// # 与 [`GarrisonFirewallStrategy`] 的区分
///
/// - `GarrisonFirewallStrategy::check`：硬拦截，直接返回 `FirewallBlocked`。
/// - `CaptchaChallenge::should_challenge`：软挑战，返回 true 时调用方应弹出验证码，
///   用户通过 `verify_challenge` 后才允许后续请求。
///
/// # 调用流程
///
/// 1. 调用 `should_challenge(ctx)` 判断是否需要挑战。
/// 2. 需要挑战时，调用方（如 web 中间件）弹出验证码并接收用户答案。
/// 3. 调用 `verify_challenge(ctx, answer)` 验证答案。
#[async_trait]
pub trait CaptchaChallenge: Send + Sync {
    /// 判断当前上下文是否应触发验证码挑战。
    ///
    /// # 参数
    /// - `ctx`: 防火墙上下文（IP / login_id / tenant_id）。
    ///
    /// # 返回
    /// - `Ok(true)`: 应触发挑战（如请求计数接近阈值）。
    /// - `Ok(false)`: 无需挑战。
    /// - `Err(_)`: 内部错误（如 DAO 故障）。
    async fn should_challenge(&self, ctx: &FirewallContext) -> GarrisonResult<bool>;

    /// 验证用户提交的验证码答案。
    ///
    /// # 参数
    /// - `ctx`: 防火墙上下文（用于定位期望答案）。
    /// - `answer`: 用户提交的答案。
    ///
    /// # 返回
    /// - `Ok(true)`: 答案正确，挑战通过。
    /// - `Ok(false)`: 答案错误或未设置期望答案，挑战失败。
    /// - `Err(_)`: 内部错误（如 DAO 故障）。
    async fn verify_challenge(&self, ctx: &FirewallContext, answer: &str) -> GarrisonResult<bool>;
}

// ============================================================================
// StrategyRegistration：inventory 编译期注册
// ============================================================================

/// 防火墙策略注册条目，用于 `inventory` 收集。
///
/// 仅注册策略名称（声明存在），不含 factory —— strategy 需依赖注入 dao/lookup，
/// 无参 factory 无法创建可用实例。调用方通过 name 知道哪些 strategy 可用后，
/// 手动用 `new(config, dao)` 构造实际实例。
///
/// 通过 `inventory::submit! { StrategyRegistration { name: "bruteforce" } }` 注册策略，
/// 运行期通过 `inventory::iter::<StrategyRegistration>()` 遍历。
pub struct StrategyRegistration {
    /// 策略名称（唯一标识，如 `"bruteforce"` / `"ratelimit"`）。
    pub name: &'static str,
}

// 编译期策略注册收集点
inventory::collect!(StrategyRegistration);

#[cfg(test)]
mod tests {
    /// 验证启用全部 5 个 firewall feature 时，inventory 注册了至少 5 个 strategy
    #[test]
    #[cfg(all(
        feature = "firewall-bruteforce",
        feature = "firewall-ratelimit",
        feature = "firewall-anomalous",
        feature = "firewall-ddos",
        feature = "firewall-geoip"
    ))]
    fn all_five_strategies_registered_via_inventory() {
        use super::*;
        use std::iter::Iterator;
        // 显式引用每个 strategy 类型，强制链接器保留 inventory::submit! 静态变量
        //（inventory 静态变量未被引用时可能被链接器优化丢弃）
        use super::AnomalousLoginStrategy;
        use super::BruteForceStrategy;
        use super::DDoSStrategy;
        use super::GeoIPStrategy;
        use super::RateLimitStrategy;
        let _ = std::any::TypeId::of::<AnomalousLoginStrategy>();
        let _ = std::any::TypeId::of::<BruteForceStrategy>();
        let _ = std::any::TypeId::of::<DDoSStrategy>();
        let _ = std::any::TypeId::of::<GeoIPStrategy>();
        let _ = std::any::TypeId::of::<RateLimitStrategy>();

        let names: Vec<&'static str> = inventory::iter::<StrategyRegistration>()
            .map(|r| r.name)
            .collect();
        let count = names.len();
        assert!(
            count >= 5,
            "启用全部 5 个 firewall feature 时应注册至少 5 个 strategy，实际: {}",
            count
        );

        // 验证 5 个预期名称都存在
        let names: Vec<&'static str> = inventory::iter::<StrategyRegistration>()
            .map(|r| r.name)
            .collect();
        for expected in &["bruteforce", "ratelimit", "anomalous", "ddos", "geoip"] {
            assert!(
                names.contains(expected),
                "strategy {:?} 未注册，实际注册: {:?}",
                expected,
                names
            );
        }
    }
}
