// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! IP 级防火墙策略套件模块（策略各自独立 feature）：`GarrisonFirewallStrategy` 定义 `check(ctx)` 拦截契约，
//! `FirewallContext` 携带 IP / login_id / tenant_id 供策略决策，`StrategyRegistration` 经 inventory 编译期注册策略名。
//!
//! 5 个策略：`BruteForceStrategy`（oxcache 计数 + 锁定）、`RateLimitStrategy`（滑动窗口）、`AnomalousLoginStrategy`
//! （haversine + maxminddb）、`DDoSStrategy`（固定窗口计数）、`GeoIPStrategy`（maxminddb 国家码）。
//! 与同名 trait 区分：`GarrisonPermissionStrategy` 做权限/角色校验，registry 的 `FirewallStrategy` 是登录前钩子检查，
//! 本模块的 `GarrisonFirewallStrategy` 是 IP 级防火墙拦截。

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

// 模块重导出：通过 mod 路径访问子模块类型（避免外部代码引用具体文件路径）

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

// FirewallContext：防火墙策略上下文

/// 防火墙策略上下文，携带请求级信息供策略决策使用。
///
/// # 构造
///
/// ```ignore
/// use garrison::strategy::firewall::FirewallContext;
///
/// let ctx = FirewallContext::new("192.168.1.1")
/// .with_login_id("1001")
/// .with_tenant_id(0);
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

// GarrisonFirewallStrategy trait：IP 级防火墙策略契约

/// IP 级防火墙策略 trait，定义请求级安全检查的可插拔契约。
///
/// `Ok(())` 放行；`Err(FirewallBlocked)` 拦截；`Err(other)` 为内部错误（如 DAO 故障）。5 个实现见模块文档。
#[async_trait]
pub trait GarrisonFirewallStrategy: Send + Sync {
    /// 执行防火墙安全检查（`ctx` 携带 IP / login_id / tenant_id）。
    async fn check(&self, ctx: &FirewallContext) -> GarrisonResult<()>;
}

// CaptchaChallenge trait：验证码挑战契约

/// 验证码挑战 trait，定义"接近阈值时触发挑战 + 验证答案"的可插拔契约（实现方如 `RateLimitStrategy`）。
///
/// 与 `GarrisonFirewallStrategy::check` 的硬拦截不同，`should_challenge` 为软挑战：返回 true 时调用方弹出验证码，
/// 用户经 `verify_challenge` 通过后才允许后续请求。
#[async_trait]
pub trait CaptchaChallenge: Send + Sync {
    /// 判断当前上下文是否应触发验证码挑战（如请求计数接近阈值）；`Err` 为内部错误（如 DAO 故障）。
    async fn should_challenge(&self, ctx: &FirewallContext) -> GarrisonResult<bool>;

    /// 验证用户提交的验证码答案（`ctx` 用于定位期望答案）；答案错误或未设置期望答案返回 `Ok(false)`，`Err` 为内部错误。
    async fn verify_challenge(&self, ctx: &FirewallContext, answer: &str) -> GarrisonResult<bool>;
}

// StrategyRegistration：inventory 编译期注册

/// 防火墙策略注册条目，用于 `inventory` 收集；仅注册策略名称（声明存在），不含 factory——strategy 需依赖注入
/// dao/lookup，无参 factory 无法创建可用实例，调用方按 name 判断哪些 strategy 可用后手动用 `new(config, dao)` 构造。
///
/// 经 `inventory::submit! { StrategyRegistration { name: "bruteforce" } }` 注册，运行期经 `inventory::iter::<StrategyRegistration>()` 遍历。
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
        // 显式引用每个 strategy 类型，强制链接器保留 inventory::submit! 静态变量（未被引用时可能被链接器优化丢弃）
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
