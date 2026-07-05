//! IP 级防火墙策略套件模块（v0.5.0 新增，依据 proposal H5 / spec firewall）。
//!
//! ## 设计
//!
//! - [`BulwarkFirewallStrategy`] trait：定义 `check(&self, ctx: &FirewallContext) -> BulwarkResult<()>` 契约
//! - [`FirewallContext`]：携带 IP / login_id / tenant_id 供策略决策
//! - [`StrategyRegistration`]：inventory 注册项，5 个 strategy 通过 `inventory::submit!` 注册
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
//! - [`BulwarkPermissionStrategy`](crate::strategy::BulwarkPermissionStrategy)（v0.3.0）：权限/角色校验
//! - [`FirewallStrategy`](crate::strategy::registry::FirewallStrategy)（v0.4.2）：登录前钩子检查
//! - [`BulwarkFirewallStrategy`]（v0.5.0，本 trait）：IP 级防火墙拦截

use crate::error::BulwarkResult;
use async_trait::async_trait;

/// 异地登录检测策略（依据 spec firewall R-firewall-003）。
#[cfg(feature = "firewall-anomalous")]
pub mod anomalous;
/// DDoS 防护策略（依据 spec firewall R-firewall-004）。
#[cfg(feature = "firewall-ddos")]
pub mod ddos;
/// IP 地理位置查询抽象（firewall-anomalous / firewall-geoip 共享）。
#[cfg(any(feature = "firewall-anomalous", feature = "firewall-geoip"))]
pub mod geo;
/// GeoIP 地理位置拦截策略（依据 spec firewall R-firewall-005）。
#[cfg(feature = "firewall-geoip")]
pub mod geoip;
/// 速率限制策略（依据 spec firewall R-firewall-002）。
#[cfg(feature = "firewall-ratelimit")]
pub mod rate_limit;

// ============================================================================
// FirewallContext：防火墙策略上下文
// ============================================================================

/// 防火墙策略上下文，携带请求级信息供策略决策使用（依据 spec firewall）。
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
/// use bulwark::strategy::firewall::FirewallContext;
///
/// let ctx = FirewallContext::new("192.168.1.1")
///     .with_login_id(1001)
///     .with_tenant_id(0);
/// ```
#[derive(Debug, Clone)]
pub struct FirewallContext {
    /// 请求来源 IP（必须，所有策略依赖）。
    pub ip: String,
    /// 登录主体标识（可选，登录后策略如 AnomalousLogin / RateLimit scope=User 依赖）。
    pub login_id: Option<i64>,
    /// 租户标识（可选，RateLimit scope=Tenant 依赖）。
    pub tenant_id: Option<i64>,
}

impl FirewallContext {
    /// 创建防火墙上下文，仅指定 IP。
    pub fn new(ip: impl Into<String>) -> Self {
        Self {
            ip: ip.into(),
            login_id: None,
            tenant_id: None,
        }
    }

    /// 链式设置 login_id。
    pub fn with_login_id(mut self, login_id: i64) -> Self {
        self.login_id = Some(login_id);
        self
    }

    /// 链式设置 tenant_id。
    pub fn with_tenant_id(mut self, tenant_id: i64) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }
}

// ============================================================================
// BulwarkFirewallStrategy trait：IP 级防火墙策略契约
// ============================================================================

/// IP 级防火墙策略 trait，定义请求级安全检查的可插拔契约（依据 spec firewall）。
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
/// - `Err(BulwarkError::FirewallBlocked)`：检查未通过，拦截请求。
/// - `Err(other)`：内部错误（如 DAO 故障）。
#[async_trait]
pub trait BulwarkFirewallStrategy: Send + Sync {
    /// 执行防火墙安全检查。
    ///
    /// # 参数
    /// - `ctx`: 防火墙上下文（IP / login_id / tenant_id）。
    async fn check(&self, ctx: &FirewallContext) -> BulwarkResult<()>;
}

// ============================================================================
// StrategyRegistration：inventory 编译期注册
// ============================================================================

/// 防火墙策略工厂函数指针，返回 `Box<dyn BulwarkFirewallStrategy>`。
pub type FirewallStrategyFactoryFn = fn() -> Box<dyn BulwarkFirewallStrategy>;

/// 防火墙策略注册条目，用于 `inventory` 收集（依据 spec firewall R-firewall-006）。
///
/// 通过 `inventory::submit! { StrategyRegistration { name, factory } }` 注册策略，
/// 运行期通过 `inventory::iter::<StrategyRegistration>()` 遍历。
pub struct StrategyRegistration {
    /// 策略名称（唯一标识，如 `"bruteforce"` / `"ratelimit"`）。
    pub name: &'static str,
    /// 策略工厂函数。
    pub factory: FirewallStrategyFactoryFn,
}

// 编译期策略注册收集点
inventory::collect!(StrategyRegistration);
