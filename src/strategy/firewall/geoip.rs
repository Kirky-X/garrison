//! GeoIP 地理位置拦截策略（依据 spec firewall R-firewall-005）。
//!
//! `GeoIPStrategy` 实现 [`BulwarkFirewallStrategy`] trait，
//! 用 [`CountryLookup`] trait 抽象 IP → 国家码查询，
//! 对照 `allowed_countries`（白名单）/ `blocked_countries`（黑名单）做拦截决策。
//!
//! # 算法（白名单优先）
//!
//! 1. `allowed_countries` 非空（白名单模式）：仅允许列表内国家，其他（含无法定位的 IP）拦截
//! 2. `allowed_countries` 为空且 `blocked_countries` 非空（黑名单模式）：拦截列表内国家，其他放行
//! 3. 两者均为空：全部放行（默认开放）
//!
//! # 与 AnomalousLoginStrategy 的区分
//!
//! - `AnomalousLoginStrategy` 用 [`GeoLookup`]（IP → 坐标）算 haversine 距离
//! - `GeoIPStrategy` 用 [`CountryLookup`]（IP → 国家码）做 allow/block 匹配
//!
//! [`CountryLookup`]: crate::strategy::firewall::geo::CountryLookup
//! [`GeoLookup`]: crate::strategy::firewall::geo::GeoLookup

use crate::error::{BulwarkError, BulwarkResult};
use crate::strategy::firewall::geo::CountryLookup;
use crate::strategy::firewall::{BulwarkFirewallStrategy, FirewallContext};
use async_trait::async_trait;
use std::sync::Arc;

/// GeoIP 拦截配置（依据 spec firewall R-firewall-005）。
///
/// 不含 `db_path`（db_path 属于 `MaxMindDbCountryLookup` 构造参数，
/// 通过 [`CountryLookup`] trait 注入到 [`GeoIPStrategy`]）。
///
/// 国家码比较大小写不敏感（ISO 3166-1 alpha-2，如 `"CN"` / `"US"`）。
#[derive(Debug, Clone, Default)]
pub struct GeoIPConfig {
    /// 白名单国家（非空时仅允许列表内国家，其他拦截）。
    pub allowed_countries: Vec<String>,
    /// 黑名单国家（allowed 为空时生效，拦截列表内国家）。
    pub blocked_countries: Vec<String>,
}

/// GeoIP 地理位置拦截策略（依据 spec firewall R-firewall-005）。
///
/// 持有 [`CountryLookup`] trait 抽象（依赖注入），生产用 `MaxMindDbCountryLookup`，
/// 测试用 `MockCountryLookup`。
///
/// # 构造
///
/// ```ignore
/// use std::sync::Arc;
/// use bulwark::strategy::firewall::geo::CountryLookup;
/// use bulwark::strategy::firewall::geoip::{GeoIPConfig, GeoIPStrategy};
///
/// let country_lookup: Arc<dyn CountryLookup> = /* MaxMindDbCountryLookup 或 mock */;
/// let config = GeoIPConfig { allowed_countries: vec!["CN".into()], blocked_countries: vec![] };
/// let strategy = GeoIPStrategy::new(config, country_lookup);
/// ```
pub struct GeoIPStrategy {
    /// 配置（白名单 / 黑名单国家列表）。
    config: GeoIPConfig,
    /// IP → 国家码查询抽象（依赖注入）。
    country_lookup: Arc<dyn CountryLookup>,
}

impl GeoIPStrategy {
    /// 创建 GeoIP 拦截策略实例。
    ///
    /// # 参数
    /// - `config`: 配置（白名单 / 黑名单国家列表）。
    /// - `country_lookup`: IP → 国家码查询抽象（生产用 `MaxMindDbCountryLookup`，测试用 mock）。
    pub fn new(config: GeoIPConfig, country_lookup: Arc<dyn CountryLookup>) -> Self {
        Self {
            config,
            country_lookup,
        }
    }

    /// 大小写不敏感检查国家码是否在列表中。
    fn is_in_list(country: &str, list: &[String]) -> bool {
        list.iter().any(|c| c.eq_ignore_ascii_case(country))
    }
}

#[async_trait]
impl BulwarkFirewallStrategy for GeoIPStrategy {
    async fn check(&self, ctx: &FirewallContext) -> BulwarkResult<()> {
        let country = self.country_lookup.lookup_country(&ctx.ip).await?;

        if !self.config.allowed_countries.is_empty() {
            // 白名单模式：仅允许列表内国家，其他（含无法定位）拦截
            match country.as_deref() {
                Some(c) if Self::is_in_list(c, &self.config.allowed_countries) => Ok(()),
                Some(c) => Err(BulwarkError::FirewallBlocked(format!(
                    "geoip: IP {} 国家码 {} 不在白名单 {:?}",
                    ctx.ip, c, self.config.allowed_countries
                ))),
                None => Err(BulwarkError::FirewallBlocked(format!(
                    "geoip: IP {} 无法定位国家，不在白名单 {:?} 内",
                    ctx.ip, self.config.allowed_countries
                ))),
            }
        } else if !self.config.blocked_countries.is_empty() {
            // 黑名单模式：拦截列表内国家，其他放行
            match country.as_deref() {
                Some(c) if Self::is_in_list(c, &self.config.blocked_countries) => {
                    Err(BulwarkError::FirewallBlocked(format!(
                        "geoip: IP {} 国家码 {} 在黑名单 {:?} 内",
                        ctx.ip, c, self.config.blocked_countries
                    )))
                },
                _ => Ok(()),
            }
        } else {
            // 两者均为空：全部放行（默认开放）
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::firewall::geo::CountryLookup;
    use async_trait::async_trait;
    use std::collections::HashMap;

    /// MockCountryLookup：硬编码 IP → 国家码映射，避免依赖真实 mmdb 文件。
    struct MockCountryLookup {
        map: HashMap<String, String>,
    }

    impl MockCountryLookup {
        fn new() -> Self {
            Self {
                map: HashMap::new(),
            }
        }

        fn with(mut self, ip: &str, country: &str) -> Self {
            self.map.insert(ip.to_string(), country.to_string());
            self
        }
    }

    #[async_trait]
    impl CountryLookup for MockCountryLookup {
        async fn lookup_country(&self, ip: &str) -> BulwarkResult<Option<String>> {
            Ok(self.map.get(ip).cloned())
        }
    }

    /// 验证白名单模式：allowed=["CN"] 时，IP 解析为 US 返回 FirewallBlocked
    ///（依据 spec firewall R-firewall-005 验收标准 1）。
    #[tokio::test]
    async fn geoip_blocks_when_not_in_allowed_countries() {
        let lookup: Arc<dyn CountryLookup> =
            Arc::new(MockCountryLookup::new().with("1.2.3.4", "US"));
        let config = GeoIPConfig {
            allowed_countries: vec!["CN".into()],
            blocked_countries: vec![],
        };
        let strategy = GeoIPStrategy::new(config, lookup);
        let ctx = FirewallContext::new("1.2.3.4");

        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "US 不在白名单 [CN] 应拦截，实际: {:?}",
            result
        );
    }

    /// 验证黑名单模式：blocked=["XX"] 时，IP 解析为 XX 返回 FirewallBlocked
    ///（依据 spec firewall R-firewall-005 验收标准 2）。
    #[tokio::test]
    async fn geoip_blocks_when_in_blocked_countries() {
        let lookup: Arc<dyn CountryLookup> =
            Arc::new(MockCountryLookup::new().with("1.2.3.4", "XX"));
        let config = GeoIPConfig {
            allowed_countries: vec![],
            blocked_countries: vec!["XX".into()],
        };
        let strategy = GeoIPStrategy::new(config, lookup);
        let ctx = FirewallContext::new("1.2.3.4");

        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "XX 在黑名单 [XX] 应拦截，实际: {:?}",
            result
        );
    }

    /// 验证白名单放行：allowed=["CN"] 时，IP 解析为 CN 放行
    ///（依据 spec firewall R-firewall-005 验收标准 3）。
    #[tokio::test]
    async fn geoip_allows_when_in_allowed_countries() {
        let lookup: Arc<dyn CountryLookup> =
            Arc::new(MockCountryLookup::new().with("1.2.3.4", "CN"));
        let config = GeoIPConfig {
            allowed_countries: vec!["CN".into()],
            blocked_countries: vec![],
        };
        let strategy = GeoIPStrategy::new(config, lookup);
        let ctx = FirewallContext::new("1.2.3.4");

        assert!(
            strategy.check(&ctx).await.is_ok(),
            "CN 在白名单 [CN] 应放行"
        );
    }

    /// 验证黑名单放行：blocked=["XX"] 时，IP 解析为 CN 放行
    ///（依据 spec firewall R-firewall-005 验收标准 2 反向）。
    #[tokio::test]
    async fn geoip_allows_when_not_in_blocked_countries() {
        let lookup: Arc<dyn CountryLookup> =
            Arc::new(MockCountryLookup::new().with("1.2.3.4", "CN"));
        let config = GeoIPConfig {
            allowed_countries: vec![],
            blocked_countries: vec!["XX".into()],
        };
        let strategy = GeoIPStrategy::new(config, lookup);
        let ctx = FirewallContext::new("1.2.3.4");

        assert!(
            strategy.check(&ctx).await.is_ok(),
            "CN 不在黑名单 [XX] 应放行"
        );
    }

    /// 验证默认开放：allowed=[] 且 blocked=[] 时全部放行
    ///（依据 spec firewall R-firewall-005 验收标准 4）。
    #[tokio::test]
    async fn geoip_allows_when_both_lists_empty() {
        let lookup: Arc<dyn CountryLookup> =
            Arc::new(MockCountryLookup::new().with("1.2.3.4", "US"));
        let config = GeoIPConfig {
            allowed_countries: vec![],
            blocked_countries: vec![],
        };
        let strategy = GeoIPStrategy::new(config, lookup);
        let ctx = FirewallContext::new("1.2.3.4");

        assert!(
            strategy.check(&ctx).await.is_ok(),
            "两个列表均为空时应全部放行"
        );
    }

    /// 验证白名单优先：allowed 非空时仅检查白名单，忽略黑名单
    ///（依据 spec firewall R-firewall-005 验收标准 3 白名单优先）。
    #[tokio::test]
    async fn geoip_whitelist_takes_priority_over_blacklist() {
        let lookup: Arc<dyn CountryLookup> =
            Arc::new(MockCountryLookup::new().with("1.2.3.4", "CN"));
        // CN 同时在白名单和黑名单中，白名单优先应放行
        let config = GeoIPConfig {
            allowed_countries: vec!["CN".into()],
            blocked_countries: vec!["CN".into()],
        };
        let strategy = GeoIPStrategy::new(config, lookup);
        let ctx = FirewallContext::new("1.2.3.4");

        assert!(
            strategy.check(&ctx).await.is_ok(),
            "白名单非空时仅检查白名单，CN 在白名单应放行"
        );
    }

    /// 验证白名单模式拦截无法定位的 IP：allowed=["CN"] 时，IP 无法定位返回 FirewallBlocked
    ///（白名单模式下不在列表内的都拦截，含 None）。
    #[tokio::test]
    async fn geoip_blocks_unknown_ip_in_whitelist_mode() {
        let lookup: Arc<dyn CountryLookup> = Arc::new(MockCountryLookup::new()); // 无记录
        let config = GeoIPConfig {
            allowed_countries: vec!["CN".into()],
            blocked_countries: vec![],
        };
        let strategy = GeoIPStrategy::new(config, lookup);
        let ctx = FirewallContext::new("192.168.1.1");

        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "白名单模式下无法定位的 IP 应拦截，实际: {:?}",
            result
        );
    }

    /// 验证黑名单模式放行无法定位的 IP：blocked=["XX"] 时，IP 无法定位放行
    ///（黑名单模式下无匹配的都放行）。
    #[tokio::test]
    async fn geoip_allows_unknown_ip_in_blacklist_mode() {
        let lookup: Arc<dyn CountryLookup> = Arc::new(MockCountryLookup::new()); // 无记录
        let config = GeoIPConfig {
            allowed_countries: vec![],
            blocked_countries: vec!["XX".into()],
        };
        let strategy = GeoIPStrategy::new(config, lookup);
        let ctx = FirewallContext::new("192.168.1.1");

        assert!(
            strategy.check(&ctx).await.is_ok(),
            "黑名单模式下无法定位的 IP 应放行"
        );
    }

    /// 验证国家码大小写不敏感：allowed=["cn"] 时，IP 解析为 "CN" 放行
    ///（ISO 3166-1 alpha-2 大小写不敏感比较）。
    #[tokio::test]
    async fn geoip_country_code_case_insensitive() {
        let lookup: Arc<dyn CountryLookup> =
            Arc::new(MockCountryLookup::new().with("1.2.3.4", "CN"));
        let config = GeoIPConfig {
            allowed_countries: vec!["cn".into()], // 小写
            blocked_countries: vec![],
        };
        let strategy = GeoIPStrategy::new(config, lookup);
        let ctx = FirewallContext::new("1.2.3.4");

        assert!(
            strategy.check(&ctx).await.is_ok(),
            "国家码大小写不敏感，cn 应匹配 CN"
        );
    }
}
