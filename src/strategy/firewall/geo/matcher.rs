//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! limiteron GeoMatcher 生产后端实现（自研库吸收）。
//!
//! 提供 [`GeoMatcherLookup`](crate::strategy::firewall::geo::matcher::GeoMatcherLookup) 与
//! [`GeoMatcherCountryLookup`](crate::strategy::firewall::geo::matcher::GeoMatcherCountryLookup)
//! 两个生产实现，内部委托 limiteron `GeoMatcher`（内置 mmdb 读取 + Moka LRU
//! 查询缓存 + 批量查询），分别映射到 garrison 的 [`GeoLookup`] / [`CountryLookup`] trait。
//!
//! # 依赖
//!
//! - limiteron `geo-matching` feature（由 `firewall-geoip` 启用）
//! - 测试数据：`tests/data/GeoLite2-City-Test.mmdb` / `GeoLite2-Country-Test.mmdb`
//!   （小体积测试库——limiteron 对非全量库仅告警，不拒绝）
//!
//! # 语义映射
//!
//! - 库中无该 IP 记录（私有 IP / 未知网段）：GeoMatcher 返回 `GeoInfo::empty()`
//!   → garrison 映射为 `Ok(None)`（与历史 maxminddb 直读后端一致）
//! - 数据库损坏/IO 错误：`Err(LimiteronError)` → `GarrisonError::Internal`

use super::{CountryLookup, GeoCoord, GeoLookup};
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use limiteron::matchers::geo::GeoMatcher;
use std::net::IpAddr;
use std::sync::Arc;

/// limiteron GeoMatcher 坐标查询后端（生产实现，City 库）。
///
/// 实现 [`GeoLookup`] trait，供 `AnomalousLoginStrategy` 的 haversine 距离计算。
///
/// # 构造
///
/// ```ignore
/// use garrison::strategy::firewall::geo::matcher::GeoMatcherLookup;
///
/// let lookup = GeoMatcherLookup::open("tests/data/GeoLite2-City-Test.mmdb").await?;
/// ```
pub struct GeoMatcherLookup {
    matcher: Arc<GeoMatcher>,
}

impl std::fmt::Debug for GeoMatcherLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoMatcherLookup").finish_non_exhaustive()
    }
}

impl GeoMatcherLookup {
    /// 从文件路径打开 mmdb 数据库（GeoLite2-City / GeoIP2-City）。
    ///
    /// # 错误
    /// - `GarrisonError::Internal`: 文件不存在、格式错误或 IO 错误。
    pub async fn open(path: &str) -> GarrisonResult<Self> {
        let matcher = GeoMatcher::new(path).await.map_err(|e| {
            GarrisonError::Internal(format!("strategy-geo-matcher-open::{}::{}", path, e))
        })?;
        Ok(Self {
            matcher: Arc::new(matcher),
        })
    }
}

#[async_trait]
impl GeoLookup for GeoMatcherLookup {
    async fn lookup(&self, ip: &str) -> GarrisonResult<Option<GeoCoord>> {
        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|_| GarrisonError::InvalidParam(format!("strategy-invalid-ip::{}", ip)))?;

        let info = self.matcher.lookup(ip_addr).await.map_err(|e| {
            GarrisonError::Internal(format!("strategy-geo-matcher-query::{}::{}", ip, e))
        })?;

        // 空信息 = 库中无记录（私有 IP / 未知网段）→ None
        if info.is_empty() {
            return Ok(None);
        }
        match (info.latitude, info.longitude) {
            (Some(lat), Some(lon)) => GeoCoord::new(lat, lon).map(Some),
            _ => Ok(None),
        }
    }
}

/// limiteron GeoMatcher 国家码查询后端（生产实现，Country/City 库）。
///
/// 实现 [`CountryLookup`] trait，供 `GeoIPStrategy` 的 allow/block 匹配。
pub struct GeoMatcherCountryLookup {
    matcher: Arc<GeoMatcher>,
}

impl std::fmt::Debug for GeoMatcherCountryLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoMatcherCountryLookup")
            .finish_non_exhaustive()
    }
}

impl GeoMatcherCountryLookup {
    /// 从文件路径打开 mmdb 数据库（GeoLite2-Country / GeoIP2-City）。
    ///
    /// # 错误
    /// - `GarrisonError::Internal`: 文件不存在、格式错误或 IO 错误。
    pub async fn open(path: &str) -> GarrisonResult<Self> {
        let matcher = GeoMatcher::new(path).await.map_err(|e| {
            GarrisonError::Internal(format!("strategy-geo-matcher-open::{}::{}", path, e))
        })?;
        Ok(Self {
            matcher: Arc::new(matcher),
        })
    }
}

#[async_trait]
impl CountryLookup for GeoMatcherCountryLookup {
    async fn lookup_country(&self, ip: &str) -> GarrisonResult<Option<String>> {
        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|_| GarrisonError::InvalidParam(format!("strategy-invalid-ip::{}", ip)))?;

        let info = self.matcher.lookup(ip_addr).await.map_err(|e| {
            GarrisonError::Internal(format!("strategy-geo-matcher-query::{}::{}", ip, e))
        })?;

        Ok(if info.is_empty() {
            None
        } else {
            info.country_code
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// 测试数据文件路径常量。
    const CITY_TEST_DB: &str = "tests/data/GeoLite2-City-Test.mmdb";
    const COUNTRY_TEST_DB: &str = "tests/data/GeoLite2-Country-Test.mmdb";

    // =========================================================================
    // GeoMatcherLookup 测试
    // =========================================================================

    /// 验证从测试 mmdb 文件打开 GeoMatcherLookup 成功（小体积测试库——
    /// limiteron 对非全量库仅告警不拒绝）。
    #[tokio::test]
    async fn geo_matcher_open_success() {
        let result = GeoMatcherLookup::open(CITY_TEST_DB).await;
        assert!(
            result.is_ok(),
            "打开 City 测试数据库应成功: {:?}",
            result.err()
        );
    }

    /// 验证打开不存在的文件返回 Err。
    #[tokio::test]
    async fn geo_matcher_open_file_not_found() {
        let result = GeoMatcherLookup::open("tests/data/nonexistent.mmdb").await;
        assert!(result.is_err(), "打开不存在的文件应返回 Err");
        let err = result.unwrap_err();
        assert!(
            matches!(err, GarrisonError::Internal(_)),
            "错误类型应为 Internal，实际: {:?}",
            err
        );
    }

    /// 验证查询已知 IP 返回 Some(GeoCoord)。
    ///
    /// 81.2.69.142 是 MaxMind 测试数据中的已知 IP（英国伦敦）。
    #[tokio::test]
    async fn geo_matcher_lookup_known_ip() {
        let lookup = GeoMatcherLookup::open(CITY_TEST_DB)
            .await
            .expect("打开数据库失败");
        let result = lookup.lookup("81.2.69.142").await;
        assert!(result.is_ok(), "查询已知 IP 应成功: {:?}", result.err());
        let coord = result.unwrap();
        assert!(coord.is_some(), "已知 IP 应返回 Some(GeoCoord)");
        let coord = coord.unwrap();
        // 伦敦纬度约 51.x，经度约 -0.x
        assert!(
            coord.lat > 50.0 && coord.lat < 52.0,
            "伦敦纬度应在 50-52 之间，实际: {}",
            coord.lat
        );
        assert!(
            coord.lon > -1.0 && coord.lon < 1.0,
            "伦敦经度应在 -1~1 之间，实际: {}",
            coord.lon
        );
    }

    /// 验证查询私有 IP 返回 None（GeoInfo::empty 映射）。
    #[tokio::test]
    async fn geo_matcher_lookup_private_ip() {
        let lookup = GeoMatcherLookup::open(CITY_TEST_DB)
            .await
            .expect("打开数据库失败");
        let result = lookup.lookup("192.168.1.1").await;
        assert!(result.is_ok(), "查询私有 IP 应成功: {:?}", result.err());
        assert!(
            result.unwrap().is_none(),
            "私有 IP 应返回 None（数据库无记录）"
        );
    }

    /// 验证查询无效 IP 返回 Err。
    #[tokio::test]
    async fn geo_matcher_lookup_invalid_ip() {
        let lookup = GeoMatcherLookup::open(CITY_TEST_DB)
            .await
            .expect("打开数据库失败");
        let result = lookup.lookup("invalid").await;
        assert!(result.is_err(), "无效 IP 应返回 Err");
        let err = result.unwrap_err();
        assert!(
            matches!(err, GarrisonError::InvalidParam(_)),
            "无效 IP 错误类型应为 InvalidParam，实际: {:?}",
            err
        );
    }

    // =========================================================================
    // GeoMatcherCountryLookup 测试
    // =========================================================================

    /// 验证从测试 mmdb 文件打开 GeoMatcherCountryLookup 成功。
    #[tokio::test]
    async fn geo_matcher_country_open_success() {
        let result = GeoMatcherCountryLookup::open(COUNTRY_TEST_DB).await;
        assert!(
            result.is_ok(),
            "打开 Country 测试数据库应成功: {:?}",
            result.err()
        );
    }

    /// 验证打开不存在的文件返回 Err。
    #[tokio::test]
    async fn geo_matcher_country_open_file_not_found() {
        let result = GeoMatcherCountryLookup::open("tests/data/nonexistent.mmdb").await;
        assert!(result.is_err(), "打开不存在的文件应返回 Err");
    }

    /// 验证查询已知 IP 返回 Some(国家码)。
    ///
    /// 81.2.69.142 是 MaxMind 测试数据中的已知 IP（英国，国家码 GB）。
    #[tokio::test]
    async fn geo_matcher_country_lookup_known_ip() {
        let lookup = GeoMatcherCountryLookup::open(COUNTRY_TEST_DB)
            .await
            .expect("打开数据库失败");
        let result = lookup.lookup_country("81.2.69.142").await;
        assert!(result.is_ok(), "查询已知 IP 应成功: {:?}", result.err());
        let country = result.unwrap();
        assert!(country.is_some(), "已知 IP 应返回 Some(国家码)");
        let country = country.unwrap();
        assert!(
            country == "GB" || country == "gb",
            "81.2.69.142 国家码应为 GB，实际: {}",
            country
        );
    }

    /// 验证查询私有 IP 返回 None。
    #[tokio::test]
    async fn geo_matcher_country_lookup_private_ip() {
        let lookup = GeoMatcherCountryLookup::open(COUNTRY_TEST_DB)
            .await
            .expect("打开数据库失败");
        let result = lookup.lookup_country("192.168.1.1").await;
        assert!(result.is_ok(), "查询私有 IP 应成功: {:?}", result.err());
        assert!(
            result.unwrap().is_none(),
            "私有 IP 应返回 None（数据库无记录）"
        );
    }

    /// 验证查询无效 IP 返回 Err。
    #[tokio::test]
    async fn geo_matcher_country_lookup_invalid_ip() {
        let lookup = GeoMatcherCountryLookup::open(COUNTRY_TEST_DB)
            .await
            .expect("打开数据库失败");
        let result = lookup.lookup_country("invalid").await;
        assert!(result.is_err(), "无效 IP 应返回 Err");
        let err = result.unwrap_err();
        assert!(
            matches!(err, GarrisonError::InvalidParam(_)),
            "无效 IP 错误类型应为 InvalidParam，实际: {:?}",
            err
        );
    }

    // =========================================================================
    // 集成测试
    // =========================================================================

    /// 验证 GeoIPStrategy 注入 GeoMatcherCountryLookup 的白名单拦截行为。
    ///
    /// 81.2.69.142 → GB，白名单 ["CN"]，应拦截。
    #[tokio::test]
    async fn geoip_strategy_with_geo_matcher() {
        use crate::strategy::firewall::{FirewallContext, GarrisonFirewallStrategy};
        use crate::strategy::firewall::{GeoIPConfig, GeoIPStrategy};

        let country_lookup: Arc<dyn CountryLookup> = Arc::new(
            GeoMatcherCountryLookup::open(COUNTRY_TEST_DB)
                .await
                .expect("打开数据库失败"),
        );
        let config = GeoIPConfig {
            allowed_countries: vec!["CN".into()],
            blocked_countries: vec![],
        };
        let strategy = GeoIPStrategy::new(config, country_lookup);
        let ctx = FirewallContext::new("81.2.69.142");

        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(GarrisonError::FirewallBlocked(_))),
            "GB 不在白名单 [CN] 应拦截，实际: {:?}",
            result
        );
    }

    /// 验证 AnomalousLoginStrategy 注入 GeoMatcherLookup 的异地登录检测。
    ///
    /// 使用 City 测试数据库，81.2.69.142 → 伦敦坐标。
    /// MockDao 提供历史坐标（北京），haversine 距离 > 500km，应拦截。
    #[tokio::test]
    async fn anomalous_strategy_with_geo_matcher() {
        use crate::dao::tests::MockDao;
        use crate::strategy::firewall::{AnomalousConfig, AnomalousLoginStrategy};
        use crate::strategy::firewall::{FirewallContext, GarrisonFirewallStrategy};

        let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(MockDao::new());
        let geo_lookup: Arc<dyn GeoLookup> = Arc::new(
            GeoMatcherLookup::open(CITY_TEST_DB)
                .await
                .expect("打开数据库失败"),
        );
        let config = AnomalousConfig {
            known_geo_threshold: 500,
        };
        let strategy = AnomalousLoginStrategy::new(config, dao, geo_lookup);

        // 首次登录：81.2.69.142（伦敦），无历史，应放行
        let ctx_first = FirewallContext::new("81.2.69.142").with_login_id("1001");
        let result_first = strategy.check(&ctx_first).await;
        assert!(
            result_first.is_ok(),
            "首次登录应放行（无历史记录），实际: {:?}",
            result_first.err()
        );

        // 再次登录同一 IP → 同一位置，应放行
        let ctx_second = FirewallContext::new("81.2.69.142").with_login_id("1001");
        let result_second = strategy.check(&ctx_second).await;
        assert!(
            result_second.is_ok(),
            "同地登录（伦敦→伦敦）应放行，实际: {:?}",
            result_second.err()
        );
    }
}
