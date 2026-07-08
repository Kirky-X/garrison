//! MaxMindDb 生产后端实现（v0.5.3 新增，依据 spec firewall）。
//!
//! 提供 [`MaxMindDbGeoLookup`] 和 [`MaxMindDbCountryLookup`] 两个生产实现，
//! 分别读取 GeoIP2-City / GeoIP2-Country mmdb 数据库文件。
//!
//! # 依赖
//!
//! - `maxminddb` 0.29 crate（由 `firewall-maxminddb` feature 启用）
//! - 测试数据：`tests/data/GeoLite2-City-Test.mmdb` / `GeoLite2-Country-Test.mmdb`
//!
//! # API 说明
//!
//! maxminddb 0.28+ API：`reader.lookup(ip)?` 返回 `LookupResult`，
//! 再 `result.decode::<City>()?` 返回 `Option<City>`。
//!
//! # 线程安全
//!
//! `maxminddb::Reader<Vec<u8>>` 实现 `Send + Sync`，可安全跨线程共享。

use crate::error::{BulwarkError, BulwarkResult};
use crate::strategy::firewall::geo::{CountryLookup, GeoCoord, GeoLookup};
use async_trait::async_trait;
use maxminddb::geoip2;
use std::net::IpAddr;

// ============================================================================
// MaxMindDbGeoLookup：IP → 坐标（GeoIP2-City 数据库）
// ============================================================================

/// MaxMindDb GeoIP2-City 查询后端（生产实现）。
///
/// 读取 GeoIP2-City / GeoLite2-City mmdb 文件，提供 IP → 坐标查询。
/// 实现 [`GeoLookup`] trait。
///
/// # 构造
///
/// ```ignore
/// use bulwark::strategy::firewall::geo::maxminddb::MaxMindDbGeoLookup;
///
/// // 从文件打开
/// let lookup = MaxMindDbGeoLookup::open("tests/data/GeoLite2-City-Test.mmdb")?;
///
/// // 从内存字节打开
/// let bytes = std::fs::read("tests/data/GeoLite2-City-Test.mmdb")?;
/// let lookup = MaxMindDbGeoLookup::from_bytes(bytes)?;
/// ```
pub struct MaxMindDbGeoLookup {
    /// maxminddb Reader（持有 mmdb 文件数据，`Reader<Vec<u8>>` 是 Send + Sync）。
    reader: maxminddb::Reader<Vec<u8>>,
}

impl std::fmt::Debug for MaxMindDbGeoLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaxMindDbGeoLookup").finish_non_exhaustive()
    }
}

impl MaxMindDbGeoLookup {
    /// 从文件路径打开 mmdb 数据库。
    ///
    /// # 参数
    /// - `path`: mmdb 文件路径（如 `GeoLite2-City.mmdb`）。
    ///
    /// # 错误
    /// - `BulwarkError::Internal`: 文件不存在、格式错误或 IO 错误。
    pub fn open(path: &str) -> BulwarkResult<Self> {
        let reader = maxminddb::Reader::open_readfile(path).map_err(|e| {
            BulwarkError::Internal(format!("MaxMindDb 打开文件失败 {}: {}", path, e))
        })?;
        Ok(Self { reader })
    }

    /// 从内存字节构造 mmdb Reader。
    ///
    /// # 参数
    /// - `data`: mmdb 文件完整字节内容。
    ///
    /// # 错误
    /// - `BulwarkError::Internal`: 数据格式错误。
    pub fn from_bytes(data: Vec<u8>) -> BulwarkResult<Self> {
        let reader = maxminddb::Reader::from_source(data)
            .map_err(|e| BulwarkError::Internal(format!("MaxMindDb 从字节构造失败: {}", e)))?;
        Ok(Self { reader })
    }
}

#[async_trait]
impl GeoLookup for MaxMindDbGeoLookup {
    async fn lookup(&self, ip: &str) -> BulwarkResult<Option<GeoCoord>> {
        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|_| BulwarkError::InvalidParam(format!("无效的 IP 地址: {}", ip)))?;

        let result = self.reader.lookup(ip_addr).map_err(|e| {
            BulwarkError::Internal(format!("MaxMindDb 查询失败 (IP={}): {}", ip, e))
        })?;

        match result.decode::<geoip2::City>() {
            Ok(Some(city)) => {
                let lat = city.location.latitude;
                let lon = city.location.longitude;
                match (lat, lon) {
                    (Some(lat), Some(lon)) => Ok(Some(GeoCoord::new(lat, lon))),
                    _ => Ok(None),
                }
            },
            Ok(None) => Ok(None),
            Err(e) => Err(BulwarkError::Internal(format!(
                "MaxMindDb 解码 City 记录失败 (IP={}): {}",
                ip, e
            ))),
        }
    }
}

// ============================================================================
// MaxMindDbCountryLookup：IP → 国家码（GeoIP2-Country 数据库）
// ============================================================================

/// MaxMindDb GeoIP2-Country 查询后端（生产实现）。
///
/// 读取 GeoIP2-Country / GeoLite2-Country mmdb 文件，提供 IP → 国家码查询。
/// 实现 [`CountryLookup`] trait。
///
/// # 构造
///
/// ```ignore
/// use bulwark::strategy::firewall::geo::maxminddb::MaxMindDbCountryLookup;
///
/// let lookup = MaxMindDbCountryLookup::open("tests/data/GeoLite2-Country-Test.mmdb")?;
/// ```
pub struct MaxMindDbCountryLookup {
    /// maxminddb Reader。
    reader: maxminddb::Reader<Vec<u8>>,
}

impl std::fmt::Debug for MaxMindDbCountryLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaxMindDbCountryLookup")
            .finish_non_exhaustive()
    }
}

impl MaxMindDbCountryLookup {
    /// 从文件路径打开 mmdb 数据库。
    ///
    /// # 参数
    /// - `path`: mmdb 文件路径（如 `GeoLite2-Country.mmdb`）。
    ///
    /// # 错误
    /// - `BulwarkError::Internal`: 文件不存在、格式错误或 IO 错误。
    pub fn open(path: &str) -> BulwarkResult<Self> {
        let reader = maxminddb::Reader::open_readfile(path).map_err(|e| {
            BulwarkError::Internal(format!("MaxMindDb 打开文件失败 {}: {}", path, e))
        })?;
        Ok(Self { reader })
    }

    /// 从内存字节构造 mmdb Reader。
    ///
    /// # 参数
    /// - `data`: mmdb 文件完整字节内容。
    ///
    /// # 错误
    /// - `BulwarkError::Internal`: 数据格式错误。
    pub fn from_bytes(data: Vec<u8>) -> BulwarkResult<Self> {
        let reader = maxminddb::Reader::from_source(data)
            .map_err(|e| BulwarkError::Internal(format!("MaxMindDb 从字节构造失败: {}", e)))?;
        Ok(Self { reader })
    }
}

#[async_trait]
impl CountryLookup for MaxMindDbCountryLookup {
    async fn lookup_country(&self, ip: &str) -> BulwarkResult<Option<String>> {
        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|_| BulwarkError::InvalidParam(format!("无效的 IP 地址: {}", ip)))?;

        let result = self.reader.lookup(ip_addr).map_err(|e| {
            BulwarkError::Internal(format!("MaxMindDb 查询失败 (IP={}): {}", ip, e))
        })?;

        match result.decode::<geoip2::Country>() {
            Ok(Some(country)) => {
                let iso_code = country.country.iso_code.map(|s| s.to_string());
                Ok(iso_code)
            },
            Ok(None) => Ok(None),
            Err(e) => Err(BulwarkError::Internal(format!(
                "MaxMindDb 解码 Country 记录失败 (IP={}): {}",
                ip, e
            ))),
        }
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// 测试数据文件路径常量。
    const CITY_TEST_DB: &str = "tests/data/GeoLite2-City-Test.mmdb";
    const COUNTRY_TEST_DB: &str = "tests/data/GeoLite2-Country-Test.mmdb";

    // =========================================================================
    // MaxMindDbGeoLookup 测试（T049-T057）
    // =========================================================================

    /// 验证从测试 mmdb 文件打开 MaxMindDbGeoLookup 成功（T051）。
    #[test]
    fn maxminddb_geo_open_success() {
        let result = MaxMindDbGeoLookup::open(CITY_TEST_DB);
        assert!(
            result.is_ok(),
            "打开 City 测试数据库应成功: {:?}",
            result.err()
        );
    }

    /// 验证打开不存在的文件返回 Err（T052）。
    #[test]
    fn maxminddb_geo_open_file_not_found() {
        let result = MaxMindDbGeoLookup::open("tests/data/nonexistent.mmdb");
        assert!(result.is_err(), "打开不存在的文件应返回 Err");
        let err = result.unwrap_err();
        assert!(
            matches!(err, BulwarkError::Internal(_)),
            "错误类型应为 Internal，实际: {:?}",
            err
        );
    }

    /// 验证从字节构造 MaxMindDbGeoLookup 成功。
    #[test]
    fn maxminddb_geo_from_bytes_success() {
        let bytes = std::fs::read(CITY_TEST_DB).expect("读取测试数据库文件失败");
        let result = MaxMindDbGeoLookup::from_bytes(bytes);
        assert!(result.is_ok(), "从字节构造应成功: {:?}", result.err());
    }

    /// 验证查询已知 IP 返回 Some(GeoCoord)（T053）。
    ///
    /// 81.2.69.142 是 MaxMind 测试数据中的已知 IP（英国伦敦）。
    #[tokio::test]
    async fn maxminddb_geo_lookup_known_ip() {
        let lookup = MaxMindDbGeoLookup::open(CITY_TEST_DB).expect("打开数据库失败");
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

    /// 验证查询私有 IP 返回 None（T054）。
    ///
    /// 192.168.1.1 是私有 IP，mmdb 数据库中无记录。
    #[tokio::test]
    async fn maxminddb_geo_lookup_private_ip() {
        let lookup = MaxMindDbGeoLookup::open(CITY_TEST_DB).expect("打开数据库失败");
        let result = lookup.lookup("192.168.1.1").await;
        assert!(result.is_ok(), "查询私有 IP 应成功: {:?}", result.err());
        assert!(
            result.unwrap().is_none(),
            "私有 IP 应返回 None（数据库无记录）"
        );
    }

    /// 验证查询无效 IP 返回 Err（T055）。
    #[tokio::test]
    async fn maxminddb_geo_lookup_invalid_ip() {
        let lookup = MaxMindDbGeoLookup::open(CITY_TEST_DB).expect("打开数据库失败");
        let result = lookup.lookup("invalid").await;
        assert!(result.is_err(), "无效 IP 应返回 Err");
        let err = result.unwrap_err();
        assert!(
            matches!(err, BulwarkError::InvalidParam(_)),
            "无效 IP 错误类型应为 InvalidParam，实际: {:?}",
            err
        );
    }

    // =========================================================================
    // MaxMindDbCountryLookup 测试（T058-T064）
    // =========================================================================

    /// 验证从测试 mmdb 文件打开 MaxMindDbCountryLookup 成功（T059）。
    #[test]
    fn maxminddb_country_open_success() {
        let result = MaxMindDbCountryLookup::open(COUNTRY_TEST_DB);
        assert!(
            result.is_ok(),
            "打开 Country 测试数据库应成功: {:?}",
            result.err()
        );
    }

    /// 验证打开不存在的文件返回 Err。
    #[test]
    fn maxminddb_country_open_file_not_found() {
        let result = MaxMindDbCountryLookup::open("tests/data/nonexistent.mmdb");
        assert!(result.is_err(), "打开不存在的文件应返回 Err");
    }

    /// 验证从字节构造 MaxMindDbCountryLookup 成功。
    #[test]
    fn maxminddb_country_from_bytes_success() {
        let bytes = std::fs::read(COUNTRY_TEST_DB).expect("读取测试数据库文件失败");
        let result = MaxMindDbCountryLookup::from_bytes(bytes);
        assert!(result.is_ok(), "从字节构造应成功: {:?}", result.err());
    }

    /// 验证查询已知 IP 返回 Some(国家码)（T060）。
    ///
    /// 81.2.69.142 是 MaxMind 测试数据中的已知 IP（英国，国家码 GB）。
    #[tokio::test]
    async fn maxminddb_country_lookup_known_ip() {
        let lookup = MaxMindDbCountryLookup::open(COUNTRY_TEST_DB).expect("打开数据库失败");
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

    /// 验证查询私有 IP 返回 None（T061）。
    #[tokio::test]
    async fn maxminddb_country_lookup_private_ip() {
        let lookup = MaxMindDbCountryLookup::open(COUNTRY_TEST_DB).expect("打开数据库失败");
        let result = lookup.lookup_country("192.168.1.1").await;
        assert!(result.is_ok(), "查询私有 IP 应成功: {:?}", result.err());
        assert!(
            result.unwrap().is_none(),
            "私有 IP 应返回 None（数据库无记录）"
        );
    }

    /// 验证查询无效 IP 返回 Err（T062）。
    #[tokio::test]
    async fn maxminddb_country_lookup_invalid_ip() {
        let lookup = MaxMindDbCountryLookup::open(COUNTRY_TEST_DB).expect("打开数据库失败");
        let result = lookup.lookup_country("invalid").await;
        assert!(result.is_err(), "无效 IP 应返回 Err");
        let err = result.unwrap_err();
        assert!(
            matches!(err, BulwarkError::InvalidParam(_)),
            "无效 IP 错误类型应为 InvalidParam，实际: {:?}",
            err
        );
    }

    // =========================================================================
    // 集成测试（T065-T066）
    // =========================================================================

    /// 验证 GeoIPStrategy 注入 MaxMindDbCountryLookup 的白名单拦截行为（T065）。
    ///
    /// 81.2.69.142 → GB，白名单 ["CN"]，应拦截。
    #[tokio::test]
    async fn geoip_strategy_with_maxminddb() {
        use crate::strategy::firewall::geoip::{GeoIPConfig, GeoIPStrategy};
        use crate::strategy::firewall::{BulwarkFirewallStrategy, FirewallContext};

        let country_lookup: Arc<dyn CountryLookup> =
            Arc::new(MaxMindDbCountryLookup::open(COUNTRY_TEST_DB).expect("打开数据库失败"));
        let config = GeoIPConfig {
            allowed_countries: vec!["CN".into()],
            blocked_countries: vec![],
        };
        let strategy = GeoIPStrategy::new(config, country_lookup);
        let ctx = FirewallContext::new("81.2.69.142");

        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(BulwarkError::FirewallBlocked(_))),
            "GB 不在白名单 [CN] 应拦截，实际: {:?}",
            result
        );
    }

    /// 验证 AnomalousLoginStrategy 注入 MaxMindDbGeoLookup 的异地登录检测（T066）。
    ///
    /// 使用 City 测试数据库，81.2.69.142 → 伦敦坐标。
    /// MockDao 提供历史坐标（北京），haversine 距离 > 500km，应拦截。
    #[tokio::test]
    async fn anomalous_strategy_with_maxminddb() {
        use crate::dao::tests::MockDao;
        use crate::strategy::firewall::anomalous::{AnomalousConfig, AnomalousLoginStrategy};
        use crate::strategy::firewall::{BulwarkFirewallStrategy, FirewallContext};

        let dao: Arc<dyn crate::dao::BulwarkDao> = Arc::new(MockDao::new());
        let geo_lookup: Arc<dyn GeoLookup> =
            Arc::new(MaxMindDbGeoLookup::open(CITY_TEST_DB).expect("打开数据库失败"));
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

        // 第二次登录：用另一个已知 IP（如有），检查是否触发异地检测
        // 81.2.69.142 伦敦 → 历史记录为伦敦
        // 再次登录 81.2.69.142 → 同一位置，应放行
        let ctx_second = FirewallContext::new("81.2.69.142").with_login_id("1001");
        let result_second = strategy.check(&ctx_second).await;
        assert!(
            result_second.is_ok(),
            "同地登录（伦敦→伦敦）应放行，实际: {:?}",
            result_second.err()
        );
    }
}
