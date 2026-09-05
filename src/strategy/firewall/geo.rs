//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! IP 地理位置查询抽象（firewall-anomalous / firewall-geoip 共享）。
//!
//! 定义 [`GeoCoord`](crate::strategy::firewall::geo::GeoCoord) 坐标结构与
//! [`GeoLookup`](crate::strategy::firewall::geo::GeoLookup) /
//! [`CountryLookup`](crate::strategy::firewall::geo::CountryLookup) 两个 trait：
//! - [`GeoLookup`](crate::strategy::firewall::geo::GeoLookup)：IP → 坐标（lat/lon），供 `AnomalousLoginStrategy` 算 haversine 距离
//! - [`CountryLookup`](crate::strategy::firewall::geo::CountryLookup)：IP → 国家码（ISO 3166-1 alpha-2），供 `GeoIPStrategy` 做 allow/block 匹配
//!
//! 生产实现可用 maxminddb 读取 MaxMind GeoIP2 数据库（City.mmdb 含坐标，Country.mmdb 含国家码），
//! 测试可用 mock 实现（避免依赖真实数据库文件）。

use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;

/// MaxMindDb 生产后端（由 `firewall-maxminddb` feature 启用）。
#[cfg(feature = "firewall-maxminddb")]
pub mod maxminddb;

/// 地理坐标（纬度 / 经度，十进制度）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GeoCoord {
    /// 纬度（-90.0 ~ 90.0）。
    pub lat: f64,
    /// 经度（-180.0 ~ 180.0）。
    pub lon: f64,
}

impl GeoCoord {
    /// 创建地理坐标，校验 lat ∈ [-90.0, 90.0]、lon ∈ [-180.0, 180.0]。
    ///
    /// # 错误
    /// - 坐标越界时返回 `GarrisonError::InvalidParam`。
    pub fn new(lat: f64, lon: f64) -> Result<Self, GarrisonError> {
        if !(-90.0..=90.0).contains(&lat) {
            return Err(GarrisonError::InvalidParam(format!(
                "firewall-geo-lat-out-of-range::{}",
                lat
            )));
        }
        if !(-180.0..=180.0).contains(&lon) {
            return Err(GarrisonError::InvalidParam(format!(
                "firewall-geo-lon-out-of-range::{}",
                lon
            )));
        }
        Ok(Self { lat, lon })
    }

    /// 序列化为 "lat,lon" 字符串（用于 oxcache 存储）。
    pub fn to_csv(self) -> String {
        format!("{},{}", self.lat, self.lon)
    }

    /// 从 "lat,lon" 字符串解析。
    ///
    /// # 返回
    /// - `Some(coord)`: 解析成功。
    /// - `None`: 格式错误或字段缺失。
    pub fn from_csv(s: &str) -> Option<Self> {
        let mut parts = s.splitn(2, ',');
        let lat: f64 = parts.next()?.trim().parse().ok()?;
        let lon: f64 = parts.next()?.trim().parse().ok()?;
        Self::new(lat, lon).ok()
    }
}

/// IP 地理位置查询 trait（抽象 maxminddb 等后端）。
///
/// 生产实现：`MaxMindDbGeoLookup`（依赖 maxminddb，读取 GeoIP2-City 数据库）。
/// 测试实现：`MockGeoLookup`（硬编码 IP → 坐标映射）。
#[async_trait]
pub trait GeoLookup: Send + Sync {
    /// 查询 IP 的地理坐标。
    ///
    /// # 返回
    /// - `Ok(Some(coord))`: 查询成功，返回坐标。
    /// - `Ok(None)`: IP 无法定位（如私有 IP、数据库无记录）。
    /// - `Err(_)`: 查询失败（如数据库读取错误）。
    async fn lookup(&self, ip: &str) -> GarrisonResult<Option<GeoCoord>>;
}

/// IP → 国家码查询 trait（抽象 maxminddb 等后端）。
///
/// 与 [`GeoLookup`](crate::strategy::firewall::geo::GeoLookup) 并列（单一职责）：`GeoLookup` 返回坐标供 haversine 距离计算，
/// `CountryLookup` 返回 ISO 3166-1 alpha-2 国家码（如 `"CN"` / `"US"`）供 allow/block 匹配。
///
/// 生产实现：`MaxMindDbCountryLookup`（依赖 maxminddb，读取 GeoIP2-Country 数据库）。
/// 测试实现：`MockCountryLookup`（硬编码 IP → 国家码映射）。
#[async_trait]
pub trait CountryLookup: Send + Sync {
    /// 查询 IP 的国家码（ISO 3166-1 alpha-2，大写）。
    ///
    /// # 返回
    /// - `Ok(Some(country))`: 查询成功，返回国家码（如 `"CN"`）。
    /// - `Ok(None)`: IP 无法定位（如私有 IP、数据库无记录）。
    /// - `Err(_)`: 查询失败（如数据库读取错误）。
    async fn lookup_country(&self, ip: &str) -> GarrisonResult<Option<String>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geo_coord_csv_roundtrip() {
        let coord = GeoCoord::new(39.9042, 116.4074).unwrap();
        let csv = coord.to_csv();
        let parsed = GeoCoord::from_csv(&csv).unwrap();
        assert_eq!(coord, parsed);
    }

    #[test]
    fn geo_coord_from_csv_rejects_invalid() {
        assert!(GeoCoord::from_csv("invalid").is_none());
        assert!(GeoCoord::from_csv("abc,def").is_none());
        assert!(GeoCoord::from_csv("").is_none());
        assert!(GeoCoord::from_csv("1.0").is_none());
    }

    /// 验证 `GeoCoord::new` 拒绝纬度越界（> 90 / < -90），错误消息含 "lat"。
    #[test]
    fn geo_coord_new_rejects_lat_out_of_range() {
        let above = GeoCoord::new(90.5, 0.0);
        assert!(
            matches!(&above, Err(GarrisonError::InvalidParam(msg)) if msg.contains("lat")),
            "纬度 90.5 应返回 InvalidParam 且消息含 'lat'，实际: {:?}",
            above
        );
        let below = GeoCoord::new(-90.5, 0.0);
        assert!(
            matches!(&below, Err(GarrisonError::InvalidParam(msg)) if msg.contains("lat")),
            "纬度 -90.5 应返回 InvalidParam 且消息含 'lat'，实际: {:?}",
            below
        );
    }

    /// 验证 `GeoCoord::new` 拒绝经度越界（> 180 / < -180），错误消息含 "lon"。
    #[test]
    fn geo_coord_new_rejects_lon_out_of_range() {
        let above = GeoCoord::new(0.0, 180.5);
        assert!(
            matches!(&above, Err(GarrisonError::InvalidParam(msg)) if msg.contains("lon")),
            "经度 180.5 应返回 InvalidParam 且消息含 'lon'，实际: {:?}",
            above
        );
        let below = GeoCoord::new(0.0, -180.5);
        assert!(
            matches!(&below, Err(GarrisonError::InvalidParam(msg)) if msg.contains("lon")),
            "经度 -180.5 应返回 InvalidParam 且消息含 'lon'，实际: {:?}",
            below
        );
    }

    /// 验证 `GeoCoord::new` 接受边界值（±90 纬度 / ±180 经度均合法）。
    #[test]
    fn geo_coord_new_accepts_boundary_values() {
        assert!(GeoCoord::new(-90.0, -180.0).is_ok());
        assert!(GeoCoord::new(90.0, 180.0).is_ok());
        assert!(GeoCoord::new(0.0, 0.0).is_ok());
    }

    /// 验证 `GeoCoord::new` 拒绝 NaN（NaN 不在任何区间内，fail-closed）。
    #[test]
    fn geo_coord_new_rejects_nan() {
        assert!(GeoCoord::new(f64::NAN, 0.0).is_err());
        assert!(GeoCoord::new(0.0, f64::NAN).is_err());
    }

    /// 验证 `from_csv` 解析时 trim 前后空白（与 oxcache 存储格式兼容）。
    #[test]
    fn geo_coord_from_csv_trims_whitespace() {
        let parsed = GeoCoord::from_csv(" 39.9042 , 116.4074 ").expect("带空白 CSV 应可解析");
        assert_eq!(parsed.lat, 39.9042);
        assert_eq!(parsed.lon, 116.4074);
    }

    /// 验证 `from_csv` 对坐标合法但越界的输入返回 None（内部走 `GeoCoord::new` 校验）。
    #[test]
    fn geo_coord_from_csv_rejects_out_of_range_coords() {
        assert!(GeoCoord::from_csv("91.0,0.0").is_none(), "纬度越界应 None");
        assert!(GeoCoord::from_csv("-90.5,0.0").is_none(), "纬度越界应 None");
        assert!(GeoCoord::from_csv("0.0,181.0").is_none(), "经度越界应 None");
        assert!(
            GeoCoord::from_csv("0.0,-180.5").is_none(),
            "经度越界应 None"
        );
    }

    /// 验证 `to_csv` 输出 "lat,lon" 精确格式（逗号分隔、无空格）。
    #[test]
    fn geo_coord_to_csv_format() {
        let coord = GeoCoord::new(-33.865143, 151.209900).unwrap();
        assert_eq!(coord.to_csv(), "-33.865143,151.2099");
    }

    /// 验证 mock `GeoLookup` / `CountryLookup` trait 可被实现并经 trait 对象调用
    ///（生产用 maxminddb 后端，测试用 mock 避免依赖真实数据库文件）。
    #[tokio::test]
    async fn mock_geo_and_country_lookup_trait_objects() {
        struct MockGeo;
        struct MockCountry;

        #[async_trait]
        impl GeoLookup for MockGeo {
            async fn lookup(&self, ip: &str) -> GarrisonResult<Option<GeoCoord>> {
                if ip == "1.2.3.4" {
                    Ok(Some(GeoCoord::new(1.0, 2.0).unwrap()))
                } else {
                    Ok(None)
                }
            }
        }

        #[async_trait]
        impl CountryLookup for MockCountry {
            async fn lookup_country(&self, ip: &str) -> GarrisonResult<Option<String>> {
                if ip == "1.2.3.4" {
                    Ok(Some("CN".to_string()))
                } else {
                    Ok(None)
                }
            }
        }

        let geo: std::sync::Arc<dyn GeoLookup> = std::sync::Arc::new(MockGeo);
        let country: std::sync::Arc<dyn CountryLookup> = std::sync::Arc::new(MockCountry);

        let hit = geo.lookup("1.2.3.4").await.unwrap();
        assert_eq!(hit, Some(GeoCoord { lat: 1.0, lon: 2.0 }));
        assert_eq!(geo.lookup("unknown").await.unwrap(), None);

        assert_eq!(
            country.lookup_country("1.2.3.4").await.unwrap(),
            Some("CN".into())
        );
        assert_eq!(country.lookup_country("unknown").await.unwrap(), None);
    }
}
