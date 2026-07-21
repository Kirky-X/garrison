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

use crate::error::GarrisonResult;
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
    /// 创建地理坐标。
    pub fn new(lat: f64, lon: f64) -> Self {
        Self { lat, lon }
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
        let lat = parts.next()?.trim().parse().ok()?;
        let lon = parts.next()?.trim().parse().ok()?;
        Some(Self { lat, lon })
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
        let coord = GeoCoord::new(39.9042, 116.4074);
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
}
