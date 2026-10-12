// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 异地登录检测策略：`AnomalousLoginStrategy` 实现 `GarrisonFirewallStrategy`，用 oxcache key
//! `anom:user:{login_id}` 存储用户历史登录 IP 的地理坐标，新登录 geo 与历史 geo 的 haversine 距离
//! 超阈值（`known_geo_threshold` km）则拦截（`FirewallBlocked`）。
//!
//! 无法定位当前 IP 时放行（不因数据缺失拦截）；无历史 geo 则写入当前 geo 并放行，有历史且未超阈值则更新为当前 geo。
//! 依赖 `GeoLookup` 抽象（生产实现 `GeoMatcherLookup`，测试用 `MockGeoLookup`）。

use super::geo::{GeoCoord, GeoLookup};
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::strategy::firewall::{FirewallContext, GarrisonFirewallStrategy};
use async_trait::async_trait;
use std::sync::Arc;

/// 异地登录检测配置：`known_geo_threshold`（km）显式配置（确定性逻辑），不交给模型判断"是否异常"。
#[derive(Debug, Clone)]
pub struct AnomalousConfig {
    /// 已知地理位置阈值（km），新登录地与历史地距离超此值则拦截。
    pub known_geo_threshold: u32,
}

impl Default for AnomalousConfig {
    fn default() -> Self {
        Self {
            known_geo_threshold: 500,
        }
    }
}

/// 异地登录检测策略。
///
/// # 构造
///
/// ```ignore
/// use std::sync::Arc;
/// use garrison::dao::GarrisonDao;
/// use garrison::strategy::firewall::anomalous::{AnomalousConfig, AnomalousLoginStrategy};
/// use garrison::strategy::firewall::geo::GeoLookup;
///
/// let dao: Arc<dyn GarrisonDao> = /* oxcache 实现 */;
/// let geo: Arc<dyn GeoLookup> = /* maxminddb 实现或 mock */;
/// let strategy = AnomalousLoginStrategy::new(AnomalousConfig::default(), dao, geo);
/// ```
pub struct AnomalousLoginStrategy {
    /// 配置（距离阈值 km）。
    config: AnomalousConfig,
    /// DAO（oxcache 抽象，用于历史 geo 存储）。
    dao: Arc<dyn GarrisonDao>,
    /// IP → geo 查询后端（maxminddb 或 mock）。
    geo_lookup: Arc<dyn GeoLookup>,
}

impl AnomalousLoginStrategy {
    /// 创建异地登录检测策略实例（`config` 为距离阈值 km，`dao` 用于历史 geo 存储，`geo_lookup` 为 IP → geo 查询后端）。
    pub fn new(
        config: AnomalousConfig,
        dao: Arc<dyn GarrisonDao>,
        geo_lookup: Arc<dyn GeoLookup>,
    ) -> Self {
        Self {
            config,
            dao,
            geo_lookup,
        }
    }

    /// 更新历史坐标到当前位置（`set_permanent`），统一 `check` 中 None 分支与 Some 分支 else 子句的写调用。
    async fn update_historic_coord(
        &self,
        key: &str,
        current_coord: GeoCoord,
    ) -> GarrisonResult<()> {
        self.dao.set_permanent(key, &current_coord.to_csv()).await
    }
}

/// 用 haversine 公式计算两个地理坐标间的球面距离（公里），地球半径取 6371 km（平均半径）。
fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R_KM: f64 = 6371.0;
    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a =
        (dlat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    R_KM * c
}

#[async_trait]
impl GarrisonFirewallStrategy for AnomalousLoginStrategy {
    async fn check(&self, ctx: &FirewallContext) -> GarrisonResult<()> {
        let login_id = ctx.login_id.as_ref().ok_or_else(|| {
            GarrisonError::InvalidParam("firewall-anomalous-need-login-id::".to_string())
        })?;

        // 无法定位当前 IP 则放行（不因数据缺失拦截）
        let current_coord = match self.geo_lookup.lookup(&ctx.ip).await? {
            Some(c) => c,
            None => return Ok(()),
        };

        let key = format!("anom:user:{}", login_id);

        // 无历史 geo 则写入当前 geo 并放行
        match self.dao.get(&key).await? {
            None => {
                self.update_historic_coord(&key, current_coord).await?;
                Ok(())
            },
            Some(csv) => {
                let historic_coord = GeoCoord::from_csv(&csv).ok_or_else(|| {
                    GarrisonError::Dao(format!(
                        "firewall-anomalous-geo-parse-failed::{}::{}",
                        key, csv
                    ))
                })?;
                let distance = haversine_km(
                    historic_coord.lat,
                    historic_coord.lon,
                    current_coord.lat,
                    current_coord.lon,
                );
                if distance > self.config.known_geo_threshold as f64 {
                    let loc = format!("{}f {}", login_id, ctx.ip);
                    let detail = format!(
                        "distance {:.0}km exceeds threshold {}km",
                        distance, self.config.known_geo_threshold
                    );
                    Err(GarrisonError::FirewallBlocked(format!(
                        "firewall-anomalous-distance-exceeded::{}::{}",
                        loc, detail
                    )))
                } else {
                    // 距离未超阈值：更新历史 geo 为当前位置
                    self.update_historic_coord(&key, current_coord).await?;
                    Ok(())
                }
            },
        }
    }
}

inventory::submit! {
    crate::strategy::firewall::StrategyRegistration {
        name: "anomalous",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::error::GarrisonError;
    use crate::strategy::firewall::GeoCoord;
    use std::collections::HashMap;

    /// Mock GeoLookup 实现，硬编码 IP → 坐标映射（避免依赖真实 GeoIP 数据库）。
    struct MockGeoLookup {
        map: HashMap<String, GeoCoord>,
    }

    impl MockGeoLookup {
        fn new() -> Self {
            Self {
                map: HashMap::new(),
            }
        }

        fn with(mut self, ip: &str, coord: GeoCoord) -> Self {
            self.map.insert(ip.to_string(), coord);
            self
        }
    }

    #[async_trait]
    impl GeoLookup for MockGeoLookup {
        async fn lookup(&self, ip: &str) -> GarrisonResult<Option<GeoCoord>> {
            Ok(self.map.get(ip).copied())
        }
    }

    #[test]
    fn haversine_beijing_to_new_york_exceeds_500km() {
        // 北京 (39.9042, 116.4074) → 纽约 (40.7128, -74.0060)
        let dist = haversine_km(39.9042, 116.4074, 40.7128, -74.0060);
        assert!(dist > 500.0, "北京→纽约距离应 > 500km，实际: {}", dist);
        assert!(dist > 10000.0, "北京→纽约距离应 > 10000km，实际: {}", dist);
    }

    #[test]
    fn haversine_same_city_under_10km() {
        // 北京两点的距离应 < 10km
        let dist = haversine_km(39.9042, 116.4074, 39.9100, 116.4000);
        assert!(dist < 10.0, "同城距离应 < 10km，实际: {}", dist);
    }

    /// 验证异地登录检测：历史北京，新登录纽约，距离>500km，拦截
    #[tokio::test]
    async fn anomalous_blocks_cross_continent_login() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let geo: Arc<dyn GeoLookup> = Arc::new(
            MockGeoLookup::new()
                .with("1.1.1.1", GeoCoord::new(39.9042, 116.4074).unwrap()) // 北京
                .with("2.2.2.2", GeoCoord::new(40.7128, -74.0060).unwrap()), // 纽约
        );
        let config = AnomalousConfig {
            known_geo_threshold: 500,
        };
        let strategy = AnomalousLoginStrategy::new(config, dao, geo);

        let ctx_first = FirewallContext::new("1.1.1.1").with_login_id("1001");
        let ctx_second = FirewallContext::new("2.2.2.2").with_login_id("1001");

        assert!(
            strategy.check(&ctx_first).await.is_ok(),
            "首次登录应放行（无历史记录）"
        );

        // 第二次登录：北京→纽约，距离 > 500km，拦截
        let result = strategy.check(&ctx_second).await;
        assert!(
            matches!(result, Err(GarrisonError::FirewallBlocked(_))),
            "异地登录应返回 FirewallBlocked，实际: {:?}",
            result
        );
    }

    /// 验证首次登录放行并写入历史 geo。
    #[tokio::test]
    async fn anomalous_first_login_passes_and_writes_geo() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let geo: Arc<dyn GeoLookup> = Arc::new(
            MockGeoLookup::new().with("1.1.1.1", GeoCoord::new(39.9042, 116.4074).unwrap()),
        );
        let config = AnomalousConfig {
            known_geo_threshold: 500,
        };
        let strategy = AnomalousLoginStrategy::new(config, dao.clone(), geo);

        let ctx = FirewallContext::new("1.1.1.1").with_login_id("1001");

        assert!(strategy.check(&ctx).await.is_ok());

        let stored = dao.get("anom:user:1001").await.unwrap();
        assert!(stored.is_some(), "首次登录后应写入历史 geo");
        let coord = GeoCoord::from_csv(&stored.unwrap()).unwrap();
        assert!((coord.lat - 39.9042).abs() < 1e-6);
        assert!((coord.lon - 116.4074).abs() < 1e-6);
    }

    /// 验证同城登录（距离 < 阈值）放行。
    #[tokio::test]
    async fn anomalous_same_city_login_passes() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let geo: Arc<dyn GeoLookup> = Arc::new(
            MockGeoLookup::new()
                .with("1.1.1.1", GeoCoord::new(39.9042, 116.4074).unwrap())
                .with("1.1.1.2", GeoCoord::new(39.9100, 116.4000).unwrap()), // 同城
        );
        let config = AnomalousConfig {
            known_geo_threshold: 500,
        };
        let strategy = AnomalousLoginStrategy::new(config, dao, geo);

        let ctx_first = FirewallContext::new("1.1.1.1").with_login_id("1001");
        let ctx_second = FirewallContext::new("1.1.1.2").with_login_id("1001");

        assert!(strategy.check(&ctx_first).await.is_ok());
        assert!(
            strategy.check(&ctx_second).await.is_ok(),
            "同城登录（距离 < 阈值）应放行"
        );
    }

    /// 验证 login_id=None 返回 InvalidParam（显性失败）。
    #[tokio::test]
    async fn anomalous_requires_login_id() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let geo: Arc<dyn GeoLookup> = Arc::new(MockGeoLookup::new());
        let config = AnomalousConfig {
            known_geo_threshold: 500,
        };
        let strategy = AnomalousLoginStrategy::new(config, dao, geo);
        let ctx = FirewallContext::new("1.1.1.1"); // 无 login_id

        let result = strategy.check(&ctx).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "login_id=None 应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// 保护网测试：确保首次登录（无历史坐标）经 `update_historic_coord` 精确写入当前坐标 csv。
    #[tokio::test]
    async fn check_updates_historic_coord_on_first_login() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let current_coord = GeoCoord::new(39.9042, 116.4074).unwrap(); // 北京
        let expected_csv = current_coord.to_csv();
        let geo: Arc<dyn GeoLookup> = Arc::new(MockGeoLookup::new().with("1.1.1.1", current_coord));
        let config = AnomalousConfig {
            known_geo_threshold: 500,
        };
        let strategy = AnomalousLoginStrategy::new(config, dao.clone(), geo);

        let ctx = FirewallContext::new("1.1.1.1").with_login_id("1001");

        assert!(
            strategy.check(&ctx).await.is_ok(),
            "首次登录应放行（无历史记录）"
        );

        // 断言 set_permanent 被调用：通过 dao.get 验证写入了当前坐标（精确匹配 csv）
        let stored = dao.get("anom:user:1001").await.unwrap();
        assert_eq!(
            stored.as_deref(),
            Some(expected_csv.as_str()),
            "首次登录后应调用 set_permanent 写入当前坐标（精确匹配 csv）"
        );
    }
}
