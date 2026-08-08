//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 健康检查完整流程示例：探针注册 → 并发执行 → 聚合报告。
//!
//! 演示 Garrison 健康检查模块的完整业务链路：
//! 1. HealthRegistry 注册多个检查器（Config / Cache / DB）
//! 2. 并发执行所有检查器，聚合健康报告
//! 3. 自定义检查器实现（模拟外部依赖健康探测）
//! 4. 降级场景：部分依赖故障时的整体状态判定
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin health_check --features "cache-memory db-sqlite"
//! ```

use garrison::dao::{init_dbnexus, GarrisonDaoOxcache, GarrisonMigration};
use garrison::error::GarrisonResult;
use garrison::health::{CacheHealthCheck, ConfigHealthCheck, DbHealthCheck};
use garrison::health::{HealthCheck, HealthRegistry, HealthStatus};
use garrison::GarrisonConfig;
use std::path::PathBuf;
use std::sync::Arc;

/// 运行健康检查完整流程。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 健康检查完整流程 ===\n");

    // ================================================================
    // 场景一：内置检查器 + 聚合报告
    // ================================================================
    demo_builtin_checks().await?;

    // ================================================================
    // 场景二：自定义检查器
    // ================================================================
    demo_custom_check().await?;

    // ================================================================
    // 场景三：降级场景
    // ================================================================
    demo_degraded_scenario().await?;

    println!("\n=== 健康检查流程演示完成 ===");
    println!("已展示功能：");
    println!("  • 内置检查器（Config / Cache / DB）");
    println!("  • 并发执行 + 聚合报告（HealthRegistry.check_all）");
    println!("  • 自定义检查器（实现 HealthCheck trait）");
    println!("  • 降级场景（部分依赖故障 → Degraded 状态）");

    Ok(())
}

/// 场景一：内置检查器 + 聚合报告。
///
/// 注册 Config / Cache / DB 三个内置检查器，验证全部 Healthy。
async fn demo_builtin_checks() -> GarrisonResult<()> {
    println!("--- 场景一：内置检查器 + 聚合报告 ---");

    // 初始化基础设施
    let config = Arc::new(GarrisonConfig::default_config());
    let _dao = Arc::new(GarrisonDaoOxcache::new().await?);

    let pool = init_dbnexus("sqlite::memory:").await?;
    let migration =
        GarrisonMigration::with_base_dir(pool.clone(), PathBuf::from("../migrations/sqlite"));
    migration.run_all().await?;

    // 注册检查器
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(ConfigHealthCheck::new(config.clone())));
    registry.register(Box::new(CacheHealthCheck::new()));
    registry.register(Box::new(DbHealthCheck::new()));

    // 并发执行所有检查
    let report = registry.check_all().await;

    println!("[1] 健康检查报告：");
    println!("    整体状态: {:?}", report.overall);
    for check in &report.checks {
        let msg = check.message.as_deref().unwrap_or("-");
        println!("    • {} → {:?} ({})", check.name, check.status, msg);
    }

    assert_eq!(report.overall, HealthStatus::Healthy);
    assert_eq!(report.checks.len(), 3);
    println!("    ✓ 所有内置检查器均 Healthy\n");

    Ok(())
}

/// 自定义健康检查器：模拟 Redis 连通性探测。
struct RedisHealthCheck {
    connected: bool,
}

impl HealthCheck for RedisHealthCheck {
    fn name(&self) -> &str {
        "redis"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = GarrisonResult<HealthStatus>> + Send>>
    {
        let connected = self.connected;
        Box::pin(async move {
            if connected {
                Ok(HealthStatus::Healthy)
            } else {
                Ok(HealthStatus::Unhealthy)
            }
        })
    }
}

/// 自定义健康检查器：模拟慢响应（降级）。
struct SlowDependencyCheck;

impl HealthCheck for SlowDependencyCheck {
    fn name(&self) -> &str {
        "slow-dep"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = GarrisonResult<HealthStatus>> + Send>>
    {
        Box::pin(async { Ok(HealthStatus::Degraded) })
    }
}

/// 场景二：自定义检查器。
async fn demo_custom_check() -> GarrisonResult<()> {
    println!("--- 场景二：自定义检查器 ---");

    let mut registry = HealthRegistry::new();

    // 自定义 Redis 检查（模拟连接正常）
    registry.register(Box::new(RedisHealthCheck { connected: true }));
    println!("[1] 注册自定义检查器：Redis（connected=true）");

    let report = registry.check_all().await;
    assert_eq!(report.overall, HealthStatus::Healthy);
    println!("    整体状态: {:?} ✓", report.overall);

    // 自定义 Redis 检查（模拟连接断开）
    let mut registry2 = HealthRegistry::new();
    registry2.register(Box::new(RedisHealthCheck { connected: false }));
    println!("[2] 注册自定义检查器：Redis（connected=false）");

    let report2 = registry2.check_all().await;
    assert_eq!(report2.overall, HealthStatus::Unhealthy);
    println!(
        "    整体状态: {:?} ✓（Redis 故障 → 整体 Unhealthy）",
        report2.overall
    );

    println!();
    Ok(())
}

/// 场景三：降级场景。
///
/// 模拟部分依赖故障：核心服务正常 + 非核心依赖降级。
async fn demo_degraded_scenario() -> GarrisonResult<()> {
    println!("--- 场景三：降级场景（部分依赖故障）---");

    let config = Arc::new(GarrisonConfig::default_config());

    let mut registry = HealthRegistry::new();

    // 核心服务正常
    registry.register(Box::new(ConfigHealthCheck::new(config.clone())));
    registry.register(Box::new(CacheHealthCheck::new()));

    // 非核心依赖降级（如外部通知服务不可用）
    registry.register(Box::new(SlowDependencyCheck));

    let report = registry.check_all().await;

    println!("[1] 混合健康状态报告：");
    println!("    整体状态: {:?}", report.overall);
    for check in &report.checks {
        println!("    • {} → {:?}", check.name, check.status);
    }

    // 聚合规则：有 Degraded 且无 Unhealthy → 整体 Degraded
    assert_eq!(report.overall, HealthStatus::Degraded);
    println!("\n    ✓ 聚合规则验证：");
    println!("      Config → Healthy（核心正常）");
    println!("      Cache → Healthy（缓存正常）");
    println!("      slow-dep → Degraded（非核心降级）");
    println!("      整体 → Degraded（有降级 + 无不可用 = 降级）");

    // 序列化报告为 JSON（模拟 /health/ready 响应）
    let json = serde_json::to_string_pretty(&report).unwrap();
    println!("\n[2] JSON 报告（模拟 /health/ready 响应）：");
    println!("{}", json);

    Ok(())
}
