//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 三层缓存示例：演示 L1（oxcache 内存）→ L2（DAO 持久化）→ L3（interface 回调）架构。
//!
//! 对应模块：`src/cache/three_tier.rs`（`three-tier-cache` feature 开启时可用）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin three_tier_cache --features "three-tier-cache"
//! ```

use garrison::error::GarrisonResult;

// ============================================================================
// 1. 三层缓存配置
// ============================================================================

fn demo_cache_config() {
    use garrison::config::{
        DEFAULT_L1_CACHE_CAPACITY, DEFAULT_L1_CACHE_TTL_SECS, DEFAULT_L2_CACHE_TTL_SECS,
    };

    println!("[1] 三层缓存配置:");
    println!("    默认值（来自 garrison::config 常量）:");
    println!(
        "      • L1 缓存 TTL:     {}s（oxcache 内存层，短 TTL 保证新鲜度）",
        DEFAULT_L1_CACHE_TTL_SECS
    );
    println!(
        "      • L2 缓存 TTL:     {}s（DAO 持久化层，长 TTL 减少 L3 压力）",
        DEFAULT_L2_CACHE_TTL_SECS
    );
    println!(
        "      • L1 缓存容量:     {} 条（超出后按 LRU 淘汰）",
        DEFAULT_L1_CACHE_CAPACITY
    );
    println!();

    // 演示自定义配置
    let l1_ttl = 60; // 生产环境可适当调大
    let l2_ttl = 3600; // L2 持久化缓存可设更长
    let capacity = 50_000;

    println!("    自定义配置示例:");
    println!("      • l1_cache_ttl_secs:     {}", l1_ttl);
    println!("      • l2_cache_ttl_secs:     {}", l2_ttl);
    println!("      • l1_cache_capacity:     {}", capacity);
    println!();

    // 校验约束
    println!("    校验约束（GarrisonConfig::validate 强制）:");
    println!("      • l1_cache_ttl_secs > 0（= 0 时 Err）");
    println!("      • l2_cache_ttl_secs > 0（= 0 时 Err）");
    println!("      • l1_cache_capacity > 0（= 0 时 Err）");
    println!();
}

// ============================================================================
// 2. 三层缓存查询流程
// ============================================================================

fn demo_query_flow() {
    println!("[2] 三层缓存查询流程（以权限查询为例）:");
    println!("    ┌─────────────────────────────────────────────┐");
    println!("    │  get_permissions(login_id)                  │");
    println!("    │  缓存键: perm:cache:{{login_id}}             │");
    println!("    ├─────────────────────────────────────────────┤");
    println!("    │  1. L1 命中 → 反序列化返回（无锁快路径）    │");
    println!("    │  2. L1 miss → L2 命中 → 回填 L1 → 返回     │");
    println!("    │  3. L1+L2 miss → L3 interface → 回填 → 返回│");
    println!("    └─────────────────────────────────────────────┘");
    println!();
    println!("    关键设计:");
    println!("      • Per-key singleflight 锁防缓存击穿（同一 key 并发只触发 1 次 L3）");
    println!(
        "      • 失效顺序: 先 L2 再 L1（避免窗口期 L1 miss → L2 hit 旧数据 → 回填 L1 旧数据）"
    );
    println!("      • 查询方法: get_permissions / get_roles / get_user_info");
    println!();
}

// ============================================================================
// 3. UserCacheService 构造与集成
// ============================================================================

fn demo_service_construction() {
    println!("[3] UserCacheService 构造与集成:");
    println!();
    println!("    // 方式 1: 手动构造（适合需要自定义参数的场景）");
    println!("    use garrison::cache::UserCacheService;");
    println!("    let ucs = UserCacheService::new(");
    println!("        dao,           // Arc<dyn GarrisonDao>");
    println!("        interface,     // Arc<dyn GarrisonPermissionStrategy>");
    println!("        l1_ttl_secs,   // u64, L1 缓存 TTL");
    println!("        l2_ttl_secs,   // u64, L2 缓存 TTL");
    println!("        l1_capacity,   // u64, L1 最大条目数");
    println!("    )?;");
    println!();
    println!("    // 方式 2: 通过 GarrisonManager builder 自动构造");
    println!(
        "    // 启用 three-tier-cache feature 后，builder.build() 时自动创建 UserCacheService"
    );
    println!("    // 也可通过 builder.with_user_cache_service(ucs) 注入自定义实例");
    println!();
    println!("    // 缓存失效:");
    println!("    ucs.invalidate(login_id).await?;  // 同时失效 L1 + L2");
    println!();
}

// ============================================================================
// 4. 配置集成到 GarrisonConfig
// ============================================================================

fn demo_config_integration() {
    println!("[4] GarrisonConfig 集成:");
    println!("    // 在 GarrisonConfig 中设置三层缓存参数:");
    println!("    let mut config = GarrisonConfig::default_config();");
    println!("    config.l1_cache_ttl_secs = 60;     // L1 TTL 60s");
    println!("    config.l2_cache_ttl_secs = 3600;   // L2 TTL 1h");
    println!("    config.l1_cache_capacity = 50_000;  // L1 容量 5 万条");
    println!();
    println!("    // config.validate() 会校验三层缓存参数 > 0");
    println!("    // GarrisonManager::builder() 读取 config 中的缓存参数自动构造 UserCacheService");
    println!();
}

/// 运行三层缓存示例。
///
/// 演示三层缓存架构配置、查询流程、UserCacheService 构造与集成。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 三层缓存示例 ===\n");

    demo_cache_config();
    demo_query_flow();
    demo_service_construction();
    demo_config_integration();

    println!("=== 示例执行完成 ===");
    Ok(())
}
