//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Credit 计量示例：演示多租户配额消费统计、告警、周期重置。
//!
//! 对应模块：`src/credit/`（`credit-metering` feature 开启时可用）。
//!
//! 流程：
//! 1. 构造 CreditConfig（配额上限 + 周期模式 + 资源权重 + 告警阈值）
//! 2. 创建 CreditMeter 计量引擎
//! 3. 消费 credit（按资源权重扣减）
//! 4. 查询使用情况
//! 5. 触发告警阈值
//! 6. 手动重置
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin credit_metering --features "credit-metering,cache-memory"
//! ```

use garrison::credit::{CreditAlertConfig, CreditConfig, CreditCycle, CreditMeter, CreditSchedule};
use garrison::dao::{GarrisonDao, GarrisonDaoOxcache};
use garrison::error::GarrisonResult;
use std::sync::Arc;

/// 运行 Credit 计量示例。
///
/// 演示 CreditMeter 的消费、查询、告警、重置全流程。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison Credit 计量示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 配置 Credit 计量
    // ----------------------------------------------------------------
    let mut schedule = CreditSchedule::new();
    schedule.insert("login", 1); // 1 次登录 = 1 credit
    schedule.insert("sms", 5); // 1 条短信 = 5 credits
    schedule.insert("api_call", 2); // 1 次 API 调用 = 2 credits

    let config = CreditConfig {
        credit_limit: 100,                        // 每租户 100 credits/月
        cycle: CreditCycle::Rolling { days: 30 }, // 30 天滚动窗口
        schedule,
        alert_thresholds: vec![80, 90, 100], // 80%/90%/100% 告警
        persist_history: false,              // 示例不持久化流水
    };

    println!("[1] CreditConfig 构造完成:");
    println!("    配额上限: {} credits/周期", config.credit_limit);
    println!("    周期模式: Rolling {{ days: 30 }}");
    println!("    资源权重: login=1, sms=5, api_call=2");
    println!("    告警阈值: {:?}%\n", config.alert_thresholds);

    // ----------------------------------------------------------------
    // 2. 创建计量引擎
    // ----------------------------------------------------------------
    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await?);
    let meter = CreditMeter::new(dao, config);
    println!("[2] CreditMeter 创建完成\n");

    // ----------------------------------------------------------------
    // 3. 消费 credit
    // ----------------------------------------------------------------
    let tenant_id = 42;

    // 登录消费（weight=1, cost=1 → 1 credit）
    let r1 = meter.consume_credit(tenant_id, "login", 1).await?;
    println!("[3] 消费 credit:");
    println!(
        "    login ×1 → credits={}, remaining={}, allowed={}",
        r1.consumed_credits, r1.remaining, r1.allowed
    );

    // API 调用消费（weight=2, cost=3 → 6 credits）
    let r2 = meter.consume_credit(tenant_id, "api_call", 3).await?;
    println!(
        "    api_call ×3 → credits={}, total={}, remaining={}",
        r2.consumed_credits, r2.total_consumed, r2.remaining
    );

    // 短信消费（weight=5, cost=2 → 10 credits）
    let r3 = meter.consume_credit(tenant_id, "sms", 2).await?;
    println!(
        "    sms ×2 → credits={}, total={}, remaining={}\n",
        r3.consumed_credits, r3.total_consumed, r3.remaining
    );

    // ----------------------------------------------------------------
    // 4. 查询使用情况
    // ----------------------------------------------------------------
    let usage = meter.get_credit_usage(tenant_id).await?;
    println!("[4] 当前使用情况:");
    println!(
        "    tenant_id={}, consumed={}, limit={}, remaining={}",
        usage.tenant_id, usage.consumed, usage.limit, usage.remaining
    );
    println!("    使用率: {:.1}%\n", usage.usage_percent);

    // ----------------------------------------------------------------
    // 5. 触发告警阈值
    // ----------------------------------------------------------------
    println!("[5] 触发告警阈值:");
    // 消费到 80+ credits 触发 80% 告警
    let r4 = meter.consume_credit(tenant_id, "api_call", 35).await?;
    println!(
        "    api_call ×35 → total={}, usage={:.1}%",
        r4.total_consumed, r4.usage_percent
    );
    if !r4.alerts_triggered.is_empty() {
        println!("    触发告警阈值: {:?}%", r4.alerts_triggered);
    }
    println!();

    // ----------------------------------------------------------------
    // 6. CreditAlertConfig 独立配置
    // ----------------------------------------------------------------
    let alert_config = CreditAlertConfig {
        thresholds: vec![50, 75, 90],
        cooldown_seconds: 1800, // 同一阈值 30 分钟内不重复告警
    };
    println!("[6] CreditAlertConfig:");
    println!("    告警阈值: {:?}%", alert_config.thresholds);
    println!("    冷却间隔: {}s\n", alert_config.cooldown_seconds);

    // ----------------------------------------------------------------
    // 7. 手动重置
    // ----------------------------------------------------------------
    meter.reset_credit(tenant_id).await?;
    let after_reset = meter.get_credit_usage(tenant_id).await?;
    println!("[7] 手动重置后:");
    println!(
        "    consumed={}, remaining={}\n",
        after_reset.consumed, after_reset.remaining
    );

    println!("=== 示例执行完成 ===");
    Ok(())
}
