//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! ABAC 策略示例：演示 AbacEngine 的 Cedar 策略求值。
//!
//! 对应模块：`src/abac/`（`abac` feature 开启时可用）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin abac_policy --features full
//! ```
//!
//! 注意：`check_abac_with_policy` 是宏入口，需要全局引擎初始化 + 登录上下文。
//! 本示例直接使用 `AbacEngine::evaluate_with_temp_policy` 演示核心求值逻辑，
//! 避免引入 BulwarkManager 全局状态依赖。

use bulwark::abac::AbacEngine;
use bulwark::error::BulwarkResult;

/// Cedar schema JSON：定义 User / Resource 实体类型和 access 动作。
const SCHEMA_JSON: &str = r#"{
    "": {
        "entityTypes": {
            "User": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "department": { "type": "String" }
                    }
                }
            },
            "Resource": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "owner": { "type": "String" }
                    }
                }
            }
        },
        "actions": {
            "access": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Resource"]
                }
            }
        }
    }
}"#;

/// 运行 ABAC 策略示例。
///
/// 演示：
/// 1. 从 JSON schema 创建 AbacEngine
/// 2. 使用临时策略求值：条件 `1 == 1` → Allow
/// 3. 使用临时策略求值：条件 `1 == 2` → Deny
/// 4. 加载共享 permit 策略后求值 → Allow
/// 5. 卸载策略后求值 → Deny
pub async fn run() -> BulwarkResult<()> {
    println!("=== Bulwark ABAC 策略示例 ===\n");

    // 1. 创建 AbacEngine
    let engine = AbacEngine::new(SCHEMA_JSON)?;
    println!("[1] AbacEngine 创建成功（schema: User / Resource / access 动作）\n");

    // 2. 临时策略求值：when { 1 == 1 } → Allow
    let permit_policy =
        r#"permit(principal, action == Action::"access", resource) when { 1 == 1 };"#;
    let decision_allow = engine
        .evaluate_with_temp_policy(
            r#"User::"alice""#,
            r#"Action::"access""#,
            r#"Resource::"doc1""#,
            None,
            permit_policy,
        )
        .await?;
    println!("[2] 临时策略求值（when {{ 1 == 1 }}）:");
    println!("    allowed = {}（期望: true）\n", decision_allow.allowed);
    assert!(decision_allow.allowed, "1 == 1 应 Allow");

    // 3. 临时策略求值：when { 1 == 2 } → Deny
    let deny_policy = r#"permit(principal, action == Action::"access", resource) when { 1 == 2 };"#;
    let decision_deny = engine
        .evaluate_with_temp_policy(
            r#"User::"alice""#,
            r#"Action::"access""#,
            r#"Resource::"doc1""#,
            None,
            deny_policy,
        )
        .await?;
    println!("[3] 临时策略求值（when {{ 1 == 2 }}）:");
    println!("    allowed = {}（期望: false）\n", decision_deny.allowed);
    assert!(!decision_deny.allowed, "1 == 2 应 Deny");

    // 4. 加载共享 permit 策略后求值 → Allow
    engine
        .load_policy(
            "p1",
            r#"permit(principal, action == Action::"access", resource);"#,
        )
        .await?;
    let shared_decision = engine
        .evaluate(
            r#"User::"alice""#,
            r#"Action::"access""#,
            r#"Resource::"doc1""#,
            None,
        )
        .await?;
    println!("[4] 共享策略求值（已加载 permit）:");
    println!("    allowed = {}（期望: true）\n", shared_decision.allowed);
    assert!(shared_decision.allowed, "加载 permit 后应 Allow");

    // 5. 卸载策略后求值 → Deny
    engine.unload_policy("p1").await?;
    let after_unload = engine
        .evaluate(
            r#"User::"alice""#,
            r#"Action::"access""#,
            r#"Resource::"doc1""#,
            None,
        )
        .await?;
    println!("[5] 共享策略求值（已卸载 permit）:");
    println!("    allowed = {}（期望: false）\n", after_unload.allowed);
    assert!(!after_unload.allowed, "卸载 permit 后应 Deny");

    println!("=== 示例执行完成 ===");
    Ok(())
}
