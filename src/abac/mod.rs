// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! ABAC（Attribute-Based Access Control）策略引擎模块：基于 `cedar-policy` 提供 principal-action-resource 三元组策略求值。
//!
//! ABAC 是 RBAC 的增量校验层（RBAC 通过后再检查，不替换 RBAC）。核心类型：`AbacEngine` 求值器、`EntityLoader` 数据源 trait、`EmptyEntityLoader` / `StaticEntityLoader` 内置实现；全局引擎见 `init_abac_engine`，宏入口 `check_abac_with_policy`。
//!
//! feature 依赖：启用 `abac` feature 时编译核心引擎；关闭时 `check_abac_with_policy` 提供 fail-closed 实现，确保宏生成代码在任意 feature 组合下均可编译。

#[cfg(feature = "abac")]
mod engine;

#[cfg(feature = "abac")]
mod loader;

#[cfg(feature = "abac")]
use crate::error::GarrisonResult;

#[cfg(feature = "abac")]
pub use engine::AbacEngine;

#[cfg(feature = "abac")]
pub use loader::{EmptyEntityLoader, StaticEntityLoader};

// EntityLoader trait

/// Cedar Entities 数据源 trait：调用方注入实体数据源，支持基于属性的 ABAC 策略（如 `resource.owner == principal.id`）。
///
/// 内置 [`EmptyEntityLoader`]（返回空 Entities）与 [`StaticEntityLoader`]（持有预构造 Entities，clone 返回）；生产可实现本 trait 从数据库 / 远程服务加载实体：
///
/// ```ignore
/// #[async_trait::async_trait]
/// impl EntityLoader for MyDbEntityLoader {
/// async fn load_entities(&self) -> GarrisonResult<cedar_policy::Entities> {
/// // 从数据库查询实体并构造 Entities
/// (未实现占位)
/// }
/// }
/// ```
///
/// # 缓存语义
///
/// `load_entities` 每次 `evaluate` 时调用；决策缓存 key 含 (principal, action, resource, context 摘要) 但不含实体属性状态——实体属性运行期变更（如 owner 转移、组成员变更）时调用方必须在变更点调用 [`AbacEngine::invalidate_entities`] 清空缓存，否则最长 TTL 60s 内返回陈旧决策（安全风险）；策略集变更由引擎自动清空缓存。`load_entities` 出错经 `?` 传播，缓存不受污染。
#[cfg(feature = "abac")]
#[async_trait::async_trait]
pub trait EntityLoader: Send + Sync {
    /// 加载 Cedar Entities 集合；失败（数据源不可达、解析错误等）返回 `GarrisonError` 并经 `?` 传播。
    async fn load_entities(&self) -> GarrisonResult<cedar_policy::Entities>;
}

#[cfg(feature = "abac")]
mod init;
#[cfg(feature = "abac")]
pub use init::*;

// abac feature 关闭时 check_abac_with_policy 仍须可用（宏无条件生成调用），降级为 fail-closed

/// `abac` feature 缺失时的降级策略（进程级原子开关）。
///
/// 0（默认）= Deny（fail-closed）：声明了 `abac` 策略却未启用 feature 时返回 `Err(Config)`，杜绝"编译通过但 ABAC 校验被静默放行"；1 = AllowWithWarn（显式 opt-in，放行并 warn，仅测试或可接受风险的过渡场景）。
#[cfg(not(feature = "abac"))]
static ABAC_MISSING_FEATURE_POLICY: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

/// 设置 `abac` feature 缺失时的行为：true 切换 AllowWithWarn（放行 + 告警）opt-in 降级，false 恢复默认 Deny（fail-closed）。
#[cfg(not(feature = "abac"))]
pub fn set_abac_missing_feature_policy(allow_with_warn: bool) {
    ABAC_MISSING_FEATURE_POLICY.store(
        if allow_with_warn { 1 } else { 0 },
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// ABAC 策略校验入口（`abac` feature 关闭时的 fail-closed 实现）：宏无条件生成调用，故必须始终存在以保证任意 feature 组合可编译。
///
/// 端点未声明 `abac` 策略（`abac_expr` 空）→ `Ok(())` no-op（无授权保障可丢失）；声明了策略但 feature 未启用 → 默认 `Err(Config)`（fail-closed，属性级授权保障已丢失），可经 [`set_abac_missing_feature_policy`](true) opt-in 为 AllowWithWarn。
#[cfg(not(feature = "abac"))]
pub async fn check_abac_with_policy(
    action: &str,
    _resource: &str,
    abac_expr: &str,
) -> crate::error::GarrisonResult<()> {
    if abac_expr.trim().is_empty() {
        // 未声明 ABAC 策略，无授权保障可丢失，no-op 安全。
        return Ok(());
    }
    if ABAC_MISSING_FEATURE_POLICY.load(std::sync::atomic::Ordering::Relaxed) == 1 {
        tracing::warn!(
            abac_expr = %abac_expr,
            action = %action,
            "ABAC feature disabled but endpoint requires abac policy; \
             AllowWithWarn opt-in grants access (enable 'abac' feature for real enforcement)"
        );
        return Ok(());
    }
    Err(crate::error::GarrisonError::Config(format!(
        "ABAC policy required by endpoint (action={action}, abac_expr={abac_expr}) \
         but 'abac' feature is disabled (fail-closed). \
         Enable 'abac' feature or remove the abac attribute."
    )))
}

#[cfg(all(test, not(feature = "abac")))]
mod no_feature_tests {
    use super::*;

    // ABAC_MISSING_FEATURE_POLICY 进程级共享：涉及它的测试必须互斥，否则并行下 opt-in 的"置 1→恢复 0"窗口会让 fail-closed 测试读到 1
    static ABAC_POLICY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试进程退出即释放；互斥正确性优先
    async fn abac_with_expr_but_feature_off_is_fail_closed() {
        let _guard = ABAC_POLICY_LOCK.lock().unwrap();
        let r = check_abac_with_policy(
            "order:read",
            "Resource::\"order\"",
            "resource.owner == principal.id",
        )
        .await;
        assert!(
            matches!(r, Err(crate::error::GarrisonError::Config(_))),
            "应 fail-closed，实际: {:?}",
            r
        );
    }

    #[tokio::test]
    async fn abac_without_expr_is_noop_ok() {
        let r = check_abac_with_policy("order:read", "Resource::\"order\"", "").await;
        assert!(r.is_ok(), "空 abac_expr 应 no-op 放行，实际: {:?}", r);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试进程退出即释放；互斥正确性优先
    async fn abac_allow_with_warn_opt_in_grants() {
        let _guard = ABAC_POLICY_LOCK.lock().unwrap();
        set_abac_missing_feature_policy(true);
        let r = check_abac_with_policy(
            "order:read",
            "Resource::\"order\"",
            "resource.owner == principal.id",
        )
        .await;
        assert!(r.is_ok(), "opt-in 应放行，实际: {:?}", r);
        set_abac_missing_feature_policy(false);
    }
}

#[cfg(all(test, feature = "abac"))]
mod tests;
