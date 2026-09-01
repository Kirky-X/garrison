//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! ABAC（Attribute-Based Access Control）策略引擎模块。
//!
//! 基于 `cedar-policy` crate，提供 principal-action-resource 三元组策略求值。
//! ABAC 作为 RBAC 的增量校验层，不替换 RBAC。RBAC 通过后再检查 ABAC。
//!
//! # 核心类型
//!
//! - `AbacEngine`：Cedar 策略求值器（`abac` feature 开启时可用）
//! - `EntityLoader`：Cedar Entities 数据源 trait
//! - `EmptyEntityLoader` / `StaticEntityLoader`：内置实现
//!
//! # 全局引擎管理
//!
//! - `init_abac_engine`：初始化全局 AbacEngine（`abac` feature 开启时可用）
//! - `check_abac_with_policy`：宏入口，RBAC 通过后调用 ABAC 求值
//!
//! # Feature 依赖
//!
//! 启用 `abac` feature 时编译核心引擎，依赖 `cedar-policy` crate。
//! `check_abac_with_policy` 在 `abac` feature 关闭时提供 fail-closed stub，
//! 确保宏生成的代码在任意 feature 组合下均可编译。

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

// ============================================================================
// EntityLoader trait
// ============================================================================

/// Cedar Entities 数据源 trait。
///
/// 抽象实体加载逻辑，让调用方注入实体数据源，支持基于属性的 ABAC 策略
/// （如 `resource.owner == principal.id`）。
///
/// # 内置实现
///
/// - [`EmptyEntityLoader`]：返回空 Entities（向后兼容默认行为）
/// - [`StaticEntityLoader`]：持有预构造 Entities，clone 返回（测试与固定实体场景）
///
/// # 自定义实现
///
/// 生产代码可实现本 trait 从数据库 / 远程服务加载实体，例如：
///
/// ```ignore
/// #[async_trait::async_trait]
/// impl EntityLoader for MyDbEntityLoader {
///     async fn load_entities(&self) -> GarrisonResult<cedar_policy::Entities> {
///         // 从数据库查询实体并构造 Entities
///         (未实现占位)
///     }
/// }
/// ```
///
/// # 缓存语义
///
/// `load_entities` 在每次 `AbacEngine::evaluate` 时调用。决策缓存不主动失效，
/// 调用方需保证 `EntityLoader` 返回稳定实体集合（同一实体集合的多次加载应返回一致结果）。
/// 若 `load_entities` 返回错误，错误通过 `?` 传播，缓存不受污染。
#[cfg(feature = "abac")]
#[async_trait::async_trait]
pub trait EntityLoader: Send + Sync {
    /// 加载 Cedar Entities 集合。
    ///
    /// # 错误
    ///
    /// - 实体加载失败（数据源不可达、解析错误等）：返回 `GarrisonError`
    async fn load_entities(&self) -> GarrisonResult<cedar_policy::Entities>;
}

#[cfg(feature = "abac")]
mod init;
#[cfg(feature = "abac")]
pub use init::*;

// ============================================================================
// `abac` feature 关闭时：`check_abac_with_policy` 必须始终可用（宏无条件生成调用），
// 但降级为 fail-closed（CRIT-009 / R-abac-001）。
// ============================================================================

/// `abac` feature 缺失时的降级策略。
///
/// - `0`（默认）：Deny —— fail-closed。端点声明了 `abac` 策略却未启用 feature 时
///   返回 `Err(Config)`，杜绝"编译通过但 ABAC 校验被静默放行"的安全假象。
/// - `1`：AllowWithWarn —— 显式 opt-in 的降级模式，放行同时输出 `warn` 告警。
///   仅测试或已知风险可接受的过渡场景使用。
#[cfg(not(feature = "abac"))]
static ABAC_MISSING_FEATURE_POLICY: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

/// 设置 `abac` feature 缺失时的行为（默认 Deny / fail-closed）。
///
/// 传入 `true` 切换为 AllowWithWarn（放行 + 告警）的 opt-in 降级模式；
/// 传入 `false` 恢复默认的 Deny（fail-closed）。
#[cfg(not(feature = "abac"))]
pub fn set_abac_missing_feature_policy(allow_with_warn: bool) {
    ABAC_MISSING_FEATURE_POLICY.store(
        if allow_with_warn { 1 } else { 0 },
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// ABAC 策略校验入口（`abac` feature 关闭时的 fail-closed 实现）。
///
/// 宏 `#[check_permission(permission, resource, abac = "...")]` 无条件生成对此函数的调用，
/// 因此本函数必须始终存在以确保任意 feature 组合下均可编译。
///
/// - 端点**未声明** `abac` 策略（`abac_expr` 为空）→ `Ok(())`，no-op 安全。
/// - 端点**声明了** `abac` 策略但 feature 未启用 → 默认 `Err(Config)`（fail-closed），
///   因为该端点的属性级授权保障已丢失。可通过
///   [`set_abac_missing_feature_policy`](true) 显式 opt-in 为 AllowWithWarn。
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

    // 全局开关 ABAC_MISSING_FEATURE_POLICY 进程级共享：涉及它的测试必须互斥，
    // 否则并行执行下 opt-in 测试的"置 1→恢复 0"窗口会让 fail-closed 测试读到 1。
    static ABAC_POLICY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// CRIT-009: 声明了 abac 策略但 feature 关闭 → 必须 fail-closed Err(Config)。
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

    /// 未声明 abac 策略的端点保持 no-op（安全放行）。
    #[tokio::test]
    async fn abac_without_expr_is_noop_ok() {
        let r = check_abac_with_policy("order:read", "Resource::\"order\"", "").await;
        assert!(r.is_ok(), "空 abac_expr 应 no-op 放行，实际: {:?}", r);
    }

    /// 显式 opt-in AllowWithWarn 时放行（并恢复默认）。
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
