//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! ABAC 全局引擎管理与策略校验（从 mod.rs 迁移，Rule 25 合规）。

#[cfg(feature = "abac")]
use super::AbacEngine;

// ============================================================================
// 全局 AbacEngine 管理（abac feature 开启时）
// ============================================================================

#[cfg(feature = "abac")]
use crate::error::{BulwarkError, BulwarkResult};

#[cfg(feature = "abac")]
use std::sync::{Arc, Mutex};

/// 全局 AbacEngine 实例。
///
/// 通过 [`init_abac_engine`] 初始化。未初始化时 [`check_abac_with_policy`] 返回 `Err(Config)`（fail-closed）。
#[cfg(feature = "abac")]
static CURRENT_ENGINE: Mutex<Option<Arc<AbacEngine>>> = Mutex::new(None);

/// 初始化全局 AbacEngine。
///
/// 必须在使用 `#[check_permission(permission = "...", abac = "...")]` 宏前调用一次。
/// 重复调用返回 `BulwarkError::Config`。
///
/// # 参数
/// - `engine`: `AbacEngine` 实例（已加载 schema 和策略）
///
/// # 示例
///
/// ```ignore
/// use bulwark::abac::{AbacEngine, EmptyEntityLoader, init_abac_engine};
/// use std::sync::Arc;
///
/// let engine = AbacEngine::new(schema_json, Arc::new(EmptyEntityLoader)).await.unwrap();
/// init_abac_engine(engine).unwrap();
/// ```
#[cfg(feature = "abac")]
pub fn init_abac_engine(engine: AbacEngine) -> BulwarkResult<()> {
    let mut guard = CURRENT_ENGINE
        .lock()
        .map_err(|_| BulwarkError::Config("CURRENT_ENGINE lock poisoned".into()))?;
    if guard.is_some() {
        return Err(BulwarkError::Config(
            "AbacEngine already initialized".into(),
        ));
    }
    *guard = Some(Arc::new(engine));
    Ok(())
}

/// 获取全局 AbacEngine 的 Arc 克隆。
#[cfg(feature = "abac")]
pub(crate) fn get_abac_engine() -> BulwarkResult<Option<Arc<AbacEngine>>> {
    let guard = CURRENT_ENGINE
        .lock()
        .map_err(|_| BulwarkError::Config("CURRENT_ENGINE lock poisoned".into()))?;
    Ok(guard.clone())
}

/// 重置全局 AbacEngine（仅测试用）。
///
/// 生产代码中严禁调用此函数。
///
/// 通过 `testing` feature 门控：单元测试（crate 内 `#[cfg(test)]`）与
/// 显式启用 `testing` 特性的集成测试（外部二进制）可访问。
#[cfg(feature = "abac")]
#[cfg(any(test, feature = "testing"))]
pub fn reset_abac_for_test() {
    if let Ok(mut guard) = CURRENT_ENGINE.lock() {
        *guard = None;
    }
}

// ============================================================================
// check_abac_with_policy — 宏入口（R-abac-004 / R-abac-005）
// ============================================================================

/// ABAC 策略校验（宏入口）。
///
/// 供 `#[check_permission(permission = "...", resource = "...", abac = "...")]` 宏生成的代码调用。
/// RBAC 校验通过后执行 ABAC 增量校验。
///
/// # 行为
///
/// 1. 全局 AbacEngine 未初始化 → 返回 `Err(BulwarkError::Config(...))`（R-abac-001 fail-closed）
/// 2. 获取当前 `login_id` 作为 principal，未登录 → 返回 `Err(NotLogin)`
/// 3. 将 `abac_expr` 包装为 Cedar 策略：
///    `permit(principal, action == Action::"<action>", resource) when { <abac_expr> };`
/// 4. 使用 `evaluate_with_temp_policy` 求值（不修改共享策略集），resource 由调用方显式传入
/// 5. Allow → `Ok(())`，Deny → `Err(NotPermission)`
///
/// # 参数
/// - `action`: 权限标识（如 "order:read"），作为 Cedar action
/// - `resource`: Cedar resource EntityUid 字符串（如 `Resource::"default"`、`Resource::"order"`）。
///   由宏属性 `resource = "..."` 注入，避免硬编码。
///   非法格式由 Cedar 解析器拒绝（返回 `Err(InvalidParam)`，fail-closed）。
/// - `abac_expr`: Cedar 条件表达式（如 "resource.user_id == principal.id"）
///
/// # 错误
/// - `BulwarkError::NotLogin`: 未登录（`get_login_id` 返回 None）
/// - `BulwarkError::NotPermission`: ABAC 策略拒绝
/// - `BulwarkError::InvalidParam`: Cedar 策略解析失败（含 resource 注入尝试）
/// - 其他: 透传 `BulwarkManager` / AbacEngine 错误
#[cfg(feature = "abac")]
pub async fn check_abac_with_policy(
    action: &str,
    resource: &str,
    abac_expr: &str,
) -> BulwarkResult<()> {
    let engine = match get_abac_engine()? {
        Some(e) => e,
        None => {
            return Err(BulwarkError::Config(
                "AbacEngine 未初始化，ABAC 校验失败（fail-closed）".into(),
            ))
        }, // R-abac-001: 未初始化 fail-closed
    };
    let login_id = crate::stp::BulwarkUtil::get_login_id().await?;
    let login_id = match login_id {
        Some(id) => id,
        None => {
            return Err(BulwarkError::NotLogin(
                "ABAC 校验时未获取到 login_id".to_string(),
            ))
        },
    };
    let principal = format!(r#"User::"{login_id}""#);
    let action_uid = format!(r#"Action::"{action}""#);
    let policy_src = format!(
        r#"permit(principal, action == Action::"{action}", resource) when {{ {abac_expr} }};"#
    );
    // resource 由调用方显式传入，移除硬编码 Resource::"default"。
    // 非法 resource 字符串（含注入尝试）由 evaluate_with_temp_policy 内部 EntityUid::parse 拒绝。
    let decision = engine
        .evaluate_with_temp_policy(&principal, &action_uid, resource, None, &policy_src)
        .await?;
    if decision.allowed {
        Ok(())
    } else {
        Err(BulwarkError::NotPermission(format!(
            "ABAC 策略拒绝: action={action}, resource={resource}, expr={abac_expr}"
        )))
    }
}

/// ABAC 策略校验 stub（`abac` feature 关闭时）。
///
/// 始终返回 `Ok(())`，使宏生成的代码在不启用 `abac` feature 时无副作用。
/// 满足 R-abac-001："`abac` feature 关闭时 stub 仍返回 `Ok(())`（no-op 语义不变）"——
/// 虽然宏仍生成调用代码，但本 stub 使其成为 no-op。
/// 注意：`abac` feature 开启时未初始化引擎走 fail-closed 路径（见上方 `#[cfg(feature = "abac")]` 版本）。
#[cfg(not(feature = "abac"))]
pub async fn check_abac_with_policy(
    _action: &str,
    _resource: &str,
    _abac_expr: &str,
) -> crate::error::BulwarkResult<()> {
    Ok(())
}
