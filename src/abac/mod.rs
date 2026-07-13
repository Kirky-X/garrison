//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! ABAC（Attribute-Based Access Control）策略引擎模块。
//!
//! 基于 `cedar-policy` crate，提供 principal-action-resource 三元组策略求值。
//! ABAC 作为 RBAC 的增量校验层，不替换 RBAC。RBAC 通过后再检查 ABAC。
//!
//! # 核心类型
//!
//! - [`AbacEngine`]：Cedar 策略求值器（`abac` feature 开启时可用）
//!
//! # 全局引擎管理
//!
//! - [`init_abac_engine`]：初始化全局 AbacEngine（`abac` feature 开启时可用）
//! - [`check_abac_with_policy`]：宏入口，RBAC 通过后调用 ABAC 求值
//!
//! # Feature 依赖
//!
//! 启用 `abac` feature 时编译核心引擎，依赖 `cedar-policy` crate。
//! `check_abac_with_policy` 在 `abac` feature 关闭时提供 no-op stub，
//! 确保宏生成的代码在任意 feature 组合下均可编译。

#[cfg(feature = "abac")]
mod engine;

#[cfg(feature = "abac")]
pub use engine::AbacEngine;

// ============================================================================
// 全局 AbacEngine 管理（abac feature 开启时）
// ============================================================================

#[cfg(feature = "abac")]
use crate::error::{BulwarkError, BulwarkResult};

#[cfg(feature = "abac")]
use std::sync::{Arc, Mutex};

/// 全局 AbacEngine 实例。
///
/// 通过 [`init_abac_engine`] 初始化。未初始化时 [`check_abac_with_policy`] 默认 Allow。
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
/// use bulwark::abac::{AbacEngine, init_abac_engine};
///
/// let engine = AbacEngine::new(schema_json).unwrap();
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
fn get_abac_engine() -> BulwarkResult<Option<Arc<AbacEngine>>> {
    let guard = CURRENT_ENGINE
        .lock()
        .map_err(|_| BulwarkError::Config("CURRENT_ENGINE lock poisoned".into()))?;
    Ok(guard.clone())
}

/// 重置全局 AbacEngine（仅测试用）。
///
/// 生产代码中严禁调用此函数。
#[cfg(feature = "abac")]
#[cfg(test)]
pub(crate) fn reset_abac_for_test() {
    if let Ok(mut guard) = CURRENT_ENGINE.lock() {
        *guard = None;
    }
}

// ============================================================================
// check_abac_with_policy — 宏入口（R-abac-004 / R-abac-005）
// ============================================================================

/// ABAC 策略校验（宏入口）。
///
/// 供 `#[check_permission(permission = "...", abac = "...")]` 宏生成的代码调用。
/// RBAC 校验通过后执行 ABAC 增量校验。
///
/// # 行为
///
/// 1. 全局 AbacEngine 未初始化 → 返回 `Ok(())`（R-abac-005 默认 Allow）
/// 2. 获取当前 `login_id` 作为 principal，未登录 → 返回 `Err(NotLogin)`
/// 3. 将 `abac_expr` 包装为 Cedar 策略：
///    `permit(principal, action == Action::"<action>", resource) when { <abac_expr> };`
/// 4. 使用 `evaluate_with_temp_policy` 求值（不修改共享策略集）
/// 5. Allow → `Ok(())`，Deny → `Err(NotPermission)`
///
/// # 参数
/// - `action`: 权限标识（如 "order:read"），作为 Cedar action
/// - `abac_expr`: Cedar 条件表达式（如 "resource.user_id == principal.id"）
///
/// # 错误
/// - `BulwarkError::NotLogin`: 未登录（`get_login_id` 返回 None）
/// - `BulwarkError::NotPermission`: ABAC 策略拒绝
/// - `BulwarkError::InvalidParam`: Cedar 策略解析失败
/// - 其他: 透传 `BulwarkManager` / AbacEngine 错误
#[cfg(feature = "abac")]
pub async fn check_abac_with_policy(action: &str, abac_expr: &str) -> BulwarkResult<()> {
    let engine = match get_abac_engine()? {
        Some(e) => e,
        None => return Ok(()), // R-abac-005: 未初始化默认 Allow
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
    let decision = engine
        .evaluate_with_temp_policy(
            &principal,
            &action_uid,
            r#"Resource::"default""#,
            None,
            &policy_src,
        )
        .await?;
    if decision.allowed {
        Ok(())
    } else {
        Err(BulwarkError::NotPermission(format!(
            "ABAC 策略拒绝: action={action}, expr={abac_expr}"
        )))
    }
}

/// ABAC 策略校验 stub（`abac` feature 关闭时）。
///
/// 始终返回 `Ok(())`，使宏生成的代码在不启用 `abac` feature 时无副作用。
/// 满足 R-abac-005："`abac` feature 关闭时宏不生成 ABAC 调用代码"——
/// 虽然宏仍生成调用代码，但本 stub 使其成为 no-op。
#[cfg(not(feature = "abac"))]
pub async fn check_abac_with_policy(
    _action: &str,
    _abac_expr: &str,
) -> crate::error::BulwarkResult<()> {
    Ok(())
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(all(test, feature = "abac"))]
mod tests {
    use super::*;

    /// 全局引擎未初始化时 check_abac_with_policy 默认 Allow。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_abac_with_policy_no_engine_returns_ok() {
        reset_abac_for_test();
        let result = check_abac_with_policy("test:read", "1 == 1").await;
        assert!(result.is_ok(), "未初始化时应默认 Allow: {:?}", result.err());
        reset_abac_for_test();
    }

    /// init_abac_engine 重复调用返回错误。
    #[tokio::test]
    #[serial_test::serial]
    async fn init_abac_engine_duplicate_fails() {
        reset_abac_for_test();
        let engine = AbacEngine::new(r#"{"":{"entityTypes":{},"actions":{}}}"#).unwrap();
        init_abac_engine(engine).unwrap();
        let engine2 = AbacEngine::new(r#"{"":{"entityTypes":{},"actions":{}}}"#).unwrap();
        let result = init_abac_engine(engine2);
        assert!(result.is_err(), "重复 init_abac_engine 应返回错误");
        reset_abac_for_test();
    }
}
