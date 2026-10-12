// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! ABAC 全局引擎管理与策略校验。

#[cfg(feature = "abac")]
use super::AbacEngine;

// 全局 AbacEngine 管理（abac feature 开启时）

#[cfg(feature = "abac")]
use crate::error::{GarrisonError, GarrisonResult};

#[cfg(feature = "abac")]
use crate::loc;

#[cfg(feature = "abac")]
use std::sync::{Arc, Mutex};

/// 全局 AbacEngine 实例。
///
/// 通过 [`init_abac_engine`] 初始化。未初始化时 [`check_abac_with_policy`] 返回 `Err(Config)`（fail-closed）。
#[cfg(feature = "abac")]
static CURRENT_ENGINE: Mutex<Option<Arc<AbacEngine>>> = Mutex::new(None);

/// 初始化全局 AbacEngine；必须在使用 `#[check_permission(..., abac = "...")]` 宏前调用一次，重复调用返回 `GarrisonError::Config`。
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
pub fn init_abac_engine(engine: AbacEngine) -> GarrisonResult<()> {
    let mut guard = CURRENT_ENGINE
        .lock()
        .map_err(|_| GarrisonError::Config("CURRENT_ENGINE lock poisoned".into()))?;
    if guard.is_some() {
        return Err(GarrisonError::Config(
            "AbacEngine already initialized".into(),
        ));
    }
    *guard = Some(Arc::new(engine));
    Ok(())
}

/// 获取全局 AbacEngine 的 Arc 克隆。
#[cfg(feature = "abac")]
pub(crate) fn get_abac_engine() -> GarrisonResult<Option<Arc<AbacEngine>>> {
    let guard = CURRENT_ENGINE
        .lock()
        .map_err(|_| GarrisonError::Config("CURRENT_ENGINE lock poisoned".into()))?;
    Ok(guard.clone())
}

/// 重置全局 AbacEngine（仅测试用，生产代码严禁调用）；经 `testing` feature 门控，供 crate 内单测与显式启用 `testing` 的集成测试访问。
#[cfg(feature = "abac")]
#[cfg(any(test, feature = "testing"))]
pub fn reset_abac_for_test() {
    if let Ok(mut guard) = CURRENT_ENGINE.lock() {
        *guard = None;
    }
}

// validate_abac_expr — Cedar 策略注入防御

/// ABAC 表达式最大长度（512 字符），防止 DoS 攻击。
#[cfg(feature = "abac")]
const ABAC_EXPR_MAX_LEN: usize = 512;

/// 校验 ABAC 表达式，拒绝 Cedar 策略注入（纵深防御：即便绕过宏属性注入恶意 `abac_expr`，本层也拒绝已知 payload；Cedar 解析器仍会再次校验语法）。
///
/// 拒绝规则（命中返回 `Err(GarrisonError::InvalidParam)`）：空或仅空白；trim 后超长（>512 字符，DoS 防御）；含 `};`（闭合 when 块注入）；含 `permit(` / `forbid(`（声明新策略）；无 `principal` / `resource` / `action` 引用的纯字面量。
#[cfg(feature = "abac")]
pub fn validate_abac_expr(expr: &str) -> GarrisonResult<()> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Err(GarrisonError::InvalidParam(loc!(
            "abac-expr-empty",
            "abac_expr must not be empty"
        )));
    }
    // 长度限制按 trim 后内容判定，避免空白填充误拒合法表达式；空白填充开销可忽略，DoS 防御不受影响
    if trimmed.len() > ABAC_EXPR_MAX_LEN {
        return Err(GarrisonError::InvalidParam(loc!(
            "abac-expr-too-long",
            format!(
                "abac_expr exceeds {} characters (DoS protection)",
                ABAC_EXPR_MAX_LEN
            ),
            ("max", ABAC_EXPR_MAX_LEN.to_string().as_str())
        )));
    }
    if expr.contains("};") {
        return Err(GarrisonError::InvalidParam(loc!(
            "abac-expr-illegal-chars",
            "abac_expr contains illegal characters `};` (possible policy injection)"
        )));
    }
    if expr.contains("permit(") || expr.contains("forbid(") {
        return Err(GarrisonError::InvalidParam(loc!(
            "abac-expr-policy-forbidden",
            "abac_expr must not declare permit/forbid policies"
        )));
    }
    let lower = expr.to_lowercase();
    if !lower.contains("principal") && !lower.contains("resource") && !lower.contains("action") {
        return Err(GarrisonError::InvalidParam(loc!(
            "abac-expr-must-reference-entity",
            "abac_expr must reference principal/resource/action (plain literals rejected)"
        )));
    }
    Ok(())
}

// check_abac_with_policy — 宏入口

/// ABAC 策略校验（宏入口，RBAC 通过后的增量校验）：引擎未初始化 → `Err(Config)`（fail-closed）；校验 `abac_expr` 防注入；`login_id` 缺失 → `Err(NotLogin)`；把表达式包装为 `permit(principal, action == Action::"<action>", resource) when { <abac_expr> };` 后经 `evaluate_with_temp_policy` 求值（不改共享策略集）；Allow → `Ok(())`，Deny → `Err(NotPermission)`，其他引擎错误透传。
///
/// `resource` 为 Cedar resource EntityUid 字符串（如 `Resource::"order"`），由宏属性 `resource = "..."` 注入；非法格式由 Cedar 解析器拒绝（`Err(InvalidParam)`，fail-closed）。`action` 为权限标识（如 "order:read"），作为 Cedar action。
#[cfg(feature = "abac")]
pub async fn check_abac_with_policy(
    action: &str,
    resource: &str,
    abac_expr: &str,
) -> GarrisonResult<()> {
    let engine = match get_abac_engine()? {
        Some(e) => e,
        None => {
            return Err(GarrisonError::Config(loc!(
                "abac-engine-not-initialized",
                "AbacEngine not initialized; ABAC check failed (fail-closed)"
            )))
        }, // 未初始化 fail-closed
    };
    validate_abac_expr(abac_expr)?;
    let login_id = crate::stp::GarrisonUtil::get_login_id().await?;
    let login_id = match login_id {
        Some(id) => id,
        None => {
            return Err(GarrisonError::NotLogin(loc!(
                "abac-login-id-missing",
                "login_id not available during ABAC validation"
            )))
        },
    };
    let principal = format!(r#"User::"{login_id}""#);
    let action_uid = format!(r#"Action::"{action}""#);
    let policy_src = format!(
        r#"permit(principal, action == Action::"{action}", resource) when {{ {abac_expr} }};"#
    );
    // resource 由调用方显式传入；非法 resource 字符串（含注入尝试）由 evaluate_with_temp_policy 内部 EntityUid::parse 拒绝
    let decision = engine
        .evaluate_with_temp_policy(&principal, &action_uid, resource, None, &policy_src)
        .await?;
    if decision.allowed {
        Ok(())
    } else {
        // expr 不编码进错误消息（避免破坏 parse_keyed_detail 解析），仅 debug 日志保持可观测性
        tracing::debug!(expr = %abac_expr, "ABAC policy denied");
        Err(GarrisonError::NotPermission(format!(
            "abac-policy-denied::{}::{}",
            action, resource
        )))
    }
}

/// ABAC 策略校验 stub（`abac` feature 关闭时，实际由 mod.rs 的同名 fail-closed 实现覆盖）：返回 `Ok(())` no-op；feature 开启时未初始化引擎走 fail-closed（见上方 feature 版本）。
#[cfg(not(feature = "abac"))]
pub async fn check_abac_with_policy(
    _action: &str,
    _resource: &str,
    _abac_expr: &str,
) -> crate::error::GarrisonResult<()> {
    Ok(())
}
