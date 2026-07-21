//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! ABAC 全局引擎管理与策略校验（从 mod.rs 迁移，Rule 25 合规）。

#[cfg(feature = "abac")]
use super::AbacEngine;

// ============================================================================
// 全局 AbacEngine 管理（abac feature 开启时）
// ============================================================================

#[cfg(feature = "abac")]
use crate::error::{GarrisonError, GarrisonResult};

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
/// 重复调用返回 `GarrisonError::Config`。
///
/// # 参数
/// - `engine`: `AbacEngine` 实例（已加载 schema 和策略）
///
/// # 示例
///
/// ```ignore
/// use garrison::abac::{AbacEngine, EmptyEntityLoader, init_abac_engine};
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
// validate_abac_expr — Cedar 策略注入防御（A3）
// ============================================================================

/// ABAC 表达式最大长度（512 字符），防止 DoS 攻击。
#[cfg(feature = "abac")]
const ABAC_EXPR_MAX_LEN: usize = 512;

/// 校验 ABAC 表达式，防止 Cedar 策略注入。
///
/// 拒绝以下恶意模式：
/// - 空表达式或仅空白
/// - 超长表达式（>512 字符，DoS 防御）
/// - 含 `};`：尝试闭合 `when { ... }` 块并注入新策略
/// - 含 `permit(` / `forbid(`：尝试在表达式内声明新策略
/// - 纯字面量：无 `principal` / `resource` / `action` 引用（要求表达式绑定到上下文）
///
/// # 参数
/// - `expr`: Cedar 条件表达式字符串（如 "resource.owner == principal.id"）
///
/// # 返回
/// - `Ok(())`: 表达式通过校验
/// - `Err(GarrisonError::InvalidParam)`: 表达式含恶意模式或为纯字面量
///
/// # 安全考量
///
/// 此校验为纵深防御层。即便攻击者绕过宏属性注入恶意 `abac_expr`，
/// 本函数也会拒绝已知的策略注入 payload。Cedar 解析器仍会再次校验语法。
#[cfg(feature = "abac")]
pub fn validate_abac_expr(expr: &str) -> GarrisonResult<()> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Err(GarrisonError::InvalidParam("abac-expr-empty".to_string()));
    }
    if expr.len() > ABAC_EXPR_MAX_LEN {
        return Err(GarrisonError::InvalidParam(format!(
            "abac_expr 长度超过 {} 字符（DoS 防御）",
            ABAC_EXPR_MAX_LEN
        )));
    }
    // 拒绝策略终止符（闭合 when 块并注入新策略）
    if expr.contains("};") {
        return Err(GarrisonError::InvalidParam(
            "abac_expr 含非法字符 `};`（疑似策略注入）".to_string(),
        ));
    }
    // 拒绝显式 permit/forbid 策略声明
    if expr.contains("permit(") || expr.contains("forbid(") {
        return Err(GarrisonError::InvalidParam(
            "abac_expr 不允许声明 permit/forbid 策略".to_string(),
        ));
    }
    // 要求至少含 principal/resource/action 之一，拒绝纯字面量
    let lower = expr.to_lowercase();
    if !lower.contains("principal") && !lower.contains("resource") && !lower.contains("action") {
        return Err(GarrisonError::InvalidParam(
            "abac_expr 必须引用 principal/resource/action 之一（拒绝纯字面量）".to_string(),
        ));
    }
    Ok(())
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
/// 1. 全局 AbacEngine 未初始化 → 返回 `Err(GarrisonError::Config(...))`（R-abac-001 fail-closed）
/// 2. 校验 `abac_expr` 防止 Cedar 策略注入（A3）
/// 3. 获取当前 `login_id` 作为 principal，未登录 → 返回 `Err(NotLogin)`
/// 4. 将 `abac_expr` 包装为 Cedar 策略：
///    `permit(principal, action == Action::"<action>", resource) when { <abac_expr> };`
/// 5. 使用 `evaluate_with_temp_policy` 求值（不修改共享策略集），resource 由调用方显式传入
/// 6. Allow → `Ok(())`，Deny → `Err(NotPermission)`
///
/// # 参数
/// - `action`: 权限标识（如 "order:read"），作为 Cedar action
/// - `resource`: Cedar resource EntityUid 字符串（如 `Resource::"default"`、`Resource::"order"`）。
///   由宏属性 `resource = "..."` 注入，避免硬编码。
///   非法格式由 Cedar 解析器拒绝（返回 `Err(InvalidParam)`，fail-closed）。
/// - `abac_expr`: Cedar 条件表达式（如 "resource.user_id == principal.id"）
///
/// # 错误
/// - `GarrisonError::NotLogin`: 未登录（`get_login_id` 返回 None）
/// - `GarrisonError::NotPermission`: ABAC 策略拒绝
/// - `GarrisonError::InvalidParam`: abac_expr 含恶意模式或 Cedar 策略解析失败（含 resource 注入尝试）
/// - 其他: 透传 `GarrisonManager` / AbacEngine 错误
#[cfg(feature = "abac")]
pub async fn check_abac_with_policy(
    action: &str,
    resource: &str,
    abac_expr: &str,
) -> GarrisonResult<()> {
    let engine = match get_abac_engine()? {
        Some(e) => e,
        None => {
            return Err(GarrisonError::Config(
                "AbacEngine 未初始化，ABAC 校验失败（fail-closed）".into(),
            ))
        }, // R-abac-001: 未初始化 fail-closed
    };
    // A3: 校验 abac_expr 防止 Cedar 策略注入
    validate_abac_expr(abac_expr)?;
    let login_id = crate::stp::GarrisonUtil::get_login_id().await?;
    let login_id = match login_id {
        Some(id) => id,
        None => {
            return Err(GarrisonError::NotLogin(
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
        Err(GarrisonError::NotPermission(format!(
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
) -> crate::error::GarrisonResult<()> {
    Ok(())
}
