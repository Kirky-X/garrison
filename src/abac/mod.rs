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
//!
//! # 全局引擎管理
//!
//! - `init_abac_engine`：初始化全局 AbacEngine（`abac` feature 开启时可用）
//! - `check_abac_with_policy`：宏入口，RBAC 通过后调用 ABAC 求值
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

    /// init_abac_engine 成功初始化后 get_abac_engine 返回 Some。
    #[tokio::test]
    #[serial_test::serial]
    async fn init_abac_engine_success_then_get_returns_some() {
        reset_abac_for_test();
        let engine = AbacEngine::new(r#"{"":{"entityTypes":{},"actions":{}}}"#).unwrap();
        init_abac_engine(engine).expect("首次 init_abac_engine 应成功");

        // get_abac_engine 应返回 Some(Arc<AbacEngine>)
        let result = get_abac_engine();
        assert!(
            result.is_ok(),
            "get_abac_engine 应返回 Ok: {:?}",
            result.err()
        );
        let engine_opt = result.unwrap();
        assert!(engine_opt.is_some(), "初始化后应返回 Some");

        reset_abac_for_test();
    }

    /// get_abac_engine 未初始化时返回 Ok(None)。
    #[tokio::test]
    #[serial_test::serial]
    async fn get_abac_engine_returns_none_when_not_initialized() {
        reset_abac_for_test();
        let result = get_abac_engine();
        assert!(
            result.is_ok(),
            "get_abac_engine 应返回 Ok: {:?}",
            result.err()
        );
        assert!(result.unwrap().is_none(), "未初始化时应返回 None");
        reset_abac_for_test();
    }

    /// init_abac_engine 重复调用返回 Config 错误（验证错误类型）。
    #[tokio::test]
    #[serial_test::serial]
    async fn init_abac_engine_duplicate_returns_config_error() {
        reset_abac_for_test();
        let engine = AbacEngine::new(r#"{"":{"entityTypes":{},"actions":{}}}"#).unwrap();
        init_abac_engine(engine).expect("首次 init 应成功");
        let engine2 = AbacEngine::new(r#"{"":{"entityTypes":{},"actions":{}}}"#).unwrap();
        let result = init_abac_engine(engine2);
        assert!(result.is_err());
        match result {
            Err(crate::error::BulwarkError::Config(msg)) => {
                assert!(
                    msg.contains("already initialized"),
                    "错误消息应包含 'already initialized'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 Config 错误，实际: {:?}", other),
            Ok(_) => panic!("期望错误，实际成功"),
        }
        reset_abac_for_test();
    }

    /// reset_abac_for_test 清除引擎后 get_abac_engine 返回 None。
    #[tokio::test]
    #[serial_test::serial]
    async fn reset_abac_for_test_clears_engine() {
        reset_abac_for_test();
        let engine = AbacEngine::new(r#"{"":{"entityTypes":{},"actions":{}}}"#).unwrap();
        init_abac_engine(engine).expect("init 应成功");
        assert!(get_abac_engine().unwrap().is_some());

        reset_abac_for_test();
        assert!(get_abac_engine().unwrap().is_none(), "reset 后应返回 None");
    }

    /// check_abac_with_policy 在引擎未初始化时对任意 action 均返回 Ok。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_abac_with_policy_no_engine_various_actions() {
        reset_abac_for_test();
        // 不同 action 和 abac_expr 均应返回 Ok（引擎未初始化时默认 Allow）
        let result1 = check_abac_with_policy("order:read", "1 == 1").await;
        assert!(result1.is_ok());
        let result2 = check_abac_with_policy("user:delete", "resource.owner == principal.id").await;
        assert!(result2.is_ok());
        let result3 = check_abac_with_policy("", "").await;
        assert!(result3.is_ok());
        reset_abac_for_test();
    }

    // ========================================================================
    // check_abac_with_policy 实际求值路径测试（引擎已初始化）
    // 覆盖 lines 126-157：engine 求值 + Allow/Deny/NotLogin 分支
    // ========================================================================

    /// 测试用 Cedar schema JSON（与 engine.rs 测试一致）。
    const EVAL_SCHEMA_JSON: &str = r#"{
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

    /// 初始化 BulwarkManager（空权限/角色，用于 get_login_id 上下文）。
    fn init_manager_for_abac() {
        use crate::dao::BulwarkDao;
        use crate::manager::BulwarkManager;
        use crate::stp::BulwarkInterface;
        let dao: Arc<dyn BulwarkDao> = Arc::new(crate::dao::tests::MockDao::new());
        let mut config = crate::config::BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = false;
        let interface: Arc<dyn BulwarkInterface> = Arc::new(crate::stp::mock::MockInterface);
        BulwarkManager::init(dao, Arc::new(config), interface).unwrap();
    }

    /// 引擎已初始化且用户已登录时，abac_expr "1 == 1" 求值 Allow → 返回 Ok。
    ///
    /// 覆盖 lines 126-131, 138-153（engine 获取 + principal/action 构造 + evaluate + Allow 分支）。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_abac_with_policy_engine_initialized_allow() {
        use crate::stp::{with_current_token, BulwarkUtil};
        reset_abac_for_test();
        crate::manager::BulwarkManager::reset_for_test();
        init_manager_for_abac();

        // 初始化 ABAC 引擎
        let engine = AbacEngine::new(EVAL_SCHEMA_JSON).expect("schema valid");
        init_abac_engine(engine).expect("init_abac_engine 应成功");

        // 登录获取 token
        let token = BulwarkUtil::login_simple("1001")
            .await
            .expect("login 应成功");

        // 在 token 作用域内调用 check_abac_with_policy
        let result = with_current_token(token, async {
            check_abac_with_policy("access", "1 == 1").await
        })
        .await;
        assert!(result.is_ok(), "1 == 1 应 Allow: {:?}", result.err());

        reset_abac_for_test();
        crate::manager::BulwarkManager::reset_for_test();
    }

    /// 引擎已初始化且用户已登录时，abac_expr "1 == 2" 求值 Deny → 返回 Err(NotPermission)。
    ///
    /// 覆盖 lines 154-157（Deny 分支 → Err(NotPermission)）。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_abac_with_policy_engine_initialized_deny() {
        use crate::stp::{with_current_token, BulwarkUtil};
        reset_abac_for_test();
        crate::manager::BulwarkManager::reset_for_test();
        init_manager_for_abac();

        let engine = AbacEngine::new(EVAL_SCHEMA_JSON).expect("schema valid");
        init_abac_engine(engine).expect("init_abac_engine 应成功");

        let token = BulwarkUtil::login_simple("1001")
            .await
            .expect("login 应成功");

        let result = with_current_token(token, async {
            check_abac_with_policy("access", "1 == 2").await
        })
        .await;
        assert!(result.is_err(), "1 == 2 应 Deny");
        match result {
            Err(crate::error::BulwarkError::NotPermission(msg)) => {
                assert!(
                    msg.contains("ABAC 策略拒绝"),
                    "错误消息应包含 'ABAC 策略拒绝'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 NotPermission，实际: {:?}", other),
            Ok(_) => panic!("期望错误，实际返回 Ok"),
        }

        reset_abac_for_test();
        crate::manager::BulwarkManager::reset_for_test();
    }

    /// 引擎已初始化但未登录时（无 token 上下文）→ 返回 Err(NotLogin)。
    ///
    /// 覆盖 lines 132-136（get_login_id 返回 None → NotLogin 分支）。
    #[tokio::test]
    #[serial_test::serial]
    async fn check_abac_with_policy_not_logged_in_returns_not_login() {
        reset_abac_for_test();
        crate::manager::BulwarkManager::reset_for_test();
        init_manager_for_abac();

        let engine = AbacEngine::new(EVAL_SCHEMA_JSON).expect("schema valid");
        init_abac_engine(engine).expect("init_abac_engine 应成功");

        // 不调用 login_simple，不设置 with_current_token
        // current_token() 返回 Err → get_login_id 返回 Ok(None) → NotLogin
        let result = check_abac_with_policy("access", "1 == 1").await;
        assert!(result.is_err(), "未登录应返回错误");
        match result {
            Err(crate::error::BulwarkError::NotLogin(msg)) => {
                assert!(
                    msg.contains("未获取到 login_id"),
                    "错误消息应包含 '未获取到 login_id'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 NotLogin，实际: {:?}", other),
            Ok(_) => panic!("期望错误，实际返回 Ok"),
        }

        reset_abac_for_test();
        crate::manager::BulwarkManager::reset_for_test();
    }
}
