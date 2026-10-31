// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! ABAC 模块测试。

use super::*;
use std::sync::Arc;

#[tokio::test]
#[serial_test::serial]
async fn check_abac_with_policy_no_engine_returns_err() {
    let _en = crate::i18n::set_locale(crate::i18n::GarrisonLocale::En);
    reset_abac_for_test();
    let result = check_abac_with_policy("test:read", r#"Resource::"default""#, "1 == 1").await;
    assert!(
        result.is_err(),
        "未初始化时应 fail-closed 返回 Err: {:?}",
        result.ok()
    );
    match result {
        Err(crate::error::GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("AbacEngine not initialized"),
                "错误消息应含 'AbacEngine not initialized'，实际: {}",
                msg
            );
        },
        Err(other) => panic!("期望 Config 错误，实际: {:?}", other),
        Ok(_) => panic!("期望 Err(fail-closed)，实际 Ok"),
    }
    reset_abac_for_test();
}

#[tokio::test]
#[serial_test::serial]
async fn init_abac_engine_duplicate_fails() {
    reset_abac_for_test();
    let engine = AbacEngine::new(
        r#"{"":{"entityTypes":{},"actions":{}}}"#,
        Arc::new(EmptyEntityLoader),
    )
    .await
    .unwrap();
    init_abac_engine(engine).unwrap();
    let engine2 = AbacEngine::new(
        r#"{"":{"entityTypes":{},"actions":{}}}"#,
        Arc::new(EmptyEntityLoader),
    )
    .await
    .unwrap();
    let result = init_abac_engine(engine2);
    assert!(result.is_err(), "重复 init_abac_engine 应返回错误");
    reset_abac_for_test();
}

#[tokio::test]
#[serial_test::serial]
async fn init_abac_engine_success_then_get_returns_some() {
    reset_abac_for_test();
    let engine = AbacEngine::new(
        r#"{"":{"entityTypes":{},"actions":{}}}"#,
        Arc::new(EmptyEntityLoader),
    )
    .await
    .unwrap();
    init_abac_engine(engine).expect("首次 init_abac_engine 应成功");

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

#[tokio::test]
#[serial_test::serial]
async fn init_abac_engine_duplicate_returns_config_error() {
    reset_abac_for_test();
    let engine = AbacEngine::new(
        r#"{"":{"entityTypes":{},"actions":{}}}"#,
        Arc::new(EmptyEntityLoader),
    )
    .await
    .unwrap();
    init_abac_engine(engine).expect("首次 init 应成功");
    let engine2 = AbacEngine::new(
        r#"{"":{"entityTypes":{},"actions":{}}}"#,
        Arc::new(EmptyEntityLoader),
    )
    .await
    .unwrap();
    let result = init_abac_engine(engine2);
    assert!(result.is_err());
    match result {
        Err(crate::error::GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("AbacEngine already initialized"),
                "错误消息应包含 'AbacEngine already initialized'，实际: {}",
                msg
            );
        },
        Err(other) => panic!("期望 Config 错误，实际: {:?}", other),
        Ok(_) => panic!("期望错误，实际成功"),
    }
    reset_abac_for_test();
}

#[tokio::test]
#[serial_test::serial]
async fn reset_abac_for_test_clears_engine() {
    reset_abac_for_test();
    let engine = AbacEngine::new(
        r#"{"":{"entityTypes":{},"actions":{}}}"#,
        Arc::new(EmptyEntityLoader),
    )
    .await
    .unwrap();
    init_abac_engine(engine).expect("init 应成功");
    assert!(get_abac_engine().unwrap().is_some());

    reset_abac_for_test();
    assert!(get_abac_engine().unwrap().is_none(), "reset 后应返回 None");
}

#[tokio::test]
#[serial_test::serial]
async fn check_abac_with_policy_no_engine_various_actions() {
    reset_abac_for_test();
    // 不同 action 和 abac_expr 均应返回 Err（引擎未初始化时 fail-closed）
    let result1 = check_abac_with_policy("order:read", r#"Resource::"default""#, "1 == 1").await;
    assert!(result1.is_err());
    let result2 = check_abac_with_policy(
        "user:delete",
        r#"Resource::"default""#,
        "resource.owner == principal.id",
    )
    .await;
    assert!(result2.is_err());
    let result3 = check_abac_with_policy("", r#"Resource::"default""#, "").await;
    assert!(result3.is_err());
    if let Err(crate::error::GarrisonError::Config(_)) = result1 {
    } else {
        panic!("期望 Config 错误，实际: {:?}", result1);
    }
    reset_abac_for_test();
}

// check_abac_with_policy 实际求值路径测试（引擎已初始化）

/// 测试用 Cedar schema（与 engine.rs 测试一致）。
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

/// 初始化 GarrisonManager（空权限/角色，用于 get_login_id 上下文）。
async fn init_manager_for_abac() {
    use crate::dao::GarrisonDao;
    use crate::manager::GarrisonManager;
    use crate::stp::GarrisonInterface;
    let dao: Arc<dyn GarrisonDao> = Arc::new(crate::dao::tests::MockDao::new());
    let mut config = crate::config::GarrisonConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    let interface: Arc<dyn GarrisonInterface> = Arc::new(crate::stp::mock::MockInterface);
    GarrisonManager::builder()
        .dao(dao)
        .config(Arc::new(config))
        .interface(interface)
        .build()
        .await
        .unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn check_abac_with_policy_engine_initialized_allow() {
    use crate::stp::{with_current_token, GarrisonUtil};
    reset_abac_for_test();
    crate::manager::GarrisonManager::reset_for_test();
    init_manager_for_abac().await;

    let engine = AbacEngine::new(EVAL_SCHEMA_JSON, Arc::new(EmptyEntityLoader))
        .await
        .expect("schema valid");
    init_abac_engine(engine).expect("init_abac_engine 应成功");

    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login 应成功");

    let result = with_current_token(token, async {
        check_abac_with_policy("access", r#"Resource::"default""#, "principal == principal").await
    })
    .await;
    assert!(
        result.is_ok(),
        "principal == principal 应 Allow: {:?}",
        result.err()
    );

    reset_abac_for_test();
    crate::manager::GarrisonManager::reset_for_test();
}

#[tokio::test]
#[serial_test::serial]
async fn check_abac_with_policy_engine_initialized_deny() {
    use crate::stp::{with_current_token, GarrisonUtil};
    reset_abac_for_test();
    crate::manager::GarrisonManager::reset_for_test();
    init_manager_for_abac().await;

    let engine = AbacEngine::new(EVAL_SCHEMA_JSON, Arc::new(EmptyEntityLoader))
        .await
        .expect("schema valid");
    init_abac_engine(engine).expect("init_abac_engine 应成功");

    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login 应成功");

    let result = with_current_token(token, async {
        check_abac_with_policy("access", r#"Resource::"default""#, "principal != principal").await
    })
    .await;
    assert!(result.is_err(), "principal != principal 应 Deny");
    match result {
        Err(crate::error::GarrisonError::NotPermission(msg)) => {
            assert!(
                msg.contains("abac-policy-denied"),
                "错误消息应包含 'abac-policy-denied'，实际: {}",
                msg
            );
        },
        Err(other) => panic!("期望 NotPermission，实际: {:?}", other),
        Ok(_) => panic!("期望错误，实际返回 Ok"),
    }

    reset_abac_for_test();
    crate::manager::GarrisonManager::reset_for_test();
}

#[tokio::test]
#[serial_test::serial]
async fn check_abac_with_policy_not_logged_in_returns_not_login() {
    reset_abac_for_test();
    crate::manager::GarrisonManager::reset_for_test();
    init_manager_for_abac().await;

    let engine = AbacEngine::new(EVAL_SCHEMA_JSON, Arc::new(EmptyEntityLoader))
        .await
        .expect("schema valid");
    init_abac_engine(engine).expect("init_abac_engine 应成功");

    // 不调用 login_simple，不设置 with_current_token
    // current_token() 返回 Err → get_login_id 返回 Ok(None) → NotLogin
    let result =
        check_abac_with_policy("access", r#"Resource::"default""#, "principal == principal").await;
    assert!(result.is_err(), "未登录应返回错误");
    match result {
        Err(crate::error::GarrisonError::NotLogin(msg)) => {
            assert!(
                msg.contains("login_id"),
                "错误消息应包含 'login_id'，实际: {}",
                msg
            );
        },
        Err(other) => panic!("期望 NotLogin，实际: {:?}", other),
        Ok(_) => panic!("期望错误，实际返回 Ok"),
    }

    reset_abac_for_test();
    crate::manager::GarrisonManager::reset_for_test();
}

// resource 注入防御测试

/// 恶意 resource 字符串（如 `Resource::"x"); forbid(principal); //"`）应被 Cedar `EntityUid::parse` 拒绝为 `InvalidParam`（fail-closed），不得 Ok/NotPermission。
#[tokio::test]
#[serial_test::serial]
async fn check_abac_with_policy_rejects_resource_injection() {
    use crate::stp::{with_current_token, GarrisonUtil};
    reset_abac_for_test();
    crate::manager::GarrisonManager::reset_for_test();
    init_manager_for_abac().await;

    let engine = AbacEngine::new(EVAL_SCHEMA_JSON, Arc::new(EmptyEntityLoader))
        .await
        .expect("schema valid");
    init_abac_engine(engine).expect("init_abac_engine 应成功");

    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login 应成功");

    // 蓝军注入 payload：尝试闭合 Cedar 字符串并注入 forbid 策略
    let malicious_resource = r#"Resource::"x"); forbid(principal); //"#;
    let result = with_current_token(token, async {
        check_abac_with_policy("access", malicious_resource, "principal == principal").await
    })
    .await;
    // 必须返回 Err（fail-closed），绝不能 Ok 或 NotPermission（那意味着注入成功）
    assert!(
        result.is_err(),
        "resource 注入应被 Cedar 解析拒绝（fail-closed），实际: {:?}",
        result
    );
    // 错误类型应为 InvalidParam（Cedar EntityUid 解析失败）
    match result {
        Err(crate::error::GarrisonError::InvalidParam(msg)) => {
            assert!(
                msg.contains("abac-resource-parse"),
                "错误消息应含 '解析失败'，实际: {}",
                msg
            );
        },
        Err(other) => panic!("期望 InvalidParam（Cedar 解析失败），实际: {:?}", other),
        Ok(_) => panic!("resource 注入应被拒绝，实际返回 Ok（注入成功，安全漏洞）"),
    }

    reset_abac_for_test();
    crate::manager::GarrisonManager::reset_for_test();
}

#[tokio::test]
#[serial_test::serial]
async fn check_abac_with_policy_accepts_legitimate_resource() {
    use crate::stp::{with_current_token, GarrisonUtil};
    reset_abac_for_test();
    crate::manager::GarrisonManager::reset_for_test();
    init_manager_for_abac().await;

    let engine = AbacEngine::new(EVAL_SCHEMA_JSON, Arc::new(EmptyEntityLoader))
        .await
        .expect("schema valid");
    init_abac_engine(engine).expect("init_abac_engine 应成功");

    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login 应成功");

    // 合法 resource：正常 EntityUid 字符串
    let result = with_current_token(token, async {
        check_abac_with_policy("access", r#"Resource::"order""#, "principal == principal").await
    })
    .await;
    assert!(result.is_ok(), "合法 resource 应 Allow: {:?}", result.err());

    reset_abac_for_test();
    crate::manager::GarrisonManager::reset_for_test();
}

// validate_abac_expr — 防御 Cedar 策略注入

#[test]
fn validate_abac_expr_accepts_legitimate_expressions() {
    assert!(validate_abac_expr("resource.owner == principal.id").is_ok());
    assert!(validate_abac_expr("principal.department == \"eng\"").is_ok());
    assert!(validate_abac_expr("action in [Action::\"read\"]").is_ok());
    assert!(validate_abac_expr(
        "resource.owner == principal.id && principal.department == \"eng\""
    )
    .is_ok());
}

#[test]
fn validate_abac_expr_rejects_policy_termination() {
    let payloads = [
        "}; permit(principal, action, resource);",
        "}; forbid(principal, action, resource);",
        "1 == 1 }; permit(principal, action, resource);",
        "resource.owner == principal.id }; forbid(principal);",
    ];
    for p in payloads {
        assert!(
            validate_abac_expr(p).is_err(),
            "应拒绝 `}};` 注入 payload: {:?}",
            p
        );
    }
}

#[test]
fn validate_abac_expr_rejects_policy_declarations() {
    let payloads = [
        "permit(principal, action, resource)",
        "forbid(principal, action, resource)",
        "true || permit(principal, action, resource)",
        "forbid(principal)",
    ];
    for p in payloads {
        assert!(
            validate_abac_expr(p).is_err(),
            "应拒绝 permit/forbid 声明: {:?}",
            p
        );
    }
}

#[test]
fn validate_abac_expr_rejects_pure_literal() {
    let payloads = ["1 == 1", "true", "false", "0", "\"hello\""];
    for p in payloads {
        assert!(
            validate_abac_expr(p).is_err(),
            "应拒绝纯字面量（无 principal/resource/action 引用）: {:?}",
            p
        );
    }
}

#[test]
fn validate_abac_expr_rejects_empty() {
    assert!(validate_abac_expr("").is_err());
    assert!(validate_abac_expr("   ").is_err());
}

#[test]
fn validate_abac_expr_rejects_overlong() {
    let long_expr = "a".repeat(513);
    assert!(validate_abac_expr(&long_expr).is_err());
}

#[test]
fn validate_abac_expr_rejects_injection_with_keywords() {
    let payload = "principal.id == resource.owner }; permit(principal, action, resource);";
    assert!(validate_abac_expr(payload).is_err());
}
