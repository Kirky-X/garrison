//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 测试套件单元测试（从 `mod.rs` 迁移）。
//!
//! 注：原测试假定 `AuthRequest.login_id` 为 `i64`，但当前 API 已改为 `String`。
//! 迁移时同步修正 MockAuthorizer 与测试数据以匹配 `String` 类型（非 DSL 变更）。

use super::*;
use crate::core::permission::{AuthRequest, Authorizer, Decision, DecisionReason};
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};

/// 测试用 MockAuthorizer，根据 `login_id` 预设返回 Decision 或 Error。
///
/// - `decisions`：login_id -> Decision 映射，命中则返回对应 Decision
/// - `errors`：login_id 集合，命中则返回 `GarrisonError::Internal`
struct MockAuthorizer {
    decisions: HashMap<String, Decision>,
    errors: HashSet<String>,
}

impl MockAuthorizer {
    fn new() -> Self {
        Self {
            decisions: HashMap::new(),
            errors: HashSet::new(),
        }
    }

    /// 注册一个 login_id -> Decision 映射。
    fn with_decision(mut self, login_id: impl Into<String>, decision: Decision) -> Self {
        self.decisions.insert(login_id.into(), decision);
        self
    }

    /// 注册一个应该返回错误的 login_id。
    fn with_error(mut self, login_id: impl Into<String>) -> Self {
        self.errors.insert(login_id.into());
        self
    }
}

#[async_trait]
impl Authorizer for MockAuthorizer {
    async fn authorize(&self, req: &AuthRequest) -> GarrisonResult<Decision> {
        if self.errors.contains(&req.login_id) {
            return Err(GarrisonError::Internal(format!(
                "mock error for login_id={}",
                req.login_id
            )));
        }
        Ok(self
            .decisions
            .get(&req.login_id)
            .cloned()
            .unwrap_or_else(|| Decision::deny(DecisionReason::NoMatchingPermission)))
    }
}

/// T073-1: 合法 JSON 解析为 JsonTestSuite，name + cases 数量正确。
#[tokio::test]
async fn from_json_parses_valid_suite() {
    let json = r#"{
            "name": "rbac-basic",
            "cases": [
                {
                    "name": "admin_can_read",
                    "request": {"login_id": "1", "tenant_id": 0, "action": "read", "resource": null, "context": null},
                    "expected": {"allowed": true, "reason": "explicit_allow"}
                },
                {
                    "name": "guest_cannot_write",
                    "request": {"login_id": "2", "tenant_id": 0, "action": "write", "resource": null, "context": null},
                    "expected": {"allowed": false, "reason": "no_matching_permission"}
                }
            ]
        }"#;
    let suite = JsonTestSuite::from_json(json).expect("valid JSON should parse");
    assert_eq!(suite.name, "rbac-basic");
    assert_eq!(suite.cases.len(), 2);
    assert_eq!(suite.cases[0].name, "admin_can_read");
    assert_eq!(suite.cases[0].request.login_id, "1");
    assert_eq!(suite.cases[0].request.action, "read");
    assert!(suite.cases[0].expected.allowed);
    assert_eq!(
        suite.cases[0].expected.reason,
        DecisionReason::ExplicitAllow
    );
    assert!(!suite.cases[1].expected.allowed);
}

/// T073-2: 非法 JSON（语法错误）返回 GarrisonError。
#[test]
fn from_json_rejects_invalid_json() {
    // 数组括号不匹配（`[}`），serde_json 会报语法错误
    let invalid_json = r#"{"name": "broken", "cases": [}"#;
    let result = JsonTestSuite::from_json(invalid_json);
    assert!(result.is_err(), "syntactically invalid JSON should error");
    match result.err() {
        Some(GarrisonError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }
}

/// T073-3: 缺少必填字段（name / cases / request / expected）返回错误。
#[test]
fn from_json_rejects_missing_required_field() {
    // 缺 name
    let missing_name = r#"{"cases": []}"#;
    assert!(
        JsonTestSuite::from_json(missing_name).is_err(),
        "缺 name 字段应报错"
    );
    // 缺 cases
    let missing_cases = r#"{"name": "x"}"#;
    assert!(
        JsonTestSuite::from_json(missing_cases).is_err(),
        "缺 cases 字段应报错"
    );
    // 缺 request
    let missing_request = r#"{"name": "x", "cases": [{"name": "y", "expected": {"allowed": true, "reason": "explicit_allow"}}]}"#;
    assert!(
        JsonTestSuite::from_json(missing_request).is_err(),
        "缺 request 字段应报错"
    );
    // 缺 expected
    let missing_expected = r#"{"name": "x", "cases": [{"name": "y", "request": {"login_id": "1", "tenant_id": 0, "action": "read", "resource": null, "context": null}}]}"#;
    assert!(
        JsonTestSuite::from_json(missing_expected).is_err(),
        "缺 expected 字段应报错"
    );
}

/// T073-4: 3 个 case 全部通过，返回 TestReport{passed:3, failed:0}。
#[tokio::test]
async fn run_returns_all_passed_when_all_cases_match() {
    let suite = JsonTestSuite {
        name: "all-pass".to_string(),
        cases: vec![
            JsonTestCase {
                name: "u1_read".to_string(),
                request: AuthRequest::new("1", "read"),
                expected: Decision::allow(),
            },
            JsonTestCase {
                name: "u2_read".to_string(),
                request: AuthRequest::new("2", "read"),
                expected: Decision::allow(),
            },
            JsonTestCase {
                name: "u3_read".to_string(),
                request: AuthRequest::new("3", "read"),
                expected: Decision::allow(),
            },
        ],
    };
    let authorizer = MockAuthorizer::new()
        .with_decision("1", Decision::allow())
        .with_decision("2", Decision::allow())
        .with_decision("3", Decision::allow());
    let report = suite.run(&authorizer).await.expect("run should ok");
    assert_eq!(report.suite_name, "all-pass");
    assert_eq!(report.total, 3);
    assert_eq!(report.passed, 3);
    assert_eq!(report.failed, 0);
    assert!(report.failures.is_empty(), "failures should be empty");
}

/// T073-5: 1 个 case 失败（Decision.allowed 不匹配），返回 TestReport{passed:2, failed:1}。
#[tokio::test]
async fn run_returns_failures_when_some_cases_dont_match() {
    let suite = JsonTestSuite {
        name: "partial-fail".to_string(),
        cases: vec![
            JsonTestCase {
                name: "u1_allow".to_string(),
                request: AuthRequest::new("1", "read"),
                expected: Decision::allow(),
            },
            JsonTestCase {
                name: "u2_allow_but_actual_deny".to_string(),
                request: AuthRequest::new("2", "read"),
                expected: Decision::allow(),
            },
            JsonTestCase {
                name: "u3_allow".to_string(),
                request: AuthRequest::new("3", "read"),
                expected: Decision::allow(),
            },
        ],
    };
    // login_id="2" 返回 deny，与 expected(allow) 不匹配
    let authorizer = MockAuthorizer::new()
        .with_decision("1", Decision::allow())
        .with_decision("2", Decision::deny(DecisionReason::NoMatchingPermission))
        .with_decision("3", Decision::allow());
    let report = suite.run(&authorizer).await.expect("run should ok");
    assert_eq!(report.total, 3);
    assert_eq!(report.passed, 2);
    assert_eq!(report.failed, 1);
    assert_eq!(report.failures.len(), 1);
    let failure = &report.failures[0];
    assert_eq!(failure.case_name, "u2_allow_but_actual_deny");
    assert!(failure.expected.allowed);
    assert!(!failure.actual.allowed);
    assert!(
        failure.error.is_none(),
        "无 authorize error 时 error 应为 None"
    );
}

/// T073-6: Authorizer 返回 Err 时该 case 记为失败（error 字段填充）。
#[tokio::test]
async fn run_handles_authorizer_error() {
    let suite = JsonTestSuite {
        name: "auth-error".to_string(),
        cases: vec![
            JsonTestCase {
                name: "u1_ok".to_string(),
                request: AuthRequest::new("1", "read"),
                expected: Decision::allow(),
            },
            JsonTestCase {
                name: "u2_errors".to_string(),
                request: AuthRequest::new("2", "read"),
                expected: Decision::allow(),
            },
        ],
    };
    // login_id="2" 触发 authorize 返回 Err
    let authorizer = MockAuthorizer::new()
        .with_decision("1", Decision::allow())
        .with_error("2");
    let report = suite.run(&authorizer).await.expect("run should ok");
    assert_eq!(report.total, 2);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failed, 1);
    let failure = &report.failures[0];
    assert_eq!(failure.case_name, "u2_errors");
    assert!(
        failure.error.is_some(),
        "authorize 返回 Err 时 error 应填充"
    );
    assert!(
        failure.error.as_ref().unwrap().contains("login_id=2"),
        "error 消息应包含 login_id=2，实际: {:?}",
        failure.error
    );
}
