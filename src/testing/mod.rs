//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 声明式 JSON 测试套件。
//!
//! 提供从 JSON 文件加载测试用例并运行 [`Authorizer`] trait 的能力，
//! 输出 [`TestReport`] 报告。
//!
//! # 启用方式
//!
//! 启用 `bulwark-testing` feature（依赖 `authorize-api`）：
//!
//! ```toml
//! [dependencies]
//! bulwark = { version = "0.5", features = ["bulwark-testing"] }
//! ```
//!
//! # JSON 格式
//!
//! ```json
//! {
//!   "name": "rbac-basic",
//!   "cases": [
//!     {
//!       "name": "admin_can_read",
//!       "request": {"login_id": 1, "tenant_id": 0, "action": "read", "resource": null, "context": null},
//!       "expected": {"allowed": true, "reason": "explicit_allow"}
//!     }
//!   ]
//! }
//! ```
//!
//! # 使用示例
//!
//! ```ignore
//! use bulwark::testing::JsonTestSuite;
//! use bulwark::core::permission::Authorizer;
//!
//! let json = std::fs::read_to_string("tests/rbac.json")?;
//! let suite = JsonTestSuite::from_json(&json)?;
//! let authorizer: Box<dyn Authorizer> = /* 你的 Authorizer 实现 */;
//! let report = suite.run(&*authorizer).await?;
//! println!("passed: {}/{}", report.passed, report.total);
//! ```
//!
//! [`Authorizer`]: crate::core::permission::Authorizer

use serde::{Deserialize, Serialize};

use crate::core::permission::{AuthRequest, Authorizer, Decision, DecisionReason};
use crate::error::{BulwarkError, BulwarkResult};

/// 声明式 JSON 测试套件。
///
/// 从 JSON 文件加载一组 [`JsonTestCase`]，运行 [`Authorizer::authorize`]，
/// 比较实际决策与期望决策，输出 [`TestReport`]。
///
/// # JSON 格式
///
/// ```json
/// {
///   "name": "rbac-basic",
///   "cases": [
///     {
///       "name": "admin_can_read",
///       "request": {"login_id": 1, "tenant_id": 0, "action": "read", "resource": null, "context": null},
///       "expected": {"allowed": true, "reason": "explicit_allow"}
///     }
///   ]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTestSuite {
    /// 测试套件名称。
    pub name: String,
    /// 测试用例列表。
    pub cases: Vec<JsonTestCase>,
}

/// 单个声明式测试用例。
///
/// 包含一个 [`AuthRequest`] 输入和期望的 [`Decision`] 输出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTestCase {
    /// 用例名称（用于报告标识）。
    pub name: String,
    /// 鉴权请求输入。
    pub request: AuthRequest,
    /// 期望的鉴权决策输出。
    pub expected: Decision,
}

/// 测试套件运行报告。
///
/// 由 [`JsonTestSuite::run`] 返回，包含通过/失败计数与失败详情。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestReport {
    /// 测试套件名称。
    pub suite_name: String,
    /// 总用例数。
    pub total: usize,
    /// 通过用例数。
    pub passed: usize,
    /// 失败用例数。
    pub failed: usize,
    /// 失败详情列表（仅失败用例）。
    pub failures: Vec<TestFailure>,
}

/// 单个失败用例详情。
///
/// 记录期望决策、实际决策与可选错误消息（当 [`Authorizer::authorize`] 返回 `Err` 时）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestFailure {
    /// 用例名称。
    pub case_name: String,
    /// 期望的决策。
    pub expected: Decision,
    /// 实际的决策（`authorize` 返回 `Err` 时为 [`Decision::deny`] 占位）。
    pub actual: Decision,
    /// 错误消息（`authorize` 返回 `Err` 时填充，否则 `None`）。
    pub error: Option<String>,
}

impl JsonTestSuite {
    /// 从 JSON 字符串解析测试套件。
    ///
    /// # 错误
    ///
    /// - JSON 语法错误：返回 [`BulwarkError::InvalidParam`]
    /// - 缺失必填字段（`name` / `cases` / `request` / `expected`）：返回 [`BulwarkError::InvalidParam`]
    pub fn from_json(json: &str) -> BulwarkResult<Self> {
        serde_json::from_str::<Self>(json)
            .map_err(|e| BulwarkError::InvalidParam(format!("JSON parse error: {}", e)))
    }

    /// 运行测试套件，对每个用例调用 [`Authorizer::authorize`] 并比较决策。
    ///
    /// # 比较策略
    ///
    /// 比较 `allowed` / `reason` / `errors` / `checked_permissions` / `matched_roles`，
    /// **不比较 `trace_id`**（动态生成，不应作为测试断言依据）。
    ///
    /// # 错误处理
    ///
    /// 单个用例的 `authorize` 返回 `Err` 时，该用例记为失败（填充 `error` 字段），
    /// 不影响其他用例执行。
    ///
    /// # 参数
    ///
    /// - `authorizer`: 实现 [`Authorizer`] trait 的授权器
    pub async fn run(&self, authorizer: &dyn Authorizer) -> BulwarkResult<TestReport> {
        let total = self.cases.len();
        let mut passed = 0usize;
        let mut failures = Vec::new();

        for case in &self.cases {
            match authorizer.authorize(&case.request).await {
                Ok(actual) => {
                    if decisions_match(&case.expected, &actual) {
                        passed += 1;
                    } else {
                        failures.push(TestFailure {
                            case_name: case.name.clone(),
                            expected: case.expected.clone(),
                            actual,
                            error: None,
                        });
                    }
                },
                Err(e) => {
                    failures.push(TestFailure {
                        case_name: case.name.clone(),
                        expected: case.expected.clone(),
                        // authorize 失败时无 actual Decision，用 deny 占位
                        actual: Decision::deny(DecisionReason::NoMatchingPermission),
                        error: Some(e.to_string()),
                    });
                },
            }
        }

        let failed = failures.len();
        Ok(TestReport {
            suite_name: self.name.clone(),
            total,
            passed,
            failed,
            failures,
        })
    }
}

/// 比较期望决策与实际决策是否匹配（忽略 `trace_id`）。
///
/// 比较字段：`allowed` / `reason` / `errors` / `checked_permissions` / `matched_roles`。
/// `trace_id` 通常是运行时动态生成，不应作为测试断言依据，故忽略。
///
/// # reason 前缀匹配
///
/// `reason` 字段支持部分匹配（前缀匹配，非精确匹配）：
/// - 无数据变体（`ExplicitAllow` / `NoMatchingPermission` 等）：精确匹配
/// - `FirewallBlocked(expected_msg)`：`actual_msg.starts_with(expected_msg)`，
///   允许 expected 只指定前缀（如 `"ip blocked"` 匹配 actual `"ip blocked: 1.2.3.4"`）
fn decisions_match(expected: &Decision, actual: &Decision) -> bool {
    expected.allowed == actual.allowed
        && reason_matches(&expected.reason, &actual.reason)
        && expected.errors == actual.errors
        && expected.checked_permissions == actual.checked_permissions
        && expected.matched_roles == actual.matched_roles
}

/// 比较 `DecisionReason` 是否匹配（前缀匹配）。
///
/// - 无数据变体：精确匹配（`PartialEq`）
/// - `FirewallBlocked(expected_msg)`：`actual_msg.starts_with(expected_msg)`
fn reason_matches(expected: &DecisionReason, actual: &DecisionReason) -> bool {
    match (expected, actual) {
        (DecisionReason::FirewallBlocked(exp), DecisionReason::FirewallBlocked(act)) => {
            act.starts_with(exp)
        },
        (exp, act) => exp == act,
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::permission::{AuthRequest, Authorizer, Decision, DecisionReason};
    use crate::error::BulwarkError;
    use async_trait::async_trait;
    use std::collections::{HashMap, HashSet};

    /// 测试用 MockAuthorizer，根据 `login_id` 预设返回 Decision 或 Error。
    ///
    /// - `decisions`：login_id -> Decision 映射，命中则返回对应 Decision
    /// - `errors`：login_id 集合，命中则返回 `BulwarkError::Internal`
    struct MockAuthorizer {
        decisions: HashMap<i64, Decision>,
        errors: HashSet<i64>,
    }

    impl MockAuthorizer {
        fn new() -> Self {
            Self {
                decisions: HashMap::new(),
                errors: HashSet::new(),
            }
        }

        /// 注册一个 login_id -> Decision 映射。
        fn with_decision(mut self, login_id: i64, decision: Decision) -> Self {
            self.decisions.insert(login_id, decision);
            self
        }

        /// 注册一个应该返回错误的 login_id。
        fn with_error(mut self, login_id: i64) -> Self {
            self.errors.insert(login_id);
            self
        }
    }

    #[async_trait]
    impl Authorizer for MockAuthorizer {
        async fn authorize(&self, req: &AuthRequest) -> BulwarkResult<Decision> {
            if self.errors.contains(&req.login_id) {
                return Err(BulwarkError::Internal(format!(
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
                    "request": {"login_id": 1, "tenant_id": 0, "action": "read", "resource": null, "context": null},
                    "expected": {"allowed": true, "reason": "explicit_allow"}
                },
                {
                    "name": "guest_cannot_write",
                    "request": {"login_id": 2, "tenant_id": 0, "action": "write", "resource": null, "context": null},
                    "expected": {"allowed": false, "reason": "no_matching_permission"}
                }
            ]
        }"#;
        let suite = JsonTestSuite::from_json(json).expect("valid JSON should parse");
        assert_eq!(suite.name, "rbac-basic");
        assert_eq!(suite.cases.len(), 2);
        assert_eq!(suite.cases[0].name, "admin_can_read");
        assert_eq!(suite.cases[0].request.login_id, 1);
        assert_eq!(suite.cases[0].request.action, "read");
        assert!(suite.cases[0].expected.allowed);
        assert_eq!(
            suite.cases[0].expected.reason,
            DecisionReason::ExplicitAllow
        );
        assert!(!suite.cases[1].expected.allowed);
    }

    /// T073-2: 非法 JSON（语法错误）返回 BulwarkError。
    #[test]
    fn from_json_rejects_invalid_json() {
        // 数组括号不匹配（`[}`），serde_json 会报语法错误
        let invalid_json = r#"{"name": "broken", "cases": [}"#;
        let result = JsonTestSuite::from_json(invalid_json);
        assert!(result.is_err(), "syntactically invalid JSON should error");
        match result.err() {
            Some(BulwarkError::InvalidParam(_)) => {},
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
        let missing_expected = r#"{"name": "x", "cases": [{"name": "y", "request": {"login_id": 1, "tenant_id": 0, "action": "read", "resource": null, "context": null}}]}"#;
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
                    request: AuthRequest::new(1, "read"),
                    expected: Decision::allow(),
                },
                JsonTestCase {
                    name: "u2_read".to_string(),
                    request: AuthRequest::new(2, "read"),
                    expected: Decision::allow(),
                },
                JsonTestCase {
                    name: "u3_read".to_string(),
                    request: AuthRequest::new(3, "read"),
                    expected: Decision::allow(),
                },
            ],
        };
        let authorizer = MockAuthorizer::new()
            .with_decision(1, Decision::allow())
            .with_decision(2, Decision::allow())
            .with_decision(3, Decision::allow());
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
                    request: AuthRequest::new(1, "read"),
                    expected: Decision::allow(),
                },
                JsonTestCase {
                    name: "u2_allow_but_actual_deny".to_string(),
                    request: AuthRequest::new(2, "read"),
                    expected: Decision::allow(),
                },
                JsonTestCase {
                    name: "u3_allow".to_string(),
                    request: AuthRequest::new(3, "read"),
                    expected: Decision::allow(),
                },
            ],
        };
        // login_id=2 返回 deny，与 expected(allow) 不匹配
        let authorizer = MockAuthorizer::new()
            .with_decision(1, Decision::allow())
            .with_decision(2, Decision::deny(DecisionReason::NoMatchingPermission))
            .with_decision(3, Decision::allow());
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
                    request: AuthRequest::new(1, "read"),
                    expected: Decision::allow(),
                },
                JsonTestCase {
                    name: "u2_errors".to_string(),
                    request: AuthRequest::new(2, "read"),
                    expected: Decision::allow(),
                },
            ],
        };
        // login_id=2 触发 authorize 返回 Err
        let authorizer = MockAuthorizer::new()
            .with_decision(1, Decision::allow())
            .with_error(2);
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
}
