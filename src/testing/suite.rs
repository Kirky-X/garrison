//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! [`JsonTestSuite`] 实现：JSON 解析与测试套件运行逻辑。
//!
//! 从 `mod.rs` 迁移以遵守 Rule 25（mod.rs 接口隔离）。

use crate::core::permission::{Authorizer, Decision, DecisionReason};
use crate::error::{BulwarkError, BulwarkResult};

use super::{JsonTestSuite, TestFailure, TestReport};

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
