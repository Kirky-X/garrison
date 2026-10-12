// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! [`JsonTestSuite`] 实现：JSON 解析与测试套件运行逻辑。

use crate::core::permission::{Authorizer, Decision, DecisionReason};
use crate::error::{GarrisonError, GarrisonResult};

use super::{JsonTestSuite, TestFailure, TestReport};

impl JsonTestSuite {
    /// 从 JSON 字符串解析测试套件（语法错误或缺必填字段返回 `InvalidParam`）。
    pub fn from_json(json: &str) -> GarrisonResult<Self> {
        serde_json::from_str::<Self>(json)
            .map_err(|e| GarrisonError::InvalidParam(format!("testing-json-parse-error::{}", e)))
    }

    /// 运行测试套件：逐用例调用 [`Authorizer::authorize`] 并比较决策。
    ///
    /// 比较 `allowed`/`reason`/`errors`/`checked_permissions`/`matched_roles`，
    /// **不比较 `trace_id`**（动态生成）；单用例 `authorize` 出错只记该用例失败
    /// （`actual` 置 `None` 并填 `error`），不影响其他用例。
    pub async fn run(&self, authorizer: &dyn Authorizer) -> GarrisonResult<TestReport> {
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
                            actual: Some(actual),
                            error: None,
                        });
                    }
                },
                Err(e) => {
                    // authorize 失败时无实际决策：actual 置 None，不用合成 deny 占位
                    failures.push(TestFailure {
                        case_name: case.name.clone(),
                        expected: case.expected.clone(),
                        actual: None,
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

/// 比较期望决策与实际决策是否匹配（比较 `allowed`/`reason`/`errors`/
/// `checked_permissions`/`matched_roles`，忽略动态生成的 `trace_id`）。
///
/// `reason` 前缀匹配：无数据变体（`ExplicitAllow` 等）精确匹配；含消息变体
/// （如 `FirewallBlocked`）用 `starts_with`，expected 可只指定前缀
/// （如 `"ip blocked"` 匹配 `"ip blocked: 1.2.3.4"`）。
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
