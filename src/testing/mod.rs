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

pub mod suite;

use serde::{Deserialize, Serialize};

use crate::core::permission::{AuthRequest, Decision};

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

#[cfg(test)]
mod tests;
