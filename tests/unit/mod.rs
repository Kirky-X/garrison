//! 单元测试目录（production-mock-purge 产物）。
//!
//! 按净化规则，**本地 mock（含错误注入/故障模拟替身）只允许存在于单元测试**，
//! 集成 / e2e / protocol 测试禁止 mock。此目录承接从集成测试下沉的、
//! 依赖 mock 语义（如"DAO 不清理过期键"）的用例。
//!
//! 各子模块按 feature cfg 门控，仅在启用对应 feature 时编译。

#[cfg(feature = "protocol-apikey")]
mod apikey_mock_edge;

mod acceptance_criteria;