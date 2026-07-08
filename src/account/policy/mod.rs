//! 密码策略套件子模块（v0.6.0 新增，吸收 keycloak PasswordPolicyRule）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 提供 12+ 密码策略规则实现，支持企业合规场景。
//! 详见 spec `password-policy`。

// T007 将在此实现 PasswordPolicyRule trait + PasswordPolicyEngine + PolicyContext
// T008 将在此实现 6 个核心规则
// T009 将在此实现 6 个扩展规则

// 临时占位类型，供 T001 编译测试引用（T007 替换为完整实现）
/// 密码策略引擎（占位，T007 实现完整逻辑）。
#[derive(Debug, Clone)]
pub struct PasswordPolicyEngine;
