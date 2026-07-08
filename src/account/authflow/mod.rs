//! AuthenticationFlow DSL 子模块（v0.6.0 新增，吸收 keycloak AuthenticationFlow）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 提供声明式认证流程编排，覆盖登录 + MFA + 社交登录 + SSO 全认证流程。
//! 详见 spec `auth-flow-dsl`。

// T013 将在此实现 AuthenticationFlow + AuthStep + AuthContext + AuthResult
// T014 将在此实现 FlowBuilder
// T015 将在此实现 FlowRegistry
// T016 将在此实现 AuthExecutor
// T017 将在此实现 SocialProvider + SsoServer 步骤
// T018 将在此实现内置 AuthenticationFlow

// 临时占位类型，供 T001 编译测试引用（T013 替换为完整实现）
/// 认证流程定义（占位，T013 实现完整字段）。
#[derive(Debug, Clone)]
pub struct AuthenticationFlow;
