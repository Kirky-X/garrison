//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 请求对象式授权器（0.5.1 新增，依据 spec authorize-api M4）。
//!
//! 提供以 [`AuthRequest`] 为入参、返回 [`Decision`] 的公开授权 trait [`Authorizer`]。
//!
//! # 与 [`PermissionChecker`] 的区别
//!
//! - [`PermissionChecker`] 依赖 [`BulwarkInterface`](crate::stp::BulwarkInterface)，是内部 trait，绑定具体数据源
//! - [`Authorizer`] 是公开 API，不假设具体实现，可由任何授权引擎实现
//! - 通过 blanket impl 自动为所有 [`PermissionChecker`] 提供 [`Authorizer`] 实现
//!
//! # Rule 7 冲突说明（design.md D6 vs 现有实现）
//!
//! design.md D6 原计划在本文件定义 `AuthRequest` + `Decision` + `Authorizer` trait，
//! 但 `AuthRequest` / `Decision` / `DecisionReason` 已在 `decision` 模块定义（v0.5.0）。
//! 遵循 Rule 8（先读再写，不重复造轮子）+ Rule 11（惯例优先），本文件仅新增 `Authorizer` trait，
//! 复用现有类型。字段命名差异保留现有惯例：
//!
//! | 字段 | design.md D6 | 现有 decision.rs | 决策 |
//! |---|---|---|---|
//! | 主体标识 | `principal: i64` | `login_id: i64` | 保留 `login_id`（Sa-Token 惯例，Rule 11） |
//! | 租户隔离 | 缺失 | `tenant_id: i64` | 保留（现有更全） |
//! | 上下文 | `HashMap<String, Value>` | `serde_json::Value` | 保留 `serde_json::Value`（更灵活） |
//! | 决策原因 | `String` | `DecisionReason` 枚举 | 保留枚举（更类型安全） |
//!
//! [`PermissionChecker`]: crate::core::permission::PermissionChecker

use async_trait::async_trait;

use crate::error::BulwarkResult;

use super::decision::{AuthRequest, Decision};
use super::PermissionChecker;

/// 请求对象式授权器 trait（依据 spec authorize-api M4）。
///
/// 以 [`AuthRequest`] 为入参、返回 [`Decision`] 的公开授权 API，不假设具体实现，
/// 可由任何授权引擎实现（不限于 [`PermissionChecker`]）。
///
/// # 与 [`PermissionChecker`] 的关系
///
/// [`PermissionChecker`] 已有 `authorize` 方法，但它是内部 trait（依赖
/// [`BulwarkInterface`](crate::stp::BulwarkInterface)）。`Authorizer` 的角色是
/// **显式公开 API**：任何授权引擎可实现此 trait，无需依赖具体数据源。
///
/// 通过 blanket impl，所有 [`PermissionChecker`] 自动实现 `Authorizer`，
/// 行为委托给 `PermissionChecker::authorize`，保持向后兼容。
///
/// # trait object 安全
///
/// `Authorizer: Send + Sync` 且方法签名兼容 trait object，可用 `Box<dyn Authorizer>`。
///
/// # 使用示例
///
/// ```ignore
/// use bulwark::prelude::*;
/// use std::sync::Arc;
///
/// // 任何 PermissionChecker 自动实现 Authorizer
/// let checker: Arc<dyn PermissionChecker> = ...;
/// let req = AuthRequest::new("1001", "user:read");
/// let decision: Decision = Authorizer::authorize(&*checker, &req).await?;
/// ```
///
/// [`PermissionChecker`]: crate::core::permission::PermissionChecker
#[async_trait]
pub trait Authorizer: Send + Sync {
    /// 鉴权决策：基于 [`AuthRequest`] 返回完整 [`Decision`]。
    ///
    /// # 错误
    ///
    /// 校验过程本身出错（如 DAO 故障、参数无效）返回 `Err(BulwarkError)`；
    /// "未持有权限"不是错误，返回 `Ok(Decision { allowed: false, .. })`。
    async fn authorize(&self, req: &AuthRequest) -> BulwarkResult<Decision>;
}

/// Blanket impl：任何 [`PermissionChecker`] 自动实现 [`Authorizer`]。
///
/// 委托给 [`PermissionChecker::authorize`]，保持行为一致。这使所有现有的
/// `PermissionChecker` 实现（如 `PermissionCheckerDefault`）自动获得
/// `Authorizer` 实现，无需重复实现。
///
/// # Rule 7 冲突处理
///
/// design.md D6 原计划为 `BulwarkLogicDefault` 单独实现 `Authorizer`，但
/// `PermissionChecker` trait 已有 `authorize` 方法且 `PermissionCheckerDefault`
/// 已实现之。通过 blanket impl 复用现有实现，避免重复代码（Rule 8 先读再写）。
///
/// [`PermissionChecker::authorize`]: crate::core::permission::PermissionChecker::authorize
#[async_trait]
impl<T: PermissionChecker> Authorizer for T {
    async fn authorize(&self, req: &AuthRequest) -> BulwarkResult<Decision> {
        PermissionChecker::authorize(self, req).await
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::Authorizer;
    use crate::core::permission::{
        AuthRequest, Decision, DecisionReason, PermissionChecker, PermissionCheckerDefault,
    };
    use crate::error::{BulwarkError, BulwarkResult};
    use crate::stp::BulwarkInterface;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Mock 行为枚举，控制 MockAuthorizer 返回的决策或错误。
    enum MockOutcome {
        Allow,
        DenyNoMatch,
        InvalidParam,
    }

    /// 测试用 MockAuthorizer，返回固定 Decision 或 Error，并捕获传入的 AuthRequest。
    ///
    /// 用于在隔离环境下测试 `Authorizer` trait 契约（不依赖 BulwarkLogicDefault）。
    struct MockAuthorizer {
        outcome: MockOutcome,
        captured: Mutex<Option<AuthRequest>>,
    }

    impl MockAuthorizer {
        fn new(outcome: MockOutcome) -> Self {
            Self {
                outcome,
                captured: Mutex::new(None),
            }
        }

        /// 取出捕获的请求副本（用于断言字段传递正确性）。
        fn captured_request(&self) -> Option<AuthRequest> {
            self.captured.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Authorizer for MockAuthorizer {
        async fn authorize(&self, req: &AuthRequest) -> BulwarkResult<Decision> {
            *self.captured.lock().unwrap() = Some(req.clone());
            match &self.outcome {
                MockOutcome::Allow => Ok(Decision::allow()),
                MockOutcome::DenyNoMatch => {
                    Ok(Decision::deny(DecisionReason::NoMatchingPermission))
                },
                MockOutcome::InvalidParam => {
                    Err(BulwarkError::InvalidParam("mock invalid param".to_string()))
                },
            }
        }
    }

    // ========================================================================
    // Authorizer trait 测试（依据 spec authorize-api M4）
    // ========================================================================

    /// T062-1: Authorizer::authorize 在允许场景返回 allowed=true 的 Decision。
    #[tokio::test]
    async fn authorizer_allows_when_permission_held() {
        let authorizer = MockAuthorizer::new(MockOutcome::Allow);
        let req = AuthRequest::new("1001", "user:read");
        let decision = authorizer.authorize(&req).await.expect("authorize ok");
        assert!(decision.allowed);
        assert_eq!(decision.reason, DecisionReason::ExplicitAllow);
    }

    /// T062-2: Authorizer::authorize 在拒绝场景返回 allowed=false + NoMatchingPermission。
    #[tokio::test]
    async fn authorizer_denies_when_permission_not_held() {
        let authorizer = MockAuthorizer::new(MockOutcome::DenyNoMatch);
        let req = AuthRequest::new("1001", "user:delete");
        let decision = authorizer.authorize(&req).await.expect("authorize ok");
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::NoMatchingPermission);
    }

    /// T062-3: Authorizer::authorize 在参数无效时返回 InvalidParam 错误。
    #[tokio::test]
    async fn authorizer_returns_error_on_invalid_param() {
        let authorizer = MockAuthorizer::new(MockOutcome::InvalidParam);
        let req = AuthRequest::new("1001", "");
        let result = authorizer.authorize(&req).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam，实际: {:?}", other),
        }
    }

    /// T062-4: Authorizer::authorize 完整传递 AuthRequest 的 login_id/action/resource 字段。
    #[tokio::test]
    async fn authorizer_passes_auth_request_intact() {
        let authorizer = MockAuthorizer::new(MockOutcome::Allow);
        let req = AuthRequest {
            login_id: "2002".to_string(),
            tenant_id: 0,
            action: "doc:write".to_string(),
            resource: Some("doc:42".to_string()),
            context: serde_json::Value::Null,
        };
        authorizer.authorize(&req).await.expect("authorize ok");
        let captured = authorizer
            .captured_request()
            .expect("request should be captured");
        assert_eq!(captured.login_id, "2002");
        assert_eq!(captured.action, "doc:write");
        assert_eq!(captured.resource.as_deref(), Some("doc:42"));
    }

    /// T062-5: Authorizer::authorize 正确传递 context 字段（serde_json::Value）。
    #[tokio::test]
    async fn authorizer_passes_context_field() {
        let authorizer = MockAuthorizer::new(MockOutcome::Allow);
        let ctx = serde_json::json!({"ip": "10.0.0.1", "device": "mobile"});
        let req = AuthRequest {
            login_id: "1".to_string(),
            tenant_id: 0,
            action: "test".to_string(),
            resource: None,
            context: ctx.clone(),
        };
        authorizer.authorize(&req).await.expect("authorize ok");
        let captured = authorizer
            .captured_request()
            .expect("request should be captured");
        assert_eq!(captured.context, ctx);
        assert_eq!(captured.context["ip"], serde_json::json!("10.0.0.1"));
        assert_eq!(captured.context["device"], serde_json::json!("mobile"));
    }

    /// T062-6: Authorizer::authorize 正确传递 tenant_id 字段。
    #[tokio::test]
    async fn authorizer_passes_tenant_id() {
        let authorizer = MockAuthorizer::new(MockOutcome::Allow);
        let req = AuthRequest {
            login_id: "1".to_string(),
            tenant_id: 42,
            action: "test".to_string(),
            resource: None,
            context: serde_json::Value::Null,
        };
        authorizer.authorize(&req).await.expect("authorize ok");
        let captured = authorizer
            .captured_request()
            .expect("request should be captured");
        assert_eq!(captured.tenant_id, 42);
    }

    /// T062-7: blanket impl — PermissionCheckerDefault 自动实现 Authorizer，
    /// authorize 行为与 PermissionChecker::authorize 一致。
    ///
    /// **Red 阶段**：此测试在 T063 添加 blanket impl 前不编译
    ///（`PermissionCheckerDefault` 未实现 `Authorizer`）。
    #[tokio::test]
    async fn authorizer_blanket_impl_works_with_permission_checker() {
        let interface = MockInterface::new().with_perms("1001", vec!["user:read"]);
        let interface_arc: Arc<dyn BulwarkInterface> = Arc::new(interface);
        let checker = PermissionCheckerDefault::new(interface_arc);

        let req = AuthRequest::new("1001", "user:read");

        // Via PermissionChecker（内部 trait）
        let decision_pc = PermissionChecker::authorize(&checker, &req)
            .await
            .expect("PermissionChecker::authorize ok");

        // Via Authorizer（blanket impl — 需要 T063 添加才能编译）
        let decision_auth = Authorizer::authorize(&checker, &req)
            .await
            .expect("Authorizer::authorize ok");

        // 行为一致：两条路径返回相同的 allowed/reason
        assert_eq!(decision_pc.allowed, decision_auth.allowed);
        assert_eq!(decision_pc.reason, decision_auth.reason);
        assert!(decision_auth.allowed);
        assert_eq!(decision_auth.reason, DecisionReason::ExplicitAllow);
    }

    /// T062-8: Authorizer 可作为 dyn trait 使用（Box<dyn Authorizer>）。
    ///
    /// 验证 trait object 安全：`Authorizer: Send + Sync` + `#[async_trait]` 使
    /// `Box<dyn Authorizer>` 可构造并调用 `authorize`。
    #[tokio::test]
    async fn authorizer_can_be_used_as_dyn_trait() {
        let authorizer: Box<dyn Authorizer> = Box::new(MockAuthorizer::new(MockOutcome::Allow));
        let req = AuthRequest::new("1001", "user:read");
        let decision = authorizer.authorize(&req).await.expect("authorize ok");
        assert!(decision.allowed);
        assert_eq!(decision.reason, DecisionReason::ExplicitAllow);
    }

    // ========================================================================
    // 测试用 MockInterface（BulwarkInterface 实现，用于 blanket impl 测试）
    // ========================================================================

    /// 测试用 mock BulwarkInterface（仅提供 permission/role 数据，供 PermissionCheckerDefault 使用）。
    struct MockInterface {
        permissions: HashMap<String, Vec<String>>,
        #[allow(dead_code)]
        roles: HashMap<String, Vec<String>>,
    }

    impl MockInterface {
        fn new() -> Self {
            Self {
                permissions: HashMap::new(),
                roles: HashMap::new(),
            }
        }

        fn with_perms(mut self, login_id: &str, perms: Vec<&str>) -> Self {
            self.permissions.insert(
                login_id.to_string(),
                perms.iter().map(|s| s.to_string()).collect(),
            );
            self
        }
    }

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(self.roles.get(login_id).cloned().unwrap_or_default())
        }
    }
}
