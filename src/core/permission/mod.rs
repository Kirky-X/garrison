//! 权限校验模块，定义以 login_id 为入参的权限与角色校验抽象。
//!
//! [借鉴 Sa-Token] 权限认证核心逻辑，对应 Sa-Token 的 `StpLogic.checkPermission / checkRole` 方法。
//!
//! 0.2.0 将 API 改为 login_id-as-input，与 token 格式无关，便于在任意 token 风格下复用。
//!
//! 0.5.0 新增 [`decision`] 子模块：`Decision` / `DecisionReason` / `AuthRequest`，
//! 支持决策溯源（依据 spec decision-trace）。

pub mod decision;

use async_trait::async_trait;
use std::sync::Arc;
use unicode_normalization::UnicodeNormalization;

use crate::error::{BulwarkError, BulwarkResult};
use crate::stp::BulwarkInterface;

pub use decision::{AuthRequest, Decision, DecisionReason};

/// 权限注册表模块（0.5.1 新增，依据 spec permission-registry M3）。
#[cfg(feature = "permission-registry")]
pub mod registry;

#[cfg(feature = "permission-registry")]
pub use registry::{PermissionRegistration, PermissionRegistry, PermissionSpec};

/// 请求对象式授权器模块（0.5.1 新增，依据 spec authorize-api M4）。
#[cfg(feature = "authorize-api")]
pub mod authorize;

#[cfg(feature = "authorize-api")]
pub use authorize::Authorizer;

/// 权限校验 trait，定义以 login_id 为入参的权限与角色校验抽象（依据 spec core-permission）。
///
/// 所有方法 MUST 使用 `async_trait` 标注，trait 绑定 `Send + Sync`。
/// 入参为 `login_id: i64` 而非 token，使权限校验可在任意 token 风格下复用。
///
/// 0.5.0 新增 [`authorize`](Self::authorize) 方法支持决策溯源（依据 spec decision-trace）。
/// `check_permission` / `check_role` 改为默认实现，委托 `authorize` 并返回断言结果。
#[async_trait]
pub trait PermissionChecker: Send + Sync {
    /// 校验主体是否持有指定权限（依据 spec core-permission）。
    ///
    /// # 返回
    /// - `Ok(true)`: 持有权限。
    /// - `Ok(false)`: 未持有权限。
    /// - `Err(BulwarkError::InvalidParam)`: 权限字符串为空。
    async fn has_permission(&self, login_id: i64, permission: &str) -> BulwarkResult<bool>;

    /// 校验主体是否持有指定角色（依据 spec core-permission）。
    async fn has_role(&self, login_id: i64, role: &str) -> BulwarkResult<bool>;

    /// 鉴权决策：基于 [`AuthRequest`] 返回完整 [`Decision`]（依据 spec decision-trace）。
    ///
    /// 默认实现调用 [`has_permission`](Self::has_permission) 并构造 [`Decision`]：
    /// - 持有权限 → `Decision { allowed: true, reason: ExplicitAllow, .. }`
    /// - 未持有权限 → `Decision { allowed: false, reason: NoMatchingPermission, .. }`
    ///
    /// `decision-trace` feature 启用时，默认实现自动生成 UUID v7（时间有序）作为
    /// `trace_id`（依据 design.md D11 D5）；不启用时 `trace_id` 为 `None`（性能优先）。
    /// 实现者可覆盖此方法填充 `checked_permissions` / `matched_roles` 字段。
    ///
    /// # 错误
    ///
    /// 校验过程本身出错（如 DAO 故障、参数无效）返回 `Err(BulwarkError)`；
    /// "未持有权限"不是错误，返回 `Ok(Decision { allowed: false, .. })`。
    async fn authorize(&self, request: &AuthRequest) -> BulwarkResult<Decision> {
        // D5（v0.5.1）：decision-trace feature 启用时自动生成 UUID v7 作为 trace_id
        // （时间有序，便于跨服务追踪与日志关联）；不启用时为 None，避免性能开销。
        #[cfg(feature = "decision-trace")]
        let trace_id = Some(uuid::Uuid::now_v7().to_string());
        #[cfg(not(feature = "decision-trace"))]
        let trace_id: Option<String> = None;

        let allowed = self
            .has_permission(request.login_id, &request.action)
            .await?;
        let decision = if allowed {
            Decision {
                allowed: true,
                reason: DecisionReason::ExplicitAllow,
                errors: Vec::new(),
                checked_permissions: Vec::new(),
                matched_roles: Vec::new(),
                trace_id,
            }
        } else {
            Decision {
                allowed: false,
                reason: DecisionReason::NoMatchingPermission,
                errors: Vec::new(),
                checked_permissions: Vec::new(),
                matched_roles: Vec::new(),
                trace_id,
            }
        };
        Ok(decision)
    }

    /// 断言权限：被拒绝时返回 `Err(BulwarkError::NotPermission)`（依据 spec core-permission）。
    ///
    /// 0.5.0 默认实现委托 [`authorize`](Self::authorize)，保持向后兼容。
    async fn check_permission(&self, login_id: i64, permission: &str) -> BulwarkResult<()> {
        let request = AuthRequest::new(login_id, permission);
        let decision = self.authorize(&request).await?;
        if decision.allowed {
            Ok(())
        } else {
            Err(BulwarkError::NotPermission(format!(
                "账号 {} 未持有权限: {}",
                login_id, permission
            )))
        }
    }

    /// 断言角色：被拒绝时返回 `Err(BulwarkError::NotRole)`（依据 spec core-permission）。
    async fn check_role(&self, login_id: i64, role: &str) -> BulwarkResult<()> {
        if self.has_role(login_id, role).await? {
            Ok(())
        } else {
            Err(BulwarkError::NotRole(format!(
                "账号 {} 未持有角色: {}",
                login_id, role
            )))
        }
    }

    /// 批量校验权限：任一满足即返回 true（依据 spec core-permission）。
    ///
    /// 内部调用 `has_permission`，遇到错误时该权限视为不满足。
    async fn has_any_permission(&self, login_id: i64, perms: &[&str]) -> bool;

    /// 批量校验权限：全部满足才返回 true（依据 spec core-permission）。
    ///
    /// 内部调用 `has_permission`，遇到错误时该权限视为不满足。
    async fn has_all_permissions(&self, login_id: i64, perms: &[&str]) -> bool;
}

/// `PermissionChecker` 的默认实现，委托 `BulwarkInterface` 获取权限/角色数据后做字符串匹配（依据 spec core-permission）。
///
/// 与 `BulwarkPermissionStrategy` 的职责区分：
/// - `PermissionCheckerDefault`：纯数据查询（返回 bool/Err，无副作用）
/// - `BulwarkPermissionStrategy`：编排（校验 + 抛异常 + 事件广播）
pub struct PermissionCheckerDefault {
    /// 业务接口（提供 get_permission_list / get_role_list）。
    interface: Arc<dyn BulwarkInterface>,
}

impl PermissionCheckerDefault {
    /// 创建新的 `PermissionCheckerDefault` 实例。
    pub fn new(interface: Arc<dyn BulwarkInterface>) -> Self {
        Self { interface }
    }
}

#[async_trait]
impl PermissionChecker for PermissionCheckerDefault {
    async fn has_permission(&self, login_id: i64, permission: &str) -> BulwarkResult<bool> {
        // P2.4: NFC 规范化 permission 字符串，防止 Unicode 同形异义字攻击
        // （NFD 与 NFC 形式视觉相同但字节不同，规范化后统一比较）
        let normalized = permission.nfc().collect::<String>();
        if normalized.is_empty() {
            return Err(BulwarkError::InvalidParam("权限字符串不能为空".to_string()));
        }
        // P2.4: 长度校验（>256 字节返回 InvalidParam），防止 DoS
        if normalized.len() > 256 {
            return Err(BulwarkError::InvalidParam(format!(
                "permission too long: {} bytes (max 256)",
                normalized.len()
            )));
        }
        let perms = self.interface.get_permission_list(login_id).await?;
        Ok(perms.iter().any(|p| p == &normalized))
    }

    async fn has_role(&self, login_id: i64, role: &str) -> BulwarkResult<bool> {
        if role.is_empty() {
            return Err(BulwarkError::InvalidParam("角色字符串不能为空".to_string()));
        }
        let roles = self.interface.get_role_list(login_id).await?;
        Ok(roles.iter().any(|r| r == role))
    }

    // check_permission / check_role 使用 trait 默认实现（委托 authorize / has_role），
    // 保持与 0.5.0 决策溯源路径一致（依据 spec decision-trace）。

    async fn has_any_permission(&self, login_id: i64, perms: &[&str]) -> bool {
        for perm in perms {
            if self.has_permission(login_id, perm).await.unwrap_or(false) {
                return true;
            }
        }
        false
    }

    async fn has_all_permissions(&self, login_id: i64, perms: &[&str]) -> bool {
        for perm in perms {
            if !self.has_permission(login_id, perm).await.unwrap_or(false) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;

    /// 测试用 mock BulwarkInterface。
    struct MockInterface {
        permissions: HashMap<i64, Vec<String>>,
        roles: HashMap<i64, Vec<String>>,
    }

    impl MockInterface {
        fn new() -> Self {
            Self {
                permissions: HashMap::new(),
                roles: HashMap::new(),
            }
        }

        fn with_perms(mut self, login_id: i64, perms: Vec<&str>) -> Self {
            self.permissions
                .insert(login_id, perms.iter().map(|s| s.to_string()).collect());
            self
        }

        fn with_roles(mut self, login_id: i64, roles: Vec<&str>) -> Self {
            self.roles
                .insert(login_id, roles.iter().map(|s| s.to_string()).collect());
            self
        }
    }

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(self.permissions.get(&login_id).cloned().unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(self.roles.get(&login_id).cloned().unwrap_or_default())
        }
    }

    /// 创建 PermissionCheckerDefault 实例（账号 1001 持有 user:read/user:write 权限 + admin/user 角色）。
    fn make_checker() -> PermissionCheckerDefault {
        let interface = MockInterface::new()
            .with_perms(1001, vec!["user:read", "user:write"])
            .with_roles(1001, vec!["admin", "user"]);
        let interface_arc: Arc<dyn BulwarkInterface> = Arc::new(interface);
        PermissionCheckerDefault::new(interface_arc)
    }

    // ========================================================================
    // has_permission 测试（依据 spec core-permission）
    // ========================================================================

    /// has_permission 持有权限返回 true（spec Scenario）。
    #[tokio::test]
    async fn has_permission_held_returns_true() {
        let checker = make_checker();
        assert!(checker.has_permission(1001, "user:read").await.unwrap());
    }

    /// has_permission 未持有权限返回 false（spec Scenario）。
    #[tokio::test]
    async fn has_permission_not_held_returns_false() {
        let checker = make_checker();
        assert!(!checker.has_permission(1001, "user:delete").await.unwrap());
    }

    /// has_permission 空字符串返回错误（spec Scenario）。
    #[tokio::test]
    async fn has_permission_empty_string_returns_error() {
        let checker = make_checker();
        let result = checker.has_permission(1001, "").await;
        assert!(result.is_err());
    }

    // ========================================================================
    // has_role 测试（依据 spec core-permission）
    // ========================================================================

    /// has_role 持有角色返回 true（spec Scenario）。
    #[tokio::test]
    async fn has_role_held_returns_true() {
        let checker = make_checker();
        assert!(checker.has_role(1001, "admin").await.unwrap());
    }

    /// has_role 未持有角色返回 false（spec Scenario）。
    #[tokio::test]
    async fn has_role_not_held_returns_false() {
        let checker = make_checker();
        assert!(!checker.has_role(1001, "superadmin").await.unwrap());
    }

    // ========================================================================
    // check_permission 测试（依据 spec core-permission）
    // ========================================================================

    /// check_permission 持有权限返回 Ok(())（spec Scenario）。
    #[tokio::test]
    async fn check_permission_held_returns_ok() {
        let checker = make_checker();
        assert!(checker.check_permission(1001, "user:read").await.is_ok());
    }

    /// check_permission 未持有权限返回 NotPermission 错误（spec Scenario）。
    #[tokio::test]
    async fn check_permission_not_held_returns_error() {
        let checker = make_checker();
        let result = checker.check_permission(1001, "user:delete").await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::NotPermission(_)) => {},
            other => panic!("期望 NotPermission，实际: {:?}", other),
        }
    }

    // ========================================================================
    // check_role 测试（依据 spec core-permission）
    // ========================================================================

    /// check_role 持有角色返回 Ok(())。
    #[tokio::test]
    async fn check_role_held_returns_ok() {
        let checker = make_checker();
        assert!(checker.check_role(1001, "admin").await.is_ok());
    }

    /// check_role 未持有角色返回 NotRole 错误（spec Scenario）。
    #[tokio::test]
    async fn check_role_not_held_returns_error() {
        let checker = make_checker();
        let result = checker.check_role(1001, "superadmin").await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::NotRole(_)) => {},
            other => panic!("期望 NotRole，实际: {:?}", other),
        }
    }

    // ========================================================================
    // has_any_permission 测试（依据 spec core-permission）
    // ========================================================================

    /// has_any_permission 任一匹配返回 true（spec Scenario）。
    #[tokio::test]
    async fn has_any_permission_any_match_returns_true() {
        let checker = make_checker();
        assert!(
            checker
                .has_any_permission(1001, &["user:read", "user:delete"])
                .await
        );
    }

    /// has_any_permission 全不匹配返回 false（spec Scenario）。
    #[tokio::test]
    async fn has_any_permission_no_match_returns_false() {
        let checker = make_checker();
        assert!(
            !checker
                .has_any_permission(1001, &["user:delete", "user:create"])
                .await
        );
    }

    // ========================================================================
    // has_all_permissions 测试（依据 spec core-permission）
    // ========================================================================

    /// has_all_permissions 全部匹配返回 true（spec Scenario）。
    #[tokio::test]
    async fn has_all_permissions_all_match_returns_true() {
        let checker = make_checker();
        assert!(
            checker
                .has_all_permissions(1001, &["user:read", "user:write"])
                .await
        );
    }

    /// has_all_permissions 部分匹配返回 false（spec Scenario）。
    #[tokio::test]
    async fn has_all_permissions_partial_match_returns_false() {
        let checker = make_checker();
        assert!(
            !checker
                .has_all_permissions(1001, &["user:read", "user:delete"])
                .await
        );
    }

    /// has_all_permissions 空列表返回 true（vacuous truth）。
    #[tokio::test]
    async fn has_all_permissions_empty_list_returns_true() {
        let checker = make_checker();
        assert!(checker.has_all_permissions(1001, &[]).await);
    }

    // ========================================================================
    // authorize 测试（依据 spec decision-trace，0.5.0 新增）
    // ========================================================================

    /// T015: authorize 在权限匹配时返回 allowed=true 的 Decision。
    ///
    /// 验证 `authorize(&AuthRequest{ login_id: 1001, action: "user:read", .. })`
    /// 返回 `Decision { allowed: true, reason: ExplicitAllow, .. }`。
    #[tokio::test]
    async fn authorize_returns_decision_with_allowed_true_when_permission_matches() {
        let checker = make_checker();
        let request = AuthRequest::new(1001, "user:read");
        let decision = PermissionChecker::authorize(&checker, &request)
            .await
            .expect("authorize ok");
        assert!(decision.allowed);
        assert_eq!(decision.reason, DecisionReason::ExplicitAllow);
    }

    /// T015 补充: authorize 在权限不匹配时返回 allowed=false + NoMatchingPermission。
    #[tokio::test]
    async fn authorize_returns_deny_when_permission_not_matched() {
        let checker = make_checker();
        let request = AuthRequest::new(1001, "user:delete");
        let decision = PermissionChecker::authorize(&checker, &request)
            .await
            .expect("authorize ok");
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::NoMatchingPermission);
    }

    /// T015 补充: authorize 在权限字符串为空时返回 InvalidParam 错误。
    #[tokio::test]
    async fn authorize_returns_error_for_empty_permission() {
        let checker = make_checker();
        let request = AuthRequest::new(1001, "");
        let result = PermissionChecker::authorize(&checker, &request).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam，实际: {:?}", other),
        }
    }

    /// T017: check_permission 与 authorize 行为一致（向后兼容）。
    ///
    /// 验证 `check_permission(login_id, perm)` 的返回值（Ok/Err）与
    /// `authorize(&AuthRequest{..}).await?.allowed` 一致：
    /// - allowed=true → check_permission 返回 Ok(())
    /// - allowed=false → check_permission 返回 Err(NotPermission)
    #[tokio::test]
    async fn check_permission_delegates_to_authorize_and_returns_allowed() {
        let checker = make_checker();

        // 持有权限：authorize().allowed == true，check_permission == Ok
        let req_ok = AuthRequest::new(1001, "user:read");
        let decision_ok = PermissionChecker::authorize(&checker, &req_ok)
            .await
            .expect("authorize ok");
        assert!(decision_ok.allowed);
        assert!(checker.check_permission(1001, "user:read").await.is_ok());

        // 未持有权限：authorize().allowed == false，check_permission == Err
        let req_no = AuthRequest::new(1001, "user:delete");
        let decision_no = PermissionChecker::authorize(&checker, &req_no)
            .await
            .expect("authorize ok");
        assert!(!decision_no.allowed);
        assert!(checker.check_permission(1001, "user:delete").await.is_err());
    }

    /// T017 补充: check_permission 的错误类型为 NotPermission（不是其他错误）。
    #[tokio::test]
    async fn check_permission_deny_returns_not_permission_error() {
        let checker = make_checker();
        let result = checker.check_permission(1001, "user:delete").await;
        match result.err() {
            Some(BulwarkError::NotPermission(msg)) => {
                assert!(msg.contains("1001"), "错误消息应含 login_id");
                assert!(msg.contains("user:delete"), "错误消息应含 permission");
            },
            other => panic!("期望 NotPermission，实际: {:?}", other),
        }
    }

    /// T017 补充: check_role 仍保持原行为（未持有角色返回 NotRole）。
    #[tokio::test]
    async fn check_role_still_returns_not_role_when_unmatched() {
        let checker = make_checker();
        let result = checker.check_role(1001, "superadmin").await;
        match result.err() {
            Some(BulwarkError::NotRole(_)) => {},
            other => panic!("期望 NotRole，实际: {:?}", other),
        }
    }

    /// T017 补充: Decision 可从 authorize 序列化为 JSON（端到端 trace 输出验证）。
    #[tokio::test]
    async fn authorize_decision_serializes_to_json() {
        let checker = make_checker();
        let request = AuthRequest::new(1001, "user:read");
        let decision = PermissionChecker::authorize(&checker, &request)
            .await
            .expect("authorize ok");
        let json = serde_json::to_value(&decision).expect("serialize Decision");
        assert_eq!(json["allowed"], serde_json::json!(true));
        assert_eq!(json["reason"], serde_json::json!("explicit_allow"));
    }

    // ========================================================================
    // T041: Unicode NFC 规范化 + 长度限制测试（依据 spec P2.4，防止 Unicode 同形异义字攻击与 DoS）
    // ========================================================================

    /// T041: check_permission 对 permission 字符串做 NFC 规范化。
    ///
    /// NFD 形式 `"user:e\u{0301}read"`（e + COMBINING ACUTE ACCENT U+0301）应规范化为
    /// NFC 形式 `"user:\u{00e9}read"`（LATIN SMALL LETTER E WITH ACUTE U+00E9）。
    /// mock 存储 NFC 形式，传入 NFD 形式应规范化后匹配。
    ///
    /// 注：任务描述原例 `"user\u{0301}:read"` → `"user\u{00e9}:read"` 不正确，
    /// 因为 U+0301 会与前一个 'r' 组合形成 'ŕ'（U+0157），而非 'é'（U+00E9）。
    /// 正确的 NFD→NFC 对为 `"user:e\u{0301}read"` → `"user:\u{00e9}read"`。
    #[tokio::test]
    async fn check_permission_normalizes_unicode() {
        let interface = MockInterface::new().with_perms(1001, vec!["user:\u{00e9}read"]);
        let interface_arc: Arc<dyn BulwarkInterface> = Arc::new(interface);
        let checker = PermissionCheckerDefault::new(interface_arc);

        let nfd = "user:e\u{0301}read";
        let nfc = "user:\u{00e9}read";

        assert!(
            checker.check_permission(1001, nfd).await.is_ok(),
            "NFD 形式应规范化后匹配 NFC permission"
        );
        assert!(
            checker.check_permission(1001, nfc).await.is_ok(),
            "NFC 形式应直接匹配"
        );
    }

    /// T041: check_permission 拒绝超过 256 字节的 permission 字符串（防止 DoS）。
    #[tokio::test]
    async fn check_permission_rejects_over_256_bytes() {
        let long_perm = "x".repeat(300); // 300 字节，超过 256 字节上限
        let checker = make_checker();
        let result = checker.check_permission(1001, &long_perm).await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "超长 permission 应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    // ========================================================================
    // 覆盖率补充：has_role 空角色 + check_role 错误消息验证
    // ========================================================================

    /// has_role 空字符串返回 InvalidParam 错误（覆盖行 180）。
    #[tokio::test]
    async fn has_role_empty_string_returns_error() {
        let checker = make_checker();
        let result = checker.has_role(1001, "").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(ref msg)) if msg.contains("角色字符串不能为空")),
            "has_role 空字符串应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// check_role 未持有角色的错误消息包含 login_id 和 role（覆盖行 124-125 的 format）。
    #[tokio::test]
    async fn check_role_deny_message_includes_login_id_and_role() {
        let checker = make_checker();
        let result = checker.check_role(1001, "superadmin").await;
        match result.err() {
            Some(BulwarkError::NotRole(msg)) => {
                assert!(msg.contains("1001"), "错误消息应含 login_id，实际: {}", msg);
                assert!(
                    msg.contains("superadmin"),
                    "错误消息应含 role，实际: {}",
                    msg
                );
            },
            other => panic!("期望 NotRole，实际: {:?}", other),
        }
    }
}
