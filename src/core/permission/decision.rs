//! 鉴权决策与请求模型（0.5.0 新增，依据 spec decision-trace）。
//!
//! 提供决策溯源（Decision Provenance）所需的数据结构：
//! - [`Decision`]：鉴权决策结果，含 allowed/reason/errors/trace 字段
//! - [`DecisionReason`]：决策原因枚举（显式允许/角色继承/显式拒绝/...）
//! - [`AuthRequest`]：鉴权请求输入，含 login_id/tenant_id/action/resource/context
//!
//! # 设计
//!
//! `Decision` 的 `errors` 字段为 `Vec<String>` 而非 `Vec<BulwarkError>`：
//! - `BulwarkError` / `BulwarkException` 未 derive `Serialize`，给它们加 derive 会触碰大量现有代码（违反外科手术式修改原则）
//! - 决策溯源场景只需可读错误消息（用于 trace 输出），不需要错误类型枚举
//! - 存储时调用 `err.to_string()` 转为字符串

use serde::{Deserialize, Serialize};

/// 鉴权决策原因（依据 spec decision-trace Requirement: DecisionReason）。
///
/// 描述决策的"为什么"，用于 trace 输出和审计日志。
///
/// # 序列化
///
/// 同时 derive `Serialize` 与 `Deserialize`，使 [`Decision`] 可在
/// `bulwark-testing` feature 下从 JSON 反序列化（声明式测试套件用）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReason {
    /// 显式允许：主体直接持有该权限。
    ExplicitAllow,
    /// 角色继承允许：主体未直接持有权限，但其角色继承覆盖该权限。
    RoleInheritedAllow,
    /// 显式拒绝：主体被显式拒绝（黑名单/防火墙规则）。
    ExplicitDeny,
    /// 无匹配权限：主体权限列表中无请求的 action。
    NoMatchingPermission,
    /// 无匹配角色：主体角色列表中无请求的角色。
    NoMatchingRole,
    /// 防火墙拦截：防火墙策略拒绝（含拦截原因）。
    FirewallBlocked(String),
    /// Token 无效。
    TokenInvalid,
    /// Token 已过期。
    TokenExpired,
    /// 租户不匹配：跨租户访问被拒。
    TenantMismatch,
}

/// 鉴权决策结果（依据 spec decision-trace Requirement: Decision）。
///
/// 包含决策本身（allowed/reason）和溯源信息（errors/checked_permissions/matched_roles/trace_id）。
///
/// # 序列化
///
/// `Decision` 实现 `Serialize`，可序列化为 JSON 用于审计日志和 trace 输出。
/// `errors` 字段为 `Vec<String>`（错误消息），不是 `Vec<BulwarkError>`（错误类型）。
///
/// `bulwark-testing` feature 启用时同时实现 `Deserialize`，使声明式测试套件
/// 可从 JSON 文件反序列化期望决策（`JsonTestCase::expected`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    /// 是否允许。
    pub allowed: bool,
    /// 决策原因。
    pub reason: DecisionReason,
    /// 校验过程中收集的错误消息（`err.to_string()`），用于 trace。
    ///
    /// 反序列化时缺失默认空 vec（声明式测试套件的 `expected` 通常只填 `allowed` + `reason`）。
    #[serde(default)]
    pub errors: Vec<String>,
    /// 已校验的权限列表（decision-trace feature 启用时填充）。
    #[serde(default)]
    pub checked_permissions: Vec<String>,
    /// 已匹配的角色列表（decision-trace feature 启用时填充）。
    #[serde(default)]
    pub matched_roles: Vec<String>,
    /// trace ID（decision-trace feature 启用时填充）。
    ///
    /// `Option<T>` 字段在 JSON 缺失时 serde 自动处理为 `None`。
    pub trace_id: Option<String>,
}

impl Decision {
    /// 创建一个允许决策（显式允许，无错误）。
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: DecisionReason::ExplicitAllow,
            errors: Vec::new(),
            checked_permissions: Vec::new(),
            matched_roles: Vec::new(),
            trace_id: None,
        }
    }

    /// 创建一个拒绝决策（无匹配权限，无错误）。
    pub fn deny(reason: DecisionReason) -> Self {
        Self {
            allowed: false,
            reason,
            errors: Vec::new(),
            checked_permissions: Vec::new(),
            matched_roles: Vec::new(),
            trace_id: None,
        }
    }
}

/// 鉴权请求输入（依据 spec decision-trace Requirement: AuthRequest）。
///
/// 封装一次鉴权请求的所有上下文，用于 `PermissionChecker::authorize` 方法。
///
/// # 序列化
///
/// `bulwark-testing` feature 启用时同时 derive `Serialize` 与 `Deserialize`，
/// 使声明式测试套件（`JsonTestCase`）可双向转换。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    /// 主体 login_id。
    pub login_id: String,
    /// 租户 ID（0 表示单租户/未隔离）。
    pub tenant_id: i64,
    /// 请求的权限/动作字符串（如 `"user:read"`）。
    pub action: String,
    /// 可选的资源标识（如 `"user:123"`），用于资源级权限校验。
    pub resource: Option<String>,
    /// 请求上下文（任意 JSON，用于扩展校验逻辑）。
    pub context: serde_json::Value,
}

impl AuthRequest {
    /// 创建一个新的鉴权请求（tenant_id=0，resource=None，context=Null）。
    pub fn new(login_id: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            login_id: login_id.into(),
            tenant_id: 0,
            action: action.into(),
            resource: None,
            context: serde_json::Value::Null,
        }
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BulwarkResult;

    /// T011: Decision 序列化为 JSON 含所有必需字段。
    ///
    /// 验证 `Decision { allowed, reason, errors, checked_permissions, matched_roles, trace_id }`
    /// 序列化后包含全部 6 个字段。
    #[test]
    fn decision_serializes_to_json_with_required_fields() {
        let decision = Decision {
            allowed: true,
            reason: DecisionReason::ExplicitAllow,
            errors: vec![],
            checked_permissions: vec!["user:read".to_string()],
            matched_roles: vec!["admin".to_string()],
            trace_id: Some("t-123".to_string()),
        };
        let json = serde_json::to_value(&decision).expect("serialize Decision");
        assert_eq!(json["allowed"], serde_json::json!(true));
        assert_eq!(json["reason"], serde_json::json!("explicit_allow"));
        assert!(json["errors"].is_array());
        assert_eq!(
            json["checked_permissions"][0],
            serde_json::json!("user:read")
        );
        assert_eq!(json["matched_roles"][0], serde_json::json!("admin"));
        assert_eq!(json["trace_id"], serde_json::json!("t-123"));
    }

    /// T011 补充：拒绝决策序列化 reason 为 NoMatchingPermission。
    #[test]
    fn decision_deny_serializes_reason_no_matching_permission() {
        let decision = Decision::deny(DecisionReason::NoMatchingPermission);
        let json = serde_json::to_value(&decision).expect("serialize Decision");
        assert_eq!(json["allowed"], serde_json::json!(false));
        assert_eq!(json["reason"], serde_json::json!("no_matching_permission"));
    }

    /// T011 补充：FirewallBlocked 变体序列化为 { FirewallBlocked: "..." }。
    #[test]
    fn decision_reason_firewall_blocked_serializes_with_message() {
        let reason = DecisionReason::FirewallBlocked("ip blocked".to_string());
        let json = serde_json::to_value(&reason).expect("serialize DecisionReason");
        assert_eq!(
            json,
            serde_json::json!({ "firewall_blocked": "ip blocked" })
        );
    }

    /// T011 补充：allow() 构造器创建 ExplicitAllow 决策。
    #[test]
    fn decision_allow_constructor_creates_explicit_allow() {
        let decision = Decision::allow();
        assert!(decision.allowed);
        assert_eq!(decision.reason, DecisionReason::ExplicitAllow);
        assert!(decision.errors.is_empty());
    }

    /// T013: AuthRequest 构造并字段可读。
    ///
    /// 验证 `AuthRequest { login_id, tenant_id, action, resource, context }` 编译通过且字段可读。
    #[test]
    fn auth_request_constructs_with_required_fields() {
        let req = AuthRequest {
            login_id: "1".to_string(),
            tenant_id: 0,
            action: "user:read".to_string(),
            resource: None,
            context: serde_json::Value::Null,
        };
        assert_eq!(req.login_id, "1");
        assert_eq!(req.tenant_id, 0);
        assert_eq!(req.action, "user:read");
        assert!(req.resource.is_none());
        assert!(req.context.is_null());
    }

    /// T013 补充：AuthRequest::new 构造器设置默认值。
    #[test]
    fn auth_request_new_sets_defaults() {
        let req = AuthRequest::new("1001", "user:write");
        assert_eq!(req.login_id, "1001");
        assert_eq!(req.tenant_id, 0);
        assert_eq!(req.action, "user:write");
        assert!(req.resource.is_none());
        assert!(req.context.is_null());
    }

    /// T013 补充：AuthRequest 可构造带 tenant_id 和 resource。
    #[test]
    fn auth_request_with_tenant_and_resource() {
        let req = AuthRequest {
            login_id: "1".to_string(),
            tenant_id: 42,
            action: "doc:read".to_string(),
            resource: Some("doc:99".to_string()),
            context: serde_json::json!({"ip": "10.0.0.1"}),
        };
        assert_eq!(req.tenant_id, 42);
        assert_eq!(req.resource.as_deref(), Some("doc:99"));
        assert_eq!(req.context["ip"], serde_json::json!("10.0.0.1"));
    }

    /// T013 补充：DecisionReason 全变体可序列化（覆盖枚举完整性）。
    #[test]
    fn all_decision_reason_variants_serialize() {
        let variants: &[DecisionReason] = &[
            DecisionReason::ExplicitAllow,
            DecisionReason::RoleInheritedAllow,
            DecisionReason::ExplicitDeny,
            DecisionReason::NoMatchingPermission,
            DecisionReason::NoMatchingRole,
            DecisionReason::FirewallBlocked("test".to_string()),
            DecisionReason::TokenInvalid,
            DecisionReason::TokenExpired,
            DecisionReason::TenantMismatch,
        ];
        for v in variants {
            let json = serde_json::to_string(v).expect("serialize variant");
            assert!(!json.is_empty(), "变体应序列化为非空 JSON: {:?}", v);
        }
    }

    /// T013 补充：BulwarkResult<Decision> 可用于 authorize 返回类型。
    #[test]
    fn bulwark_result_decision_compiles() {
        let ok: BulwarkResult<Decision> = Ok(Decision::allow());
        assert!(ok.is_ok());
        let err: BulwarkResult<Decision> = Err(crate::error::BulwarkError::NotLogin("x".into()));
        assert!(err.is_err());
    }

    // ========================================================================
    // T103: trace_id 自动生成测试（依据 design.md D11 D5）
    //
    // 启用 decision-trace feature 时，PermissionChecker::authorize 默认实现
    // 应自动生成 UUID v7（时间有序）作为 trace_id。
    // ========================================================================
    #[cfg(feature = "decision-trace")]
    mod trace_id_tests {
        use super::AuthRequest;
        use crate::core::permission::{PermissionChecker, PermissionCheckerDefault};
        use crate::error::BulwarkResult;
        use crate::stp::BulwarkInterface;
        use async_trait::async_trait;
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Duration;
        use uuid::Uuid;

        /// 最小化 mock BulwarkInterface：仅返回固定权限列表。
        struct MockInterface {
            permissions: HashMap<String, Vec<String>>,
        }

        #[async_trait]
        impl BulwarkInterface for MockInterface {
            async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
                Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
            }

            async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
                Ok(Vec::new())
            }
        }

        /// 构造一个 PermissionCheckerDefault（账号 1001 持有 user:read 权限）。
        fn make_checker() -> PermissionCheckerDefault {
            let mut perms = HashMap::new();
            perms.insert("1001".to_string(), vec!["user:read".to_string()]);
            let interface = MockInterface { permissions: perms };
            let interface_arc: Arc<dyn BulwarkInterface> = Arc::new(interface);
            PermissionCheckerDefault::new(interface_arc)
        }

        /// T103: 启用 decision-trace 时 authorize 生成的 trace_id 是合法 UUID v7。
        ///
        /// 验证 `Decision.trace_id` 为 `Some`，且解析后 version_num == 7（UUID v7，时间有序）。
        #[tokio::test]
        async fn authorize_generates_trace_id_when_decision_trace_enabled() {
            let checker = make_checker();
            let request = AuthRequest::new("1001", "user:read");
            let decision = PermissionChecker::authorize(&checker, &request)
                .await
                .expect("authorize ok");
            let trace_id = decision
                .trace_id
                .expect("decision-trace 启用时 trace_id 应为 Some");
            let parsed = Uuid::parse_str(&trace_id)
                .unwrap_or_else(|err| panic!("trace_id 不是合法 UUID: {trace_id} (err: {err})"));
            assert_eq!(
                parsed.get_version_num(),
                7,
                "trace_id 应为 UUID v7（时间有序），实际: {trace_id}"
            );
        }

        /// T103: 多次调用 authorize 生成不同的 trace_id。
        ///
        /// 验证连续 3 次 authorize 调用生成的 trace_id 互不相同（UUID v7 随机部分保证唯一性）。
        #[tokio::test]
        async fn authorize_trace_id_is_unique_per_request() {
            let checker = make_checker();
            let request = AuthRequest::new("1001", "user:read");
            let d1 = PermissionChecker::authorize(&checker, &request)
                .await
                .expect("authorize 1");
            let d2 = PermissionChecker::authorize(&checker, &request)
                .await
                .expect("authorize 2");
            let d3 = PermissionChecker::authorize(&checker, &request)
                .await
                .expect("authorize 3");
            let t1 = d1.trace_id.as_deref().expect("trace_id 1");
            let t2 = d2.trace_id.as_deref().expect("trace_id 2");
            let t3 = d3.trace_id.as_deref().expect("trace_id 3");
            assert_ne!(t1, t2, "trace_id 1 与 2 不应相同");
            assert_ne!(t2, t3, "trace_id 2 与 3 不应相同");
            assert_ne!(t1, t3, "trace_id 1 与 3 不应相同");
        }

        /// T103: 连续生成的 trace_id 字典序递增（UUID v7 时间有序特性）。
        ///
        /// UUID v7 前 48 bits 为 unix_ts_ms（毫秒时间戳），跨毫秒时字典序严格递增。
        /// 测试中显式 sleep 2ms 保证跨毫秒，避免同毫秒内随机部分导致字典序不稳定。
        #[tokio::test]
        async fn authorize_trace_id_is_time_ordered() {
            let checker = make_checker();
            let request = AuthRequest::new("1001", "user:read");
            let d1 = PermissionChecker::authorize(&checker, &request)
                .await
                .expect("authorize 1");
            tokio::time::sleep(Duration::from_millis(2)).await;
            let d2 = PermissionChecker::authorize(&checker, &request)
                .await
                .expect("authorize 2");
            let t1 = d1.trace_id.as_deref().expect("trace_id 1");
            let t2 = d2.trace_id.as_deref().expect("trace_id 2");
            assert!(
                t1 < t2,
                "UUID v7 应时间有序（字典序递增）：t1={t1}, t2={t2}"
            );
        }
    }
}
