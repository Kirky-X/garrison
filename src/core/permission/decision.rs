// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 鉴权决策与请求模型：提供决策溯源所需的数据结构——[`Decision`]（结果，含
//! allowed/reason/errors/trace）、[`DecisionReason`]（原因枚举）、[`AuthRequest`]（请求输入）。
//!
//! `Decision.errors` 用 `Vec<String>` 而非 `Vec<GarrisonError>`：后者未 derive `Serialize`
//! （加 derive 会触碰大量代码），且溯源只需 `err.to_string()` 的可读消息。

use serde::{Deserialize, Serialize};

/// 鉴权决策原因（决策的"为什么"，用于 trace 与审计）；derive `Deserialize` 使 [`Decision`]
/// 可在 `garrison-testing` 下从 JSON 反序列化（声明式测试套件用）。
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
    /// 强制拒绝（forbid 优先，不可被 Allow 覆盖；`core-advanced` feature）：组合时优先级最高，
    /// 任一 Forbid 决策存在即最终 Forbid。
    #[cfg(feature = "core-advanced")]
    Forbid(String),
    /// 策略引擎求值故障（fail-closed 拒绝）：区别于 [`DecisionReason::ExplicitDeny`]（业务显式
    /// 拒绝），本变体意味着决策过程不可信（如 Cedar schema / 类型 / 运行时错误），按最小权限
    /// 原则拒绝；调用方应同时关注引擎侧 `error` 级日志。
    EvaluationError,
}

/// 鉴权决策结果：决策本身（allowed/reason）+ 溯源信息（errors/checked_permissions/
/// matched_roles/trace_id）。`Serialize` 可输出 JSON 审计日志；`garrison-testing` 下同时实现
/// `Deserialize`，声明式测试套件可从 JSON 反序列化期望决策（`JsonTestCase::expected`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    /// 是否允许。
    pub allowed: bool,
    /// 决策原因。
    pub reason: DecisionReason,
    /// 校验过程中收集的错误消息（`err.to_string()`），用于 trace；反序列化缺失时默认空 vec。
    #[serde(default)]
    pub errors: Vec<String>,
    /// 已校验的权限列表（decision-trace feature 启用时填充）。
    #[serde(default)]
    pub checked_permissions: Vec<String>,
    /// 已匹配的角色列表（decision-trace feature 启用时填充）。
    #[serde(default)]
    pub matched_roles: Vec<String>,
    /// trace ID（decision-trace feature 启用时填充）；JSON 缺失时 serde 处理为 `None`。
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

    /// 创建 Forbid 决策（`allowed: false`，组合时优先级最高；`core-advanced` feature）。
    #[cfg(feature = "core-advanced")]
    pub fn forbid(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: DecisionReason::Forbid(reason.into()),
            errors: Vec::new(),
            checked_permissions: Vec::new(),
            matched_roles: Vec::new(),
            trace_id: None,
        }
    }

    /// 判断是否为 Forbid 决策（`core-advanced` feature）。
    #[cfg(feature = "core-advanced")]
    pub fn is_forbid(&self) -> bool {
        matches!(self.reason, DecisionReason::Forbid(_))
    }
}

/// 鉴权请求输入（`PermissionChecker::authorize` 的入参）；`garrison-testing` 下
/// `Serialize` / `Deserialize` 双向可用（声明式测试套件 `JsonTestCase`）。
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
    /// 请求上下文（任意 JSON，用于扩展校验逻辑）；安全提示：无大小 / 深度约束，若由外部输入
    /// 填充，调用方须先自行验证（建议上限 1MB / 深度 10 层），深层嵌套 JSON 可致内存耗尽。
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GarrisonResult;

    /// Decision 序列化为 JSON 含全部 6 个必需字段。
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

    /// 拒绝决策序列化 reason 为 NoMatchingPermission。
    #[test]
    fn decision_deny_serializes_reason_no_matching_permission() {
        let decision = Decision::deny(DecisionReason::NoMatchingPermission);
        let json = serde_json::to_value(&decision).expect("serialize Decision");
        assert_eq!(json["allowed"], serde_json::json!(false));
        assert_eq!(json["reason"], serde_json::json!("no_matching_permission"));
    }

    /// FirewallBlocked 变体序列化为 { FirewallBlocked: "..." }。
    #[test]
    fn decision_reason_firewall_blocked_serializes_with_message() {
        let reason = DecisionReason::FirewallBlocked("ip blocked".to_string());
        let json = serde_json::to_value(&reason).expect("serialize DecisionReason");
        assert_eq!(
            json,
            serde_json::json!({ "firewall_blocked": "ip blocked" })
        );
    }

    /// allow() 构造器创建 ExplicitAllow 决策。
    #[test]
    fn decision_allow_constructor_creates_explicit_allow() {
        let decision = Decision::allow();
        assert!(decision.allowed);
        assert_eq!(decision.reason, DecisionReason::ExplicitAllow);
        assert!(decision.errors.is_empty());
    }

    /// AuthRequest 构造并字段可读（5 字段编译通过）。
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

    /// AuthRequest::new 构造器设置默认值。
    #[test]
    fn auth_request_new_sets_defaults() {
        let req = AuthRequest::new("1001", "user:write");
        assert_eq!(req.login_id, "1001");
        assert_eq!(req.tenant_id, 0);
        assert_eq!(req.action, "user:write");
        assert!(req.resource.is_none());
        assert!(req.context.is_null());
    }

    /// AuthRequest 可构造带 tenant_id 和 resource。
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

    /// DecisionReason 全变体可序列化（覆盖枚举完整性）。
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

    /// GarrisonResult<Decision> 可用于 authorize 返回类型。
    #[test]
    fn garrison_result_decision_compiles() {
        let ok: GarrisonResult<Decision> = Ok(Decision::allow());
        assert!(ok.is_ok());
        let err: GarrisonResult<Decision> = Err(crate::error::GarrisonError::NotLogin("x".into()));
        assert!(err.is_err());
    }

    // trace_id 自动生成测试：decision-trace 启用时 authorize 默认实现生成 UUID v7（时间有序）。
    #[cfg(feature = "core-advanced")]
    mod trace_id_tests {
        use super::AuthRequest;
        use crate::core::permission::{PermissionChecker, PermissionCheckerDefault};
        use crate::error::GarrisonResult;
        use crate::stp::GarrisonInterface;
        use async_trait::async_trait;
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Duration;
        use uuid::Uuid;

        /// 最小化 mock GarrisonInterface：仅返回固定权限列表。
        struct MockInterface {
            permissions: HashMap<String, Vec<String>>,
        }

        #[async_trait]
        impl GarrisonInterface for MockInterface {
            async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
            }

            async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(Vec::new())
            }
        }

        /// 构造一个 PermissionCheckerDefault（账号 1001 持有 user:read 权限）。
        fn make_checker() -> PermissionCheckerDefault {
            let mut perms = HashMap::new();
            perms.insert("1001".to_string(), vec!["user:read".to_string()]);
            let interface = MockInterface { permissions: perms };
            let interface_arc: Arc<dyn GarrisonInterface> = Arc::new(interface);
            PermissionCheckerDefault::new(interface_arc)
        }

        /// decision-trace 启用时 authorize 生成合法 UUID v7 trace_id（version_num == 7，时间有序）。
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

        /// 连续 3 次 authorize 的 trace_id 互不相同（UUID v7 随机部分保证唯一性）。
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

        /// 连续 trace_id 字典序递增（UUID v7 前 48 bits 为毫秒时间戳）；sleep 2ms 保证跨毫秒，
        /// 避免同毫秒随机部分导致字典序不稳。
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

    // Forbid 优先语义测试（core-advanced feature：Forbid 变体 + forbid() / is_forbid()）。
    #[cfg(feature = "core-advanced")]
    mod safe_defaults_tests {
        use super::*;

        /// forbid() 创建 `allowed == false` + `Forbid("test")` reason 的决策。
        #[test]
        fn forbid_constructor_creates_forbid_decision() {
            let decision = Decision::forbid("test");
            assert!(!decision.allowed, "forbid 决策 allowed 应为 false");
            assert_eq!(
                decision.reason,
                DecisionReason::Forbid("test".to_string()),
                "forbid 决策 reason 应为 Forbid(\"test\")"
            );
        }

        /// is_forbid() 对 Forbid 决策返回 true。
        #[test]
        fn is_forbid_returns_true_for_forbid() {
            let decision = Decision::forbid("test");
            assert!(
                decision.is_forbid(),
                "Forbid 决策的 is_forbid() 应返回 true"
            );
        }

        /// is_forbid() 对 Allow 决策返回 false。
        #[test]
        fn is_forbid_returns_false_for_allow() {
            let decision = Decision::allow();
            assert!(
                !decision.is_forbid(),
                "Allow 决策的 is_forbid() 应返回 false"
            );
        }

        /// is_forbid() 对 Deny 决策返回 false。
        #[test]
        fn is_forbid_returns_false_for_deny() {
            let decision = Decision::deny(DecisionReason::NoMatchingPermission);
            assert!(
                !decision.is_forbid(),
                "Deny 决策的 is_forbid() 应返回 false"
            );
        }

        /// Forbid 变体序列化为 { "forbid": "test" }（serde rename_all = "snake_case"）。
        #[test]
        fn forbid_serializes_to_json() {
            let reason = DecisionReason::Forbid("test".to_string());
            let json = serde_json::to_value(&reason).expect("serialize Forbid");
            assert_eq!(
                json,
                serde_json::json!({ "forbid": "test" }),
                "Forbid(\"test\") 应序列化为 {{ \"forbid\": \"test\" }}"
            );
        }

        /// { "forbid": "test" } 反序列化为 Forbid("test")。
        #[test]
        fn forbid_deserializes_from_json() {
            let json = serde_json::json!({ "forbid": "test" });
            let reason: DecisionReason = serde_json::from_value(json).expect("deserialize Forbid");
            assert_eq!(
                reason,
                DecisionReason::Forbid("test".to_string()),
                "{{ \"forbid\": \"test\" }} 应反序列化为 Forbid(\"test\")"
            );
        }

        /// Forbid 变体支持 PartialEq 比较。
        #[test]
        fn forbid_partial_eq() {
            let a = DecisionReason::Forbid("a".to_string());
            let b = DecisionReason::Forbid("a".to_string());
            assert_eq!(a, b, "Forbid(\"a\") == Forbid(\"a\") 应为 true");
        }

        /// allow()/deny() 行为不因 safe-defaults feature 改变。
        #[test]
        fn existing_allow_deny_unchanged() {
            let allow = Decision::allow();
            assert!(allow.allowed, "allow() 的 allowed 应为 true");
            assert_eq!(
                allow.reason,
                DecisionReason::ExplicitAllow,
                "allow() 的 reason 应为 ExplicitAllow"
            );

            let deny = Decision::deny(DecisionReason::NoMatchingPermission);
            assert!(!deny.allowed, "deny() 的 allowed 应为 false");
            assert_eq!(
                deny.reason,
                DecisionReason::NoMatchingPermission,
                "deny() 的 reason 应为传入的 reason"
            );
        }
    }
}
