//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! AbacEngine — Cedar 策略求值器实现。
//!
//! 基于 `cedar-policy` crate，提供 principal-action-resource 三元组策略求值。
//! 策略集使用 `Arc<RwLock<PolicySet>>` 支持读写分离热加载。

use crate::core::permission::{Decision, DecisionReason};
use crate::error::{BulwarkError, BulwarkResult};
use cedar_policy::{
    Authorizer, Context, Entities, EntityUid, Policy, PolicyId, PolicySet, Request, Schema,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// ABAC 策略求值器，基于 Cedar 策略语言。
///
/// 提供 principal-action-resource 三元组策略求值，支持策略的热加载。
/// ABAC 作为 RBAC 的增量校验层，不替换 RBAC。RBAC 通过后再检查 ABAC。
///
/// # 设计
///
/// - `authorizer`：Cedar 授权器（无状态，可共享）
/// - `policies`：策略集（`Arc<RwLock<PolicySet>>` 支持读写分离热加载）
/// - `schema`：Cedar schema（定义实体类型、属性、动作）
///
/// # 线程安全
///
/// `AbacEngine` 内部使用 `Arc<RwLock<PolicySet>>`，可安全共享。
/// 求值时获取读锁，热加载时获取写锁，互不阻塞。
pub struct AbacEngine {
    /// Cedar 授权器（无状态）。
    authorizer: Authorizer,
    /// 策略集（RwLock 支持热加载时读写分离）。
    policies: Arc<RwLock<PolicySet>>,
    /// Cedar schema（定义实体类型、属性、动作）。
    schema: Schema,
}

impl AbacEngine {
    /// 从 JSON schema 创建 AbacEngine。
    ///
    /// # 参数
    /// - `schema_json`：Cedar schema JSON 字符串
    ///
    /// # 错误
    /// - schema JSON 解析失败：`BulwarkError::InvalidParam`
    pub fn new(schema_json: &str) -> BulwarkResult<Self> {
        let schema = Schema::from_json_str(schema_json)
            .map_err(|e| BulwarkError::InvalidParam(format!("Cedar schema 解析失败: {e}")))?;
        Ok(Self {
            authorizer: Authorizer::new(),
            policies: Arc::new(RwLock::new(PolicySet::new())),
            schema,
        })
    }

    /// 求值策略。
    ///
    /// # 参数
    /// - `principal`：主体 EntityUid 字符串（如 `User::"alice"`）
    /// - `action`：动作 EntityUid 字符串（如 `Action::"access"`）
    /// - `resource`：资源 EntityUid 字符串（如 `Resource::"doc1"`）
    /// - `context_json`：可选的上下文 JSON 字符串
    ///
    /// # 返回
    /// - `Decision::allow()`：Cedar 允许
    /// - `Decision::deny(...)`：Cedar 拒绝（默认拒绝或显式 forbid）
    ///
    /// # 错误
    /// - EntityUid 解析失败：`BulwarkError::InvalidParam`
    /// - Context 解析失败：`BulwarkError::InvalidParam`
    /// - Request 构造失败：`BulwarkError::InvalidParam`
    pub async fn evaluate(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context_json: Option<&str>,
    ) -> BulwarkResult<Decision> {
        let principal_uid: EntityUid = principal
            .parse()
            .map_err(|e| BulwarkError::InvalidParam(format!("principal 解析失败: {e}")))?;
        let action_uid: EntityUid = action
            .parse()
            .map_err(|e| BulwarkError::InvalidParam(format!("action 解析失败: {e}")))?;
        let resource_uid: EntityUid = resource
            .parse()
            .map_err(|e| BulwarkError::InvalidParam(format!("resource 解析失败: {e}")))?;
        let context = match context_json {
            Some(json) => Context::from_json_str(json, Some((&self.schema, &action_uid)))
                .map_err(|e| BulwarkError::InvalidParam(format!("context 解析失败: {e}")))?,
            None => Context::empty(),
        };
        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            context,
            Some(&self.schema),
        )
        .map_err(|e| BulwarkError::InvalidParam(format!("Cedar Request 构造失败: {e}")))?;
        let policies = self.policies.read().await;
        let entities = Entities::empty();
        let response = self
            .authorizer
            .is_authorized(&request, &policies, &entities);
        match response.decision() {
            cedar_policy::Decision::Allow => Ok(Decision::allow()),
            cedar_policy::Decision::Deny => {
                Ok(Decision::deny(DecisionReason::NoMatchingPermission))
            },
        }
    }

    /// 加载策略。
    ///
    /// # 参数
    /// - `policy_id`：策略 ID（用于卸载）
    /// - `policy_src`：Cedar DSL 策略文本
    ///
    /// # 错误
    /// - 策略语法错误：`BulwarkError::InvalidParam`
    /// - 策略 ID 冲突：`BulwarkError::InvalidParam`
    pub async fn load_policy(&self, policy_id: &str, policy_src: &str) -> BulwarkResult<()> {
        let policy = Policy::parse(Some(PolicyId::new(policy_id)), policy_src)
            .map_err(|e| BulwarkError::InvalidParam(format!("Cedar 策略解析失败: {e}")))?;
        let mut policies = self.policies.write().await;
        policies
            .add(policy)
            .map_err(|e| BulwarkError::InvalidParam(format!("Cedar 策略添加失败: {e}")))?;
        Ok(())
    }

    /// 卸载策略。
    ///
    /// # 参数
    /// - `policy_id`：策略 ID
    ///
    /// # 错误
    /// - 策略不存在：`BulwarkError::InvalidParam`
    pub async fn unload_policy(&self, policy_id: &str) -> BulwarkResult<()> {
        let policy_id = PolicyId::new(policy_id);
        let mut policies = self.policies.write().await;
        policies
            .remove_static(policy_id)
            .map_err(|e| BulwarkError::InvalidParam(format!("Cedar 策略删除失败: {e}")))?;
        Ok(())
    }

    /// 原子替换全部策略。
    ///
    /// 先解析所有策略，全部成功后原子替换 PolicySet。
    /// 任一策略语法错误则不替换，保持现有策略集不变。
    ///
    /// # 参数
    /// - `policies`：策略 ID → 策略文本的映射
    ///
    /// # 错误
    /// - 任一策略语法错误：`BulwarkError::InvalidParam`（不部分加载）
    pub async fn reload_all(&self, policies: HashMap<String, String>) -> BulwarkResult<()> {
        let mut new_set = PolicySet::new();
        for (id, src) in &policies {
            let policy = Policy::parse(Some(PolicyId::new(id)), src).map_err(|e| {
                BulwarkError::InvalidParam(format!("Cedar 策略 {id} 解析失败: {e}"))
            })?;
            new_set.add(policy).map_err(|e| {
                BulwarkError::InvalidParam(format!("Cedar 策略 {id} 添加失败: {e}"))
            })?;
        }
        let mut guard = self.policies.write().await;
        *guard = new_set;
        Ok(())
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用 Cedar schema JSON（空 namespace，EntityUid 直接用 `User::"alice"` 格式）。
    ///
    /// 定义 User 和 Resource 实体类型，以及 access 动作。
    const SCHEMA_JSON: &str = r#"{
        "": {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "department": { "type": "String" }
                        }
                    }
                },
                "Resource": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "owner": { "type": "String" }
                        }
                    }
                }
            },
            "actions": {
                "access": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Resource"]
                    }
                }
            }
        }
    }"#;

    /// T121: AbacEngine::new 从 JSON schema 初始化成功。
    #[test]
    fn t121_new_from_json_schema_success() {
        let engine = AbacEngine::new(SCHEMA_JSON);
        assert!(engine.is_ok(), "AbacEngine::new 应成功: {:?}", engine.err());
    }

    /// T121: 无效 JSON schema 返回 InvalidParam。
    #[test]
    fn t121_new_invalid_schema_returns_invalid_param() {
        let result = AbacEngine::new("not a valid json");
        assert!(result.is_err());
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "应为 InvalidParam"
        );
    }

    /// T123: evaluate — 匹配 permit 策略时返回 Allow。
    #[tokio::test]
    async fn t123_evaluate_permit_returns_allow() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy(
                "p1",
                r#"permit(principal == User::"alice", action == Action::"access", resource);"#,
            )
            .await
            .expect("load policy");
        let decision = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(decision.allowed, "alice 应被允许");
        assert_eq!(decision.reason, DecisionReason::ExplicitAllow);
    }

    /// T123: evaluate — 不匹配 permit 策略时返回 Deny（默认拒绝）。
    #[tokio::test]
    async fn t123_evaluate_no_match_returns_deny() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy(
                "p1",
                r#"permit(principal == User::"alice", action == Action::"access", resource);"#,
            )
            .await
            .expect("load policy");
        let decision = engine
            .evaluate(
                r#"User::"bob""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(!decision.allowed, "bob 应被拒绝");
        assert_eq!(decision.reason, DecisionReason::NoMatchingPermission);
    }

    /// T123: evaluate — 无策略时默认 Deny。
    #[tokio::test]
    async fn t123_evaluate_no_policies_returns_deny() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        let decision = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(!decision.allowed, "无策略时应默认拒绝");
    }

    /// T123: evaluate — 无效 principal 格式返回 InvalidParam。
    #[tokio::test]
    async fn t123_evaluate_invalid_principal_returns_error() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        let result = engine
            .evaluate(
                "invalid",
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "应为 InvalidParam"
        );
    }

    /// T125: Decision 映射 — Cedar Allow → Decision::allow()。
    #[tokio::test]
    async fn t125_decision_mapping_allow() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load policy");
        let decision = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(decision.allowed);
        assert_eq!(decision.reason, DecisionReason::ExplicitAllow);
    }

    /// T125: Decision 映射 — Cedar Deny → Decision::deny()。
    #[tokio::test]
    async fn t125_decision_mapping_deny() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        // 空策略集，默认 Deny
        let decision = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::NoMatchingPermission);
    }

    /// T125: forbid 策略覆盖 permit — Cedar 语义验证。
    #[tokio::test]
    async fn t125_forbid_overrides_permit() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load permit");
        engine
            .load_policy(
                "p2",
                r#"forbid(principal == User::"alice", action, resource);"#,
            )
            .await
            .expect("load forbid");
        let decision = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(!decision.allowed, "forbid 应覆盖 permit");
    }

    /// T125: evaluate 带 context JSON 不报错。
    #[tokio::test]
    async fn t125_evaluate_with_context() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load policy");
        let decision = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                Some(r#"{}"#),
            )
            .await
            .expect("evaluate");
        assert!(decision.allowed);
    }

    /// 策略语法错误返回 InvalidParam。
    #[tokio::test]
    async fn load_policy_syntax_error_returns_invalid_param() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        let result = engine
            .load_policy("p1", "this is not a valid cedar policy")
            .await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "应为 InvalidParam"
        );
    }

    /// unload_policy 删除策略后求值变化。
    #[tokio::test]
    async fn unload_policy_changes_decision() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");
        let before = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(before.allowed, "卸载前应允许");
        engine.unload_policy("p1").await.expect("unload");
        let after = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(!after.allowed, "卸载后应拒绝");
    }

    /// reload_all 原子替换全部策略。
    #[tokio::test]
    async fn reload_all_atomically_replaces_policies() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");
        let mut new_policies = HashMap::new();
        new_policies.insert(
            "p2".to_string(),
            r#"permit(principal == User::"bob", action, resource);"#.to_string(),
        );
        engine.reload_all(new_policies).await.expect("reload");
        // p1 已被替换，alice 不再匹配
        let alice = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(!alice.allowed, "alice 应被拒绝（p1 已被替换）");
        // p2 匹配 bob
        let bob = engine
            .evaluate(
                r#"User::"bob""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(bob.allowed, "bob 应被允许（p2 匹配）");
    }

    /// reload_all 任一策略语法错误时不替换（原子性）。
    #[tokio::test]
    async fn reload_all_syntax_error_keeps_existing() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");
        let mut bad_policies = HashMap::new();
        bad_policies.insert("p2".to_string(), "invalid policy".to_string());
        let result = engine.reload_all(bad_policies).await;
        assert!(result.is_err(), "reload_all 应失败");
        // 现有策略 p1 仍应有效
        let decision = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(decision.allowed, "现有策略应保持不变");
    }

    /// 并发求值不阻塞（RwLock 读写分离验证）。
    #[tokio::test]
    async fn concurrent_evaluate_does_not_block() {
        let engine = Arc::new(AbacEngine::new(SCHEMA_JSON).expect("schema valid"));
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");
        // 并发 10 个求值
        let mut handles = Vec::new();
        for i in 0..10 {
            let e = engine.clone();
            handles.push(tokio::spawn(async move {
                e.evaluate(
                    r#"User::"alice""#,
                    r#"Action::"access""#,
                    &format!(r#"Resource::"doc{i}""#),
                    None,
                )
                .await
                .expect("evaluate")
            }));
        }
        for handle in handles {
            let decision = handle.await.expect("task complete");
            assert!(decision.allowed, "并发求值应全部允许");
        }
    }
}
