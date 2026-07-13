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
use moka::sync::Cache;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// ABAC 决策缓存 key：(principal, action, resource) 三元组。
///
/// # 设计权衡
///
/// `context_json` 不参与缓存 key。原因：
/// - 任务规格 T016 明确 `key = (principal, action, resource)`
/// - ABAC 策略热加载时通过 `invalidate_all()` 清空缓存，保证策略变更后决策一致
/// - 调用方若需 context 敏感的求值，应使用 `evaluate_with_temp_policy`（不走缓存）
type DecisionKey = (String, String, String);

/// ABAC 决策缓存 TTL（秒）。
const DECISION_CACHE_TTL_SECS: u64 = 60;

/// ABAC 决策缓存最大容量。
const DECISION_CACHE_MAX_CAPACITY: u64 = 10_000;

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
/// - `cache`：决策缓存（moka TTL 60s, max 10000），key 为 (principal, action, resource)
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
    /// 决策缓存（moka sync::Cache，TTL 60s, max 10000）。
    ///
    /// 策略热加载（load/unload/reload_all 成功）时调用 `invalidate_all()` 清空。
    cache: Cache<DecisionKey, Decision>,
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
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(DECISION_CACHE_TTL_SECS))
            .max_capacity(DECISION_CACHE_MAX_CAPACITY)
            .build();
        Ok(Self {
            authorizer: Authorizer::new(),
            policies: Arc::new(RwLock::new(PolicySet::new())),
            schema,
            cache,
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
        // 缓存查询：命中则直接返回（不调用 Cedar）
        let cache_key: DecisionKey = (
            principal.to_string(),
            action.to_string(),
            resource.to_string(),
        );
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(cached);
        }

        // 缓存未命中，调用 Cedar 求值
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
        let decision = match response.decision() {
            cedar_policy::Decision::Allow => Decision::allow(),
            cedar_policy::Decision::Deny => Decision::deny(DecisionReason::NoMatchingPermission),
        };

        // 写入缓存（仅在求值成功后）
        self.cache.insert(cache_key, decision.clone());

        Ok(decision)
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
        // 策略变更后清空决策缓存（新策略可能改变现有 key 的决策）
        self.cache.invalidate_all();
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
        // 策略变更后清空决策缓存（移除策略可能改变现有 key 的决策）
        self.cache.invalidate_all();
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
        // 策略集原子替换后清空决策缓存（新策略集可能改变现有 key 的决策）
        // 仅在替换成功后执行；任一策略解析失败时提前 return Err，不会到达此处
        self.cache.invalidate_all();
        Ok(())
    }

    /// 使用临时策略求值（不修改共享策略集）。
    ///
    /// 供 `check_abac_with_policy` 调用：宏生成的 Cedar 条件表达式包装为完整策略后，
    /// 通过本方法求值，避免临时策略污染全局策略集。
    ///
    /// 临时策略独立求值，不与 `load_policy` 加载的共享策略合并。
    ///
    /// # 参数
    /// - `principal`：主体 EntityUid 字符串
    /// - `action`：动作 EntityUid 字符串
    /// - `resource`：资源 EntityUid 字符串
    /// - `context_json`：可选的上下文 JSON
    /// - `temp_policy_src`：临时 Cedar 策略文本
    ///
    /// # 错误
    /// - EntityUid/Context/Request 解析失败：`BulwarkError::InvalidParam`
    /// - 临时策略语法错误：`BulwarkError::InvalidParam`
    pub async fn evaluate_with_temp_policy(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context_json: Option<&str>,
        temp_policy_src: &str,
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
        let temp_policy = Policy::parse(None, temp_policy_src)
            .map_err(|e| BulwarkError::InvalidParam(format!("临时 Cedar 策略解析失败: {e}")))?;
        let mut temp_set = PolicySet::new();
        temp_set
            .add(temp_policy)
            .map_err(|e| BulwarkError::InvalidParam(format!("临时 Cedar 策略添加失败: {e}")))?;
        let entities = Entities::empty();
        let response = self
            .authorizer
            .is_authorized(&request, &temp_set, &entities);
        match response.decision() {
            cedar_policy::Decision::Allow => Ok(Decision::allow()),
            cedar_policy::Decision::Deny => {
                Ok(Decision::deny(DecisionReason::NoMatchingPermission))
            },
        }
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

    // ============================================================
    // evaluate_with_temp_policy 测试（T138/T139）
    // ============================================================

    /// T139: evaluate_with_temp_policy — 匹配的临时策略返回 Allow。
    #[tokio::test]
    async fn t139_evaluate_with_temp_policy_permit_returns_allow() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        let temp_policy = r#"permit(principal, action == Action::"access", resource);"#;
        let decision = engine
            .evaluate_with_temp_policy(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
                temp_policy,
            )
            .await
            .expect("evaluate temp policy");
        assert!(decision.allowed, "匹配的临时策略应 Allow");
    }

    /// T139: evaluate_with_temp_policy — 不匹配的临时策略返回 Deny。
    #[tokio::test]
    async fn t139_evaluate_with_temp_policy_no_match_returns_deny() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        let temp_policy =
            r#"permit(principal == User::"bob", action == Action::"access", resource);"#;
        let decision = engine
            .evaluate_with_temp_policy(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
                temp_policy,
            )
            .await
            .expect("evaluate temp policy");
        assert!(!decision.allowed, "不匹配的临时策略应 Deny");
    }

    /// T139: evaluate_with_temp_policy — 无效策略返回 InvalidParam。
    #[tokio::test]
    async fn t139_evaluate_with_temp_policy_invalid_returns_error() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        let result = engine
            .evaluate_with_temp_policy(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
                "not a valid cedar policy",
            )
            .await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "应为 InvalidParam"
        );
    }

    /// T139: evaluate_with_temp_policy — 不修改共享策略集。
    #[tokio::test]
    async fn t139_evaluate_with_temp_policy_does_not_modify_shared() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        // 共享策略集初始为空
        let before = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(!before.allowed, "共享策略集为空时应 Deny");

        // 临时策略求值
        let temp_policy = r#"permit(principal, action == Action::"access", resource);"#;
        let temp_decision = engine
            .evaluate_with_temp_policy(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
                temp_policy,
            )
            .await
            .expect("evaluate temp");
        assert!(temp_decision.allowed, "临时策略应 Allow");

        // 共享策略集仍为空
        let after = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(!after.allowed, "临时策略求值后共享策略集应仍为空（Deny）");
    }

    /// T139: evaluate_with_temp_policy — 带 when 条件的策略。
    #[tokio::test]
    async fn t139_evaluate_with_temp_policy_when_condition() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        // when 条件为 true（1 == 1）→ Allow
        let temp_policy_true =
            r#"permit(principal, action == Action::"access", resource) when { 1 == 1 };"#;
        let decision_true = engine
            .evaluate_with_temp_policy(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
                temp_policy_true,
            )
            .await
            .expect("evaluate");
        assert!(decision_true.allowed, "when {{ 1 == 1 }} 应 Allow");

        // when 条件为 false（1 == 2）→ Deny
        let temp_policy_false =
            r#"permit(principal, action == Action::"access", resource) when { 1 == 2 };"#;
        let decision_false = engine
            .evaluate_with_temp_policy(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
                temp_policy_false,
            )
            .await
            .expect("evaluate");
        assert!(!decision_false.allowed, "when {{ 1 == 2 }} 应 Deny");
    }

    // ============================================================
    // T016: ABAC 决策缓存 moka TTL 60s 测试
    // ============================================================

    /// T016: 同 key 两次 evaluate，第二次命中缓存（entry_count == 1）。
    #[tokio::test]
    async fn t016_cache_hit_on_second_evaluate_same_key() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");

        let principal = r#"User::"alice""#;
        let action = r#"Action::"access""#;
        let resource = r#"Resource::"doc1""#;

        let d1 = engine
            .evaluate(principal, action, resource, None)
            .await
            .expect("evaluate 1");
        engine.cache.run_pending_tasks();
        assert_eq!(engine.cache.entry_count(), 1, "首次求值后缓存应有 1 条");

        let d2 = engine
            .evaluate(principal, action, resource, None)
            .await
            .expect("evaluate 2");
        engine.cache.run_pending_tasks();
        assert_eq!(
            engine.cache.entry_count(),
            1,
            "第二次求值命中缓存，缓存仍为 1 条"
        );
        assert_eq!(d1.allowed, d2.allowed, "两次求值结果应一致");
    }

    /// T016: 不同 key 两次 evaluate，缓存各存一条（entry_count == 2）。
    #[tokio::test]
    async fn t016_cache_miss_on_different_keys() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");

        engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate 1");
        engine
            .evaluate(
                r#"User::"bob""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate 2");
        engine.cache.run_pending_tasks();
        assert_eq!(engine.cache.entry_count(), 2, "不同 key 应缓存 2 条");
    }

    /// T016: unload_policy 后缓存失效（entry_count == 0）。
    #[tokio::test]
    async fn t016_cache_invalidated_on_unload_policy() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");

        engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        engine.cache.run_pending_tasks();
        assert_eq!(engine.cache.entry_count(), 1, "求值后应有缓存");

        engine.unload_policy("p1").await.expect("unload");
        engine.cache.run_pending_tasks();
        assert_eq!(engine.cache.entry_count(), 0, "unload 后缓存应清空");

        // 再次求值，应重新调用 Cedar（结果变为 Deny）
        let after = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate after");
        assert!(!after.allowed, "unload 后应 Deny");
    }

    /// T016: reload_all 成功后缓存失效（entry_count == 0）。
    #[tokio::test]
    async fn t016_cache_invalidated_on_reload_all() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");

        engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        engine.cache.run_pending_tasks();
        assert_eq!(engine.cache.entry_count(), 1);

        let mut new_policies = HashMap::new();
        new_policies.insert(
            "p2".to_string(),
            r#"permit(principal == User::"bob", action, resource);"#.to_string(),
        );
        engine.reload_all(new_policies).await.expect("reload");
        engine.cache.run_pending_tasks();
        assert_eq!(engine.cache.entry_count(), 0, "reload 后缓存应清空");

        // alice 应被拒绝（p1 已替换为 p2）
        let alice = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(!alice.allowed, "alice 应被拒绝");
    }

    /// T016: reload_all 失败时缓存保持不变（不失效）。
    #[tokio::test]
    async fn t016_cache_kept_on_reload_all_failure() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");

        engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        engine.cache.run_pending_tasks();
        assert_eq!(engine.cache.entry_count(), 1);

        let mut bad_policies = HashMap::new();
        bad_policies.insert("p2".to_string(), "invalid policy".to_string());
        let result = engine.reload_all(bad_policies).await;
        assert!(result.is_err(), "reload_all 应失败");
        engine.cache.run_pending_tasks();
        assert_eq!(engine.cache.entry_count(), 1, "reload 失败时缓存应保持不变");

        // alice 仍应被允许（缓存命中）
        let alice = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(alice.allowed, "reload 失败后 alice 应仍被允许（缓存命中）");
    }

    /// T016: load_policy 后缓存失效（新策略可能改变现有 key 的决策）。
    #[tokio::test]
    async fn t016_cache_invalidated_on_load_policy() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");

        // 初始无策略，evaluate 返回 Deny
        let before = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(!before.allowed, "无策略时应 Deny");
        engine.cache.run_pending_tasks();
        assert_eq!(engine.cache.entry_count(), 1);

        // load_policy 后缓存失效
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");
        engine.cache.run_pending_tasks();
        assert_eq!(engine.cache.entry_count(), 0, "load 后缓存应清空");

        // 再次 evaluate 应返回 Allow（重新调用 Cedar）
        let after = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(after.allowed, "load 后应 Allow");
    }

    /// T016: evaluate_with_temp_policy 不写入缓存。
    #[tokio::test]
    async fn t016_evaluate_with_temp_policy_does_not_cache() {
        let engine = AbacEngine::new(SCHEMA_JSON).expect("schema valid");

        let temp_policy = r#"permit(principal, action == Action::"access", resource);"#;
        engine
            .evaluate_with_temp_policy(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
                temp_policy,
            )
            .await
            .expect("temp evaluate");
        engine.cache.run_pending_tasks();
        assert_eq!(engine.cache.entry_count(), 0, "temp policy 不应写入缓存");
    }
}
