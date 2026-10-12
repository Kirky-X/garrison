// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! AbacEngine — Cedar 策略求值器：principal-action-resource 三元组策略求值；策略集用 `Arc<RwLock<PolicySet>>` 支持读写分离热加载。

use crate::abac::EntityLoader;
use crate::core::permission::{Decision, DecisionReason};
use crate::error::{GarrisonError, GarrisonResult};
use cedar_policy::{Authorizer, Context, EntityUid, Policy, PolicyId, PolicySet, Request, Schema};
use oxcache::canonical_json_string;
use oxcache::traits::CacheKey;
use oxcache::Cache;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// 计算 context 成分的缓存 key 分量：`context_json` 先按 JSON 解析并 `canonical_json_string` 归一化（对象键字典序重排、去空白），再取 SHA-256 前 16 字节（128-bit）hex；`None` 用固定占位 `"none"`。
///
/// context 必须参与 key：否则同一 (principal, action, resource) 下不同 context 共享条目，context 敏感策略（如时间窗校验）返回陈旧决策；128-bit 摘要碰撞概率在 10^4 容量下可忽略。
/// 归一化令 key 派生口径与求值输入口径一致（`Context::from_json_str` 读的是 JSON 语义而非字节形态）：键序/空白不同但语义相同的 context 命中同一条目，不会各占一条、各求值一次，key 空间也不受调用方字符串形态支配。
/// 解析失败退回原始字节摘要：错误面不变——解析错误仍在未命中路径由 `Context::from_json_str` 以 `InvalidParam` 显性返回，此处只负责 key 派生。
fn context_key_component(context_json: Option<&str>) -> String {
    match context_json {
        None => "none".to_string(),
        Some(json) => {
            let normalized = serde_json::from_str::<serde_json::Value>(json)
                .map(|value| canonical_json_string(&value));
            let bytes = normalized
                .as_deref()
                .map(str::as_bytes)
                .unwrap_or(json.as_bytes());
            let digest = Sha256::digest(bytes);
            let mut hex = String::with_capacity(32);
            for byte in &digest[..16] {
                let _ = write!(hex, "{byte:02x}");
            }
            hex
        },
    }
}

/// ABAC 决策缓存 key：(principal, action, resource, context 摘要) 四元组；实体属性状态不参与 key（数据量大且无稳定指纹，纳入成本过高），实体变更需调用方 [`AbacEngine::invalidate_entities`]，策略变更经 `clear()` + 代数递增保证一致性。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DecisionKey(String, String, String, String);

impl CacheKey for DecisionKey {
    fn to_key_string(&self) -> String {
        // 使用 \x1F (ASCII Unit Separator) 作为字段分隔符，避免与 Cedar EntityUid 中的 ::" 冲突
        format!("{}\x1F{}\x1F{}\x1F{}", self.0, self.1, self.2, self.3)
    }
}

/// ABAC 决策缓存 TTL（秒）。
const DECISION_CACHE_TTL_SECS: u64 = 60;

/// ABAC 决策缓存最大容量。
const DECISION_CACHE_MAX_CAPACITY: u64 = 10_000;

/// ABAC 策略求值器（Cedar）：principal-action-resource 三元组求值，支持热加载；ABAC 是 RBAC 的增量校验层（RBAC 通过后再检查，不替换 RBAC）。
///
/// 线程安全：策略集为 `Arc<RwLock<PolicySet>>`，求值取读锁、热加载取写锁，互不阻塞。
pub struct AbacEngine {
    /// Cedar 授权器（无状态）。
    authorizer: Authorizer,
    /// 策略集（RwLock 支持热加载时读写分离）。
    policies: Arc<RwLock<PolicySet>>,
    /// 策略集代数（并发竞态防护）：每次策略变更（load/unload/reload_all，写锁内）递增；`evaluate` 读锁内同时取（代数, 快照），写缓存前重读比较，不一致说明期间发生热加载、决策基于旧快照，跳过写入避免陈旧决策回填（滞留 TTL 60s）。
    policy_generation: AtomicU64,
    /// Cedar schema（定义实体类型、属性、动作）。
    schema: Schema,
    /// 决策缓存（`oxcache::Cache<DecisionKey, Decision>`，全局 TTL 60s、max 10000）：策略热加载成功时 `clear()` 清空；实体状态变更需调用方 [`AbacEngine::invalidate_entities`]。
    cache: Cache<DecisionKey, Decision>,
    /// 实体加载器：每次 `evaluate` 调用 `load_entities` 获取 Cedar Entities，支持属性策略（如 `resource.owner == principal.id`）；缓存不因实体加载失效，属性变更需调用 [`AbacEngine::invalidate_entities`]。
    entity_loader: Arc<dyn EntityLoader>,
}

impl AbacEngine {
    /// 从 JSON schema 创建 AbacEngine：`EmptyEntityLoader` 保持空实体行为，`StaticEntityLoader` 支持属性策略；schema 解析或缓存初始化失败返回 `InvalidParam`。
    pub async fn new(
        schema_json: &str,
        entity_loader: Arc<dyn EntityLoader>,
    ) -> GarrisonResult<Self> {
        let schema = Schema::from_json_str(schema_json)
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-cedar-schema-parse::{}", e)))?;
        let cache = Cache::builder()
            .ttl(Duration::from_secs(DECISION_CACHE_TTL_SECS))
            .capacity(DECISION_CACHE_MAX_CAPACITY)
            .build()
            .await
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-decision-cache-init::{}", e)))?;
        Ok(Self {
            authorizer: Authorizer::new(),
            policies: Arc::new(RwLock::new(PolicySet::new())),
            policy_generation: AtomicU64::new(0),
            schema,
            cache,
            entity_loader,
        })
    }

    /// 清空决策缓存（实体状态变更时由调用方触发）：缓存 key 不含实体属性状态，实体属性运行期变化（owner 转移、组成员变更）后必须调用，否则最长 TTL 60s 内返回旧快照决策。
    /// 策略集变更（load/unload/reload_all）内部已自动清空并递增代数，无需调用。
    pub async fn invalidate_entities(&self) -> GarrisonResult<()> {
        self.cache
            .clear()
            .await
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-decision-cache-clear::{}", e)))
    }

    /// 求值策略：principal/action/resource 为 EntityUid 字符串（如 `User::"alice"`），`context_json` 可选；EntityUid/Context/Request 解析失败返回 `InvalidParam`。
    ///
    /// 缓存 key 为 (principal, action, resource, context 归一化摘要) 四元组：不同 context 不共享条目，语义相同（键序/空白不同）的 context 共享条目；实体属性状态不参与 key，实体变更时需 [`Self::invalidate_entities`]。
    pub async fn evaluate(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context_json: Option<&str>,
    ) -> GarrisonResult<Decision> {
        // 缓存命中直接返回；缓存读失败降级 Cedar 求值（fall-through），瞬态故障不中断求值
        let cache_key = DecisionKey(
            principal.to_string(),
            action.to_string(),
            resource.to_string(),
            context_key_component(context_json),
        );
        match self.cache.get(&cache_key).await {
            Ok(Some(cached)) => return Ok(cached),
            Ok(None) => {}, // 缓存未命中，继续 Cedar 求值
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "abac-decision-cache-read: cache read failed, falling back to Cedar evaluation"
                );
            },
        }

        // 读锁内取（代数, 策略快照）保证一致：写方在写锁内递增代数
        let (policies, generation) = {
            let guard = self.policies.read().await;
            (
                guard.clone(),
                self.policy_generation.load(Ordering::Acquire),
            )
        };

        // 共享求值 helper（与 evaluate_with_temp_policy 复用同一诊断/fail-closed 逻辑）
        let (decision, has_eval_errors) = self
            .evaluate_policies(
                principal,
                action,
                resource,
                context_json,
                &policies,
                "policy",
            )
            .await?;

        // 诊断含错误时 fail-closed 拒绝且不缓存：瞬态故障（实体缺失等）不应钉死在 TTL 60s，恢复后立即可重评
        if has_eval_errors {
            return Ok(decision);
        }

        // 写缓存前重读代数：若求值期间发生热加载（已清空缓存并递增代数），本决策基于旧策略快照，写入会回填陈旧决策（TTL 60s）——跳过写入
        if self.policy_generation.load(Ordering::Acquire) != generation {
            tracing::warn!(
                principal = %principal,
                action = %action,
                resource = %resource,
                "abac-decision-cache: policy set changed during evaluation, skipping cache write"
            );
            return Ok(decision);
        }
        // 缓存写失败不影响求值结果，仅记录警告
        if let Err(e) = self.cache.set(&cache_key, &decision).await {
            tracing::warn!(
                error = %e,
                    "abac-decision-cache-write: cache write failed, decision still returned"
            );
        }

        Ok(decision)
    }

    /// 加载策略（`policy_id` 用于卸载）；语法错误或 ID 冲突返回 `InvalidParam`。
    pub async fn load_policy(&self, policy_id: &str, policy_src: &str) -> GarrisonResult<()> {
        let policy = Policy::parse(Some(PolicyId::new(policy_id)), policy_src)
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-cedar-policy-parse::{}", e)))?;
        let mut policies = self.policies.write().await;
        policies
            .add(policy)
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-cedar-policy-add::{}", e)))?;
        // 策略变更后清空缓存并在写锁内递增代数（并发 evaluate 的旧快照决策据此跳过写回）
        self.policy_generation.fetch_add(1, Ordering::Release);
        self.cache.clear().await.map_err(|e| {
            GarrisonError::InvalidParam(format!("abac-decision-cache-clear::{}", e))
        })?;
        Ok(())
    }

    /// 卸载策略；策略不存在返回 `InvalidParam`。
    pub async fn unload_policy(&self, policy_id: &str) -> GarrisonResult<()> {
        let policy_id = PolicyId::new(policy_id);
        let mut policies = self.policies.write().await;
        policies
            .remove_static(policy_id)
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-cedar-policy-delete::{}", e)))?;
        // 策略变更后清空缓存并递增代数（同 load_policy）
        self.policy_generation.fetch_add(1, Ordering::Release);
        self.cache.clear().await.map_err(|e| {
            GarrisonError::InvalidParam(format!("abac-decision-cache-clear::{}", e))
        })?;
        Ok(())
    }

    /// 原子替换全部策略：先解析全部，任一语法错误返回 `InvalidParam` 且不替换（不部分加载）；全部成功后原子替换并清空缓存。
    pub async fn reload_all(&self, policies: HashMap<String, String>) -> GarrisonResult<()> {
        let mut new_set = PolicySet::new();
        for (id, src) in &policies {
            let policy = Policy::parse(Some(PolicyId::new(id)), src).map_err(|e| {
                GarrisonError::InvalidParam(format!("abac-cedar-policy-parse-id::{}::{}", id, e))
            })?;
            new_set.add(policy).map_err(|e| {
                GarrisonError::InvalidParam(format!("abac-cedar-policy-add-id::{}::{}", id, e))
            })?;
        }
        let mut guard = self.policies.write().await;
        *guard = new_set;
        // 替换成功后清空缓存并递增代数（解析失败已提前返回，不达此处）
        self.policy_generation.fetch_add(1, Ordering::Release);
        self.cache.clear().await.map_err(|e| {
            GarrisonError::InvalidParam(format!("abac-decision-cache-clear::{}", e))
        })?;
        Ok(())
    }

    /// 用临时策略求值（不修改共享策略集、不与 `load_policy` 的策略合并）：供 `check_abac_with_policy` 将宏生成的表达式包装为完整策略后求值，避免污染全局策略集；解析失败返回 `InvalidParam`，不写缓存。
    pub async fn evaluate_with_temp_policy(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context_json: Option<&str>,
        temp_policy_src: &str,
    ) -> GarrisonResult<Decision> {
        let temp_policy = Policy::parse(None, temp_policy_src).map_err(|e| {
            GarrisonError::InvalidParam(format!("abac-temp-cedar-policy-parse::{}", e))
        })?;
        let mut temp_set = PolicySet::new();
        temp_set.add(temp_policy).map_err(|e| {
            GarrisonError::InvalidParam(format!("abac-temp-cedar-policy-add::{}", e))
        })?;
        // 共享求值 helper（同 evaluate 的诊断/fail-closed 逻辑）；不写缓存，错误经 ? 传播
        let (decision, _has_eval_errors) = self
            .evaluate_policies(
                principal,
                action,
                resource,
                context_json,
                &temp_set,
                "temp-policy",
            )
            .await?;
        Ok(decision)
    }

    /// 共享求值 helper：构建 Request → Cedar 求值 → 诊断错误 fail-closed → Decision 映射。
    ///
    /// Cedar `is_authorized` 在策略内部求值出错（schema/类型/运行时错误）时仍可能返回 `Allow`：诊断含错误时逐条 warn 并统一返回 `Decision::deny(DecisionReason::EvaluationError)`（fail-closed，决不静默转 Allow）。
    ///
    /// 返回 `(Decision, has_eval_errors)`：`has_eval_errors=true` 时决策为 fail-closed 拒绝，调用方不得写入缓存（瞬态故障不钉死 TTL）；解析失败返回 `InvalidParam`，EntityLoader 错误透传。
    async fn evaluate_policies(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context_json: Option<&str>,
        policies: &PolicySet,
        label: &str,
    ) -> GarrisonResult<(Decision, bool)> {
        let principal_uid: EntityUid = principal
            .parse()
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-principal-parse::{}", e)))?;
        let action_uid: EntityUid = action
            .parse()
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-action-parse::{}", e)))?;
        let resource_uid: EntityUid = resource
            .parse()
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-resource-parse::{}", e)))?;
        let context = match context_json {
            Some(json) => Context::from_json_str(json, Some((&self.schema, &action_uid)))
                .map_err(|e| GarrisonError::InvalidParam(format!("abac-context-parse::{}", e)))?,
            None => Context::empty(),
        };
        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            context,
            Some(&self.schema),
        )
        .map_err(|e| GarrisonError::InvalidParam(format!("abac-cedar-request-build::{}", e)))?;
        // EntityLoader 出错经 ? 传播，缓存不受污染
        let entities = self.entity_loader.load_entities().await?;
        let response = self.authorizer.is_authorized(&request, policies, &entities);

        let mut has_eval_errors = false;
        for error in response.diagnostics().errors() {
            has_eval_errors = true;
            tracing::warn!(
                principal = %principal,
                action = %action,
                resource = %resource,
                error = %error,
                "Cedar {} evaluation diagnostic error",
                label
            );
        }

        // 诊断含错误时 fail-closed 拒绝：策略求值故障必须显性化为 Deny + 日志告警，绝不静默采用 Cedar 的 Allow
        if has_eval_errors {
            tracing::error!(
                principal = %principal,
                action = %action,
                resource = %resource,
                "Cedar {} evaluation produced diagnostic errors; denying (fail-closed, issue 2756)",
                label
            );
            return Ok((Decision::deny(DecisionReason::EvaluationError), true));
        }

        let decision = match response.decision() {
            cedar_policy::Decision::Allow => Decision::allow(),
            cedar_policy::Decision::Deny => {
                // 区分显式 forbid 与隐式 deny：diagnostics.reason() 有匹配 policy ID 说明 forbid 生效
                let has_matching_policy = response.diagnostics().reason().next().is_some();
                if has_matching_policy {
                    Decision::deny(DecisionReason::ExplicitDeny)
                } else {
                    Decision::deny(DecisionReason::NoMatchingPermission)
                }
            },
        };

        Ok((decision, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abac::{EmptyEntityLoader, StaticEntityLoader};
    use cedar_policy::Entities;

    /// 测试辅助：判断 (principal, action, resource, context) 决策是否已缓存；用 `get()` 而非 `len()`（len 为最终一致估算，写入后未必立即可见）。
    async fn cache_has_entry_with_context(
        engine: &AbacEngine,
        principal: &str,
        action: &str,
        resource: &str,
        context_json: Option<&str>,
    ) -> bool {
        let key = DecisionKey(
            principal.to_string(),
            action.to_string(),
            resource.to_string(),
            context_key_component(context_json),
        );
        engine.cache.get(&key).await.unwrap_or(None).is_some()
    }

    /// 测试辅助：判断 (principal, action, resource) 决策是否已缓存（无 context）。
    async fn cache_has_entry(
        engine: &AbacEngine,
        principal: &str,
        action: &str,
        resource: &str,
    ) -> bool {
        cache_has_entry_with_context(engine, principal, action, resource, None).await
    }

    /// 测试用 Cedar schema：User/Resource 实体与 access 动作（空 namespace，EntityUid 直接用 `User::"alice"` 格式）。
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

    #[tokio::test]
    async fn t121_new_from_json_schema_success() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader)).await;
        assert!(engine.is_ok(), "AbacEngine::new 应成功: {:?}", engine.err());
    }

    #[tokio::test]
    async fn t121_new_invalid_schema_returns_invalid_param() {
        let result = AbacEngine::new("not a valid json", Arc::new(EmptyEntityLoader)).await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "应为 InvalidParam"
        );
    }

    #[tokio::test]
    async fn t123_evaluate_permit_returns_allow() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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

    #[tokio::test]
    async fn t123_evaluate_no_match_returns_deny() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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

    #[tokio::test]
    async fn t123_evaluate_no_policies_returns_deny() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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

    #[tokio::test]
    async fn t123_evaluate_invalid_principal_returns_error() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "应为 InvalidParam"
        );
    }

    #[tokio::test]
    async fn t125_decision_mapping_allow() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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

    #[tokio::test]
    async fn t125_decision_mapping_deny() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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

    #[tokio::test]
    async fn t125_forbid_overrides_permit() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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
        assert_eq!(
            decision.reason,
            DecisionReason::ExplicitDeny,
            "forbid 策略匹配应映射为 ExplicitDeny"
        );
    }

    #[tokio::test]
    async fn t125_evaluate_with_context() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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

    #[tokio::test]
    async fn load_policy_syntax_error_returns_invalid_param() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
        let result = engine
            .load_policy("p1", "this is not a valid cedar policy")
            .await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "应为 InvalidParam"
        );
    }

    #[tokio::test]
    async fn unload_policy_changes_decision() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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

    #[tokio::test]
    async fn reload_all_atomically_replaces_policies() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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

    #[tokio::test]
    async fn reload_all_syntax_error_keeps_existing() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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

    #[tokio::test]
    async fn concurrent_evaluate_does_not_block() {
        let engine = Arc::new(
            AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
                .await
                .expect("schema valid"),
        );
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");
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

    // evaluate_with_temp_policy 测试

    #[tokio::test]
    async fn t139_evaluate_with_temp_policy_permit_returns_allow() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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

    #[tokio::test]
    async fn t139_evaluate_with_temp_policy_no_match_returns_deny() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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

    #[tokio::test]
    async fn t139_evaluate_with_temp_policy_invalid_returns_error() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "应为 InvalidParam"
        );
    }

    #[tokio::test]
    async fn t139_evaluate_with_temp_policy_does_not_modify_shared() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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

    #[tokio::test]
    async fn t139_evaluate_with_temp_policy_when_condition() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
        // when true → Allow
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

        // when false → Deny
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

    // ABAC 决策缓存 oxcache TTL 60s 测试

    #[tokio::test]
    async fn t016_cache_hit_on_second_evaluate_same_key() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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
        assert!(
            cache_has_entry(&engine, principal, action, resource).await,
            "首次求值后缓存应包含该 key"
        );

        let d2 = engine
            .evaluate(principal, action, resource, None)
            .await
            .expect("evaluate 2");
        assert!(
            cache_has_entry(&engine, principal, action, resource).await,
            "第二次求值后缓存仍应包含该 key"
        );
        assert_eq!(d1.allowed, d2.allowed, "两次求值结果应一致");
    }

    #[tokio::test]
    async fn t016_cache_miss_on_different_keys() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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
        assert!(
            cache_has_entry(
                &engine,
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#
            )
            .await
                && cache_has_entry(
                    &engine,
                    r#"User::"bob""#,
                    r#"Action::"access""#,
                    r#"Resource::"doc1""#
                )
                .await,
            "不同 key 应分别缓存"
        );
    }

    #[tokio::test]
    async fn t016_cache_invalidated_on_unload_policy() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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
        assert!(
            cache_has_entry(
                &engine,
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#
            )
            .await,
            "求值后缓存应包含该 key"
        );

        engine.unload_policy("p1").await.expect("unload");
        assert!(
            !cache_has_entry(
                &engine,
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#
            )
            .await,
            "unload 后缓存应清空"
        );

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

    #[tokio::test]
    async fn t016_cache_invalidated_on_reload_all() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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
        assert!(
            cache_has_entry(
                &engine,
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#
            )
            .await,
            "求值后缓存应包含该 key"
        );

        let mut new_policies = HashMap::new();
        new_policies.insert(
            "p2".to_string(),
            r#"permit(principal == User::"bob", action, resource);"#.to_string(),
        );
        engine.reload_all(new_policies).await.expect("reload");
        assert!(
            !cache_has_entry(
                &engine,
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#
            )
            .await,
            "reload 后缓存应清空"
        );

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

    #[tokio::test]
    async fn t016_cache_kept_on_reload_all_failure() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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
        assert!(
            cache_has_entry(
                &engine,
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#
            )
            .await,
            "求值后缓存应包含该 key"
        );

        let mut bad_policies = HashMap::new();
        bad_policies.insert("p2".to_string(), "invalid policy".to_string());
        let result = engine.reload_all(bad_policies).await;
        assert!(result.is_err(), "reload_all 应失败");
        assert!(
            cache_has_entry(
                &engine,
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#
            )
            .await,
            "reload 失败时缓存应保持不变"
        );

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

    #[tokio::test]
    async fn t016_cache_invalidated_on_load_policy() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");

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
        assert!(
            cache_has_entry(
                &engine,
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#
            )
            .await,
            "首次求值后缓存应包含该 key"
        );

        // load_policy 后缓存失效
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");
        assert!(
            !cache_has_entry(
                &engine,
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#
            )
            .await,
            "load 后缓存应清空"
        );

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

    #[tokio::test]
    async fn t016_evaluate_with_temp_policy_does_not_cache() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");

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
        assert!(
            !cache_has_entry(
                &engine,
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#
            )
            .await,
            "temp policy 不应写入缓存"
        );
    }

    // EntityLoader 集成测试
    // 验证带属性的实体能被 ABAC 策略正确求值

    /// 带属性实体 schema：User 带 id、Resource 带 owner（`resource.owner == principal.id` 类策略需 EntityLoader 提供带属性实体）。
    const ATTR_SCHEMA_JSON: &str = r#"{
        "": {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "id": { "type": "String" }
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

    #[tokio::test]
    async fn test_evaluate_with_static_entity_loader_attribute_based_policy() {
        // Cedar 4.x Entities JSON 格式要求 uid 为对象形式 `{"__entity": {"type", "id"}}`。
        let entities_json = r#"[
            {"uid": {"__entity": {"type": "User", "id": "alice"}}, "attrs": {"id": "alice"}, "parents": []},
            {"uid": {"__entity": {"type": "Resource", "id": "doc1"}}, "attrs": {"owner": "alice"}, "parents": []}
        ]"#;
        let schema = cedar_policy::Schema::from_json_str(ATTR_SCHEMA_JSON).expect("schema valid");
        let entities =
            Entities::from_json_str(entities_json, Some(&schema)).expect("构造带属性实体应成功");

        let engine = AbacEngine::new(
            ATTR_SCHEMA_JSON,
            Arc::new(StaticEntityLoader::new(entities)),
        )
        .await
        .expect("schema valid");

        // 策略：当 resource.owner == principal.id 时允许（基于实体属性的条件）
        let policy = r#"permit(principal, action == Action::"access", resource) when { resource.owner == principal.id };"#;
        engine.load_policy("p1", policy).await.expect("load policy");

        // alice 访问 doc1：owner == id == "alice" → Allow
        let decision_allow = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(
            decision_allow.allowed,
            "属性匹配时应 Allow（EntityLoader 提供实体属性后应能求值基于属性的策略）"
        );

        // 切换为 owner 不匹配的实体 → Deny
        let entities_mismatch_json = r#"[
            {"uid": {"__entity": {"type": "User", "id": "alice"}}, "attrs": {"id": "alice"}, "parents": []},
            {"uid": {"__entity": {"type": "Resource", "id": "doc1"}}, "attrs": {"owner": "bob"}, "parents": []}
        ]"#;
        let entities_mismatch = Entities::from_json_str(entities_mismatch_json, Some(&schema))
            .expect("构造不匹配实体应成功");
        let engine_deny = AbacEngine::new(
            ATTR_SCHEMA_JSON,
            Arc::new(StaticEntityLoader::new(entities_mismatch)),
        )
        .await
        .expect("schema valid");
        engine_deny
            .load_policy("p1", policy)
            .await
            .expect("load policy");
        let decision_deny = engine_deny
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate");
        assert!(
            !decision_deny.allowed,
            "属性不匹配时应 Deny（owner=bob != id=alice）"
        );
    }

    #[tokio::test]
    async fn test_evaluate_with_entity_loader_error_propagates() {
        struct ErrorEntityLoader;

        #[async_trait::async_trait]
        impl crate::abac::EntityLoader for ErrorEntityLoader {
            async fn load_entities(&self) -> GarrisonResult<Entities> {
                Err(GarrisonError::Config(
                    "EntityLoader 故意返回错误（模拟数据源不可达）".into(),
                ))
            }
        }

        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(ErrorEntityLoader))
            .await
            .expect("schema valid");
        // 即使加载了 permit 策略，evaluate 也应因 EntityLoader 错误而失败
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load policy");

        let result = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await;
        assert!(
            result.is_err(),
            "EntityLoader 错误应通过 ? 传播，而非默认成功（规则 12：失败必须显性化）"
        );
        match result {
            Err(GarrisonError::Config(msg)) => {
                assert!(
                    msg.contains("EntityLoader"),
                    "错误消息应包含 'EntityLoader'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!(
                "期望 Config 错误（EntityLoader 错误传播），实际: {:?}",
                other
            ),
            Ok(_) => panic!("期望 Err，实际 Ok（错误被吞掉，违反规则 12）"),
        }

        // 验证缓存未受污染（错误传播路径不应写入缓存）
        assert!(
            !cache_has_entry(
                &engine,
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#
            )
            .await,
            "EntityLoader 错误传播时缓存不应被污染"
        );

        // evaluate_with_temp_policy 同样应传播 EntityLoader 错误
        let temp_result = engine
            .evaluate_with_temp_policy(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
                r#"permit(principal, action, resource);"#,
            )
            .await;
        assert!(
            temp_result.is_err(),
            "evaluate_with_temp_policy 也应传播 EntityLoader 错误"
        );
        match temp_result {
            Err(GarrisonError::Config(msg)) => {
                assert!(
                    msg.contains("EntityLoader"),
                    "temp policy 错误消息应包含 'EntityLoader'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!(
                "evaluate_with_temp_policy 期望 Config 错误，实际: {:?}",
                other
            ),
            Ok(_) => panic!("evaluate_with_temp_policy 期望 Err，实际 Ok"),
        }
    }

    // context 参与缓存 key

    /// context 敏感 schema：access 动作带 context 属性 `level`（Long）。
    const CONTEXT_SCHEMA_JSON: &str = r#"{
        "": {
            "entityTypes": {
                "User": {},
                "Resource": {}
            },
            "actions": {
                "access": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Resource"],
                        "context": {
                            "type": "Record",
                            "attributes": {
                                "level": { "type": "Long" }
                            }
                        }
                    }
                }
            }
        }
    }"#;

    /// 同三元组不同 context 不得共享缓存：`level=5` 的 Allow 不得被 `level=1` 命中（context 摘要参与 key）。
    #[tokio::test]
    async fn t016_context_participates_in_cache_key() {
        let engine = AbacEngine::new(CONTEXT_SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
        engine
            .load_policy(
                "p1",
                r#"permit(principal, action, resource) when { context.level >= 3 };"#,
            )
            .await
            .expect("load");

        let principal = r#"User::"alice""#;
        let action = r#"Action::"access""#;
        let resource = r#"Resource::"doc1""#;

        // level=5 → Allow（写入 hash(ctx5) 条目）
        let allow = engine
            .evaluate(principal, action, resource, Some(r#"{"level": 5}"#))
            .await
            .expect("evaluate level=5");
        assert!(allow.allowed, "level=5 应 Allow");

        // level=1 → 必须 Deny（不得命中 level=5 的缓存条目）
        let deny = engine
            .evaluate(principal, action, resource, Some(r#"{"level": 1}"#))
            .await
            .expect("evaluate level=1");
        assert!(
            !deny.allowed,
            "level=1 应 Deny（不同 context 不得共享缓存条目）"
        );

        // level=5 再次求值 → 仍 Allow（其缓存条目未被 level=1 污染）
        let allow_again = engine
            .evaluate(principal, action, resource, Some(r#"{"level": 5}"#))
            .await
            .expect("evaluate level=5 again");
        assert!(allow_again.allowed, "level=5 缓存条目应保持 Allow");
    }

    // context key 归一化（canonical JSON）

    /// 归一化在 key 分量层面生效：键序/空白不同但语义相同的 context 派生同一分量，语义不同（数组序、值）仍区分。
    #[test]
    fn context_key_component_normalizes_json_semantics() {
        assert_eq!(
            context_key_component(Some(r#"{"b": 2, "a": {"d": 4, "c": 3}}"#)),
            context_key_component(Some(r#"{ "a": { "c": 3, "d": 4 }, "b": 2 }"#)),
            "键序/空白不同但语义相同的 context 应派生同一分量"
        );
        assert_ne!(
            context_key_component(Some(r#"{"a": [1, 2]}"#)),
            context_key_component(Some(r#"{"a": [2, 1]}"#)),
            "数组有序，元素顺序不同是不同语义，应区分"
        );
        assert_ne!(
            context_key_component(Some(r#"{"a": 1}"#)),
            context_key_component(Some(r#"{"a": 2}"#)),
            "值不同应区分"
        );
        assert_ne!(
            context_key_component(None),
            context_key_component(Some(r#"null"#)),
            "None 与显式 null context 应区分"
        );
    }

    /// 非法 JSON 退回原始字节摘要：不做归一化（含仅空白差异也区分），不引入新错误面。
    #[test]
    fn context_key_component_falls_back_to_raw_bytes_on_invalid_json() {
        assert_eq!(
            context_key_component(Some(r#"{"a":1}"#)),
            context_key_component(Some(r#"{ "a" : 1 }"#)),
            "合法 JSON 的空白差异应被归一化抹平"
        );
        assert_ne!(
            context_key_component(Some(r#"{"a":}"#)),
            context_key_component(Some(r#"{ "a":}"#)),
            "解析失败时应按原始字节区分，空白差异不得被抹平"
        );
    }

    /// 多属性 context schema：两个属性才能构造键序差异。
    const MULTI_ATTR_CONTEXT_SCHEMA_JSON: &str = r#"{
        "": {
            "entityTypes": {
                "User": {},
                "Resource": {}
            },
            "actions": {
                "access": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Resource"],
                        "context": {
                            "type": "Record",
                            "attributes": {
                                "level": { "type": "Long" },
                                "region": { "type": "String" }
                            }
                        }
                    }
                }
            }
        }
    }"#;

    /// 语义相同的两种键序只产生一个缓存条目：键序 B 从未提交求值即可读到键序 A 写入的条目，且再次求值命中缓存不再触发 EntityLoader（未回落到 Cedar 求值）。
    #[tokio::test]
    async fn t016_equivalent_context_key_orders_share_one_cache_entry() {
        struct CountingEntityLoader {
            calls: std::sync::atomic::AtomicUsize,
        }

        #[async_trait::async_trait]
        impl crate::abac::EntityLoader for CountingEntityLoader {
            async fn load_entities(&self) -> GarrisonResult<Entities> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(Entities::empty())
            }
        }

        let loader = Arc::new(CountingEntityLoader {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let engine = AbacEngine::new(MULTI_ATTR_CONTEXT_SCHEMA_JSON, loader.clone())
            .await
            .expect("schema valid");
        engine
            .load_policy(
                "p1",
                r#"permit(principal, action, resource) when { context.level >= 3 };"#,
            )
            .await
            .expect("load");

        let principal = r#"User::"alice""#;
        let action = r#"Action::"access""#;
        let resource = r#"Resource::"doc1""#;
        let order_a = r#"{"level": 5, "region": "cn"}"#;
        let order_b = r#"{ "region": "cn", "level": 5 }"#;

        let first = engine
            .evaluate(principal, action, resource, Some(order_a))
            .await
            .expect("evaluate 键序 A");
        assert!(first.allowed, "level=5 应 Allow");
        assert_eq!(
            loader.calls.load(Ordering::SeqCst),
            1,
            "首次求值未命中缓存，应调用一次 EntityLoader"
        );

        // 键序 B 从未提交过求值：其 key 存在即证明与键序 A 是同一条目（各占一条时此处为 false）
        assert!(
            cache_has_entry_with_context(&engine, principal, action, resource, Some(order_b)).await,
            "语义相同的另一种键序应命中键序 A 写入的同一条目"
        );

        let second = engine
            .evaluate(principal, action, resource, Some(order_b))
            .await
            .expect("evaluate 键序 B");
        assert!(second.allowed, "键序 B 应命中缓存并返回 Allow");
        assert_eq!(
            loader.calls.load(Ordering::SeqCst),
            1,
            "第二次求值应命中缓存，不得再次调用 EntityLoader"
        );

        // 归一化不得越界合并：语义不同（region 不同）仍是独立条目，需重新求值
        engine
            .evaluate(
                principal,
                action,
                resource,
                Some(r#"{"level": 5, "region": "us"}"#),
            )
            .await
            .expect("evaluate region=us");
        assert_eq!(
            loader.calls.load(Ordering::SeqCst),
            2,
            "region 不同的 context 是另一条目，应重新求值"
        );
    }

    /// 非法 context JSON：key 派生不改动错误面——evaluate 仍显性返回 InvalidParam，且失败路径不写缓存。
    #[tokio::test]
    async fn t016_invalid_context_json_returns_invalid_param_without_cache_write() {
        let engine = AbacEngine::new(CONTEXT_SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");

        let principal = r#"User::"alice""#;
        let action = r#"Action::"access""#;
        let resource = r#"Resource::"doc1""#;
        let invalid_context = r#"{"level": }"#;

        let result = engine
            .evaluate(principal, action, resource, Some(invalid_context))
            .await;
        match result {
            Err(GarrisonError::InvalidParam(_)) => {},
            other => panic!(
                "非法 context JSON 应显性返回 InvalidParam，实际: {:?}",
                other
            ),
        }
        assert!(
            !cache_has_entry_with_context(
                &engine,
                principal,
                action,
                resource,
                Some(invalid_context)
            )
            .await,
            "解析失败路径不得写入缓存"
        );
    }

    #[tokio::test]
    async fn invalidate_entities_clears_decision_cache() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
        engine
            .load_policy("p1", r#"permit(principal, action, resource);"#)
            .await
            .expect("load");

        let principal = r#"User::"alice""#;
        let action = r#"Action::"access""#;
        let resource = r#"Resource::"doc1""#;
        engine
            .evaluate(principal, action, resource, None)
            .await
            .expect("evaluate");
        assert!(
            cache_has_entry(&engine, principal, action, resource).await,
            "求值后缓存应包含该 key"
        );

        engine.invalidate_entities().await.expect("invalidate");
        assert!(
            !cache_has_entry(&engine, principal, action, resource).await,
            "invalidate_entities 后缓存应清空"
        );
    }

    // Cedar 诊断错误 fail-closed

    /// 实体缺失致 Cedar 诊断错误时必须 fail-closed 拒绝为 EvaluationError（不得采用 Cedar 的 Allow）。
    #[tokio::test]
    async fn evaluation_error_fails_closed_denies() {
        let engine = AbacEngine::new(ATTR_SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
        engine
            .load_policy(
                "p1",
                r#"permit(principal, action, resource) when { resource.owner == principal.id };"#,
            )
            .await
            .expect("load");

        let decision = engine
            .evaluate(
                r#"User::"alice""#,
                r#"Action::"access""#,
                r#"Resource::"doc1""#,
                None,
            )
            .await
            .expect("evaluate（诊断错误走 fail-closed 拒绝而非 Err）");
        assert!(!decision.allowed, "Cedar 诊断错误时必须拒绝（fail-closed）");
        assert!(
            decision.reason == DecisionReason::EvaluationError,
            "诊断错误的拒绝原因应为 EvaluationError，实际: {:?}",
            decision.reason
        );
    }
}
