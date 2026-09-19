// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! AbacEngine — Cedar 策略求值器实现。
//!
//! 基于 `cedar-policy` crate，提供 principal-action-resource 三元组策略求值。
//! 策略集使用 `Arc<RwLock<PolicySet>>` 支持读写分离热加载。

use crate::abac::EntityLoader;
use crate::core::permission::{Decision, DecisionReason};
use crate::error::{GarrisonError, GarrisonResult};
use cedar_policy::{Authorizer, Context, EntityUid, Policy, PolicyId, PolicySet, Request, Schema};
use oxcache::traits::CacheKey;
use oxcache::Cache;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// 计算 context 成分的缓存 key 分量。
///
/// `context_json` 曾被排除在缓存 key 之外（设计），导致同一
/// (principal, action, resource) 三元组下不同 context 共享缓存条目，
/// context 敏感策略（如时间窗校验）返回陈旧决策。修复：将 context_json 的
/// SHA-256 摘要前 16 字节（128-bit，碰撞概率在 10^4 容量下可忽略）hex 编码后
/// 纳入 key；`None` 使用固定占位 `"none"`。
fn context_key_component(context_json: Option<&str>) -> String {
    match context_json {
        None => "none".to_string(),
        Some(json) => {
            let digest = Sha256::digest(json.as_bytes());
            let mut hex = String::with_capacity(32);
            for byte in &digest[..16] {
                let _ = write!(hex, "{byte:02x}");
            }
            hex
        },
    }
}

/// ABAC 决策缓存 key：(principal, action, resource, context 摘要) 四元组。
///
/// # 设计权衡
///
/// `context_json` 以 SHA-256 前 16 字节摘要参与缓存 key，
/// 不同 context 不再共享缓存条目。实体属性状态仍**不**参与 key：
/// - 实体属性数据量大且无稳定指纹，纳入 key 的成本过高
/// - 实体变更时调用方需调用 [`AbacEngine::invalidate_entities`] 清空缓存（见其文档）
/// - 策略变更（load/unload/reload_all）通过 `clear()` + 代数递增保证一致性
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

/// ABAC 策略求值器，基于 Cedar 策略语言。
///
/// 提供 principal-action-resource 三元组策略求值，支持策略的热加载。
/// ABAC 作为 RBAC 的增量校验层，不替换 RBAC。RBAC 通过后再检查 ABAC。
///
/// # 设计
///
/// - `authorizer`：Cedar 授权器（无状态，可共享）
/// - `policies`：策略集（`Arc<RwLock<PolicySet>>` 支持读写分离热加载）
/// - `policy_generation`：策略集代数（每次热加载递增，用于缓存写回校验）
/// - `schema`：Cedar schema（定义实体类型、属性、动作）
/// - `cache`：决策缓存（`oxcache::Cache`，全局 TTL 60s, max 10000），key 为 DecisionKey
/// - `entity_loader`：实体加载器
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
    /// 策略集代数（用于并发竞态防护）。
    ///
    /// 每次策略集变更（load_policy / unload_policy / reload_all，均在写锁范围内）
    /// 递增。`evaluate` 在读锁范围内克隆策略快照时同时读取代数，写缓存前重读比较：
    /// 代数不一致说明求值期间发生了热加载，该决策基于旧策略快照，跳过缓存写入，
    /// 避免旧策略决策在 `reload_all` 清空缓存后回填（陈旧决策滞留 TTL 60s）。
    policy_generation: AtomicU64,
    /// Cedar schema（定义实体类型、属性、动作）。
    schema: Schema,
    /// 决策缓存（`oxcache::Cache<DecisionKey, Decision>`，全局 TTL 60s, max 10000）。
    ///
    /// 策略热加载（load/unload/reload_all 成功）时调用 `clear()` 清空。
    /// 实体状态变更需调用方显式调用 [`AbacEngine::invalidate_entities`] 清空。
    cache: Cache<DecisionKey, Decision>,
    /// 实体加载器。
    ///
    /// 每次 `evaluate` 时调用 `load_entities` 获取 Cedar Entities 集合，
    /// 支持基于实体属性的策略（如 `resource.owner == principal.id`）。
    /// 决策缓存不因实体加载而失效——实体属性变更时调用方需调用
    /// [`AbacEngine::invalidate_entities`]（见其文档的调用时机说明）。
    entity_loader: Arc<dyn EntityLoader>,
}

impl AbacEngine {
    /// 从 JSON schema 创建 AbacEngine。
    ///
    /// # 参数
    /// - `schema_json`：Cedar schema JSON 字符串
    /// - `entity_loader`：实体加载器（`Arc<dyn EntityLoader>`）。
    ///   传 `Arc::new(EmptyEntityLoader)` 保持空实体行为，传 `Arc::new(StaticEntityLoader::new(...))`
    ///   支持基于属性的策略。
    ///
    /// # 错误
    /// - schema JSON 解析失败：`GarrisonError::InvalidParam`
    /// - oxcache 初始化失败：`GarrisonError::InvalidParam`
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

    /// 清空决策缓存（实体状态变更时由调用方触发）。
    ///
    /// # 何时调用
    ///
    /// 决策缓存 key 含 (principal, action, resource, context 摘要)，但**不含实体属性状态**。
    /// 若 `EntityLoader` 返回的实体属性在运行期发生变化（如 `resource.owner` 所有权转移、
    /// 部门/组成员变更），调用方必须在实体变更点调用本方法清空缓存，否则最长
    /// TTL 60s 内 `evaluate` 会返回基于旧实体属性的陈旧决策。
    ///
    /// 策略集变更（`load_policy` / `unload_policy` / `reload_all`）无需调用——
    /// 内部已自动清空缓存并递增策略代数。
    ///
    /// # 错误
    /// - 缓存清空失败：`GarrisonError::InvalidParam`
    pub async fn invalidate_entities(&self) -> GarrisonResult<()> {
        self.cache
            .clear()
            .await
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-decision-cache-clear::{}", e)))
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
    /// # 缓存语义
    ///
    /// 缓存 key 为 (principal, action, resource, context 摘要) 四元组：不同
    /// `context_json` 不会共享缓存条目。实体属性状态
    /// 不参与 key——实体变更时调用方需调用 [`Self::invalidate_entities`]。
    ///
    /// # 错误
    /// - EntityUid 解析失败：`GarrisonError::InvalidParam`
    /// - Context 解析失败：`GarrisonError::InvalidParam`
    /// - Request 构造失败：`GarrisonError::InvalidParam`
    pub async fn evaluate(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context_json: Option<&str>,
    ) -> GarrisonResult<Decision> {
        // 缓存查询：命中则直接返回（不调用 Cedar）
        // 缓存读失败时降级到 Cedar 求值（fall-through），不因瞬态故障中断求值
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

        // 在读锁范围内读取策略代数并克隆策略快照：写方在写锁范围内递增代数，
        // 因此（代数, 策略快照）对在读锁内是一致的
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

        // Cedar 诊断含错误时 fail-closed 拒绝（不缓存）：
        // 瞬态故障（实体数据缺失等）不应钉死在 TTL 60s 的缓存里，恢复后立即可重评
        if has_eval_errors {
            return Ok(decision);
        }

        // 写入缓存（仅在求值成功后）
        // 写缓存前重读策略代数。若求值期间发生了热加载
        //（load/unload/reload_all 已清空缓存并递增代数），本决策基于旧策略快照，
        // 写入会把陈旧决策回填到新策略集的缓存中（TTL 60s 内返回过期决策）——跳过写入。
        if self.policy_generation.load(Ordering::Acquire) != generation {
            tracing::warn!(
                principal = %principal,
                action = %action,
                resource = %resource,
                "abac-decision-cache: policy set changed during evaluation, skipping cache write"
            );
            return Ok(decision);
        }
        // 缓存写失败不影响求值结果——决策本身是正确的，仅记录警告
        if let Err(e) = self.cache.set(&cache_key, &decision).await {
            tracing::warn!(
                error = %e,
                    "abac-decision-cache-write: cache write failed, decision still returned"
            );
        }

        Ok(decision)
    }

    /// 加载策略。
    ///
    /// # 参数
    /// - `policy_id`：策略 ID（用于卸载）
    /// - `policy_src`：Cedar DSL 策略文本
    ///
    /// # 错误
    /// - 策略语法错误：`GarrisonError::InvalidParam`
    /// - 策略 ID 冲突：`GarrisonError::InvalidParam`
    pub async fn load_policy(&self, policy_id: &str, policy_src: &str) -> GarrisonResult<()> {
        let policy = Policy::parse(Some(PolicyId::new(policy_id)), policy_src)
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-cedar-policy-parse::{}", e)))?;
        let mut policies = self.policies.write().await;
        policies
            .add(policy)
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-cedar-policy-add::{}", e)))?;
        // 策略变更后清空决策缓存（新策略可能改变现有 key 的决策）；
        // 在写锁范围内递增策略代数，使并发 evaluate 的旧快照决策跳过缓存写回
        self.policy_generation.fetch_add(1, Ordering::Release);
        self.cache.clear().await.map_err(|e| {
            GarrisonError::InvalidParam(format!("abac-decision-cache-clear::{}", e))
        })?;
        Ok(())
    }

    /// 卸载策略。
    ///
    /// # 参数
    /// - `policy_id`：策略 ID
    ///
    /// # 错误
    /// - 策略不存在：`GarrisonError::InvalidParam`
    pub async fn unload_policy(&self, policy_id: &str) -> GarrisonResult<()> {
        let policy_id = PolicyId::new(policy_id);
        let mut policies = self.policies.write().await;
        policies
            .remove_static(policy_id)
            .map_err(|e| GarrisonError::InvalidParam(format!("abac-cedar-policy-delete::{}", e)))?;
        // 策略变更后清空决策缓存（移除策略可能改变现有 key 的决策）；
        // 在写锁范围内递增策略代数（同 load_policy）
        self.policy_generation.fetch_add(1, Ordering::Release);
        self.cache.clear().await.map_err(|e| {
            GarrisonError::InvalidParam(format!("abac-decision-cache-clear::{}", e))
        })?;
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
    /// - 任一策略语法错误：`GarrisonError::InvalidParam`（不部分加载）
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
        // 策略集原子替换后清空决策缓存（新策略集可能改变现有 key 的决策）
        // 仅在替换成功后执行；任一策略解析失败时提前 return Err，不会到达此处。
        // 在写锁范围内递增策略代数（同 load_policy）
        self.policy_generation.fetch_add(1, Ordering::Release);
        self.cache.clear().await.map_err(|e| {
            GarrisonError::InvalidParam(format!("abac-decision-cache-clear::{}", e))
        })?;
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
    /// - EntityUid/Context/Request 解析失败：`GarrisonError::InvalidParam`
    /// - 临时策略语法错误：`GarrisonError::InvalidParam`
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
        // 共享求值 helper（与 evaluate 复用同一诊断/fail-closed 逻辑）。
        // evaluate_with_temp_policy 不写入缓存，错误通过 ? 传播。
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
    /// `evaluate` 与 `evaluate_with_temp_policy` 原本各自维护一份重复的
    /// 构建/求值/诊断逻辑，
    /// 抽取至此单点维护。
    ///
    /// # Cedar 诊断错误的 fail-closed 处理
    ///
    /// Cedar `is_authorized` 在策略内部求值出错（schema 不匹配、类型错误、运行时
    /// 错误）时仍可能返回 `Allow`。原实现仅记录 warn 后照常采用 `response.decision()`，
    /// 把策略求值故障静默转换为 Allow（fail-open）。修复：诊断含错误时逐条 warn 记录，
    /// 并统一返回 `Decision::deny(DecisionReason::EvaluationError)`（fail-closed 默认拒绝）。
    ///
    /// # 返回
    /// - `(Decision, has_eval_errors)`：`has_eval_errors` 为 true 表示诊断含错误，
    ///   决策为 fail-closed 拒绝；调用方不得将该决策写入缓存（瞬态故障不钉死 TTL）。
    ///
    /// # 错误
    /// - EntityUid/Context/Request 解析失败：`GarrisonError::InvalidParam`
    /// - EntityLoader 加载失败：透传（不污染缓存，调用方未到达写入路径）
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
        // 通过 EntityLoader 加载实体。若返回错误，通过 ? 传播，缓存不受污染。
        let entities = self.entity_loader.load_entities().await?;
        let response = self.authorizer.is_authorized(&request, policies, &entities);

        // 记录 Cedar 诊断错误（原代码丢弃了 diagnostics errors）
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

        // 诊断含错误时默认拒绝（fail-closed），绝不采用 Cedar 的
        // Allow——策略求值故障（schema/类型/运行时错误）必须显性化为 Deny + 日志告警，
        // 而非静默放行。
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
                // 区分显式 forbid 策略匹配与隐式 deny（无策略匹配）
                // diagnostics.reasons() 返回匹配的 policy ID；有匹配说明是 forbid 策略生效
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

    /// 测试辅助：判断指定 (principal, action, resource) 决策是否已在缓存中（无 context）。
    ///
    /// 使用 oxcache `get()` 而非 `len()`：oxcache `len()` 是
    /// 最终一致估算值，写入后未必立即可见；`get()` 强制检索 key，可靠。
    async fn cache_has_entry(
        engine: &AbacEngine,
        principal: &str,
        action: &str,
        resource: &str,
    ) -> bool {
        let key = DecisionKey(
            principal.to_string(),
            action.to_string(),
            resource.to_string(),
            context_key_component(None),
        );
        engine.cache.get(&key).await.unwrap_or(None).is_some()
    }

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

    /// AbacEngine::new 从 JSON schema 初始化成功。
    #[tokio::test]
    async fn t121_new_from_json_schema_success() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader)).await;
        assert!(engine.is_ok(), "AbacEngine::new 应成功: {:?}", engine.err());
    }

    /// 无效 JSON schema 返回 InvalidParam。
    #[tokio::test]
    async fn t121_new_invalid_schema_returns_invalid_param() {
        let result = AbacEngine::new("not a valid json", Arc::new(EmptyEntityLoader)).await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "应为 InvalidParam"
        );
    }

    /// evaluate — 匹配 permit 策略时返回 Allow。
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

    /// evaluate — 不匹配 permit 策略时返回 Deny（默认拒绝）。
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

    /// evaluate — 无策略时默认 Deny。
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

    /// evaluate — 无效 principal 格式返回 InvalidParam。
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

    /// Decision 映射 — Cedar Allow → Decision::allow()。
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

    /// Decision 映射 — Cedar Deny → Decision::deny()。
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

    /// forbid 策略覆盖 permit — Cedar 语义验证。
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

    /// evaluate 带 context JSON 不报错。
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

    /// 策略语法错误返回 InvalidParam。
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

    /// unload_policy 删除策略后求值变化。
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

    /// reload_all 原子替换全部策略。
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

    /// 并发求值不阻塞（RwLock 读写分离验证）。
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
    // evaluate_with_temp_policy 测试
    // ============================================================

    /// evaluate_with_temp_policy — 匹配的临时策略返回 Allow。
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

    /// evaluate_with_temp_policy — 不匹配的临时策略返回 Deny。
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

    /// evaluate_with_temp_policy — 无效策略返回 InvalidParam。
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

    /// evaluate_with_temp_policy — 不修改共享策略集。
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

    /// evaluate_with_temp_policy — 带 when 条件的策略。
    #[tokio::test]
    async fn t139_evaluate_with_temp_policy_when_condition() {
        let engine = AbacEngine::new(SCHEMA_JSON, Arc::new(EmptyEntityLoader))
            .await
            .expect("schema valid");
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
    // ABAC 决策缓存 oxcache TTL 60s 测试
    // ============================================================

    /// 同 key 两次 evaluate，第二次命中缓存（len == 1）。
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

    /// 不同 key 两次 evaluate，缓存各存一条（len == 2）。
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

    /// unload_policy 后缓存失效（len == 0）。
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

    /// reload_all 成功后缓存失效（len == 0）。
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

    /// reload_all 失败时缓存保持不变（不失效）。
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

    /// load_policy 后缓存失效（新策略可能改变现有 key 的决策）。
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

    /// evaluate_with_temp_policy 不写入缓存。
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

    // ============================================================
    // EntityLoader 集成测试
    // 验证带属性的实体能被 ABAC 策略正确求值
    // ============================================================

    /// 带属性实体集合的 Cedar schema：User 带 id 属性，Resource 带 owner 属性。
    ///
    /// 策略 `resource.owner == principal.id` 需访问实体属性，
    /// 必须通过 EntityLoader 提供带属性的 Entities 才能正确求值。
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

    /// StaticEntityLoader + 带属性实体 + `resource.owner == principal.id` 策略应 Allow（属性匹配）。
    /// 通过 EntityLoader 注入带属性实体，策略能正确求值。
    #[tokio::test]
    async fn test_evaluate_with_static_entity_loader_attribute_based_policy() {
        // 构造带属性的实体：User "alice" {id: "alice"}, Resource "doc1" {owner: "alice"}。
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

    /// EntityLoader 返回错误时，evaluate 通过 ? 传播错误，缓存不污染。
    /// 若 load_entities 失败（如数据源不可达），错误必须显式传播，禁止默认成功。
    #[tokio::test]
    async fn test_evaluate_with_entity_loader_error_propagates() {
        /// 总是返回错误的 EntityLoader（模拟数据源不可达）。
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

    // ============================================================
    // context 参与缓存 key
    // ============================================================

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

    /// 同三元组不同 context 不得共享缓存：context.level 敏感策略按各自 context 正确求值。
    ///
    /// 修复前：key 仅 (principal, action, resource)，`level=5` 的 Allow 决策会被
    /// `level=1` 的请求命中（返回错误的 Allow）。修复后：context 摘要参与 key。
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

    /// invalidate_entities 清空决策缓存。
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

    // ============================================================
    // Cedar 诊断错误 fail-closed
    // ============================================================

    /// Cedar 求值诊断错误时必须 fail-closed 拒绝（不得采用 Cedar 的 Allow）。
    ///
    /// 策略访问实体属性（`resource.owner`），但 EmptyEntityLoader 返回空实体集合，
    /// Cedar 求值产生诊断错误（实体不存在）。修复前：仅 warn 后采用 decision
    /// （可能 Allow，fail-open）；修复后：统一返回 deny(EvaluationError)。
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
