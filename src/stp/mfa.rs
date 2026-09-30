// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! MFA/step-up 编排基座。
//!
//! 核心组件：[`MfaLogic`] trait（二级认证与账号禁用校验契约）、会话因子
//! 账本（[`AmrEntry`] → RFC 8176 amr / auth_time claim 映射）、per-client
//! MFA chain 三态（[`validate_mfa_chains`]）、新鲜度断言、
//! [`RequiredActionProvider`] 三段式（TOTP / WebAuthn）、恢复码管理器
//! （mfa-recovery feature）与 MFA remember cookie。

use super::current_token;
use super::GarrisonLogicDefault;
#[cfg(feature = "protocol-jwt")]
use crate::config::GarrisonConfig;
use crate::constants::DaoKeyPrefix;
#[cfg(feature = "protocol-jwt")]
use crate::context::{build_set_cookie_value, CookieType};
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::stp::session::SessionLogic;
use async_trait::async_trait;
use std::sync::Arc;

/// MFA 逻辑 trait，定义二级认证与账号禁用校验契约。
///
/// 对应 `StpLogic` 的 `checkSafe` / `checkDisable` 部分。
///
/// # 默认实现
///
/// - [`check_safe`](Self::check_safe)：默认调用 `is_safe("default")`，未通过时返回
/// `Err(NotSafe("SAFE_EXPIRED"))`；未覆写 `is_safe` 时返回 `Ok(())`（视为已通过）。
/// - [`check_disable`](Self::check_disable)：默认返回 `Ok(())`（未实现禁用账号库）。
/// 业务方覆写以查询当前 login_id 是否在禁用列表中。
#[async_trait]
pub trait MfaLogic: SessionLogic {
    /// 检查二级认证（MFA）状态。
    ///
    /// 默认实现调用 `is_safe("default")` 检查 "default" service 的二级认证状态：
    /// - `Ok(true)` → 返回 `Ok(())`
    /// - `Ok(false)` → 返回 `Err(Self::not_safe("SAFE_EXPIRED"))`
    /// - `Err(e)` → 透传错误
    ///
    /// 未覆写 `is_safe` 的实现者（如未启用 `safe-auth` feature 时），
    /// `is_safe` 默认返回 `Ok(true)`，因此 `check_safe` 返回 `Ok(())`。
    ///
    /// # 返回
    /// - `Ok(())`: 已通过二级认证或未启用 MFA。
    /// - `Err(GarrisonError::NotSafe)`: 未通过二级认证（service 未开启或已过期）。
    async fn check_safe(&self) -> GarrisonResult<()> {
        self.check_mfa_chain(None).await?;
        if !self.is_safe("default").await? {
            return Err(Self::not_safe("SAFE_EXPIRED"));
        }
        Ok(())
    }

    /// 校验 per-client MFA 强制链覆盖（MFA 编排的 gate 入口）。
    ///
    /// 配置了强制链（`mfa.global_chain` / per-client 覆盖）时，当前会话的
    /// 因子账本必须覆盖全部强制 factor（otp/webauthn → 同名 amr），否则返回
    /// `NotSafe { reason: "MFA_CHAIN_INCOMPLETE::<factor>" }`。
    /// [`check_safe`](Self::check_safe) 默认先执行本检查再走 safe-service
    /// 逻辑——authflow 的 Mfa 步骤与 `/auth/check-safe` 端点经此路径自动
    /// 获得链强制；challenge 的产出与完成由
    /// [`RequiredActionProvider`](crate::stp::mfa::RequiredActionProvider)
    /// 承载（业务侧编排 provider 并经
    /// [`GarrisonSession::append_amr_entry`](crate::session::GarrisonSession::append_amr_entry)
    /// 升级账本）。
    ///
    /// # 参数
    /// - `client_id`: 请求上下文中的客户端标识；`None` 时按全局默认链判定。
    ///
    /// # 默认实现
    /// `Ok(())`（未覆写的实现者无链强制）。
    async fn check_mfa_chain(&self, _client_id: Option<&str>) -> GarrisonResult<()> {
        Ok(())
    }

    /// 检查账号是否被禁用。
    ///
    /// trait 默认实现返回 `Ok(())`（不查询禁用账号库）；`GarrisonLogicDefault` 覆写：
    /// 从当前 token 取 login_id 并查询封禁状态，被封禁则返回
    /// `DisableService` 错误。未登录时返回 `Ok(())`。
    ///
    /// # 返回
    /// - `Ok(())`: 账号未禁用 / 未登录。
    /// - `Err(GarrisonError::DisableService)`: 账号已封禁（推荐使用专用异常）。
    async fn check_disable(&self) -> GarrisonResult<()> {
        Ok(())
    }

    /// 开启指定 service 的二级认证（瞬态标记）。
    ///
    /// 在当前 TokenSession 的 `safe_services` 中记录 service → 过期时间戳。
    /// 调用后 `is_safe(service)` 在过期前返回 `true`。
    ///
    /// # 参数
    /// - `service`: 服务名称（如 "default" / "payment"）。
    /// - `duration_secs`: 有效时长（秒）；过期后 `is_safe` 返回 `false`。
    ///
    /// # 返回
    /// - `Ok(())`: 成功开启。
    /// - `Err`: 未登录或 session 不存在。
    ///
    /// # 默认实现
    /// 返回 `Ok(())`（no-op）。
    /// `safe-auth` feature 启用时由 `GarrisonLogicDefault` 覆写为真实实现；
    /// 未启用时二级认证标记能力不可用，此默认实现维持接口完整。
    async fn open_safe(&self, _service: &str, _duration_secs: u64) -> GarrisonResult<()> {
        Ok(())
    }

    /// 检查指定 service 是否处于二级认证有效期内。
    ///
    /// # 参数
    /// - `service`: 服务名称。
    ///
    /// # 返回
    /// - `Ok(true)`: service 已开启且未过期。
    /// - `Ok(false)`: service 未开启或已过期。
    ///
    /// # 默认实现
    /// 返回 `Ok(true)`（默认视为已通过二级认证）。
    /// `safe-auth` feature 启用时由 `GarrisonLogicDefault` 覆写为真实实现。
    async fn is_safe(&self, _service: &str) -> GarrisonResult<bool> {
        Ok(true)
    }

    /// 关闭指定 service 的二级认证（移除瞬态标记）。
    ///
    /// # 参数
    /// - `service`: 服务名称。
    ///
    /// # 返回
    /// - `Ok(())`: 成功关闭（或 service 本就未开启，幂等）。
    /// - `Err`: 未登录或 session 不存在。
    ///
    /// # 默认实现
    /// 返回 `Ok(())`（no-op）。
    /// `safe-auth` feature 启用时由 `GarrisonLogicDefault` 覆写为真实实现；
    /// 未启用时二级认证标记能力不可用，此默认实现维持接口完整。
    async fn close_safe(&self, _service: &str) -> GarrisonResult<()> {
        Ok(())
    }

    /// 构造账号被封禁异常。
    ///
    /// 业务方在自定义 `check_disable` 实现中调用此关联函数抛出专用异常：
    ///
    /// ```ignore
    /// async fn check_disable(&self) -> GarrisonResult<()> {
    /// if account_is_banned().await {
    /// return Err(Self::disable_service("default", None));
    /// }
    /// Ok(())
    /// }
    /// ```
    ///
    /// # 参数
    /// - `service`: 被封禁的服务名（如 "default" / "oidc"）。
    /// - `until`: 定时解封时间；`None` 表示永久封禁。
    fn disable_service(
        service: &str,
        until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> GarrisonError {
        GarrisonError::DisableService {
            service: service.to_string(),
            until,
        }
    }

    /// 构造未完成二次认证异常。
    ///
    /// 业务方在自定义 `check_safe` 实现中调用此关联函数抛出专用异常：
    ///
    /// ```ignore
    /// async fn check_safe(&self) -> GarrisonResult<()> {
    /// if !mfa_completed().await {
    /// return Err(Self::not_safe("MFA_TOTP_REQUIRED"));
    /// }
    /// Ok(())
    /// }
    /// ```
    ///
    /// # 参数
    /// - `reason`: 未完成认证的原因标识（如 "MFA_TOTP_REQUIRED" / "WEBAUTHN_REQUIRED"）。
    fn not_safe(reason: &str) -> GarrisonError {
        GarrisonError::NotSafe {
            reason: reason.to_string(),
        }
    }
}

// ============================================================================
// MFA 编排基座：因子账本
// ============================================================================

/// chain 可引用的 factor 词汇表（强制集合语义；pwd 是主因子不参与 chain）。
pub const KNOWN_CHAIN_FACTORS: &[&str] = &["otp", "webauthn"];

/// 校验 MFA chain 配置：引用词汇表之外的 factor 时返回 `GarrisonError::Config`
/// （fail-closed，启动期拒绝，不降级放行）。
///
/// # 参数
/// - `global_chain`: 全局默认链。
/// - `per_client_chains`: per-client 覆盖表（空集覆盖 = 显式禁用，合法）。
///
/// # 错误
/// - 任一链引用 [`KNOWN_CHAIN_FACTORS`] 之外的 factor：
///   `GarrisonError::Config("config-mfa-chain-factor-unknown::{factor}")`
pub fn validate_mfa_chains(
    global_chain: &[String],
    per_client_chains: &std::collections::HashMap<String, Vec<String>>,
) -> GarrisonResult<()> {
    for factor in global_chain {
        if !KNOWN_CHAIN_FACTORS.contains(&factor.as_str()) {
            return Err(GarrisonError::Config(format!(
                "config-mfa-chain-factor-unknown::{factor}"
            )));
        }
    }
    for chains in per_client_chains.values() {
        for factor in chains {
            if !KNOWN_CHAIN_FACTORS.contains(&factor.as_str()) {
                return Err(GarrisonError::Config(format!(
                    "config-mfa-chain-factor-unknown::{factor}"
                )));
            }
        }
    }
    Ok(())
}

/// chain factor → amr method 映射（gate 校验用）。
///
/// 词汇表外的 factor 返回 `None`：启动校验（`validate_mfa_chains`）会拒绝
/// 其入配置，此处兜底按未满足处理（fail-closed，不静默放行）。
pub fn chain_factor_amr(factor: &str) -> Option<&'static str> {
    match factor {
        "otp" => Some("otp"),
        "webauthn" => Some("webauthn"),
        _ => None,
    }
}

/// 强制链覆盖判定：返回账本未满足的首个强制 factor。
///
/// - [`MfaChainDecision::None`] → `None`（无强制，一律满足）；
/// - [`MfaChainDecision::Require`] → 首个在账本中没有对应 amr 条目的 factor
///   （词汇表外 factor 恒视为未满足）。
///
/// 供 gate 路径（`check_mfa_chain`）把三态决策落到会话账本上。
pub fn first_unmet_chain_factor(
    decision: &MfaChainDecision,
    ledger: &[AmrEntry],
) -> Option<String> {
    let MfaChainDecision::Require(factors) = decision else {
        return None;
    };
    factors
        .iter()
        .find(|f| match chain_factor_amr(f) {
            Some(amr) => !ledger.iter().any(|e| e.method == amr),
            None => true,
        })
        .cloned()
}

/// per-client MFA chain 的生效决策（三态语义的解析结果）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MfaChainDecision {
    /// 该 client 无 MFA 强制要求（继承全局后为空，或被空集显式禁用）。
    None,
    /// 该 client 必须完成集合内的 factor（任意顺序，全部完成或按 provider 语义）。
    Require(Vec<String>),
}

/// 解析 per-client MFA chain 三态：
///
/// - `None`（覆盖表无该 client）→ 回退全局默认链（空则 [`MfaChainDecision::None`]）；
/// - `Some(空集)` → 显式禁用：即使全局有默认链也不强制（[`MfaChainDecision::None`]）；
/// - `Some(非空)` → 强制该集合（[`MfaChainDecision::Require`]）。
pub fn resolve_mfa_chain(
    per_client: Option<&Vec<String>>,
    global_chain: &[String],
) -> MfaChainDecision {
    match per_client {
        None => {
            if global_chain.is_empty() {
                MfaChainDecision::None
            } else {
                MfaChainDecision::Require(global_chain.to_vec())
            }
        },
        Some(chain) if chain.is_empty() => MfaChainDecision::None,
        Some(chain) => MfaChainDecision::Require(chain.clone()),
    }
}

// ============================================================================
// 新鲜度断言与 Required Action 三段式（evaluate → challenge → process）
// ============================================================================

/// step-up 新鲜度门槛：auth_time 窗口与最低 AAL 要求。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MfaFreshness {
    /// `auth_time` 允许的最大年龄（秒）；超过即视为过期会话。
    pub max_age_secs: i64,
    /// 账本最高 AAL 必须达到的等级。
    pub min_aal: u8,
}

/// 新鲜度断言的输入快照。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessInput {
    /// 会话 `auth_time`（主认证时刻；`None` = 历史会话，fail-closed 视为过期）。
    pub auth_time: Option<i64>,
    /// 因子账本最高 AAL。
    pub ledger_max_aal: u8,
    /// 当前时刻（Unix 秒）。
    pub now: i64,
}

/// 新鲜度断言结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessVerdict {
    /// 会话新鲜：免二次 challenge。
    Fresh,
    /// 会话过期或 AAL 不足：触发 Required Action。
    Stale,
}

/// 新鲜度断言（step-up 判定核心）。
///
/// 新鲜 = `auth_time` 存在且 `now - auth_time <= max_age_secs` **且**
/// 账本最高 AAL ≥ `min_aal`。任一不满足 → [`FreshnessVerdict::Stale`]。
pub fn assert_freshness(input: &FreshnessInput, threshold: &MfaFreshness) -> FreshnessVerdict {
    let Some(auth_time) = input.auth_time else {
        return FreshnessVerdict::Stale;
    };
    if input.now - auth_time > threshold.max_age_secs {
        return FreshnessVerdict::Stale;
    }
    if input.ledger_max_aal < threshold.min_aal {
        return FreshnessVerdict::Stale;
    }
    FreshnessVerdict::Fresh
}

/// step-up 总判定：新鲜度断言 + MFA remember cookie 豁免。
///
/// 有效 remember cookie（HMAC/JWT 绑定 stage + credential_id + exp）视为
/// 「本设备近期已完成该 stage」，压过过期会话的重复 challenge。
pub fn stepup_required(
    input: &FreshnessInput,
    threshold: &MfaFreshness,
    remember_cookie_valid: bool,
) -> bool {
    !remember_cookie_valid && assert_freshness(input, threshold) == FreshnessVerdict::Stale
}

/// Required Action 上下文（provider 三段式的共享输入快照）。
#[derive(Debug, Clone)]
pub struct RequiredActionContext {
    /// 登录主体标识。
    pub login_id: String,
    /// 会话 `auth_time`（Unix 秒；`None` = 历史会话）。
    pub auth_time: Option<i64>,
    /// 因子账本最高 AAL。
    pub ledger_max_aal: u8,
    /// 当前时刻（Unix 秒）。
    pub now: i64,
}

impl RequiredActionContext {
    /// 构造新鲜度断言输入。
    pub fn freshness_input(&self) -> FreshnessInput {
        FreshnessInput {
            auth_time: self.auth_time,
            ledger_max_aal: self.ledger_max_aal,
            now: self.now,
        }
    }
}

/// Required Action 挑战载荷（challenge 段的产出）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredActionChallenge {
    /// 动作标识（如 `"otp"`），客户端据此渲染对应 UI。
    pub action: String,
    /// 挑战载荷（TOTP 为静态提示；WebAuthn 为服务器 challenge）。
    pub payload: String,
}

/// process 段的验证结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcome {
    /// 验证成功：账本按 (method, aal) 升级。
    Verified {
        /// 升级账本使用的 amr method。
        method: &'static str,
        /// 升级到的 AAL。
        aal: u8,
    },
    /// 验证失败：账本不变。
    Rejected,
}

/// Required Action provider 三段式契约（evaluate → challenge → process）。
///
/// 对齐 authentik `AuthenticatorValidateStageView` 的
/// 「判定 → 出挑战 → 验响应」编排，拆为三个独立步骤：
/// - [`evaluate`](Self::evaluate)：该动作对当前会话是否必需（新鲜度/AAL 门槛）；
/// - [`challenge`](Self::challenge)：产出客户端可响应的挑战；
/// - [`process`](Self::process)：校验响应；成功后由调用方经
///   [`complete_required_action`] 升级账本（provider 不直接持有会话）。
#[async_trait]
pub trait RequiredActionProvider: Send + Sync {
    /// 动作唯一标识（如 `"otp"` / `"webauthn"`）。
    fn action_id(&self) -> &'static str;

    /// 判定该动作对当前会话是否必需。
    ///
    /// # 参数
    /// - `ctx`: 会话快照。
    /// - `threshold`: step-up 新鲜度门槛。
    async fn evaluate(
        &self,
        ctx: &RequiredActionContext,
        threshold: &MfaFreshness,
    ) -> GarrisonResult<bool>;

    /// 产出挑战载荷。
    async fn challenge(
        &self,
        ctx: &RequiredActionContext,
    ) -> GarrisonResult<RequiredActionChallenge>;

    /// 校验客户端响应。
    ///
    /// # 参数
    /// - `ctx`: 会话快照。
    /// - `response`: 客户端提交的验证材料（验证码 / authenticator 断言）。
    /// - `dao`: DAO（重放防护等原子记录用）。
    async fn process(
        &self,
        ctx: &RequiredActionContext,
        response: &str,
        dao: &dyn GarrisonDao,
    ) -> GarrisonResult<ProcessOutcome>;
}

/// process 验证成功后的账本升级（编排收口：provider 只判结果，会话写入在此）。
///
/// `Verified` → 追加 `AmrEntry{method, aal, completed_at}`；`Rejected` → no-op
/// （账本不变）。
pub async fn complete_required_action(
    session: &crate::session::GarrisonSession,
    token: &str,
    outcome: &ProcessOutcome,
    completed_at: i64,
) -> GarrisonResult<()> {
    let ProcessOutcome::Verified { method, aal } = outcome else {
        return Ok(());
    };
    session
        .append_amr_entry(token, method, *aal, completed_at)
        .await
}

/// 签发路径允许写入账本的 amr method 词汇表（RFC 8176 已登记值）。
///
/// 账本条目 `method` 只接受本表内的值：账本是 amr claim 的权威来源，
/// 词汇表外的值入账会让签发载荷携带未登记的认证方法引用。
pub const AMR_METHODS: &[&str] = &["pwd", "otp", "webauthn"];

/// 主登录因子对应的 amr method（本框架 `login` 即主认证，约定为密码认证）。
pub const PRIMARY_FACTOR_AMR: &str = "pwd";

/// 主登录因子授予的认证保证等级（密码单因子 = AAL 1）。
pub const PRIMARY_FACTOR_AAL: u8 = 1;

/// 因子账本条目：一次完成的认证步骤在会话内的权威记录。
///
/// - `method`：RFC 8176 amr 值（[`AMR_METHODS`] 词汇表内）
/// - `aal`：该步骤授予的认证保证等级（1..=3）
/// - `completed_at`：完成时刻（Unix 秒）
///
/// 账本随 [`crate::session::TokenSession`] 持久化，签发 token 时映射为
/// RFC 8176 `amr` claim（完成顺序去重）与 OIDC `auth_time` claim。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AmrEntry {
    /// 认证方法（RFC 8176 amr 值）。
    pub method: String,
    /// 该步骤授予的认证保证等级（1..=3）。
    pub aal: u8,
    /// 完成时刻（Unix 秒）。
    pub completed_at: i64,
}

impl AmrEntry {
    /// 构造账本条目并校验词汇表 / AAL 边界。
    ///
    /// # 错误
    /// - `method` 不在 [`AMR_METHODS`]：`GarrisonError::InvalidParam`
    /// - `aal` 不在 1..=3：`GarrisonError::InvalidParam`
    pub fn new(method: impl Into<String>, aal: u8, completed_at: i64) -> GarrisonResult<Self> {
        let method = method.into();
        if !AMR_METHODS.contains(&method.as_str()) {
            return Err(GarrisonError::InvalidParam(format!(
                "mfa-amr-method-unknown::{method}::allowed={:?}",
                AMR_METHODS
            )));
        }
        if !(1..=3).contains(&aal) {
            return Err(GarrisonError::InvalidParam(format!(
                "mfa-aal-out-of-range::{aal}::allowed=1..=3"
            )));
        }
        Ok(Self {
            method,
            aal,
            completed_at,
        })
    }
}

/// 主登录签发的 claim 映射输入（主因子 amr + 认证时刻的单一口径）。
///
/// stp `generate_token` 与 `AuthLogic` 的 login 共用：主登录即密码认证，
/// 签发载荷携带 `amr=["pwd"]` 与 `auth_time=签发时刻`（与会话账本播种同源）。
/// 续签/换签路径不得使用本函数——应从会话账本映射（[`amr_claim`] +
/// `TokenSession.auth_time`），保证 token claim 与账本一致不凭空消失。
pub fn primary_issuance_claims(now: i64) -> (Vec<String>, Option<i64>) {
    (vec![PRIMARY_FACTOR_AMR.to_string()], Some(now))
}

/// 因子账本 → RFC 8176 `amr` claim：按完成顺序输出、method 去重保序。
///
/// RFC 8176 的 amr 为字符串数组；同一方法多次完成（如多次 step-up）
/// 对 rp 而言只表达一种方法引用，去重保序保证 claim 确定性。
pub fn amr_claim(entries: &[AmrEntry]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    entries
        .iter()
        .filter(|e| seen.insert(e.method.clone()))
        .map(|e| e.method.clone())
        .collect()
}

/// 因子账本的最高认证保证等级；空账本为 0（未完成任何认证步骤）。
pub fn ledger_max_aal(entries: &[AmrEntry]) -> u8 {
    entries.iter().map(|e| e.aal).max().unwrap_or(0)
}

// ============================================================================
// TOTP Required Action provider（复用既有 TOTP 设施）
// ============================================================================

/// TOTP Required Action provider：evaluate 依新鲜度门槛判定、challenge 产出
/// 静态提示、process 委托 [`TotpHandler::validate_and_consume`]（DAO 原子防重放）。
///
/// secret 由集成方按 login_id 查询凭证库后构造 provider（或为其注入查询回调）；
/// 本基座只承载三段式编排，不做凭证存储。
#[cfg(feature = "secure-totp")]
pub struct TotpRequiredActionProvider {
    /// Base32 编码的 TOTP 密钥。
    secret_base32: String,
}

#[cfg(feature = "secure-totp")]
impl TotpRequiredActionProvider {
    /// 构造 provider。
    ///
    /// # 参数
    /// - `secret_base32`: Base32 编码的 TOTP 密钥（与凭证库 `secret_data` 同口径）。
    pub fn new(secret_base32: impl Into<String>) -> Self {
        Self {
            secret_base32: secret_base32.into(),
        }
    }

    /// 生成当前时刻的验证码（测试/便捷用途）。
    pub fn generate_current_code(&self, now: i64) -> GarrisonResult<String> {
        self.handler()?.generate(now)
    }

    /// 从 Base32 密钥构造 [`TotpHandler`]（默认 step=30 / digits=6，与
    /// [`crate::account::credential::totp::TotpCredential`] 默认口径一致）。
    fn handler(&self) -> GarrisonResult<crate::secure::totp::TotpHandler> {
        let secret = crate::secure::totp::TotpHandler::secret_from_base32(&self.secret_base32)?;
        crate::secure::totp::TotpHandler::new(secret, 30, 6)
    }
}

#[cfg(feature = "secure-totp")]
#[async_trait]
impl RequiredActionProvider for TotpRequiredActionProvider {
    fn action_id(&self) -> &'static str {
        "otp"
    }

    async fn evaluate(
        &self,
        ctx: &RequiredActionContext,
        threshold: &MfaFreshness,
    ) -> GarrisonResult<bool> {
        Ok(assert_freshness(&ctx.freshness_input(), threshold) == FreshnessVerdict::Stale)
    }

    async fn challenge(
        &self,
        _ctx: &RequiredActionContext,
    ) -> GarrisonResult<RequiredActionChallenge> {
        Ok(RequiredActionChallenge {
            action: self.action_id().to_string(),
            payload: "totp:enter-code".to_string(),
        })
    }

    async fn process(
        &self,
        ctx: &RequiredActionContext,
        response: &str,
        dao: &dyn GarrisonDao,
    ) -> GarrisonResult<ProcessOutcome> {
        let handler = self.handler()?;
        let ok = handler
            .validate_and_consume(&ctx.login_id, response, ctx.now, dao)
            .await?;
        if ok {
            Ok(ProcessOutcome::Verified {
                method: "otp",
                aal: 2,
            })
        } else {
            Ok(ProcessOutcome::Rejected)
        }
    }
}

// ============================================================================
// WebAuthn Required Action provider（protocol-webauthn feature）
// ============================================================================

/// WebAuthn 二次认证 Required Action provider。
///
/// `process` 调 R07 service 认证仪式（经 [`webauthn_factor`] 进程级注册表
/// 取校验函数）：用户绑定由仪式自身承载——`start_authentication(tenant,
/// user)` 将 tenant/user 写入 challenge payload，`finish` 从 payload 取出
/// （不信任请求重传）。未注册校验函数时 `process` 显性报错（装配方漏接
/// 线不静默降级为通过）。
#[cfg(feature = "protocol-webauthn")]
pub struct WebauthnRequiredActionProvider;

#[cfg(feature = "protocol-webauthn")]
#[async_trait]
impl RequiredActionProvider for WebauthnRequiredActionProvider {
    fn action_id(&self) -> &'static str {
        "webauthn"
    }

    async fn evaluate(
        &self,
        ctx: &RequiredActionContext,
        threshold: &MfaFreshness,
    ) -> GarrisonResult<bool> {
        Ok(assert_freshness(&ctx.freshness_input(), threshold) == FreshnessVerdict::Stale)
    }

    /// 挑战契约说明：WebAuthn 的真实协议挑战（server challenge →
    /// authenticator assertion）不在此产出——trait 的 `challenge` 仅为
    /// 客户端 UI 提示；真实挑战由编排方经 `webauthn_factor().service()`
    /// 的 `start_authentication` 获取（用户绑定写于 challenge payload），
    /// `process` 消费 assertion JSON。该分工对有状态挑战 provider（邮件
    /// OTP 等）不适用，届时应扩展 trait 而非复用本形态。
    async fn challenge(
        &self,
        _ctx: &RequiredActionContext,
    ) -> GarrisonResult<RequiredActionChallenge> {
        Ok(RequiredActionChallenge {
            action: self.action_id().to_string(),
            payload: "webauthn:use-passkey".to_string(),
        })
    }

    async fn process(
        &self,
        ctx: &RequiredActionContext,
        response: &str,
        _dao: &dyn GarrisonDao,
    ) -> GarrisonResult<ProcessOutcome> {
        let verifier = webauthn_factor::webauthn_factor().ok_or_else(|| {
            GarrisonError::Config("mfa-webauthn-factor-not-registered::".to_string())
        })?;
        // response 为浏览器 WebAuthn API 产出的 PublicKeyCredential JSON
        let assertion: webauthn_rs::prelude::PublicKeyCredential = serde_json::from_str(response)
            .map_err(|e| {
            GarrisonError::InvalidParam(format!("mfa-webauthn-assertion-parse::{e}"))
        })?;
        let auth = verifier.verify_second_factor(&assertion).await?;
        // 仪式锁定的用户绑定必须与当前会话主体一致——跨用户 assertion
        // （攻击者用自己的 passkey 完成他人 step-up）在此显性拒绝
        if auth.user_id != ctx.login_id {
            return Err(GarrisonError::InvalidParam(format!(
                "mfa-webauthn-subject-mismatch::asserted-for={}::session={}",
                auth.user_id, ctx.login_id
            )));
        }
        Ok(ProcessOutcome::Verified {
            method: "webauthn",
            aal: 2,
        })
    }
}

#[cfg(feature = "protocol-webauthn")]
#[cfg(test)]
mod webauthn_provider_tests {
    use super::*;

    /// 未注册校验函数时 process 显性报错（不静默降级为通过）。
    ///
    /// 注册表为进程级共享状态：与 `webauthn_factor::tests` 的注册测试经
    /// `serial` 串行化，且本测试先重置保证前置条件自管（顺序无关）。
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn process_without_registered_verifier_fails_closed() {
        webauthn_factor::reset_webauthn_factor_for_tests();
        let provider = WebauthnRequiredActionProvider;
        let ctx = RequiredActionContext {
            login_id: "user-wn-provider".to_string(),
            auth_time: None,
            ledger_max_aal: 1,
            now: 1_700_000_000,
        };
        let result = provider
            .process(&ctx, "{}", &crate::dao::InMemoryDao::new())
            .await;
        assert!(
            matches!(result, Err(GarrisonError::Config(ref m)) if m.contains("not-registered")),
            "未注册校验函数应 fail-closed，实际: {result:?}"
        );
    }
}

// ============================================================================
// 恢复码：批量一次性生成 / verify-consume 分离 / CAS 原子消费 / 误用容忍
// ============================================================================
#[cfg(feature = "mfa-recovery")]
/// 恢复码 verify 结论。
#[cfg(feature = "mfa-recovery")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryVerify {
    /// 码存在且未使用。
    Valid,
    /// 码不存在或已使用（计一次误用）。
    Invalid,
    /// 误用次数超过豁免额度，已锁定（fail-closed，正确码也拒绝）。
    Locked,
}

/// 恢复码管理器：verify（校验）与 consume（置已用）分离。
///
/// 存储布局（DAO，无新表）：
/// - `mfa:recovery:{login_id}:{code}` → `"unused"` / `"used"`
/// - `mfa:recovery:misuse:{login_id}` → 误用计数（原子 `incr`）
///
/// 并发竞态（verify 与 consume 之间、并发 consume 之间）由
/// [`GarrisonDao::compare_and_swap`] 的 CAS 语义消除：置已用只在当前值为
/// `"unused"` 时成功，双花不可能发生。
pub struct RecoveryCodeManager {
    dao: Arc<dyn GarrisonDao>,
    /// 误用豁免额度（默认 0）：连续无效 verify 超过该次数即锁定。
    misuse_tolerance: u32,
}

#[cfg(feature = "mfa-recovery")]
impl RecoveryCodeManager {
    /// 恢复码存储 key 前缀。
    const KEY_PREFIX: &'static str = "recovery:";
    /// 误用计数 key 后缀。
    const MISUSE_SUFFIX: &'static str = "misuse:";

    /// 构造管理器。
    ///
    /// # 参数
    /// - `dao`: DAO 抽象（CAS 消费与误用计数）。
    /// - `misuse_tolerance`: 误用豁免额度（0 = 首次误用即锁定）。
    pub fn new(dao: Arc<dyn GarrisonDao>, misuse_tolerance: u32) -> Self {
        Self {
            dao,
            misuse_tolerance,
        }
    }

    /// 恢复码存储 key：`mfa:recovery:{len}:{login_id}:{sha256(code)}`。
    ///
    /// 两个安全约束：
    /// - **存哈希不存明文**（行业标准）：恢复码是可直接兑换登录的机密，
    ///   DAO key 泄露（keys() 枚举/转储/运维工具）不得等于泄露可用凭证；
    /// - **长度前缀分隔 login_id**：`user1` 与 `user1x` 的裸拼接存在前缀
    ///   歧义（glob `user1*` 命中他人键位），长度前缀彻底隔离键空间。
    fn code_key(&self, login_id: &str, code: &str) -> String {
        let code_hash = Self::code_hash(code);
        format!(
            "{}{}{}:{}:{}",
            DaoKeyPrefix::Mfa.as_str(),
            Self::KEY_PREFIX,
            login_id.len(),
            login_id,
            code_hash
        )
    }

    /// 恢复码哈希（SHA-256 hex；key 侧只落哈希，明文不出现在存储面）。
    fn code_hash(code: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        let result = hasher.finalize();
        result.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn misuse_key(&self, login_id: &str) -> String {
        format!(
            "{}{}{}{}",
            DaoKeyPrefix::Mfa.as_str(),
            Self::KEY_PREFIX,
            Self::MISUSE_SUFFIX,
            login_id
        )
    }

    /// 批量一次性生成恢复码（每码独立存储为未用状态）。
    ///
    /// 码取 UUID 简写形式的 10 个 hex 字符（5-5 分组），随机源为 OS CSPRNG。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `count`: 生成数量。
    ///
    /// # 错误
    /// - `count == 0` 或超过单批上限（64）：`GarrisonError::InvalidParam`
    /// - DAO 写入失败：透传
    pub async fn generate(&self, login_id: &str, count: usize) -> GarrisonResult<Vec<String>> {
        const MAX_BATCH: usize = 64;
        if count == 0 || count > MAX_BATCH {
            return Err(GarrisonError::InvalidParam(format!(
                "mfa-recovery-batch-size-invalid::{count}::allowed=1..={MAX_BATCH}"
            )));
        }
        let mut codes = Vec::with_capacity(count);
        for _ in 0..count {
            let hex = uuid::Uuid::new_v4().simple().to_string();
            let code = format!("{}-{}", &hex[..5], &hex[5..10]);
            self.dao
                .set(&self.code_key(login_id, &code), "unused", 0)
                .await?;
            codes.push(code);
        }
        Ok(codes)
    }

    /// 误用计数当前值。
    async fn misuse_count(&self, login_id: &str) -> GarrisonResult<u64> {
        match self.dao.get(&self.misuse_key(login_id)).await? {
            Some(v) => v
                .parse::<u64>()
                .map_err(|e| GarrisonError::Internal(format!("mfa-recovery-misuse-parse::{}", e))),
            None => Ok(0),
        }
    }

    /// 校验恢复码（不改状态；无效码计一次误用，超豁免即锁定）。
    ///
    /// 锁定后连 Valid 码也返回 [`RecoveryVerify::Locked`]（fail-closed）。
    pub async fn verify(&self, login_id: &str, code: &str) -> GarrisonResult<RecoveryVerify> {
        if self.misuse_count(login_id).await? > self.misuse_tolerance as u64 {
            return Ok(RecoveryVerify::Locked);
        }
        match self.dao.get(&self.code_key(login_id, code)).await? {
            Some(state) if state == "unused" => Ok(RecoveryVerify::Valid),
            // 已用码 = 已识别的重放：拒绝但不计误用（合法持有者可能重复提交；
            // 消费由 CAS 保护，重放无收益）
            Some(_) => Ok(RecoveryVerify::Invalid),
            // 不存在的码 = 猜测攻击：计一次误用，超豁免即锁定
            None => {
                // 误用计数带 24h TTL：定向 DoS（烧毁恢复码通道）与合法用户
                // 手误的代价有界——超时自动解冻（管理端重置流程 out of scope，
                // 运维处置：删除 `mfa:recovery:misuse:{login_id}` 键立即解冻）
                const MISUSE_LOCK_TTL_SECS: u64 = 24 * 60 * 60;
                let count = self
                    .dao
                    .incr(&self.misuse_key(login_id), MISUSE_LOCK_TTL_SECS)
                    .await?;
                if count > self.misuse_tolerance as u64 {
                    Ok(RecoveryVerify::Locked)
                } else {
                    Ok(RecoveryVerify::Invalid)
                }
            },
        }
    }

    /// 原子消费恢复码（CAS `unused` → `used`）。
    ///
    /// 并发消费同一码时仅一个成功；锁定状态直接拒绝（返回错误）。
    ///
    /// # 返回
    /// - `Ok(true)`：消费成功。
    /// - `Ok(false)`：码不存在或已被使用（消费失败，不计误用——并发
    ///   竞争的落败方持有的是有效码，不是滥用）。
    /// - `Err`：误用计数超限（锁定，fail-closed）或 DAO 失败。
    pub async fn consume(&self, login_id: &str, code: &str) -> GarrisonResult<bool> {
        if self.misuse_count(login_id).await? > self.misuse_tolerance as u64 {
            return Err(GarrisonError::NotSafe {
                reason: "MFA_RECOVERY_LOCKED".to_string(),
            });
        }
        self.dao
            .compare_and_swap(&self.code_key(login_id, code), Some("unused"), "used", 0)
            .await
    }

    /// 统计 login_id 名下未消费恢复码数量（管理用途）。
    ///
    /// 存储只落 `sha256(code)`（不存明文），故只能计数、不能反解码值；
    /// 明文码仅在 [`generate`](Self::generate) 返回时对调用方出现一次。
    pub async fn unconsumed_count(&self, login_id: &str) -> GarrisonResult<usize> {
        let pattern = format!(
            "{}{}{}:{}:*",
            DaoKeyPrefix::Mfa.as_str(),
            Self::KEY_PREFIX,
            login_id.len(),
            login_id
        );
        let misuse_prefix = self.misuse_key(login_id);
        let mut count = 0;
        for key in self.dao.keys(&pattern).await? {
            if key.starts_with(&misuse_prefix) {
                continue;
            }
            count += 1;
        }
        Ok(count)
    }
}

// ============================================================================
// MFA remember cookie：JWT(HS256) 绑 stage + credential_id + exp，
// Set-Cookie 经单一构建点产出
// ============================================================================

/// MFA remember cookie 载荷（吸收 authentik MFA cookie 的三绑定语义）。
///
/// 绑定三元组：`stage`（编排阶段/动作上下文）+ `credential_id`
/// （完成认证的因子凭证）+ `exp`（有效期上界）。签名密钥为部署级 secret，
/// 客户端无法伪造或跨 stage / 跨 credential 重放。
#[cfg(feature = "protocol-jwt")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MfaRememberClaims {
    /// 编排阶段标识（绑定：其他 stage 不可复用）。
    pub stage: String,
    /// 完成认证的主体（绑定：跨主体不通用——防持有式豁免退化为
    /// 「同 credential 的任意主体可复用」）。
    pub login_id: String,
    /// 完成认证的因子凭证 ID（绑定：跨 credential 不通用）。
    pub credential_id: String,
    /// 过期时刻（Unix 秒）。
    pub exp: i64,
}

/// MFA remember cookie 名（经 [`CookieType::session`] 构建点产出属性）。
#[cfg(feature = "protocol-jwt")]
pub const MFA_REMEMBER_COOKIE_NAME: &str = "mfa_remember";

/// 从部署级 secret 派生 remember cookie 独立签名子钥（HMAC 域分隔，零新依赖）。
#[cfg(feature = "protocol-jwt")]
fn mfa_remember_subkey(secret: &str) -> Vec<u8> {
    // HKDF（RFC 5869）域分隔派生，与 protocol-sign / protocol-httpdigest
    // 的部署级 secret 派生惯例同一习语（零新增依赖成本：hkdf 与 hmac 同源）
    use hkdf::Hkdf;
    let hk = Hkdf::<sha2::Sha256>::new(None, secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"garrison:mfa-remember-cookie:v1" as &[u8], &mut okm)
        .expect("32 字节 OKM 在 HKDF-SHA256 输出上限内");
    okm.to_vec()
}

/// 签发 MFA remember cookie 的 Set-Cookie 值。
///
/// 载荷 JWT（HS256，`exp = now + ttl_secs`）作为 cookie 值，属性（HttpOnly 恒定、
/// SameSite 白名单与 None→Lax 降级、production `__Host-`/`__Secure-` 前缀、
/// `Max-Age`）全部由单一构建点 [`build_set_cookie_value`] 产出，
/// 本函数不自行拼接任何属性串。
///
/// 签名密钥为部署级 secret 经 HMAC 派生的独立子钥（RFC 8725 密钥分离：
/// 与主 token 签发同源不同钥，一侧新增字段不会桥接另一侧）。
///
/// # 参数
/// - `secret`: 部署级 secret（≥ 32 字节，与 [`crate::protocol::jwt::JwtHandler`] 同源）。
/// - `config`: 配置（取 `cookie_same_site` / `cookie_secure`）。
/// - `stage`: 编排阶段标识。
/// - `credential_id`: 完成认证的因子凭证 ID。
/// - `ttl_secs`: 有效期秒数（0 = 立即过期的会话级标记；负值由构建点拒绝）。
///
/// # 错误
/// - 密钥为空/过短：`GarrisonError::Config`
/// - ttl 为负 / cookie 属性非法：透传构建点错误
#[cfg(feature = "protocol-jwt")]
pub fn issue_mfa_remember_cookie(
    secret: &str,
    config: &GarrisonConfig,
    stage: &str,
    login_id: &str,
    credential_id: &str,
    ttl_secs: i64,
) -> GarrisonResult<String> {
    if secret.len() < 32 {
        return Err(GarrisonError::Config(format!(
            "mfa-remember-secret-too-short::{}::min=32",
            secret.len()
        )));
    }
    let signing_key = mfa_remember_subkey(secret);
    let now = chrono::Utc::now().timestamp();
    let claims = MfaRememberClaims {
        stage: stage.to_string(),
        login_id: login_id.to_string(),
        credential_id: credential_id.to_string(),
        exp: now.checked_add(ttl_secs).ok_or_else(|| {
            GarrisonError::InvalidParam(format!("mfa-remember-ttl-overflow::{ttl_secs}"))
        })?,
    };
    let jwt = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(&signing_key),
    )
    .map_err(|e| GarrisonError::Internal(format!("mfa-remember-sign::{}", e)))?;

    let cookie = CookieType {
        max_age: Some(ttl_secs),
        ..CookieType::session(MFA_REMEMBER_COOKIE_NAME, config)?
    };
    build_set_cookie_value(&cookie, &jwt, config.cookie_secure)
}

/// 校验 MFA remember cookie 的 JWT 载荷（三元绑定 + exp，leeway=0）。
///
/// # 返回
/// - `true`：签名有效、stage / credential_id 匹配且未过期——调用方可跳过
///   重复 challenge。
/// - `false`：签名无效 / stage 不符 / 跨 credential / 已过期（含 `exp` 缺失）。
#[cfg(feature = "protocol-jwt")]
pub fn verify_mfa_remember_cookie(
    secret: &str,
    jwt: &str,
    stage: &str,
    login_id: &str,
    credential_id: &str,
    now: i64,
) -> bool {
    if secret.is_empty() {
        return false;
    }
    let signing_key = mfa_remember_subkey(secret);
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.leeway = 0;
    let Ok(data) = jsonwebtoken::decode::<MfaRememberClaims>(
        jwt,
        &jsonwebtoken::DecodingKey::from_secret(&signing_key),
        &validation,
    ) else {
        return false;
    };
    data.claims.stage == stage
        && data.claims.login_id == login_id
        && data.claims.credential_id == credential_id
        && data.claims.exp > now
}
// ============================================================================
// GarrisonLogicDefault impl
// ============================================================================

#[async_trait]
impl MfaLogic for GarrisonLogicDefault {
    /// 检查二级认证（MFA）状态。
    ///
    /// `GarrisonLogicDefault` 覆写实现：
    /// 调用 `is_safe("default")` 检查 "default" service 的二级认证状态。
    ///
    /// # 为什么覆写 trait default？
    ///
    /// `async_trait` 宏将 trait default 方法编译为泛型代码，`self` 类型为 `&Self`（泛型）。
    /// 在泛型上下文中，编译器无法解析到 inherent method（safe.rs 中的 `is_safe`），
    /// 只能解析到 trait default `is_safe`（返回 `Ok(true)`）。
    /// 在 impl 块中，`self` 是 `&GarrisonLogicDefault`（具体类型），编译器能解析到
    /// inherent method（当 `safe-auth` feature 启用时）。
    ///
    /// # 行为
    /// - 无 `safe-auth` feature：`is_safe` 使用 trait default（`Ok(true)`）→ 返回 `Ok(())`
    /// - 有 `safe-auth` feature：`is_safe` 使用 inherent method（检查 `safe_services`）
    /// - `Ok(true)` → 返回 `Ok(())`
    /// - `Ok(false)` → 返回 `Err(Self::not_safe("SAFE_EXPIRED"))`
    /// - `Err(e)` → 透传错误
    async fn check_safe(&self) -> GarrisonResult<()> {
        self.check_mfa_chain(None).await?;
        if !self.is_safe("default").await? {
            return Err(Self::not_safe("SAFE_EXPIRED"));
        }
        Ok(())
    }

    /// MFA 强制链 gate：三态解析 + 会话账本覆盖判定（fail-closed）。
    ///
    /// - 链决策为 `None`（禁用/继承为空）→ `Ok(())`（与未配置链时行为一致）；
    /// - 链决策为 `Require` 时要求已登录（无 token / 无会话视为未满足），
    ///   账本缺任一 factor → `NotSafe { MFA_CHAIN_INCOMPLETE::<factor> }`。
    async fn check_mfa_chain(&self, client_id: Option<&str>) -> GarrisonResult<()> {
        let decision = crate::stp::mfa::resolve_mfa_chain(
            client_id.and_then(|id| self.config.mfa.per_client_chains.get(id)),
            &self.config.mfa.global_chain,
        );
        if matches!(decision, crate::stp::mfa::MfaChainDecision::None) {
            return Ok(());
        }
        let not_enrolled = || GarrisonError::NotSafe {
            reason: "MFA_CHAIN_INCOMPLETE::no-active-session".to_string(),
        };
        let token = current_token().map_err(|_| not_enrolled())?;
        let ts = self
            .session
            .get_token_session(&token)
            .await?
            .ok_or_else(not_enrolled)?;
        match crate::stp::mfa::first_unmet_chain_factor(&decision, &ts.amr_ledger) {
            None => Ok(()),
            Some(factor) => Err(GarrisonError::NotSafe {
                reason: format!("MFA_CHAIN_INCOMPLETE::{factor}"),
            }),
        }
    }

    /// 检查当前登录账号是否被封禁。
    ///
    /// `GarrisonLogicDefault` 覆写实现：
    /// 1. 无当前 token（未登录）→ 返回 `Ok(())`
    /// 2. token 对应的 TokenSession 不存在 → 返回 `Ok(())`
    /// 3. 调用 `DisableRepository::is_disable(login_id, "default")`，未封禁 → `Ok(())`
    /// 4. 已封禁 → 返回 `Err(Self::disable_service("default", until))`，
    /// `until` 来自 `get_disable_time`（None=永久封禁，Some=定时解封）
    ///
    /// # 错误
    /// - `GarrisonError::DisableService`: 账号已封禁。
    /// - DAO/反序列化失败：透传 `GarrisonError`。
    async fn check_disable(&self) -> GarrisonResult<()> {
        // 获取当前 token（未登录时返回 Ok）
        let token = match current_token() {
            Ok(t) => t,
            Err(_) => {
                tracing::warn!(
                    reason = "no_current_token",
                    "check_disable skipped (fail-open): no current token (not logged in)"
                );
                return Ok(());
            },
        };
        // 获取 login_id（TokenSession 不存在时返回 Ok）
        let ts = match self.session.get_token_session(&token).await? {
            Some(ts) => ts,
            None => {
                tracing::warn!(
                    reason = "token_session_not_found",
                    token = %token.get(..8).unwrap_or("***"),
                    "check_disable skipped (fail-open): TokenSession not found for current token"
                );
                return Ok(());
            },
        };
        // 检查封禁状态
        if self
            .disable_repository
            .is_disable(&ts.login_id, "default")
            .await?
        {
            let until = self
                .disable_repository
                .get_disable_time(&ts.login_id, "default")
                .await?;
            return Err(Self::disable_service("default", until));
        }
        Ok(())
    }
}

// ============================================================================
// WebAuthn factor 接线点（protocol-webauthn feature）
// ============================================================================

/// WebAuthn 二次认证因子的凭据校验函数接线点。
///
/// 完整 MFA 编排（因子账本 / Required Action / 新鲜度断言）归 stp/mfa 的
/// MFA 编排基座交付；本接线点只暴露「给 MFA 层一个可调用的 WebAuthn
/// assertion 校验函数」这一最小缝：
///
/// - [`WebauthnFactorVerifier`]：包装 [`WebauthnService`] 的校验入口，
///   把模块自有错误词汇表映射为 [`GarrisonError`]（`InvalidParam` 携带
///   显性 detail，不静默吞错）；
/// - [`register_webauthn_factor`] / [`webauthn_factor`]：进程级注册表，
///   装配方注入一次，MFA 编排层按 `webauthn` 方法名取用（未注册返回
///   `None`——编排层据此走「因子未配置」分支，不视为错误）。
#[cfg(feature = "protocol-webauthn")]
pub mod webauthn_factor {
    use super::*;
    use crate::protocol::webauthn::service::WebauthnService;

    use std::sync::{Arc, RwLock};

    static WEBAUTHN_FACTOR: RwLock<Option<Arc<WebauthnFactorVerifier>>> = RwLock::new(None);

    /// WebAuthn 二次认证校验函数（包装 [`WebauthnService`] 认证仪式）。
    pub struct WebauthnFactorVerifier {
        service: Arc<WebauthnService>,
    }

    impl WebauthnFactorVerifier {
        /// 包装既有 service（仪式/challenge/凭据存取均由 service 承载）。
        pub fn new(service: Arc<WebauthnService>) -> Self {
            Self { service }
        }

        /// 校验二次认证 assertion：走认证仪式全流程（challenge 一次性消费、
        /// sign_count 单调性克隆检测、backup flags 更新落库）。
        ///
        /// 返回仪式锁定的用户绑定（`WebauthnAuthentication`，tenant/user
        /// 取自 challenge 暂存而非请求重传）——调用方必须与当前会话主体
        /// 比对，防「自己的 passkey 完成他人 step-up」的跨用户断言。
        pub async fn verify_second_factor(
            &self,
            assertion: &webauthn_rs::prelude::PublicKeyCredential,
        ) -> GarrisonResult<crate::protocol::webauthn::service::WebauthnAuthentication> {
            self.service
                .finish_authentication(assertion)
                .await
                .map_err(GarrisonError::from)
        }

        /// 底层 service（MFA 编排层需要发起 challenge 时使用）。
        pub fn service(&self) -> &Arc<WebauthnService> {
            &self.service
        }
    }

    /// 注册 WebAuthn factor 校验函数（进程级，重复注册显性拒绝——
    /// 静默覆盖会让「后注册者改变全库校验行为」变得不可见）。
    pub fn register_webauthn_factor(verifier: Arc<WebauthnFactorVerifier>) -> GarrisonResult<()> {
        let mut guard = WEBAUTHN_FACTOR
            .write()
            .expect("mfa webauthn factor 注册表锁不应中毒");
        if guard.is_some() {
            return Err(GarrisonError::Config(
                "mfa-webauthn-factor-already-registered::".to_string(),
            ));
        }
        *guard = Some(verifier);
        Ok(())
    }

    /// 取已注册的 WebAuthn factor 校验函数；未注册返回 `None`（编排层
    /// 据此判定「因子未配置」，不视为错误）。
    pub fn webauthn_factor() -> Option<Arc<WebauthnFactorVerifier>> {
        WEBAUTHN_FACTOR
            .read()
            .expect("mfa webauthn factor 注册表锁不应中毒")
            .clone()
    }

    /// 重置注册表（仅供测试用，业务代码不应调用）。
    #[cfg(test)]
    pub fn reset_webauthn_factor_for_tests() {
        *WEBAUTHN_FACTOR
            .write()
            .expect("mfa webauthn factor 注册表锁不应中毒") = None;
    }

    // 测试经 sqlite 内存库构造 service 依赖（repository 需 DbPool），
    // 无 db-sqlite 的组合（如 production 门禁）不编译
    #[cfg(all(test, feature = "db-sqlite"))]
    mod tests {
        use super::*;
        use crate::dao::InMemoryDao;
        use crate::protocol::webauthn::WebauthnConfig;

        #[tokio::test(flavor = "multi_thread")]
        #[serial_test::serial]
        async fn register_then_get_and_duplicate_rejected() {
            let pool = crate::dao::init_dbnexus("sqlite::memory:")
                .await
                .expect("init_dbnexus 应成功");
            // 本测试只验证注册表语义（register/get/重复注册拒绝），不触达
            // 凭据存取——repository 仅在构造时被 service 持有
            let service = Arc::new(WebauthnService::new(
                Arc::new(InMemoryDao::new()),
                Arc::new(
                    crate::dao::repository::sqlite::DbnexusWebauthnCredentialRepository::new(pool),
                ),
                WebauthnConfig {
                    issuer: "https://auth.example.com".to_string(),
                    challenge_ttl_secs: 120,
                    passwordless: crate::protocol::webauthn::FactorPolicy { enabled: false },
                    second_factor: crate::protocol::webauthn::FactorPolicy { enabled: true },
                },
            ));
            let verifier = Arc::new(WebauthnFactorVerifier::new(service));
            // 注册表为进程级：先重置保证本测试自管前置条件（顺序无关）
            reset_webauthn_factor_for_tests();
            register_webauthn_factor(verifier.clone()).expect("首次注册应成功");
            let got = webauthn_factor();
            assert!(got.is_some(), "注册后应可取回 factor");
            let dup = register_webauthn_factor(verifier);
            assert!(
                matches!(dup, Err(GarrisonError::Config(_))),
                "重复注册应显性拒绝，实际: {dup:?}"
            );
            if let Err(GarrisonError::Config(m)) = &dup {
                assert!(
                    m.contains("already-registered"),
                    "重复注册错误应含 already-registered 指引，实际: {m}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GarrisonConfig;
    use crate::error::GarrisonResult;
    use crate::stp::core::GarrisonCore;
    use crate::stp::session::SessionLogic;
    use crate::stp::LoginParams;
    use std::sync::Arc;

    /// 最小 mock：实现 `GarrisonCore` + `SessionLogic`（9 必需方法）。
    /// `MfaLogic` 2 个方法均有默认实现，空 impl 即可获得全部默认行为。
    struct MockMfa {
        config: Arc<GarrisonConfig>,
    }

    impl GarrisonCore for MockMfa {
        fn config(&self) -> Arc<GarrisonConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockMfa {
        async fn login(
            &self,
            _login_id: &str,
            _params: &crate::stp::LoginParams,
        ) -> GarrisonResult<String> {
            Ok("mock-token".to_string())
        }
        async fn login_with_token(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn logout(&self) -> GarrisonResult<()> {
            Ok(())
        }
        async fn logout_by_login_id(&self, _login_id: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn kickout(&self, _login_id: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn kickout_by_token(&self, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn revoke_token(&self, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> GarrisonResult<bool> {
            Ok(true)
        }
        async fn get_login_id(&self) -> GarrisonResult<Option<String>> {
            Ok(Some("42".to_string()))
        }
    }

    #[async_trait]
    impl MfaLogic for MockMfa {}

    #[tokio::test]
    async fn check_safe_default_ok() {
        let mock = MockMfa {
            config: Arc::new(GarrisonConfig::default()),
        };
        mock.check_safe().await.unwrap();
    }

    #[tokio::test]
    async fn check_disable_default_ok() {
        let mock = MockMfa {
            config: Arc::new(GarrisonConfig::default()),
        };
        mock.check_disable().await.unwrap();
    }

    // ========================================================================
    // disable_service / not_safe 构造方法测试
    // ========================================================================

    /// 验证 `disable_service` 构造正确的 `GarrisonError::DisableService` 变体。
    ///
    /// service 字段正确传递，until=None 表示永久封禁。
    #[test]
    fn disable_service_constructs_correct_error() {
        let err = MockMfa::disable_service("default", None);
        match err {
            GarrisonError::DisableService { service, until } => {
                assert_eq!(service, "default");
                assert!(until.is_none(), "until=None 表示永久封禁");
            },
            other => panic!("期望 DisableService 变体，实际: {:?}", other),
        }
    }

    /// 验证 `disable_service` 带 until 时间戳时正确传递。
    #[test]
    fn disable_service_with_until_timestamp() {
        let until = chrono::DateTime::parse_from_rfc3339("2026-12-31T23:59:59Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let err = MockMfa::disable_service("oidc", Some(until));
        match err {
            GarrisonError::DisableService { service, until: u } => {
                assert_eq!(service, "oidc");
                assert!(u.is_some(), "until 应为 Some");
                assert_eq!(u.unwrap().to_rfc3339(), "2026-12-31T23:59:59+00:00");
            },
            other => panic!("期望 DisableService 变体，实际: {:?}", other),
        }
    }

    /// 验证 `not_safe` 构造正确的 `GarrisonError::NotSafe` 变体。
    ///
    /// reason 字段正确传递。
    #[test]
    fn not_safe_constructs_correct_error() {
        let err = MockMfa::not_safe("MFA_TOTP_REQUIRED");
        match err {
            GarrisonError::NotSafe { reason } => {
                assert_eq!(reason, "MFA_TOTP_REQUIRED");
            },
            other => panic!("期望 NotSafe 变体，实际: {:?}", other),
        }
    }

    /// 验证 `not_safe` 可构造 Display 输出包含 reason。
    #[test]
    fn not_safe_display_includes_reason() {
        let err = MockMfa::not_safe("WEBAUTHN_REQUIRED");
        let display = err.to_string();
        assert!(
            display.contains("WEBAUTHN_REQUIRED"),
            "Display 应包含 reason，实际: {}",
            display
        );
        assert!(
            display.contains("authentication required") || display.contains("二次认证"),
            "Display 应包含认证描述，实际: {}",
            display
        );
    }

    /// 验证 `open_safe` trait 默认实现返回 Ok(())（no-op）。
    ///
    /// 覆盖 trait default 路径：未覆写的实现者调用 open_safe 应直接返回 Ok。
    #[tokio::test]
    async fn open_safe_default_returns_ok() {
        let mock = MockMfa {
            config: Arc::new(GarrisonConfig::default()),
        };
        mock.open_safe("default", 3600).await.unwrap();
    }

    /// 验证 `close_safe` trait 默认实现返回 Ok(())（no-op）。
    ///
    /// 覆盖 trait default 路径：未覆写的实现者调用 close_safe 应直接返回 Ok。
    #[tokio::test]
    async fn close_safe_default_returns_ok() {
        let mock = MockMfa {
            config: Arc::new(GarrisonConfig::default()),
        };
        mock.close_safe("default").await.unwrap();
    }

    // ========================================================================
    // check_safe 默认实现测试
    // ========================================================================

    /// 不启用 safe-auth 时，MockMfa（只实现 trait defaults）的 check_safe 返回 Ok。
    ///
    /// is_safe 默认返回 Ok(true) → check_safe 返回 Ok(())。
    #[tokio::test]
    async fn t025_check_safe_default_without_safe_auth() {
        let mock = MockMfa {
            config: Arc::new(GarrisonConfig::default()),
        };
        mock.check_safe().await.unwrap();
    }

    /// MockMfa 不覆写 is_safe，使用 trait default Ok(true)。
    ///
    /// 验证 check_safe 默认调用 is_safe("default")，因 is_safe=true，返回 Ok(())。
    #[tokio::test]
    async fn t025_check_safe_default_uses_is_safe_default() {
        let mock = MockMfa {
            config: Arc::new(GarrisonConfig::default()),
        };
        // is_safe 默认返回 Ok(true)
        assert!(
            mock.is_safe("default").await.unwrap(),
            "is_safe 默认应返回 Ok(true)"
        );
        // check_safe 调用 is_safe，因 is_safe=true，返回 Ok(())
        assert!(mock.check_safe().await.is_ok(), "check_safe 应返回 Ok(())");
    }

    // ========================================================================
    // check_safe 默认实现：is_safe 覆写场景测试
    // 覆盖 trait default check_safe（lines 42-47）的 false / Err 分支
    // ========================================================================

    /// 可配置 is_safe 返回值的 mock，用于测试 check_safe trait default 的各分支。
    ///
    /// `safe_result` 为 is_safe 预设返回值，覆盖 Ok(true)/Ok(false)/Err 三类分支。
    struct MockMfaSafe {
        config: Arc<GarrisonConfig>,
        safe_result: GarrisonResult<bool>,
    }

    impl GarrisonCore for MockMfaSafe {
        fn config(&self) -> Arc<GarrisonConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockMfaSafe {
        async fn login(
            &self,
            _login_id: &str,
            _params: &crate::stp::LoginParams,
        ) -> GarrisonResult<String> {
            Ok("mock-token".to_string())
        }
        async fn login_with_token(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn logout(&self) -> GarrisonResult<()> {
            Ok(())
        }
        async fn logout_by_login_id(&self, _login_id: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn kickout(&self, _login_id: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn kickout_by_token(&self, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn revoke_token(&self, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> GarrisonResult<bool> {
            Ok(true)
        }
        async fn get_login_id(&self) -> GarrisonResult<Option<String>> {
            Ok(Some("42".to_string()))
        }
    }

    #[async_trait]
    impl MfaLogic for MockMfaSafe {
        // 覆写 is_safe 返回预设值，测试 check_safe trait default 各分支
        async fn is_safe(&self, _service: &str) -> GarrisonResult<bool> {
            match &self.safe_result {
                Ok(b) => Ok(*b),
                Err(GarrisonError::Dao(s)) => Err(GarrisonError::Dao(s.clone())),
                Err(GarrisonError::Internal(s)) => Err(GarrisonError::Internal(s.clone())),
                Err(e) => panic!("MockMfaSafe 不支持此错误变体: {:?}", e),
            }
        }
    }

    /// check_safe + is_safe 返回 Ok(false) → 返回 Err(NotSafe("SAFE_EXPIRED"))。
    ///
    /// 覆盖 mfa.rs 第 43-45 行 `!is_safe → Err(Self::not_safe("SAFE_EXPIRED"))` 分支。
    #[tokio::test]
    async fn check_safe_is_safe_false_returns_not_safe() {
        let mock = MockMfaSafe {
            config: Arc::new(GarrisonConfig::default()),
            safe_result: Ok(false),
        };
        let result = mock.check_safe().await;
        match result {
            Err(GarrisonError::NotSafe { reason }) => {
                assert_eq!(
                    reason, "SAFE_EXPIRED",
                    "is_safe=false 时 check_safe 应返回 NotSafe(reason=\"SAFE_EXPIRED\")"
                );
            },
            other => panic!(
                "is_safe=false 时 check_safe 应返回 Err(NotSafe)，实际: {:?}",
                other
            ),
        }
    }

    /// check_safe + is_safe 返回 Ok(true) → 返回 Ok(())。
    ///
    /// 覆盖 mfa.rs 第 46 行 `Ok(())` 分支（通过覆写 is_safe 而非 trait default）。
    #[tokio::test]
    async fn check_safe_is_safe_true_returns_ok() {
        let mock = MockMfaSafe {
            config: Arc::new(GarrisonConfig::default()),
            safe_result: Ok(true),
        };
        mock.check_safe().await.unwrap();
    }

    /// check_safe + is_safe 返回 Err(Dao) → 透传错误。
    ///
    /// 覆盖 mfa.rs 第 43 行 `is_safe(...).await?` 错误传播路径。
    #[tokio::test]
    async fn check_safe_is_safe_error_propagates() {
        let mock = MockMfaSafe {
            config: Arc::new(GarrisonConfig::default()),
            safe_result: Err(GarrisonError::Dao("数据源连接失败".to_string())),
        };
        let result = mock.check_safe().await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref s)) if s.contains("数据源连接失败")),
            "is_safe 返回 Dao 错误时应透传，实际: {:?}",
            result
        );
    }

    /// check_safe + is_safe 返回 Err(Internal) → 透传错误。
    ///
    /// 覆盖 mfa.rs 第 43 行 `is_safe(...).await?` 错误传播路径（Internal 变体）。
    #[tokio::test]
    async fn check_safe_is_safe_internal_error_propagates() {
        let mock = MockMfaSafe {
            config: Arc::new(GarrisonConfig::default()),
            safe_result: Err(GarrisonError::Internal("内部错误".to_string())),
        };
        let result = mock.check_safe().await;
        assert!(
            matches!(result, Err(GarrisonError::Internal(ref s)) if s.contains("内部错误")),
            "is_safe 返回 Internal 错误时应透传，实际: {:?}",
            result
        );
    }

    /// 验证 `disable_service` Display 输出包含 service 名称。
    ///
    /// 覆盖 mfa.rs disable_service 关联函数 + Display 实现。
    #[test]
    fn disable_service_display_includes_service() {
        let err = MockMfa::disable_service("payment", None);
        let display = err.to_string();
        assert!(
            display.contains("payment"),
            "Display 应包含 service 名称，实际: {}",
            display
        );
    }

    /// 调用 MockMfa 的所有 SessionLogic + GarrisonCore 方法以确保覆盖。
    #[tokio::test]
    async fn mock_mfa_session_logic_all_methods() {
        let mock = MockMfa {
            config: Arc::new(GarrisonConfig::default()),
        };
        let _ = mock.config();
        let params = LoginParams::default();
        let _ = mock.login("u1", &params).await.unwrap();
        let _ = mock.login_with_token("u1", "tok").await;
        let _ = mock.logout().await;
        let _ = mock.logout_by_login_id("u1").await;
        let _ = mock.kickout("u1").await;
        let _ = mock.kickout_by_token("tok").await;
        let _ = mock.revoke_token("tok").await;
        let _ = mock.check_login().await.unwrap();
        let _ = mock.get_login_id().await.unwrap();
    }

    // ========================================================================
    // per-client MFA chain 三态
    // ========================================================================

    /// per-client 缺失（None）回退全局默认链。
    #[test]
    fn resolve_mfa_chain_none_inherits_global() {
        let global = vec!["otp".to_string()];
        assert_eq!(
            resolve_mfa_chain(None, &global),
            MfaChainDecision::Require(vec!["otp".to_string()])
        );
    }

    /// per-client 缺失且全局链为空 → 不强制。
    #[test]
    fn resolve_mfa_chain_none_empty_global_is_none() {
        assert_eq!(resolve_mfa_chain(None, &[]), MfaChainDecision::None);
    }

    /// per-client 空集显式禁用：全局有默认链也不强制。
    #[test]
    fn resolve_mfa_chain_empty_set_disables() {
        let global = vec!["otp".to_string()];
        let empty = Vec::new();
        assert_eq!(
            resolve_mfa_chain(Some(&empty), &global),
            MfaChainDecision::None,
            "Some(空集) 应显式禁用（压过全局默认）"
        );
    }

    /// per-client 非空集强制该集合（不合并全局）。
    #[test]
    fn resolve_mfa_chain_non_empty_overrides_global() {
        let global = vec!["otp".to_string()];
        let own = vec!["webauthn".to_string()];
        assert_eq!(
            resolve_mfa_chain(Some(&own), &global),
            MfaChainDecision::Require(vec!["webauthn".to_string()])
        );
    }

    /// validate_mfa_chains 拒绝未知 factor（全局与 per-client 两条路径）。
    #[test]
    fn validate_mfa_chains_rejects_unknown_factor() {
        let mut per_client = std::collections::HashMap::new();
        per_client.insert("c1".to_string(), vec!["otp".to_string()]);
        assert!(validate_mfa_chains(&["webauthn".to_string()], &per_client).is_ok());

        assert!(validate_mfa_chains(&["sms".to_string()], &per_client).is_err());
        per_client.insert("c2".to_string(), vec!["pwd".to_string()]);
        let result = validate_mfa_chains(&[], &per_client);
        assert!(
            matches!(result, Err(GarrisonError::Config(ref m)) if m.contains("pwd")),
            "pwd 不入 chain 词汇表（主因子），实际: {:?}",
            result
        );
    }

    // ========================================================================
    // MFA 编排基座：因子账本（AmrEntry / amr claim 映射）
    // ========================================================================

    /// AmrEntry::new 接受词汇表内的 method 与 1..=3 的 aal。
    #[test]
    fn amr_entry_new_accepts_known_method_and_valid_aal() {
        for method in AMR_METHODS {
            let entry = AmrEntry::new(*method, 2, 1_700_000_000).unwrap();
            assert_eq!(entry.method, *method);
            assert_eq!(entry.aal, 2);
            assert_eq!(entry.completed_at, 1_700_000_000);
        }
    }

    /// AmrEntry::new 拒绝词汇表之外的 method（显性化，不入账）。
    #[test]
    fn amr_entry_new_rejects_unknown_method() {
        for method in ["sms", "", "PWD", "push"] {
            let result = AmrEntry::new(method, 2, 0);
            assert!(
                matches!(result, Err(GarrisonError::InvalidParam(ref m)) if m.contains("amr-method")),
                "method={:?} 应被拒绝，实际: {:?}",
                method,
                result.map(|_| ())
            );
        }
    }

    /// AmrEntry::new 拒绝越界 aal（0 与 4）。
    #[test]
    fn amr_entry_new_rejects_out_of_range_aal() {
        for aal in [0u8, 4] {
            let result = AmrEntry::new("otp", aal, 0);
            assert!(
                matches!(result, Err(GarrisonError::InvalidParam(ref m)) if m.contains("aal")),
                "aal={} 应被拒绝，实际: {:?}",
                aal,
                result.map(|_| ())
            );
        }
    }

    /// amr_claim 按完成顺序输出并对 method 去重保序（RFC 8176 数组语义）。
    #[test]
    fn amr_claim_preserves_order_and_dedups() {
        let entries = vec![
            AmrEntry::new("pwd", 1, 1).unwrap(),
            AmrEntry::new("otp", 2, 2).unwrap(),
            AmrEntry::new("webauthn", 2, 3).unwrap(),
            AmrEntry::new("otp", 2, 4).unwrap(),
        ];
        assert_eq!(
            amr_claim(&entries),
            vec!["pwd".to_string(), "otp".to_string(), "webauthn".to_string()]
        );
    }

    /// 空账本映射为空 amr 数组。
    #[test]
    fn amr_claim_empty_ledger_maps_to_empty_array() {
        assert!(amr_claim(&[]).is_empty());
    }

    /// ledger_max_aal 取最高等级；空账本为 0。
    #[test]
    fn ledger_max_aal_takes_maximum() {
        assert_eq!(ledger_max_aal(&[]), 0);
        let entries = vec![
            AmrEntry::new("pwd", 1, 1).unwrap(),
            AmrEntry::new("otp", 2, 2).unwrap(),
        ];
        assert_eq!(ledger_max_aal(&entries), 2);
    }

    /// token_style=jwt 的主登录签发：amr=["pwd"] + auth_time=签发时刻。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn login_jwt_token_carries_primary_amr_and_auth_time() {
        use crate::dao::tests::MockDao;
        use crate::dao::GarrisonDao;
        use crate::session::GarrisonSession;
        use crate::strategy::GarrisonPermissionStrategy;

        struct NoopFirewall;

        #[async_trait::async_trait]
        impl GarrisonPermissionStrategy for NoopFirewall {
            async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec![])
            }
            async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec![])
            }
            async fn check_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role(&self, _login_id: &str, _role: &str) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_any(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_all(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_permission_in_tenant(
                &self,
                _tenant_id: i64,
                _login_id: &str,
                _permission: &str,
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_in_tenant(
                &self,
                _tenant_id: i64,
                _login_id: &str,
                _role: &str,
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            #[cfg(any(
                feature = "sms-rate-limit",
                feature = "firewall-ratelimit",
                feature = "firewall-bruteforce",
                feature = "firewall-ddos",
                feature = "firewall",
                feature = "oauth2-server"
            ))]
            async fn check_login_hooks(
                &self,
                _login_id: &str,
                _ctx: &crate::strategy::hooks::LoginContext,
            ) -> GarrisonResult<()> {
                Ok(())
            }
        }

        let dao = Arc::new(MockDao::new());
        let session = Arc::new(GarrisonSession::new(
            dao.clone() as Arc<dyn GarrisonDao>,
            3600,
            86400,
            0,
        ));
        let mut config = GarrisonConfig::default_config();
        config.throw_on_not_login = false;
        config.token_style = "jwt".to_string();
        config.jwt_secret = "0123456789abcdef0123456789abcdef".to_string().into();
        let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(NoopFirewall);
        let logic = GarrisonLogicDefault::new(
            session,
            Arc::new(config),
            firewall,
            Arc::new(crate::account::disable::DefaultDisableRepository::new(
                dao.clone() as Arc<dyn GarrisonDao>,
            )),
        );
        let token = logic
            .login("user-mfa-1", &LoginParams::default())
            .await
            .unwrap();
        let handler = crate::protocol::jwt::JwtHandler::new("0123456789abcdef0123456789abcdef");
        let claims = handler.verify(&token).unwrap();
        assert_eq!(
            claims.amr,
            Some(vec![PRIMARY_FACTOR_AMR.to_string()]),
            "主登录签发的 amr 应为 [\"pwd\"]"
        );
        let now = chrono::Utc::now().timestamp();
        assert!(
            claims.auth_time.is_some_and(|t| (now - t).abs() <= 5),
            "auth_time 应等于签发时刻（±5s），实际: {:?}",
            claims.auth_time
        );
    }

    /// 调用 MockMfaSafe 的所有 SessionLogic + GarrisonCore 方法以确保覆盖。
    #[tokio::test]
    async fn mock_mfa_safe_session_logic_all_methods() {
        let mock = MockMfaSafe {
            config: Arc::new(GarrisonConfig::default()),
            safe_result: Ok(true),
        };
        let _ = mock.config();
        let params = LoginParams::default();
        let _ = mock.login("u1", &params).await.unwrap();
        let _ = mock.login_with_token("u1", "tok").await;
        let _ = mock.logout().await;
        let _ = mock.logout_by_login_id("u1").await;
        let _ = mock.kickout("u1").await;
        let _ = mock.kickout_by_token("tok").await;
        let _ = mock.revoke_token("tok").await;
        let _ = mock.check_login().await.unwrap();
        let _ = mock.get_login_id().await.unwrap();
    }

    // ========================================================================
    // DisableRepository 集成测试（GarrisonLogicDefault.check_disable）
    // ========================================================================

    mod t019_disable_integration {
        use super::*;
        use crate::account::disable::{DefaultDisableRepository, DisableRepository};
        use crate::config::GarrisonConfig;
        use crate::dao::tests::MockDao;
        use crate::dao::GarrisonDao;
        use crate::session::GarrisonSession;
        use crate::stp::with_current_token;
        use crate::stp::LoginParams;
        use crate::strategy::GarrisonPermissionStrategy;
        use async_trait::async_trait;
        use chrono::Utc;
        use std::sync::Arc;

        // --------------------------------------------------------------------
        // MockFirewall：no-op 权限策略，允许所有登录
        // --------------------------------------------------------------------

        struct MockFirewall;

        #[async_trait]
        impl GarrisonPermissionStrategy for MockFirewall {
            async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec![])
            }
            async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec![])
            }
            async fn check_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role(&self, _login_id: &str, _role: &str) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_any(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_all(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_permission_in_tenant(
                &self,
                _tenant_id: i64,
                _login_id: &str,
                _permission: &str,
            ) -> GarrisonResult<bool> {
                // 测试桩与租户无关：任意租户返回相同结果
                Ok(true)
            }
            async fn check_role_in_tenant(
                &self,
                _tenant_id: i64,
                _login_id: &str,
                _role: &str,
            ) -> GarrisonResult<bool> {
                // 测试桩与租户无关：任意租户返回相同结果
                Ok(true)
            }
            #[cfg(any(
                feature = "sms-rate-limit",
                feature = "firewall-ratelimit",
                feature = "firewall-bruteforce",
                feature = "firewall-ddos",
                feature = "firewall",
                feature = "oauth2-server"
            ))]
            async fn check_login_hooks(
                &self,
                _login_id: &str,
                _ctx: &crate::strategy::hooks::LoginContext,
            ) -> GarrisonResult<()> {
                // 测试桩不注入防火墙 hook，显式 no-op
                Ok(())
            }
        }

        // --------------------------------------------------------------------
        // 辅助函数
        // --------------------------------------------------------------------

        /// 创建 GarrisonLogicDefault，返回 (logic, repo, dao) 便于测试。
        fn make_logic_with_repo() -> (
            GarrisonLogicDefault,
            Arc<DefaultDisableRepository>,
            Arc<MockDao>,
        ) {
            let dao = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(
                dao.clone() as Arc<dyn GarrisonDao>,
                3600,
                86400,
                0,
            ));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall);
            let repo = Arc::new(DefaultDisableRepository::new(
                dao.clone() as Arc<dyn GarrisonDao>
            ));
            let logic = GarrisonLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
                repo.clone() as Arc<dyn DisableRepository>,
            );
            (logic, repo, dao)
        }

        // --------------------------------------------------------------------
        // 集成测试
        // --------------------------------------------------------------------

        /// 注入 repository 但未封禁，check_disable 返回 Ok。
        #[tokio::test]
        async fn test_check_disable_not_disabled_returns_ok() {
            let (logic, _repo, _dao) = make_logic_with_repo();
            let token = logic.login("1001", &LoginParams::default()).await.unwrap();

            let result = with_current_token(token, async { logic.check_disable().await }).await;

            assert!(
                result.is_ok(),
                "未封禁时 check_disable 应返回 Ok，实际: {:?}",
                result
            );
        }

        /// 注入 repository 且已封禁，check_disable 返回 DisableService 错误。
        #[tokio::test]
        async fn test_check_disable_disabled_returns_error() {
            let (logic, repo, _dao) = make_logic_with_repo();
            let token = logic.login("1001", &LoginParams::default()).await.unwrap();

            // 封禁该用户（定时封禁）
            let until = Utc::now() + chrono::Duration::seconds(3600);
            repo.disable("1001", "default", Some(until), 0, 3600)
                .await
                .unwrap();

            let result = with_current_token(token, async { logic.check_disable().await }).await;

            match result {
                Err(GarrisonError::DisableService { service, .. }) => {
                    assert_eq!(
                        service, "default",
                        "DisableService 错误的 service 字段应为 'default'"
                    );
                },
                other => panic!(
                    "已封禁时 check_disable 应返回 Err(DisableService)，实际: {:?}",
                    other
                ),
            }
        }

        /// 永久封禁（until=None），错误中 until 字段为 None。
        #[tokio::test]
        async fn test_check_disable_permanent_ban_until_none() {
            let (logic, repo, _dao) = make_logic_with_repo();
            let token = logic.login("1002", &LoginParams::default()).await.unwrap();

            // 永久封禁（until=None, duration_secs=0）
            repo.disable("1002", "default", None, 0, 0).await.unwrap();

            let result = with_current_token(token, async { logic.check_disable().await }).await;

            match result {
                Err(GarrisonError::DisableService { service, until }) => {
                    assert_eq!(service, "default");
                    assert!(
                        until.is_none(),
                        "永久封禁 until 应为 None，实际: {:?}",
                        until
                    );
                },
                other => panic!(
                    "永久封禁应返回 Err(DisableService {{ until: None }})，实际: {:?}",
                    other
                ),
            }
        }

        /// 定时封禁（until=Some），错误中 until 字段为 Some 且精确匹配。
        #[tokio::test]
        async fn test_check_disable_timed_ban_until_some() {
            let (logic, repo, _dao) = make_logic_with_repo();
            let token = logic.login("1003", &LoginParams::default()).await.unwrap();

            // 定时封禁（until=Some(future), duration_secs=7200）
            let until = Utc::now() + chrono::Duration::seconds(7200);
            repo.disable("1003", "default", Some(until), 0, 7200)
                .await
                .unwrap();

            let result = with_current_token(token, async { logic.check_disable().await }).await;

            match result {
                Err(GarrisonError::DisableService { service, until: u }) => {
                    assert_eq!(service, "default");
                    assert!(u.is_some(), "定时封禁 until 应为 Some");
                    assert_eq!(
                        u.unwrap(),
                        until,
                        "定时封禁 until 应精确匹配 disable 时设置的值"
                    );
                },
                other => panic!(
                    "定时封禁应返回 Err(DisableService {{ until: Some(_) }})，实际: {:?}",
                    other
                ),
            }
        }

        /// 未设置 current_token（未登录），check_disable 返回 Ok（不抛错）。
        #[tokio::test]
        async fn test_check_disable_no_token_returns_ok() {
            let (logic, _repo, _dao) = make_logic_with_repo();
            // 不调用 login，也不设置 task_local current_token

            // 直接调用 check_disable（无 task_local 上下文）
            let result = logic.check_disable().await;

            assert!(
                result.is_ok(),
                "未登录（无 current_token）时 check_disable 应返回 Ok，实际: {:?}",
                result
            );
        }

        /// 设置 current_token 但对应 TokenSession 不存在，check_disable 返回 Ok（幂等）。
        ///
        /// 覆盖 lines 219-222：token 存在但 session.get_token_session 返回 None → Ok(())。
        #[tokio::test]
        async fn test_check_disable_token_session_not_found_returns_ok() {
            let (logic, _repo, _dao) = make_logic_with_repo();
            // 不调用 login，直接设置一个不存在的 token
            let result = with_current_token("nonexistent-token-xyz".to_string(), async {
                logic.check_disable().await
            })
            .await;

            assert!(
                result.is_ok(),
                "token 对应的 TokenSession 不存在时 check_disable 应返回 Ok，实际: {:?}",
                result
            );
        }

        /// 直接调用 MockFirewall 的所有方法以确保覆盖。
        #[tokio::test]
        async fn mock_firewall_all_methods() {
            let fw = MockFirewall;
            let _ = fw.get_permission_list("u1").await.unwrap();
            let _ = fw.get_role_list("u1").await.unwrap();
            let _ = fw.check_permission("u1", "user:read").await.unwrap();
            let _ = fw.check_role("u1", "admin").await.unwrap();
            let _ = fw.check_role_any("u1", &["admin", "user"]).await.unwrap();
            let _ = fw.check_role_all("u1", &["admin", "user"]).await.unwrap();
        }
    }

    // ========================================================================
    // check_safe 默认实现集成测试（需要 safe-auth feature）
    // ========================================================================

    /// 集成测试：验证 check_safe 默认实现与 GarrisonLogicDefault inherent method
    /// （open_safe / is_safe / close_safe）的交互。
    ///
    /// 仅在 `safe-auth` feature 启用时编译，因为测试需要 inherent method 支持。
    #[cfg(feature = "security-extra")]
    mod t025_check_safe_integration {
        use super::*;
        use crate::config::GarrisonConfig;
        use crate::dao::tests::MockDao;
        use crate::dao::GarrisonDao;
        use crate::error::GarrisonError;
        use crate::session::GarrisonSession;
        use crate::stp::session::SessionLogic;
        use crate::stp::with_current_token;
        use crate::stp::LoginParams;
        use crate::strategy::GarrisonPermissionStrategy;
        use async_trait::async_trait;
        use std::sync::Arc;

        // ----------------------------------------------------------------
        // MockFirewall：no-op 权限策略，允许所有登录
        // ----------------------------------------------------------------

        struct MockFirewall;

        #[async_trait]
        impl GarrisonPermissionStrategy for MockFirewall {
            async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec![])
            }
            async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec![])
            }
            async fn check_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role(&self, _login_id: &str, _role: &str) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_any(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_all(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_permission_in_tenant(
                &self,
                _tenant_id: i64,
                _login_id: &str,
                _permission: &str,
            ) -> GarrisonResult<bool> {
                // 测试桩与租户无关：任意租户返回相同结果
                Ok(true)
            }
            async fn check_role_in_tenant(
                &self,
                _tenant_id: i64,
                _login_id: &str,
                _role: &str,
            ) -> GarrisonResult<bool> {
                // 测试桩与租户无关：任意租户返回相同结果
                Ok(true)
            }
            #[cfg(any(
                feature = "sms-rate-limit",
                feature = "firewall-ratelimit",
                feature = "firewall-bruteforce",
                feature = "firewall-ddos",
                feature = "firewall",
                feature = "oauth2-server"
            ))]
            async fn check_login_hooks(
                &self,
                _login_id: &str,
                _ctx: &crate::strategy::hooks::LoginContext,
            ) -> GarrisonResult<()> {
                // 测试桩不注入防火墙 hook，显式 no-op
                Ok(())
            }
        }

        // ----------------------------------------------------------------
        // 辅助函数
        // ----------------------------------------------------------------

        /// 创建 GarrisonLogicDefault 并返回 (logic, dao) 便于测试。
        fn make_logic() -> (GarrisonLogicDefault, Arc<MockDao>) {
            let dao = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(
                dao.clone() as Arc<dyn GarrisonDao>,
                3600,
                86400,
                0,
            ));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall);
            let logic = GarrisonLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
                Arc::new(crate::account::disable::DefaultDisableRepository::new(
                    dao.clone(),
                )),
            );
            (logic, dao)
        }

        // ----------------------------------------------------------------
        // 4 个集成测试
        // ----------------------------------------------------------------

        /// login → open_safe("default", 3600) → check_safe 返回 Ok(())。
        ///
        /// 验证 open_safe 开启二级认证后，check_safe 默认实现（调用 is_safe）
        /// 能正确识别已认证状态并返回 Ok。
        #[tokio::test]
        async fn t025_check_safe_passes_after_open_safe() {
            let (logic, _dao) = make_logic();
            let token = logic
                .login("user-4001", &LoginParams::default())
                .await
                .unwrap();

            let result = with_current_token(token.clone(), async {
                logic.open_safe("default", 3600).await.unwrap();
                logic.check_safe().await
            })
            .await;

            assert!(
                result.is_ok(),
                "open_safe 后 check_safe 应返回 Ok(())，实际: {:?}",
                result
            );
        }

        /// login → check_safe（未 open_safe）→ 返回 Err(NotSafe { reason: "SAFE_EXPIRED" })。
        ///
        /// 验证未开启二级认证时，check_safe 默认实现（调用 is_safe）能正确识别
        /// 未认证状态并返回 NotSafe 错误。
        #[tokio::test]
        async fn t025_check_safe_fails_without_open_safe() {
            let (logic, _dao) = make_logic();
            let token = logic
                .login("user-4002", &LoginParams::default())
                .await
                .unwrap();

            let result =
                with_current_token(token.clone(), async { logic.check_safe().await }).await;

            match result {
                Err(GarrisonError::NotSafe { reason }) => {
                    assert_eq!(
                        reason, "SAFE_EXPIRED",
                        "未 open_safe 时 check_safe 应返回 NotSafe(reason=\"SAFE_EXPIRED\")"
                    );
                },
                other => panic!(
                    "未 open_safe 时 check_safe 应返回 Err(NotSafe {{ reason: \"SAFE_EXPIRED\" }})，实际: {:?}",
                    other
                ),
            }
        }

        /// login → open_safe("default", 0)（立即过期）→ check_safe → 返回 Err(NotSafe)。
        ///
        /// 验证 duration_secs=0 导致立即过期后，check_safe 能正确识别过期状态。
        #[tokio::test]
        async fn t025_check_safe_fails_after_expiry() {
            let (logic, _dao) = make_logic();
            let token = logic
                .login("user-4003", &LoginParams::default())
                .await
                .unwrap();

            let result = with_current_token(token.clone(), async {
                logic.open_safe("default", 0).await.unwrap();
                logic.check_safe().await
            })
            .await;

            match result {
                Err(GarrisonError::NotSafe { reason }) => {
                    assert_eq!(
                        reason, "SAFE_EXPIRED",
                        "过期后 check_safe 应返回 NotSafe(reason=\"SAFE_EXPIRED\")"
                    );
                },
                other => panic!(
                    "过期后 check_safe 应返回 Err(NotSafe {{ reason: \"SAFE_EXPIRED\" }})，实际: {:?}",
                    other
                ),
            }
        }

        /// login → open_safe("default") → close_safe("default") → check_safe → 返回 Err(NotSafe)。
        ///
        /// 验证 close_safe 关闭二级认证后，check_safe 能正确识别未认证状态。
        #[tokio::test]
        async fn t025_check_safe_fails_after_close_safe() {
            let (logic, _dao) = make_logic();
            let token = logic
                .login("user-4004", &LoginParams::default())
                .await
                .unwrap();

            let result = with_current_token(token.clone(), async {
                logic.open_safe("default", 3600).await.unwrap();
                logic.close_safe("default").await.unwrap();
                logic.check_safe().await
            })
            .await;

            match result {
                Err(GarrisonError::NotSafe { reason }) => {
                    assert_eq!(
                        reason, "SAFE_EXPIRED",
                        "close_safe 后 check_safe 应返回 NotSafe(reason=\"SAFE_EXPIRED\")"
                    );
                },
                other => panic!(
                    "close_safe 后 check_safe 应返回 Err(NotSafe {{ reason: \"SAFE_EXPIRED\" }})，实际: {:?}",
                    other
                ),
            }
        }
    }
    // ========================================================================
    // 新鲜度断言（auth_time / aal 门槛）与 Required Action 三段式
    // ========================================================================

    use crate::stp::mfa::{
        assert_freshness, stepup_required, FreshnessInput, FreshnessVerdict, MfaFreshness,
    };
    #[cfg(feature = "secure-totp")]
    use crate::stp::mfa::{ProcessOutcome, RequiredActionContext};

    /// 新鲜度：auth_time 在窗口内且账本最高 AAL 达标 → Fresh（免二次 challenge）。
    #[test]
    fn freshness_fresh_within_window_and_aal() {
        let threshold = MfaFreshness {
            max_age_secs: 300,
            min_aal: 1,
        };
        let input = FreshnessInput {
            auth_time: Some(1_000),
            ledger_max_aal: 1,
            now: 1_000 + 299,
        };
        assert_eq!(
            assert_freshness(&input, &threshold),
            FreshnessVerdict::Fresh
        );
        assert!(
            !stepup_required(&input, &threshold, false),
            "新鲜会话不应触发 step-up"
        );
    }

    /// 新鲜度：auth_time 超窗 → Stale（触发 Required Action）。
    #[test]
    fn freshness_stale_after_window() {
        let threshold = MfaFreshness {
            max_age_secs: 300,
            min_aal: 1,
        };
        let input = FreshnessInput {
            auth_time: Some(1_000),
            ledger_max_aal: 2,
            now: 1_000 + 301,
        };
        assert_eq!(
            assert_freshness(&input, &threshold),
            FreshnessVerdict::Stale
        );
        assert!(stepup_required(&input, &threshold, false));
    }

    /// 新鲜度：账本最高 AAL 低于门槛 → Stale（即使时间未超窗）。
    #[test]
    fn freshness_stale_when_aal_below_threshold() {
        let threshold = MfaFreshness {
            max_age_secs: 300,
            min_aal: 2,
        };
        let input = FreshnessInput {
            auth_time: Some(1_000),
            ledger_max_aal: 1,
            now: 1_005,
        };
        assert_eq!(
            assert_freshness(&input, &threshold),
            FreshnessVerdict::Stale
        );
    }

    /// 新鲜度：无 auth_time（历史会话）→ Stale（fail-closed）。
    #[test]
    fn freshness_stale_without_auth_time() {
        let threshold = MfaFreshness {
            max_age_secs: 300,
            min_aal: 1,
        };
        let input = FreshnessInput {
            auth_time: None,
            ledger_max_aal: 2,
            now: 1_000,
        };
        assert_eq!(
            assert_freshness(&input, &threshold),
            FreshnessVerdict::Stale
        );
    }

    /// 有效的 MFA remember cookie 跳过二次 challenge（压过过期会话）。
    #[test]
    fn valid_remember_cookie_skips_challenge() {
        let threshold = MfaFreshness {
            max_age_secs: 300,
            min_aal: 1,
        };
        let stale = FreshnessInput {
            auth_time: Some(1_000),
            ledger_max_aal: 2,
            now: 1_000 + 301,
        };
        assert!(stepup_required(&stale, &threshold, false));
        assert!(
            !stepup_required(&stale, &threshold, true),
            "有效 remember cookie 应跳过重复 challenge"
        );
    }

    /// process 验证成功后经 complete_required_action 升级账本（otp / AAL 2）。
    #[cfg(feature = "secure-totp")]
    #[tokio::test]
    async fn totp_provider_process_upgrades_ledger() {
        use crate::constants::DaoKeyPrefix;
        use crate::dao::tests::MockDao;
        use crate::dao::GarrisonDao;
        use crate::session::GarrisonSession;
        use crate::session::TokenSession;
        use crate::stp::mfa::{complete_required_action, TotpRequiredActionProvider};
        use std::sync::Arc;

        let dao = Arc::new(MockDao::new());
        let session = GarrisonSession::new(dao.clone() as Arc<dyn GarrisonDao>, 3600, 86400, 0);
        session.create("user-ta", "TOK").await.unwrap();
        // 人为老化 auth_time 使会话过期（走 DAO 直写，模拟时间流逝）
        let key = format!("{}session:{}", DaoKeyPrefix::Token, "TOK");
        let raw = dao.get(&key).await.unwrap().unwrap();
        let mut ts: TokenSession = serde_json::from_str(&raw).unwrap();
        ts.auth_time = Some(chrono::Utc::now().timestamp() - 3600);
        dao.set(&key, &serde_json::to_string(&ts).unwrap(), 3600)
            .await
            .unwrap();

        let now = chrono::Utc::now().timestamp();
        let ctx = RequiredActionContext {
            login_id: "user-ta".to_string(),
            auth_time: ts.auth_time,
            ledger_max_aal: 1,
            now,
        };
        let threshold = MfaFreshness {
            max_age_secs: 300,
            min_aal: 2,
        };
        let provider = TotpRequiredActionProvider::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        // evaluate：过期会话触发 Required Action
        assert!(
            provider.evaluate(&ctx, &threshold).await.unwrap(),
            "过期会话应触发 Required Action"
        );
        // challenge：产出非空挑战
        let challenge = provider.challenge(&ctx).await.unwrap();
        assert_eq!(challenge.action, "otp");
        assert!(!challenge.payload.is_empty());
        // process：正确验证码 → Verified
        let code = provider.generate_current_code(now).unwrap();
        let outcome = provider.process(&ctx, &code, dao.as_ref()).await.unwrap();
        match outcome {
            ProcessOutcome::Verified { method, aal } => {
                assert_eq!(method, "otp");
                assert_eq!(aal, 2);
            },
            other => panic!("正确验证码应 Verified，实际: {:?}", other),
        }
        // 账本升级
        complete_required_action(&session, "TOK", &outcome, now)
            .await
            .unwrap();
        let upgraded = session.get_token_session("TOK").await.unwrap().unwrap();
        assert_eq!(upgraded.amr_ledger.len(), 2);
        assert_eq!(upgraded.amr_ledger[1].method, "otp");
        assert_eq!(upgraded.amr_ledger[1].aal, 2);
        assert_eq!(
            crate::stp::mfa::ledger_max_aal(&upgraded.amr_ledger),
            2,
            "process 验证成功后账本最高 AAL 应升级"
        );
    }

    /// process 错误验证码 → Rejected 且账本不变。
    #[cfg(feature = "secure-totp")]
    #[tokio::test]
    async fn totp_provider_process_wrong_code_rejected() {
        use crate::dao::tests::MockDao;
        use crate::dao::GarrisonDao;
        use crate::session::GarrisonSession;
        use crate::stp::mfa::TotpRequiredActionProvider;
        use std::sync::Arc;

        let dao = Arc::new(MockDao::new());
        let session = GarrisonSession::new(dao.clone() as Arc<dyn GarrisonDao>, 3600, 86400, 0);
        session.create("user-tb", "TOK2").await.unwrap();

        let provider = TotpRequiredActionProvider::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let ctx = RequiredActionContext {
            login_id: "user-tb".to_string(),
            auth_time: Some(chrono::Utc::now().timestamp() - 3600),
            ledger_max_aal: 1,
            now: chrono::Utc::now().timestamp(),
        };
        let outcome = provider
            .process(&ctx, "000000", dao.as_ref())
            .await
            .unwrap();
        assert!(
            matches!(outcome, ProcessOutcome::Rejected),
            "错误验证码应 Rejected，实际: {:?}",
            outcome
        );
        let ts = session.get_token_session("TOK2").await.unwrap().unwrap();
        assert_eq!(ts.amr_ledger.len(), 1, "Rejected 不得升级账本");
    }

    /// evaluate 对新鲜会话不触发 Required Action。
    #[cfg(feature = "secure-totp")]
    #[tokio::test]
    async fn totp_provider_evaluate_fresh_session_skips() {
        use crate::stp::mfa::TotpRequiredActionProvider;

        let now = chrono::Utc::now().timestamp();
        let ctx = RequiredActionContext {
            login_id: "user-tc".to_string(),
            auth_time: Some(now),
            ledger_max_aal: 2,
            now,
        };
        let threshold = MfaFreshness {
            max_age_secs: 300,
            min_aal: 1,
        };
        let provider = TotpRequiredActionProvider::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert!(
            !provider.evaluate(&ctx, &threshold).await.unwrap(),
            "新鲜会话不应触发 Required Action"
        );
    }

    // ========================================================================
    // 恢复码：批量一次性生成 / verify-consume 分离 / CAS 原子消费 / 误用容忍
    // ========================================================================

    use crate::dao::tests::MockDao;
    #[cfg(feature = "mfa-recovery")]
    use crate::stp::mfa::{RecoveryCodeManager, RecoveryVerify};

    /// 批量生成：数量正确、码非空且互不相同（一次性批次）。
    #[cfg(feature = "mfa-recovery")]
    #[tokio::test]
    async fn recovery_generate_batch_unique_codes() {
        let dao = Arc::new(MockDao::new());
        let mgr = RecoveryCodeManager::new(dao, 0);
        let codes = mgr.generate("user-rc", 10).await.unwrap();
        assert_eq!(codes.len(), 10);
        assert!(codes.iter().all(|c| !c.is_empty()));
        let unique: std::collections::HashSet<&String> = codes.iter().collect();
        assert_eq!(unique.len(), 10, "同批次码不得重复");
    }

    /// verify 对未用码返回 Valid；consume 后 verify 变 Invalid（已用码拒绝）。
    #[cfg(feature = "mfa-recovery")]
    #[tokio::test]
    async fn recovery_used_code_rejected() {
        let dao = Arc::new(MockDao::new());
        let mgr = RecoveryCodeManager::new(dao, 0);
        let codes = mgr.generate("user-rc2", 1).await.unwrap();
        let code = codes[0].clone();

        assert_eq!(
            mgr.verify("user-rc2", &code).await.unwrap(),
            RecoveryVerify::Valid
        );
        assert!(
            mgr.consume("user-rc2", &code).await.unwrap(),
            "首次 consume 应成功"
        );
        assert_eq!(
            mgr.verify("user-rc2", &code).await.unwrap(),
            RecoveryVerify::Invalid,
            "已用码 verify 应拒绝"
        );
        assert!(
            !mgr.consume("user-rc2", &code).await.unwrap(),
            "已用码二次消费应失败"
        );
    }

    /// 并发消费同一码：CAS 原子性保证仅一个成功。
    #[cfg(feature = "mfa-recovery")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn recovery_concurrent_consume_only_one_succeeds() {
        let dao = Arc::new(MockDao::new());
        let mgr = Arc::new(RecoveryCodeManager::new(dao, 0));
        let codes = mgr.generate("user-rc3", 1).await.unwrap();
        let code = codes[0].clone();

        let m1 = Arc::clone(&mgr);
        let m2 = Arc::clone(&mgr);
        let c1 = code.clone();
        let c2 = code.clone();
        let (r1, r2) = tokio::join!(
            async move { m1.consume("user-rc3", &c1).await },
            async move { m2.consume("user-rc3", &c2).await },
        );
        let successes = [r1.unwrap(), r2.unwrap()]
            .into_iter()
            .filter(|ok| *ok)
            .count();
        assert_eq!(successes, 1, "并发消费同一恢复码应恰好一个成功");
    }

    /// 误用超限锁定：tolerance=0 时一次无效 verify 即锁定（默认 0 豁免）。
    #[cfg(feature = "mfa-recovery")]
    #[tokio::test]
    async fn recovery_misuse_over_tolerance_locks() {
        let dao = Arc::new(MockDao::new());
        let mgr = RecoveryCodeManager::new(dao, 0);
        let codes = mgr.generate("user-rc4", 1).await.unwrap();

        assert_eq!(
            mgr.verify("user-rc4", "wrong-code").await.unwrap(),
            RecoveryVerify::Locked,
            "tolerance=0 时首次误用即锁定"
        );
        // 锁定后连正确码也拒绝消费（fail-closed）
        assert!(
            mgr.consume("user-rc4", &codes[0]).await.is_err(),
            "锁定状态下 consume 应返回错误"
        );
    }

    /// 误用豁免：tolerance=2 时前两次误用仅 Invalid，第三次锁定。
    #[cfg(feature = "mfa-recovery")]
    #[tokio::test]
    async fn recovery_misuse_within_tolerance_excused() {
        let dao = Arc::new(MockDao::new());
        let mgr = RecoveryCodeManager::new(dao, 2);
        let codes = mgr.generate("user-rc5", 1).await.unwrap();

        assert_eq!(
            mgr.verify("user-rc5", "bad-1").await.unwrap(),
            RecoveryVerify::Invalid
        );
        assert_eq!(
            mgr.verify("user-rc5", "bad-2").await.unwrap(),
            RecoveryVerify::Invalid
        );
        assert_eq!(
            mgr.verify("user-rc5", "bad-3").await.unwrap(),
            RecoveryVerify::Locked,
            "第三次误用（超过 tolerance=2）应锁定"
        );
        assert!(
            mgr.consume("user-rc5", &codes[0]).await.is_err(),
            "锁定后正确码也不得消费"
        );
    }

    // ========================================================================
    // MFA remember cookie：签发/校验（经单一构建点）
    // ========================================================================

    /// 有效 cookie：签发 → 校验通过（可跳过重复 challenge），Set-Cookie 属性
    /// 全部来自 Set-Cookie 单一构建点（HttpOnly / SameSite / Path / Max-Age）。
    #[cfg(feature = "protocol-jwt")]
    #[test]
    fn mfa_remember_cookie_roundtrip_and_buildpoint_attributes() {
        let config = GarrisonConfig::default_config();
        let secret = "0123456789abcdef0123456789abcdef";
        let set_cookie =
            issue_mfa_remember_cookie(secret, &config, "login", "user-rc", "cred-1", 3600).unwrap();
        // 写读一致：读侧用构建点的 resolved_name 解析同名（production 前缀自动生效）
        let expected_name = CookieType::session(MFA_REMEMBER_COOKIE_NAME, &config)
            .unwrap()
            .resolved_name(config.cookie_secure);
        assert!(
            set_cookie.starts_with(&format!("{expected_name}=")),
            "cookie 名应与构建点 resolved_name 一致，实际: {}",
            set_cookie
        );
        assert!(
            set_cookie.contains("HttpOnly"),
            "HttpOnly 恒定，实际: {}",
            set_cookie
        );
        assert!(set_cookie.contains("SameSite="), "实际: {}", set_cookie);
        assert!(set_cookie.contains("Path=/"), "实际: {}", set_cookie);
        assert!(set_cookie.contains("Max-Age=3600"), "实际: {}", set_cookie);

        let jwt = set_cookie
            .split(';')
            .next()
            .unwrap()
            .splitn(2, '=')
            .nth(1)
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(
            verify_mfa_remember_cookie(secret, jwt, "login", "user-rc", "cred-1", now),
            "有效 cookie 应通过校验（跳过重复 challenge）"
        );
    }

    /// 跨 credential 不通用：credential_id 不符 → false。
    #[cfg(feature = "protocol-jwt")]
    #[test]
    fn mfa_remember_cookie_not_portable_across_credentials() {
        let config = GarrisonConfig::default_config();
        let secret = "0123456789abcdef0123456789abcdef";
        let set_cookie =
            issue_mfa_remember_cookie(secret, &config, "login", "user-rc", "cred-1", 3600).unwrap();
        let jwt = set_cookie
            .split(';')
            .next()
            .unwrap()
            .splitn(2, '=')
            .nth(1)
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(
            !verify_mfa_remember_cookie(secret, jwt, "login", "user-rc", "cred-2", now),
            "跨 credential 的 cookie 不得通用"
        );
        assert!(
            !verify_mfa_remember_cookie(secret, jwt, "other-stage", "user-rc", "cred-1", now),
            "跨 stage 的 cookie 不得通用"
        );
    }

    /// 跨主体不通用：login_id 不符 → false（防持有式豁免跨主体复用）。
    #[cfg(feature = "protocol-jwt")]
    #[test]
    fn mfa_remember_cookie_not_portable_across_subjects() {
        let config = GarrisonConfig::default_config();
        let secret = "0123456789abcdef0123456789abcdef";
        let set_cookie =
            issue_mfa_remember_cookie(secret, &config, "login", "user-a", "cred-1", 3600).unwrap();
        let jwt = set_cookie
            .split(';')
            .next()
            .unwrap()
            .splitn(2, '=')
            .nth(1)
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(
            !verify_mfa_remember_cookie(secret, jwt, "login", "user-b", "cred-1", now),
            "跨主体的 cookie 不得通用"
        );
    }

    /// 过期失效：exp 已过（leeway=0）→ false。
    #[cfg(feature = "protocol-jwt")]
    #[test]
    fn mfa_remember_cookie_expired_is_invalid() {
        let secret = "0123456789abcdef0123456789abcdef";
        let claims = MfaRememberClaims {
            stage: "login".to_string(),
            login_id: "user-rc".to_string(),
            credential_id: "cred-1".to_string(),
            exp: chrono::Utc::now().timestamp() - 10,
        };
        let jwt = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        assert!(
            !verify_mfa_remember_cookie(
                secret,
                &jwt,
                "login",
                "user-rc",
                "cred-1",
                chrono::Utc::now().timestamp()
            ),
            "过期 cookie 应失效"
        );
    }

    /// 篡改载荷（密钥不符）→ false；短密钥签发 fail-fast。
    #[cfg(feature = "protocol-jwt")]
    #[test]
    fn mfa_remember_cookie_rejects_tamper_and_short_secret() {
        let config = GarrisonConfig::default_config();
        let secret = "0123456789abcdef0123456789abcdef";
        let set_cookie =
            issue_mfa_remember_cookie(secret, &config, "login", "user-rc", "cred-1", 3600).unwrap();
        let jwt = set_cookie
            .split(';')
            .next()
            .unwrap()
            .splitn(2, '=')
            .nth(1)
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(!verify_mfa_remember_cookie(
            "ffffffffffffffffffffffffffffffff",
            jwt,
            "login",
            "user-rc",
            "cred-1",
            now
        ));

        let result =
            issue_mfa_remember_cookie("short", &config, "login", "user-rc", "cred-1", 3600);
        assert!(
            matches!(result, Err(GarrisonError::Config(ref m)) if m.contains("mfa-remember-secret-too-short")),
            "短密钥应 fail-fast，实际: {:?}",
            result.map(|_| ())
        );
    }

    /// SameSite=None + 非 Secure 上下文：构建点自动降级为 Lax（构建点不变式）。
    #[cfg(feature = "protocol-jwt")]
    #[test]
    fn mfa_remember_cookie_none_downgrades_via_buildpoint() {
        let mut config = GarrisonConfig::default_config();
        config.cookie_same_site = "None".to_string();
        config.cookie_secure = false;
        let set_cookie = issue_mfa_remember_cookie(
            "0123456789abcdef0123456789abcdef",
            &config,
            "login",
            "user-rc",
            "c",
            60,
        )
        .unwrap();
        assert!(
            set_cookie.contains("SameSite=Lax"),
            "非 Secure 上下文应降级 Lax，实际: {}",
            set_cookie
        );
        assert!(!set_cookie.contains("SameSite=None"));
    }
    // ========================================================================
    // MFA 强制链 gate 接线：check_mfa_chain + check_safe 前置链校验
    // ========================================================================

    use crate::stp::mfa::{chain_factor_amr, first_unmet_chain_factor};

    /// chain factor → amr 映射：词汇表内一一对应，词汇表外 None（兜底拒绝）。
    #[test]
    fn chain_factor_amr_maps_vocabulary() {
        assert_eq!(chain_factor_amr("otp"), Some("otp"));
        assert_eq!(chain_factor_amr("webauthn"), Some("webauthn"));
        assert_eq!(chain_factor_amr("sms"), None);
    }

    /// 链覆盖判定：账本覆盖全部强制 factor → None；缺失 → 返回首个未满足 factor。
    #[test]
    fn first_unmet_chain_factor_finds_gap() {
        use crate::stp::mfa::MfaChainDecision;
        let ledger = vec![AmrEntry::new("pwd", 1, 1).unwrap()];
        let decision = MfaChainDecision::Require(vec!["otp".to_string()]);
        assert_eq!(
            first_unmet_chain_factor(&decision, &ledger),
            Some("otp".to_string())
        );
        let full = vec![
            AmrEntry::new("pwd", 1, 1).unwrap(),
            AmrEntry::new("otp", 2, 2).unwrap(),
        ];
        assert_eq!(first_unmet_chain_factor(&decision, &full), None);
        // Disabled 一律满足
        assert_eq!(
            first_unmet_chain_factor(&MfaChainDecision::None, &ledger),
            None
        );
    }

    /// 构造已登录的 GarrisonLogicDefault（返回 logic 与 token）。
    async fn logged_in_logic(config: GarrisonConfig) -> (GarrisonLogicDefault, String) {
        use crate::account::disable::DefaultDisableRepository;
        use crate::dao::tests::MockDao;
        use crate::dao::GarrisonDao;
        use crate::session::GarrisonSession;
        use crate::strategy::GarrisonPermissionStrategy;

        struct NoopFirewall;

        #[async_trait::async_trait]
        impl GarrisonPermissionStrategy for NoopFirewall {
            async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec![])
            }
            async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec![])
            }
            async fn check_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role(&self, _login_id: &str, _role: &str) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_any(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_all(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_permission_in_tenant(
                &self,
                _tenant_id: i64,
                _login_id: &str,
                _permission: &str,
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_in_tenant(
                &self,
                _tenant_id: i64,
                _login_id: &str,
                _role: &str,
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            #[cfg(any(
                feature = "sms-rate-limit",
                feature = "firewall-ratelimit",
                feature = "firewall-bruteforce",
                feature = "firewall-ddos",
                feature = "firewall",
                feature = "oauth2-server"
            ))]
            async fn check_login_hooks(
                &self,
                _login_id: &str,
                _ctx: &crate::strategy::hooks::LoginContext,
            ) -> GarrisonResult<()> {
                Ok(())
            }
        }

        let dao = Arc::new(MockDao::new());
        let session = Arc::new(GarrisonSession::new(
            dao.clone() as Arc<dyn GarrisonDao>,
            3600,
            86400,
            0,
        ));
        let mut config = config;
        config.throw_on_not_login = false;
        let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(NoopFirewall);
        let logic = GarrisonLogicDefault::new(
            session,
            Arc::new(config),
            firewall,
            Arc::new(DefaultDisableRepository::new(dao as Arc<dyn GarrisonDao>)),
        );
        let token = logic
            .login("chain-user", &LoginParams::default())
            .await
            .unwrap();
        (logic, token)
    }

    /// 全局强制链：账本缺 otp 时 check_mfa_chain 拒绝（NotSafe + 具体 factor），
    /// step-up 补齐后通过——gate 面真实强制，不是休眠配置。
    #[tokio::test]
    async fn check_mfa_chain_enforces_global_chain() {
        let mut config = GarrisonConfig::default_config();
        config.mfa.global_chain = vec!["otp".to_string()];
        let (logic, token) = logged_in_logic(config).await;

        use crate::stp::with_current_token;
        let result =
            with_current_token(token.clone(), async { logic.check_mfa_chain(None).await }).await;
        match &result {
            Err(GarrisonError::NotSafe { reason }) => assert_eq!(
                reason, "MFA_CHAIN_INCOMPLETE::otp",
                "缺 otp 时应报告具体缺失因子"
            ),
            other => panic!("账本未覆盖强制链应 Err，实际 ok={:?}", other.is_ok()),
        }

        // step-up 补齐 otp → gate 通过
        logic
            .session
            .append_amr_entry(&token, "otp", 2, chrono::Utc::now().timestamp())
            .await
            .unwrap();
        let result = with_current_token(token, async { logic.check_mfa_chain(None).await }).await;
        assert!(
            result.is_ok(),
            "补齐后链校验应通过，实际: {:?}",
            result.err()
        );
    }

    /// per-client 显式禁用（空集）压过全局强制链；非空集覆盖全局。
    #[tokio::test]
    async fn check_mfa_chain_per_client_tri_state() {
        use crate::stp::with_current_token;

        // 全局 ["otp"]，client-acme 显式禁用
        let mut config = GarrisonConfig::default_config();
        config.mfa.global_chain = vec!["otp".to_string()];
        config
            .mfa
            .per_client_chains
            .insert("acme".to_string(), vec![]);
        let (logic, token) = logged_in_logic(config).await;
        let ok =
            with_current_token(token, async { logic.check_mfa_chain(Some("acme")).await }).await;
        assert!(
            ok.is_ok(),
            "显式禁用的 client 不应强制，实际: {:?}",
            ok.err()
        );

        // client-web 非空集 ["otp"] 覆盖全局（同为 otp 但路径不同），未 step-up → 拒绝
        let mut config = GarrisonConfig::default_config();
        config.mfa.global_chain = vec![];
        config
            .mfa
            .per_client_chains
            .insert("web".to_string(), vec!["otp".to_string()]);
        let (logic, token) = logged_in_logic(config).await;
        let result =
            with_current_token(token, async { logic.check_mfa_chain(Some("web")).await }).await;
        assert!(
            matches!(&result, Err(GarrisonError::NotSafe { reason }) if reason == "MFA_CHAIN_INCOMPLETE::otp"),
            "per-client 强制集应生效，实际: {:?}",
            result.map(|_| ())
        );
    }

    /// check_safe 前置链校验：链未满足时在 safe-service 检查之前即拒绝
    /// （authflow Mfa 步骤与 /auth/check-safe 端点经此路径获得链强制）。
    #[cfg(feature = "security-extra")]
    #[tokio::test]
    async fn check_safe_enforces_chain_before_safe_service() {
        use crate::stp::with_current_token;

        let mut config = GarrisonConfig::default_config();
        config.mfa.global_chain = vec!["otp".to_string()];
        let (logic, token) = logged_in_logic(config).await;
        let result = with_current_token(token, async { logic.check_safe().await }).await;
        match &result {
            Err(GarrisonError::NotSafe { reason }) => assert!(
                reason.starts_with("MFA_CHAIN_INCOMPLETE"),
                "链校验应先于 safe-service 检查，实际: {}",
                reason
            ),
            other => panic!("链未满足时 check_safe 应 Err，实际 ok={:?}", other.is_ok()),
        }
    }
}
