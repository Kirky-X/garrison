//! AuthExecutor 核心（v0.6.0 新增，依据 spec auth-flow-dsl R-auth-flow-dsl-008 / R-auth-flow-dsl-009）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 提供认证流程执行引擎，按 [`AuthenticationFlow`] 步骤顺序执行认证逻辑。
//!
//! # 设计冲突解决（R-008 五字段 vs Login 步骤需要 CredentialBuilder）
//!
//! spec R-008 要求 [`AuthExecutor`] 严格 5 字段，但 Login 步骤需要
//! `CredentialModel → dyn Credential` 转换（需 `CredentialBuilder`）。
//!
//! 解决方案：定义 [`CredentialBuilder`] trait 作为 `execute_with_builder` 的参数
//! （非 struct 字段），保持 5 字段不变。`execute`（spec R-009 签名）在遇到 Login
//! 步骤时返回 `Failed`（无 builder），完整 Login 支持使用 `execute_with_builder`。
//!
//! # T017：SocialProvider + SsoServer 步骤扩展
//!
//! 同样的设计模式应用于社交登录与 SSO 登录步骤：定义 [`SocialProviderResolver`] /
//! [`SsoServerResolver`] trait 作为 [`AuthExecutor::execute_with_full`] 的参数
//! （非 struct 字段），保持 5 字段不变。
//!
//! resolver trait 方法返回 `BulwarkResult<String>`（login_id），由实现方在内部委托
//! `protocol::social::SocialLoginProvider::exchange_token` /
//! `protocol::sso::server::SsoServer::validate_ticket`。这样 `executor.rs` 不直接
//! 依赖 `protocol` 模块，避免 feature gate 链穿透 `account-authflow` feature。
//!
//! # 核心类型
//!
//! - [`CredentialBuilder`]：凭证构造 trait（`CredentialModel → Box<dyn Credential>`）
//! - [`SocialProviderResolver`]：社交登录 provider 解析 trait（T017）
//! - [`SsoServerResolver`]：SSO Server 解析 trait（T017）
//! - [`AuthExecutor`]：认证执行器（5 字段：logic / credential_repo / policy_engine / lockout / registry）

use super::registry::FlowRegistry;
use super::{AuthCondition, AuthContext, AuthResult, AuthStep, AuthenticationFlow};
use crate::account::credential::{Credential, CredentialModel, CredentialRepository};
use crate::account::lockout::UserLockoutStrategy;
use crate::account::policy::PasswordPolicyEngine;
use crate::error::BulwarkResult;
use crate::stp::{BulwarkLogicDefault, MfaLogic, SessionLogic};
use crate::strategy::firewall::{BulwarkFirewallStrategy, FirewallContext};
use async_trait::async_trait;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// AuthenticationFlow 嵌套递归最大深度（防止循环引用导致栈溢出）。
const MAX_FLOW_DEPTH: usize = 10;

// ============================================================================
// CredentialBuilder trait（解决 R-008 五字段约束）
// ============================================================================

/// 凭证构造 trait，将 `CredentialModel` 转换为 `Box<dyn Credential>`。
///
/// Login / Mfa(Some) 步骤需要通过此 trait 将 DAO 查询到的 [`CredentialModel`]
/// 转换为可校验的 [`Credential`] 实例（如 `PasswordCredential` / `TotpCredential`）。
///
/// # 设计理由
///
/// 此 trait 不作为 [`AuthExecutor`] 的字段（R-008 严格 5 字段约束），
/// 而是作为 [`AuthExecutor::execute_with_builder`] 的参数传入。
/// [`AuthExecutor::execute`]（spec R-009 签名）不接收 builder，
/// 遇到 Login 步骤时返回 `Failed`。
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::authflow::executor::CredentialBuilder;
/// use bulwark::account::credential::{CredentialModel, Credential, password::Argon2Hasher};
/// use bulwark::account::credential::password::PasswordCredential;
/// use bulwark::error::BulwarkResult;
///
/// struct PasswordCredentialBuilder;
/// impl CredentialBuilder for PasswordCredentialBuilder {
///     fn build(&self, model: CredentialModel) -> BulwarkResult<Box<dyn Credential>> {
///         let hasher = Box::new(Argon2Hasher::new());
///         Ok(Box::new(PasswordCredential::new(model, hasher)))
///     }
/// }
/// ```
pub trait CredentialBuilder: Send + Sync {
    /// 将 [`CredentialModel`] 构造为 `Box<dyn Credential>`。
    ///
    /// # 错误
    /// - 凭证类型不支持：`BulwarkError::InvalidParam`
    /// - 哈希器初始化失败：透传 `BulwarkError`
    fn build(&self, model: CredentialModel) -> BulwarkResult<Box<dyn Credential>>;
}

// ============================================================================
// SocialProviderResolver / SsoServerResolver（T017，解决 R-008 五字段约束）
// ============================================================================

/// 社交登录 provider 解析 trait（T017，依据 spec auth-flow-dsl R-auth-flow-dsl-010）。
///
/// 在 [`AuthExecutor::execute_with_full`] 中作为参数传入（非 struct 字段，保持 R-008
/// 5 字段不变）。实现方在内部委托
/// `protocol::social::SocialLoginProvider::exchange_token(code, state)` 并返回
/// `provider_user_id`（作为 `login_id`）。
///
/// # 设计理由
///
/// `executor.rs` 不直接 `use protocol::social::SocialLoginProvider`，避免 feature gate
/// 链穿透 `account-authflow` feature（社交登录仅在 `social-wechat`/`social-alipay`
/// 启用时编译）。resolver 实现方负责 provider 注册表维护与 OAuth2 调用细节。
///
/// # 参数语义
///
/// - `provider`: provider 名称（`AuthStep::SocialProvider { provider }` 字段，如
///   `"wechat"` / `"alipay"` / `"keycloak"`）
/// - `code`: OAuth2 授权码（来自 `ctx.input`）
/// - `state`: OAuth2 state 参数（来自 `ctx.extras["state"]`，CSRF 防护）
///
/// # 返回
///
/// - `Ok(login_id)`: 社交用户标识（`SocialUserInfo.provider_user_id`）
/// - `Err(BulwarkError::InvalidParam)`: provider 未注册
/// - `Err(_)`: provider 调用失败 / 网络错误 / 授权码无效
///
/// # 示例
///
/// ```ignore
/// use std::collections::HashMap;
/// use std::sync::Arc;
/// use bulwark::account::authflow::executor::SocialProviderResolver;
/// use bulwark::error::{BulwarkError, BulwarkResult};
///
/// struct Registry {
///     providers: HashMap<String, Arc<dyn bulwark::protocol::social::SocialLoginProvider>>,
/// }
///
/// #[async_trait::async_trait]
/// impl SocialProviderResolver for Registry {
///     async fn resolve_login_id(&self, provider: &str, code: &str, state: &str)
///         -> BulwarkResult<String> {
///         let p = self.providers.get(provider)
///             .ok_or_else(|| BulwarkError::InvalidParam(format!("unknown: {}", provider)))?;
///         let user = p.exchange_token(code, state).await?;
///         Ok(user.provider_user_id)
///     }
/// }
/// ```
#[async_trait]
pub trait SocialProviderResolver: Send + Sync {
    /// 用授权码换取 login_id（内部委托 `SocialLoginProvider::exchange_token`）。
    async fn resolve_login_id(
        &self,
        provider: &str,
        code: &str,
        state: &str,
    ) -> BulwarkResult<String>;
}

/// SSO Server 解析 trait（T017，依据 spec auth-flow-dsl R-auth-flow-dsl-011）。
///
/// 在 [`AuthExecutor::execute_with_full`] 中作为参数传入（非 struct 字段，保持 R-008
/// 5 字段不变）。实现方在内部委托
/// `protocol::sso::server::SsoServer::validate_ticket(ticket, client_id)` 并返回
/// `login_id`。
///
/// # 设计理由
///
/// 同 [`SocialProviderResolver`]：`executor.rs` 不直接 `use protocol::sso::server::SsoServer`，
/// 避免 feature gate 链穿透 `account-authflow` feature（SSO Server 仅在
/// `protocol-sso-server` 启用时编译）。
///
/// # 参数语义
///
/// - `server_id`: SSO 服务器标识（`AuthStep::SsoServer { server_id }` 字段）
/// - `ticket`: SSO 票据（来自 `ctx.input`）
/// - `client_id`: 客户端标识（来自 `ctx.extras["client_id"]`，解析为 `i64`）
///
/// # 返回
///
/// - `Ok(login_id)`: ticket 对应的登录主体标识
/// - `Err(BulwarkError::InvalidParam)`: server 未注册
/// - `Err(BulwarkError::InvalidToken)`: ticket 无效 / 已过期 / client_id 不匹配
#[async_trait]
pub trait SsoServerResolver: Send + Sync {
    /// 验证 ticket 并返回 login_id（内部委托 `SsoServer::validate_ticket`）。
    async fn validate_and_get_login_id(
        &self,
        server_id: &str,
        ticket: &str,
        client_id: i64,
    ) -> BulwarkResult<String>;
}

// ============================================================================
// AuthExecutor（依据 spec R-auth-flow-dsl-008）
// ============================================================================

/// 认证流程执行器（依据 spec auth-flow-dsl R-auth-flow-dsl-008）。
///
/// 按 [`AuthenticationFlow`] 步骤顺序执行认证逻辑，支持 Login / Mfa / Conditional /
/// SubFlow / SocialProvider / SsoServer 六种步骤类型（RequiredAction 待 v0.6.5 实现）。
///
/// # 5 字段 schema（R-008 严格约束）
///
/// | 字段 | 类型 | 说明 |
/// |:---|:---|:---|
/// | `logic` | `Arc<BulwarkLogicDefault>` | 核心认证逻辑（SessionLogic + MfaLogic） |
/// | `credential_repo` | `Arc<dyn CredentialRepository>` | 凭证存储抽象 |
/// | `policy_engine` | `Option<Arc<PasswordPolicyEngine>>` | 密码策略引擎（可选，用于 RequiredAction） |
/// | `lockout` | `Option<Arc<UserLockoutStrategy>>` | 用户级锁定策略（可选） |
/// | `registry` | `Arc<FlowRegistry>` | 流程注册表（用于 SubFlow 查询） |
///
/// # 设计冲突解决
///
/// Login 步骤需要 `CredentialBuilder` 将 `CredentialModel → dyn Credential` 转换，
/// 但 R-008 限制 5 字段。解决方案：[`CredentialBuilder`] 作为
/// [`execute_with_builder`](Self::execute_with_builder) 的参数而非 struct 字段。
///
/// # 示例
///
/// ```ignore
/// use std::sync::Arc;
/// use bulwark::account::authflow::executor::AuthExecutor;
/// use bulwark::account::authflow::registry::FlowRegistry;
///
/// let executor = AuthExecutor::new(
///     logic,
///     credential_repo,
///     None,               // policy_engine
///     None,               // lockout
///     Arc::new(FlowRegistry::from_inventory()),
/// );
/// let result = executor.execute_with_builder(&flow, &mut ctx, &builder).await?;
/// ```
pub struct AuthExecutor {
    /// 核心认证逻辑（SessionLogic::login / MfaLogic::check_safe）。
    logic: Arc<BulwarkLogicDefault>,
    /// 凭证存储抽象（查询用户凭证）。
    credential_repo: Arc<dyn CredentialRepository>,
    /// 密码策略引擎（可选，v0.6.0 未在 execute 中使用，预留给 RequiredAction 步骤）。
    policy_engine: Option<Arc<PasswordPolicyEngine>>,
    /// 用户级锁定策略（可选，Login 步骤前检查 + 失败时 record_failure）。
    lockout: Option<Arc<UserLockoutStrategy>>,
    /// 流程注册表（SubFlow 步骤查询子流程）。
    registry: Arc<FlowRegistry>,
}

/// 步骤执行结果（内部类型，非公开）。
///
/// [`execute_step`](AuthExecutor::execute_step) 返回此枚举，
/// [`execute_inner`](AuthExecutor::execute_inner) 据此决定继续/中断/暂停。
#[derive(Debug)]
enum StepOutcome {
    /// 步骤成功，`token` 为 Login 步骤生成的会话 token（非 Login 步骤为 None）。
    Success {
        /// Login 步骤生成的会话 token（其他步骤为 None）。
        token: Option<String>,
    },
    /// 步骤失败，携带失败原因。
    Failed(String),
    /// 需要挑战（如 MFA 需要用户输入验证码）。
    ChallengeRequired {
        /// 挑战类型（如 "totp" / "captcha"）。
        challenge_type: String,
        /// 挑战消息。
        message: String,
    },
}

impl AuthExecutor {
    /// 创建认证执行器实例。
    ///
    /// # 参数
    /// - `logic`: 核心认证逻辑（`Arc<BulwarkLogicDefault>`）。
    /// - `credential_repo`: 凭证存储抽象。
    /// - `policy_engine`: 密码策略引擎（可选，`None` 时 RequiredAction 步骤返回 Failed）。
    /// - `lockout`: 用户级锁定策略（可选，`None` 时跳过锁定检查）。
    /// - `registry`: 流程注册表（用于 SubFlow 查询）。
    ///
    /// # 返回
    /// 新建的 `AuthExecutor` 实例。
    pub fn new(
        logic: Arc<BulwarkLogicDefault>,
        credential_repo: Arc<dyn CredentialRepository>,
        policy_engine: Option<Arc<PasswordPolicyEngine>>,
        lockout: Option<Arc<UserLockoutStrategy>>,
        registry: Arc<FlowRegistry>,
    ) -> Self {
        Self {
            logic,
            credential_repo,
            policy_engine,
            lockout,
            registry,
        }
    }

    /// 获取密码策略引擎引用（供 RequiredAction 步骤使用）。
    pub fn policy_engine(&self) -> Option<&Arc<PasswordPolicyEngine>> {
        self.policy_engine.as_ref()
    }

    /// 获取用户级锁定策略引用。
    pub fn lockout(&self) -> Option<&Arc<UserLockoutStrategy>> {
        self.lockout.as_ref()
    }

    /// 执行认证流程（spec R-009 签名，无 CredentialBuilder / 无 Resolver）。
    ///
    /// 遇到 Login / Mfa(Some) 步骤时返回 `Failed`（无 builder 无法构造 Credential）。
    /// 遇到 SocialProvider / SsoServer 步骤时返回 `Failed`（无 resolver）。
    /// Mfa(None) / Conditional / SubFlow 步骤可正常执行。
    ///
    /// 完整 Login 支持请使用 [`execute_with_builder`](Self::execute_with_builder)。
    /// 完整 SocialProvider / SsoServer 支持请使用 [`execute_with_full`](Self::execute_with_full)。
    ///
    /// # 参数
    /// - `flow`: 认证流程定义。
    /// - `ctx`: 执行上下文（可变引用，执行过程中更新 `completed_steps`）。
    ///
    /// # 返回
    /// - `Ok(AuthResult::Success)`: 全部步骤通过。
    /// - `Ok(AuthResult::Failed)`: 某步骤失败且 `allow_skip=false`。
    /// - `Ok(AuthResult::Pending)`: 命中 `pause_after_step` 标记，等待下一步输入。
    /// - `Ok(AuthResult::ChallengeRequired)`: 步骤需要挑战（如 MFA 需要验证码）。
    /// - `Err(_)`: 基础设施故障（DAO / session 创建失败等）。
    pub async fn execute(
        &self,
        flow: &AuthenticationFlow,
        ctx: &mut AuthContext,
    ) -> BulwarkResult<AuthResult> {
        self.execute_inner(flow, ctx, None, None, None, None, 0)
            .await
    }

    /// 执行认证流程（带 CredentialBuilder，支持 Login 步骤）。
    ///
    /// Login 步骤通过 `builder` 将 `CredentialModel` 转换为 `dyn Credential` 后调用 `verify`。
    /// 遇到 SocialProvider / SsoServer 步骤时返回 `Failed`（无 resolver）。
    ///
    /// # 参数
    /// - `flow`: 认证流程定义。
    /// - `ctx`: 执行上下文（可变引用）。
    /// - `builder`: 凭证构造器（将 `CredentialModel → Box<dyn Credential>`）。
    ///
    /// # 返回
    /// 同 [`execute`](Self::execute)。
    pub async fn execute_with_builder(
        &self,
        flow: &AuthenticationFlow,
        ctx: &mut AuthContext,
        builder: &dyn CredentialBuilder,
    ) -> BulwarkResult<AuthResult> {
        self.execute_inner(flow, ctx, Some(builder), None, None, None, 0)
            .await
    }

    /// 执行认证流程（带 CredentialBuilder + SocialProviderResolver + SsoServerResolver，
    /// 支持 Login / SocialProvider / SsoServer 全部步骤类型，T017 新增）。
    ///
    /// SocialProvider 步骤通过 `social_resolver` 调用
    /// `SocialLoginProvider::exchange_token(ctx.input, state)` 取得 `provider_user_id`，
    /// 然后调用 `logic.login(&login_id)` 建立本地会话。
    ///
    /// SsoServer 步骤通过 `sso_resolver` 调用
    /// `SsoServer::validate_ticket(ctx.input, client_id)` 取得 `login_id`，然后调用
    /// `logic.login(&login_id)` 建立本地会话。
    ///
    /// # 参数
    /// - `flow`: 认证流程定义。
    /// - `ctx`: 执行上下文（可变引用）。
    /// - `builder`: 凭证构造器（Login 步骤用）。
    /// - `social_resolver`: 社交登录 provider 解析器（SocialProvider 步骤用）。
    /// - `sso_resolver`: SSO Server 解析器（SsoServer 步骤用）。
    ///
    /// # 返回
    /// 同 [`execute`](Self::execute)。
    pub async fn execute_with_full(
        &self,
        flow: &AuthenticationFlow,
        ctx: &mut AuthContext,
        builder: &dyn CredentialBuilder,
        social_resolver: &dyn SocialProviderResolver,
        sso_resolver: &dyn SsoServerResolver,
    ) -> BulwarkResult<AuthResult> {
        self.execute_inner(
            flow,
            ctx,
            Some(builder),
            Some(social_resolver),
            Some(sso_resolver),
            None,
            0,
        )
        .await
    }

    /// 执行认证流程（带 CredentialBuilder + AccountMetrics，支持指标采集，
    /// 依据 spec account-metrics D-001）。
    ///
    /// 与 [`execute_with_builder`](Self::execute_with_builder) 一致，额外注入
    /// `metrics` 用于采集 `authflow_execute_duration`（label = `flow.name`）与
    /// `credential_verify_duration`（label = `credential_type`，Login/Mfa 步骤 verify 前后）。
    ///
    /// 保持 R-008 五字段约束：`metrics` 作为方法参数传入，非 struct 字段。
    ///
    /// # 参数
    /// - `flow`: 认证流程定义。
    /// - `ctx`: 执行上下文（可变引用）。
    /// - `builder`: 凭证构造器（将 `CredentialModel → Box<dyn Credential>`）。
    /// - `metrics`: 账号安全指标（记录流程执行与凭证验证耗时）。
    ///
    /// # 返回
    /// 同 [`execute`](Self::execute)。
    #[cfg(feature = "metrics-prometheus")]
    pub async fn execute_with_metrics(
        &self,
        flow: &AuthenticationFlow,
        ctx: &mut AuthContext,
        builder: &dyn CredentialBuilder,
        metrics: &crate::account::metrics::AccountMetrics,
    ) -> BulwarkResult<AuthResult> {
        self.execute_inner(flow, ctx, Some(builder), None, None, Some(metrics), 0)
            .await
    }

    /// 执行认证流程核心逻辑（内部方法）。
    ///
    /// `builder` 为 `None` 时 Login / Mfa(Some) 步骤返回 `Failed`。
    /// `social_resolver` 为 `None` 时 SocialProvider 步骤返回 `Failed`。
    /// `sso_resolver` 为 `None` 时 SsoServer 步骤返回 `Failed`。
    /// `metrics` 为 `Some` 时记录 `authflow_execute_duration`（label = `flow.name`）。
    async fn execute_inner(
        &self,
        flow: &AuthenticationFlow,
        ctx: &mut AuthContext,
        builder: Option<&dyn CredentialBuilder>,
        social_resolver: Option<&dyn SocialProviderResolver>,
        sso_resolver: Option<&dyn SsoServerResolver>,
        metrics: Option<&crate::account::metrics::AccountMetrics>,
        depth: usize,
    ) -> BulwarkResult<AuthResult> {
        #[cfg(feature = "metrics-prometheus")]
        let flow_start = std::time::Instant::now();
        #[cfg(feature = "metrics-prometheus")]
        let flow_name = flow.name.clone();

        // 空流程：直接返回 Success（无步骤可失败）
        if flow.steps.is_empty() {
            let result = Ok(AuthResult::Success {
                login_id: ctx.user_id.clone().unwrap_or_default(),
                token: String::new(),
            });
            #[cfg(feature = "metrics-prometheus")]
            if let Some(m) = metrics {
                m.observe_authflow_execute(&flow_name, flow_start.elapsed());
            }
            return result;
        }

        let mut token: Option<String> = None;
        let mut early_result: Option<BulwarkResult<AuthResult>> = None;

        for (index, step) in flow.steps.iter().enumerate() {
            let outcome = self
                .execute_step(
                    step,
                    ctx,
                    builder,
                    social_resolver,
                    sso_resolver,
                    metrics,
                    depth,
                )
                .await?;

            match outcome {
                StepOutcome::Success { token: step_token } => {
                    ctx.completed_steps.push(index);
                    if let Some(t) = step_token {
                        token = Some(t);
                    }
                    // 检查 pause_after_step 标记
                    if let Some(pause_str) = ctx.extras.get("pause_after_step") {
                        if pause_str.parse::<usize>().ok() == Some(index)
                            && index + 1 < flow.steps.len()
                        {
                            let challenge = self.step_challenge(&flow.steps[index + 1]);
                            early_result = Some(Ok(AuthResult::Pending {
                                completed_step: index,
                                next_step: index + 1,
                                challenge,
                            }));
                            break;
                        }
                    }
                },
                StepOutcome::Failed(reason) => {
                    if flow.allow_skip {
                        continue;
                    }
                    early_result = Some(Ok(AuthResult::Failed {
                        reason,
                        step: index,
                    }));
                    break;
                },
                StepOutcome::ChallengeRequired {
                    challenge_type,
                    message,
                } => {
                    early_result = Some(Ok(AuthResult::ChallengeRequired {
                        challenge_type,
                        message,
                    }));
                    break;
                },
            }
        }

        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = metrics {
            m.observe_authflow_execute(&flow_name, flow_start.elapsed());
        }

        // 全部步骤通过 或 early_result 中断
        if let Some(result) = early_result {
            return result;
        }

        Ok(AuthResult::Success {
            login_id: ctx.user_id.clone().unwrap_or_default(),
            token: token.unwrap_or_default(),
        })
    }

    /// 执行单个认证步骤（内部方法）。
    ///
    /// 使用 `Pin<Box<dyn Future>>` 返回类型支持 Conditional 步骤的递归调用
    /// （async fn 不支持直接递归，需 boxing）。
    fn execute_step<'a>(
        &'a self,
        step: &'a AuthStep,
        ctx: &'a mut AuthContext,
        builder: Option<&'a dyn CredentialBuilder>,
        social_resolver: Option<&'a dyn SocialProviderResolver>,
        sso_resolver: Option<&'a dyn SsoServerResolver>,
        metrics: Option<&'a crate::account::metrics::AccountMetrics>,
        depth: usize,
    ) -> Pin<Box<dyn Future<Output = BulwarkResult<StepOutcome>> + Send + 'a>> {
        Box::pin(async move {
            match step {
                AuthStep::Login { credential_type } => {
                    self.execute_login(credential_type, ctx, builder, metrics)
                        .await
                },
                AuthStep::Mfa { credential_type } => {
                    self.execute_mfa(credential_type.as_ref(), ctx, builder, metrics)
                        .await
                },
                AuthStep::Conditional {
                    condition,
                    if_step,
                    else_step,
                } => {
                    let condition_result = self.evaluate_condition(condition, ctx).await?;
                    if condition_result {
                        self.execute_step(
                            if_step,
                            ctx,
                            builder,
                            social_resolver,
                            sso_resolver,
                            metrics,
                            depth,
                        )
                        .await
                    } else if let Some(else_step) = else_step {
                        self.execute_step(
                            else_step,
                            ctx,
                            builder,
                            social_resolver,
                            sso_resolver,
                            metrics,
                            depth,
                        )
                        .await
                    } else {
                        // else_step 为 None 时跳过（视为成功）
                        Ok(StepOutcome::Success { token: None })
                    }
                },
                AuthStep::SubFlow { flow_name } => {
                    self.execute_subflow(
                        flow_name,
                        ctx,
                        builder,
                        social_resolver,
                        sso_resolver,
                        metrics,
                        depth,
                    )
                    .await
                },
                AuthStep::SocialProvider { provider } => {
                    self.execute_social(provider, ctx, social_resolver).await
                },
                AuthStep::SsoServer { server_id } => {
                    self.execute_sso(server_id, ctx, sso_resolver).await
                },
                AuthStep::RequiredAction { .. } => Ok(StepOutcome::Failed(
                    "RequiredAction 步骤在 v0.6.0 未实现".to_string(),
                )),
            }
        })
    }

    /// 执行 Login 步骤（内部方法）。
    async fn execute_login(
        &self,
        credential_type: &str,
        ctx: &mut AuthContext,
        builder: Option<&dyn CredentialBuilder>,
        metrics: Option<&crate::account::metrics::AccountMetrics>,
    ) -> BulwarkResult<StepOutcome> {
        // 未启用 metrics-prometheus 时显式忽略 metrics 参数（避免 unused_variables warning）
        #[cfg(not(feature = "metrics-prometheus"))]
        let _ = metrics;

        // 锁定检查（Login 前检查用户是否被锁定）
        if let Some(lockout) = &self.lockout {
            if let Some(user_id) = &ctx.user_id {
                let fw_ctx = FirewallContext::new(&ctx.ip).with_login_id(user_id.clone());
                if let Err(e) = lockout.check(&fw_ctx).await {
                    return Ok(StepOutcome::Failed(format!("用户已被锁定: {}", e)));
                }
            }
        }

        // 需要 CredentialBuilder
        let builder = match builder {
            Some(b) => b,
            None => {
                return Ok(StepOutcome::Failed(
                    "Login 步骤需要 CredentialBuilder，请使用 execute_with_builder".to_string(),
                ));
            },
        };

        // 需要 user_id
        let user_id = match &ctx.user_id {
            Some(id) => id.clone(),
            None => {
                return Ok(StepOutcome::Failed("Login 步骤需要 user_id".to_string()));
            },
        };

        // 查询凭证
        let creds = self
            .credential_repo
            .find_by_user_and_type(&user_id, credential_type)
            .await?;
        if creds.is_empty() {
            return Ok(StepOutcome::Failed(format!(
                "未找到 {} 类型的凭证",
                credential_type
            )));
        }

        // 构造 Credential 并校验
        let cred = builder.build(creds[0].clone())?;
        #[cfg(feature = "metrics-prometheus")]
        let verify_start = std::time::Instant::now();
        let verified = cred.verify(&ctx.input).await?;
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = metrics {
            m.observe_credential_verify(credential_type, verify_start.elapsed());
        }

        if verified {
            // 创建会话
            let session_token = self.logic.login(&user_id).await?;
            // 记录登录成功（重置失败计数）
            if let Some(lockout) = &self.lockout {
                let _ = lockout.record_success(&user_id).await;
            }
            Ok(StepOutcome::Success {
                token: Some(session_token),
            })
        } else {
            // 记录登录失败（增加失败计数）
            if let Some(lockout) = &self.lockout {
                let _ = lockout.record_failure(&user_id).await;
            }
            Ok(StepOutcome::Failed("凭证校验失败".to_string()))
        }
    }

    /// 执行 Mfa 步骤（内部方法）。
    async fn execute_mfa(
        &self,
        credential_type: Option<&String>,
        ctx: &mut AuthContext,
        builder: Option<&dyn CredentialBuilder>,
        metrics: Option<&crate::account::metrics::AccountMetrics>,
    ) -> BulwarkResult<StepOutcome> {
        // 未启用 metrics-prometheus 时显式忽略 metrics 参数（避免 unused_variables warning）
        #[cfg(not(feature = "metrics-prometheus"))]
        let _ = metrics;

        match credential_type {
            None => {
                // Mfa(None): 调用 check_safe（默认返回 Ok）
                self.logic.check_safe().await?;
                Ok(StepOutcome::Success { token: None })
            },
            Some(cred_type) => {
                // Mfa(Some): 需要 TOTP 等凭证校验
                // 输入为空时返回 ChallengeRequired
                if ctx.input.is_empty() {
                    return Ok(StepOutcome::ChallengeRequired {
                        challenge_type: cred_type.clone(),
                        message: format!("请输入 {} 验证码", cred_type),
                    });
                }

                // 需要 CredentialBuilder
                let builder = match builder {
                    Some(b) => b,
                    None => {
                        return Ok(StepOutcome::Failed(
                            "Mfa(Some) 步骤需要 CredentialBuilder，请使用 execute_with_builder"
                                .to_string(),
                        ));
                    },
                };

                // 需要 user_id
                let user_id = match &ctx.user_id {
                    Some(id) => id.clone(),
                    None => {
                        return Ok(StepOutcome::Failed("Mfa 步骤需要 user_id".to_string()));
                    },
                };

                // 查询凭证
                let creds = self
                    .credential_repo
                    .find_by_user_and_type(&user_id, cred_type)
                    .await?;
                if creds.is_empty() {
                    return Ok(StepOutcome::Failed(format!(
                        "未找到 {} 类型的凭证",
                        cred_type
                    )));
                }

                // 构造 Credential 并校验
                let cred = builder.build(creds[0].clone())?;
                #[cfg(feature = "metrics-prometheus")]
                let verify_start = std::time::Instant::now();
                let verified = cred.verify(&ctx.input).await?;
                #[cfg(feature = "metrics-prometheus")]
                if let Some(m) = metrics {
                    m.observe_credential_verify(cred_type, verify_start.elapsed());
                }

                if verified {
                    Ok(StepOutcome::Success { token: None })
                } else {
                    Ok(StepOutcome::Failed(format!("{} 校验失败", cred_type)))
                }
            },
        }
    }

    /// 执行 SubFlow 步骤（内部方法）。
    ///
    /// v0.6.0 简化：SubFlow 返回的 Pending 视为 Failed（不支持嵌套 Pending 传播）。
    async fn execute_subflow(
        &self,
        flow_name: &str,
        ctx: &mut AuthContext,
        builder: Option<&dyn CredentialBuilder>,
        social_resolver: Option<&dyn SocialProviderResolver>,
        sso_resolver: Option<&dyn SsoServerResolver>,
        metrics: Option<&crate::account::metrics::AccountMetrics>,
        depth: usize,
    ) -> BulwarkResult<StepOutcome> {
        // 递归深度检查：防止循环引用导致栈溢出
        if depth >= MAX_FLOW_DEPTH {
            return Ok(StepOutcome::Failed(format!(
                "AuthenticationFlow 嵌套深度超过 {} 层上限，疑似循环引用",
                MAX_FLOW_DEPTH
            )));
        }

        let sub_flow = match self.registry.get(flow_name) {
            Some(f) => f,
            None => {
                return Ok(StepOutcome::Failed(format!("未找到子流程: {}", flow_name)));
            },
        };

        // 递归深度检查（v0.6.5 实现：depth >= MAX_FLOW_DEPTH 时返回 Failed）
        let result = self
            .execute_inner(
                sub_flow,
                ctx,
                builder,
                social_resolver,
                sso_resolver,
                metrics,
                depth + 1,
            )
            .await?;

        match result {
            AuthResult::Success { .. } => Ok(StepOutcome::Success { token: None }),
            AuthResult::Failed { reason, .. } => Ok(StepOutcome::Failed(format!(
                "子流程 {} 失败: {}",
                flow_name, reason
            ))),
            AuthResult::Pending { .. } => Ok(StepOutcome::Failed(format!(
                "子流程 {} 返回 Pending，v0.6.0 不支持嵌套 Pending 传播",
                flow_name
            ))),
            AuthResult::ChallengeRequired {
                challenge_type,
                message,
            } => Ok(StepOutcome::ChallengeRequired {
                challenge_type,
                message,
            }),
        }
    }

    /// 执行 SocialProvider 步骤（内部方法，T017 新增）。
    ///
    /// 流程（依据 spec auth-flow-dsl R-auth-flow-dsl-010）：
    /// 1. `social_resolver` 为 `None` → `Failed`（需通过 `execute_with_full` 调用）。
    /// 2. `ctx.input` 为空 → `ChallengeRequired`（提示用户完成社交授权）。
    /// 3. 从 `ctx.extras["state"]` 取 OAuth2 state（缺失则空串）。
    /// 4. 调用 `social_resolver.resolve_login_id(provider, ctx.input, state)` 取得 `login_id`。
    /// 5. 用 `login_id` 调用 `logic.login` 建立本地会话，返回 `token`。
    /// 6. 写回 `ctx.user_id = Some(login_id)`（供后续步骤使用）。
    async fn execute_social(
        &self,
        provider: &str,
        ctx: &mut AuthContext,
        social_resolver: Option<&dyn SocialProviderResolver>,
    ) -> BulwarkResult<StepOutcome> {
        let resolver = match social_resolver {
            Some(r) => r,
            None => {
                return Ok(StepOutcome::Failed(
                    "SocialProvider 步骤需要 SocialProviderResolver，请使用 execute_with_full"
                        .to_string(),
                ));
            },
        };

        // ctx.input 为空 → ChallengeRequired（提示用户完成社交授权拿 code）
        if ctx.input.is_empty() {
            return Ok(StepOutcome::ChallengeRequired {
                challenge_type: format!("social:{}", provider),
                message: format!("请完成 {} 社交登录授权", provider),
            });
        }

        // 从 ctx.extras 取 state（OAuth2 CSRF 防护参数）
        let state = ctx.extras.get("state").cloned().unwrap_or_default();

        // 调用 resolver 取得 login_id（内部委托 SocialLoginProvider::exchange_token）
        let login_id = match resolver
            .resolve_login_id(provider, &ctx.input, &state)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                return Ok(StepOutcome::Failed(format!(
                    "社交登录 {} 失败: {}",
                    provider, e
                )));
            },
        };

        // 用 login_id 建立本地会话
        let token = self.logic.login(&login_id).await?;

        // 写回 ctx.user_id（供后续步骤如 Mfa 使用）
        ctx.user_id = Some(login_id.clone());

        Ok(StepOutcome::Success { token: Some(token) })
    }

    /// 执行 SsoServer 步骤（内部方法，T017 新增）。
    ///
    /// 流程（依据 spec auth-flow-dsl R-auth-flow-dsl-011）：
    /// 1. `sso_resolver` 为 `None` → `Failed`（需通过 `execute_with_full` 调用）。
    /// 2. `ctx.input` 为空 → `ChallengeRequired`（提示用户提交 SSO ticket）。
    /// 3. 从 `ctx.extras["client_id"]` 取客户端标识（解析为 `i64`，缺失则 0）。
    /// 4. 调用 `sso_resolver.validate_and_get_login_id(server_id, ctx.input, client_id)`
    ///    取得 `login_id`（内部委托 `SsoServer::validate_ticket`，一次性消费 ticket）。
    /// 5. 用 `login_id` 调用 `logic.login` 建立本地会话，返回 `token`。
    /// 6. 写回 `ctx.user_id = Some(login_id)`。
    async fn execute_sso(
        &self,
        server_id: &str,
        ctx: &mut AuthContext,
        sso_resolver: Option<&dyn SsoServerResolver>,
    ) -> BulwarkResult<StepOutcome> {
        let resolver = match sso_resolver {
            Some(r) => r,
            None => {
                return Ok(StepOutcome::Failed(
                    "SsoServer 步骤需要 SsoServerResolver，请使用 execute_with_full".to_string(),
                ));
            },
        };

        // ctx.input 为空 → ChallengeRequired（提示用户提交 SSO ticket）
        if ctx.input.is_empty() {
            return Ok(StepOutcome::ChallengeRequired {
                challenge_type: format!("sso:{}", server_id),
                message: format!("请完成 SSO 登录: {}", server_id),
            });
        }

        // 从 ctx.extras 取 client_id（解析为 i64，缺失或解析失败则默认 0）
        let client_id: i64 = ctx
            .extras
            .get("client_id")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // 调用 resolver 验证 ticket 取得 login_id（内部委托 SsoServer::validate_ticket）
        let login_id = match resolver
            .validate_and_get_login_id(server_id, &ctx.input, client_id)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                return Ok(StepOutcome::Failed(format!("SSO 票据校验失败: {}", e)));
            },
        };

        // 用 login_id 建立本地会话
        let token = self.logic.login(&login_id).await?;

        // 写回 ctx.user_id（供后续步骤使用）
        ctx.user_id = Some(login_id.clone());

        Ok(StepOutcome::Success { token: Some(token) })
    }

    /// 评估条件分支（内部方法）。
    async fn evaluate_condition(
        &self,
        condition: &AuthCondition,
        ctx: &AuthContext,
    ) -> BulwarkResult<bool> {
        match condition {
            AuthCondition::HasCredential(cred_type) => {
                if let Some(user_id) = &ctx.user_id {
                    let creds = self
                        .credential_repo
                        .find_by_user_and_type(user_id, cred_type)
                        .await?;
                    Ok(!creds.is_empty())
                } else {
                    Ok(false)
                }
            },
            AuthCondition::IsLocked => {
                if let (Some(lockout), Some(user_id)) = (&self.lockout, &ctx.user_id) {
                    let fw_ctx = FirewallContext::new(&ctx.ip).with_login_id(user_id.clone());
                    Ok(lockout.check(&fw_ctx).await.is_err())
                } else {
                    Ok(false)
                }
            },
            AuthCondition::IpWhitelisted => {
                // v0.6.0: 无 IP 白名单配置，返回 false
                Ok(false)
            },
            AuthCondition::Custom(_) => {
                // v0.6.5: Custom 条件返回 false（未实现）
                Ok(false)
            },
        }
    }

    /// 生成下一步骤的挑战提示信息（内部方法）。
    fn step_challenge(&self, step: &AuthStep) -> String {
        match step {
            AuthStep::Login { credential_type } => format!("请输入 {}", credential_type),
            AuthStep::Mfa { credential_type } => match credential_type {
                Some(ct) => format!("请输入 {} 验证码", ct),
                None => "请完成 MFA 校验".to_string(),
            },
            AuthStep::SocialProvider { provider } => format!("请完成 {} 社交登录", provider),
            AuthStep::SsoServer { server_id } => format!("请完成 SSO 登录: {}", server_id),
            AuthStep::RequiredAction { action } => format!("请完成必需动作: {}", action),
            AuthStep::Conditional { .. } => "请完成条件分支".to_string(),
            AuthStep::SubFlow { flow_name } => format!("请完成子流程: {}", flow_name),
        }
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::authflow::builder::FlowBuilder;
    use crate::account::credential::CredentialType;
    use crate::config::BulwarkConfig;
    use crate::dao::tests::MockDao;
    use crate::dao::BulwarkDao;
    use crate::error::BulwarkError;
    use crate::session::BulwarkSession;
    use crate::stp::BulwarkInterface;
    use crate::strategy::BulwarkPermissionStrategyDefault;
    use std::collections::HashMap;

    // ------------------------------------------------------------------------
    // Mock 类型：MockCredential / MockCredentialBuilder / MockCredentialRepository
    // ------------------------------------------------------------------------

    /// Mock 凭证，`verify` 返回预设的布尔值。
    struct MockCredential {
        verify_result: bool,
    }

    #[async_trait]
    impl Credential for MockCredential {
        fn credential_type(&self) -> CredentialType {
            "mock"
        }

        fn to_model(&self) -> CredentialModel {
            CredentialModel {
                id: "mock".to_string(),
                user_id: "mock".to_string(),
                credential_type: "mock".to_string(),
                secret_data: String::new(),
                label: None,
                created_at: 0,
                enabled: true,
                priority: 0,
            }
        }

        async fn verify(&self, _input: &str) -> BulwarkResult<bool> {
            Ok(self.verify_result)
        }
    }

    /// Mock 凭证构造器，按 `credential_type` 返回不同 `verify_result` 的 MockCredential。
    struct MockCredentialBuilder {
        password_verify_result: bool,
        totp_verify_result: bool,
    }

    impl CredentialBuilder for MockCredentialBuilder {
        fn build(&self, model: CredentialModel) -> BulwarkResult<Box<dyn Credential>> {
            let verify_result = match model.credential_type.as_str() {
                "password" => self.password_verify_result,
                "totp" => self.totp_verify_result,
                _ => false,
            };
            Ok(Box::new(MockCredential { verify_result }))
        }
    }

    /// Mock 凭证存储（内存 HashMap）。
    #[derive(Default)]
    struct MockCredentialRepository {
        store: std::sync::Mutex<HashMap<String, CredentialModel>>,
    }

    #[async_trait]
    impl CredentialRepository for MockCredentialRepository {
        async fn create(&self, credential: CredentialModel) -> BulwarkResult<()> {
            let mut store = self.store.lock().unwrap();
            if store.contains_key(&credential.id) {
                return Err(BulwarkError::InvalidParam(format!(
                    "credential already exists: {}",
                    credential.id
                )));
            }
            store.insert(credential.id.clone(), credential);
            Ok(())
        }

        async fn find_by_user(&self, user_id: &str) -> BulwarkResult<Vec<CredentialModel>> {
            let store = self.store.lock().unwrap();
            let mut creds: Vec<CredentialModel> = store
                .values()
                .filter(|c| c.user_id == user_id)
                .cloned()
                .collect();
            creds.sort_by_key(|c| c.priority);
            Ok(creds)
        }

        async fn find_by_user_and_type(
            &self,
            user_id: &str,
            cred_type: &str,
        ) -> BulwarkResult<Vec<CredentialModel>> {
            let store = self.store.lock().unwrap();
            let mut creds: Vec<CredentialModel> = store
                .values()
                .filter(|c| c.user_id == user_id && c.credential_type == cred_type)
                .cloned()
                .collect();
            creds.sort_by_key(|c| c.priority);
            Ok(creds)
        }

        async fn update(&self, credential: CredentialModel) -> BulwarkResult<()> {
            let mut store = self.store.lock().unwrap();
            if !store.contains_key(&credential.id) {
                return Err(BulwarkError::InvalidParam(format!(
                    "credential not found: {}",
                    credential.id
                )));
            }
            store.insert(credential.id.clone(), credential);
            Ok(())
        }

        async fn delete(&self, credential_id: &str) -> BulwarkResult<()> {
            let mut store = self.store.lock().unwrap();
            if !store.contains_key(credential_id) {
                return Err(BulwarkError::InvalidParam(format!(
                    "credential not found: {}",
                    credential_id
                )));
            }
            store.remove(credential_id);
            Ok(())
        }
    }

    /// Mock BulwarkInterface（空权限/角色数据）。
    struct MockInterface;

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(Vec::new())
        }
    }

    // ------------------------------------------------------------------------
    // 辅助函数
    // ------------------------------------------------------------------------

    /// 构造测试用 `Arc<BulwarkLogicDefault>`。
    fn make_logic() -> Arc<BulwarkLogicDefault> {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(BulwarkConfig::default_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
        let timeout = u64::try_from(config.timeout).unwrap_or(3600);
        let session = Arc::new(BulwarkSession::new(dao, timeout, timeout));
        let firewall: Arc<dyn crate::strategy::BulwarkPermissionStrategy> =
            Arc::new(BulwarkPermissionStrategyDefault::new(interface));
        Arc::new(BulwarkLogicDefault::new(session, config, firewall))
    }

    /// 构造测试用 AuthExecutor。
    fn make_executor(
        credential_repo: Arc<dyn CredentialRepository>,
        lockout: Option<Arc<UserLockoutStrategy>>,
    ) -> AuthExecutor {
        AuthExecutor::new(
            make_logic(),
            credential_repo,
            None,
            lockout,
            Arc::new(FlowRegistry::from_inventory()),
        )
    }

    /// 构造测试用 AuthExecutor（带自定义 registry）。
    fn make_executor_with_registry(
        credential_repo: Arc<dyn CredentialRepository>,
        registry: Arc<FlowRegistry>,
    ) -> AuthExecutor {
        AuthExecutor::new(make_logic(), credential_repo, None, None, registry)
    }

    /// 构造测试用 AuthContext。
    fn make_context(user_id: &str, input: &str) -> AuthContext {
        AuthContext {
            input: input.to_string(),
            user_id: Some(user_id.to_string()),
            tenant_id: None,
            ip: "127.0.0.1".to_string(),
            completed_steps: Vec::new(),
            extras: HashMap::new(),
        }
    }

    /// 构造测试用 CredentialModel。
    fn make_credential_model(id: &str, user: &str, cred_type: &str) -> CredentialModel {
        CredentialModel {
            id: id.to_string(),
            user_id: user.to_string(),
            credential_type: cred_type.to_string(),
            secret_data: "hash".to_string(),
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        }
    }

    /// 创建预填充密码凭证的 MockCredentialRepository。
    async fn make_repo_with_password(user: &str) -> Arc<MockCredentialRepository> {
        let repo = MockCredentialRepository::default();
        repo.create(make_credential_model("c1", user, "password"))
            .await
            .unwrap();
        Arc::new(repo)
    }

    /// 创建预填充密码 + totp 凭证的 MockCredentialRepository。
    async fn make_repo_with_password_and_totp(user: &str) -> Arc<MockCredentialRepository> {
        let repo = MockCredentialRepository::default();
        repo.create(make_credential_model("c1", user, "password"))
            .await
            .unwrap();
        repo.create(make_credential_model("c2", user, "totp"))
            .await
            .unwrap();
        Arc::new(repo)
    }

    // ------------------------------------------------------------------------
    // 测试 1: password_login_success
    // ------------------------------------------------------------------------

    /// R-009: Login 步骤 — 密码校验成功 → AuthResult::Success。
    #[tokio::test]
    async fn password_login_success() {
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("test").login("password").build();
        let mut ctx = make_context("alice", "correct-password");

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Success { login_id, token } => {
                assert_eq!(login_id, "alice");
                assert!(!token.is_empty(), "token 不应为空");
            },
            other => panic!("应为 Success，实际: {:?}", other),
        }
    }

    // ------------------------------------------------------------------------
    // 测试 2: password_login_failure
    // ------------------------------------------------------------------------

    /// R-009: Login 步骤 — 密码校验失败 → AuthResult::Failed。
    #[tokio::test]
    async fn password_login_failure() {
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: false,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("test").login("password").build();
        let mut ctx = make_context("alice", "wrong-password");

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(
                    reason.contains("凭证校验失败"),
                    "reason 应含凭证校验失败: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed，实际: {:?}", other),
        }
    }

    // ------------------------------------------------------------------------
    // 测试 3: mfa_check_safe_success
    // ------------------------------------------------------------------------

    /// R-009: Mfa(None) 步骤 — check_safe 默认返回 Ok → Success。
    #[tokio::test]
    async fn mfa_check_safe_success() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let flow = FlowBuilder::new("test").mfa(None).build();
        let mut ctx = make_context("alice", "");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Success { login_id, .. } => {
                assert_eq!(login_id, "alice");
            },
            other => panic!("应为 Success，实际: {:?}", other),
        }
    }

    // ------------------------------------------------------------------------
    // 测试 4: mfa_totp_success
    // ------------------------------------------------------------------------

    /// R-009: Mfa(Some("totp")) 步骤 — TOTP 校验成功 → Success。
    #[tokio::test]
    async fn mfa_totp_success() {
        let repo = make_repo_with_password_and_totp("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: false,
            totp_verify_result: true,
        };
        let flow = FlowBuilder::new("test").mfa(Some("totp")).build();
        let mut ctx = make_context("alice", "123456");

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Success { .. } => {},
            other => panic!("应为 Success，实际: {:?}", other),
        }
    }

    // ------------------------------------------------------------------------
    // 测试 5: mfa_totp_failure
    // ------------------------------------------------------------------------

    /// R-009: Mfa(Some("totp")) 步骤 — TOTP 校验失败 → Failed。
    #[tokio::test]
    async fn mfa_totp_failure() {
        let repo = make_repo_with_password_and_totp("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: false,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("test").mfa(Some("totp")).build();
        let mut ctx = make_context("alice", "wrong-code");

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(reason.contains("totp"), "reason 应含 totp: {}", reason);
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed，实际: {:?}", other),
        }
    }

    // ------------------------------------------------------------------------
    // 测试 6: conditional_true
    // ------------------------------------------------------------------------

    /// R-009: Conditional 步骤 — 条件为真执行 if_step（Login verify=false → Failed）。
    #[tokio::test]
    async fn conditional_true() {
        let repo = make_repo_with_password_and_totp("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: false,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("test")
            .conditional(
                AuthCondition::HasCredential("totp".to_string()),
                AuthStep::Login {
                    credential_type: "password".to_string(),
                },
                None,
            )
            .build();
        let mut ctx = make_context("alice", "wrong-password");

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, .. } => {
                assert!(
                    reason.contains("凭证校验失败"),
                    "reason 应含凭证校验失败: {}",
                    reason
                );
            },
            other => panic!(
                "应为 Failed（条件为真执行 Login verify=false），实际: {:?}",
                other
            ),
        }
    }

    // ------------------------------------------------------------------------
    // 测试 7: conditional_false
    // ------------------------------------------------------------------------

    /// R-009: Conditional 步骤 — 条件为假且 else_step=None → 跳过 → Success。
    #[tokio::test]
    async fn conditional_false() {
        // 用户只有 password 凭证，没有 totp 凭证 → HasCredential("totp") = false
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let flow = FlowBuilder::new("test")
            .conditional(
                AuthCondition::HasCredential("totp".to_string()),
                AuthStep::Login {
                    credential_type: "password".to_string(),
                },
                None,
            )
            .build();
        let mut ctx = make_context("alice", "");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Success { login_id, .. } => {
                assert_eq!(login_id, "alice");
            },
            other => panic!("应为 Success（条件为假跳过），实际: {:?}", other),
        }
    }

    // ------------------------------------------------------------------------
    // 测试 8: subflow_executes_child
    // ------------------------------------------------------------------------

    /// R-009: SubFlow 步骤 — 子流程 Login 成功 → 父流程 Success。
    #[tokio::test]
    async fn subflow_executes_child() {
        let repo = make_repo_with_password("alice").await;
        let mut registry = FlowRegistry::from_inventory();
        let child = FlowBuilder::new("child-flow").login("password").build();
        registry.register(child);
        let executor = make_executor_with_registry(repo, Arc::new(registry));
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("parent").sub_flow("child-flow").build();
        let mut ctx = make_context("alice", "correct-password");

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Success { login_id, .. } => {
                assert_eq!(login_id, "alice");
            },
            other => panic!("应为 Success（子流程成功），实际: {:?}", other),
        }
    }

    // ------------------------------------------------------------------------
    // 测试 9: empty_steps_returns_success
    // ------------------------------------------------------------------------

    /// R-009: 空步骤流程 → 直接返回 Success。
    #[tokio::test]
    async fn empty_steps_returns_success() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let flow = FlowBuilder::new("empty").build();
        let mut ctx = make_context("alice", "");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Success { login_id, .. } => {
                assert_eq!(login_id, "alice");
            },
            other => panic!("空步骤应返回 Success，实际: {:?}", other),
        }
    }

    // ------------------------------------------------------------------------
    // 测试 10: multi_step_flow_success
    // ------------------------------------------------------------------------

    /// R-009: 多步流程（Login + Mfa(None)）— 两步均通过 → Success。
    #[tokio::test]
    async fn multi_step_flow_success() {
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("multi")
            .login("password")
            .mfa(None)
            .build();
        let mut ctx = make_context("alice", "correct-password");

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Success { login_id, token } => {
                assert_eq!(login_id, "alice");
                assert!(!token.is_empty(), "Login 步骤应生成 token");
                assert_eq!(ctx.completed_steps.len(), 2, "应完成 2 个步骤");
            },
            other => panic!("应为 Success，实际: {:?}", other),
        }
    }

    // ------------------------------------------------------------------------
    // 测试 11: pending_intermediate_state
    // ------------------------------------------------------------------------

    /// R-009: pause_after_step 标记 — Login 成功后暂停 → Pending。
    #[tokio::test]
    async fn pending_intermediate_state() {
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("multi")
            .login("password")
            .mfa(None)
            .build();
        let mut ctx = make_context("alice", "correct-password");
        ctx.extras
            .insert("pause_after_step".to_string(), "0".to_string());

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Pending {
                completed_step,
                next_step,
                challenge,
            } => {
                assert_eq!(completed_step, 0);
                assert_eq!(next_step, 1);
                assert!(!challenge.is_empty(), "challenge 不应为空");
            },
            other => panic!("应为 Pending，实际: {:?}", other),
        }
    }

    // ------------------------------------------------------------------------
    // 测试 12: challenge_required_for_mfa
    // ------------------------------------------------------------------------

    /// R-009: Mfa(Some("totp")) 输入为空 → ChallengeRequired。
    #[tokio::test]
    async fn challenge_required_for_mfa() {
        let repo = make_repo_with_password_and_totp("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: false,
            totp_verify_result: true,
        };
        let flow = FlowBuilder::new("test").mfa(Some("totp")).build();
        let mut ctx = make_context("alice", ""); // 空输入

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::ChallengeRequired {
                challenge_type,
                message,
            } => {
                assert_eq!(challenge_type, "totp");
                assert!(message.contains("totp"), "message 应含 totp: {}", message);
            },
            other => panic!("应为 ChallengeRequired，实际: {:?}", other),
        }
    }

    // ------------------------------------------------------------------------
    // 测试 13: lockout_blocks_login
    // ------------------------------------------------------------------------

    /// R-009: Login 步骤前检查锁定 — 用户被锁定 → Failed。
    #[tokio::test]
    async fn lockout_blocks_login() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let lockout = Arc::new(UserLockoutStrategy::new(
            crate::account::lockout::UserLockoutConfig {
                max_failure_factor: 2,
                permanent_lockout: false,
                max_temporary_lockouts: 99,
                wait_strategy: crate::account::lockout::WaitStrategy::Linear { base_seconds: 300 },
                failure_window_seconds: 300,
            },
            dao,
        ));

        // 记录 2 次失败触发临时锁定
        lockout.record_failure("alice").await.unwrap();
        lockout.record_failure("alice").await.unwrap();

        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, Some(lockout));
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("test").login("password").build();
        let mut ctx = make_context("alice", "correct-password");

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(reason.contains("锁定"), "reason 应含锁定: {}", reason);
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed（用户被锁定），实际: {:?}", other),
        }
    }

    // ========================================================================
    // T017: SocialProvider + SsoServer 步骤测试
    // ========================================================================
    //
    // T017 子模块仅在 `social-wechat` + `protocol-sso-server` 同时启用时编译
    //（与测试命令 `cargo test --features "account-authflow social-wechat
    // protocol-sso-server cache-memory"` 对应）。mock resolver 内部持有 mock
    // SocialLoginProvider / SsoServer，证明 executor 通过 resolver 委托调用了
    // exchange_token / validate_ticket。

    #[cfg(all(feature = "social-wechat", feature = "protocol-sso-server"))]
    mod t017 {
        use super::*;
        use crate::error::BulwarkError;
        use crate::protocol::social::{
            SocialLoginProvider, SocialProvider as SocialProviderEnum, SocialUserInfo,
        };
        use crate::protocol::sso::server::SsoServer;
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // --------------------------------------------------------------------
        // Mock 类型
        // --------------------------------------------------------------------

        /// Mock `SocialLoginProvider`，记录 `exchange_token` 调用次数。
        struct MockSocialLoginProvider {
            provider_user_id: String,
            exchange_count: AtomicUsize,
            fail_exchange: bool,
        }

        impl MockSocialLoginProvider {
            fn new(provider_user_id: &str) -> Self {
                Self {
                    provider_user_id: provider_user_id.to_string(),
                    exchange_count: AtomicUsize::new(0),
                    fail_exchange: false,
                }
            }

            fn exchange_count(&self) -> usize {
                self.exchange_count.load(Ordering::SeqCst)
            }
        }

        #[async_trait]
        impl SocialLoginProvider for MockSocialLoginProvider {
            async fn get_authorization_url(
                &self,
                _state: &str,
                _redirect_uri: &str,
            ) -> BulwarkResult<String> {
                Ok("https://example.com/auth".to_string())
            }

            async fn exchange_token(
                &self,
                _code: &str,
                _state: &str,
            ) -> BulwarkResult<SocialUserInfo> {
                self.exchange_count.fetch_add(1, Ordering::SeqCst);
                if self.fail_exchange {
                    return Err(BulwarkError::Internal(
                        "mock exchange_token 失败".to_string(),
                    ));
                }
                Ok(SocialUserInfo {
                    provider: SocialProviderEnum::Wechat,
                    provider_user_id: self.provider_user_id.clone(),
                    nickname: None,
                    avatar: None,
                    union_id: None,
                    raw: serde_json::json!({}),
                })
            }

            async fn get_user_info(&self, _access_token: &str) -> BulwarkResult<SocialUserInfo> {
                Ok(SocialUserInfo {
                    provider: SocialProviderEnum::Wechat,
                    provider_user_id: self.provider_user_id.clone(),
                    nickname: None,
                    avatar: None,
                    union_id: None,
                    raw: serde_json::json!({}),
                })
            }
        }

        /// Mock `SocialProviderResolver`，内部维护 provider 名 → mock provider。
        struct MockSocialProviderResolver {
            providers: HashMap<String, Arc<dyn SocialLoginProvider>>,
        }

        impl MockSocialProviderResolver {
            fn new() -> Self {
                Self {
                    providers: HashMap::new(),
                }
            }

            fn register(&mut self, name: &str, provider: Arc<dyn SocialLoginProvider>) {
                self.providers.insert(name.to_string(), provider);
            }
        }

        #[async_trait]
        impl SocialProviderResolver for MockSocialProviderResolver {
            async fn resolve_login_id(
                &self,
                provider: &str,
                code: &str,
                state: &str,
            ) -> BulwarkResult<String> {
                let p = self.providers.get(provider).ok_or_else(|| {
                    BulwarkError::InvalidParam(format!("unknown social provider: {}", provider))
                })?;
                let user_info = p.exchange_token(code, state).await?;
                Ok(user_info.provider_user_id)
            }
        }

        /// Mock `SsoServer`，记录 `validate_ticket` 调用次数。
        struct MockSsoServer {
            login_id: String,
            validate_count: AtomicUsize,
            fail_validate: bool,
        }

        impl MockSsoServer {
            fn new(login_id: &str) -> Self {
                Self {
                    login_id: login_id.to_string(),
                    validate_count: AtomicUsize::new(0),
                    fail_validate: false,
                }
            }

            fn new_failing() -> Self {
                Self {
                    login_id: String::new(),
                    validate_count: AtomicUsize::new(0),
                    fail_validate: true,
                }
            }

            fn validate_count(&self) -> usize {
                self.validate_count.load(Ordering::SeqCst)
            }
        }

        #[async_trait]
        impl SsoServer for MockSsoServer {
            async fn issue_ticket(
                &self,
                _login_id: &str,
                _client_id: i64,
            ) -> BulwarkResult<String> {
                Ok("mock-ticket".to_string())
            }

            async fn validate_ticket(
                &self,
                _ticket: &str,
                _client_id: i64,
            ) -> BulwarkResult<String> {
                self.validate_count.fetch_add(1, Ordering::SeqCst);
                if self.fail_validate {
                    return Err(BulwarkError::InvalidToken(
                        "mock validate_ticket 失败".to_string(),
                    ));
                }
                Ok(self.login_id.clone())
            }

            async fn destroy_ticket(&self, _ticket: &str) -> BulwarkResult<()> {
                Ok(())
            }

            async fn push_message(&self, _login_id: &str, _message: &str) -> BulwarkResult<()> {
                Ok(())
            }
        }

        /// Mock `SsoServerResolver`，内部维护 server_id → mock server。
        struct MockSsoServerResolver {
            servers: HashMap<String, Arc<dyn SsoServer>>,
        }

        impl MockSsoServerResolver {
            fn new() -> Self {
                Self {
                    servers: HashMap::new(),
                }
            }

            fn register(&mut self, id: &str, server: Arc<dyn SsoServer>) {
                self.servers.insert(id.to_string(), server);
            }
        }

        #[async_trait]
        impl SsoServerResolver for MockSsoServerResolver {
            async fn validate_and_get_login_id(
                &self,
                server_id: &str,
                ticket: &str,
                client_id: i64,
            ) -> BulwarkResult<String> {
                let s = self.servers.get(server_id).ok_or_else(|| {
                    BulwarkError::InvalidParam(format!("unknown sso server: {}", server_id))
                })?;
                s.validate_ticket(ticket, client_id).await
            }
        }

        // --------------------------------------------------------------------
        // 辅助函数
        // --------------------------------------------------------------------

        /// 构造空凭证 repo 的 executor（T017 不依赖凭证，但 make_executor 需要 repo）。
        fn make_t017_executor() -> AuthExecutor {
            let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
            make_executor(repo, None)
        }

        /// 占位 CredentialBuilder（T017 流程不含 Login，但 execute_with_full 需要传 builder）。
        fn dummy_builder() -> MockCredentialBuilder {
            MockCredentialBuilder {
                password_verify_result: false,
                totp_verify_result: false,
            }
        }

        // --------------------------------------------------------------------
        // 测试 14: t017_social_login_success
        // --------------------------------------------------------------------

        /// R-010: SocialProvider 步骤 — exchange_token 成功 → Success。
        /// 验证 executor 通过 resolver 委托调用了 SocialLoginProvider::exchange_token。
        #[tokio::test]
        async fn t017_social_login_success() {
            let wechat = Arc::new(MockSocialLoginProvider::new("wx_user_123"));
            let wechat_ref = wechat.clone() as Arc<dyn SocialLoginProvider>;
            let mut social_resolver = MockSocialProviderResolver::new();
            social_resolver.register("wechat", wechat_ref);
            let executor = make_t017_executor();
            let builder = dummy_builder();
            let sso_resolver = MockSsoServerResolver::new();
            let flow = FlowBuilder::new("wechat-flow").social("wechat").build();
            let mut ctx = make_context("", "auth_code_456");
            ctx.extras
                .insert("state".to_string(), "state_789".to_string());

            let result = executor
                .execute_with_full(&flow, &mut ctx, &builder, &social_resolver, &sso_resolver)
                .await
                .unwrap();

            match result {
                AuthResult::Success { login_id, token } => {
                    assert_eq!(login_id, "wx_user_123");
                    assert!(!token.is_empty(), "token 不应为空");
                    assert_eq!(ctx.user_id.as_deref(), Some("wx_user_123"));
                },
                other => panic!("应为 Success，实际: {:?}", other),
            }
            // 验证 resolver 内部确实调用了 exchange_token
            assert_eq!(wechat.exchange_count(), 1, "exchange_token 应被调用 1 次");
        }

        // --------------------------------------------------------------------
        // 测试 15: t017_social_login_unknown_provider_returns_failed
        // --------------------------------------------------------------------

        /// R-010: SocialProvider 步骤 — provider 未注册 → Failed。
        #[tokio::test]
        async fn t017_social_login_unknown_provider_returns_failed() {
            let social_resolver = MockSocialProviderResolver::new(); // 空 resolver
            let executor = make_t017_executor();
            let builder = dummy_builder();
            let sso_resolver = MockSsoServerResolver::new();
            let flow = FlowBuilder::new("github-flow").social("github").build();
            let mut ctx = make_context("", "auth_code");
            ctx.extras.insert("state".to_string(), "state".to_string());

            let result = executor
                .execute_with_full(&flow, &mut ctx, &builder, &social_resolver, &sso_resolver)
                .await
                .unwrap();

            match result {
                AuthResult::Failed { reason, step } => {
                    assert!(
                        reason.contains("unknown social provider"),
                        "reason 应含 unknown social provider: {}",
                        reason
                    );
                    assert_eq!(step, 0);
                },
                other => panic!("应为 Failed，实际: {:?}", other),
            }
        }

        // --------------------------------------------------------------------
        // 测试 16: t017_social_login_empty_input_challenge_required
        // --------------------------------------------------------------------

        /// R-010: SocialProvider 步骤 — ctx.input 为空 → ChallengeRequired。
        #[tokio::test]
        async fn t017_social_login_empty_input_challenge_required() {
            let social_resolver = MockSocialProviderResolver::new();
            let executor = make_t017_executor();
            let builder = dummy_builder();
            let sso_resolver = MockSsoServerResolver::new();
            let flow = FlowBuilder::new("wechat-flow").social("wechat").build();
            let mut ctx = make_context("", ""); // 空输入

            let result = executor
                .execute_with_full(&flow, &mut ctx, &builder, &social_resolver, &sso_resolver)
                .await
                .unwrap();

            match result {
                AuthResult::ChallengeRequired {
                    challenge_type,
                    message,
                } => {
                    assert_eq!(challenge_type, "social:wechat");
                    assert!(
                        message.contains("wechat"),
                        "message 应含 wechat: {}",
                        message
                    );
                },
                other => panic!("应为 ChallengeRequired，实际: {:?}", other),
            }
        }

        // --------------------------------------------------------------------
        // 测试 17: t017_social_login_multiple_providers_switch
        // --------------------------------------------------------------------

        /// R-010: 多 Provider 切换 — wechat 与 alipay 分别返回不同 login_id。
        #[tokio::test]
        async fn t017_social_login_multiple_providers_switch() {
            let wechat = Arc::new(MockSocialLoginProvider::new("wx_openid"));
            let alipay = Arc::new(MockSocialLoginProvider::new("alipay_uid"));
            let wechat_ref = wechat.clone() as Arc<dyn SocialLoginProvider>;
            let alipay_ref = alipay.clone() as Arc<dyn SocialLoginProvider>;
            let mut social_resolver = MockSocialProviderResolver::new();
            social_resolver.register("wechat", wechat_ref);
            social_resolver.register("alipay", alipay_ref);
            let executor = make_t017_executor();
            let builder = dummy_builder();
            let sso_resolver = MockSsoServerResolver::new();

            // 测试 wechat → login_id = "wx_openid"
            let flow_w = FlowBuilder::new("w").social("wechat").build();
            let mut ctx_w = make_context("", "code_w");
            ctx_w.extras.insert("state".to_string(), "s".to_string());
            let result_w = executor
                .execute_with_full(
                    &flow_w,
                    &mut ctx_w,
                    &builder,
                    &social_resolver,
                    &sso_resolver,
                )
                .await
                .unwrap();
            match result_w {
                AuthResult::Success { login_id, .. } => assert_eq!(login_id, "wx_openid"),
                other => panic!("wechat 应返回 Success，实际: {:?}", other),
            }

            // 测试 alipay → login_id = "alipay_uid"
            let flow_a = FlowBuilder::new("a").social("alipay").build();
            let mut ctx_a = make_context("", "code_a");
            ctx_a.extras.insert("state".to_string(), "s".to_string());
            let result_a = executor
                .execute_with_full(
                    &flow_a,
                    &mut ctx_a,
                    &builder,
                    &social_resolver,
                    &sso_resolver,
                )
                .await
                .unwrap();
            match result_a {
                AuthResult::Success { login_id, .. } => assert_eq!(login_id, "alipay_uid"),
                other => panic!("alipay 应返回 Success，实际: {:?}", other),
            }

            // 验证两个 provider 各被调用 1 次（互不干扰）
            assert_eq!(wechat.exchange_count(), 1);
            assert_eq!(alipay.exchange_count(), 1);
        }

        // --------------------------------------------------------------------
        // 测试 18: t017_sso_login_success
        // --------------------------------------------------------------------

        /// R-011: SsoServer 步骤 — validate_ticket 成功 → Success。
        /// 验证 executor 通过 resolver 委托调用了 SsoServer::validate_ticket。
        #[tokio::test]
        async fn t017_sso_login_success() {
            let server = Arc::new(MockSsoServer::new("1001"));
            let server_ref = server.clone() as Arc<dyn SsoServer>;
            let mut sso_resolver = MockSsoServerResolver::new();
            sso_resolver.register("keycloak", server_ref);
            let social_resolver = MockSocialProviderResolver::new();
            let executor = make_t017_executor();
            let builder = dummy_builder();
            let flow = FlowBuilder::new("sso-flow").sso("keycloak").build();
            let mut ctx = make_context("", "ticket_abc");
            ctx.extras
                .insert("client_id".to_string(), "2001".to_string());

            let result = executor
                .execute_with_full(&flow, &mut ctx, &builder, &social_resolver, &sso_resolver)
                .await
                .unwrap();

            match result {
                AuthResult::Success { login_id, token } => {
                    assert_eq!(login_id, "1001");
                    assert!(!token.is_empty(), "token 不应为空");
                    assert_eq!(ctx.user_id.as_deref(), Some("1001"));
                },
                other => panic!("应为 Success，实际: {:?}", other),
            }
            assert_eq!(server.validate_count(), 1, "validate_ticket 应被调用 1 次");
        }

        // --------------------------------------------------------------------
        // 测试 19: t017_sso_login_invalid_ticket_returns_failed
        // --------------------------------------------------------------------

        /// R-011: SsoServer 步骤 — validate_ticket 失败 → Failed。
        #[tokio::test]
        async fn t017_sso_login_invalid_ticket_returns_failed() {
            let server = Arc::new(MockSsoServer::new_failing());
            let server_ref = server.clone() as Arc<dyn SsoServer>;
            let mut sso_resolver = MockSsoServerResolver::new();
            sso_resolver.register("keycloak", server_ref);
            let social_resolver = MockSocialProviderResolver::new();
            let executor = make_t017_executor();
            let builder = dummy_builder();
            let flow = FlowBuilder::new("sso-flow").sso("keycloak").build();
            let mut ctx = make_context("", "invalid-ticket");
            ctx.extras
                .insert("client_id".to_string(), "2001".to_string());

            let result = executor
                .execute_with_full(&flow, &mut ctx, &builder, &social_resolver, &sso_resolver)
                .await
                .unwrap();

            match result {
                AuthResult::Failed { reason, step } => {
                    assert!(
                        reason.contains("SSO 票据校验失败"),
                        "reason 应含 SSO 票据校验失败: {}",
                        reason
                    );
                    assert_eq!(step, 0);
                },
                other => panic!("应为 Failed，实际: {:?}", other),
            }
            assert_eq!(
                server.validate_count(),
                1,
                "validate_ticket 应被调用 1 次（即使失败）"
            );
        }

        // --------------------------------------------------------------------
        // 测试 20: t017_sso_login_empty_input_challenge_required
        // --------------------------------------------------------------------

        /// R-011: SsoServer 步骤 — ctx.input 为空 → ChallengeRequired。
        #[tokio::test]
        async fn t017_sso_login_empty_input_challenge_required() {
            let sso_resolver = MockSsoServerResolver::new();
            let social_resolver = MockSocialProviderResolver::new();
            let executor = make_t017_executor();
            let builder = dummy_builder();
            let flow = FlowBuilder::new("sso-flow").sso("keycloak").build();
            let mut ctx = make_context("", ""); // 空输入

            let result = executor
                .execute_with_full(&flow, &mut ctx, &builder, &social_resolver, &sso_resolver)
                .await
                .unwrap();

            match result {
                AuthResult::ChallengeRequired {
                    challenge_type,
                    message,
                } => {
                    assert_eq!(challenge_type, "sso:keycloak");
                    assert!(
                        message.contains("SSO 登录"),
                        "message 应含 SSO 登录: {}",
                        message
                    );
                },
                other => panic!("应为 ChallengeRequired，实际: {:?}", other),
            }
        }

        // --------------------------------------------------------------------
        // 测试 21: t017_social_sso_combined_flow_success
        // --------------------------------------------------------------------

        /// R-010 + R-011: SocialProvider + SsoServer 组合流程 — 两步均成功。
        /// 验证多步流程中 resolver 链可用，且最后一步的 login_id 覆盖前一步。
        #[tokio::test]
        async fn t017_social_sso_combined_flow_success() {
            let wechat = Arc::new(MockSocialLoginProvider::new("wx_user"));
            let wechat_ref = wechat.clone() as Arc<dyn SocialLoginProvider>;
            let server = Arc::new(MockSsoServer::new("sso_user"));
            let server_ref = server.clone() as Arc<dyn SsoServer>;
            let mut social_resolver = MockSocialProviderResolver::new();
            social_resolver.register("wechat", wechat_ref);
            let mut sso_resolver = MockSsoServerResolver::new();
            sso_resolver.register("keycloak", server_ref);
            let executor = make_t017_executor();
            let builder = dummy_builder();
            // 组合流程：先社交登录，再 SSO（实际场景二选一，此处验证多步串联）
            let flow = FlowBuilder::new("combined")
                .social("wechat")
                .sso("keycloak")
                .build();

            // 第一步：社交登录（ctx.input = auth code）
            let mut ctx = make_context("", "auth_code");
            ctx.extras.insert("state".to_string(), "s".to_string());
            ctx.extras
                .insert("client_id".to_string(), "2001".to_string());
            let result = executor
                .execute_with_full(&flow, &mut ctx, &builder, &social_resolver, &sso_resolver)
                .await
                .unwrap();

            // 第一步 social 成功 → token 由 logic.login 生成，第二步 sso 用新 ticket
            // 但 ctx.input 是单个值，第二步 sso 复用同一 input "auth_code" 作为 ticket。
            // mock sso server 不校验 ticket 内容，直接返回 login_id "sso_user"。
            match result {
                AuthResult::Success { login_id, token } => {
                    // 最后一步 SsoServer 的 login_id 覆盖 SocialProvider 的
                    assert_eq!(login_id, "sso_user");
                    assert!(!token.is_empty(), "token 不应为空");
                    assert_eq!(ctx.user_id.as_deref(), Some("sso_user"));
                    assert_eq!(ctx.completed_steps.len(), 2, "应完成 2 个步骤");
                },
                other => panic!("应为 Success，实际: {:?}", other),
            }
            assert_eq!(wechat.exchange_count(), 1);
            assert_eq!(server.validate_count(), 1);
        }

        // --------------------------------------------------------------------
        // 测试 22: t017_social_step_without_resolver_returns_failed
        // --------------------------------------------------------------------

        /// R-010: SocialProvider 步骤 — execute_with_builder 无 resolver → Failed。
        /// 覆盖 execute_with_builder 路径，验证占位失败信息。
        #[tokio::test]
        async fn t017_social_step_without_resolver_returns_failed() {
            let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
            let executor = make_executor(repo, None);
            let builder = dummy_builder();
            let flow = FlowBuilder::new("wechat-flow").social("wechat").build();
            let mut ctx = make_context("", "auth_code");
            ctx.extras.insert("state".to_string(), "s".to_string());

            let result = executor
                .execute_with_builder(&flow, &mut ctx, &builder)
                .await
                .unwrap();

            match result {
                AuthResult::Failed { reason, step } => {
                    assert!(
                        reason.contains("SocialProviderResolver"),
                        "reason 应含 SocialProviderResolver: {}",
                        reason
                    );
                    assert_eq!(step, 0);
                },
                other => panic!("应为 Failed（无 resolver），实际: {:?}", other),
            }
        }
    }
}
