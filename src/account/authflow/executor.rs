// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0
//! AuthExecutor 核心：按 [`AuthenticationFlow`] 步骤顺序执行认证逻辑。
//!
//! 5 字段约束下（logic / credential_repo / policy_engine / lockout / registry），[`CredentialBuilder`] /
//! [`SocialProviderResolver`] / [`SsoServerResolver`] 以 trait 参数注入，不作 struct 字段；resolver 使本模块
//! 不直接依赖 `protocol`，避免 feature gate 链穿透 `account-authflow`
//! （SocialProvider 仅 `social-wechat`/`social-alipay`、SsoServer 仅 `protocol-sso-server` 启用时编译）。

use super::registry::FlowRegistry;
use super::{
    AuthCondition, AuthContext, AuthResult, AuthStep, AuthenticationFlow, CustomConditionEvaluator,
    IpWhitelist,
};
use crate::account::credential::{Credential, CredentialModel, CredentialRepository};
use crate::account::lockout::UserLockoutStrategy;
use crate::account::policy::PasswordPolicyEngine;
use crate::error::{GarrisonError, GarrisonResult};
use crate::loc;
use crate::stp::{GarrisonLogicDefault, LoginParams, MfaLogic, SessionLogic};
use crate::strategy::firewall::{FirewallContext, GarrisonFirewallStrategy};
use async_trait::async_trait;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// AuthenticationFlow 嵌套递归最大深度（防止循环引用导致栈溢出）。
const MAX_FLOW_DEPTH: usize = 10;

/// 凭证构造 trait：将 DAO 查询到的 [`CredentialModel`] 转为可校验的 [`Credential`]（如
/// `PasswordCredential` / `TotpCredential`）。受 5 字段约束不作 [`AuthExecutor`] 字段，经
/// [`AuthExecutor::execute_with_builder`] 注入；[`AuthExecutor::execute`] 无 builder 时 Login 步骤返回 `Failed`。
///
/// # 示例
///
/// ```ignore
/// use garrison::account::authflow::executor::CredentialBuilder;
/// use garrison::account::credential::{CredentialModel, Credential, password::Argon2Hasher};
/// use garrison::account::credential::password::PasswordCredential;
/// use garrison::error::GarrisonResult;
///
/// struct PasswordCredentialBuilder;
/// impl CredentialBuilder for PasswordCredentialBuilder {
/// fn build(&self, model: CredentialModel) -> GarrisonResult<Box<dyn Credential>> {
/// let hasher = std::sync::Arc::new(Argon2Hasher::new());
/// Ok(Box::new(PasswordCredential::new(model, hasher)))
/// }
/// }
/// ```
pub trait CredentialBuilder: Send + Sync {
    /// 将 [`CredentialModel`] 构造为 `Box<dyn Credential>`；凭证类型不支持等构造失败返回 `Err`。
    fn build(&self, model: CredentialModel) -> GarrisonResult<Box<dyn Credential>>;
}

/// 社交登录解析 trait：用授权码换取 login_id（实现方委托 `SocialLoginProvider::exchange_token(code, state)`，
/// 取 `provider_user_id`）。经 [`AuthExecutor::execute_with_full`] 参数注入（非 struct 字段，保持 5 字段）；
/// `code` 取 `ctx.input`、`state` 取 `ctx.extras["state"]`（CSRF 防护）；provider 未注册返回 `InvalidParam`，调用失败透传。
///
/// # 设计理由
///
/// 不直接依赖 `protocol::social`，避免 feature gate 链穿透 `account-authflow`（社交登录仅在
/// `social-wechat`/`social-alipay` 启用时编译）。
///
/// # 示例
///
/// ```ignore
/// use std::collections::HashMap;
/// use std::sync::Arc;
/// use garrison::account::authflow::executor::SocialProviderResolver;
/// use garrison::error::{GarrisonError, GarrisonResult};
///
/// struct Registry {
/// providers: HashMap<String, Arc<dyn garrison::protocol::social::SocialLoginProvider>>,
/// }
///
/// #[async_trait::async_trait]
/// impl SocialProviderResolver for Registry {
/// async fn resolve_login_id(&self, provider: &str, code: &str, state: &str)
/// -> GarrisonResult<String> {
/// let p = self.providers.get(provider)
/// .ok_or_else(|| GarrisonError::InvalidParam(format!("unknown: {}", provider)))?;
/// let user = p.exchange_token(code, state).await?;
/// Ok(user.provider_user_id)
/// }
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
    ) -> GarrisonResult<String>;
}

/// SSO Server 解析 trait：验证 ticket 并返回 login_id（实现方委托 `SsoServer::validate_ticket(ticket, client_id)`，
/// ticket 一次性消费）。经 [`AuthExecutor::execute_with_full`] 注入（非 struct 字段）；`ticket` 取 `ctx.input`、
/// `client_id` 取 `ctx.extras["client_id"]`；server 未注册返回 `InvalidParam`，ticket 无效返回 `InvalidToken`。
///
/// # 设计理由
///
/// 同 [`SocialProviderResolver`]：不直接依赖 `protocol::sso::server`，避免 feature gate 链穿透
/// `account-authflow`（SSO Server 仅在 `protocol-sso-server` 启用时编译）。
#[async_trait]
pub trait SsoServerResolver: Send + Sync {
    /// 验证 ticket 并返回 login_id（内部委托 `SsoServer::validate_ticket`）。
    async fn validate_and_get_login_id(
        &self,
        server_id: &str,
        ticket: &str,
        client_id: i64,
    ) -> GarrisonResult<String>;
}

/// 认证流程执行器：按 [`AuthenticationFlow`] 步骤顺序执行，支持 Login / Mfa / Conditional /
/// SubFlow / SocialProvider / SsoServer 六种步骤。
///
/// 5 字段：logic / credential_repo / policy_engine / lockout / registry（后两者可选）；
/// Login 所需的 [`CredentialBuilder`] 经 [`execute_with_builder`](Self::execute_with_builder) 参数注入。
///
/// # 示例
///
/// ```ignore
/// use std::sync::Arc;
/// use garrison::account::authflow::executor::AuthExecutor;
/// use garrison::account::authflow::registry::FlowRegistry;
///
/// let executor = AuthExecutor::new(
/// logic,
/// credential_repo,
/// None, // policy_engine
/// None, // lockout
/// Arc::new(FlowRegistry::from_inventory()),
/// );
/// let result = executor.execute_with_builder(&flow, &mut ctx, &builder).await?;
/// ```
pub struct AuthExecutor {
    /// 核心认证逻辑（SessionLogic::login / MfaLogic::check_safe）。
    logic: Arc<GarrisonLogicDefault>,
    /// 凭证存储抽象（查询用户凭证）。
    credential_repo: Arc<dyn CredentialRepository>,
    /// 密码策略引擎（可选，供 RequiredAction 步骤使用）。
    policy_engine: Option<Arc<PasswordPolicyEngine>>,
    /// 用户级锁定策略（可选，Login 步骤前检查 + 失败时 record_failure）。
    lockout: Option<Arc<UserLockoutStrategy>>,
    /// 流程注册表（SubFlow 步骤查询子流程）。
    registry: Arc<FlowRegistry>,
    /// IP 白名单（可选，`IpWhitelisted` 条件真实求值；未注入恒 false）。
    ip_whitelist: Option<IpWhitelist>,
    /// 自定义条件求值器注册表（可选，`Custom(name)` 按名查找；未注册返回显性错误）。
    custom_evaluators: HashMap<String, Arc<dyn CustomConditionEvaluator>>,
}

/// 步骤执行结果（内部类型）：由 [`execute_step`](AuthExecutor::execute_step) 返回，
/// [`execute_inner`](AuthExecutor::execute_inner) 据此决定继续/中断/暂停。
#[derive(Debug)]
enum StepOutcome {
    /// 步骤成功，携带 Login 步骤生成的会话 token（非 Login 步骤为 None）。
    Success { token: Option<String> },
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
    /// 创建认证执行器：`policy_engine` 为 `None` 时 RequiredAction 步骤返回 Failed，
    /// `lockout` 为 `None` 时跳过锁定检查。
    pub fn new(
        logic: Arc<GarrisonLogicDefault>,
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
            ip_whitelist: None,
            custom_evaluators: HashMap::new(),
        }
    }

    /// 注入 IP 白名单（`IpWhitelisted` 条件的真实求值依据；未注入恒 false）。
    pub fn with_ip_whitelist(mut self, whitelist: IpWhitelist) -> Self {
        self.ip_whitelist = Some(whitelist);
        self
    }

    /// 注册自定义条件求值器（`Custom(name)` 运行期扩展点）；未注册的 Custom 条件求值时返回
    /// [`GarrisonError::InvalidParam`]（显性错误，不静默 false）。
    pub fn with_custom_evaluator(
        mut self,
        name: impl Into<String>,
        evaluator: Arc<dyn CustomConditionEvaluator>,
    ) -> Self {
        self.custom_evaluators.insert(name.into(), evaluator);
        self
    }

    /// 获取密码策略引擎引用（供 RequiredAction 步骤使用）。
    pub fn policy_engine(&self) -> Option<&Arc<PasswordPolicyEngine>> {
        self.policy_engine.as_ref()
    }

    /// 获取用户级锁定策略引用。
    pub fn lockout(&self) -> Option<&Arc<UserLockoutStrategy>> {
        self.lockout.as_ref()
    }

    /// 执行认证流程（无 builder / resolver）：Login、Mfa(Some)、SocialProvider、SsoServer 步骤返回
    /// `Failed`，Mfa(None) / Conditional / SubFlow 正常执行；完整支持用
    /// [`execute_with_builder`](Self::execute_with_builder) / [`execute_with_full`](Self::execute_with_full)。
    ///
    /// 返回 `Ok` 为 Success（全部通过）/ Failed（步骤失败且 `allow_skip=false`）/ Pending（命中
    /// `pause_after_step`）/ ChallengeRequired（如需 MFA 验证码）；基础设施故障（DAO / session）返回 `Err`。
    pub async fn execute(
        &self,
        flow: &AuthenticationFlow,
        ctx: &mut AuthContext,
    ) -> GarrisonResult<AuthResult> {
        self.execute_inner(flow, ctx, None, None, None, None, 0)
            .await
    }

    /// 执行认证流程（带 CredentialBuilder，支持 Login 步骤）：Login 经 `builder` 构造 `dyn Credential`
    /// 后 `verify`；SocialProvider / SsoServer 无 resolver 返回 `Failed`，返回值同 [`execute`](Self::execute)。
    pub async fn execute_with_builder(
        &self,
        flow: &AuthenticationFlow,
        ctx: &mut AuthContext,
        builder: &dyn CredentialBuilder,
    ) -> GarrisonResult<AuthResult> {
        self.execute_inner(flow, ctx, Some(builder), None, None, None, 0)
            .await
    }

    /// 执行认证流程（带 builder + social / sso resolver，支持 Login / SocialProvider / SsoServer 全部步骤类型）：
    /// SocialProvider 经 resolver 换 `provider_user_id`、SsoServer 经验证 ticket 取 `login_id`，再以
    /// `logic.login` 建立本地会话；返回值同 [`execute`](Self::execute)。
    pub async fn execute_with_full(
        &self,
        flow: &AuthenticationFlow,
        ctx: &mut AuthContext,
        builder: &dyn CredentialBuilder,
        social_resolver: &dyn SocialProviderResolver,
        sso_resolver: &dyn SsoServerResolver,
    ) -> GarrisonResult<AuthResult> {
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

    /// 执行认证流程（带 builder + AccountMetrics）：采集 `authflow_execute_duration`（label = `flow.name`）
    /// 与 `credential_verify_duration`（label = `credential_type`，Login/Mfa verify 前后）；`metrics` 作方法
    /// 参数传入以保持 5 字段约束，返回值同 [`execute`](Self::execute)。
    #[cfg(feature = "metrics-prometheus")]
    pub async fn execute_with_metrics(
        &self,
        flow: &AuthenticationFlow,
        ctx: &mut AuthContext,
        builder: &dyn CredentialBuilder,
        metrics: &crate::account::metrics::AccountMetrics,
    ) -> GarrisonResult<AuthResult> {
        self.execute_inner(flow, ctx, Some(builder), None, None, Some(metrics), 0)
            .await
    }

    /// 执行认证流程核心逻辑：`builder` / `social_resolver` / `sso_resolver` 为 `None` 时对应步骤返回
    /// `Failed`；`metrics` 为 `Some` 时记录 `authflow_execute_duration`（label = `flow.name`）。
    async fn execute_inner(
        &self,
        flow: &AuthenticationFlow,
        ctx: &mut AuthContext,
        builder: Option<&dyn CredentialBuilder>,
        social_resolver: Option<&dyn SocialProviderResolver>,
        sso_resolver: Option<&dyn SsoServerResolver>,
        metrics: Option<&crate::account::metrics::AccountMetrics>,
        depth: usize,
    ) -> GarrisonResult<AuthResult> {
        #[cfg(feature = "metrics-prometheus")]
        let flow_start = std::time::Instant::now();
        #[cfg(feature = "metrics-prometheus")]
        let flow_name = flow.name.clone();

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
        let mut early_result: Option<GarrisonResult<AuthResult>> = None;

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

            if let Some(result) = self.handle_step_outcome(
                outcome,
                index,
                &flow.steps,
                flow.allow_skip,
                ctx,
                &mut token,
            ) {
                early_result = Some(result);
                break;
            }
        }

        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = metrics {
            m.observe_authflow_execute(&flow_name, flow_start.elapsed());
        }

        if let Some(result) = early_result {
            return result;
        }

        Ok(AuthResult::Success {
            login_id: ctx.user_id.clone().unwrap_or_default(),
            token: token.unwrap_or_default(),
        })
    }

    /// 处理单个步骤的执行结果，返回 `Some(result)` 表示流程中断，`None` 表示继续。
    fn handle_step_outcome(
        &self,
        outcome: StepOutcome,
        index: usize,
        steps: &[AuthStep],
        allow_skip: bool,
        ctx: &mut AuthContext,
        token: &mut Option<String>,
    ) -> Option<GarrisonResult<AuthResult>> {
        match outcome {
            StepOutcome::Success { token: step_token } => {
                ctx.completed_steps.push(index);
                if let Some(t) = step_token {
                    *token = Some(t);
                }
                if let Some(pause_str) = ctx.extras.get("pause_after_step") {
                    if pause_str.parse::<usize>().ok() == Some(index) && index + 1 < steps.len() {
                        let challenge = self.step_challenge(&steps[index + 1]);
                        return Some(Ok(AuthResult::Pending {
                            completed_step: index,
                            next_step: index + 1,
                            challenge,
                        }));
                    }
                }
                None
            },
            StepOutcome::Failed(reason) => {
                if allow_skip {
                    return None;
                }
                Some(Ok(AuthResult::Failed {
                    reason,
                    step: index,
                }))
            },
            StepOutcome::ChallengeRequired {
                challenge_type,
                message,
            } => Some(Ok(AuthResult::ChallengeRequired {
                challenge_type,
                message,
            })),
        }
    }

    /// 执行单个认证步骤；返回 `Pin<Box<dyn Future>>` 以支持 Conditional 递归
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
    ) -> Pin<Box<dyn Future<Output = GarrisonResult<StepOutcome>> + Send + 'a>> {
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
                    "authflow-required-action-not-implemented".to_string(),
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
    ) -> GarrisonResult<StepOutcome> {
        // 未启用 metrics-prometheus 时显式忽略 metrics 参数（避免 unused_variables warning）
        #[cfg(not(feature = "metrics-prometheus"))]
        let _ = metrics;

        if let Some(result) = self.check_login_lockout(ctx).await? {
            return Ok(result);
        }

        let builder = match builder {
            Some(b) => b,
            None => {
                return Ok(StepOutcome::Failed(loc!(
                    "authflow-login-needs-builder",
                    ""
                )));
            },
        };

        let user_id = match &ctx.user_id {
            Some(id) => id.clone(),
            None => {
                return Ok(StepOutcome::Failed(loc!(
                    "authflow-login-needs-user-id",
                    ""
                )));
            },
        };

        let creds = self
            .credential_repo
            .find_by_user_and_type(&user_id, credential_type)
            .await?;
        if creds.is_empty() {
            return Ok(StepOutcome::Failed(loc!(
                "authflow-credential-not-found",
                "",
                ("arg0", credential_type)
            )));
        }

        let cred = builder.build(creds[0].clone())?;
        #[cfg(feature = "metrics-prometheus")]
        let verify_start = std::time::Instant::now();
        let verified = cred.verify(&ctx.input).await?;
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = metrics {
            m.observe_credential_verify(credential_type, verify_start.elapsed());
        }

        self.handle_login_result(verified, &user_id).await
    }

    /// 锁定检查：被锁定返回 `Some(Failed)`，通过返回 `None`。
    async fn check_login_lockout(&self, ctx: &AuthContext) -> GarrisonResult<Option<StepOutcome>> {
        if let Some(lockout) = &self.lockout {
            if let Some(user_id) = &ctx.user_id {
                let fw_ctx = FirewallContext::new(&ctx.ip).with_login_id(user_id.clone());
                if let Err(e) = lockout.check(&fw_ctx).await {
                    let err_str = e.to_string();
                    return Ok(Some(StepOutcome::Failed(loc!(
                        "authflow-user-locked",
                        "",
                        ("arg0", &err_str)
                    ))));
                }
            }
        }
        Ok(None)
    }

    /// 处理凭证校验结果：成功则创建会话，失败则记录失败。
    async fn handle_login_result(
        &self,
        verified: bool,
        user_id: &str,
    ) -> GarrisonResult<StepOutcome> {
        if verified {
            let session_token = self.logic.login(user_id, &LoginParams::default()).await?;
            if let Some(lockout) = &self.lockout {
                if let Err(e) = lockout.record_success(user_id).await {
                    tracing::warn!(user_id = %user_id, error = %e, "lockout record_success failed");
                }
            }
            Ok(StepOutcome::Success {
                token: Some(session_token),
            })
        } else {
            if let Some(lockout) = &self.lockout {
                if let Err(e) = lockout.record_failure(user_id).await {
                    tracing::warn!(user_id = %user_id, error = %e, "lockout record_failure failed");
                }
            }
            Ok(StepOutcome::Failed(loc!(
                "authflow-credential-verify-failed",
                ""
            )))
        }
    }

    /// 执行 Mfa 步骤（内部方法）。
    async fn execute_mfa(
        &self,
        credential_type: Option<&String>,
        ctx: &mut AuthContext,
        builder: Option<&dyn CredentialBuilder>,
        metrics: Option<&crate::account::metrics::AccountMetrics>,
    ) -> GarrisonResult<StepOutcome> {
        // 未启用 metrics-prometheus 时显式忽略 metrics 参数（避免 unused_variables warning）
        #[cfg(not(feature = "metrics-prometheus"))]
        let _ = metrics;

        match credential_type {
            None => {
                // Mfa(None)：check_safe 默认返回 Ok
                self.logic.check_safe().await?;
                Ok(StepOutcome::Success { token: None })
            },
            Some(cred_type) => {
                if ctx.input.is_empty() {
                    return Ok(StepOutcome::ChallengeRequired {
                        challenge_type: cred_type.clone(),
                        message: loc!(
                            "authflow-enter-verification-code",
                            "",
                            ("arg0", &**cred_type)
                        ),
                    });
                }

                let builder = match builder {
                    Some(b) => b,
                    None => {
                        return Ok(StepOutcome::Failed(loc!("authflow-mfa-needs-builder", "")));
                    },
                };

                let user_id = match &ctx.user_id {
                    Some(id) => id.clone(),
                    None => {
                        return Ok(StepOutcome::Failed(loc!("authflow-mfa-needs-user-id", "")));
                    },
                };

                let creds = self
                    .credential_repo
                    .find_by_user_and_type(&user_id, cred_type)
                    .await?;
                if creds.is_empty() {
                    return Ok(StepOutcome::Failed(loc!(
                        "authflow-credential-not-found",
                        "",
                        ("arg0", &**cred_type)
                    )));
                }

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
                    Ok(StepOutcome::Failed(loc!(
                        "authflow-verify-failed",
                        "",
                        ("arg0", &**cred_type)
                    )))
                }
            },
        }
    }

    /// 执行 SubFlow 步骤；子流程返回的 Pending 视为 Failed（不支持嵌套 Pending 传播）。
    async fn execute_subflow(
        &self,
        flow_name: &str,
        ctx: &mut AuthContext,
        builder: Option<&dyn CredentialBuilder>,
        social_resolver: Option<&dyn SocialProviderResolver>,
        sso_resolver: Option<&dyn SsoServerResolver>,
        metrics: Option<&crate::account::metrics::AccountMetrics>,
        depth: usize,
    ) -> GarrisonResult<StepOutcome> {
        if depth >= MAX_FLOW_DEPTH {
            let depth_str = MAX_FLOW_DEPTH.to_string();
            return Ok(StepOutcome::Failed(loc!(
                "authflow-max-depth-exceeded",
                "",
                ("arg0", depth_str.as_str())
            )));
        }

        let sub_flow = match self.registry.get(flow_name) {
            Some(f) => f,
            None => {
                return Ok(StepOutcome::Failed(loc!(
                    "authflow-subflow-not-found",
                    "",
                    ("arg0", flow_name)
                )));
            },
        };

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
            // 透传子流程 token；空串保持 None 语义。
            AuthResult::Success { token, .. } => Ok(StepOutcome::Success {
                token: if token.is_empty() { None } else { Some(token) },
            }),
            AuthResult::Failed { reason, .. } => {
                let reason_str = reason;
                Ok(StepOutcome::Failed(loc!(
                    "authflow-subflow-failed",
                    "",
                    ("arg0", flow_name),
                    ("arg1", &reason_str)
                )))
            },
            AuthResult::Pending { .. } => Ok(StepOutcome::Failed(loc!(
                "authflow-subflow-pending",
                "",
                ("arg0", flow_name)
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

    /// 执行 SocialProvider 步骤：`social_resolver` 为 `None` 返回 `Failed`、`ctx.input` 为空返回
    /// `ChallengeRequired`；`state` 取 `ctx.extras["state"]`（缺失空串），经 resolver 换 `login_id`
    /// 后 `logic.login` 建会话并写回 `ctx.user_id`。
    async fn execute_social(
        &self,
        provider: &str,
        ctx: &mut AuthContext,
        social_resolver: Option<&dyn SocialProviderResolver>,
    ) -> GarrisonResult<StepOutcome> {
        let resolver = match social_resolver {
            Some(r) => r,
            None => {
                return Ok(StepOutcome::Failed(loc!(
                    "authflow-social-needs-resolver",
                    ""
                )));
            },
        };

        if ctx.input.is_empty() {
            return Ok(StepOutcome::ChallengeRequired {
                challenge_type: format!("social:{}", provider),
                message: loc!("authflow-complete-social-auth", "", ("arg0", provider)),
            });
        }

        // state 来自 extras（OAuth2 CSRF 防护）
        let state = ctx.extras.get("state").cloned().unwrap_or_default();

        let login_id = match resolver
            .resolve_login_id(provider, &ctx.input, &state)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                let err_str = e.to_string();
                return Ok(StepOutcome::Failed(loc!(
                    "authflow-social-login-failed",
                    "",
                    ("arg0", provider),
                    ("arg1", &err_str)
                )));
            },
        };

        let token = self.logic.login(&login_id, &LoginParams::default()).await?;

        // 写回 ctx.user_id 供后续步骤（如 Mfa）使用
        ctx.user_id = Some(login_id.clone());

        Ok(StepOutcome::Success { token: Some(token) })
    }

    /// 执行 SsoServer 步骤：`sso_resolver` 为 `None` 返回 `Failed`、`ctx.input` 为空返回
    /// `ChallengeRequired`；`client_id` 取 `ctx.extras["client_id"]`（缺失或解析失败回退 0），
    /// 经验证 ticket 取 `login_id` 后建会话并写回 `ctx.user_id`。
    async fn execute_sso(
        &self,
        server_id: &str,
        ctx: &mut AuthContext,
        sso_resolver: Option<&dyn SsoServerResolver>,
    ) -> GarrisonResult<StepOutcome> {
        let resolver = match sso_resolver {
            Some(r) => r,
            None => {
                return Ok(StepOutcome::Failed(loc!("authflow-sso-needs-resolver", "")));
            },
        };

        if ctx.input.is_empty() {
            return Ok(StepOutcome::ChallengeRequired {
                challenge_type: format!("sso:{}", server_id),
                message: loc!("authflow-complete-sso-auth", "", ("arg0", server_id)),
            });
        }

        // client_id 缺失或解析失败回退 0（warn 记录）
        let client_id: i64 = match ctx.extras.get("client_id") {
            Some(s) => s.parse().unwrap_or_else(|e| {
                tracing::warn!(
                    server_id,
                    raw = %s,
                    error = %e,
                    "SSO client_id parse failed, falling back to default value 0"
                );
                0
            }),
            None => 0,
        };

        let login_id = match resolver
            .validate_and_get_login_id(server_id, &ctx.input, client_id)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                let err_str = e.to_string();
                return Ok(StepOutcome::Failed(loc!(
                    "authflow-sso-verify-failed",
                    "",
                    ("arg0", &err_str)
                )));
            },
        };

        let token = self.logic.login(&login_id, &LoginParams::default()).await?;

        // 写回 ctx.user_id 供后续步骤使用
        ctx.user_id = Some(login_id.clone());

        Ok(StepOutcome::Success { token: Some(token) })
    }

    /// 评估条件分支。
    async fn evaluate_condition(
        &self,
        condition: &AuthCondition,
        ctx: &AuthContext,
    ) -> GarrisonResult<bool> {
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
            AuthCondition::IpWhitelisted => match &self.ip_whitelist {
                Some(whitelist) => Ok(whitelist.contains(&ctx.ip)),
                None => {
                    // 未注入白名单恒 false（fail-safe），留 debug 痕迹
                    tracing::debug!("authflow-ip-whitelist-not-configured (ip={})", ctx.ip);
                    Ok(false)
                },
            },
            AuthCondition::Custom(name) => {
                // 扩展点：按名查注册的求值器；未注册是配置错误，显性报错而非静默 false
                match self.custom_evaluators.get(name) {
                    Some(evaluator) => evaluator.evaluate(ctx).await,
                    None => Err(GarrisonError::InvalidParam(format!(
                        "authflow-unknown-custom-condition::{name}"
                    ))),
                }
            },
        }
    }

    /// 生成下一步骤的挑战提示。
    fn step_challenge(&self, step: &AuthStep) -> String {
        match step {
            AuthStep::Login { credential_type } => {
                loc!("authflow-step-enter", "", ("arg0", &**credential_type))
            },
            AuthStep::Mfa { credential_type } => match credential_type {
                Some(ct) => loc!("authflow-step-enter-code", "", ("arg0", &**ct)),
                None => loc!("authflow-step-complete-mfa", "").to_string(),
            },
            AuthStep::SocialProvider { provider } => {
                loc!("authflow-step-complete-social", "", ("arg0", &**provider))
            },
            AuthStep::SsoServer { server_id } => {
                loc!("authflow-step-complete-sso", "", ("arg0", server_id))
            },
            AuthStep::RequiredAction { action } => {
                loc!("authflow-step-complete-action", "", ("arg0", &**action))
            },
            AuthStep::Conditional { .. } => loc!("authflow-step-complete-condition", ""),
            AuthStep::SubFlow { flow_name } => {
                loc!("authflow-step-complete-subflow", "", ("arg0", &**flow_name))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::authflow::FlowBuilder;
    use crate::account::credential::CredentialType;
    use crate::config::GarrisonConfig;
    use crate::dao::tests::MockDao;
    use crate::dao::GarrisonDao;
    use crate::error::GarrisonError;
    use crate::session::GarrisonSession;
    use crate::stp::GarrisonInterface;
    use crate::strategy::GarrisonPermissionStrategyDefault;
    use std::collections::HashMap;

    // Mock 类型：MockCredential / MockCredentialBuilder / MockCredentialRepository

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

        async fn verify(&self, _input: &str) -> GarrisonResult<bool> {
            Ok(self.verify_result)
        }
    }

    /// Mock 凭证构造器，按 `credential_type` 返回不同 `verify_result` 的 MockCredential。
    struct MockCredentialBuilder {
        password_verify_result: bool,
        totp_verify_result: bool,
    }

    impl CredentialBuilder for MockCredentialBuilder {
        fn build(&self, model: CredentialModel) -> GarrisonResult<Box<dyn Credential>> {
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
        async fn create(&self, credential: CredentialModel) -> GarrisonResult<()> {
            let mut store = self.store.lock().unwrap();
            if store.contains_key(&credential.id) {
                return Err(GarrisonError::InvalidParam(format!(
                    "credential already exists: {}",
                    credential.id
                )));
            }
            store.insert(credential.id.clone(), credential);
            Ok(())
        }

        async fn find_by_user(
            &self,
            caller_login_id: &str,
            user_id: &str,
        ) -> GarrisonResult<Vec<CredentialModel>> {
            // IDOR 防护：caller 必须是自己
            if caller_login_id != user_id {
                return Err(GarrisonError::NotPermission(format!(
                    "caller {} cannot query credentials of {}",
                    caller_login_id, user_id
                )));
            }
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
        ) -> GarrisonResult<Vec<CredentialModel>> {
            // 安全语义：调用方应在认证上下文中使用，user_id 即为会话主体。
            let all = self.find_by_user(user_id, user_id).await?;
            Ok(all
                .into_iter()
                .filter(|c| c.credential_type == cred_type)
                .collect())
        }

        async fn update(
            &self,
            caller_login_id: &str,
            credential: CredentialModel,
        ) -> GarrisonResult<()> {
            let mut store = self.store.lock().unwrap();
            let existing = match store.get(&credential.id) {
                Some(m) => m.clone(),
                None => {
                    return Err(GarrisonError::InvalidParam(format!(
                        "credential not found: {}",
                        credential.id
                    )));
                },
            };
            // IDOR 防护 1：caller 必须是凭证原 owner
            if existing.user_id != caller_login_id {
                return Err(GarrisonError::NotPermission(format!(
                    "caller {} cannot update credential {} owned by {}",
                    caller_login_id, credential.id, existing.user_id
                )));
            }
            // IDOR 防护 2：禁止通过 update 改变 user_id
            if credential.user_id != existing.user_id {
                return Err(GarrisonError::NotPermission(format!(
                    "cannot transfer credential {} from user {} to {}",
                    credential.id, existing.user_id, credential.user_id
                )));
            }
            store.insert(credential.id.clone(), credential);
            Ok(())
        }

        async fn delete(&self, caller_login_id: &str, credential_id: &str) -> GarrisonResult<()> {
            let mut store = self.store.lock().unwrap();
            let existing = match store.get(credential_id) {
                Some(m) => m.clone(),
                None => {
                    return Err(GarrisonError::InvalidParam(format!(
                        "credential not found: {}",
                        credential_id
                    )));
                },
            };
            // IDOR 防护：caller 必须是凭证 owner
            if existing.user_id != caller_login_id {
                return Err(GarrisonError::NotPermission(format!(
                    "caller {} cannot delete credential {} owned by {}",
                    caller_login_id, credential_id, existing.user_id
                )));
            }
            store.remove(credential_id);
            Ok(())
        }
    }

    /// Mock GarrisonInterface（空权限/角色数据）。
    struct MockInterface;

    #[async_trait]
    impl GarrisonInterface for MockInterface {
        async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
            Ok(Vec::new())
        }
    }

    // 辅助函数

    /// 构造测试用 `Arc<GarrisonLogicDefault>`。
    fn make_logic() -> Arc<GarrisonLogicDefault> {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = Arc::new(GarrisonConfig::default_config());
        let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface);
        let timeout = u64::try_from(config.timeout).unwrap_or(3600);
        let session = Arc::new(GarrisonSession::new(dao.clone(), timeout, timeout, 0));
        let firewall: Arc<dyn crate::strategy::GarrisonPermissionStrategy> =
            Arc::new(GarrisonPermissionStrategyDefault::new(interface));
        Arc::new(GarrisonLogicDefault::new(
            session,
            config,
            firewall,
            Arc::new(crate::account::disable::DefaultDisableRepository::new(
                dao.clone(),
            )),
        ))
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

    /// Login 步骤 — 密码校验成功 → AuthResult::Success。
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

    /// Login 步骤 — 密码校验失败 → AuthResult::Failed。
    #[tokio::test]
    async fn password_login_failure() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
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

    /// Mfa(None) 步骤 — check_safe 默认返回 Ok → Success。
    ///
    /// 仅在 security-extra 禁用时有效：启用时 check_safe 检查 safe_services 标记，
    /// 未 open_safe 返回 NotSafe 错误。
    #[cfg(not(feature = "security-extra"))]
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

    /// Mfa(Some("totp")) 步骤 — TOTP 校验成功 → Success。
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

    /// Mfa(Some("totp")) 步骤 — TOTP 校验失败 → Failed。
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

    /// Conditional 步骤 — 条件为真执行 if_step（Login verify=false → Failed）。
    #[tokio::test]
    async fn conditional_true() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
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

    /// Conditional 步骤 — 条件为假且 else_step=None → 跳过 → Success。
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

    /// SubFlow 步骤 — 子流程 Login 成功 → 父流程 Success。
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

    /// 空步骤流程 → 直接返回 Success。
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

    /// 多步流程（Login + Mfa(None)）— 两步均通过 → Success。
    ///
    /// 仅在 security-extra 禁用时有效：启用时 Mfa(None) 的 check_safe 检查 safe_services
    /// 标记，未 open_safe 时返回 NotSafe 错误。
    #[cfg(not(feature = "security-extra"))]
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

    /// pause_after_step 标记 — Login 成功后暂停 → Pending。
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

    /// Mfa(Some("totp")) 输入为空 → ChallengeRequired。
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

    /// Login 步骤前检查锁定 — 用户被锁定 → Failed。
    #[tokio::test]
    async fn lockout_blocks_login() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
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

    /// Login 步骤 — ctx.user_id 为 None → Failed（"Login 步骤需要 user_id"）。
    #[tokio::test]
    async fn login_without_user_id_returns_failed() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("test").login("password").build();
        let mut ctx = make_context("alice", "password");
        ctx.user_id = None;

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(
                    reason.contains("user_id"),
                    "reason 应含 user_id: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed（无 user_id），实际: {:?}", other),
        }
    }

    /// Login 步骤 — 凭证存储为空 → Failed（"未找到 X 类型的凭证"）。
    #[tokio::test]
    async fn login_credential_not_found_returns_failed() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("test").login("password").build();
        let mut ctx = make_context("alice", "password");

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(reason.contains("未找到"), "reason 应含未找到: {}", reason);
                assert!(
                    reason.contains("password"),
                    "reason 应含凭证类型 password: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed（无凭证），实际: {:?}", other),
        }
    }

    /// execute() 遇到 Login 步骤 → Failed（无 CredentialBuilder）。
    #[tokio::test]
    async fn execute_without_builder_login_returns_failed() {
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let flow = FlowBuilder::new("test").login("password").build();
        let mut ctx = make_context("alice", "password");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(
                    reason.contains("CredentialBuilder"),
                    "reason 应含 CredentialBuilder: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed（无 builder），实际: {:?}", other),
        }
    }

    /// execute() 遇到 Mfa(Some("totp")) 步骤 → Failed（无 CredentialBuilder）。
    /// 需 ctx.input 非空，否则会先返回 ChallengeRequired。
    #[tokio::test]
    async fn mfa_some_without_builder_returns_failed() {
        let repo = make_repo_with_password_and_totp("alice").await;
        let executor = make_executor(repo, None);
        let flow = FlowBuilder::new("test").mfa(Some("totp")).build();
        let mut ctx = make_context("alice", "123456");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(
                    reason.contains("CredentialBuilder"),
                    "reason 应含 CredentialBuilder: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed（无 builder），实际: {:?}", other),
        }
    }

    /// Mfa(Some) 步骤 — ctx.user_id 为 None → Failed（"Mfa 步骤需要 user_id"）。
    #[tokio::test]
    async fn mfa_without_user_id_returns_failed() {
        let repo = make_repo_with_password_and_totp("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: false,
            totp_verify_result: true,
        };
        let flow = FlowBuilder::new("test").mfa(Some("totp")).build();
        let mut ctx = make_context("alice", "123456");
        ctx.user_id = None;

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(
                    reason.contains("user_id"),
                    "reason 应含 user_id: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed（无 user_id），实际: {:?}", other),
        }
    }

    /// Mfa(Some) 步骤 — 凭证存储中无对应类型 → Failed（"未找到 X 类型的凭证"）。
    #[tokio::test]
    async fn mfa_credential_not_found_returns_failed() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        // repo 只有 password 凭证，没有 totp 凭证
        let repo = make_repo_with_password("alice").await;
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
            AuthResult::Failed { reason, step } => {
                assert!(reason.contains("未找到"), "reason 应含未找到: {}", reason);
                assert!(
                    reason.contains("totp"),
                    "reason 应含凭证类型 totp: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed（无 totp 凭证），实际: {:?}", other),
        }
    }

    /// SubFlow 步骤 — registry 中无对应 flow_name → Failed（"未找到子流程: X"）。
    #[tokio::test]
    async fn subflow_unknown_flow_returns_failed() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        // 空 registry（from_inventory 默认无注册流程）
        let executor = make_executor_with_registry(repo, Arc::new(FlowRegistry::from_inventory()));
        let flow = FlowBuilder::new("parent")
            .sub_flow("nonexistent-flow")
            .build();
        let mut ctx = make_context("alice", "");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(
                    reason.contains("未找到子流程"),
                    "reason 应含未找到子流程: {}",
                    reason
                );
                assert!(
                    reason.contains("nonexistent-flow"),
                    "reason 应含 flow 名称: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed（子流程未找到），实际: {:?}", other),
        }
    }

    /// SubFlow 步骤 — 递归深度超过 MAX_FLOW_DEPTH（10）→ Failed（"嵌套深度超过上限"）。
    /// 构造自引用流程（flow 引用自身），递归至 depth=10 时被截断。
    #[tokio::test]
    async fn subflow_max_depth_exceeded_returns_failed() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let mut registry = FlowRegistry::from_inventory();
        // 自引用流程：唯一步骤是 SubFlow("loop")，将递归自身
        let recursive_flow = FlowBuilder::new("loop").sub_flow("loop").build();
        registry.register(recursive_flow);
        let executor = make_executor_with_registry(repo, Arc::new(registry));
        let flow = FlowBuilder::new("parent").sub_flow("loop").build();
        let mut ctx = make_context("alice", "");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Failed { reason, .. } => {
                assert!(
                    reason.contains("嵌套深度") || reason.contains("循环引用"),
                    "reason 应含嵌套深度或循环引用: {}",
                    reason
                );
            },
            other => panic!("应为 Failed（深度超限），实际: {:?}", other),
        }
    }

    /// RequiredAction 步骤未实现 → Failed（错误消息 "RequiredAction 步骤未实现"）。
    /// FlowBuilder 未提供 required_action 方法，直接构造 AuthenticationFlow。
    #[tokio::test]
    async fn required_action_step_returns_failed() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let flow = AuthenticationFlow {
            name: "test".to_string(),
            steps: vec![AuthStep::RequiredAction {
                action: "verify_email".to_string(),
            }],
            allow_skip: false,
        };
        let mut ctx = make_context("alice", "");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(
                    reason.contains("authflow-required-action-not-implemented"),
                    "reason 应含 authflow-required-action-not-implemented: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed（RequiredAction 未实现），实际: {:?}", other),
        }
    }

    /// allow_skip=true — 第一步 Failed (RequiredAction) 被跳过，
    /// 第二步 Conditional (IpWhitelisted=false → else_step=None → Success) → 流程 Success。
    #[tokio::test]
    async fn allow_skip_continues_after_failed_step() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let flow = AuthenticationFlow {
            name: "test".to_string(),
            steps: vec![
                // 必失败步骤：RequiredAction 未实现
                AuthStep::RequiredAction {
                    action: "verify_email".to_string(),
                },
                // 必成功步骤：IpWhitelisted 永远 false，else_step=None → 跳过视为 Success
                AuthStep::Conditional {
                    condition: AuthCondition::IpWhitelisted,
                    if_step: Box::new(AuthStep::RequiredAction {
                        action: "x".to_string(),
                    }),
                    else_step: None,
                },
            ],
            allow_skip: true,
        };
        let mut ctx = make_context("alice", "");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Success { login_id, .. } => {
                assert_eq!(login_id, "alice");
                // 仅 Conditional 步骤成功被记入 completed_steps（RequiredAction 被跳过）
                assert_eq!(
                    ctx.completed_steps.len(),
                    1,
                    "应只完成 1 个步骤（跳过失败的 RequiredAction）"
                );
                assert_eq!(ctx.completed_steps[0], 1, "应记录第 2 步（索引 1）");
            },
            other => panic!("应为 Success（allow_skip 跳过失败），实际: {:?}", other),
        }
    }

    /// pause_after_step 指向最后一步 — 无 next_step 可暂停 → 返回 Success（不 Pending）。
    #[tokio::test]
    async fn pause_after_last_step_returns_success() {
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("single").login("password").build();
        let mut ctx = make_context("alice", "correct-password");
        // pause_after_step = 0 = 最后一步索引，无 next_step，不应触发 Pending
        ctx.extras
            .insert("pause_after_step".to_string(), "0".to_string());

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Success { login_id, token } => {
                assert_eq!(login_id, "alice");
                assert!(!token.is_empty(), "token 不应为空");
            },
            other => panic!("应为 Success（最后一步不暂停），实际: {:?}", other),
        }
    }

    /// Conditional 步骤 — 条件为假且 else_step=Some(...) → 执行 else_step。
    /// 验证 else_step 不为 None 时分支被实际执行（而非跳过）。
    #[tokio::test]
    async fn conditional_with_else_step_executed_when_false() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: false, // else_step Login verify 失败 → Failed
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("test")
            .conditional(
                // HasCredential("totp")=false（用户只有 password 凭证）
                AuthCondition::HasCredential("totp".to_string()),
                // if_step（不会执行）
                AuthStep::Login {
                    credential_type: "password".to_string(),
                },
                Some(AuthStep::Login {
                    credential_type: "password".to_string(),
                }),
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
                    "reason 应含凭证校验失败（else_step 执行并失败）: {}",
                    reason
                );
            },
            other => panic!(
                "应为 Failed（else_step 执行后 verify=false），实际: {:?}",
                other
            ),
        }
    }

    /// SubFlow 步骤 — 子流程返回 Failed → 父流程 Failed（"子流程 X 失败: ..."）。
    #[tokio::test]
    async fn subflow_child_failed_propagates_failed() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let mut registry = FlowRegistry::from_inventory();
        // 子流程：RequiredAction 步骤（必失败）
        let child = AuthenticationFlow {
            name: "failing-child".to_string(),
            steps: vec![AuthStep::RequiredAction {
                action: "verify_email".to_string(),
            }],
            allow_skip: false,
        };
        registry.register(child);
        let executor = make_executor_with_registry(repo, Arc::new(registry));
        let flow = FlowBuilder::new("parent").sub_flow("failing-child").build();
        let mut ctx = make_context("alice", "");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(
                    reason.contains("子流程")
                        || reason.contains("failing-child")
                        || reason.contains("authflow-required-action-not-implemented"),
                    "reason 应含子流程: {}",
                    reason
                );
                assert!(
                    reason.contains("failing-child"),
                    "reason 应含子流程名称: {}",
                    reason
                );
                assert!(
                    reason.contains("authflow-required-action-not-implemented")
                        || reason.contains("RequiredAction"),
                    "reason 应含原始失败原因: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed（子流程失败传播），实际: {:?}", other),
        }
    }

    /// AuthExecutor::policy_engine / lockout 访问器 — 注入 Some 时返回 Some，None 时返回 None。
    #[tokio::test]
    async fn accessors_return_some_when_provided() {
        use crate::account::policy::{ErrorMode, PasswordPolicyEngine};

        // 场景 1: 注入 policy_engine + lockout → 访问器返回 Some
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let policy = Arc::new(PasswordPolicyEngine::new(vec![], ErrorMode::FirstError));
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let lockout = Arc::new(UserLockoutStrategy::new(
            crate::account::lockout::UserLockoutConfig {
                max_failure_factor: 5,
                permanent_lockout: false,
                max_temporary_lockouts: 99,
                wait_strategy: crate::account::lockout::WaitStrategy::Linear { base_seconds: 60 },
                failure_window_seconds: 300,
            },
            dao,
        ));
        let executor_with = AuthExecutor::new(
            make_logic(),
            repo,
            Some(policy),
            Some(lockout),
            Arc::new(FlowRegistry::from_inventory()),
        );
        assert!(
            executor_with.policy_engine().is_some(),
            "注入 policy_engine 后访问器应返回 Some"
        );
        assert!(
            executor_with.lockout().is_some(),
            "注入 lockout 后访问器应返回 Some"
        );

        // 场景 2: 不注入（None）→ 访问器返回 None
        let repo_none: Arc<dyn CredentialRepository> =
            Arc::new(MockCredentialRepository::default());
        let executor_none = make_executor(repo_none, None);
        assert!(
            executor_none.policy_engine().is_none(),
            "未注入 policy_engine 时访问器应返回 None"
        );
        assert!(
            executor_none.lockout().is_none(),
            "未注入 lockout 时访问器应返回 None"
        );
    }

    /// Conditional 步骤 — IsLocked 条件为真（用户被锁定）→ 执行 if_step。
    /// 覆盖 evaluate_condition 的 IsLocked 分支返回 true 的路径。
    /// 使用 RequiredAction 作为 if_step（不走 Login 的 lockout 检查，避免与条件判断耦合）。
    #[tokio::test]
    async fn conditional_is_locked_true_executes_if_step() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
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
        // 触发锁定（2 次失败达到 max_failure_factor 阈值）
        lockout.record_failure("alice").await.unwrap();
        lockout.record_failure("alice").await.unwrap();

        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, Some(lockout));
        let flow = FlowBuilder::new("test")
            .conditional(
                AuthCondition::IsLocked,
                // if_step: RequiredAction 永远返回 Failed（不走 lockout 检查，能区分条件分支）
                AuthStep::RequiredAction {
                    action: "verify_email".to_string(),
                },
                None,
            )
            .build();
        let mut ctx = make_context("alice", "");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                // IsLocked=true → if_step (RequiredAction) 被执行
                assert!(
                    reason.contains("authflow-required-action-not-implemented")
                        || reason.contains("RequiredAction"),
                    "reason 应含 RequiredAction 失败 key（IsLocked=true → if_step 执行）: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!(
                "应为 Failed（IsLocked=true，if_step 执行失败），实际: {:?}",
                other
            ),
        }
    }

    /// Custom 条件未注册求值器 → 显性 InvalidParam 错误（不再静默 false）。
    #[tokio::test]
    async fn conditional_custom_condition_unregistered_returns_error() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let flow = FlowBuilder::new("test")
            .conditional(
                AuthCondition::Custom("never_registered".to_string()),
                AuthStep::RequiredAction {
                    action: "x".to_string(),
                },
                None,
            )
            .build();
        let mut ctx = make_context("alice", "");

        let result = executor.execute(&flow, &mut ctx).await;
        match result {
            Err(GarrisonError::InvalidParam(msg)) => {
                assert!(
                    msg.contains("never_registered"),
                    "错误应包含条件名，实际: {msg}"
                );
            },
            other => panic!(
                "未注册 Custom 条件应为 InvalidParam 显性错误，实际: {:?}",
                other
            ),
        }
    }

    /// Custom 条件已注册且返回 true → 走 if_step。
    #[tokio::test]
    async fn conditional_custom_condition_registered_true_executes_if_step() {
        struct AlwaysTrue;
        #[async_trait]
        impl CustomConditionEvaluator for AlwaysTrue {
            async fn evaluate(&self, _ctx: &AuthContext) -> GarrisonResult<bool> {
                Ok(true)
            }
        }

        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor =
            make_executor(repo, None).with_custom_evaluator("my_check", Arc::new(AlwaysTrue));
        let flow = FlowBuilder::new("test")
            .conditional(
                AuthCondition::Custom("my_check".to_string()),
                AuthStep::RequiredAction {
                    action: "do_review".to_string(),
                },
                None,
            )
            .build();
        let mut ctx = make_context("alice", "");

        // if_step（RequiredAction）被执行 → 未实现 Failed 路径（区分分支被执行）
        let result = executor.execute(&flow, &mut ctx).await.unwrap();
        match result {
            AuthResult::Failed { reason, .. } => {
                assert!(
                    reason.contains("authflow-required-action-not-implemented")
                        || reason.contains("RequiredAction"),
                    "注册求值器=true 应执行 if_step（RequiredAction → Failed），reason: {reason}"
                );
            },
            other => panic!(
                "注册求值器=true 应执行 if_step（Failed），实际: {:?}",
                other
            ),
        }
    }

    /// Custom 求值器内部错误按 `?` 传播（不吞错）。
    #[tokio::test]
    async fn conditional_custom_condition_evaluator_error_propagates() {
        struct FailingEval;
        #[async_trait]
        impl CustomConditionEvaluator for FailingEval {
            async fn evaluate(&self, _ctx: &AuthContext) -> GarrisonResult<bool> {
                Err(GarrisonError::InvalidParam(
                    "evaluator-intentional-failure".to_string(),
                ))
            }
        }

        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor =
            make_executor(repo, None).with_custom_evaluator("failing", Arc::new(FailingEval));
        let flow = FlowBuilder::new("test")
            .conditional(
                AuthCondition::Custom("failing".to_string()),
                AuthStep::RequiredAction {
                    action: "x".to_string(),
                },
                None,
            )
            .build();
        let mut ctx = make_context("alice", "");

        let result = executor.execute(&flow, &mut ctx).await;
        match result {
            Err(GarrisonError::InvalidParam(msg)) => {
                assert!(msg.contains("evaluator-intentional-failure"), "got: {msg}");
            },
            other => panic!("求值器错误应传播，实际: {:?}", other),
        }
    }

    /// 白名单命中（IPv4 CIDR）→ IpWhitelisted 为 true → 执行 if_step。
    #[tokio::test]
    async fn conditional_ip_whitelisted_hit_executes_if_step() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let whitelist =
            IpWhitelist::parse(&["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()]).unwrap();
        let executor = make_executor(repo, None).with_ip_whitelist(whitelist);
        let flow = FlowBuilder::new("test")
            .conditional(
                AuthCondition::IpWhitelisted,
                AuthStep::RequiredAction {
                    action: "trusted_path".to_string(),
                },
                None,
            )
            .build();
        let mut ctx = make_context("alice", "");
        ctx.ip = "10.20.30.40".to_string();

        let result = executor.execute(&flow, &mut ctx).await.unwrap();
        match result {
            AuthResult::Failed { reason, .. } => {
                assert!(
                    reason.contains("authflow-required-action-not-implemented")
                        || reason.contains("RequiredAction"),
                    "白名单命中应执行 if_step（RequiredAction → Failed），reason: {reason}"
                );
            },
            other => panic!("白名单命中应执行 if_step（Failed），实际: {:?}", other),
        }
    }

    /// 白名单未命中 → false → else_step=None 跳过 → Success。
    #[tokio::test]
    async fn conditional_ip_whitelisted_miss_skips() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let whitelist = IpWhitelist::parse(&["10.0.0.0/8".to_string()]).unwrap();
        let executor = make_executor(repo, None).with_ip_whitelist(whitelist);
        let flow = FlowBuilder::new("test")
            .conditional(
                AuthCondition::IpWhitelisted,
                AuthStep::RequiredAction {
                    action: "trusted_path".to_string(),
                },
                None,
            )
            .build();
        let mut ctx = make_context("alice", "");
        ctx.ip = "203.0.113.9".to_string();

        let result = executor.execute(&flow, &mut ctx).await.unwrap();
        match result {
            AuthResult::Success { login_id, .. } => assert_eq!(login_id, "alice"),
            other => panic!("未命中应跳过（Success），实际: {:?}", other),
        }
    }

    /// 未注入白名单 → 恒 false（fail-safe）→ Success。
    #[tokio::test]
    async fn conditional_ip_whitelisted_not_configured_is_false() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let flow = FlowBuilder::new("test")
            .conditional(
                AuthCondition::IpWhitelisted,
                AuthStep::RequiredAction {
                    action: "trusted_path".to_string(),
                },
                None,
            )
            .build();
        let mut ctx = make_context("alice", "");
        ctx.ip = "10.0.0.1".to_string();

        let result = executor.execute(&flow, &mut ctx).await.unwrap();
        match result {
            AuthResult::Success { login_id, .. } => assert_eq!(login_id, "alice"),
            other => panic!("无白名单配置应为 false→Success，实际: {:?}", other),
        }
    }

    /// IPv6 CIDR 命中 + 单 IP（无前缀）视作 /32 或 /128 + 非法 IP 字符串 contains=false。
    #[test]
    fn ip_whitelist_ipv6_single_ip_and_invalid() {
        let wl = IpWhitelist::parse(&[
            "2001:db8::/32".to_string(),
            "172.16.5.7".to_string(), // 单 IP → /32
        ])
        .unwrap();
        assert!(wl.contains("2001:db8::1"));
        assert!(!wl.contains("2001:db9::1"));
        assert!(wl.contains("172.16.5.7"));
        assert!(!wl.contains("172.16.5.8"));
        assert!(!wl.contains("not-an-ip"));
        let err = IpWhitelist::parse(&["10.0.0.0/99".to_string()]).unwrap_err();
        match err {
            GarrisonError::InvalidParam(msg) => assert!(msg.contains("10.0.0.0/99")),
            other => panic!("非法 CIDR 应为 InvalidParam，实际: {other:?}"),
        }
    }

    /// pause_after_step 标记 — 验证 step_challenge 对 Login 步骤的输出格式。
    /// 在 Login 成功后暂停，下一步为 Login → challenge 应含 "请输入"。
    #[tokio::test]
    async fn pause_after_step_challenge_for_login_step() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let repo = make_repo_with_password_and_totp("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("two-login")
            .login("password")
            .login("totp")
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
                // 下一步是 Login("totp") → challenge 应为 "请输入 totp"
                assert!(
                    challenge.contains("请输入"),
                    "challenge 应含请输入: {}",
                    challenge
                );
                assert!(
                    challenge.contains("totp"),
                    "challenge 应含 totp: {}",
                    challenge
                );
            },
            other => panic!("应为 Pending，实际: {:?}", other),
        }
    }

    /// Login 步骤 — lockout=Some 且 verify=true → record_success 重置失败计数。
    /// 验证：[fail, ok, fail] 后第 4 次 login 仍可成功（count=1 < 2）；
    /// 若 record_success 未调用，第 3 次失败即达阈值（count=2）置锁定，第 4 次被 check 拦截返回 Failed。
    #[tokio::test]
    async fn login_with_lockout_success_resets_failure_count() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
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
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, Some(lockout));
        let flow = FlowBuilder::new("test").login("password").build();
        let builder_fail = MockCredentialBuilder {
            password_verify_result: false,
            totp_verify_result: false,
        };
        let builder_ok = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };

        let mut ctx1 = make_context("alice", "wrong");
        let _ = executor
            .execute_with_builder(&flow, &mut ctx1, &builder_fail)
            .await
            .unwrap();

        let mut ctx2 = make_context("alice", "correct");
        let _ = executor
            .execute_with_builder(&flow, &mut ctx2, &builder_ok)
            .await
            .unwrap();

        let mut ctx3 = make_context("alice", "wrong");
        let _ = executor
            .execute_with_builder(&flow, &mut ctx3, &builder_fail)
            .await
            .unwrap();

        // 第 4 次尝试 correct：若 record_success 已在第 2 次尝试调用，count=1 < 2 → check 通过 → Success
        // 若从未调用，count=2 已达阈值（第 3 次失败即置锁定）→ 第 4 次 check 被拦截 → Failed
        let mut ctx4 = make_context("alice", "correct");
        let result = executor
            .execute_with_builder(&flow, &mut ctx4, &builder_ok)
            .await
            .unwrap();

        match result {
            AuthResult::Success { login_id, .. } => {
                assert_eq!(
                    login_id, "alice",
                    "record_success 应在第 2 次尝试重置失败计数，使第 4 次尝试不被锁定"
                );
            },
            AuthResult::Failed { reason, .. } => {
                panic!(
                    "应为 Success（record_success 重置了计数），但 Failed: {}",
                    reason
                );
            },
            other => panic!("应为 Success，实际: {:?}", other),
        }
    }

    /// Login 步骤 — lockout=Some 且 verify=false → record_failure 增加失败计数。
    /// 验证：max_failure_factor=1 时，1 次失败 login 后第 2 次 login 被 lockout.check 拦截。
    #[tokio::test]
    async fn login_with_lockout_failure_triggers_lockout() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let lockout = Arc::new(UserLockoutStrategy::new(
            crate::account::lockout::UserLockoutConfig {
                max_failure_factor: 1,
                permanent_lockout: false,
                max_temporary_lockouts: 99,
                wait_strategy: crate::account::lockout::WaitStrategy::Linear { base_seconds: 300 },
                failure_window_seconds: 300,
            },
            dao,
        ));
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, Some(lockout));
        let flow = FlowBuilder::new("test").login("password").build();
        let builder_fail = MockCredentialBuilder {
            password_verify_result: false,
            totp_verify_result: false,
        };
        let builder_ok = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };

        let mut ctx1 = make_context("alice", "wrong");
        let r1 = executor
            .execute_with_builder(&flow, &mut ctx1, &builder_fail)
            .await
            .unwrap();
        assert!(
            matches!(r1, AuthResult::Failed { ref reason, .. } if reason.contains("凭证校验失败")),
            "第 1 次尝试应为凭证校验失败: {:?}",
            r1
        );

        let mut ctx2 = make_context("alice", "correct");
        let r2 = executor
            .execute_with_builder(&flow, &mut ctx2, &builder_ok)
            .await
            .unwrap();
        match r2 {
            AuthResult::Failed { reason, step } => {
                assert!(
                    reason.contains("锁定"),
                    "reason 应含锁定（record_failure 已触发锁定）: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!(
                "应为 Failed（record_failure 触发锁定，第 2 次 login 被拦截），实际: {:?}",
                other
            ),
        }
    }

    /// SubFlow 步骤 — 子流程返回 Pending → 父流程 Failed（"子流程 X 返回 Pending"）。
    /// 子流程含 2 步（Login + Mfa(None)），ctx.extras 设 pause_after_step="0"
    /// 使子流程 Login 成功后返回 Pending。验证不支持嵌套 Pending 传播。
    #[tokio::test]
    async fn subflow_pending_propagates_as_failed() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let repo = make_repo_with_password("alice").await;
        let mut registry = FlowRegistry::from_inventory();
        let child = FlowBuilder::new("child-with-pause")
            .login("password")
            .mfa(None)
            .build();
        registry.register(child);
        let executor = make_executor_with_registry(repo, Arc::new(registry));
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("parent")
            .sub_flow("child-with-pause")
            .build();
        let mut ctx = make_context("alice", "correct-password");
        ctx.extras
            .insert("pause_after_step".to_string(), "0".to_string());

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(
                    reason.contains("子流程")
                        || reason.contains("failing-child")
                        || reason.contains("authflow-required-action-not-implemented"),
                    "reason 应含子流程: {}",
                    reason
                );
                assert!(
                    reason.contains("child-with-pause"),
                    "reason 应含子流程名称: {}",
                    reason
                );
                assert!(
                    reason.contains("Pending"),
                    "reason 应含 Pending: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!(
                "应为 Failed（子流程 Pending 传播为 Failed），实际: {:?}",
                other
            ),
        }
    }

    /// SubFlow 步骤 — 子流程返回 ChallengeRequired → 父流程 ChallengeRequired。
    /// 子流程含 Mfa(Some("totp"))，ctx.input 为空 → ChallengeRequired。
    #[tokio::test]
    async fn subflow_challenge_required_propagates() {
        let repo = make_repo_with_password_and_totp("alice").await;
        let mut registry = FlowRegistry::from_inventory();
        let child = FlowBuilder::new("child-challenge")
            .mfa(Some("totp"))
            .build();
        registry.register(child);
        let executor = make_executor_with_registry(repo, Arc::new(registry));
        let builder = MockCredentialBuilder {
            password_verify_result: false,
            totp_verify_result: true,
        };
        let flow = FlowBuilder::new("parent")
            .sub_flow("child-challenge")
            .build();
        let mut ctx = make_context("alice", ""); // 空输入 → ChallengeRequired

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
            other => panic!(
                "应为 ChallengeRequired（子流程 ChallengeRequired 传播），实际: {:?}",
                other
            ),
        }
    }

    /// Conditional 步骤 — HasCredential 条件且 ctx.user_id=None → 返回 false → else_step=None → Success。
    /// 覆盖 evaluate_condition 的 HasCredential 分支中 user_id=None 的路径。
    #[tokio::test]
    async fn conditional_has_credential_without_user_id_returns_false() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let flow = FlowBuilder::new("test")
            .conditional(
                AuthCondition::HasCredential("password".to_string()),
                // if_step（不会执行）
                AuthStep::RequiredAction {
                    action: "x".to_string(),
                },
                // else_step=None → 跳过视为成功
                None,
            )
            .build();
        let mut ctx = make_context("alice", "");
        ctx.user_id = None;

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Success { login_id, .. } => {
                assert_eq!(login_id, "", "user_id=None 时 login_id 应为空串");
            },
            other => panic!(
                "应为 Success（HasCredential user_id=None → false → 跳过），实际: {:?}",
                other
            ),
        }
    }

    /// Conditional 步骤 — IsLocked 条件且 lockout=None → 返回 false → else_step=None → Success。
    /// 覆盖 evaluate_condition 的 IsLocked 分支中 lockout=None 的路径。
    #[tokio::test]
    async fn conditional_is_locked_without_lockout_returns_false() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None); // lockout=None
        let flow = FlowBuilder::new("test")
            .conditional(
                AuthCondition::IsLocked,
                AuthStep::RequiredAction {
                    action: "x".to_string(),
                },
                None,
            )
            .build();
        let mut ctx = make_context("alice", "");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Success { .. } => {},
            other => panic!(
                "应为 Success（IsLocked lockout=None → false → 跳过），实际: {:?}",
                other
            ),
        }
    }

    /// Conditional 步骤 — IsLocked 条件且 lockout=Some 但 ctx.user_id=None → 返回 false。
    /// 覆盖 evaluate_condition 的 IsLocked 分支中 user_id=None 的路径。
    #[tokio::test]
    async fn conditional_is_locked_without_user_id_returns_false() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
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
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, Some(lockout));
        let flow = FlowBuilder::new("test")
            .conditional(
                AuthCondition::IsLocked,
                AuthStep::RequiredAction {
                    action: "x".to_string(),
                },
                None,
            )
            .build();
        let mut ctx = make_context("alice", "");
        ctx.user_id = None;

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Success { .. } => {},
            other => panic!(
                "应为 Success（IsLocked user_id=None → false → 跳过），实际: {:?}",
                other
            ),
        }
    }

    /// pause_after_step — 验证 step_challenge 对 Mfa(Some("totp")) 的输出格式。
    /// Login 成功后暂停，下一步为 Mfa(Some("totp")) → challenge 应含 "请输入 totp 验证码"。
    #[tokio::test]
    async fn pause_after_step_challenge_for_mfa_some_step() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("two-step")
            .login("password")
            .mfa(Some("totp"))
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
                challenge,
                next_step,
                ..
            } => {
                assert_eq!(next_step, 1);
                assert!(
                    challenge.contains("totp"),
                    "challenge 应含 totp: {}",
                    challenge
                );
                assert!(
                    challenge.contains("验证码"),
                    "challenge 应含验证码: {}",
                    challenge
                );
            },
            other => panic!("应为 Pending，实际: {:?}", other),
        }
    }

    /// pause_after_step — 验证 step_challenge 对 Mfa(None) 的输出格式。
    /// Login 成功后暂停，下一步为 Mfa(None) → challenge 应为 "请完成 MFA 校验"。
    #[tokio::test]
    async fn pause_after_step_challenge_for_mfa_none_step() {
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("two-step")
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
            AuthResult::Pending { challenge, .. } => {
                assert!(
                    challenge.contains("MFA"),
                    "challenge 应含 MFA: {}",
                    challenge
                );
            },
            other => panic!("应为 Pending，实际: {:?}", other),
        }
    }

    /// pause_after_step — 验证 step_challenge 对 RequiredAction 的输出格式。
    #[tokio::test]
    async fn pause_after_step_challenge_for_required_action_step() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = AuthenticationFlow {
            name: "two-step".to_string(),
            steps: vec![
                AuthStep::Login {
                    credential_type: "password".to_string(),
                },
                AuthStep::RequiredAction {
                    action: "verify_email".to_string(),
                },
            ],
            allow_skip: false,
        };
        let mut ctx = make_context("alice", "correct-password");
        ctx.extras
            .insert("pause_after_step".to_string(), "0".to_string());

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Pending { challenge, .. } => {
                assert!(
                    challenge.contains("verify_email"),
                    "challenge 应含 action 名: {}",
                    challenge
                );
                assert!(
                    challenge.contains("必需动作"),
                    "challenge 应含必需动作: {}",
                    challenge
                );
            },
            other => panic!("应为 Pending，实际: {:?}", other),
        }
    }

    /// pause_after_step — 验证 step_challenge 对 Conditional 的输出格式。
    #[tokio::test]
    async fn pause_after_step_challenge_for_conditional_step() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = AuthenticationFlow {
            name: "two-step".to_string(),
            steps: vec![
                AuthStep::Login {
                    credential_type: "password".to_string(),
                },
                AuthStep::Conditional {
                    condition: AuthCondition::IpWhitelisted,
                    if_step: Box::new(AuthStep::RequiredAction {
                        action: "x".to_string(),
                    }),
                    else_step: None,
                },
            ],
            allow_skip: false,
        };
        let mut ctx = make_context("alice", "correct-password");
        ctx.extras
            .insert("pause_after_step".to_string(), "0".to_string());

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Pending { challenge, .. } => {
                assert!(
                    challenge.contains("条件分支"),
                    "challenge 应含条件分支: {}",
                    challenge
                );
            },
            other => panic!("应为 Pending，实际: {:?}", other),
        }
    }

    /// pause_after_step — 验证 step_challenge 对 SubFlow 的输出格式。
    #[tokio::test]
    async fn pause_after_step_challenge_for_subflow_step() {
        // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
        let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let repo = make_repo_with_password("alice").await;
        let mut registry = FlowRegistry::from_inventory();
        let child = FlowBuilder::new("child-flow").login("password").build();
        registry.register(child);
        let executor = make_executor_with_registry(repo, Arc::new(registry));
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = AuthenticationFlow {
            name: "two-step".to_string(),
            steps: vec![
                AuthStep::Login {
                    credential_type: "password".to_string(),
                },
                AuthStep::SubFlow {
                    flow_name: "child-flow".to_string(),
                },
            ],
            allow_skip: false,
        };
        let mut ctx = make_context("alice", "correct-password");
        ctx.extras
            .insert("pause_after_step".to_string(), "0".to_string());

        let result = executor
            .execute_with_builder(&flow, &mut ctx, &builder)
            .await
            .unwrap();

        match result {
            AuthResult::Pending { challenge, .. } => {
                assert!(
                    challenge.contains("child-flow"),
                    "challenge 应含子流程名: {}",
                    challenge
                );
                assert!(
                    challenge.contains("子流程"),
                    "challenge 应含子流程: {}",
                    challenge
                );
            },
            other => panic!("应为 Pending，实际: {:?}", other),
        }
    }

    /// pause_after_step 值非数字 → parse 失败 → 不触发暂停 → 全部步骤完成 → Success。
    #[tokio::test]
    async fn pause_after_step_invalid_value_does_not_pause() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let flow = AuthenticationFlow {
            name: "two-conditional".to_string(),
            steps: vec![
                AuthStep::Conditional {
                    condition: AuthCondition::IpWhitelisted,
                    if_step: Box::new(AuthStep::RequiredAction {
                        action: "x".to_string(),
                    }),
                    else_step: None,
                },
                AuthStep::Conditional {
                    condition: AuthCondition::IpWhitelisted,
                    if_step: Box::new(AuthStep::RequiredAction {
                        action: "y".to_string(),
                    }),
                    else_step: None,
                },
            ],
            allow_skip: false,
        };
        let mut ctx = make_context("alice", "");
        ctx.extras
            .insert("pause_after_step".to_string(), "abc".to_string());

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Success { .. } => {
                assert_eq!(
                    ctx.completed_steps.len(),
                    2,
                    "应完成 2 个步骤（无效 pause 值不触发暂停）"
                );
            },
            other => panic!("应为 Success（无效 pause 值不触发暂停），实际: {:?}", other),
        }
    }

    /// pause_after_step 值越界（99，无对应步骤索引）→ 不触发暂停 → Success。
    #[tokio::test]
    async fn pause_after_step_out_of_range_index_does_not_pause() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let flow = AuthenticationFlow {
            name: "two-conditional".to_string(),
            steps: vec![
                AuthStep::Conditional {
                    condition: AuthCondition::IpWhitelisted,
                    if_step: Box::new(AuthStep::RequiredAction {
                        action: "x".to_string(),
                    }),
                    else_step: None,
                },
                AuthStep::Conditional {
                    condition: AuthCondition::IpWhitelisted,
                    if_step: Box::new(AuthStep::RequiredAction {
                        action: "y".to_string(),
                    }),
                    else_step: None,
                },
            ],
            allow_skip: false,
        };
        let mut ctx = make_context("alice", "");
        ctx.extras
            .insert("pause_after_step".to_string(), "99".to_string());

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Success { .. } => {
                assert_eq!(
                    ctx.completed_steps.len(),
                    2,
                    "应完成 2 个步骤（pause 索引越界不触发暂停）"
                );
            },
            other => panic!(
                "应为 Success（pause 索引越界不触发暂停），实际: {:?}",
                other
            ),
        }
    }

    /// 空步骤流程且 ctx.user_id=None → Success（login_id 为空串）。
    /// 覆盖 execute_inner 中 `ctx.user_id.clone().unwrap_or_default()` 的 None 分支。
    #[tokio::test]
    async fn empty_flow_without_user_id_returns_success_with_empty_login_id() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let flow = FlowBuilder::new("empty").build();
        let mut ctx = make_context("alice", "");
        ctx.user_id = None;

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Success { login_id, token } => {
                assert_eq!(login_id, "", "user_id=None 时 login_id 应为空串");
                assert_eq!(token, "", "空流程 token 应为空");
            },
            other => panic!("应为 Success，实际: {:?}", other),
        }
    }

    /// SsoServer 步骤 — execute()（无 resolver）→ Failed（"需要 SsoServerResolver"）。
    /// 覆盖 execute_sso 中 sso_resolver=None 的分支（非 门控路径）。
    #[tokio::test]
    async fn sso_step_without_resolver_returns_failed() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let flow = FlowBuilder::new("sso-flow").sso("keycloak").build();
        let mut ctx = make_context("alice", "ticket_abc");

        let result = executor.execute(&flow, &mut ctx).await.unwrap();

        match result {
            AuthResult::Failed { reason, step } => {
                assert!(
                    reason.contains("SsoServerResolver"),
                    "reason 应含 SsoServerResolver: {}",
                    reason
                );
                assert_eq!(step, 0);
            },
            other => panic!("应为 Failed（无 SSO resolver），实际: {:?}", other),
        }
    }

    /// execute_with_metrics — Login 步骤成功 → 记录 authflow_execute_duration + credential_verify_duration。
    /// 覆盖 execute_with_metrics 方法及 execute_inner / execute_login 中的 metrics 观测分支。
    #[cfg(feature = "metrics-prometheus")]
    #[tokio::test]
    async fn execute_with_metrics_records_durations() {
        let registry = prometheus::Registry::new();
        let metrics = crate::account::metrics::AccountMetrics::register_to(&registry).unwrap();
        let repo = make_repo_with_password("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: true,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("metrics-test").login("password").build();
        let mut ctx = make_context("alice", "correct-password");

        let result = executor
            .execute_with_metrics(&flow, &mut ctx, &builder, &metrics)
            .await
            .unwrap();

        match result {
            AuthResult::Success { login_id, .. } => {
                assert_eq!(login_id, "alice");
            },
            other => panic!("应为 Success，实际: {:?}", other),
        }
        let gathered = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            gathered.contains("garrison_authflow_execute_duration_seconds"),
            "应记录 authflow_execute_duration: {}",
            gathered
        );
        assert!(
            gathered.contains("garrison_credential_verify_duration_seconds"),
            "应记录 credential_verify_duration: {}",
            gathered
        );
    }

    /// execute_with_metrics — Mfa(Some("totp")) 步骤成功 → 记录 credential_verify_duration（label=totp）。
    /// 覆盖 execute_mfa 中的 metrics 观测分支。
    #[cfg(feature = "metrics-prometheus")]
    #[tokio::test]
    async fn execute_with_metrics_records_mfa_verify_duration() {
        let registry = prometheus::Registry::new();
        let metrics = crate::account::metrics::AccountMetrics::register_to(&registry).unwrap();
        let repo = make_repo_with_password_and_totp("alice").await;
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: false,
            totp_verify_result: true,
        };
        let flow = FlowBuilder::new("mfa-metrics").mfa(Some("totp")).build();
        let mut ctx = make_context("alice", "123456");

        let result = executor
            .execute_with_metrics(&flow, &mut ctx, &builder, &metrics)
            .await
            .unwrap();

        match result {
            AuthResult::Success { .. } => {},
            other => panic!("应为 Success，实际: {:?}", other),
        }
        let gathered = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            gathered.contains("garrison_credential_verify_duration_seconds"),
            "应记录 credential_verify_duration: {}",
            gathered
        );
        assert!(gathered.contains("totp"), "应记录 totp 标签: {}", gathered);
    }

    /// execute_with_metrics — 空流程 → 记录 authflow_execute_duration（空流程提前返回路径）。
    #[cfg(feature = "metrics-prometheus")]
    #[tokio::test]
    async fn execute_with_metrics_empty_flow_records_duration() {
        let registry = prometheus::Registry::new();
        let metrics = crate::account::metrics::AccountMetrics::register_to(&registry).unwrap();
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let builder = MockCredentialBuilder {
            password_verify_result: false,
            totp_verify_result: false,
        };
        let flow = FlowBuilder::new("empty-metrics").build();
        let mut ctx = make_context("alice", "");

        let result = executor
            .execute_with_metrics(&flow, &mut ctx, &builder, &metrics)
            .await
            .unwrap();

        match result {
            AuthResult::Success { login_id, .. } => {
                assert_eq!(login_id, "alice");
            },
            other => panic!("应为 Success，实际: {:?}", other),
        }
        let gathered = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            gathered.contains("garrison_authflow_execute_duration_seconds"),
            "空流程也应记录 authflow_execute_duration: {}",
            gathered
        );
    }

    // SocialProvider + SsoServer 步骤测试：子模块仅在 `social-wechat` + `protocol-sso-server` 同时启用时编译
    //（测试命令 `cargo test --features "account-authflow social-wechat protocol-sso-server cache-memory"`）；
    // mock resolver 内部持有 mock provider / server，证明 executor 经 resolver 委托调用 exchange_token / validate_ticket。

    #[cfg(all(feature = "social-wechat", feature = "protocol-sso-server"))]
    mod t017 {
        use super::*;
        use crate::error::GarrisonError;
        use crate::protocol::social::{provider_names, SocialLoginProvider, SocialUserInfo};
        use crate::protocol::sso::SsoServer;
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Mock 类型

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
            ) -> GarrisonResult<String> {
                Ok("https://example.com/auth".to_string())
            }

            async fn exchange_token(
                &self,
                _code: &str,
                _state: &str,
            ) -> GarrisonResult<SocialUserInfo> {
                self.exchange_count.fetch_add(1, Ordering::SeqCst);
                if self.fail_exchange {
                    return Err(GarrisonError::Internal(
                        "mock exchange_token 失败".to_string(),
                    ));
                }
                Ok(SocialUserInfo {
                    provider: provider_names::WECHAT.to_string(),
                    provider_user_id: self.provider_user_id.clone(),
                    nickname: None,
                    avatar: None,
                    union_id: None,
                    raw: serde_json::json!({}),
                })
            }

            async fn get_user_info(&self, _access_token: &str) -> GarrisonResult<SocialUserInfo> {
                Ok(SocialUserInfo {
                    provider: provider_names::WECHAT.to_string(),
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
            ) -> GarrisonResult<String> {
                let p = self.providers.get(provider).ok_or_else(|| {
                    GarrisonError::InvalidParam(format!("unknown social provider: {}", provider))
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
            ) -> GarrisonResult<String> {
                Ok("mock-ticket".to_string())
            }

            async fn validate_ticket(
                &self,
                _ticket: &str,
                _client_id: i64,
            ) -> GarrisonResult<String> {
                self.validate_count.fetch_add(1, Ordering::SeqCst);
                if self.fail_validate {
                    return Err(GarrisonError::InvalidToken(
                        "mock validate_ticket 失败".to_string(),
                    ));
                }
                Ok(self.login_id.clone())
            }

            async fn destroy_ticket(&self, _ticket: &str) -> GarrisonResult<()> {
                Ok(())
            }

            async fn push_message(&self, _login_id: &str, _message: &str) -> GarrisonResult<()> {
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
            ) -> GarrisonResult<String> {
                let s = self.servers.get(server_id).ok_or_else(|| {
                    GarrisonError::InvalidParam(format!("unknown sso server: {}", server_id))
                })?;
                s.validate_ticket(ticket, client_id).await
            }
        }

        // 辅助函数

        /// 构造空凭证 repo 的 executor（不依赖凭证，但 make_executor 需要 repo）。
        fn make_t017_executor() -> AuthExecutor {
            let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
            make_executor(repo, None)
        }

        /// 占位 CredentialBuilder（流程不含 Login，但 execute_with_full 需要传 builder）。
        fn dummy_builder() -> MockCredentialBuilder {
            MockCredentialBuilder {
                password_verify_result: false,
                totp_verify_result: false,
            }
        }

        /// SocialProvider 步骤 — exchange_token 成功 → Success。
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
            assert_eq!(wechat.exchange_count(), 1, "exchange_token 应被调用 1 次");
        }

        /// SocialProvider 步骤 — provider 未注册 → Failed。
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

        /// SocialProvider 步骤 — ctx.input 为空 → ChallengeRequired。
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

        /// 多 Provider 切换 — wechat 与 alipay 分别返回不同 login_id。
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

        /// SsoServer 步骤 — validate_ticket 成功 → Success。
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

        /// SsoServer 步骤 — validate_ticket 失败 → Failed。
        #[tokio::test]
        async fn t017_sso_login_invalid_ticket_returns_failed() {
            // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
            let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
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

        /// SsoServer 步骤 — ctx.input 为空 → ChallengeRequired。
        #[tokio::test]
        async fn t017_sso_login_empty_input_challenge_required() {
            // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
            let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
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

        /// SocialProvider + SsoServer 组合流程 — 两步均成功。
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

        /// SocialProvider 步骤 — execute_with_builder 无 resolver → Failed。
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

        /// pause_after_step — 验证 step_challenge 对 SocialProvider 的输出格式。
        /// Login 成功后暂停，下一步为 SocialProvider("wechat") → challenge 应含 "请完成 wechat 社交登录"。
        #[tokio::test]
        async fn t017_pause_after_step_challenge_for_social_step() {
            // 钉住 locale：断言依赖中文模板文案（默认语言为英文，guard 随测试作用域恢复）
            let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
            let repo = make_repo_with_password("alice").await;
            let executor = make_executor(repo, None);
            let builder = MockCredentialBuilder {
                password_verify_result: true,
                totp_verify_result: false,
            };
            // 2 步流程：Login + SocialProvider
            let flow = FlowBuilder::new("two-step")
                .login("password")
                .social("wechat")
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
                    challenge,
                    next_step,
                    ..
                } => {
                    assert_eq!(next_step, 1);
                    assert!(
                        challenge.contains("wechat"),
                        "challenge 应含 wechat: {}",
                        challenge
                    );
                    assert!(
                        challenge.contains("社交登录"),
                        "challenge 应含社交登录: {}",
                        challenge
                    );
                },
                other => panic!("应为 Pending，实际: {:?}", other),
            }
        }

        /// pause_after_step — 验证 step_challenge 对 SsoServer 的输出格式。
        /// Login 成功后暂停，下一步为 SsoServer("keycloak") → challenge 应含 "请完成 SSO 登录: keycloak"。
        #[tokio::test]
        async fn t017_pause_after_step_challenge_for_sso_step() {
            let repo = make_repo_with_password("alice").await;
            let executor = make_executor(repo, None);
            let builder = MockCredentialBuilder {
                password_verify_result: true,
                totp_verify_result: false,
            };
            let flow = FlowBuilder::new("two-step")
                .login("password")
                .sso("keycloak")
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
                    challenge,
                    next_step,
                    ..
                } => {
                    assert_eq!(next_step, 1);
                    assert!(
                        challenge.contains("keycloak"),
                        "challenge 应含 keycloak: {}",
                        challenge
                    );
                    assert!(
                        challenge.contains("SSO"),
                        "challenge 应含 SSO: {}",
                        challenge
                    );
                },
                other => panic!("应为 Pending，实际: {:?}", other),
            }
        }

        /// SsoServer 步骤 — ctx.extras 中无 client_id → 默认 0 → 仍可成功。
        /// 覆盖 execute_sso 中 client_id 缺失时 unwrap_or(0) 的默认分支。
        #[tokio::test]
        async fn t017_sso_login_missing_client_id_uses_zero() {
            let server = Arc::new(MockSsoServer::new("1001"));
            let server_ref = server.clone() as Arc<dyn SsoServer>;
            let mut sso_resolver = MockSsoServerResolver::new();
            sso_resolver.register("keycloak", server_ref);
            let social_resolver = MockSocialProviderResolver::new();
            let executor = make_t017_executor();
            let builder = dummy_builder();
            let flow = FlowBuilder::new("sso-flow").sso("keycloak").build();
            let mut ctx = make_context("", "ticket_abc");
            // 不设置 client_id → 默认 0

            let result = executor
                .execute_with_full(&flow, &mut ctx, &builder, &social_resolver, &sso_resolver)
                .await
                .unwrap();

            match result {
                AuthResult::Success { login_id, .. } => {
                    assert_eq!(login_id, "1001");
                },
                other => panic!("应为 Success（缺失 client_id 默认 0），实际: {:?}", other),
            }
            assert_eq!(server.validate_count(), 1, "validate_ticket 应被调用 1 次");
        }

        /// SsoServer 步骤 — ctx.extras["client_id"] 非数字 → parse 失败 → 默认 0 → 仍可成功。
        /// 覆盖 execute_sso 中 client_id 解析失败时 unwrap_or(0) 的默认分支。
        #[tokio::test]
        async fn t017_sso_login_invalid_client_id_uses_zero() {
            let server = Arc::new(MockSsoServer::new("1001"));
            let server_ref = server.clone() as Arc<dyn SsoServer>;
            let mut sso_resolver = MockSsoServerResolver::new();
            sso_resolver.register("keycloak", server_ref);
            let social_resolver = MockSocialProviderResolver::new();
            let executor = make_t017_executor();
            let builder = dummy_builder();
            let flow = FlowBuilder::new("sso-flow").sso("keycloak").build();
            let mut ctx = make_context("", "ticket_abc");
            // 非数字 client_id → parse 失败 → 默认 0
            ctx.extras
                .insert("client_id".to_string(), "not-a-number".to_string());

            let result = executor
                .execute_with_full(&flow, &mut ctx, &builder, &social_resolver, &sso_resolver)
                .await
                .unwrap();

            match result {
                AuthResult::Success { login_id, .. } => {
                    assert_eq!(login_id, "1001");
                },
                other => panic!("应为 Success（无效 client_id 回退为 0），实际: {:?}", other),
            }
            assert_eq!(server.validate_count(), 1, "validate_ticket 应被调用 1 次");
        }

        /// SocialProvider 步骤 — ctx.extras 中无 state → 默认空串 → 仍可成功。
        /// 覆盖 execute_social 中 state 缺失时 unwrap_or_default() 的默认分支。
        #[tokio::test]
        async fn t017_social_login_without_state_succeeds() {
            let wechat = Arc::new(MockSocialLoginProvider::new("wx_user"));
            let wechat_ref = wechat.clone() as Arc<dyn SocialLoginProvider>;
            let mut social_resolver = MockSocialProviderResolver::new();
            social_resolver.register("wechat", wechat_ref);
            let executor = make_t017_executor();
            let builder = dummy_builder();
            let sso_resolver = MockSsoServerResolver::new();
            let flow = FlowBuilder::new("wechat-flow").social("wechat").build();
            let mut ctx = make_context("", "auth_code");
            // 不设置 state → 默认空串

            let result = executor
                .execute_with_full(&flow, &mut ctx, &builder, &social_resolver, &sso_resolver)
                .await
                .unwrap();

            match result {
                AuthResult::Success { login_id, .. } => {
                    assert_eq!(login_id, "wx_user");
                },
                other => panic!("应为 Success（无 state 仍可执行），实际: {:?}", other),
            }
            assert_eq!(wechat.exchange_count(), 1, "exchange_token 应被调用 1 次");
        }

        /// SsoServer 步骤 — execute_with_builder 无 sso_resolver → Failed。
        /// 覆盖 execute_with_builder 路径中 SsoServer 步骤的占位失败信息。
        #[tokio::test]
        async fn t017_sso_step_without_resolver_returns_failed() {
            let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
            let executor = make_executor(repo, None);
            let builder = dummy_builder();
            let flow = FlowBuilder::new("sso-flow").sso("keycloak").build();
            let mut ctx = make_context("", "ticket_abc");
            ctx.extras
                .insert("client_id".to_string(), "2001".to_string());

            let result = executor
                .execute_with_builder(&flow, &mut ctx, &builder)
                .await
                .unwrap();

            match result {
                AuthResult::Failed { reason, step } => {
                    assert!(
                        reason.contains("SsoServerResolver"),
                        "reason 应含 SsoServerResolver: {}",
                        reason
                    );
                    assert_eq!(step, 0);
                },
                other => panic!("应为 Failed（无 SSO resolver），实际: {:?}", other),
            }
        }
    }

    // 覆盖率补充：mock 方法调用 + AuthExecutor 未覆盖方法

    /// 调用所有 mock 方法以覆盖 async_trait 生成的 async wrapper。
    #[tokio::test]
    async fn mock_methods_coverage_credential_repo_interface_credential() {
        let repo = MockCredentialRepository::default();
        repo.create(make_credential_model("c1", "u1", "password"))
            .await
            .unwrap();
        let mut model = make_credential_model("c1", "u1", "password");
        model.secret_data = "new_hash".to_string();
        repo.update("u1", model).await.unwrap();
        repo.delete("u1", "c1").await.unwrap();

        let iface = MockInterface;
        let _ = iface.get_permission_list("u1").await.unwrap();
        let _ = iface.get_role_list("u1").await.unwrap();
        // 默认委托方法
        let _ = iface
            .get_permission_list_with_type("u1", "user")
            .await
            .unwrap();
        let _ = iface.get_role_list_with_type("u1", "admin").await.unwrap();

        let cred = MockCredential {
            verify_result: true,
        };
        let _ = cred.credential_type();
        let _ = cred.to_model();
    }

    /// `execute_social` 无 SocialProvider resolver 时返回 Failed。
    #[tokio::test]
    async fn execute_social_without_resolver_returns_failed() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let mut ctx = make_context("", "oauth_code");
        let result = executor
            .execute_social("wechat", &mut ctx, None)
            .await
            .unwrap();
        match result {
            StepOutcome::Failed(_) => {},
            other => panic!("应为 Failed，实际: {:?}", other),
        }
    }

    /// `execute_sso` 无 SsoServer resolver 时返回 Failed。
    #[tokio::test]
    async fn execute_sso_without_resolver_returns_failed() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(MockCredentialRepository::default());
        let executor = make_executor(repo, None);
        let mut ctx = make_context("", "ticket_abc");
        let result = executor
            .execute_sso("keycloak", &mut ctx, None)
            .await
            .unwrap();
        match result {
            StepOutcome::Failed(_) => {},
            other => panic!("应为 Failed，实际: {:?}", other),
        }
    }
}
