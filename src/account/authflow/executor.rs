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
//! # 核心类型
//!
//! - [`CredentialBuilder`]：凭证构造 trait（`CredentialModel → Box<dyn Credential>`）
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
// AuthExecutor（依据 spec R-auth-flow-dsl-008）
// ============================================================================

/// 认证流程执行器（依据 spec auth-flow-dsl R-auth-flow-dsl-008）。
///
/// 按 [`AuthenticationFlow`] 步骤顺序执行认证逻辑，支持 Login / Mfa / Conditional / SubFlow
/// 四种步骤类型（SocialProvider / SsoServer / RequiredAction 待 T017）。
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

    /// 执行认证流程（spec R-009 签名，无 CredentialBuilder）。
    ///
    /// 遇到 Login / Mfa(Some) 步骤时返回 `Failed`（无 builder 无法构造 Credential）。
    /// Mfa(None) / Conditional / SubFlow 步骤可正常执行。
    ///
    /// 完整 Login 支持请使用 [`execute_with_builder`](Self::execute_with_builder)。
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
        self.execute_inner(flow, ctx, None).await
    }

    /// 执行认证流程（带 CredentialBuilder，支持 Login 步骤）。
    ///
    /// Login 步骤通过 `builder` 将 `CredentialModel` 转换为 `dyn Credential` 后调用 `verify`。
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
        self.execute_inner(flow, ctx, Some(builder)).await
    }

    /// 执行认证流程核心逻辑（内部方法）。
    ///
    /// `builder` 为 `None` 时 Login / Mfa(Some) 步骤返回 `Failed`。
    async fn execute_inner(
        &self,
        flow: &AuthenticationFlow,
        ctx: &mut AuthContext,
        builder: Option<&dyn CredentialBuilder>,
    ) -> BulwarkResult<AuthResult> {
        // 空流程：直接返回 Success（无步骤可失败）
        if flow.steps.is_empty() {
            return Ok(AuthResult::Success {
                login_id: ctx.user_id.clone().unwrap_or_default(),
                token: String::new(),
            });
        }

        let mut token: Option<String> = None;

        for (index, step) in flow.steps.iter().enumerate() {
            let outcome = self.execute_step(step, ctx, builder).await?;

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
                            return Ok(AuthResult::Pending {
                                completed_step: index,
                                next_step: index + 1,
                                challenge,
                            });
                        }
                    }
                },
                StepOutcome::Failed(reason) => {
                    if flow.allow_skip {
                        continue;
                    }
                    return Ok(AuthResult::Failed {
                        reason,
                        step: index,
                    });
                },
                StepOutcome::ChallengeRequired {
                    challenge_type,
                    message,
                } => {
                    return Ok(AuthResult::ChallengeRequired {
                        challenge_type,
                        message,
                    });
                },
            }
        }

        // 全部步骤通过
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
    ) -> Pin<Box<dyn Future<Output = BulwarkResult<StepOutcome>> + Send + 'a>> {
        Box::pin(async move {
            match step {
                AuthStep::Login { credential_type } => {
                    self.execute_login(credential_type, ctx, builder).await
                },
                AuthStep::Mfa { credential_type } => {
                    self.execute_mfa(credential_type.as_ref(), ctx, builder)
                        .await
                },
                AuthStep::Conditional {
                    condition,
                    if_step,
                    else_step,
                } => {
                    let condition_result = self.evaluate_condition(condition, ctx).await?;
                    if condition_result {
                        self.execute_step(if_step, ctx, builder).await
                    } else if let Some(else_step) = else_step {
                        self.execute_step(else_step, ctx, builder).await
                    } else {
                        // else_step 为 None 时跳过（视为成功）
                        Ok(StepOutcome::Success { token: None })
                    }
                },
                AuthStep::SubFlow { flow_name } => {
                    self.execute_subflow(flow_name, ctx, builder).await
                },
                AuthStep::SocialProvider { .. } => Ok(StepOutcome::Failed(
                    "SocialProvider 步骤在 v0.6.0 未实现，待 T017".to_string(),
                )),
                AuthStep::SsoServer { .. } => Ok(StepOutcome::Failed(
                    "SsoServer 步骤在 v0.6.0 未实现，待 T017".to_string(),
                )),
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
    ) -> BulwarkResult<StepOutcome> {
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
        let verified = cred.verify(&ctx.input).await?;

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
    ) -> BulwarkResult<StepOutcome> {
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
                let verified = cred.verify(&ctx.input).await?;

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
    ) -> BulwarkResult<StepOutcome> {
        let sub_flow = match self.registry.get(flow_name) {
            Some(f) => f,
            None => {
                return Ok(StepOutcome::Failed(format!("未找到子流程: {}", flow_name)));
            },
        };

        // TODO: v0.6.5 添加循环引用检测（当前递归无深度限制）
        let result = self.execute_inner(sub_flow, ctx, builder).await?;

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
}
