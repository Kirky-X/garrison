//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! AuthenticationFlow DSL 子模块（吸收 keycloak AuthenticationFlow）。
//! 提供声明式认证流程编排，覆盖登录 + MFA + 社交登录 + SSO 全认证流程。
//! 详见 spec `auth-flow-dsl`。
//!
//! # 核心类型（T013）
//!
//! - [`AuthStep`](crate::account::authflow::AuthStep)：认证步骤 enum（7 变体：Login/Mfa/SocialProvider/SsoServer/RequiredAction/Conditional/SubFlow）
//! - [`AuthCondition`](crate::account::authflow::AuthCondition)：条件分支 enum（4 变体：HasCredential/IsLocked/IpWhitelisted/Custom）
//! - [`AuthenticationFlow`](crate::account::authflow::AuthenticationFlow)：认证流程定义（name + steps + allow_skip）
//! - [`AuthContext`](crate::account::authflow::AuthContext)：执行上下文（input + user_id + tenant_id + ip + completed_steps + extras）
//! - [`AuthResult`](crate::account::authflow::AuthResult)：执行结果 enum（4 变体：Success/Failed/Pending/ChallengeRequired)
//!
//! # 子模块
//!
//! - [`builder`](crate::account::authflow::builder): FlowBuilder 流式构建 DSL（T014）
//! - [`registry`](crate::account::authflow::registry): FlowRegistry inventory 注册（T015）
//! - [`executor`](crate::account::authflow::executor): AuthExecutor 执行器（T016/T017）
//! - [`builtin`](crate::account::authflow::builtin): 内置 AuthenticationFlow（T018）

pub mod builder;
pub mod builtin;
pub mod executor;
pub mod registry;

// 模块重导出：通过 mod 路径访问子模块类型（避免外部代码引用具体文件路径）
pub use builder::FlowBuilder;
pub use registry::{FlowRegistration, FlowRegistry};

use std::collections::HashMap;

use crate::error::{GarrisonError, GarrisonResult};

/// 认证步骤 enum，定义流程中的 7 种步骤类型。
///
/// 使用 enum 而非 trait object（决策 D3），保证可序列化与编译期穷尽匹配。
#[derive(Debug, Clone)]
pub enum AuthStep {
    /// 密码登录，调用 `Credential::verify`。
    Login {
        /// 凭证类型（如 "password"）。
        credential_type: String,
    },
    /// MFA 校验，调用 `MfaLogic::check_safe` 或 `Credential::verify` for TOTP。
    Mfa {
        /// 凭证类型（None 表示由执行器自动选择，Some("totp") 指定 TOTP）。
        credential_type: Option<String>,
    },
    /// 社交登录，调用 `SocialProvider::authorize`。
    SocialProvider {
        /// Provider 名称（如 "wechat"/"alipay"/"keycloak"）。
        provider: String,
    },
    /// SSO 登录，调用 `SsoServer::issue_ticket`。
    SsoServer {
        /// SSO 服务器标识。
        server_id: String,
    },
    /// 必需动作（v0.6 仅占位，v0.6.5 实现）。
    RequiredAction {
        /// 动作标识。
        action: String,
    },
    /// 条件分支，根据 `condition` 评估结果执行 `if_step` 或 `else_step`。
    Conditional {
        /// 条件判断。
        condition: AuthCondition,
        /// 条件为真时执行的步骤。
        if_step: Box<AuthStep>,
        /// 条件为假时执行的步骤（None 表示跳过）。
        else_step: Option<Box<AuthStep>>,
    },
    /// 子流程引用，从 `FlowRegistry` 查询并递归执行。
    SubFlow {
        /// 引用的流程名称。
        flow_name: String,
    },
}

/// 认证条件 enum，用于 `AuthStep::Conditional` 的条件判断
#[derive(Debug, Clone)]
pub enum AuthCondition {
    /// 用户已注册特定凭证类型（参数为 credential_type）。
    HasCredential(String),
    /// 用户处于锁定状态。
    IsLocked,
    /// 请求来源 IP 在白名单（经 [`AuthExecutor::with_ip_whitelist`] 注入，
    /// 未注入时恒为 false）。
    IpWhitelisted,
    /// 自定义条件（求值器经 [`AuthExecutor::with_custom_evaluator`] 运行期注册；
    /// 未注册的条件名将返回显性错误而非静默 false）。
    Custom(String),
}

/// IP 白名单（CIDR 列表），用于 [`AuthCondition::IpWhitelisted`] 的真实求值。
///
/// 支持 IPv4/IPv6 CIDR（如 `10.0.0.0/8`、`2001:db8::/32`）；
/// 单个 IP 视作 /32（v4）或 /128（v6）。
#[derive(Debug, Clone, Default)]
pub struct IpWhitelist {
    cidrs: Vec<ipnetwork::IpNetwork>,
}

impl IpWhitelist {
    /// 从 CIDR/IP 字符串列表构造；任一解析失败返回 [`GarrisonError::InvalidParam`]。
    pub fn parse(items: &[String]) -> GarrisonResult<Self> {
        let mut cidrs = Vec::with_capacity(items.len());
        for item in items {
            let net = ipnetwork::IpNetwork::try_from(item.trim()).map_err(|e| {
                GarrisonError::InvalidParam(format!("ip-whitelist-parse-failed::{item}::{e}"))
            })?;
            cidrs.push(net);
        }
        Ok(Self { cidrs })
    }

    /// 判断 IP 是否命中任一 CIDR。
    pub fn contains(&self, ip: &str) -> bool {
        match ip.parse::<std::net::IpAddr>() {
            Ok(addr) => self.cidrs.iter().any(|net| net.contains(addr)),
            Err(_) => false,
        }
    }

    /// 白名单是否为空。
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }
}

/// 自定义认证条件求值器（[`AuthCondition::Custom`] 的运行期扩展点）。
///
/// 实现方注册到 [`AuthExecutor::with_custom_evaluator`]；求值失败按 `?` 传播。
#[async_trait::async_trait]
pub trait CustomConditionEvaluator: Send + Sync {
    /// 对给定上下文求值（true = 走 if_step）。
    async fn evaluate(&self, ctx: &AuthContext) -> GarrisonResult<bool>;
}

/// 认证流程定义。
///
/// 含有序步骤列表，由 `FlowBuilder` 构造，`AuthExecutor` 执行。
#[derive(Debug, Clone)]
pub struct AuthenticationFlow {
    /// 流程名称（唯一标识，用于 `FlowRegistry` 查询与 `SubFlow` 引用）。
    pub name: String,
    /// 有序步骤列表（按顺序执行）。
    pub steps: Vec<AuthStep>,
    /// 是否允许步骤跳过（false 时每步必须通过，true 时允许跳过失败步骤）。
    pub allow_skip: bool,
}

/// 执行上下文，携带认证过程的状态与输入。
///
/// 作为 `AuthExecutor::execute` 的可变引用参数，执行过程中更新 `completed_steps`。
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// 用户输入（密码/TOTP code/社交 authorization_code 等）。
    pub input: String,
    /// 用户 ID（社交登录首步可能无 user_id）。
    pub user_id: Option<String>,
    /// 租户 ID。
    pub tenant_id: Option<String>,
    /// 请求来源 IP。
    pub ip: String,
    /// 已完成步骤索引列表。
    pub completed_steps: Vec<usize>,
    /// 扩展数据（社交登录 state/redirect_uri 等）。
    pub extras: HashMap<String, String>,
}

/// 认证执行结果。
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// 认证成功。
    Success {
        /// 登录 ID（用户标识）。
        login_id: String,
        /// 会话 token。
        token: String,
    },
    /// 认证失败。
    Failed {
        /// 失败原因。
        reason: String,
        /// 失败步骤索引。
        step: usize,
    },
    /// 等待用户输入（多步认证中间状态）。
    Pending {
        /// 已完成步骤索引。
        completed_step: usize,
        /// 下一步骤索引。
        next_step: usize,
        /// 挑战信息（提示用户输入下一步所需的凭证）。
        challenge: String,
    },
    /// 需要挑战（如验证码/二次验证）。
    ChallengeRequired {
        /// 挑战类型（如 "captcha"/"otp"）。
        challenge_type: String,
        /// 挑战消息。
        message: String,
    },
}

#[cfg(test)]
mod tests;
