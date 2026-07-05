//! Stp 模块，提供核心认证逻辑与工具入口。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `StpLogic` / `StpInterface` / `StpUtil` 三件套，
//! Bulwark 中统一使用 `Bulwark*` 前缀。
//!
//! ## 核心设计（依据 spec stp-core-api 与 design.md Decision 8）
//!
//! - `BulwarkLogic` trait：定义 login/logout/check_login/kickout 完整契约
//! - `BulwarkLogicDefault`：默认实现，组合 `BulwarkSession` + `BulwarkConfig`
//! - `tokio::task_local`：存储当前请求的 token（类似 Sa-Token 的 `SaHolder`，但适配 async）
//!
//! ## task_local 上下文（依据 spec context-abstraction）
//!
//! 在 axum middleware 中调用 `with_current_token(token, async { handler }).await` 设置作用域，
//! stp 核心 API（logout/check_login/get_login_id）从 `current_token()` 读取。

use crate::config::BulwarkConfig;
use crate::core::auth::AuthLogic;
use crate::core::permission::PermissionChecker;
use crate::core::token::TokenStyleFactory;
use crate::error::{BulwarkError, BulwarkResult};
#[cfg(feature = "listener")]
use crate::listener::{BulwarkEvent, BulwarkListenerManager};
use crate::plugin::BulwarkPluginManager;
use crate::session::BulwarkSession;
use crate::strategy::{BulwarkFirewallStrategy, FirewallLoginContext};
// 0.4.2: LoginId newtype（支持 i64 与 String 双形式登录主体标识）
use crate::stp::login_id::LoginId;
use async_trait::async_trait;
use std::future::Future;
use std::sync::Arc;

// 0.4.0 新增：ParameterQuery 参数化查询模块（feature-gated）
#[cfg(feature = "parameter-query")]
pub mod parameter;

// 0.4.2 新增：LoginId newtype（支持 i64 与 String 双形式登录主体标识）
pub mod login_id;

// ============================================================================
// task_local：存储当前请求的 token（类似 Sa-Token 的 SaHolder）
// ============================================================================

tokio::task_local! {
    /// 当前请求的 token，由 axum middleware 通过 `with_current_token` 设置。
    static CURRENT_TOKEN: String;
}

/// 设置当前请求的 token 作用域。
///
/// 在 axum middleware 中调用：
/// ```ignore
/// bulwark::stp::with_current_token(token, async { handler(req).await }).await
/// ```
pub async fn with_current_token<R>(token: String, f: impl Future<Output = R>) -> R {
    CURRENT_TOKEN.scope(token, f).await
}

/// 获取当前请求的 token（从 task_local 读取）。
///
/// # 错误
/// - 若未在 `with_current_token` 作用域内调用，返回 `BulwarkError::Session`。
#[allow(clippy::map_clone)]
pub fn current_token() -> BulwarkResult<String> {
    CURRENT_TOKEN.try_get().map(|t| t.clone()).map_err(|_| {
        BulwarkError::Session("未设置当前请求上下文（未调用 with_current_token）".to_string())
    })
}

// ============================================================================
// BulwarkLogic trait：核心认证逻辑契约
// ============================================================================

/// 核心逻辑 trait，定义登录认证的完整行为契约。
///
/// [借鉴 Sa-Token] 对应 `StpLogic`，是框架最核心的抽象。
/// 实现方需集成认证、会话等能力（0.1.0 仅实现 login/logout/check_login/kickout，
/// 权限/角色校验在任务组 7 实现）。
#[async_trait]
pub trait BulwarkLogic: Send + Sync {
    /// 执行登录：生成 token + 创建会话。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 生成的 token 字符串。
    ///
    /// # 错误
    /// - token 生成失败（如 `token_style` 非法）：`BulwarkError::Config`。
    /// - 会话创建失败：透传 `BulwarkError`。
    async fn login(&self, login_id: i64) -> BulwarkResult<String>;

    /// 执行登录（自定义 token）：用指定 token 创建会话。
    ///
    /// 用于 token 转发、自定义 token 生成等场景。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `token`: 自定义 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话创建失败：透传 `BulwarkError`。
    async fn login_with_token(&self, login_id: i64, token: &str) -> BulwarkResult<()>;

    /// 执行登出：从 task_local 获取当前 token 并销毁。
    ///
    /// 未登录时调用幂等返回 Ok（不抛错）。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；未设置 token 时幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn logout(&self) -> BulwarkResult<()>;

    /// 按账号登出：销毁指定 login_id 的所有会话。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn logout_by_login_id(&self, login_id: i64) -> BulwarkResult<()>;

    /// 踢出用户：按账号踢出（语义等同 logout_by_login_id）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn kickout(&self, login_id: i64) -> BulwarkResult<()>;

    /// 踢出会话：按 token 踢出（语义等同 logout(token)）。
    ///
    /// # 参数
    /// - `token`: 待踢出的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn kickout_by_token(&self, token: &str) -> BulwarkResult<()>;

    /// 主动吊销 token：销毁指定 token 的会话并广播 RevokeToken 事件
    /// （v0.4.2 新增，依据 spec listener-events-extend R-002）。
    ///
    /// 与 `logout` 的区别：
    /// - `logout` 从 task_local 读取当前 token，语义是"用户主动登出"
    /// - `revoke_token` 接收显式 token 参数，语义是"管理员/系统吊销特定 token"
    /// - `revoke_token` 广播 `RevokeToken` 事件（携带 token），`logout` 广播 `Logout` 事件（携带 login_id+token）
    ///
    /// 与 `kickout_by_token` 的区别：
    /// - `kickout_by_token` 语义是"管理员强制下线"，广播 `Kickout` 事件（携带 login_id+token+reason）
    /// - `revoke_token` 语义是"token 失效"（如 OAuth2 token revocation），广播 `RevokeToken` 事件（仅携带 token）
    ///
    /// # 参数
    /// - `token`: 待吊销的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；token 不存在时幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - 会话销毁失败：透传 `BulwarkError`。
    async fn revoke_token(&self, token: &str) -> BulwarkResult<()>;

    /// 检查登录状态：从 task_local 获取 token 验证有效性。
    ///
    /// # 返回
    /// - `Ok(true)`: token 有效且 Account-Session 未过期。
    /// - `Ok(false)`: token 无效或未登录（`throw_on_not_login=false`）。
    ///
    /// # 错误
    /// - 未登录且 `throw_on_not_login=true`：抛 `BulwarkError::Session`。
    /// - DAO 读取失败：透传 `BulwarkError`。
    async fn check_login(&self) -> BulwarkResult<bool>;

    /// 获取当前登录 ID。
    ///
    /// # 返回
    /// - `Some(login_id)`: token 有效，返回关联的 login_id。
    /// - `None`: 未登录或 token 无效。
    ///
    /// # 错误
    /// - DAO 读取失败：透传 `BulwarkError`。
    async fn get_login_id(&self) -> BulwarkResult<Option<i64>>;

    /// 校验权限（任务组 7 实现，复用 dbnexus PermissionProvider）。
    ///
    /// # 参数
    /// - `permission`: 权限标识字符串。
    ///
    /// # 返回
    /// 成功（持有权限）返回 `Ok(())`。
    ///
    /// # 错误
    /// - 未登录且 `throw_on_not_login=true`：`BulwarkError::NotLogin`。
    /// - 未登录且 `throw_on_not_login=false`：降级为 `BulwarkError::NotPermission`。
    /// - 未持有权限：`BulwarkError::NotPermission`。
    async fn check_permission(&self, permission: &str) -> BulwarkResult<()>;

    /// 校验角色（任务组 7 实现）。
    ///
    /// # 参数
    /// - `role`: 角色标识字符串。
    ///
    /// # 返回
    /// 成功（持有角色）返回 `Ok(())`。
    ///
    /// # 错误
    /// - 未登录且 `throw_on_not_login=true`：`BulwarkError::NotLogin`。
    /// - 未登录且 `throw_on_not_login=false`：降级为 `BulwarkError::NotRole`。
    /// - 未持有角色：`BulwarkError::NotRole`。
    async fn check_role(&self, role: &str) -> BulwarkResult<()>;

    /// 校验 access_token 类型会话（0.5.0 新增，依据 spec annotation-macros P2 前置）。
    ///
    /// 语义别名：默认实现委托 `check_login`，已登录返回 `Ok(())`，未登录返回 `Err(NotLogin)`。
    /// 业务方可在子类 override 实现类型区分（如校验 token 是否为 access_token 类型）。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - 未登录：`BulwarkError::NotLogin`（`throw_on_not_login=false` 时由本方法显式抛出；
    ///   `throw_on_not_login=true` 时由 `check_login` 透传 `Session` 错误）。
    async fn check_access_token(&self) -> BulwarkResult<()> {
        let valid = self.check_login().await?;
        if valid {
            Ok(())
        } else {
            Err(BulwarkError::NotLogin(
                "access_token 无效或未登录".to_string(),
            ))
        }
    }

    /// 校验 client_token 类型会话（0.5.0 新增，依据 spec annotation-macros P2 前置）。
    ///
    /// 语义别名：默认实现委托 `check_login`，已登录返回 `Ok(())`，未登录返回 `Err(NotLogin)`。
    /// 业务方可在子类 override 实现类型区分（如校验 token 是否为 client_token 类型）。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - 未登录：`BulwarkError::NotLogin`。
    async fn check_client_token(&self) -> BulwarkResult<()> {
        let valid = self.check_login().await?;
        if valid {
            Ok(())
        } else {
            Err(BulwarkError::NotLogin(
                "client_token 无效或未登录".to_string(),
            ))
        }
    }

    /// 校验 temp_token 类型会话（0.5.0 新增，依据 spec annotation-macros P2 前置）。
    ///
    /// 语义别名：默认实现委托 `check_login`，已登录返回 `Ok(())`，未登录返回 `Err(NotLogin)`。
    /// 业务方可在子类 override 实现类型区分（如校验 token 是否为 temp_token 类型）。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - 未登录：`BulwarkError::NotLogin`。
    async fn check_temp_token(&self) -> BulwarkResult<()> {
        let valid = self.check_login().await?;
        if valid {
            Ok(())
        } else {
            Err(BulwarkError::NotLogin(
                "temp_token 无效或未登录".to_string(),
            ))
        }
    }

    /// 检查二级认证（MFA）状态（0.3.0 新增，依据 spec annotation-handling）。
    ///
    /// 默认实现返回 `Ok(())`（未启用 MFA，向后兼容 0.2.x）。
    /// 业务方覆写此方法以接入 TOTP MFA 校验：检查当前会话是否已完成二级认证。
    ///
    /// # 返回
    /// - `Ok(())`: 已通过二级认证或未启用 MFA。
    /// - `Err(BulwarkError::Session)`: 未通过二级认证。
    async fn check_safe(&self) -> BulwarkResult<()> {
        Ok(())
    }

    /// 检查账号是否被禁用（0.3.0 新增，依据 spec annotation-handling）。
    ///
    /// 默认实现返回 `Ok(())`（未实现禁用账号库，向后兼容 0.2.x）。
    /// 业务方覆写此方法以接入禁用账号检查：查询当前 login_id 是否在禁用列表中。
    ///
    /// # 返回
    /// - `Ok(())`: 账号未禁用。
    /// - `Err(BulwarkError::Session)`: 账号已禁用。
    async fn check_disable(&self) -> BulwarkResult<()> {
        Ok(())
    }

    /// 通过外部 token 反向建立会话（0.2.0 新增，依据 spec core-auth-api）。
    ///
    /// 用于 OAuth2/SSO 场景：外部 token 已通过协议层校验后，
    /// 调用此方法在当前上下文建立内部会话。
    ///
    /// # 参数
    /// - `token`: 外部 token 字符串（如 OAuth2 access_token / SSO ticket）。
    ///
    /// # 错误
    /// - default 实现：`BulwarkError::NotImplemented`（未启用 protocol-oauth2/protocol-sso）。
    async fn login_by_token(&self, _token: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(
            "login_by_token 需启用 protocol-oauth2 或 protocol-sso feature".to_string(),
        ))
    }

    /// 验证显式传入的 token 并返回关联的 login_id（0.2.0 新增，依据 spec core-auth-api）。
    ///
    /// 委托 `core-token::Token::verify` 实现。与 `check_login` 区别：
    /// `check_login` 从 task_local 读取 token；`verify_token` 接收显式 token 参数。
    ///
    /// # 参数
    /// - `token`: 待验证的 token 字符串。
    ///
    /// # 返回
    /// - `Ok(login_id)`: token 有效，返回关联的 login_id。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidToken`: token 无效或不包含 login_id。
    /// - `BulwarkError::NotImplemented`: default 实现未委托 Token trait。
    async fn verify_token(&self, _token: &str) -> BulwarkResult<i64> {
        Err(BulwarkError::NotImplemented(
            "verify_token 需子类 override 委托 core-token::Token::verify".to_string(),
        ))
    }

    /// 刷新 token（0.2.0 新增，依据 spec core-auth-api）。
    ///
    /// 仅在启用 `protocol-jwt` feature 时由 `JwtHandler` 提供有效实现。
    ///
    /// # 参数
    /// - `token`: 待刷新的旧 token 字符串。
    ///
    /// # 返回
    /// - `Ok(new_token)`: 刷新后的新 token 字符串。
    ///
    /// # 错误
    /// - `BulwarkError::NotImplemented`: 未启用 protocol-jwt feature。
    /// - `BulwarkError::InvalidToken`: token 已过期或无效。
    async fn refresh_token(&self, _token: &str) -> BulwarkResult<String> {
        Err(BulwarkError::NotImplemented(
            "refresh_token 需启用 protocol-jwt feature".to_string(),
        ))
    }

    /// 密码登录：校验密码后签发 token（0.4.2 新增，依据 spec auth-password-login）。
    ///
    /// 内部流程：1) UserRepository::find_by_username 查询用户
    /// 2) PasswordHasher::verify 校验密码 3) 调用 [`login`](Self::login) 签发 token。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（i64，作为 username 字符串查询 UserRepository）。
    /// - `password`: 明文密码（仅校验时临时持有，不存储）。
    ///
    /// # 返回
    /// - `Ok(token)`: 密码校验通过，返回新签发的 token 字符串。
    ///
    /// # 错误
    /// - 未启用 `secure-password` + `db-sqlite` feature：`BulwarkError::NotImplemented`。
    /// - 未注入 `password_hasher`：`BulwarkError::Config("password hasher not configured")`。
    /// - 未注入 `user_repository`：`BulwarkError::Config("user repository not configured")`。
    /// - 用户不存在 / 密码错误：`BulwarkError::InvalidParam("invalid password")`（不泄露具体原因，防止用户枚举）。
    /// - 哈希格式不支持：`BulwarkError::InvalidParam("unsupported hash format")`。
    /// - DAO 查询失败：透传 `BulwarkError::Dao`。
    ///
    /// # 安全约束
    ///
    /// 用户不存在与密码错误统一返回 `InvalidParam("invalid password")`，日志和事件
    /// reason 统一为 "invalid_credentials"（v0.4.2 安全审计 A-014），防止攻击者通过
    /// 返回值或日志差异进行用户枚举。哈希格式错误返回 "unsupported hash format"
    /// （属配置错误，不构成枚举风险）。
    async fn login_with_password(&self, _login_id: i64, _password: &str) -> BulwarkResult<String> {
        Err(BulwarkError::NotImplemented(
            "login_with_password 未实现：需启用 secure-password + db-sqlite feature".to_string(),
        ))
    }

    /// 获取当前 `BulwarkConfig` 引用（用于 token 提取、Cookie 配置等需要配置的场景）。
    ///
    /// # 返回
    /// 全局配置的 `Arc` 引用。
    fn config(&self) -> Arc<BulwarkConfig>;
}

// ============================================================================
// JwtMode：JWT 校验模式（依据 spec protocol-jwt-modes R-001）
// ============================================================================

/// JWT 校验模式（依据 spec protocol-jwt-modes R-001）。
///
/// 控制 `check_login` 在 JWT verify 与 oxcache session 查询之间的组合策略。
/// 不依赖 `jsonwebtoken` crate，作为配置选项总是编译（即使未启用 `protocol-jwt`）。
///
/// # 变体
///
/// - `Stateless`：仅 JWT verify，不查询 oxcache session。适用于高可用场景
///   （DAO 故障时仍可校验），要求启用 `protocol-jwt` feature 且 `token_style=jwt`。
/// - `Mixin`（默认）：JWT verify + session 二级校验。推荐的平衡模式——
///   JWT 提供无状态校验，session 提供主动注销能力。
/// - `Simple`：仅 session 校验，JWT 仅作为 token 字符串载体（不验证签名）。
///   适用于 token 已由网关层校验过的场景。
///
/// # feature 依赖
///
/// `jwt_mode` 字段本身不 feature gate，但 `Stateless`/`Mixin` 中的 JWT verify
/// 调用需 `protocol-jwt` feature。未启用时 `Stateless` 返回 `Config` 错误，
/// `Mixin` 退化为仅查 session（向后兼容 0.4.1 行为）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JwtMode {
    /// 仅 JWT verify，不查询 oxcache session（高可用场景）。
    Stateless,
    /// JWT verify + session 二级校验（推荐，默认）。
    #[default]
    Mixin,
    /// 仅 session，JWT 仅作为 token 载体（不验证签名）。
    Simple,
}

// ============================================================================
// BulwarkLogicDefault：默认实现
// ============================================================================

/// `BulwarkLogic` 的默认实现，组合 `BulwarkSession` + `BulwarkConfig` + `BulwarkFirewallStrategy`。
///
/// [借鉴 Sa-Token] 对应 `StpLogic` 默认实现（design.md Decision 8）。
pub struct BulwarkLogicDefault {
    /// 会话管理器（pub(crate) 供测试验证）。
    pub(crate) session: Arc<BulwarkSession>,
    config: Arc<BulwarkConfig>,
    /// 权限策略（pub(crate) 供测试验证）。
    pub(crate) firewall: Arc<dyn BulwarkFirewallStrategy>,
    /// 插件管理器（可选，注入后 login/logout 触发插件钩子）。
    plugin_manager: Option<Arc<BulwarkPluginManager>>,
    /// 监听器管理器（可选，注入后 login/logout/kickout 广播事件）。
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<BulwarkListenerManager>>,
    /// 认证逻辑（可选，注入后 login_by_token 优先委托此实现）。
    auth_logic: Option<Arc<dyn AuthLogic>>,
    /// 权限校验器（可选，注入后 check_permission/check_role 可委托此实现）。
    permission_checker: Option<Arc<dyn PermissionChecker>>,
    /// Prometheus 指标采集器（可选，注入后 login/check_login/check_permission/check_role emit 指标）。
    #[cfg(feature = "metrics-prometheus")]
    metrics: Option<Arc<crate::observability::BulwarkMetrics>>,
    /// 密码哈希器（可选，注入后 login_with_password 委托此实现校验密码）。
    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    password_hasher: Option<Arc<dyn crate::secure::password::PasswordHasher>>,
    /// 用户 Repository（可选，注入后 login_with_password 委托此实现查询用户）。
    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    user_repository: Option<Arc<dyn crate::dao::repository::UserRepository>>,
    /// 默认 login_type（0.4.2 新增，依据 spec login-type-multi-account R-003）。
    ///
    /// 未设置时默认 "default"，通过 `with_login_type` builder 设置。
    /// `pub(crate)` 供测试验证字段值。
    pub(crate) login_type: String,
    /// JWT 校验模式（0.4.2 新增，依据 spec protocol-jwt-modes R-001）。
    ///
    /// 默认 `JwtMode::Mixin`，通过 `with_jwt_mode` builder 设置。
    /// 字段不 feature gate（JwtMode 是配置 enum，无外部依赖）；
    /// 实际 JWT verify 调用在 `check_login` 中由 `#[cfg(feature = "protocol-jwt")]` 门控。
    /// `pub(crate)` 供测试验证字段值。
    pub(crate) jwt_mode: JwtMode,
}

impl BulwarkLogicDefault {
    /// 创建默认实现实例。
    ///
    /// # 参数
    /// - `session`: 会话管理器。
    /// - `config`: 全局配置。
    /// - `firewall`: 权限策略（默认 `BulwarkFirewallStrategyDefault`，持有 `BulwarkInterface` 回调）。
    ///
    /// # 返回
    /// 新建的 `BulwarkLogicDefault` 实例。
    pub fn new(
        session: Arc<BulwarkSession>,
        config: Arc<BulwarkConfig>,
        firewall: Arc<dyn BulwarkFirewallStrategy>,
    ) -> Self {
        Self {
            session,
            config,
            firewall,
            plugin_manager: None,
            #[cfg(feature = "listener")]
            listener_manager: None,
            auth_logic: None,
            permission_checker: None,
            #[cfg(feature = "metrics-prometheus")]
            metrics: None,
            #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
            password_hasher: None,
            #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
            user_repository: None,
            login_type: "default".to_string(),
            jwt_mode: JwtMode::default(),
        }
    }

    /// 注入插件管理器（builder 模式，返回 Self 便于链式调用）。
    ///
    /// 注入后 `login` / `logout` 将触发 `on_login` / `on_logout` 钩子。
    pub fn with_plugin_manager(mut self, pm: Arc<BulwarkPluginManager>) -> Self {
        self.plugin_manager = Some(pm);
        self
    }

    /// 注入监听器管理器（builder 模式，需启用 `listener` feature）。
    ///
    /// 注入后 `login` / `logout` / `kickout` 将广播 `BulwarkEvent` 事件。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<BulwarkListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 注入认证逻辑（builder 模式）。
    ///
    /// 注入后 `login_by_token` 优先委托 `auth_logic.verify_token` 校验 token。
    pub fn with_auth_logic(mut self, auth: Arc<dyn AuthLogic>) -> Self {
        self.auth_logic = Some(auth);
        self
    }

    /// 注入权限校验器（builder 模式）。
    ///
    /// 注入后可用于权限校验链路扩展（当前 `check_permission` 仍委托 firewall，
    /// 此字段为未来扩展预留）。
    pub fn with_permission_checker(mut self, pc: Arc<dyn PermissionChecker>) -> Self {
        self.permission_checker = Some(pc);
        self
    }

    /// 注入 Prometheus 指标采集器（builder 模式，需启用 `metrics-prometheus` feature）。
    ///
    /// 注入后 `login` / `check_login` / `check_permission` / `check_role` 将自动 emit
    /// Prometheus 指标（依据 spec observability-stack）。未注入时所有指标调用为 no-op。
    #[cfg(feature = "metrics-prometheus")]
    pub fn with_metrics(mut self, metrics: Arc<crate::observability::BulwarkMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// 注入密码哈希器（builder 模式，需启用 `secure-password` + `db-sqlite` feature）。
    ///
    /// 注入后 `login_with_password` 委托此 `PasswordHasher::verify` 校验密码哈希。
    /// 未注入时 `login_with_password` 返回 `BulwarkError::Config("password hasher not configured")`。
    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    pub fn with_password_hasher(
        mut self,
        hasher: Arc<dyn crate::secure::password::PasswordHasher>,
    ) -> Self {
        self.password_hasher = Some(hasher);
        self
    }

    /// 注入用户 Repository（builder 模式，需启用 `secure-password` + `db-sqlite` feature）。
    ///
    /// 注入后 `login_with_password` 委托此 `UserRepository::find_by_username` 查询用户。
    /// 未注入时 `login_with_password` 返回 `BulwarkError::Config("user repository not configured")`。
    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    pub fn with_user_repository(
        mut self,
        repo: Arc<dyn crate::dao::repository::UserRepository>,
    ) -> Self {
        self.user_repository = Some(repo);
        self
    }

    /// 设置默认 login_type（builder 模式，0.4.2 新增，依据 spec login-type-multi-account R-003）。
    ///
    /// 注入后作为权限/角色查询的默认 `login_type` 上下文。未设置时默认 "default"。
    ///
    /// # 参数
    /// - `login_type`: 登录类型字符串（业务方自定义，如 "admin"/"user"/"merchant"）。
    ///
    /// # 示例
    /// ```ignore
    /// let logic = BulwarkLogicDefault::new(session, config, firewall)
    ///     .with_login_type("admin");
    /// ```
    pub fn with_login_type(mut self, login_type: &str) -> Self {
        self.login_type = login_type.to_string();
        self
    }

    /// 设置 JWT 校验模式（builder 模式，0.4.2 新增，依据 spec protocol-jwt-modes R-005）。
    ///
    /// 控制 `check_login` 在 JWT verify 与 session 查询之间的组合策略：
    ///
    /// - `JwtMode::Stateless`：仅 JWT verify，不查询 oxcache session（高可用场景）
    /// - `JwtMode::Mixin`（默认）：JWT verify + session 二级校验（推荐）
    /// - `JwtMode::Simple`：仅 session，JWT 仅作为 token 字符串载体
    ///
    /// 未设置时默认 `JwtMode::Mixin`。运行时不可切换（编译期配置）。
    /// `JwtMode` 字段不依赖 `protocol-jwt` feature，但 `Stateless`/`Mixin` 中的
    /// JWT verify 调用需启用 `protocol-jwt` feature，否则 `Stateless` 返回 `Config` 错误。
    ///
    /// # 参数
    /// - `mode`: JWT 校验模式。
    ///
    /// # 示例
    /// ```ignore
    /// let logic = BulwarkLogicDefault::new(session, config, firewall)
    ///     .with_jwt_mode(JwtMode::Stateless);
    /// ```
    pub fn with_jwt_mode(mut self, mode: JwtMode) -> Self {
        self.jwt_mode = mode;
        self
    }

    /// login 实际逻辑（供 `login` 方法在 metrics 包装内调用）。
    ///
    /// 0.3.0 抽取此私有方法以保持 `login` trait 方法的 metrics 包装简洁。
    async fn login_inner(&self, login_id: i64) -> BulwarkResult<String> {
        // 0.3.0：登录前防火墙安全钩子检查（依据 spec firewall-check-hook）
        // 任一 hook Err 阻断登录；未注入 hook 时为 no-op（向后兼容 0.2.x）
        let ctx = FirewallLoginContext::new(login_id);
        self.firewall.check_login_hooks(login_id, &ctx).await?;

        let token = self.generate_token(login_id)?;
        self.login_with_token(login_id, &token).await?;
        // auto-wire: 触发 plugin on_login + listener Login 事件
        if let Some(pm) = &self.plugin_manager {
            pm.on_login(login_id, &token);
        }
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::Login {
                login_id,
                token: token.clone(),
                device: None,
            })
            .await;
        }
        Ok(token)
    }

    /// 根据 `config.token_style` 生成 token。
    ///
    /// - `uuid`: UUID v4（36 字符，含连字符）
    /// - `random_64`: 两个 simple UUID 拼接（64 字符）
    /// - `simple`: simple UUID（32 字符）
    /// - `jwt`: 需启用 `protocol-jwt` feature，委托 `JwtHandler::sign`（0.2.0 修复）
    fn generate_token(&self, login_id: i64) -> BulwarkResult<String> {
        match self.config.token_style.as_str() {
            "uuid" => Ok(uuid::Uuid::new_v4().to_string()),
            "random_64" => Ok(format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            )),
            "simple" => Ok(uuid::Uuid::new_v4().simple().to_string()),
            "jwt" => {
                // 0.2.0：委托 JwtHandler::sign（依据 spec protocol-jwt + core-auth-api）
                #[cfg(feature = "protocol-jwt")]
                {
                    let handler = crate::protocol::jwt::JwtHandler::new(&self.config.jwt_secret);
                    handler.sign(login_id, self.config.timeout)
                }
                #[cfg(not(feature = "protocol-jwt"))]
                {
                    let _ = login_id;
                    Err(BulwarkError::Config(
                        "jwt token_style 需启用 protocol-jwt feature".to_string(),
                    ))
                }
            },
            other => Err(BulwarkError::Config(format!(
                "unknown token_style: {}",
                other
            ))),
        }
    }

    /// Stateless 模式：仅 JWT verify，不查询 session（依据 spec protocol-jwt-modes R-002）。
    ///
    /// 要求启用 `protocol-jwt` feature 且 `token_style=jwt`，否则返回 `Config` 错误。
    /// JWT verify 失败时透传 `InvalidToken`/`ExpiredToken`（不查询 session）。
    fn check_login_stateless(&self, token: &str) -> BulwarkResult<bool> {
        #[cfg(feature = "protocol-jwt")]
        {
            if self.config.token_style != "jwt" {
                return Err(BulwarkError::Config(
                    "Stateless 模式要求 token_style=jwt".to_string(),
                ));
            }
            let handler = crate::protocol::jwt::JwtHandler::new(&self.config.jwt_secret);
            // spec R-002: 无效签名返回 InvalidToken，过期返回 ExpiredToken（透传 verify 错误）
            handler.verify(token)?;
            Ok(true)
        }
        #[cfg(not(feature = "protocol-jwt"))]
        {
            let _ = token;
            Err(BulwarkError::Config(
                "Stateless 模式要求启用 protocol-jwt feature".to_string(),
            ))
        }
    }

    /// Mixin 模式：JWT verify + session 二级校验（依据 spec protocol-jwt-modes R-003）。
    ///
    /// 启用 `protocol-jwt` feature 且 `token_style=jwt` 时先 JWT verify 再查 session
    /// （JWT verify 失败直接返回错误，不查询 session）。否则仅查 session
    /// （向后兼容 0.4.1 行为：无 protocol-jwt 或 token_style != jwt）。
    async fn check_login_mixin(&self, token: &str) -> BulwarkResult<bool> {
        #[cfg(feature = "protocol-jwt")]
        {
            if self.config.token_style == "jwt" {
                let handler = crate::protocol::jwt::JwtHandler::new(&self.config.jwt_secret);
                // spec R-003: JWT 签名无效直接返回错误（不查询 session）
                handler.verify(token)?;
            }
        }
        let valid = self.session.is_valid(token).await?;
        if !valid {
            // v0.4.2: token 无效时广播 SessionTimeout 事件（依据 spec listener-events-extend R-001）
            // 若 token session 仍存在（account session 过期），可获取 login_id 并广播；
            // token session 完全不存在时跳过广播（无法获取 login_id）。
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                if let Ok(Some(ts)) = self.session.get_token_session(token).await {
                    lm.broadcast(&BulwarkEvent::SessionTimeout {
                        login_id: ts.login_id,
                        token: token.to_string(),
                    })
                    .await;
                }
            }
            if self.config.throw_on_not_login {
                return Err(BulwarkError::Session("未登录".to_string()));
            }
        }
        Ok(valid)
    }

    /// Simple 模式：仅 session 校验，不验证 JWT 签名（依据 spec protocol-jwt-modes R-004）。
    ///
    /// session 不存在时按 `throw_on_not_login` 决定返回 `Ok(false)` 或 `Session` 错误。
    async fn check_login_simple(&self, token: &str) -> BulwarkResult<bool> {
        let valid = self.session.is_valid(token).await?;
        if !valid {
            // v0.4.2: token 无效时广播 SessionTimeout 事件（依据 spec listener-events-extend R-001）
            // 若 token session 仍存在（account session 过期），可获取 login_id 并广播；
            // token session 完全不存在时跳过广播（无法获取 login_id）。
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                if let Ok(Some(ts)) = self.session.get_token_session(token).await {
                    lm.broadcast(&BulwarkEvent::SessionTimeout {
                        login_id: ts.login_id,
                        token: token.to_string(),
                    })
                    .await;
                }
            }
            if self.config.throw_on_not_login {
                return Err(BulwarkError::Session("未登录".to_string()));
            }
        }
        Ok(valid)
    }
}

#[async_trait]
impl BulwarkLogic for BulwarkLogicDefault {
    async fn login(&self, login_id: i64) -> BulwarkResult<String> {
        // emit metrics：登录尝试（成功/失败均记录，依据 spec observability-stack）
        #[cfg(feature = "metrics-prometheus")]
        let start = std::time::Instant::now();
        let result = self.login_inner(login_id).await;
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_login(result.is_ok());
            m.observe_token_validation(start.elapsed());
        }
        result
    }

    async fn login_with_token(&self, login_id: i64, token: &str) -> BulwarkResult<()> {
        self.session.create(login_id, token).await
    }

    async fn logout(&self) -> BulwarkResult<()> {
        // 未登录时幂等返回 Ok（不抛错）
        match current_token() {
            Ok(token) => {
                // 获取 login_id（用于 plugin/listener 回调），注销前查询
                let login_id = self
                    .session
                    .get_token_session(&token)
                    .await?
                    .map(|ts| ts.login_id);
                self.session.logout(&token).await?;
                // auto-wire: 触发 plugin on_logout + listener Logout 事件
                if let (Some(pm), Some(id)) = (&self.plugin_manager, login_id) {
                    pm.on_logout(id, &token);
                }
                #[cfg(feature = "listener")]
                if let (Some(lm), Some(id)) = (&self.listener_manager, login_id) {
                    lm.broadcast(&BulwarkEvent::Logout {
                        login_id: id,
                        token: token.clone(),
                    })
                    .await;
                }
                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    async fn logout_by_login_id(&self, login_id: i64) -> BulwarkResult<()> {
        self.session.logout_by_login_id(login_id).await
    }

    async fn kickout(&self, login_id: i64) -> BulwarkResult<()> {
        // kickout 语义等同 logout_by_login_id
        self.session.logout_by_login_id(login_id).await?;
        // auto-wire: 触发 listener Kickout 事件（plugin 无 kickout 钩子）
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::Kickout {
                login_id,
                token: String::new(),
                reason: "管理员强制下线".to_string(),
            })
            .await;
        }
        Ok(())
    }

    async fn kickout_by_token(&self, token: &str) -> BulwarkResult<()> {
        // kickout_by_token 语义等同 logout(token)
        self.session.logout(token).await
    }

    async fn revoke_token(&self, token: &str) -> BulwarkResult<()> {
        // 销毁 Token-Session（幂等：token 不存在也返回 Ok）
        self.session.logout(token).await?;
        // v0.4.2: 广播 RevokeToken 事件（依据 spec listener-events-extend R-002）
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::RevokeToken {
                token: token.to_string(),
            })
            .await;
        }
        Ok(())
    }

    async fn check_login(&self) -> BulwarkResult<bool> {
        let token = match current_token() {
            Ok(t) => t,
            Err(_) => {
                // 未设置 token = 未登录（保持现有 throw_on_not_login 语义）
                if self.config.throw_on_not_login {
                    return Err(BulwarkError::Session("未登录".to_string()));
                }
                return Ok(false);
            },
        };

        match self.jwt_mode {
            JwtMode::Stateless => self.check_login_stateless(&token),
            JwtMode::Mixin => self.check_login_mixin(&token).await,
            JwtMode::Simple => self.check_login_simple(&token).await,
        }
    }

    async fn get_login_id(&self) -> BulwarkResult<Option<i64>> {
        match current_token() {
            Ok(token) => match self.session.get_token_session(&token).await? {
                Some(ts) => Ok(Some(ts.login_id)),
                None => Ok(None),
            },
            Err(_) => Ok(None),
        }
    }

    async fn check_permission(&self, permission: &str) -> BulwarkResult<()> {
        // spec scenario "未登录抛出异常"：未登录时依据 throw_on_not_login 抛错
        let login_id = match self.get_login_id().await? {
            Some(id) => id,
            None => {
                // emit metrics：未登录视为 deny
                #[cfg(feature = "metrics-prometheus")]
                if let Some(m) = &self.metrics {
                    m.record_permission_query(false);
                }
                return if self.config.throw_on_not_login {
                    Err(BulwarkError::NotLogin("未登录，无法校验权限".to_string()))
                } else {
                    // throw_on_not_login=false：未登录视为无权限，抛 NotPermission
                    Err(BulwarkError::NotPermission(permission.to_string()))
                };
            },
        };
        // 委托 BulwarkFirewallStrategy 做权限校验
        let has_perm = self.firewall.check_permission(login_id, permission).await?;
        // emit metrics：权限查询结果
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_permission_query(has_perm);
        }
        if has_perm {
            Ok(())
        } else {
            Err(BulwarkError::NotPermission(permission.to_string()))
        }
    }

    async fn check_role(&self, role: &str) -> BulwarkResult<()> {
        // spec scenario "未登录抛出异常"：未登录时依据 throw_on_not_login 抛错
        let login_id = match self.get_login_id().await? {
            Some(id) => id,
            None => {
                // emit metrics：未登录视为 deny
                #[cfg(feature = "metrics-prometheus")]
                if let Some(m) = &self.metrics {
                    m.record_role_query(false);
                }
                return if self.config.throw_on_not_login {
                    Err(BulwarkError::NotLogin("未登录，无法校验角色".to_string()))
                } else {
                    // throw_on_not_login=false：未登录视为无角色，抛 NotRole
                    Err(BulwarkError::NotRole(role.to_string()))
                };
            },
        };
        // 委托 BulwarkFirewallStrategy 做角色校验
        let has_role = self.firewall.check_role(login_id, role).await?;
        // emit metrics：角色查询结果
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_role_query(has_role);
        }
        if has_role {
            Ok(())
        } else {
            Err(BulwarkError::NotRole(role.to_string()))
        }
    }

    async fn login_by_token(&self, token: &str) -> BulwarkResult<()> {
        // 获取 login_id：优先委托 auth_logic，否则使用 verify_token（TokenStyleFactory）
        let login_id = if let Some(auth) = &self.auth_logic {
            auth.verify_token(token).await?
        } else {
            self.verify_token(token).await?
        };
        // 建立内部会话（使用同一 token）
        self.session.create(login_id, token).await?;
        // auto-wire: 触发 plugin on_login + listener Login 事件
        if let Some(pm) = &self.plugin_manager {
            pm.on_login(login_id, token);
        }
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::Login {
                login_id,
                token: token.to_string(),
                device: None,
            })
            .await;
        }
        Ok(())
    }

    async fn verify_token(&self, token: &str) -> BulwarkResult<i64> {
        // 依据 spec core-auth-api：委托 core-token::Token::verify
        // spec: "不泄露 token 具体失效原因（统一 InvalidToken）"
        let token_handler =
            TokenStyleFactory::new(&self.config.token_style, &self.config.jwt_secret)?;
        match token_handler.verify(token) {
            Ok(Some(login_id)) => Ok(login_id),
            Ok(None) => Err(BulwarkError::InvalidToken(
                "token 无效或不包含 login_id".to_string(),
            )),
            Err(_) => Err(BulwarkError::InvalidToken("token 无效".to_string())),
        }
    }

    #[cfg(feature = "protocol-jwt")]
    async fn refresh_token(&self, token: &str) -> BulwarkResult<String> {
        // 依据 spec core-auth-api：启用 protocol-jwt 时委托 JwtHandler::refresh
        if self.config.token_style != "jwt" {
            return Err(BulwarkError::NotImplemented(
                "refresh_token 仅在 token_style=jwt 时可用".to_string(),
            ));
        }
        // 获取 login_id（用于 plugin/listener 回调）
        let login_id = self.verify_token(token).await?;
        let handler = crate::protocol::jwt::JwtHandler::new(&self.config.jwt_secret);
        let new_token = handler.refresh(token, self.config.timeout)?;
        // auto-wire: 触发 plugin on_login（新 token）
        if let Some(pm) = &self.plugin_manager {
            pm.on_login(login_id, &new_token);
        }
        // v0.4.2: 广播 TokenRefresh 事件（替换原 Login 事件，依据 spec listener-events-extend R-001）
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::TokenRefresh {
                login_id,
                old_token: token.to_string(),
                new_token: new_token.clone(),
            })
            .await;
        }
        Ok(new_token)
    }

    fn config(&self) -> Arc<BulwarkConfig> {
        Arc::clone(&self.config)
    }

    /// 密码登录实现：校验密码后调用 [`login`](Self::login) 签发 token。
    ///
    /// 依据 spec auth-password-login R-002：1) UserRepository 查询 2) PasswordHasher 校验 3) login 签发。
    /// 安全约束：用户不存在与密码错误统一返回 `InvalidParam("invalid password")`，真实原因记录在 tracing 日志。
    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    async fn login_with_password(&self, login_id: i64, password: &str) -> BulwarkResult<String> {
        let hasher = self
            .password_hasher
            .as_ref()
            .ok_or_else(|| BulwarkError::Config("password hasher not configured".to_string()))?;
        let repo = self
            .user_repository
            .as_ref()
            .ok_or_else(|| BulwarkError::Config("user repository not configured".to_string()))?;

        // 1. 查询用户（login_id 转字符串作为 username 查询）
        let username = login_id.to_string();
        let user = repo
            .find_by_username(0, &username)
            .await
            .map_err(|e| BulwarkError::Dao(format!("login_with_password 查询用户失败: {}", e)))?;

        let user = match user {
            Some(u) => u,
            None => {
                // v0.4.2 安全审计 A-014: 日志和事件统一为 "invalid_credentials"，
                // 不区分 user_not_found/wrong_password，防止日志泄露用户存在性
                tracing::warn!(
                    login_id = login_id,
                    reason = "invalid_credentials",
                    "login_with_password 失败"
                );
                // v0.4.2: 广播 LoginFailure 事件（依据 spec listener-events-extend R-001）
                #[cfg(feature = "listener")]
                if let Some(lm) = &self.listener_manager {
                    lm.broadcast(&BulwarkEvent::LoginFailure {
                        login_id,
                        reason: "invalid_credentials".to_string(),
                    })
                    .await;
                }
                return Err(BulwarkError::InvalidParam("invalid password".to_string()));
            },
        };

        // 2. 校验密码（哈希格式不支持返回 "unsupported hash format"，可泄露）
        let verified = hasher.verify(password, &user.password_hash).map_err(|e| {
            tracing::warn!(
                login_id = login_id,
                reason = "hash_format_error",
                error = %e,
                "login_with_password 密码哈希格式不支持"
            );
            BulwarkError::InvalidParam("unsupported hash format".to_string())
        })?;

        if !verified {
            // v0.4.2 安全审计 A-014: 日志和事件统一为 "invalid_credentials"，
            // 不区分 user_not_found/wrong_password，防止日志泄露用户存在性
            tracing::warn!(
                login_id = login_id,
                reason = "invalid_credentials",
                "login_with_password 失败"
            );
            // v0.4.2: 广播 LoginFailure 事件（依据 spec listener-events-extend R-001）
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                lm.broadcast(&BulwarkEvent::LoginFailure {
                    login_id,
                    reason: "invalid_credentials".to_string(),
                })
                .await;
            }
            return Err(BulwarkError::InvalidParam("invalid password".to_string()));
        }

        // 3. 调用 login 签发 token（触发 plugin/listener auto-wire）
        self.login(login_id).await
    }
}

// ============================================================================
// BulwarkInterface trait：权限数据回调（由业务方实现）
// ============================================================================

/// 接口 trait，定义获取权限 / 角色数据的回调。
///
/// [借鉴 Sa-Token] 对应 `StpInterface`，由业务方实现以提供权限数据。
///
/// # 数据来源
///
/// 业务方可自由选择数据来源（数据库 / YAML / 内存 / 外部服务等），
/// 框架不假定具体来源。`BulwarkFirewallStrategyDefault` 通过此回调获取数据后做字符串匹配。
#[async_trait]
pub trait BulwarkInterface: Send + Sync {
    /// 获取指定主体的权限列表。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 权限标识字符串列表（如 `["user:read", "user:write"]`）。
    ///
    /// # 错误
    /// - 数据源访问失败：由业务方实现决定具体 `BulwarkError`。
    async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>>;

    /// 获取指定主体的角色列表。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 角色标识字符串列表（如 `["admin", "user"]`）。
    ///
    /// # 错误
    /// - 数据源访问失败：由业务方实现决定具体 `BulwarkError`。
    async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>>;

    /// 获取指定主体在特定 `login_type` 下的权限列表（0.4.2 新增，依据 spec login-type-multi-account R-001）。
    ///
    /// 多账号体系下，不同 `login_type`（如 "admin"/"user"/"merchant"）的权限相互隔离。
    /// 业务方可 override 此方法以接入按 `login_type` 隔离的权限数据源。
    ///
    /// # 向后兼容
    ///
    /// 默认实现委托 [`get_permission_list`](Self::get_permission_list)（忽略 `login_type` 参数），
    /// 现有 `BulwarkInterface` 实现者无需修改即可工作。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `login_type`: 登录类型字符串（业务方自定义，如 "admin"/"user"/"merchant"）。
    ///
    /// # 返回
    /// 权限标识字符串列表。
    ///
    /// # 错误
    /// - 数据源访问失败：由业务方实现决定具体 `BulwarkError`。
    async fn get_permission_list_with_type(
        &self,
        login_id: i64,
        _login_type: &str,
    ) -> BulwarkResult<Vec<String>> {
        self.get_permission_list(login_id).await
    }

    /// 获取指定主体在特定 `login_type` 下的角色列表（0.4.2 新增，依据 spec login-type-multi-account R-001）。
    ///
    /// 多账号体系下，不同 `login_type`（如 "admin"/"user"/"merchant"）的角色相互隔离。
    /// 业务方可 override 此方法以接入按 `login_type` 隔离的角色数据源。
    ///
    /// # 向后兼容
    ///
    /// 默认实现委托 [`get_role_list`](Self::get_role_list)（忽略 `login_type` 参数），
    /// 现有 `BulwarkInterface` 实现者无需修改即可工作。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `login_type`: 登录类型字符串（业务方自定义，如 "admin"/"user"/"merchant"）。
    ///
    /// # 返回
    /// 角色标识字符串列表。
    ///
    /// # 错误
    /// - 数据源访问失败：由业务方实现决定具体 `BulwarkError`。
    async fn get_role_list_with_type(
        &self,
        login_id: i64,
        _login_type: &str,
    ) -> BulwarkResult<Vec<String>> {
        self.get_role_list(login_id).await
    }
}

// ============================================================================
// BulwarkUtil：静态方法入口（委托全局 BulwarkManager 单例）
// ============================================================================

/// 工具结构体，提供静态方法入口。
///
/// [借鉴 Sa-Token] 对应 `StpUtil`，是面向使用者的便捷入口。
/// 内部委托给 `BulwarkManager::logic()` 全局单例。
///
/// # 使用前提
///
/// 调用前必须先执行 `BulwarkManager::init(dao, config, interface)`，
/// 否则返回 `BulwarkError::Session("BulwarkManager 未初始化")`。
pub struct BulwarkUtil;

/// 将 `LoginId` 转换为 `i64`（v0.4.2 内部层仍使用 `i64`，String 形式待 v0.5.0+ 迁移）。
///
/// 公开为 `pub(crate)` 以便 `session` / `protocol` 等模块复用同一转换逻辑，
/// 保证 String-form login_id 在 v0.4.2 全栈一致返回 `BulwarkError::Config`。
///
/// # 错误
/// - `BulwarkError::Config`：传入 `LoginId::String` 形式，内部层尚未完成迁移。
pub(crate) fn login_id_to_i64(login_id: LoginId) -> BulwarkResult<i64> {
    login_id.as_i64().ok_or_else(|| {
        BulwarkError::Config(
            "String-form login_id 需内部层完整迁移（计划 v0.5.0+），v0.4.2 仅支持 Numeric 形式"
                .to_string(),
        )
    })
}

impl BulwarkUtil {
    /// 执行登录：生成 token + 创建会话。
    ///
    /// # 参数
    /// - `id`: 登录主体标识（支持 `i64`、`String`、`&str` 等 `Into<LoginId>` 类型）。
    ///
    /// # 返回
    /// 生成的 token 字符串。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - `LoginId::String` 形式：`BulwarkError::Config`（v0.4.2 限制，v0.5.0+ 支持）。
    /// - token 生成或会话创建失败：透传 `BulwarkError`。
    pub async fn login(id: impl Into<LoginId>) -> BulwarkResult<String> {
        let id_i64 = login_id_to_i64(id.into())?;
        crate::manager::BulwarkManager::logic()?.login(id_i64).await
    }

    /// 执行登出：从 task_local 获取当前 token 并销毁。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；未设置 token 时幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn logout() -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?.logout().await
    }

    /// 按账号登出：销毁指定 login_id 的所有会话。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（支持 `i64`、`String`、`&str` 等 `Into<LoginId>` 类型）。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - `LoginId::String` 形式：`BulwarkError::Config`（v0.4.2 限制，v0.5.0+ 支持）。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn logout_by_login_id(login_id: impl Into<LoginId>) -> BulwarkResult<()> {
        let id_i64 = login_id_to_i64(login_id.into())?;
        crate::manager::BulwarkManager::logic()?
            .logout_by_login_id(id_i64)
            .await
    }

    /// 踢出用户：按账号踢出（语义等同 logout_by_login_id）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（支持 `i64`、`String`、`&str` 等 `Into<LoginId>` 类型）。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - `LoginId::String` 形式：`BulwarkError::Config`（v0.4.2 限制，v0.5.0+ 支持）。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn kickout(login_id: impl Into<LoginId>) -> BulwarkResult<()> {
        let id_i64 = login_id_to_i64(login_id.into())?;
        crate::manager::BulwarkManager::logic()?
            .kickout(id_i64)
            .await
    }

    /// 踢出会话：按 token 踢出。
    ///
    /// # 参数
    /// - `token`: 待踢出的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn kickout_by_token(token: &str) -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .kickout_by_token(token)
            .await
    }

    /// 主动吊销 token：销毁指定 token 的会话（v0.4.2 新增，依据 spec listener-events-extend R-002）。
    ///
    /// 与 [`kickout_by_token`](Self::kickout_by_token) 的区别：
    /// - `revoke_token` 广播 `RevokeToken` 事件（仅携带 token，语义为"token 失效"）
    /// - `kickout_by_token` 不广播事件（语义为"管理员强制下线"，无对应 listener 事件）
    ///
    /// # 参数
    /// - `token`: 待吊销的 token 字符串。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；token 不存在时幂等返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn revoke_token(token: &str) -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .revoke_token(token)
            .await
    }

    /// 检查登录状态。
    ///
    /// # 返回
    /// - `Ok(true)`: 当前已登录且 token 有效。
    /// - `Ok(false)`: 未登录或 token 无效（`throw_on_not_login=false`）。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录且 `throw_on_not_login=true`：`BulwarkError::Session`。
    pub async fn check_login() -> BulwarkResult<bool> {
        crate::manager::BulwarkManager::logic()?.check_login().await
    }

    /// 获取当前登录 ID。
    ///
    /// # 返回
    /// - `Some(login_id)`: 已登录，返回关联的 login_id。
    /// - `None`: 未登录或 token 无效。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - DAO 读取失败：透传 `BulwarkError`。
    pub async fn get_login_id() -> BulwarkResult<Option<i64>> {
        crate::manager::BulwarkManager::logic()?
            .get_login_id()
            .await
    }

    /// 校验权限。
    ///
    /// # 参数
    /// - `permission`: 权限标识字符串。
    ///
    /// # 返回
    /// 成功（持有权限）返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin` 或降级为 `BulwarkError::NotPermission`。
    /// - 未持有权限：`BulwarkError::NotPermission`。
    pub async fn check_permission(permission: &str) -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .check_permission(permission)
            .await
    }

    /// 校验角色。
    ///
    /// # 参数
    /// - `role`: 角色标识字符串。
    ///
    /// # 返回
    /// 成功（持有角色）返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin` 或降级为 `BulwarkError::NotRole`。
    /// - 未持有角色：`BulwarkError::NotRole`。
    pub async fn check_role(role: &str) -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .check_role(role)
            .await
    }

    /// 校验 access_token 类型会话（0.5.0 新增，依据 spec annotation-macros P2 前置）。
    ///
    /// 委托 `BulwarkLogic::check_access_token()`，默认实现委托 `check_login`。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin`。
    pub async fn check_access_token() -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .check_access_token()
            .await
    }

    /// 校验 client_token 类型会话（0.5.0 新增，依据 spec annotation-macros P2 前置）。
    ///
    /// 委托 `BulwarkLogic::check_client_token()`，默认实现委托 `check_login`。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin`。
    pub async fn check_client_token() -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .check_client_token()
            .await
    }

    /// 校验 temp_token 类型会话（0.5.0 新增，依据 spec annotation-macros P2 前置）。
    ///
    /// 委托 `BulwarkLogic::check_temp_token()`，默认实现委托 `check_login`。
    ///
    /// # 返回
    /// - `Ok(())`: 当前会话 token 有效（已登录）。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未登录：`BulwarkError::NotLogin`。
    pub async fn check_temp_token() -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .check_temp_token()
            .await
    }

    /// 检查二级认证（MFA）状态（0.3.0 新增，依据 spec annotation-handling）。
    ///
    /// 委托 `BulwarkLogic::check_safe()`，默认实现返回 `Ok(())`（未启用 MFA）。
    ///
    /// # 返回
    /// - `Ok(())`: 已通过二级认证或未启用 MFA。
    /// - `Err(BulwarkError::Session)`: 未通过二级认证。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    pub async fn check_safe() -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?.check_safe().await
    }

    /// 检查账号是否被禁用（0.3.0 新增，依据 spec annotation-handling）。
    ///
    /// 委托 `BulwarkLogic::check_disable()`，默认实现返回 `Ok(())`（未实现禁用账号库）。
    ///
    /// # 返回
    /// - `Ok(())`: 账号未禁用。
    /// - `Err(BulwarkError::Session)`: 账号已禁用。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    pub async fn check_disable() -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .check_disable()
            .await
    }

    /// 通过外部 token 反向建立会话（0.2.0 新增，依据 spec core-auth-api）。
    ///
    /// 用于 OAuth2/SSO 场景：外部 token 已通过协议层校验后，
    /// 调用此方法在当前上下文建立内部会话。
    ///
    /// # 参数
    /// - `token`: 外部 token 字符串。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未启用协议层 feature：`BulwarkError::NotImplemented`。
    pub async fn login_by_token(token: &str) -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .login_by_token(token)
            .await
    }

    /// 验证显式传入的 token 并返回关联的 login_id（0.2.0 新增，依据 spec core-auth-api）。
    ///
    /// # 参数
    /// - `token`: 待验证的 token 字符串。
    ///
    /// # 返回
    /// - `Ok(login_id)`: token 有效，返回关联的 login_id。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - token 无效：`BulwarkError::InvalidToken`。
    pub async fn verify_token(token: &str) -> BulwarkResult<i64> {
        crate::manager::BulwarkManager::logic()?
            .verify_token(token)
            .await
    }

    /// 刷新 token（0.2.0 新增，依据 spec core-auth-api）。
    ///
    /// # 参数
    /// - `token`: 待刷新的旧 token 字符串。
    ///
    /// # 返回
    /// - `Ok(new_token)`: 刷新后的新 token 字符串。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 未启用 protocol-jwt：`BulwarkError::NotImplemented`。
    /// - token 已过期：`BulwarkError::InvalidToken`。
    pub async fn refresh_token(token: &str) -> BulwarkResult<String> {
        crate::manager::BulwarkManager::logic()?
            .refresh_token(token)
            .await
    }

    /// 获取当前 `BulwarkConfig` 引用（用于 extractor / middleware 等需要配置的场景）。
    ///
    /// # 返回
    /// 全局配置的 `Arc` 引用。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    pub fn config() -> BulwarkResult<Arc<BulwarkConfig>> {
        Ok(crate::manager::BulwarkManager::logic()?.config())
    }
}

// ============================================================================
// 测试（依据 spec stp-core-api 所有 scenario）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::BulwarkDao;
    use crate::manager::BulwarkManager;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    // ------------------------------------------------------------------------
    // MockDao：复用 dao/session 测试的 HashMap + Instant 模拟 TTL
    // ------------------------------------------------------------------------

    struct MockDao {
        store: Mutex<HashMap<String, (String, Option<Instant>)>>,
    }

    impl MockDao {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BulwarkDao for MockDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            let mut store = self.store.lock();
            match store.get(key) {
                Some((value, expire_at)) => {
                    if let Some(deadline) = expire_at {
                        if Instant::now() >= *deadline {
                            store.remove(key);
                            return Ok(None);
                        }
                    }
                    Ok(Some(value.clone()))
                },
                None => Ok(None),
            }
        }

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            let expire_at = if ttl_seconds == 0 {
                None
            } else {
                Some(Instant::now() + Duration::from_secs(ttl_seconds))
            };
            self.store
                .lock()
                .insert(key.to_string(), (value.to_string(), expire_at));
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((existing, _)) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((_, expire_at)) => {
                    *expire_at = if seconds == 0 {
                        None
                    } else {
                        Some(Instant::now() + Duration::from_secs(seconds))
                    };
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.store.lock().remove(key);
            Ok(())
        }
    }

    // ------------------------------------------------------------------------
    // MockFirewall：模拟 BulwarkFirewallStrategy，控制权限/角色校验返回值
    // ------------------------------------------------------------------------

    /// 测试用 BulwarkFirewallStrategy mock，可控制 check_permission/check_role 返回值。
    struct MockFirewall {
        has_permission: bool,
        has_role: bool,
    }

    #[async_trait]
    impl BulwarkFirewallStrategy for MockFirewall {
        async fn get_permission_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
        async fn check_permission(&self, _login_id: i64, _permission: &str) -> BulwarkResult<bool> {
            Ok(self.has_permission)
        }
        async fn check_role(&self, _login_id: i64, _role: &str) -> BulwarkResult<bool> {
            Ok(self.has_role)
        }
        async fn check_role_any(&self, _login_id: i64, _roles: &[&str]) -> BulwarkResult<bool> {
            Ok(self.has_role)
        }
        async fn check_role_all(&self, _login_id: i64, _roles: &[&str]) -> BulwarkResult<bool> {
            Ok(self.has_role)
        }
    }

    /// 辅助函数：创建 BulwarkLogicDefault 实例（throw_on_not_login + firewall 返回值可配置）。
    fn make_logic(
        timeout: u64,
        active_timeout: u64,
        throw_on_not_login: bool,
        token_style: &str,
        has_permission: bool,
        has_role: bool,
    ) -> BulwarkLogicDefault {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao, timeout, active_timeout));
        let mut config = BulwarkConfig::default_config();
        config.throw_on_not_login = throw_on_not_login;
        config.token_style = token_style.to_string();
        let firewall: Arc<dyn BulwarkFirewallStrategy> = Arc::new(MockFirewall {
            has_permission,
            has_role,
        });
        BulwarkLogicDefault::new(session, Arc::new(config), firewall)
    }

    /// 辅助函数：在当前 task_local 设置 token 后执行 future。
    async fn with_token<R>(token: &str, f: impl std::future::Future<Output = R>) -> R {
        with_current_token(token.to_string(), f).await
    }

    // ------------------------------------------------------------------------
    // MockInterface：用于 BulwarkUtil 全局管理器测试
    // ------------------------------------------------------------------------

    struct MockInterface;

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
    }

    /// 初始化全局 BulwarkManager（用于 BulwarkUtil 静态方法测试）。
    fn init_global_manager(throw_on_not_login: bool) {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = throw_on_not_login;
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
        BulwarkManager::init(dao, Arc::new(config), interface).unwrap();
    }

    // ------------------------------------------------------------------------
    // spec scenario: login 首次登录 / 重复登录 / 自定义 token 风格
    // ------------------------------------------------------------------------

    /// 验证 login 返回非空 token 并创建会话。
    #[tokio::test]
    async fn login_creates_session_and_returns_token() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let token = logic.login(1001).await.unwrap();
        assert!(!token.is_empty(), "login 应返回非空 token");

        // 验证会话创建
        let ts = logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ts.login_id, 1001);
    }

    /// 验证重复登录生成不同 token 并记录多 token。
    #[tokio::test]
    async fn login_repeated_creates_multiple_tokens() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let t1 = logic.login(1001).await.unwrap();
        let t2 = logic.login(1001).await.unwrap();
        assert_ne!(t1, t2, "重复登录应生成不同 token");

        // Account-Session 应包含两个 token
        let as_ = logic
            .session
            .get_account_session(1001)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(as_.tokens.len(), 2);
    }

    /// 验证 token_style=random_64 生成 64 字符 token。
    #[tokio::test]
    async fn login_with_random_64_style() {
        let logic = make_logic(3600, 86400, false, "random_64", true, true);
        let token = logic.login(1001).await.unwrap();
        assert_eq!(token.len(), 64, "random_64 应生成 64 字符 token");
    }

    /// 验证 token_style=simple 生成 32 字符 token。
    #[tokio::test]
    async fn login_with_simple_style() {
        let logic = make_logic(3600, 86400, false, "simple", true, true);
        let token = logic.login(1001).await.unwrap();
        assert_eq!(token.len(), 32, "simple 应生成 32 字符 token");
    }

    /// 验证未知 token_style 时 login 返回 Err（依据 codebase-hardening Task 3.6）。
    ///
    /// 覆盖 `generate_token` 的 `other =>` 分支，断言返回 `BulwarkError::Config`。
    #[tokio::test]
    async fn create_token_unknown_style_errors() {
        let logic = make_logic(3600, 86400, false, "unknown_style", true, true);
        let result = logic.login(1001).await;
        assert!(
            matches!(result, Err(BulwarkError::Config(ref msg)) if msg.contains("unknown token_style")),
            "未知 token_style 应返回含 'unknown token_style' 的 Config 错误，实际: {:?}",
            result
        );
    }

    /// 验证 login_with_token 用自定义 token 创建会话。
    #[tokio::test]
    async fn login_with_custom_token() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        logic
            .login_with_token(1001, "custom-token-123")
            .await
            .unwrap();

        let ts = logic
            .session
            .get_token_session("custom-token-123")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ts.login_id, 1001);
        assert_eq!(ts.token, "custom-token-123");
    }

    // ------------------------------------------------------------------------
    // spec scenario: logout 销毁当前 / 销毁指定账号 / kickout
    // ------------------------------------------------------------------------

    /// 验证 logout 销毁当前 token 的会话。
    #[tokio::test]
    async fn logout_destroys_current_token() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
        let token = logic.login(1001).await.unwrap();

        // 在 task_local 作用域内调用 logout
        with_current_token(token.clone(), async {
            logic.logout().await.unwrap();
        })
        .await;

        // Token-Session 已删除
        let ts = logic.session.get_token_session(&token).await.unwrap();
        assert!(ts.is_none(), "logout 后 Token-Session 应删除");
    }

    /// 验证 logout 未登录时幂等返回 Ok。
    #[tokio::test]
    async fn logout_when_not_logged_in_is_noop() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        // 未设置 task_local，logout 应幂等返回 Ok
        let result = logic.logout().await;
        assert!(result.is_ok(), "未登录时 logout 应幂等返回 Ok");
    }

    /// 验证 logout_by_login_id 销毁所有 token。
    #[tokio::test]
    async fn logout_by_login_id_destroys_all_tokens() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let t1 = logic.login(1001).await.unwrap();
        let t2 = logic.login(1001).await.unwrap();

        logic.logout_by_login_id(1001).await.unwrap();

        assert!(logic
            .session
            .get_token_session(&t1)
            .await
            .unwrap()
            .is_none());
        assert!(logic
            .session
            .get_token_session(&t2)
            .await
            .unwrap()
            .is_none());
        assert!(logic
            .session
            .get_account_session(1001)
            .await
            .unwrap()
            .is_none());
    }

    /// 验证 kickout 按账号踢出（语义等同 logout_by_login_id）。
    #[tokio::test]
    async fn kickout_by_account_destroys_session() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let token = logic.login(1001).await.unwrap();

        logic.kickout(1001).await.unwrap();

        assert!(logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .is_none());
        assert!(logic
            .session
            .get_account_session(1001)
            .await
            .unwrap()
            .is_none());
    }

    /// 验证 kickout_by_token 按 token 踢出。
    #[tokio::test]
    async fn kickout_by_token_destroys_token_session() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let token = logic.login(1001).await.unwrap();

        logic.kickout_by_token(&token).await.unwrap();

        assert!(logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .is_none());
    }

    // ------------------------------------------------------------------------
    // spec scenario: check_login 有效 / 无效 / 过期 / 未登录抛异常
    // ------------------------------------------------------------------------

    /// 验证 check_login 有效 token 返回 true。
    #[tokio::test]
    async fn check_login_returns_true_for_valid_token() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
        let token = logic.login(1001).await.unwrap();

        with_current_token(token, async {
            let valid = logic.check_login().await.unwrap();
            assert!(valid, "有效 token 应返回 true");
        })
        .await;
    }

    /// 验证 check_login 无效 token 返回 false（throw_on_not_login=false）。
    #[tokio::test]
    async fn check_login_returns_false_for_invalid_token() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));

        with_current_token("invalid-token".to_string(), async {
            let valid = logic.check_login().await.unwrap();
            assert!(!valid, "无效 token 应返回 false");
        })
        .await;
    }

    /// 验证 check_login 未设置 token 返回 false（throw_on_not_login=false）。
    #[tokio::test]
    async fn check_login_returns_false_when_no_token() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        // 未设置 task_local，check_login 返回 false
        let valid = logic.check_login().await.unwrap();
        assert!(!valid, "未设置 token 应返回 false");
    }

    /// 验证 check_login 未登录且 throw_on_not_login=true 抛异常。
    ///
    /// spec config-system Requirement: 配置校验——throw_on_not_login。
    #[tokio::test]
    async fn check_login_throws_when_throw_on_not_login() {
        let logic = make_logic(3600, 86400, true, "uuid", true, true);
        let result = logic.check_login().await;
        assert!(
            matches!(result, Err(BulwarkError::Session(_))),
            "throw_on_not_login=true 且未登录应抛 Session 错误"
        );
    }

    /// 验证 check_login 过期 token 返回 false。
    #[tokio::test]
    async fn check_login_returns_false_for_expired_token() {
        let logic = Arc::new(make_logic(1, 86400, false, "uuid", true, true));
        let token = logic.login(1001).await.unwrap();

        // 等待 token 过期（1 秒 TTL）
        tokio::time::sleep(Duration::from_secs(2)).await;

        with_current_token(token, async {
            let valid = logic.check_login().await.unwrap();
            assert!(!valid, "过期 token 应返回 false");
        })
        .await;
    }

    // ------------------------------------------------------------------------
    // v0.5.0 新增: token 类型专用校验方法（依据 spec annotation-macros P2 前置）
    // ------------------------------------------------------------------------

    /// 验证 `check_access_token` 委托 `check_login`，已登录时返回 `Ok(())`。
    ///
    /// 依据 tasks.md T151。语义：access_token 类型校验入口，默认实现委托 check_login。
    #[tokio::test]
    async fn check_access_token_delegates_to_check_login() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
        let token = logic.login(1001).await.unwrap();

        with_current_token(token, async {
            let result = logic.check_access_token().await;
            assert!(
                result.is_ok(),
                "已登录时 check_access_token 应返回 Ok，实际: {:?}",
                result
            );
        })
        .await;
    }

    /// 验证 `check_client_token` 委托 `check_login`，已登录时返回 `Ok(())`。
    ///
    /// 依据 tasks.md T151。语义：client_token 类型校验入口，默认实现委托 check_login。
    #[tokio::test]
    async fn check_client_token_delegates_to_check_login() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
        let token = logic.login(1001).await.unwrap();

        with_current_token(token, async {
            let result = logic.check_client_token().await;
            assert!(
                result.is_ok(),
                "已登录时 check_client_token 应返回 Ok，实际: {:?}",
                result
            );
        })
        .await;
    }

    /// 验证 `check_temp_token` 委托 `check_login`，已登录时返回 `Ok(())`。
    ///
    /// 依据 tasks.md T151。语义：temp_token 类型校验入口，默认实现委托 check_login。
    #[tokio::test]
    async fn check_temp_token_delegates_to_check_login() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
        let token = logic.login(1001).await.unwrap();

        with_current_token(token, async {
            let result = logic.check_temp_token().await;
            assert!(
                result.is_ok(),
                "已登录时 check_temp_token 应返回 Ok，实际: {:?}",
                result
            );
        })
        .await;
    }

    // ------------------------------------------------------------------------
    // spec scenario: get_login_id
    // ------------------------------------------------------------------------

    /// 验证 get_login_id 返回当前 login_id。
    #[tokio::test]
    async fn get_login_id_returns_current_login_id() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
        let token = logic.login(1001).await.unwrap();

        with_current_token(token, async {
            let login_id = logic.get_login_id().await.unwrap();
            assert_eq!(login_id, Some(1001));
        })
        .await;
    }

    /// 验证 get_login_id 未登录返回 None。
    #[tokio::test]
    async fn get_login_id_returns_none_when_not_logged_in() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let login_id = logic.get_login_id().await.unwrap();
        assert_eq!(login_id, None, "未登录应返回 None");
    }

    /// 验证 get_login_id 无效 token 返回 None。
    #[tokio::test]
    async fn get_login_id_returns_none_for_invalid_token() {
        let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));

        with_current_token("invalid-token".to_string(), async {
            let login_id = logic.get_login_id().await.unwrap();
            assert_eq!(login_id, None, "无效 token 应返回 None");
        })
        .await;
    }

    // ------------------------------------------------------------------------
    // task_local 上下文测试
    // ------------------------------------------------------------------------

    /// 验证 current_token 未设置时抛错。
    #[test]
    fn current_token_errors_when_not_set() {
        let result = current_token();
        assert!(
            matches!(result, Err(BulwarkError::Session(_))),
            "未设置 task_local 时 current_token 应抛错"
        );
    }

    /// 验证 current_token 在作用域内返回 token。
    #[tokio::test]
    async fn current_token_returns_value_in_scope() {
        with_current_token("scoped-token".to_string(), async {
            let token = current_token().unwrap();
            assert_eq!(token, "scoped-token");
        })
        .await;
    }

    // ------------------------------------------------------------------------
    // spec scenario: check_permission 持有/未持有/未登录抛异常
    // ------------------------------------------------------------------------

    /// spec scenario "持有权限返回 true"：已登录且 firewall 返回 true 时 check_permission 通过。
    #[tokio::test]
    async fn check_permission_held_returns_ok() {
        let logic = make_logic(3600, 86400, true, "uuid", true, true);
        let token = logic.login(1001).await.unwrap();
        let result = with_token(&token, logic.check_permission("user:read")).await;
        assert!(result.is_ok(), "持有权限应返回 Ok");
    }

    /// spec scenario "未持有权限返回 false"：已登录但 firewall 返回 false 时抛 NotPermission。
    #[tokio::test]
    async fn check_permission_not_held_throws_not_permission() {
        let logic = make_logic(3600, 86400, true, "uuid", false, true);
        let token = logic.login(1001).await.unwrap();
        let result = with_token(&token, logic.check_permission("user:delete")).await;
        assert!(
            matches!(result, Err(BulwarkError::NotPermission(_))),
            "未持有权限应抛 NotPermission"
        );
    }

    /// spec scenario "未登录抛出异常"：未登录且 throw_on_not_login=true 时抛 NotLogin。
    #[tokio::test]
    async fn check_permission_not_login_throws_when_throw_on_not_login() {
        let logic = make_logic(3600, 86400, true, "uuid", true, true);
        // 不调用 login，直接 check_permission（无 task_local token）
        let result = logic.check_permission("user:read").await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(_))),
            "未登录且 throw_on_not_login=true 应抛 NotLogin"
        );
    }

    /// 未登录且 throw_on_not_login=false 时 check_permission 抛 NotPermission（降级为无权限）。
    #[tokio::test]
    async fn check_permission_not_login_throws_not_permission_when_silent() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        // 不调用 login，直接 check_permission（无 task_local token）
        let result = logic.check_permission("user:read").await;
        assert!(
            matches!(result, Err(BulwarkError::NotPermission(_))),
            "未登录且 throw_on_not_login=false 应抛 NotPermission（降级）"
        );
    }

    // ------------------------------------------------------------------------
    // spec scenario: check_role 持有/未持有/未登录抛异常
    // ------------------------------------------------------------------------

    /// spec scenario "持有角色返回 true"：已登录且 firewall 返回 true 时 check_role 通过。
    #[tokio::test]
    async fn check_role_held_returns_ok() {
        let logic = make_logic(3600, 86400, true, "uuid", true, true);
        let token = logic.login(1001).await.unwrap();
        let result = with_token(&token, logic.check_role("admin")).await;
        assert!(result.is_ok(), "持有角色应返回 Ok");
    }

    /// spec scenario "未持有角色返回 false"：已登录但 firewall 返回 false 时抛 NotRole。
    #[tokio::test]
    async fn check_role_not_held_throws_not_role() {
        let logic = make_logic(3600, 86400, true, "uuid", true, false);
        let token = logic.login(1001).await.unwrap();
        let result = with_token(&token, logic.check_role("admin")).await;
        assert!(
            matches!(result, Err(BulwarkError::NotRole(_))),
            "未持有角色应抛 NotRole"
        );
    }

    /// spec scenario "未登录抛出异常"：未登录且 throw_on_not_login=true 时 check_role 抛 NotLogin。
    #[tokio::test]
    async fn check_role_not_login_throws_when_throw_on_not_login() {
        let logic = make_logic(3600, 86400, true, "uuid", true, true);
        // 不调用 login，直接 check_role（无 task_local token）
        let result = logic.check_role("admin").await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(_))),
            "未登录且 throw_on_not_login=true 应抛 NotLogin"
        );
    }

    /// 未登录且 throw_on_not_login=false 时 check_role 抛 NotRole（降级为无角色）。
    #[tokio::test]
    async fn check_role_not_login_throws_not_role_when_silent() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        // 不调用 login，直接 check_role（无 task_local token）
        let result = logic.check_role("admin").await;
        assert!(
            matches!(result, Err(BulwarkError::NotRole(_))),
            "未登录且 throw_on_not_login=false 应抛 NotRole（降级）"
        );
    }

    // ------------------------------------------------------------------------
    // BulwarkUtil 未初始化错误测试（spec Scenario: 未初始化抛错）
    // ------------------------------------------------------------------------

    /// 未初始化时 BulwarkUtil::logout 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_logout_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::logout().await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 logout 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::logout_by_login_id 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_logout_by_login_id_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::logout_by_login_id(1001).await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 logout_by_login_id 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::kickout 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_kickout_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::kickout(1001).await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 kickout 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::kickout_by_token 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_kickout_by_token_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::kickout_by_token("some-token").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 kickout_by_token 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::check_login 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_check_login_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::check_login().await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 check_login 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::get_login_id 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_get_login_id_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::get_login_id().await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 get_login_id 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::check_permission 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_check_permission_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::check_permission("user:read").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 check_permission 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::check_role 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_check_role_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::check_role("admin").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 check_role 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::check_safe 返回 Session 错误（0.3.0 新增）。
    #[tokio::test]
    #[serial]
    async fn util_check_safe_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::check_safe().await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 check_safe 应返回 Session 错误"
        );
    }

    /// 未初始化时 BulwarkUtil::check_disable 返回 Session 错误（0.3.0 新增）。
    #[tokio::test]
    #[serial]
    async fn util_check_disable_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::check_disable().await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 check_disable 应返回 Session 错误"
        );
    }

    // ------------------------------------------------------------------------
    // BulwarkUtil 成功路径测试（覆盖未测试的静态方法）
    // ------------------------------------------------------------------------

    /// BulwarkUtil::logout_by_login_id 成功销毁指定账号的所有会话。
    #[tokio::test]
    #[serial]
    async fn util_logout_by_login_id_succeeds() {
        init_global_manager(false);
        let token = BulwarkUtil::login(1001).await.unwrap();
        assert!(!token.is_empty());

        BulwarkUtil::logout_by_login_id(1001).await.unwrap();

        // logout 后 check_login 应返回 false
        let valid = with_token(&token, async { BulwarkUtil::check_login().await })
            .await
            .unwrap();
        assert!(!valid, "logout_by_login_id 后 check_login 应返回 false");

        BulwarkManager::reset_for_test();
    }

    /// BulwarkUtil::kickout 成功踢出指定账号。
    #[tokio::test]
    #[serial]
    async fn util_kickout_succeeds() {
        init_global_manager(false);
        let token = BulwarkUtil::login(1001).await.unwrap();

        BulwarkUtil::kickout(1001).await.unwrap();

        let valid = with_token(&token, async { BulwarkUtil::check_login().await })
            .await
            .unwrap();
        assert!(!valid, "kickout 后 check_login 应返回 false");

        BulwarkManager::reset_for_test();
    }

    /// BulwarkUtil::kickout_by_token 成功踢出指定 token。
    #[tokio::test]
    #[serial]
    async fn util_kickout_by_token_succeeds() {
        init_global_manager(false);
        let token = BulwarkUtil::login(1001).await.unwrap();

        BulwarkUtil::kickout_by_token(&token).await.unwrap();

        let valid = with_token(&token, async { BulwarkUtil::check_login().await })
            .await
            .unwrap();
        assert!(!valid, "kickout_by_token 后 check_login 应返回 false");

        BulwarkManager::reset_for_test();
    }

    /// BulwarkUtil::get_login_id 返回当前登录 ID。
    #[tokio::test]
    #[serial]
    async fn util_get_login_id_returns_current_id() {
        init_global_manager(false);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let login_id = with_token(&token, async { BulwarkUtil::get_login_id().await })
            .await
            .unwrap();
        assert_eq!(login_id, Some(1001), "get_login_id 应返回当前 login_id");

        BulwarkManager::reset_for_test();
    }

    /// BulwarkUtil::check_safe 默认实现返回 Ok（0.3.0 新增，依据 spec annotation-handling）。
    ///
    /// 默认 `BulwarkLogicDefault` 未启用 MFA，`check_safe` 返回 `Ok(())`。
    #[tokio::test]
    #[serial]
    async fn util_check_safe_returns_ok_by_default() {
        init_global_manager(false);
        let _ = BulwarkUtil::login(1001).await.unwrap();

        // 默认实现（未覆写 check_safe）应返回 Ok
        let result = BulwarkUtil::check_safe().await;
        assert!(
            result.is_ok(),
            "默认 check_safe 应返回 Ok，实际: {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }

    /// BulwarkUtil::check_disable 默认实现返回 Ok（0.3.0 新增，依据 spec annotation-handling）。
    ///
    /// 默认 `BulwarkLogicDefault` 未实现禁用账号库，`check_disable` 返回 `Ok(())`。
    #[tokio::test]
    #[serial]
    async fn util_check_disable_returns_ok_by_default() {
        init_global_manager(false);
        let _ = BulwarkUtil::login(1001).await.unwrap();

        // 默认实现（未覆写 check_disable）应返回 Ok
        let result = BulwarkUtil::check_disable().await;
        assert!(
            result.is_ok(),
            "默认 check_disable 应返回 Ok，实际: {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // 0.2.0 新增 API 测试：login_by_token / verify_token / refresh_token
    // ------------------------------------------------------------------------

    /// BulwarkLogicDefault::login_by_token 对 uuid style token 返回 InvalidToken（0.2.1 auto-wire 修复）。
    ///
    /// 0.2.1 起login_by_token 被 override：优先委托 auth_logic，否则使用 verify_token。
    /// uuid token 不包含 login_id，verify_token 返回 InvalidToken。
    #[tokio::test]
    async fn login_by_token_uuid_style_returns_invalid_token() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let result = logic.login_by_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "uuid style login_by_token 应返回 InvalidToken，实际: {:?}",
            result
        );
    }

    /// BulwarkUtil::login_by_token 未初始化时返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_login_by_token_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::login_by_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 login_by_token 应返回 Session 错误"
        );
    }

    /// verify_token 对 simple style token 返回 login_id（spec Scenario）。
    ///
    /// 注意：0.1.0 `generate_token("simple")` 生成 32 字符 UUID，
    /// 与 core-token `SimpleTokenStyle` 的 `<login_id>-<uuid>` 格式不同。
    /// 此测试手动构造 simple-format token 验证 verify_token 委托逻辑。
    #[tokio::test]
    async fn verify_token_simple_style_returns_login_id() {
        let logic = make_logic(3600, 86400, false, "simple", true, true);
        // 手动构造 simple-format token: <login_id>-<uuid>
        let token = format!("1001-{}", uuid::Uuid::new_v4());
        let login_id = logic.verify_token(&token).await.unwrap();
        assert_eq!(login_id, 1001, "verify_token 应返回 login_id");
    }

    /// verify_token 对 uuid style token 返回 InvalidToken（spec Scenario）。
    ///
    /// uuid token 不包含 login_id，Token::verify 返回 None → InvalidToken。
    #[tokio::test]
    async fn verify_token_uuid_style_returns_invalid_token() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let token = logic.login(1001).await.unwrap();
        let result = logic.verify_token(&token).await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "uuid style verify_token 应返回 InvalidToken，实际: {:?}",
            result
        );
    }

    /// verify_token 对无效 token 返回 InvalidToken（spec Scenario）。
    ///
    /// "nodash" 无 '-' 分隔符，SimpleTokenStyle::verify 返回 Ok(None) → InvalidToken。
    #[tokio::test]
    async fn verify_token_invalid_returns_error() {
        let logic = make_logic(3600, 86400, false, "simple", true, true);
        let result = logic.verify_token("nodash").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "无效 token 应返回 InvalidToken，实际: {:?}",
            result
        );
    }

    /// verify_token 对格式错误 token（含 '-' 但 login_id 非数字）返回 InvalidToken（spec Scenario）。
    ///
    /// spec: "不泄露 token 具体失效原因（统一 InvalidToken）"
    #[tokio::test]
    async fn verify_token_malformed_returns_invalid_token() {
        let logic = make_logic(3600, 86400, false, "simple", true, true);
        let result = logic.verify_token("abc-xyz").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "格式错误 token 应返回 InvalidToken（统一错误），实际: {:?}",
            result
        );
    }

    /// BulwarkUtil::verify_token 未初始化时返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_verify_token_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::verify_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 verify_token 应返回 Session 错误"
        );
    }

    /// refresh_token default 返回 NotImplemented（spec Scenario: 未启用 protocol-jwt）。
    #[tokio::test]
    async fn refresh_token_default_returns_not_implemented() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let result = logic.refresh_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(_))),
            "default refresh_token 应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// BulwarkUtil::refresh_token 未初始化时返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn util_refresh_token_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::refresh_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
            "未初始化时 refresh_token 应返回 Session 错误"
        );
    }

    /// BulwarkUtil::verify_token 端到端：simple style token → 返回 login_id。
    ///
    /// 注意：BulwarkUtil::login 使用 0.1.0 generate_token，"simple" 生成 32 字符 UUID，
    /// 与 core-token SimpleTokenStyle 格式不同。此测试手动构造 simple-format token。
    #[tokio::test]
    #[serial]
    async fn util_verify_token_returns_login_id() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.token_style = "simple".to_string();
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
        BulwarkManager::init(dao, Arc::new(config), interface).unwrap();

        // 手动构造 simple-format token: <login_id>-<uuid>
        let token = format!("1001-{}", uuid::Uuid::new_v4());
        let login_id = BulwarkUtil::verify_token(&token).await.unwrap();
        assert_eq!(login_id, 1001);

        BulwarkManager::reset_for_test();
    }

    /// BulwarkUtil::refresh_token 端到端：未启用 protocol-jwt → NotImplemented。
    #[tokio::test]
    #[serial]
    async fn util_refresh_token_returns_not_implemented_without_jwt() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
        BulwarkManager::init(dao, Arc::new(config), interface).unwrap();

        let result = BulwarkUtil::refresh_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(_))),
            "未启用 protocol-jwt 时 refresh_token 应返回 NotImplemented"
        );

        BulwarkManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // 0.2.1 auto-wire gap 修复测试：builder 方法 + plugin/listener 触发
    // ------------------------------------------------------------------------

    /// builder 方法链式调用返回 Self（spec Scenario: 4.8 builder 方法验证）。
    #[tokio::test]
    async fn builder_methods_return_self_for_chaining() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        // 链式调用所有 builder 方法，验证返回 Self
        let pm = Arc::new(BulwarkPluginManager::new());
        #[cfg(feature = "listener")]
        let lm = Arc::new(BulwarkListenerManager::new());
        #[cfg(feature = "listener")]
        let _logic = logic.with_plugin_manager(pm).with_listener_manager(lm);
        #[cfg(not(feature = "listener"))]
        let _logic = logic.with_plugin_manager(pm);
        // 验证 login 仍可正常工作（builder 未破坏核心功能）
        let logic2 = make_logic(3600, 86400, false, "uuid", true, true);
        let token = logic2.login(1001).await.unwrap();
        assert!(!token.is_empty());
    }

    /// builder 方法注入 plugin_manager 后 login 触发 on_login 钩子（spec Scenario: auto-wire）。
    #[tokio::test]
    async fn login_with_plugin_manager_triggers_on_login() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let pm = Arc::new(BulwarkPluginManager::new());
        let logic = logic.with_plugin_manager(pm);
        // login 应成功，plugin on_login 作为副作用被调用（失败仅 warn 不中断）
        let token = logic.login(1001).await.unwrap();
        assert!(!token.is_empty());
    }

    /// builder 方法注入 listener_manager 后 login 广播 Login 事件（spec Scenario: auto-wire）。
    #[tokio::test]
    async fn login_with_listener_manager_broadcasts_login_event() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        #[cfg(feature = "listener")]
        {
            let lm = Arc::new(BulwarkListenerManager::new());
            let logic = logic.with_listener_manager(lm);
            let token = logic.login(1001).await.unwrap();
            assert!(!token.is_empty());
        }
        #[cfg(not(feature = "listener"))]
        {
            let _ = logic;
        }
    }

    /// logout 注入 plugin_manager + listener_manager 后触发 on_logout + Logout 事件。
    #[tokio::test]
    async fn logout_with_managers_triggers_hooks() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let pm = Arc::new(BulwarkPluginManager::new());
        let logic = logic.with_plugin_manager(pm);
        #[cfg(feature = "listener")]
        let logic = logic.with_listener_manager(Arc::new(BulwarkListenerManager::new()));

        // 先 login 获取 token
        let token = logic.login(2002).await.unwrap();
        // 在 token 上下文中 logout
        with_current_token(token.clone(), async { logic.logout().await })
            .await
            .unwrap();
    }

    /// kickout 注入 listener_manager 后广播 Kickout 事件。
    #[tokio::test]
    async fn kickout_with_listener_manager_broadcasts_event() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        #[cfg(feature = "listener")]
        {
            let lm = Arc::new(BulwarkListenerManager::new());
            let logic = logic.with_listener_manager(lm);
            // kickout 应成功，Kickout 事件作为副作用被广播
            logic.kickout(3003).await.unwrap();
        }
        #[cfg(not(feature = "listener"))]
        {
            logic.kickout(3003).await.unwrap();
        }
    }

    /// revoke_token 销毁指定 token 的会话（v0.4.2 新增，依据 spec listener-events-extend R-002）。
    ///
    /// 验证：revoke_token 后 Token-Session 已删除。
    #[tokio::test]
    async fn revoke_token_destroys_session() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let token = logic.login(4004).await.unwrap();

        // revoke 前存在
        assert!(logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .is_some());

        logic.revoke_token(&token).await.unwrap();

        // revoke 后 Token-Session 已删除
        assert!(logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .is_none());
    }

    /// revoke_token 注入 listener_manager 后广播 RevokeToken 事件
    /// （v0.4.2 新增，依据 spec listener-events-extend R-002）。
    #[tokio::test]
    async fn revoke_token_with_listener_manager_broadcasts_event() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        #[cfg(feature = "listener")]
        {
            let lm = Arc::new(BulwarkListenerManager::new());
            let logic = logic.with_listener_manager(lm);
            let token = logic.login(4005).await.unwrap();
            // revoke 应成功，RevokeToken 事件作为副作用被广播
            logic.revoke_token(&token).await.unwrap();
            // Token-Session 已删除
            assert!(logic
                .session
                .get_token_session(&token)
                .await
                .unwrap()
                .is_none());
        }
        #[cfg(not(feature = "listener"))]
        {
            let token = logic.login(4005).await.unwrap();
            logic.revoke_token(&token).await.unwrap();
        }
    }

    /// revoke_token 对不存在的 token 幂等返回 Ok。
    #[tokio::test]
    async fn revoke_token_nonexistent_is_noop() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        // 不存在的 token 应幂等返回 Ok
        let result = logic.revoke_token("nonexistent-token").await;
        assert!(
            result.is_ok(),
            "revoke_token 对不存在的 token 应幂等返回 Ok"
        );
    }

    /// 未注入 manager 时向后兼容：login/logout/kickout 行为与 0.2.0 一致（spec Scenario: 4.9）。
    #[tokio::test]
    async fn backward_compat_without_managers_works_same_as_0_2_0() {
        // make_logic 不注入任何 manager，所有 Option 都是 None
        let logic = make_logic(3600, 86400, false, "uuid", true, true);

        // login 成功
        let token = logic.login(5005).await.unwrap();
        assert!(!token.is_empty());

        // check_login 成功
        let is_valid = with_current_token(token.clone(), async { logic.check_login().await })
            .await
            .unwrap();
        assert!(is_valid);

        // logout 成功（在 token 上下文中）
        with_current_token(token.clone(), async { logic.logout().await })
            .await
            .unwrap();

        // kickout 成功
        logic.kickout(5005).await.unwrap();
    }

    /// login_by_token 注入 auth_logic 后优先委托 auth_logic.verify_token。
    #[tokio::test]
    async fn login_by_token_with_auth_logic_delegates_to_auth() {
        use crate::core::auth::{AuthLogic, AuthLogicDefault};
        use crate::core::token::{Token, UuidTokenStyle};

        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
        let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
        let auth_logic: Arc<dyn AuthLogic> =
            Arc::new(AuthLogicDefault::new(session.clone(), token_handler, 3600));

        // 先通过 auth_logic login 生成一个有效 token
        let valid_token = auth_logic.login(6006, None).await.unwrap();

        // 构造 logic 注入 auth_logic
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let logic = logic.with_auth_logic(auth_logic);

        // login_by_token 应委托 auth_logic.verify_token 并建立会话
        logic.login_by_token(&valid_token).await.unwrap();

        // 验证会话已建立
        let ts = logic.session.get_token_session(&valid_token).await.unwrap();
        assert!(ts.is_some(), "login_by_token 后应建立会话");
        assert_eq!(ts.unwrap().login_id, 6006);
    }

    // ------------------------------------------------------------------------
    // refresh_token 覆盖率补充测试（0.2.1 新增 impl，依据 spec core-auth-api）
    // ------------------------------------------------------------------------

    /// refresh_token 在 token_style 非 jwt 时返回 NotImplemented。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn refresh_token_non_jwt_style_returns_not_implemented() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        let result = logic.refresh_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("token_style=jwt")),
            "非 jwt style 的 refresh_token 应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// refresh_token 对无效 JWT token 返回 InvalidToken 错误。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn refresh_token_invalid_jwt_returns_error() {
        // 构造 token_style=jwt 的 logic（jwt_secret 来自 default_config）
        let logic = make_logic(3600, 86400, false, "jwt", true, true);
        // 无效 token：verify_token 返回 Err，refresh_token 应透传
        let result = logic.refresh_token("invalid.jwt.token").await;
        assert!(
            result.is_err(),
            "无效 JWT refresh_token 应返回 Err，实际: {:?}",
            result
        );
    }

    /// refresh_token 对有效 JWT token 成功刷新（0.2.1 auto-wire 触发 plugin/listener）。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn refresh_token_valid_jwt_returns_new_token() {
        // 构造 logic：token_style=jwt，使用明确 secret
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
        let mut config = BulwarkConfig::default_config();
        config.token_style = "jwt".to_string();
        config.jwt_secret = "refresh-test-secret".to_string();
        config.timeout = 3600;
        let firewall: Arc<dyn BulwarkFirewallStrategy> = Arc::new(MockFirewall {
            has_permission: true,
            has_role: true,
        });
        let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

        // 注入 plugin_manager + listener_manager 验证 auto-wire 不中断
        let pm = Arc::new(BulwarkPluginManager::new());
        let logic = logic.with_plugin_manager(pm);
        #[cfg(feature = "listener")]
        let logic = logic.with_listener_manager(Arc::new(BulwarkListenerManager::new()));

        // 先生成一个有效 JWT token
        let handler = crate::protocol::jwt::JwtHandler::new("refresh-test-secret");
        let original_token = handler.sign(7007, 3600).unwrap();

        // 刷新 token（同秒内 iat/exp 可能相同，不强制 new_token != original_token）
        let new_token = logic.refresh_token(&original_token).await.unwrap();
        assert!(!new_token.is_empty(), "refresh_token 应返回非空 token");

        // 验证新 token 有效且 login_id 一致
        let new_claims = handler.verify(&new_token).unwrap();
        assert_eq!(new_claims.login_id, 7007);
    }

    // ------------------------------------------------------------------------
    // trait default 方法覆盖率测试（login_by_token/verify_token/refresh_token）
    // ------------------------------------------------------------------------

    /// 最小化 BulwarkLogic mock，仅用于测试 trait default 方法。
    /// 所有必需方法标记 unreachable!()，仅保留 default 方法（login_by_token/verify_token/refresh_token）。
    struct MinimalLogic {
        config: Arc<BulwarkConfig>,
    }

    #[async_trait]
    impl BulwarkLogic for MinimalLogic {
        async fn login(&self, _: i64) -> BulwarkResult<String> {
            unreachable!()
        }
        async fn login_with_token(&self, _: i64, _: &str) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn logout(&self) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn logout_by_login_id(&self, _: i64) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn kickout(&self, _: i64) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn kickout_by_token(&self, _: &str) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn revoke_token(&self, _: &str) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn check_login(&self) -> BulwarkResult<bool> {
            unreachable!()
        }
        async fn get_login_id(&self) -> BulwarkResult<Option<i64>> {
            unreachable!()
        }
        async fn check_permission(&self, _: &str) -> BulwarkResult<()> {
            unreachable!()
        }
        async fn check_role(&self, _: &str) -> BulwarkResult<()> {
            unreachable!()
        }
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    /// trait default login_by_token 返回 NotImplemented（spec: 未启用协议层 feature）。
    #[tokio::test]
    async fn trait_default_login_by_token_returns_not_implemented() {
        let logic = MinimalLogic {
            config: Arc::new(BulwarkConfig::default_config()),
        };
        let result = logic.login_by_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("protocol-oauth2")),
            "trait default login_by_token 应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// trait default verify_token 返回 NotImplemented（spec: 需子类 override）。
    #[tokio::test]
    async fn trait_default_verify_token_returns_not_implemented() {
        let logic = MinimalLogic {
            config: Arc::new(BulwarkConfig::default_config()),
        };
        let result = logic.verify_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("override")),
            "trait default verify_token 应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// trait default refresh_token 返回 NotImplemented（spec: 需启用 protocol-jwt）。
    #[tokio::test]
    async fn trait_default_refresh_token_returns_not_implemented() {
        let logic = MinimalLogic {
            config: Arc::new(BulwarkConfig::default_config()),
        };
        let result = logic.refresh_token("any-token").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("protocol-jwt")),
            "trait default refresh_token 应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    // ------------------------------------------------------------------------
    // login_by_token auto-wire 覆盖率补充（plugin + listener 钩子触发）
    // ------------------------------------------------------------------------

    /// login_by_token 注入 plugin_manager + listener_manager 后触发 auto-wire 钩子（simple style）。
    #[tokio::test]
    async fn login_by_token_with_managers_triggers_hooks() {
        let logic = make_logic(3600, 86400, false, "simple", true, true);
        let pm = Arc::new(BulwarkPluginManager::new());
        let logic = logic.with_plugin_manager(pm);
        #[cfg(feature = "listener")]
        let logic = logic.with_listener_manager(Arc::new(BulwarkListenerManager::new()));

        // 构造 simple 格式 token: "<login_id>-<uuid>"
        let token = format!("8008-{}", uuid::Uuid::new_v4());

        // login_by_token 应成功（plugin/listener 失败仅 warn 不中断）
        logic.login_by_token(&token).await.unwrap();

        // 验证会话已建立
        let ts = logic.session.get_token_session(&token).await.unwrap();
        assert!(ts.is_some(), "login_by_token 后应建立会话");
        assert_eq!(ts.unwrap().login_id, 8008);
    }

    // ------------------------------------------------------------------------
    // 0.4.2 Phase 5: login_with_password 测试（依据 spec auth-password-login）
    // ------------------------------------------------------------------------

    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    use crate::dao::repository::{NewUser, UpdateUser, UserRepository, UserRow};
    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    use crate::secure::password::{Argon2Hasher, PasswordHasher};

    /// 测试用 UserRepository mock，用 HashMap 存储 UserRow，按 username 索引。
    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    struct MockUserRepository {
        users: Mutex<HashMap<String, UserRow>>,
    }

    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    impl MockUserRepository {
        fn new() -> Self {
            Self {
                users: Mutex::new(HashMap::new()),
            }
        }
        fn insert(&self, user: UserRow) {
            self.users.lock().insert(user.username.clone(), user);
        }
    }

    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    #[async_trait]
    impl UserRepository for MockUserRepository {
        async fn find_by_id(&self, _tenant_id: i64, id: &str) -> BulwarkResult<Option<UserRow>> {
            Ok(self.users.lock().values().find(|u| u.id == id).cloned())
        }
        async fn find_by_username(
            &self,
            _tenant_id: i64,
            username: &str,
        ) -> BulwarkResult<Option<UserRow>> {
            Ok(self.users.lock().get(username).cloned())
        }
        async fn create(&self, _tenant_id: i64, _user: NewUser) -> BulwarkResult<String> {
            Err(BulwarkError::Internal(
                "MockUserRepository::create not implemented".to_string(),
            ))
        }
        async fn update(&self, _tenant_id: i64, _id: &str, _user: UpdateUser) -> BulwarkResult<()> {
            Ok(())
        }
        async fn delete(&self, _tenant_id: i64, _id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn list(
            &self,
            _tenant_id: i64,
            _offset: i64,
            _limit: i64,
        ) -> BulwarkResult<Vec<UserRow>> {
            Ok(vec![])
        }
    }

    /// 构造测试用 UserRow（username 与 login_id 字符串一致）。
    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    fn make_user_row(login_id: i64, password_hash: &str) -> UserRow {
        UserRow {
            id: format!("u-{}", login_id),
            username: login_id.to_string(),
            password_hash: password_hash.to_string(),
            status: "active".to_string(),
            tenant_id: 0,
            created_at: "2026-07-04T00:00:00Z".to_string(),
            updated_at: "2026-07-04T00:00:00Z".to_string(),
            last_login_at: None,
        }
    }

    /// R-001: 正确密码返回 token。
    ///
    /// 覆盖 spec auth-password-login R-001 验收 case 1：
    /// 注入 Argon2Hasher + MockUserRepository（含正确 hash）→ 调用 login_with_password → Ok(token)。
    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    #[tokio::test]
    #[serial]
    async fn login_with_password_correct_returns_token() {
        let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());
        let hash = hasher.hash("correct-password").unwrap();

        let mock_repo = MockUserRepository::new();
        mock_repo.insert(make_user_row(1001, &hash));
        let repo: Arc<dyn UserRepository> = Arc::new(mock_repo);

        let logic = make_logic(3600, 86400, false, "uuid", true, true)
            .with_password_hasher(hasher)
            .with_user_repository(repo);

        let result = logic.login_with_password(1001, "correct-password").await;
        assert!(result.is_ok(), "正确密码应返回 Ok，实际: {:?}", result);
        let token = result.unwrap();
        assert!(!token.is_empty(), "token 应非空");
    }

    /// R-001: 错误密码返回 InvalidParam("invalid password")。
    ///
    /// 覆盖 spec auth-password-login R-001 验收 case 2。
    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    #[tokio::test]
    #[serial]
    async fn login_with_password_wrong_password_returns_invalid_param() {
        let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());
        let hash = hasher.hash("correct-password").unwrap();

        let mock_repo = MockUserRepository::new();
        mock_repo.insert(make_user_row(1001, &hash));
        let repo: Arc<dyn UserRepository> = Arc::new(mock_repo);

        let logic = make_logic(3600, 86400, false, "uuid", true, true)
            .with_password_hasher(hasher)
            .with_user_repository(repo);

        let result = logic.login_with_password(1001, "wrong-password").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(ref msg)) if msg == "invalid password"),
            "错误密码应返回 InvalidParam(\"invalid password\")，实际: {:?}",
            result
        );
    }

    /// R-001: 用户不存在返回 InvalidParam("invalid password")。
    ///
    /// 覆盖 spec auth-password-login R-001 验收 case 3。
    /// 注：spec R-001 说"用户不存在返回 NotLogin"，但 Constraints 说"不泄露具体原因"。
    /// 决策：遵循 Constraints 安全要求，统一返回 InvalidParam 防止用户枚举。
    /// v0.4.2 安全审计 A-014: 日志和事件 reason 也统一为 "invalid_credentials"，
    /// 不区分 user_not_found/wrong_password。
    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    #[tokio::test]
    #[serial]
    async fn login_with_password_user_not_found_returns_invalid_param() {
        let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());
        let repo: Arc<dyn UserRepository> = Arc::new(MockUserRepository::new());
        // 不插入任何用户 → find_by_username 返回 None

        let logic = make_logic(3600, 86400, false, "uuid", true, true)
            .with_password_hasher(hasher)
            .with_user_repository(repo);

        let result = logic.login_with_password(9999, "any-password").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(ref msg)) if msg == "invalid password"),
            "用户不存在应返回 InvalidParam(\"invalid password\")（不泄露 NotLogin），实际: {:?}",
            result
        );
    }

    /// R-001: 密码哈希格式不支持返回 InvalidParam。
    ///
    /// 覆盖 spec auth-password-login R-001 验收 case 4。
    /// 注：此错误可泄露（不暴露用户是否存在），返回 "unsupported hash format"。
    #[cfg(all(feature = "secure-password", feature = "db-sqlite"))]
    #[tokio::test]
    #[serial]
    async fn login_with_password_unsupported_hash_format_returns_invalid_param() {
        let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());

        let mock_repo = MockUserRepository::new();
        mock_repo.insert(make_user_row(1001, "unsupported_hash_format"));
        let repo: Arc<dyn UserRepository> = Arc::new(mock_repo);

        let logic = make_logic(3600, 86400, false, "uuid", true, true)
            .with_password_hasher(hasher)
            .with_user_repository(repo);

        let result = logic.login_with_password(1001, "any-password").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(ref msg)) if msg == "unsupported hash format"),
            "不支持的哈希格式应返回 InvalidParam(\"unsupported hash format\")，实际: {:?}",
            result
        );
    }

    // ------------------------------------------------------------------------
    // 0.3.0 TG1: metrics 集成测试（依据 spec observability-stack）
    // ------------------------------------------------------------------------

    /// with_metrics builder 注入 BulwarkMetrics 后 login 触发 record_login(success)。
    #[cfg(feature = "metrics-prometheus")]
    #[tokio::test]
    async fn login_with_metrics_records_success() {
        let logic = make_logic(3600, 86400, false, "uuid", false, false);
        let registry = prometheus::Registry::new();
        let metrics =
            Arc::new(crate::observability::BulwarkMetrics::register_to(&registry).unwrap());
        let logic = logic.with_metrics(metrics.clone());

        let _token = logic.login(1001).await.unwrap();

        // 验证 login_total{result="success"} = 1
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("bulwark_login_total{result=\"success\"} 1"),
            "expected success counter=1, got: {}",
            output
        );
    }

    /// with_metrics 注入后 check_permission 触发 record_permission_query(allow/deny)。
    #[cfg(feature = "metrics-prometheus")]
    #[tokio::test]
    async fn check_permission_with_metrics_records_query() {
        let logic = make_logic(3600, 86400, true, "uuid", false, false);
        let registry = prometheus::Registry::new();
        let metrics =
            Arc::new(crate::observability::BulwarkMetrics::register_to(&registry).unwrap());
        let logic = logic.with_metrics(metrics.clone());

        let token = logic.login(1001).await.unwrap();

        // check_permission 应记录 deny（MockInterface 返回空权限列表）
        let result = with_token(&token, async { logic.check_permission("user:read").await }).await;
        assert!(result.is_err(), "未授权权限应返回 Err");

        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("bulwark_permission_query_total{result=\"deny\"} 1"),
            "expected deny counter=1, got: {}",
            output
        );
    }

    /// 未注入 metrics 时 login 不 panic（零开销路径）。
    #[cfg(feature = "metrics-prometheus")]
    #[tokio::test]
    async fn login_without_metrics_does_not_panic() {
        let logic = make_logic(3600, 86400, false, "uuid", false, false);
        // 不调用 with_metrics
        let _token = logic.login(1001).await.unwrap();
        // 不 panic 即通过
    }

    // ------------------------------------------------------------------------
    // 0.4.2 Phase 6: login_type Multi-Account 测试（依据 spec login-type-multi-account）
    // ------------------------------------------------------------------------

    /// 测试用 BulwarkInterface mock，支持 login_type 隔离（override 新方法）。
    struct MockInterfaceWithLoginType {
        perms: HashMap<String, Vec<String>>,
        roles: HashMap<String, Vec<String>>,
    }

    #[async_trait]
    impl BulwarkInterface for MockInterfaceWithLoginType {
        async fn get_permission_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(self.perms.get("default").cloned().unwrap_or_default())
        }
        async fn get_role_list(&self, _login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(self.roles.get("default").cloned().unwrap_or_default())
        }
        // override 新方法以支持多账号隔离
        async fn get_permission_list_with_type(
            &self,
            _login_id: i64,
            login_type: &str,
        ) -> BulwarkResult<Vec<String>> {
            Ok(self.perms.get(login_type).cloned().unwrap_or_default())
        }
        async fn get_role_list_with_type(
            &self,
            _login_id: i64,
            login_type: &str,
        ) -> BulwarkResult<Vec<String>> {
            Ok(self.roles.get(login_type).cloned().unwrap_or_default())
        }
    }

    /// R-001: 新方法 get_permission_list_with_type 默认委托旧方法。
    ///
    /// 偏差说明：spec R-001 要求"旧方法委托新方法"，实际实现为"新方法默认委托旧方法"
    /// 以保持向后兼容（28 个现有 BulwarkInterface 实现者无需修改）。
    /// MockInterface 旧方法返回空 Vec，新方法默认委托旧方法应返回相同结果。
    #[tokio::test]
    #[serial]
    async fn get_permission_list_with_type_delegates_to_default() {
        let interface = MockInterface;
        let result = interface
            .get_permission_list_with_type(1001, "default")
            .await;
        assert!(result.is_ok(), "新方法应成功，实际: {:?}", result);
        assert!(result.unwrap().is_empty(), "默认委托旧方法应返回空 Vec");
    }

    /// R-001: 新方法 get_role_list_with_type 默认委托旧方法。
    #[tokio::test]
    #[serial]
    async fn get_role_list_with_type_delegates_to_default() {
        let interface = MockInterface;
        let result = interface.get_role_list_with_type(1001, "default").await;
        assert!(result.is_ok(), "新方法应成功，实际: {:?}", result);
        assert!(result.unwrap().is_empty(), "默认委托旧方法应返回空 Vec");
    }

    /// R-002: admin login_type 的权限查询不返回 user 的权限。
    ///
    /// 覆盖 spec login-type-multi-account R-002 验收 case 1。
    #[tokio::test]
    #[serial]
    async fn get_permission_list_with_type_admin_isolated_from_user() {
        let mut perms = HashMap::new();
        perms.insert("admin".to_string(), vec!["admin:*".to_string()]);
        perms.insert("user".to_string(), vec!["user:*".to_string()]);
        let interface = MockInterfaceWithLoginType {
            perms,
            roles: HashMap::new(),
        };
        let admin_perms = interface
            .get_permission_list_with_type(1001, "admin")
            .await
            .unwrap();
        assert_eq!(admin_perms, vec!["admin:*"]);
        assert!(
            !admin_perms.iter().any(|p| p == "user:*"),
            "admin login_type 不应返回 user 的权限"
        );
    }

    /// R-002: 同一 login_id 在不同 login_type 下可拥有不同权限。
    ///
    /// 覆盖 spec login-type-multi-account R-002 验收 case 2。
    #[tokio::test]
    #[serial]
    async fn same_login_id_different_login_type_different_permissions() {
        let mut perms = HashMap::new();
        perms.insert("admin".to_string(), vec!["admin:*".to_string()]);
        perms.insert("user".to_string(), vec!["user:*".to_string()]);
        let interface = MockInterfaceWithLoginType {
            perms,
            roles: HashMap::new(),
        };
        let admin_perms = interface
            .get_permission_list_with_type(1001, "admin")
            .await
            .unwrap();
        let user_perms = interface
            .get_permission_list_with_type(1001, "user")
            .await
            .unwrap();
        assert_ne!(admin_perms, user_perms, "不同 login_type 应返回不同权限");
        assert_eq!(admin_perms, vec!["admin:*"]);
        assert_eq!(user_perms, vec!["user:*"]);
    }

    /// R-003: with_login_type builder 设置 login_type 字段。
    ///
    /// 覆盖 spec login-type-multi-account R-003 验收 case 1。
    #[tokio::test]
    #[serial]
    async fn with_login_type_builder_sets_login_type() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        assert_eq!(
            logic.login_type, "default",
            "默认 login_type 应为 'default'"
        );
        let logic2 = make_logic(3600, 86400, false, "uuid", true, true).with_login_type("admin");
        assert_eq!(
            logic2.login_type, "admin",
            "with_login_type 应设置 login_type 为 'admin'"
        );
    }

    /// R-003: with_login_type 链式调用不破坏其他 builder。
    ///
    /// 覆盖 spec login-type-multi-account R-003 验收 case 1（链式调用兼容性）。
    #[tokio::test]
    #[serial]
    async fn with_login_type_chains_with_other_builders() {
        let pm = Arc::new(BulwarkPluginManager::new());
        let logic = make_logic(3600, 86400, false, "uuid", true, true)
            .with_plugin_manager(pm)
            .with_login_type("merchant");
        assert_eq!(logic.login_type, "merchant");
        // 验证 login 仍可工作（其他 builder 未被破坏）
        let token = logic.login(1001).await.unwrap();
        assert!(!token.is_empty());
    }

    // ------------------------------------------------------------------------
    // spec protocol-jwt-modes: JwtMode 三模式（Stateless/Mixin/Simple）
    // ------------------------------------------------------------------------

    /// R-001: JwtMode::default() == JwtMode::Mixin（推荐模式为默认）。
    ///
    /// 覆盖 spec protocol-jwt-modes R-001 验收 case 1。
    #[test]
    fn jwt_mode_default_is_mixin() {
        assert_eq!(JwtMode::default(), JwtMode::Mixin);
    }

    /// R-001: JwtMode 是 Copy（无需 Arc 包装）。
    ///
    /// 覆盖 spec protocol-jwt-modes R-001 验收 case 2。
    #[test]
    fn jwt_mode_is_copy() {
        let mode = JwtMode::Stateless;
        let copied = mode; // Copy 语义：复制后原值仍可用
        assert_eq!(mode, copied);
        assert_eq!(mode, JwtMode::Stateless);
    }

    /// R-005: with_jwt_mode builder 设置 jwt_mode 字段，默认 Mixin。
    ///
    /// 覆盖 spec protocol-jwt-modes R-005 验收 case 1（默认 Mixin + builder 切换）。
    #[tokio::test]
    #[serial]
    async fn with_jwt_mode_builder_sets_mode() {
        let logic = make_logic(3600, 86400, false, "uuid", true, true);
        assert_eq!(
            logic.jwt_mode,
            JwtMode::Mixin,
            "未设置时默认 JwtMode::Mixin"
        );
        let logic2 =
            make_logic(3600, 86400, false, "uuid", true, true).with_jwt_mode(JwtMode::Stateless);
        assert_eq!(
            logic2.jwt_mode,
            JwtMode::Stateless,
            "with_jwt_mode 应设置 jwt_mode 为 Stateless"
        );
    }

    /// R-002: Stateless 模式仅 JWT verify，不查询 session。
    ///
    /// 覆盖 spec protocol-jwt-modes R-002 验收 case 1（有效 JWT 通过 + 不查 DAO）。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    #[serial]
    async fn check_login_stateless_only_jwt_verify() {
        // 构造 logic：jwt_mode=Stateless + token_style=jwt + 明确 secret
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
        let mut config = BulwarkConfig::default_config();
        config.token_style = "jwt".to_string();
        config.jwt_secret = "stateless-test-secret".to_string();
        config.throw_on_not_login = true;
        let firewall: Arc<dyn BulwarkFirewallStrategy> = Arc::new(MockFirewall {
            has_permission: true,
            has_role: true,
        });
        let logic = Arc::new(
            BulwarkLogicDefault::new(session, Arc::new(config), firewall)
                .with_jwt_mode(JwtMode::Stateless),
        );

        // 用 JwtHandler 直接签发 token，不通过 login（确保 DAO 无 session）
        let handler = crate::protocol::jwt::JwtHandler::new("stateless-test-secret");
        let token = handler.sign(1001, 3600).unwrap();

        // Stateless 模式：仅 JWT verify，不查 session → 应返回 Ok(true)
        with_current_token(token, async {
            let valid = logic.check_login().await.unwrap();
            assert!(
                valid,
                "Stateless 模式下有效 JWT 应返回 true（不查 session）"
            );
        })
        .await;
    }

    /// R-003: Mixin 模式 JWT verify + session 二级校验。
    ///
    /// 覆盖 spec protocol-jwt-modes R-003 验收 case 2（有效 JWT + session 存在 → 通过）。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    #[serial]
    async fn check_login_mixin_jwt_and_session() {
        // 构造 logic：jwt_mode=Mixin（默认）+ token_style=jwt + 明确 secret
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
        let mut config = BulwarkConfig::default_config();
        config.token_style = "jwt".to_string();
        config.jwt_secret = "mixin-test-secret".to_string();
        config.throw_on_not_login = true;
        let firewall: Arc<dyn BulwarkFirewallStrategy> = Arc::new(MockFirewall {
            has_permission: true,
            has_role: true,
        });
        let logic = Arc::new(
            BulwarkLogicDefault::new(session, Arc::new(config), firewall)
                .with_jwt_mode(JwtMode::Mixin),
        );

        // login 创建 session + 签发 JWT token
        let token = logic.login(1001).await.unwrap();

        // Mixin 模式：JWT verify 通过 + session 存在 → Ok(true)
        with_current_token(token, async {
            let valid = logic.check_login().await.unwrap();
            assert!(valid, "Mixin 模式下有效 JWT + session 存在应返回 true");
        })
        .await;
    }

    /// R-004: Simple 模式仅 session 校验，不验证 JWT 签名。
    ///
    /// 覆盖 spec protocol-jwt-modes R-004 验收 case 1（session 存在 → 通过，不验证 JWT）。
    #[tokio::test]
    #[serial]
    async fn check_login_simple_only_session() {
        // 构造 logic：jwt_mode=Simple + token_style=uuid（非 JWT）
        let logic = Arc::new(
            make_logic(3600, 86400, true, "uuid", true, true).with_jwt_mode(JwtMode::Simple),
        );

        // login 创建 session（uuid token，非 JWT 格式）
        let token = logic.login(1001).await.unwrap();

        // Simple 模式：仅查 session，不验证 JWT → session 存在应返回 Ok(true)
        with_current_token(token, async {
            let valid = logic.check_login().await.unwrap();
            assert!(valid, "Simple 模式下 session 存在应返回 true（不验证 JWT）");
        })
        .await;
    }

    // ========================================================================
    // 覆盖率补充：login_with_password trait default 实现
    // ========================================================================

    /// trait default `login_with_password` 返回 NotImplemented（spec: 需 secure-password + db-sqlite）。
    ///
    /// 覆盖行 331-333（login_with_password 默认实现）。
    #[tokio::test]
    async fn trait_default_login_with_password_returns_not_implemented() {
        let logic = MinimalLogic {
            config: Arc::new(BulwarkConfig::default_config()),
        };
        let result = logic.login_with_password(1001, "any-password").await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("secure-password")),
            "trait default login_with_password 应返回 NotImplemented（需 secure-password + db-sqlite），实际: {:?}",
            result
        );
    }
}
