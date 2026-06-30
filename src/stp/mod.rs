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
use crate::error::{BulwarkError, BulwarkResult};
use crate::session::BulwarkSession;
use crate::strategy::BulwarkFirewallStrategy;
use async_trait::async_trait;
use std::future::Future;
use std::sync::Arc;

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
        }
    }

    /// 根据 `config.token_style` 生成 token。
    ///
    /// - `uuid`: UUID v4（36 字符，含连字符）
    /// - `random_64`: 两个 simple UUID 拼接（64 字符）
    /// - `simple`: simple UUID（32 字符）
    /// - `jwt`: 需启用 `protocol-jwt` feature（0.1.0 暂不支持，抛错）
    fn generate_token(&self) -> BulwarkResult<String> {
        match self.config.token_style.as_str() {
            "uuid" => Ok(uuid::Uuid::new_v4().to_string()),
            "random_64" => Ok(format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            )),
            "simple" => Ok(uuid::Uuid::new_v4().simple().to_string()),
            "jwt" => Err(BulwarkError::Config(
                "jwt token_style 需启用 protocol-jwt feature".to_string(),
            )),
            other => Err(BulwarkError::Config(format!(
                "unknown token_style: {}",
                other
            ))),
        }
    }
}

#[async_trait]
impl BulwarkLogic for BulwarkLogicDefault {
    async fn login(&self, login_id: i64) -> BulwarkResult<String> {
        let token = self.generate_token()?;
        self.login_with_token(login_id, &token).await?;
        Ok(token)
    }

    async fn login_with_token(&self, login_id: i64, token: &str) -> BulwarkResult<()> {
        self.session.create(login_id, token).await
    }

    async fn logout(&self) -> BulwarkResult<()> {
        // 未登录时幂等返回 Ok（不抛错）
        match current_token() {
            Ok(token) => self.session.logout(&token).await,
            Err(_) => Ok(()),
        }
    }

    async fn logout_by_login_id(&self, login_id: i64) -> BulwarkResult<()> {
        self.session.logout_by_login_id(login_id).await
    }

    async fn kickout(&self, login_id: i64) -> BulwarkResult<()> {
        // kickout 语义等同 logout_by_login_id
        self.session.logout_by_login_id(login_id).await
    }

    async fn kickout_by_token(&self, token: &str) -> BulwarkResult<()> {
        // kickout_by_token 语义等同 logout(token)
        self.session.logout(token).await
    }

    async fn check_login(&self) -> BulwarkResult<bool> {
        let valid = match current_token() {
            Ok(token) => self.session.is_valid(&token).await?,
            Err(_) => false, // 未设置 token = 未登录
        };
        if !valid && self.config.throw_on_not_login {
            return Err(BulwarkError::Session("未登录".to_string()));
        }
        Ok(valid)
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
        if has_role {
            Ok(())
        } else {
            Err(BulwarkError::NotRole(role.to_string()))
        }
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

impl BulwarkUtil {
    /// 执行登录：生成 token + 创建会话。
    ///
    /// # 参数
    /// - `id`: 登录主体标识。
    ///
    /// # 返回
    /// 生成的 token 字符串。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - token 生成或会话创建失败：透传 `BulwarkError`。
    pub async fn login(id: i64) -> BulwarkResult<String> {
        crate::manager::BulwarkManager::logic()?.login(id).await
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
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn logout_by_login_id(login_id: i64) -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .logout_by_login_id(login_id)
            .await
    }

    /// 踢出用户：按账号踢出（语义等同 logout_by_login_id）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkManager` 未初始化：`BulwarkError::Session`。
    /// - 会话销毁失败：透传 `BulwarkError`。
    pub async fn kickout(login_id: i64) -> BulwarkResult<()> {
        crate::manager::BulwarkManager::logic()?
            .kickout(login_id)
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
}

// ============================================================================
// 测试（依据 spec stp-core-api 所有 scenario）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::BulwarkDao;
    use async_trait::async_trait;
    use parking_lot::Mutex;
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
}
