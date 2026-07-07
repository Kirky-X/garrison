//! 注解模块，定义鉴权注解枚举与 axum extractor。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的注解体系（`@SaCheckLogin` 等），
//! Rust 中以枚举变体表达（用于 router 中间件配置），
//! 同时提供 axum extractor（`CheckLogin` 等）用于 handler 参数提取。
//!
//! ## 设计
//!
//! - `Annotation` 枚举：保留用于 router 中间件配置
//! - marker trait（`RoleName` / `PermissionName` / `ModeSpec`）：通过关联常量表达类型级参数
//! - extractor struct（`CheckLogin` 等）：实现 `FromRequestParts`，仅在 `web-axum` feature 下编译

// ============================================================================
// Marker traits（用于泛型 extractor 的类型级参数，always compiled）
// ============================================================================

/// 角色 marker trait，通过关联常量 `NAME` 指定角色名。
///
/// 业务方定义类型实现此 trait，用作 `CheckRole<R>` 的类型参数：
/// ```ignore
/// struct AdminRole;
/// impl RoleName for AdminRole { const NAME: &'static str = "admin"; }
/// async fn handler(CheckRole::<AdminRole>: CheckRole<AdminRole>) { ... }
/// ```
pub trait RoleName: Send + Sync {
    /// 角色名称（如 "admin"）。
    const NAME: &'static str;
}

/// 权限 marker trait，通过关联常量 `NAME` 指定权限名。
///
/// 业务方定义类型实现此 trait，用作 `CheckPermission<P>` 的类型参数。
pub trait PermissionName: Send + Sync {
    /// 权限名称（如 "user:read"）。
    const NAME: &'static str;
}

/// 模式 marker trait，通过关联常量 `STRICT` 指定是否严格模式。
///
/// - `STRICT=true`：未登录抛 `NotLogin` 异常（严格模式）
/// - `STRICT=false`：未登录不抛错，允许匿名访问（宽松模式）
pub trait ModeSpec: Send + Sync {
    /// 是否严格模式。
    const STRICT: bool;
}

// ============================================================================
// 预定义模式（always compiled）
// ============================================================================

/// 严格模式：未登录抛 `NotLogin` 异常。
pub struct Strict;

impl ModeSpec for Strict {
    const STRICT: bool = true;
}

/// 宽松模式：未登录不抛错，允许匿名访问。
pub struct Loose;

impl ModeSpec for Loose {
    const STRICT: bool = false;
}

// ============================================================================
// Annotation 枚举（保留用于 router 中间件配置，always compiled）
// ============================================================================

/// 鉴权注解枚举，列出 12 个核心注解。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的注解集合。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Annotation {
    /// 检查登录（对应 `@SaCheckLogin`）。
    CheckLogin,

    /// 检查权限（对应 `@SaCheckPermission`）。
    CheckPermission(String),

    /// 检查角色（对应 `@SaCheckRole`）。
    CheckRole(String),

    /// 检查二级认证（对应 `@SaCheckSafe`）。
    CheckSafe,

    /// 检查是否被禁用（对应 `@SaCheckDisable`）。
    CheckDisable,

    /// OR 逻辑组合（对应 `@SaCheckOr`）。
    CheckOr,

    /// AND 逻辑组合（对应 `@SaCheckAnd`）。
    CheckAnd,

    /// NOT 逻辑组合（对应 `@SaCheckNot`）。
    CheckNot,

    /// 忽略鉴权（对应 `@SaIgnore`）。
    Ignore,

    /// Basic 认证检查（对应 `@SaCheckBasicAuth`）。
    CheckBasicAuth,

    /// Digest 认证检查（对应 `@SaCheckDigestAuth`）。
    CheckDigestAuth,

    /// 签名检查（对应 `@SaCheckSign`）。
    CheckSign,
}

impl Annotation {
    /// 获取注解的字符串名称。
    ///
    /// 返回对应 Sa-Token 注解的字符串标识（用于 router 中间件配置与日志记录）。
    pub fn name(&self) -> &'static str {
        match self {
            Annotation::CheckLogin => "CheckLogin",
            Annotation::CheckPermission(_) => "CheckPermission",
            Annotation::CheckRole(_) => "CheckRole",
            Annotation::CheckSafe => "CheckSafe",
            Annotation::CheckDisable => "CheckDisable",
            Annotation::CheckOr => "CheckOr",
            Annotation::CheckAnd => "CheckAnd",
            Annotation::CheckNot => "CheckNot",
            Annotation::Ignore => "Ignore",
            Annotation::CheckBasicAuth => "CheckBasicAuth",
            Annotation::CheckDigestAuth => "CheckDigestAuth",
            Annotation::CheckSign => "CheckSign",
        }
    }
}

// ============================================================================
// axum extractor（cfg(feature = "web-axum")）
// ============================================================================

#[cfg(feature = "web-axum")]
mod extractors {
    use super::{ModeSpec, PermissionName, RoleName};
    use crate::config::BulwarkConfig;
    use crate::context::token_extract::strip_bearer_prefix;
    use crate::error::BulwarkError;
    use crate::stp::{with_current_token, BulwarkUtil};
    use axum::extract::FromRequestParts;
    use axum::http::header;
    use axum::http::request::Parts;
    use std::marker::PhantomData;

    // ----------------------------------------------------------------
    // 辅助函数：从请求 parts 提取 token（按 config 决定提取顺序与字段名）
    // ----------------------------------------------------------------

    /// 从请求 parts 提取 token（依据 RFC 7235 大小写不敏感匹配 `Bearer` 前缀）。
    ///
    /// 提取顺序（受 config 开关控制）：
    /// 1. 若 `is_read_header=true`：
    ///    a. `Authorization: Bearer <token>` header（Bearer 大小写不敏感，依据 RFC 7235）
    ///    b. 自定义 `token_name` header（如 `bulwark_token: <token>`）
    /// 2. 若 `is_read_cookie=true`：
    ///    `Cookie: <token_name>=<token>` cookie
    fn extract_token_from_parts(parts: &Parts, config: &BulwarkConfig) -> Option<String> {
        // 1. 从 header 提取
        if config.is_read_header {
            // a. Authorization: Bearer <token>（RFC 7235 大小写不敏感）
            if let Some(auth) = parts.headers.get(header::AUTHORIZATION) {
                if let Ok(auth_str) = auth.to_str() {
                    // 大小写不敏感匹配 "Bearer " 前缀
                    if let Some(token) = strip_bearer_prefix(auth_str) {
                        return Some(token.to_string());
                    }
                }
            }
            // b. 自定义 token_name header
            if let Some(token) = parts.headers.get(config.token_name.as_str()) {
                if let Ok(token_str) = token.to_str() {
                    return Some(token_str.to_string());
                }
            }
        }
        // 2. 从 cookie 提取
        if config.is_read_cookie {
            if let Some(cookie) = parts.headers.get(header::COOKIE) {
                if let Ok(cookie_str) = cookie.to_str() {
                    let cookie_prefix = format!("{}=", config.token_name);
                    for c in cookie_str.split(';') {
                        let c = c.trim();
                        if let Some(rest) = c.strip_prefix(&cookie_prefix) {
                            return Some(rest.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    // ----------------------------------------------------------------
    // 辅助函数：执行登录校验（严格模式，未登录返回 NotLogin）
    // ----------------------------------------------------------------

    /// 执行登录校验：调用 `BulwarkUtil::check_login()`，未登录返回 `NotLogin`。
    ///
    /// - `throw_on_not_login=true`：check_login 返回 Err(Session)，`?` 透传
    /// - `throw_on_not_login=false`：check_login 返回 Ok(false)，手动返回 Err(NotLogin)
    async fn enforce_login() -> Result<(), BulwarkError> {
        let logged_in = BulwarkUtil::check_login().await?;
        if !logged_in {
            return Err(BulwarkError::NotLogin("未登录".to_string()));
        }
        Ok(())
    }

    // ----------------------------------------------------------------
    // CheckLogin
    // ----------------------------------------------------------------

    /// 登录校验 extractor（对应 `@SaCheckLogin`）。
    ///
    /// 从请求中提取 token 并校验登录状态。校验失败返回 `BulwarkError`。
    pub struct CheckLogin;

    /// 实现 `FromRequestParts`：从请求 parts 提取 token（若有），调用 `enforce_login` 校验登录状态。
    ///
    /// # 错误
    /// - `BulwarkError::NotLogin`：未登录且 `throw_on_not_login=false`。
    /// - `BulwarkError::Session`：未登录且 `throw_on_not_login=true`（严格模式）。
    impl<S: Send + Sync> FromRequestParts<S> for CheckLogin {
        type Rejection = BulwarkError;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            let config = BulwarkUtil::config()?;
            if let Some(t) = extract_token_from_parts(parts, &config) {
                with_current_token(t, enforce_login()).await?;
            } else {
                enforce_login().await?;
            }
            Ok(CheckLogin)
        }
    }

    // ----------------------------------------------------------------
    // CheckRole<R>
    // ----------------------------------------------------------------

    /// 角色校验 extractor（对应 `@SaCheckRole`）。
    ///
    /// 通过泛型参数 `R: RoleName` 指定角色名，校验当前用户是否持有该角色。
    pub struct CheckRole<R: RoleName>(PhantomData<R>);

    /// 实现 `FromRequestParts`：从请求 parts 提取 token（若有），调用 `BulwarkUtil::check_role(R::NAME)` 校验角色。
    ///
    /// # 错误
    /// - `BulwarkError::NotRole`：当前用户未持有角色 `R::NAME`。
    /// - `BulwarkError::NotLogin`：未登录（严格模式下）。
    impl<R: RoleName, S: Send + Sync> FromRequestParts<S> for CheckRole<R> {
        type Rejection = BulwarkError;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            let config = BulwarkUtil::config()?;
            if let Some(t) = extract_token_from_parts(parts, &config) {
                with_current_token(t, async {
                    BulwarkUtil::check_role(R::NAME).await?;
                    Ok::<(), BulwarkError>(())
                })
                .await?;
            } else {
                BulwarkUtil::check_role(R::NAME).await?;
            }
            Ok(CheckRole(PhantomData))
        }
    }

    // ----------------------------------------------------------------
    // CheckPermission<P>
    // ----------------------------------------------------------------

    /// 权限校验 extractor（对应 `@SaCheckPermission`）。
    ///
    /// 通过泛型参数 `P: PermissionName` 指定权限名，校验当前用户是否持有该权限。
    pub struct CheckPermission<P: PermissionName>(PhantomData<P>);

    /// 实现 `FromRequestParts`：从请求 parts 提取 token（若有），调用 `BulwarkUtil::check_permission(P::NAME)` 校验权限。
    ///
    /// # 错误
    /// - `BulwarkError::NotPermission`：当前用户未持有权限 `P::NAME`。
    /// - `BulwarkError::NotLogin`：未登录（严格模式下）。
    impl<P: PermissionName, S: Send + Sync> FromRequestParts<S> for CheckPermission<P> {
        type Rejection = BulwarkError;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            let config = BulwarkUtil::config()?;
            if let Some(t) = extract_token_from_parts(parts, &config) {
                with_current_token(t, async {
                    BulwarkUtil::check_permission(P::NAME).await?;
                    Ok::<(), BulwarkError>(())
                })
                .await?;
            } else {
                BulwarkUtil::check_permission(P::NAME).await?;
            }
            Ok(CheckPermission(PhantomData))
        }
    }

    // ----------------------------------------------------------------
    // Ignore
    // ----------------------------------------------------------------

    /// 忽略鉴权 extractor（对应 `@SaIgnore`）。
    ///
    /// 不执行任何校验，直接返回 `Ok`，用于路由配置标记。
    pub struct Ignore;

    /// 实现 `FromRequestParts`：不执行任何校验，直接返回 `Ok(Ignore)`。
    impl<S: Send + Sync> FromRequestParts<S> for Ignore {
        type Rejection = BulwarkError;

        async fn from_request_parts(
            _parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Ok(Ignore)
        }
    }

    // ----------------------------------------------------------------
    // Mode<M>
    // ----------------------------------------------------------------

    /// 模式 extractor（对应严格/宽松模式）。
    ///
    /// 通过泛型参数 `M: ModeSpec` 指定模式：
    /// - `Mode<Strict>`：未登录抛 `NotLogin` 异常
    /// - `Mode<Loose>`：未登录不抛错，允许匿名访问
    pub struct Mode<M: ModeSpec>(PhantomData<M>);

    /// 执行模式校验：根据 `M::STRICT` 决定行为。
    async fn enforce_mode<M: ModeSpec>() -> Result<(), BulwarkError> {
        if M::STRICT {
            enforce_login().await
        } else {
            // 宽松模式：忽略登录状态
            let _ = BulwarkUtil::check_login().await;
            Ok(())
        }
    }

    /// 实现 `FromRequestParts`：从请求 parts 提取 token（若有），调用 `enforce_mode::<M>` 执行模式校验。
    ///
    /// # 错误
    /// - `Mode<Strict>`：未登录时返回 `BulwarkError::NotLogin`。
    /// - `Mode<Loose>`：不返回错误（宽松模式允许匿名访问）。
    impl<M: ModeSpec, S: Send + Sync> FromRequestParts<S> for Mode<M> {
        type Rejection = BulwarkError;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            let config = BulwarkUtil::config()?;
            if let Some(t) = extract_token_from_parts(parts, &config) {
                with_current_token(t, enforce_mode::<M>()).await?;
            } else {
                enforce_mode::<M>().await?;
            }
            Ok(Mode(PhantomData))
        }
    }

    // ----------------------------------------------------------------
    // BulwarkPrincipal extractor（携带 login_id，依据 spec web-adapters D12）
    // ----------------------------------------------------------------

    /// 登录主体 extractor（从 `Authorization: Bearer <token>` 解析 `login_id`）。
    ///
    /// 与 actix-web / warp 版本完全对齐：
    /// - 无 token → `BulwarkError::NotLogin("未提供 token")`
    /// - token 无效或会话不存在 → `BulwarkError::NotLogin("token 无效或会话不存在")`
    /// - 有效 token → `Ok(BulwarkPrincipal { login_id })`
    ///
    /// 与 `CheckLogin` extractor 的区别：
    /// - `CheckLogin` 仅校验登录状态，返回 unit-like struct
    /// - `BulwarkPrincipal` 携带 `login_id` 字段，handler 可直接读取当前用户身份
    impl<S: Send + Sync> FromRequestParts<S> for crate::context::BulwarkPrincipal {
        type Rejection = BulwarkError;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            let config = BulwarkUtil::config()?;
            let token = extract_token_from_parts(parts, &config)
                .ok_or_else(|| BulwarkError::NotLogin("未提供 token".to_string()))?;

            let login_id = BulwarkUtil::get_login_id_by_token(&token)
                .await?
                .ok_or_else(|| BulwarkError::NotLogin("token 无效或会话不存在".to_string()))?;

            Ok(crate::context::BulwarkPrincipal { login_id })
        }
    }

    // ----------------------------------------------------------------
    // TenantContext extractor（cfg tenant-isolation，依据 spec web-adapters D12）
    // ----------------------------------------------------------------

    /// 租户上下文 extractor（从 `X-Tenant-Id` header 解析 `tenant_id`）。
    ///
    /// 与 actix-web / warp 版本完全对齐：
    /// - 缺失 `X-Tenant-Id` → `BulwarkError::Config("X-Tenant-Id header missing")`
    /// - 非数字 → `BulwarkError::Config("X-Tenant-Id 不是合法的 i64: <raw>")`
    /// - 合法 i64 → `Ok(TenantContext { tenant_id, resolved_from: TenantSource::Header })`
    ///
    /// 不依赖 `BulwarkManager`：仅做 header 解析，不查会话/权限。
    #[cfg(feature = "tenant-isolation")]
    impl<S: Send + Sync> FromRequestParts<S> for crate::context::tenant::TenantContext {
        type Rejection = BulwarkError;

        async fn from_request_parts(
            parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            let raw = parts
                .headers
                .get("x-tenant-id")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| BulwarkError::Config("X-Tenant-Id header missing".into()))?;

            let tenant_id: i64 = raw.parse().map_err(|_| {
                BulwarkError::Config(format!("X-Tenant-Id 不是合法的 i64: {}", raw))
            })?;

            Ok(crate::context::tenant::TenantContext {
                tenant_id,
                resolved_from: crate::context::tenant::TenantSource::Header,
            })
        }
    }
}

#[cfg(feature = "web-axum")]
pub use extractors::{CheckLogin, CheckPermission, CheckRole, Ignore, Mode};

// ============================================================================
// 测试（cfg all(test, feature = "web-axum")）
// ============================================================================

#[cfg(all(test, feature = "web-axum"))]
mod tests {
    use super::*;
    use crate::dao::BulwarkDao;
    use crate::error::BulwarkError;
    use crate::manager::BulwarkManager;
    use crate::stp::{with_current_token, BulwarkInterface, BulwarkUtil};
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::extract::FromRequestParts;
    use axum::http::Request;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use parking_lot::Mutex;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    // ----------------------------------------------------------------
    // MockDao（复用 manager 测试的 HashMap + Instant 模拟 TTL）
    // ----------------------------------------------------------------

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
        async fn get(&self, key: &str) -> crate::error::BulwarkResult<Option<String>> {
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

        async fn set(
            &self,
            key: &str,
            value: &str,
            ttl_seconds: u64,
        ) -> crate::error::BulwarkResult<()> {
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

        async fn update(&self, key: &str, value: &str) -> crate::error::BulwarkResult<()> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((existing, _)) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> crate::error::BulwarkResult<()> {
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

        async fn delete(&self, key: &str) -> crate::error::BulwarkResult<()> {
            self.store.lock().remove(key);
            Ok(())
        }
    }

    // ----------------------------------------------------------------
    // MockInterface（权限/角色数据回调）
    // ----------------------------------------------------------------

    struct MockInterface {
        permissions: HashMap<i64, Vec<String>>,
        roles: HashMap<i64, Vec<String>>,
    }

    impl MockInterface {
        fn new() -> Self {
            Self {
                permissions: HashMap::new(),
                roles: HashMap::new(),
            }
        }

        fn with_permission(mut self, login_id: i64, perms: &[&str]) -> Self {
            self.permissions
                .insert(login_id, perms.iter().map(|s| s.to_string()).collect());
            self
        }

        fn with_role(mut self, login_id: i64, roles: &[&str]) -> Self {
            self.roles
                .insert(login_id, roles.iter().map(|s| s.to_string()).collect());
            self
        }
    }

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(
            &self,
            login_id: i64,
        ) -> crate::error::BulwarkResult<Vec<String>> {
            Ok(self.permissions.get(&login_id).cloned().unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: i64) -> crate::error::BulwarkResult<Vec<String>> {
            Ok(self.roles.get(&login_id).cloned().unwrap_or_default())
        }
    }

    // ----------------------------------------------------------------
    // 测试用 marker 类型
    // ----------------------------------------------------------------

    struct AdminRole;
    impl RoleName for AdminRole {
        const NAME: &'static str = "admin";
    }

    struct UserRead;
    impl PermissionName for UserRead {
        const NAME: &'static str = "user:read";
    }

    // ----------------------------------------------------------------
    // 辅助函数
    // ----------------------------------------------------------------

    /// 创建测试配置（throw_on_not_login 可配置）。
    fn make_config(throw_on_not_login: bool) -> crate::config::BulwarkConfig {
        let mut config = crate::config::BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = throw_on_not_login;
        config
    }

    /// 初始化 BulwarkManager（带权限/角色数据）。
    fn init_manager(
        throw_on_not_login: bool,
        permissions: &[(i64, &[&str])],
        roles: &[(i64, &[&str])],
    ) {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config(throw_on_not_login));
        let mut interface = MockInterface::new();
        for (id, perms) in permissions {
            interface = interface.with_permission(*id, perms);
        }
        for (id, roles) in roles {
            interface = interface.with_role(*id, roles);
        }
        let interface: Arc<dyn BulwarkInterface> = Arc::new(interface);
        BulwarkManager::init(dao, config, interface).unwrap();
    }

    /// 构建空的 axum Parts（无 header）。
    fn make_parts() -> axum::http::request::Parts {
        let req = Request::builder()
            .method("GET")
            .uri("/protected")
            .body(Body::empty())
            .unwrap();
        req.into_parts().0
    }

    /// 构建带 Authorization: Bearer header 的 axum Parts。
    fn make_parts_with_bearer(token: &str) -> axum::http::request::Parts {
        let req = Request::builder()
            .method("GET")
            .uri("/protected")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        req.into_parts().0
    }

    /// 构建带 bulwark_token header 的 axum Parts。
    fn make_parts_with_bulwark_header(token: &str) -> axum::http::request::Parts {
        let req = Request::builder()
            .method("GET")
            .uri("/protected")
            .header("bulwark_token", token)
            .body(Body::empty())
            .unwrap();
        req.into_parts().0
    }

    /// 构建带 Cookie: bulwark_token=<token> 的 axum Parts（含额外 cookie 测试循环分支）。
    fn make_parts_with_cookie_token(token: &str) -> axum::http::request::Parts {
        let req = Request::builder()
            .method("GET")
            .uri("/protected")
            .header(
                "cookie",
                format!("other=val; bulwark_token={}; foo=bar", token),
            )
            .body(Body::empty())
            .unwrap();
        req.into_parts().0
    }

    // ----------------------------------------------------------------
    // CheckLogin 测试
    // ----------------------------------------------------------------

    /// 已登录时 CheckLogin 返回 Ok。
    #[tokio::test]
    #[serial]
    async fn check_login_logged_in_returns_ok() {
        init_manager(false, &[], &[]);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let mut parts = make_parts();
        let result = with_current_token(token, async {
            CheckLogin::from_request_parts(&mut parts, &()).await
        })
        .await;
        assert!(result.is_ok(), "已登录应返回 Ok");

        BulwarkManager::reset_for_test();
    }

    /// 未登录且 throw_on_not_login=false 时 CheckLogin 返回 Err(NotLogin)。
    #[tokio::test]
    #[serial]
    async fn check_login_not_logged_in_returns_not_login() {
        init_manager(false, &[], &[]);
        // 不调用 login，直接 extractor（无 token）
        let mut parts = make_parts();
        let result = CheckLogin::from_request_parts(&mut parts, &()).await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(_))),
            "未登录且 throw_on_not_login=false 应返回 Err(NotLogin)"
        );

        BulwarkManager::reset_for_test();
    }

    /// 未登录且 throw_on_not_login=true 时 CheckLogin 返回 Err(Session)。
    #[tokio::test]
    #[serial]
    async fn check_login_not_logged_in_returns_session() {
        init_manager(true, &[], &[]);
        let mut parts = make_parts();
        let result = CheckLogin::from_request_parts(&mut parts, &()).await;
        assert!(
            matches!(result, Err(BulwarkError::Session(_))),
            "未登录且 throw_on_not_login=true 应返回 Err(Session)"
        );

        BulwarkManager::reset_for_test();
    }

    // ----------------------------------------------------------------
    // CheckRole<R> 测试
    // ----------------------------------------------------------------

    /// 持有角色时 CheckRole<AdminRole> 返回 Ok。
    #[tokio::test]
    #[serial]
    async fn check_role_held_returns_ok() {
        init_manager(true, &[], &[(1001, &["admin"])]);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let mut parts = make_parts();
        let result = with_current_token(token, async {
            CheckRole::<AdminRole>::from_request_parts(&mut parts, &()).await
        })
        .await;
        assert!(result.is_ok(), "持有角色应返回 Ok");

        BulwarkManager::reset_for_test();
    }

    /// 未持有角色时 CheckRole<AdminRole> 返回 Err(NotRole)。
    #[tokio::test]
    #[serial]
    async fn check_role_not_held_returns_not_role() {
        init_manager(true, &[], &[]); // 无角色数据
        let token = BulwarkUtil::login(1001).await.unwrap();

        let mut parts = make_parts();
        let result = with_current_token(token, async {
            CheckRole::<AdminRole>::from_request_parts(&mut parts, &()).await
        })
        .await;
        assert!(
            matches!(result, Err(BulwarkError::NotRole(_))),
            "未持有角色应返回 Err(NotRole)"
        );

        BulwarkManager::reset_for_test();
    }

    // ----------------------------------------------------------------
    // CheckPermission<P> 测试
    // ----------------------------------------------------------------

    /// 持有权限时 CheckPermission<UserRead> 返回 Ok。
    #[tokio::test]
    #[serial]
    async fn check_permission_held_returns_ok() {
        init_manager(true, &[(1001, &["user:read"])], &[]);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let mut parts = make_parts();
        let result = with_current_token(token, async {
            CheckPermission::<UserRead>::from_request_parts(&mut parts, &()).await
        })
        .await;
        assert!(result.is_ok(), "持有权限应返回 Ok");

        BulwarkManager::reset_for_test();
    }

    /// 未持有权限时 CheckPermission<UserRead> 返回 Err(NotPermission)。
    #[tokio::test]
    #[serial]
    async fn check_permission_not_held_returns_not_permission() {
        init_manager(true, &[], &[]); // 无权限数据
        let token = BulwarkUtil::login(1001).await.unwrap();

        let mut parts = make_parts();
        let result = with_current_token(token, async {
            CheckPermission::<UserRead>::from_request_parts(&mut parts, &()).await
        })
        .await;
        assert!(
            matches!(result, Err(BulwarkError::NotPermission(_))),
            "未持有权限应返回 Err(NotPermission)"
        );

        BulwarkManager::reset_for_test();
    }

    // ----------------------------------------------------------------
    // Ignore 测试
    // ----------------------------------------------------------------

    /// Ignore 总是返回 Ok（不校验）。
    #[tokio::test]
    #[serial]
    async fn ignore_always_returns_ok() {
        init_manager(false, &[], &[]);
        // 未登录状态下 Ignore 仍返回 Ok
        let mut parts = make_parts();
        let result = Ignore::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok(), "Ignore 应总是返回 Ok");

        BulwarkManager::reset_for_test();
    }

    // ----------------------------------------------------------------
    // Mode<M> 测试
    // ----------------------------------------------------------------

    /// Mode<Strict> 未登录时抛 NotLogin。
    #[tokio::test]
    #[serial]
    async fn mode_strict_not_logged_in_throws_not_login() {
        init_manager(false, &[], &[]); // throw_on_not_login=false
        let mut parts = make_parts();
        let result = Mode::<Strict>::from_request_parts(&mut parts, &()).await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(_))),
            "Mode<Strict> 未登录应抛 Err(NotLogin)"
        );

        BulwarkManager::reset_for_test();
    }

    /// Mode<Loose> 未登录时返回 Ok（宽松模式）。
    #[tokio::test]
    #[serial]
    async fn mode_loose_not_logged_in_returns_ok() {
        init_manager(false, &[], &[]);
        let mut parts = make_parts();
        let result = Mode::<Loose>::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok(), "Mode<Loose> 未登录应返回 Ok");

        BulwarkManager::reset_for_test();
    }

    // ----------------------------------------------------------------
    // IntoResponse for BulwarkError 测试
    // ----------------------------------------------------------------

    /// NotLogin 映射为 401。
    #[test]
    fn not_login_returns_401() {
        let err = BulwarkError::NotLogin("test".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// InvalidToken 映射为 401。
    #[test]
    fn invalid_token_returns_401() {
        let err = BulwarkError::InvalidToken("test".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// ExpiredToken 映射为 401。
    #[test]
    fn expired_token_returns_401() {
        let err = BulwarkError::ExpiredToken("test".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// NotPermission 映射为 403。
    #[test]
    fn not_permission_returns_403() {
        let err = BulwarkError::NotPermission("test".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// NotRole 映射为 403。
    #[test]
    fn not_role_returns_403() {
        let err = BulwarkError::NotRole("test".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// 其他错误映射为 500。
    #[test]
    fn internal_error_returns_500() {
        let err = BulwarkError::Internal("test".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Session 错误映射为 500。
    #[test]
    fn session_error_returns_500() {
        let err = BulwarkError::Session("test".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ----------------------------------------------------------------
    // Annotation::name 测试
    // ----------------------------------------------------------------

    /// Annotation::name 返回注解变体名称。
    #[test]
    fn annotation_name_returns_variant_string() {
        assert_eq!(Annotation::CheckLogin.name(), "CheckLogin");
        assert_eq!(
            Annotation::CheckPermission("p".to_string()).name(),
            "CheckPermission"
        );
        assert_eq!(Annotation::CheckRole("r".to_string()).name(), "CheckRole");
        assert_eq!(Annotation::CheckSafe.name(), "CheckSafe");
        assert_eq!(Annotation::CheckDisable.name(), "CheckDisable");
        assert_eq!(Annotation::CheckOr.name(), "CheckOr");
        assert_eq!(Annotation::CheckAnd.name(), "CheckAnd");
        assert_eq!(Annotation::CheckNot.name(), "CheckNot");
        assert_eq!(Annotation::Ignore.name(), "Ignore");
        assert_eq!(Annotation::CheckBasicAuth.name(), "CheckBasicAuth");
        assert_eq!(Annotation::CheckDigestAuth.name(), "CheckDigestAuth");
        assert_eq!(Annotation::CheckSign.name(), "CheckSign");
    }

    // ----------------------------------------------------------------
    // token 提取（header / cookie）分支测试
    // ----------------------------------------------------------------

    /// CheckLogin 从 Authorization: Bearer header 提取 token 并校验通过。
    #[tokio::test]
    #[serial]
    async fn check_login_extracts_token_from_bearer_header() {
        init_manager(false, &[], &[]);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let mut parts = make_parts_with_bearer(&token);
        let result = CheckLogin::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok(), "Bearer header 提取 token 后校验应通过");

        BulwarkManager::reset_for_test();
    }

    /// CheckLogin 从 bulwark_token header 提取 token 并校验通过。
    #[tokio::test]
    #[serial]
    async fn check_login_extracts_token_from_bulwark_header() {
        init_manager(false, &[], &[]);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let mut parts = make_parts_with_bulwark_header(&token);
        let result = CheckLogin::from_request_parts(&mut parts, &()).await;
        assert!(
            result.is_ok(),
            "bulwark_token header 提取 token 后校验应通过"
        );

        BulwarkManager::reset_for_test();
    }

    /// CheckLogin 从 Cookie: bulwark_token=<token> 提取 token 并校验通过。
    #[tokio::test]
    #[serial]
    async fn check_login_extracts_token_from_cookie() {
        init_manager(false, &[], &[]);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let mut parts = make_parts_with_cookie_token(&token);
        let result = CheckLogin::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok(), "Cookie 提取 token 后校验应通过");

        BulwarkManager::reset_for_test();
    }

    // ----------------------------------------------------------------
    // extractor 通过 header 提取 token 的 if-let-Some 分支测试
    // ----------------------------------------------------------------

    /// CheckRole<AdminRole> 从 Bearer header 提取 token 并校验角色通过。
    #[tokio::test]
    #[serial]
    async fn check_role_extracts_token_from_header() {
        init_manager(true, &[], &[(1001, &["admin"])]);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let mut parts = make_parts_with_bearer(&token);
        let result = CheckRole::<AdminRole>::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok(), "持有角色时通过 header token 校验应通过");

        BulwarkManager::reset_for_test();
    }

    /// CheckPermission<UserRead> 从 Bearer header 提取 token 并校验权限通过。
    #[tokio::test]
    #[serial]
    async fn check_permission_extracts_token_from_header() {
        init_manager(true, &[(1001, &["user:read"])], &[]);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let mut parts = make_parts_with_bearer(&token);
        let result = CheckPermission::<UserRead>::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok(), "持有权限时通过 header token 校验应通过");

        BulwarkManager::reset_for_test();
    }

    /// Mode<Strict> 从 Bearer header 提取 token，已登录时校验通过。
    #[tokio::test]
    #[serial]
    async fn mode_strict_extracts_token_from_header() {
        init_manager(false, &[], &[]);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let mut parts = make_parts_with_bearer(&token);
        let result = Mode::<Strict>::from_request_parts(&mut parts, &()).await;
        assert!(
            result.is_ok(),
            "Mode<Strict> 已登录时通过 header token 校验应通过"
        );

        BulwarkManager::reset_for_test();
    }

    /// Mode<Loose> 从 Bearer header 提取 token，已登录时校验通过（宽松模式不抛错）。
    #[tokio::test]
    #[serial]
    async fn mode_loose_logged_in_with_header() {
        init_manager(false, &[], &[]);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let mut parts = make_parts_with_bearer(&token);
        let result = Mode::<Loose>::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok(), "Mode<Loose> 已登录时应返回 Ok");

        BulwarkManager::reset_for_test();
    }

    // ----------------------------------------------------------------
    // BulwarkPrincipal extractor 测试（携带 login_id，依据 spec web-adapters D12）
    // ----------------------------------------------------------------

    /// `BulwarkPrincipal::from_request_parts` 从 `Authorization: Bearer <token>`
    /// header 解析出 `login_id`。
    ///
    /// 与 actix/warp extractor 对齐：valid token → Ok(BulwarkPrincipal { login_id })。
    #[tokio::test]
    #[serial]
    async fn bulwark_principal_extracts_login_id_from_bearer_header() {
        init_manager(false, &[], &[]);
        let login_id: i64 = 1001;
        let token = BulwarkUtil::login(login_id).await.unwrap();

        let mut parts = make_parts_with_bearer(&token);
        let principal = crate::context::BulwarkPrincipal::from_request_parts(&mut parts, &())
            .await
            .expect("有效 token 应解析出 BulwarkPrincipal");

        assert_eq!(principal.login_id, login_id);

        BulwarkManager::reset_for_test();
    }

    /// `BulwarkPrincipal::from_request_parts` 在无 token 时返回 `Err(NotLogin)`。
    ///
    /// 与 actix/warp extractor 对齐：missing token → Err(NotLogin("未提供 token"))。
    #[tokio::test]
    #[serial]
    async fn bulwark_principal_returns_err_without_token() {
        init_manager(false, &[], &[]);

        let mut parts = make_parts();
        let result = crate::context::BulwarkPrincipal::from_request_parts(&mut parts, &()).await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(_))),
            "无 token 时应返回 Err(NotLogin)，实际 = {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }

    /// `BulwarkPrincipal::from_request_parts` 在无效 token 时返回 `Err(NotLogin)`。
    ///
    /// 与 actix/warp extractor 对齐：invalid token → Err(NotLogin("token 无效或会话不存在"))。
    #[tokio::test]
    #[serial]
    async fn bulwark_principal_returns_err_with_invalid_token() {
        init_manager(false, &[], &[]);

        let mut parts = make_parts_with_bearer("invalid_token_xyz");
        let result = crate::context::BulwarkPrincipal::from_request_parts(&mut parts, &()).await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(_))),
            "无效 token 时应返回 Err(NotLogin)，实际 = {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }

    /// `BulwarkPrincipal::from_request_parts` 在 token 曾有效但已 logout 时
    /// 返回 `Err(NotLogin)`。
    ///
    /// 覆盖 `get_login_id_by_token` 返回 `Ok(None)` 的路径
    /// （token 存在过但 session 已销毁）。
    #[tokio::test]
    #[serial]
    async fn bulwark_principal_returns_err_when_token_logout() {
        init_manager(false, &[], &[]);
        let login_id: i64 = 1001;
        let token = BulwarkUtil::login(login_id).await.unwrap();

        // 注销 token，使 get_login_id_by_token 返回 Ok(None)
        with_current_token(token.clone(), async {
            BulwarkUtil::logout().await.unwrap();
        })
        .await;

        let mut parts = make_parts_with_bearer(&token);
        let result = crate::context::BulwarkPrincipal::from_request_parts(&mut parts, &()).await;
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(_))),
            "token 已注销时应返回 Err(NotLogin)，实际 = {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }

    // ----------------------------------------------------------------
    // TenantContext extractor 测试（cfg tenant-isolation，依据 spec web-adapters D12）
    // ----------------------------------------------------------------

    /// `TenantContext::from_request_parts` 从 `X-Tenant-Id` header 解析出 `tenant_id`。
    ///
    /// 与 actix/warp extractor 对齐：valid X-Tenant-Id → Ok(TenantContext)。
    #[cfg(feature = "tenant-isolation")]
    #[tokio::test]
    #[serial]
    async fn tenant_context_extracts_tenant_id_from_header() {
        let req = Request::builder()
            .method("GET")
            .uri("/api/test")
            .header("x-tenant-id", "42")
            .body(Body::empty())
            .unwrap();
        let mut parts = req.into_parts().0;

        let ctx = crate::context::tenant::TenantContext::from_request_parts(&mut parts, &())
            .await
            .expect("有效 X-Tenant-Id 应解析出 TenantContext");

        assert_eq!(ctx.tenant_id, 42);
        assert!(
            matches!(
                ctx.resolved_from,
                crate::context::tenant::TenantSource::Header
            ),
            "resolved_from 应为 Header，实际 = {:?}",
            ctx.resolved_from
        );
    }

    /// `TenantContext::from_request_parts` 在缺失 `X-Tenant-Id` header 时返回 `Err`。
    ///
    /// 与 actix/warp extractor 对齐：missing X-Tenant-Id → Err(Config)。
    #[cfg(feature = "tenant-isolation")]
    #[tokio::test]
    #[serial]
    async fn tenant_context_returns_err_without_x_tenant_id_header() {
        let mut parts = make_parts();
        let result =
            crate::context::tenant::TenantContext::from_request_parts(&mut parts, &()).await;
        assert!(
            matches!(result, Err(BulwarkError::Config(_))),
            "缺失 X-Tenant-Id 时应返回 Err(Config)，实际 = {:?}",
            result
        );
    }

    /// `TenantContext::from_request_parts` 在非数字 `X-Tenant-Id` 时返回 `Err`。
    ///
    /// 与 actix/warp extractor 对齐：non-numeric X-Tenant-Id → Err(Config)。
    #[cfg(feature = "tenant-isolation")]
    #[tokio::test]
    #[serial]
    async fn tenant_context_returns_err_with_non_numeric_x_tenant_id() {
        let req = Request::builder()
            .method("GET")
            .uri("/api/test")
            .header("x-tenant-id", "not-a-number")
            .body(Body::empty())
            .unwrap();
        let mut parts = req.into_parts().0;

        let result =
            crate::context::tenant::TenantContext::from_request_parts(&mut parts, &()).await;
        assert!(
            matches!(result, Err(BulwarkError::Config(_))),
            "非数字 X-Tenant-Id 时应返回 Err(Config)，实际 = {:?}",
            result
        );
    }
}
