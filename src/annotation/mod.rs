//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 注解模块，定义鉴权注解枚举与 axum extractor。
//!
//! 对应 注解体系（`@SaCheckLogin` 等），
//! Rust 中以枚举变体表达（用于 router 中间件配置），
//! 同时提供 axum extractor（`CheckLogin` 等）用于 handler 参数提取。
//!
//! ## 设计
//!
//! - `Annotation` 枚举：保留用于 router 中间件配置
//! - marker trait（`RoleName` / `PermissionName` / `ModeSpec`）：通过关联常量表达类型级参数
//! - extractor struct（`CheckLogin` 等）：实现 `FromRequestParts`，仅在 `web-axum` feature 下编译

pub mod impls;
pub mod modes;

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

/// 宽松模式：未登录不抛错，允许匿名访问。
pub struct Loose;

// ============================================================================
// Annotation 枚举（保留用于 router 中间件配置，always compiled）
// ============================================================================

/// 鉴权注解枚举，列出 16 个核心注解。
///
/// 对应 注解集合。
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

    /// API Key 校验（对应 `@CheckApiKey`）。
    ///
    /// `namespace` 为 `Some(s)` 表示命名空间隔离（FRD §5.4.1），
    /// `None` 表示使用默认命名空间 `"default"`。
    CheckApiKey {
        /// 命名空间标识；`None` 表示默认命名空间 `"default"`。
        namespace: Option<String>,
    },

    /// 逻辑组合模式（对应 `@Mode`）。
    ///
    /// 控制 `@CheckPermission` / `@CheckRole` 的多权限组合逻辑：
    /// - [`AnnotationMode::And`]：全部满足
    /// - [`AnnotationMode::Or`]：任一满足
    Mode(AnnotationMode),

    /// OAuth2 access_token 校验。
    ///
    /// 声明受保护路由需要校验 OAuth2 access_token。
    /// 拦截器委托 `OAuth2Handler::verify_access_token` 校验；
    /// 无 OAuth2Handler 注册时返回 `NotImplemented`。
    CheckAccessToken,

    /// OAuth2 client_token 校验。
    ///
    /// 声明受保护路由需要校验 OAuth2 client_token（机器对机器访问）。
    /// 拦截器委托 `OAuth2Handler::verify_client_token` 校验；
    /// 无 OAuth2Handler 注册时返回 `NotImplemented`。
    CheckClientToken,
}

/// 注解逻辑组合模式。
///
/// 控制 `@CheckPermission` / `@CheckRole` 的多权限组合逻辑。
///
/// # 规则7 命名冲突记录
///
/// spec 要求命名为 `Mode`，但现有 `Mode<M: ModeSpec>` extractor struct（web-axum feature）
/// 已 re-export 为 `Mode`，会导致命名冲突。按规则11（惯例优先），保留现有 extractor 不变，
/// 新值级枚举命名为 `AnnotationMode`（语义更清晰：注解逻辑组合模式）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationMode {
    /// AND 模式：全部权限/角色均需满足。
    And,
    /// OR 模式：任一权限/角色满足即可。
    Or,
}

// ============================================================================
// axum extractor（cfg(feature = "web-axum")）
// ============================================================================
// 具体实现已拆到 `extractors.rs`（规则 25：mod.rs 不放具体实现函数）。

#[cfg(feature = "web-axum")]
mod extractors;

#[cfg(feature = "web-axum")]
pub use extractors::{CheckLogin, CheckPermission, CheckRole, Ignore, Mode};

#[cfg(all(test, feature = "web-axum"))]
mod mock;

#[cfg(all(test, feature = "web-axum"))]
mod tests {
    use super::mock::{MockDao, MockInterface};
    use super::*;
    use crate::context::tenant::with_default_tenant;
    use crate::dao::BulwarkDao;
    use crate::error::BulwarkError;
    use crate::manager::BulwarkManager;
    use crate::stp::{with_current_token, BulwarkInterface, BulwarkUtil};
    use axum::body::Body;
    use axum::extract::FromRequestParts;
    use axum::http::Request;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use serial_test::serial;
    use std::sync::Arc;

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
        permissions: &[(&str, &[&str])],
        roles: &[(&str, &[&str])],
    ) {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config(throw_on_not_login));
        let mut interface = MockInterface::new();
        for (id, perms) in permissions {
            interface = interface.with_permission(id, perms);
        }
        for (id, roles) in roles {
            interface = interface.with_role(id, roles);
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
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

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
        init_manager(true, &[], &[("1001", &["admin"])]);
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

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
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

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
        init_manager(true, &[("1001", &["user:read"])], &[]);
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

        let mut parts = make_parts();
        let result = with_current_token(token, async {
            with_default_tenant(async {
                CheckPermission::<UserRead>::from_request_parts(&mut parts, &()).await
            })
            .await
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
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

        let mut parts = make_parts();
        let result = with_current_token(token, async {
            with_default_tenant(async {
                CheckPermission::<UserRead>::from_request_parts(&mut parts, &()).await
            })
            .await
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

    /// Annotation::name 返回注解变体名称（16 个变体）。
    ///
    /// 覆盖 R-anno-001 / R-anno-002 验收标准：CheckApiKey 与 Mode 变体的 name() 返回正确字符串。
    /// 覆盖 R-annotation-oauth2-001/002：CheckAccessToken / CheckClientToken name() 返回正确字符串。
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
        // CheckApiKey（R-anno-001）— namespace None 与 Some 均返回同一字符串
        assert_eq!(
            Annotation::CheckApiKey { namespace: None }.name(),
            "CheckApiKey"
        );
        assert_eq!(
            Annotation::CheckApiKey {
                namespace: Some("ns1".to_string())
            }
            .name(),
            "CheckApiKey"
        );
        // Mode（R-anno-002）— And / Or 均返回 "Mode"
        assert_eq!(Annotation::Mode(AnnotationMode::And).name(), "Mode");
        assert_eq!(Annotation::Mode(AnnotationMode::Or).name(), "Mode");
        // 新增：CheckAccessToken / CheckClientToken（R-annotation-oauth2-001/002）
        assert_eq!(Annotation::CheckAccessToken.name(), "CheckAccessToken");
        assert_eq!(Annotation::CheckClientToken.name(), "CheckClientToken");
    }

    // ----------------------------------------------------------------
    // AnnotationMode Display / Debug / Clone / PartialEq 测试（R-anno-002）
    // ----------------------------------------------------------------

    /// AnnotationMode::And 的 Display 输出 "AND"，AnnotationMode::Or 输出 "OR"。
    #[test]
    fn annotation_mode_display_outputs_uppercase() {
        assert_eq!(format!("{}", AnnotationMode::And), "AND");
        assert_eq!(format!("{}", AnnotationMode::Or), "OR");
    }

    /// AnnotationMode 实现 Copy，可在 match 表达式中按值使用而无需 clone。
    #[test]
    fn annotation_mode_copy_semantics() {
        let mode = AnnotationMode::And;
        let copied = mode; // Copy，原值仍可用
        assert_eq!(mode, AnnotationMode::And);
        assert_eq!(copied, AnnotationMode::And);
    }

    /// AnnotationMode::Mode(AnnotationMode::And) 与 .Or 在 Annotation 枚举层级可比较相等性。
    #[test]
    fn annotation_mode_equality_within_annotation() {
        assert_eq!(
            Annotation::Mode(AnnotationMode::And),
            Annotation::Mode(AnnotationMode::And)
        );
        assert_ne!(
            Annotation::Mode(AnnotationMode::And),
            Annotation::Mode(AnnotationMode::Or)
        );
    }

    /// CheckApiKey 变体 namespace 字段 None 与 Some 不影响 name()，但影响 PartialEq。
    #[test]
    fn check_api_key_namespace_equality() {
        assert_eq!(
            Annotation::CheckApiKey { namespace: None },
            Annotation::CheckApiKey { namespace: None }
        );
        assert_ne!(
            Annotation::CheckApiKey { namespace: None },
            Annotation::CheckApiKey {
                namespace: Some("ns1".to_string())
            }
        );
        assert_ne!(
            Annotation::CheckApiKey {
                namespace: Some("ns1".to_string())
            },
            Annotation::CheckApiKey {
                namespace: Some("ns2".to_string())
            }
        );
    }

    // ----------------------------------------------------------------
    // Display / FromStr 测试（R-annotation-oauth2-001/002）
    // ----------------------------------------------------------------

    /// R-annotation-oauth2-001: CheckAccessToken Display 格式化为 "CheckAccessToken"。
    #[test]
    fn check_access_token_display_formats_correctly() {
        assert_eq!(
            format!("{}", Annotation::CheckAccessToken),
            "CheckAccessToken"
        );
    }

    /// R-annotation-oauth2-002: CheckClientToken Display 格式化为 "CheckClientToken"。
    #[test]
    fn check_client_token_display_formats_correctly() {
        assert_eq!(
            format!("{}", Annotation::CheckClientToken),
            "CheckClientToken"
        );
    }

    /// R-annotation-oauth2-001: from_str("CheckAccessToken") 返回 Ok(CheckAccessToken)。
    #[test]
    fn check_access_token_from_str_returns_ok() {
        let result: Result<Annotation, _> = "CheckAccessToken".parse();
        assert!(result.is_ok(), "from_str 应返回 Ok");
        assert_eq!(result.unwrap(), Annotation::CheckAccessToken);
    }

    /// R-annotation-oauth2-002: from_str("CheckClientToken") 返回 Ok(CheckClientToken)。
    #[test]
    fn check_client_token_from_str_returns_ok() {
        let result: Result<Annotation, _> = "CheckClientToken".parse();
        assert!(result.is_ok(), "from_str 应返回 Ok");
        assert_eq!(result.unwrap(), Annotation::CheckClientToken);
    }

    /// from_str 对未知字符串返回 Err(InvalidParam)。
    #[test]
    fn annotation_from_str_unknown_returns_err() {
        let result: Result<Annotation, _> = "UnknownAnnotation".parse();
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "未知注解应返回 Err(InvalidParam)，实际: {:?}",
            result
        );
    }

    /// from_str 对含数据变体（如 "CheckPermission"）返回 Err。
    #[test]
    fn annotation_from_str_data_variant_returns_err() {
        let result: Result<Annotation, _> = "CheckPermission".parse();
        assert!(
            result.is_err(),
            "含数据变体应返回 Err（无法仅从名称解析），实际: {:?}",
            result
        );
    }

    /// Display 对所有 unit 变体输出与 name() 一致的字符串。
    #[test]
    fn display_matches_name_for_all_unit_variants() {
        let unit_variants = [
            Annotation::CheckLogin,
            Annotation::CheckSafe,
            Annotation::CheckDisable,
            Annotation::CheckOr,
            Annotation::CheckAnd,
            Annotation::CheckNot,
            Annotation::Ignore,
            Annotation::CheckBasicAuth,
            Annotation::CheckDigestAuth,
            Annotation::CheckSign,
            Annotation::CheckAccessToken,
            Annotation::CheckClientToken,
        ];
        for ann in &unit_variants {
            assert_eq!(
                format!("{}", ann),
                ann.name(),
                "Display 输出应与 name() 一致"
            );
        }
    }

    // ----------------------------------------------------------------
    // token 提取（header / cookie）分支测试
    // ----------------------------------------------------------------

    /// CheckLogin 从 Authorization: Bearer header 提取 token 并校验通过。
    #[tokio::test]
    #[serial]
    async fn check_login_extracts_token_from_bearer_header() {
        init_manager(false, &[], &[]);
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

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
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

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
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

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
        init_manager(true, &[], &[("1001", &["admin"])]);
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

        let mut parts = make_parts_with_bearer(&token);
        let result = CheckRole::<AdminRole>::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok(), "持有角色时通过 header token 校验应通过");

        BulwarkManager::reset_for_test();
    }

    /// CheckPermission<UserRead> 从 Bearer header 提取 token 并校验权限通过。
    #[tokio::test]
    #[serial]
    async fn check_permission_extracts_token_from_header() {
        init_manager(true, &[("1001", &["user:read"])], &[]);
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

        let mut parts = make_parts_with_bearer(&token);
        let result = with_default_tenant(async {
            CheckPermission::<UserRead>::from_request_parts(&mut parts, &()).await
        })
        .await;
        assert!(result.is_ok(), "持有权限时通过 header token 校验应通过");

        BulwarkManager::reset_for_test();
    }

    /// Mode<Strict> 从 Bearer header 提取 token，已登录时校验通过。
    #[tokio::test]
    #[serial]
    async fn mode_strict_extracts_token_from_header() {
        init_manager(false, &[], &[]);
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

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
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

        let mut parts = make_parts_with_bearer(&token);
        let result = Mode::<Loose>::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok(), "Mode<Loose> 已登录时应返回 Ok");

        BulwarkManager::reset_for_test();
    }

    // ----------------------------------------------------------------
    // BulwarkPrincipal extractor 测试（携带 login_id）
    // ----------------------------------------------------------------

    /// `BulwarkPrincipal::from_request_parts` 从 `Authorization: Bearer <token>`
    /// header 解析出 `login_id`。
    ///
    /// 与 actix/warp extractor 对齐：valid token → Ok(BulwarkPrincipal { login_id })。
    #[tokio::test]
    #[serial]
    async fn bulwark_principal_extracts_login_id_from_bearer_header() {
        init_manager(false, &[], &[]);
        let login_id = "1001";
        let token = BulwarkUtil::login_simple(login_id).await.unwrap();

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
        let login_id = "1001";
        let token = BulwarkUtil::login_simple(login_id).await.unwrap();

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
    // TenantContext extractor 测试（cfg tenant-isolation）
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
