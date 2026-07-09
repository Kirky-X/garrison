//! # Bulwark
//!
//! Bulwark 是一个面向 Rust 生态的身份认证鉴权框架，借鉴 Sa-Token v1.45.0 的设计理念。
//!
//! ## 快速开始
//!
//! 最小可用示例：初始化管理器 → 执行登录 → 校验登录状态。
//!
//! ```ignore
//! use std::sync::Arc;
//! use bulwark::prelude::*;
//!
//! // 1. 准备依赖（业务方实现 BulwarkDao / BulwarkInterface）
//! let dao: Arc<dyn BulwarkDao> = /* oxcache / dbnexus 实现 */;
//! let config = Arc::new(BulwarkConfig::default_config());
//! let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface);
//!
//! // 2. 初始化全局管理器（覆盖式注入 dao / config / interface）
//! BulwarkManager::init(dao, config, interface).unwrap();
//!
//! // 3. 执行登录：生成 token 并写入会话
//! //    注意：login / check_login 依赖 task_local 上下文中的当前 token，
//! //    通常由 web 中间件（如 axum middleware）设置。
//! let token = BulwarkUtil::login(1001).await.unwrap();
//!
//! // 4. 校验登录状态
//! let logged_in = BulwarkUtil::check_login().await.unwrap();
//! assert!(logged_in);
//! ```
//!
//! ## 特性
//!
//! Bulwark 通过 Cargo feature flags 控制各能力域的编译：
//!
//! | 类别 | Feature | 说明 |
//! |:---|:---|:---|
//! | 默认 | `default` | 空（按需启用所需 feature；`all-defaults` 可一键启用常用组合） |
//! | 缓存 | `cache-memory` / `cache-redis` | 基于 oxcache 0.3 的 L1(moka) + L2(redis)，均启用 oxcache（语义别名） |
//! | 数据库 | `db-sqlite` | 基于 dbnexus 0.2 + auto-migrate |
//! | Web 框架 | `web-axum` / `web-actix` / `web-warp` | 路由拦截器与 extractor 适配 |
//! | 协议层 | `protocol-jwt` / `protocol-oauth2` / `protocol-sso` / `protocol-sign` / `protocol-apikey` / `protocol-temp` | 鉴权协议插件 |
//! | 安全模块 | `secure-totp` / `secure-sign` / `secure-httpbasic` / `secure-httpdigest` | TOTP / 签名 / Basic / Digest |
//! | 可观测性 | `listener` / `tracing-log` / `metrics-prometheus` | 事件监听 / 日志 / 指标 |
//! | 聚合 | `full` / `production` / `development` | 一键启用一组特性 |
//!
//! ## 0.2.0 新增模块概览
//!
//! 0.2.0 在 0.1.0 基础上扩展了协议层、安全模块与可插拔扩展点（依据 spec protocol-secure-v0-2-0）：
//!
//! - **核心扩展**（always on）
//!   - [`core::token`]：`Token` trait + `TokenStyleFactory`（uuid / random_64 / simple / jwt 四种风格）
//!   - [`core::auth`]：`AuthLogic` trait + `DefaultAuthLogic`（login_by_token / verify_token / refresh_token）
//!   - [`core::permission`]：`PermissionChecker` trait + `DefaultPermissionChecker`
//!   - [`plugin`]：`BulwarkPlugin` trait + `inventory` 编译期注册 + `BulwarkPluginManager`（on_login / on_logout / on_permission_check 钩子）
//!   - [`strategy`]：`BulwarkPermissionStrategyDefault` 扩展 `with_permission_checker` / `with_role_hierarchy` / `with_plugin_manager` / `with_dao`（权限缓存）
//!   - [`session`]：`BulwarkSession` 扩展 SSO / OAuth2 / 临时凭证关联（`link_sso_ticket` / `link_oauth2_token` / `link_temp_credential`）
//! - **协议层**（特性门控）
//!   - `protocol::jwt`：`JwtHandler`（sign / verify / refresh，HS256/HS512）
//!   - `protocol::oauth2`：`OAuth2Client`（Authorization Code / Client Credentials / Password 三种流程）
//!   - `protocol::sso`：`SsoClient`（ticket 签发 / 校验 / 销毁，一次性 60s TTL）
//!   - `protocol::sign`：`SignHandler`（HMAC-SHA256 签名 + 防重放时间窗口）
//!   - `protocol::apikey`：`ApiKeyHandler`（生成 / 校验 / 吊销 / 轮换）
//!   - `protocol::temp`：`TempCredentialHandler`（issue / get / revoke / consume）
//! - **安全模块**（特性门控）
//!   - `secure::totp`：`TotpHandler`（RFC 6238，±1 时间窗口偏差）
//!   - `secure::sign`：`SignVerifier` trait
//!   - `secure::httpbasic` / `secure::httpdigest`：HTTP Basic / Digest 认证
//! - **可观测性**
//!   - `listener`：`BulwarkEvent` + `Listener` trait + `BulwarkListenerManager`（Login / Logout / PermissionCheck / Kickout 事件）
//!
//! ## 特性域
//!
//! Bulwark 借鉴 Sa-Token 的 13 个特性域设计：
//!
//! - **登录认证** - 基于 Token 的会话管理
//! - **权限认证** - RBAC 权限模型
//! - **Session 会话** - 会话生命周期管理
//! - **OAuth2** - 第三方授权
//! - **单点登录 (SSO)** - 跨系统统一登录
//! - **JWT** - JSON Web Token 支持
//! - **微服务网关鉴权** - 网关层签名认证
//! - **API 接口鉴权** - API Key 认证
//! - **TOTP 动态验证码** - 时间一次性密码
//! - **Basic 认证** - HTTP Basic Auth
//! - **Digest 认证** - HTTP Digest Auth
//! - **路由拦截鉴权** - Web 框架适配
//! - **插件化扩展** - 编译期插件注册
//!
//! ## 架构
//!
//! Bulwark 采用双抽象层 + 全局单例的架构：
//!
//! - **双抽象层**
//!   - `dbnexus`：数据库抽象层（SQLite / PostgreSQL / MySQL），由 [`BulwarkDao`] trait 屏蔽后端差异
//!   - `oxcache`：缓存抽象层（L1 moka + L2 redis），承载 Token-Session 与 Account-Session
//! - **BulwarkManager 单例模式**
//!   - [`BulwarkManager`] 持有全局 `Arc<BulwarkLogicDefault>`（基于 `parking_lot::RwLock`，支持覆盖式 `init`）
//!   - 业务方启动时调用 [`BulwarkManager::init`] 注入 dao / config / interface 依赖
//!   - `BulwarkLogicFactory` 通过 `inventory::submit!` 在编译期注册，运行时由 `inventory::iter` 选取
//!   - [`BulwarkUtil::login`] / [`BulwarkUtil::check_login`] 等静态方法委托到全局单例
//!
//! ## 双抽象层
//!
//! - **dbnexus** - 数据库抽象层（SQLite / PostgreSQL / MySQL）
//! - **oxcache** - 缓存抽象层（L1 moka + L2 redis）
//!
//! ## 使用示例
//!
//! ```toml
//! [dependencies]
//! bulwark = { version = "0.2", features = ["web-axum", "protocol-jwt"] }
//! ```
//!
//! ```rust
//! use bulwark::prelude::*;
//!
//! // 通过 prelude 引入核心类型
//! // let _config: BulwarkConfig = BulwarkConfig::default();
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

// ====================================================================
// 核心模块（always on，无 feature flag）
// ====================================================================

/// 核心模块，包含认证、权限、Token 的核心抽象。
pub mod core;

/// Stp 模块，提供 BulwarkLogicDefault / BulwarkInterface / BulwarkUtil + 5 个子 trait。
pub mod stp;

/// 注解模块，定义鉴权注解枚举。
pub mod annotation;

/// 路由模块，提供路由器与拦截器抽象。
pub mod router;

/// DAO 模块，定义持久化数据访问抽象层。
pub mod dao;

/// 策略模块，提供鉴权策略与防火墙策略。
pub mod strategy;

/// 会话模块，提供 BulwarkSession 会话模型。
pub mod session;

/// 状态机模块，定义 Token / User 显式状态机（0.6.1 新增，依据 spec state-machine E-005）。
///
/// 提供 [`state::TokenState`]（5 状态 + 6 条合法转换）与 [`state::UserStatus`]（5 状态 + 9 条合法转换），
/// 严格遵循 FRD §4.2 / §4.3，不集成到现有 Session / User 模块（推迟到 v0.7.0）。
pub mod state;

/// 配置模块，提供 BulwarkConfig 全局配置。
pub mod config;

/// 上下文模块，提供请求/响应/存储上下文抽象。
pub mod context;

/// JSON 模块，提供 JSON 模板与序列化抽象。
pub mod json;

/// 异常模块，定义框架异常类型。
pub mod exception;

/// 管理器模块，提供全局管理器单例。
pub mod manager;

/// 插件模块，定义插件 trait 与编译期注册。
pub mod plugin;

/// 可观测性模块，提供 Prometheus 指标 / 结构化 JSON 日志 / OpenTelemetry 分布式追踪。
///
/// 启用 `metrics-prometheus` feature 启用指标采集；启用 `observability-otlp` 启用 OTLP 追踪导出。
/// 未启用任一 feature 时模块仍可导入但 API 为 no-op，保证向后兼容。
#[cfg(any(
    feature = "metrics-prometheus",
    feature = "observability-otlp",
    feature = "tracing-log"
))]
pub mod observability;

/// gRPC 鉴权拦截器模块，提供 `tonic::Interceptor` 实现。
///
/// 启用 `grpc` feature 时编译。从 gRPC 请求 metadata 提取 Authorization Bearer token
/// 并执行鉴权。
#[cfg(feature = "grpc")]
pub mod grpc;

/// 国际化模块，提供异常消息中英文切换（fluent-rs）。
///
/// 启用 `i18n` feature 时编译。通过 `set_locale(BulwarkLocale::En)` 切换至英文，
/// 默认 `Zh`（中文，向后兼容 0.2.x 硬编码行为）。
#[cfg(feature = "i18n")]
pub mod i18n;

/// 声明式 JSON 测试套件模块（0.5.1 新增，依据 spec testing-suite D8 / M6）。
///
/// 启用 `bulwark-testing` feature 时编译。提供 [`JsonTestSuite`] / [`JsonTestCase`] /
/// [`TestReport`] 类型，支持从 JSON 文件加载测试用例并运行 [`Authorizer`] trait。
///
/// 依赖 `authorize-api` feature（提供 [`Authorizer`] trait 与 [`AuthRequest`] / [`Decision`]）。
///
/// [`JsonTestSuite`]: crate::testing::JsonTestSuite
/// [`JsonTestCase`]: crate::testing::JsonTestCase
/// [`TestReport`]: crate::testing::TestReport
/// [`Authorizer`]: crate::core::permission::Authorizer
/// [`AuthRequest`]: crate::core::permission::AuthRequest
/// [`Decision`]: crate::core::permission::Decision
#[cfg(feature = "bulwark-testing")]
pub mod testing;

/// actix-web 框架适配模块（0.3.0 新增，依据 spec web-adapters）。
///
/// 启用 `web-actix` feature 时编译。提供 BulwarkRouter + FromRequest extractor +
/// BulwarkMiddleware 完整集成，与 axum 适配对齐。
#[cfg(feature = "web-actix")]
pub mod web_actix;

/// warp 框架适配模块（0.3.0 新增，依据 spec web-adapters）。
///
/// 启用 `web-warp` feature 时编译。提供 BulwarkRouter + Filter extractor +
/// BulwarkRejection 完整集成，与 axum/actix-web 适配对齐。
#[cfg(feature = "web-warp")]
pub mod web_warp;

// ====================================================================
// 可选模块（特性门控）
// ====================================================================

/// 监听器模块，提供事件监听抽象。
#[cfg(feature = "listener")]
pub mod listener;

/// 安全模块，提供 TOTP / 签名 / Basic / Digest / Unicode 同形异义字检测 验证。
///
/// 密码哈希能力已迁移到 `account::credential::password`（v0.6.0）。
#[cfg(any(
    feature = "secure-totp",
    feature = "secure-sign",
    feature = "secure-httpbasic",
    feature = "secure-httpdigest",
    feature = "secure-confusable",
))]
pub mod secure;

/// 账号安全引擎模块（v0.6.0 新增，吸收 keycloak 安全能力）。
///
/// 提供：
/// - 凭证模型 SPI（`account-credential` feature）
/// - 密码策略套件（`account-policy` feature）
/// - 用户级双态锁定（`account-lockout` feature）
/// - AuthenticationFlow DSL（`account-authflow` feature）
///
/// 与 `secure/`（密码学原语）互补：`secure/` 提供底层原语，
/// `account/` 提供账号生命周期安全能力。
pub mod account;

/// 协议层模块，包含各协议插件子模块。
#[cfg(any(
    feature = "protocol-oauth2",
    feature = "protocol-sso",
    feature = "protocol-jwt",
    feature = "protocol-sign",
    feature = "protocol-apikey",
    feature = "protocol-temp",
))]
pub mod protocol;

// ====================================================================
// 公共入口
// ====================================================================

/// 预导出模块，包含最常用的类型与 trait。
pub mod prelude;

/// 错误类型定义模块。
pub mod error;

// Re-export prelude 以便 `use bulwark::prelude::*;` 可用
pub use prelude::*;

// ============================================================================
// 多租户隔离类型 re-export（v0.5.0 新增，依据 spec tenant-isolation R-001）
// ============================================================================
//
// 业务方可通过 `use bulwark::{TenantContext, TenantResolver, ...}` 直接使用，
// 无需写完整路径 `bulwark::context::tenant::TenantContext`。
//
// `ClaimTenantResolver` 需 `protocol-jwt` feature（依赖 jsonwebtoken 解码 JWT claim）。

/// 多租户上下文类型与解析器（依据 spec tenant-isolation）。
pub use context::tenant::{
    HeaderTenantResolver, SubdomainTenantResolver, TenantContext, TenantResolver, TenantSource,
    TENANT,
};

/// JWT claim 租户解析器（需 `protocol-jwt` feature）。
#[cfg(feature = "protocol-jwt")]
pub use context::tenant::ClaimTenantResolver;

/// 登录主体（携带 login_id，由 web 框架 extractor 填充，依据 spec web-adapters D12）。
pub use context::BulwarkPrincipal;

// ============================================================================
// 状态机类型 re-export（v0.6.1 新增，依据 spec state-machine E-005）
// ============================================================================
//
// 业务方可通过 `use bulwark::{TokenState, UserStatus}` 直接使用，
// 无需写完整路径 `bulwark::state::TokenState`。
//
// 注：spec R-state-007 提及 `Mode` re-export，但 state-machine.md 未在 state 模块定义 Mode
// （AnnotationMode 位于 annotation 模块），故仅 re-export TokenState / UserStatus（规则7）。

/// Token 生命周期状态（Issued / Active / Expired / Revoked / Refreshed）。
pub use state::TokenState;

/// 用户账号状态（Pending / Active / Suspended / Inactive / Deleted）。
pub use state::UserStatus;

// ============================================================================
// 角色层级（v0.5.0 新增，依据 proposal H6）
// ============================================================================
//
// `RoleHierarchyRecord` 为 always compiled（无 feature gate）。
// `RoleHierarchyService` 需 `db-sqlite` feature（依赖 DbPool 查 SQL）。
//
// 业务方可通过 `use bulwark::{RoleHierarchyRecord, RoleHierarchyService}` 直接使用，
// 无需写完整路径 `bulwark::dao::repository::role_hierarchy::RoleHierarchyService`。

/// 角色层级表行结构（child_role → parent_role + tenant_id）。
pub use dao::repository::role_hierarchy::RoleHierarchyRecord;

/// 角色层级服务（TC 预计算 + 缓存 + 增量失效，需 `db-sqlite` feature）。
#[cfg(feature = "db-sqlite")]
pub use dao::repository::role_hierarchy::RoleHierarchyService;

// ============================================================================
// Dbnexus Repository re-export（v0.5.0 新增，依据 P3 backend-agnostic 重构）
// ============================================================================
//
// 业务方可通过 `use bulwark::{DbnexusUserRepository, ...}` 直接使用，
// 无需写完整路径 `bulwark::dao::repository::sqlite::DbnexusUserRepository`。
//
// 需 `db-sqlite` 或 `db-postgres` feature（运行时占位符转换支持两种后端）。

/// 用户表 Repository（app_user）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dao::repository::sqlite::DbnexusUserRepository;

/// 角色表 Repository（app_role）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dao::repository::sqlite::DbnexusRoleRepository;

/// 权限表 Repository（app_permission，全局表无 tenant_id）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dao::repository::sqlite::DbnexusPermissionRepository;

/// 用户-角色关联表 Repository（app_user_role）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dao::repository::sqlite::DbnexusUserRoleRepository;

/// 角色-权限关联表 Repository（app_role_permission）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dao::repository::sqlite::DbnexusRolePermissionRepository;

/// 认证方式表 Repository（app_auth_method）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dao::repository::sqlite::DbnexusAuthMethodRepository;

/// 会话表 Repository（app_session）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dao::repository::sqlite::DbnexusSessionRepository;

/// 登录日志表 Repository（app_login_log）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dao::repository::sqlite::DbnexusLoginLogRepository;

/// 用户扩展信息表 Repository（app_user_ext）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use dao::repository::sqlite::DbnexusUserExtRepository;

// ============================================================================
// JWT RefreshToken Rotation（v0.5.0 新增，依据 proposal H4）
// ============================================================================
//
// `RefreshTokenRecord` 需 `protocol-jwt` feature（hash chain 行结构）。
// `RefreshTokenRotation` 需 `protocol-jwt` + `db-sqlite` feature（依赖 DbPool 查 SQL）。
//
// 业务方可通过 `use bulwark::{RefreshTokenRecord, RefreshTokenRotation}` 直接使用，
// 无需写完整路径 `bulwark::protocol::jwt::refresh::RefreshTokenRotation`。

/// RefreshToken 表行结构（hash chain：token_hash + parent_token_hash）。
#[cfg(feature = "protocol-jwt")]
pub use protocol::jwt::refresh::RefreshTokenRecord;

/// RefreshToken Rotation 服务（rotate + detect_reuse + revoke_chain，需 `protocol-jwt` + `db-sqlite`）。
#[cfg(all(feature = "protocol-jwt", feature = "db-sqlite"))]
pub use protocol::jwt::refresh::RefreshTokenRotation;

// ============================================================================
// 审计日志（v0.5.0 新增，依据 proposal H3）
// ============================================================================
//
// 业务方可通过 `use bulwark::{AuditLogListener, AuditConfig, AuditEntry, AuditQuery}` 直接使用，
// 无需写完整路径 `bulwark::listener::audit::AuditLogListener`。
//
// `AuditConfig` 需 `audit-log` feature（纯配置结构，无 SQL 依赖）。
// `AuditEntry` / `AuditQuery` / `AuditLogListener` 需 `audit-log` + `db-sqlite` feature
// （映射 SQL 表行 / 查询条件 / 持久化监听器）。

/// 审计日志配置（掩码字段 + 保留天数 + 异步写入开关）。
#[cfg(feature = "audit-log")]
pub use listener::audit::AuditConfig;

/// `audit_logs` 表行结构（tenant_id / event_type / login_id / metadata / success / created_at）。
#[cfg(all(feature = "audit-log", feature = "db-sqlite"))]
pub use listener::audit::AuditEntry;

/// 审计日志查询条件（tenant_id / event_type / from / to，全 Option 复合过滤）。
#[cfg(all(feature = "audit-log", feature = "db-sqlite"))]
pub use listener::audit::AuditQuery;

/// 审计日志监听器（实现 `BulwarkListener`，持久化 `BulwarkEvent` 到 `audit_logs` 表）。
#[cfg(all(feature = "audit-log", feature = "db-sqlite"))]
pub use listener::audit::AuditLogListener;

// ============================================================================
// 社交登录（v0.5.0 新增，依据 proposal H2 / spec social-login）
// ============================================================================
//
// 业务方可通过 `use bulwark::{SocialLoginProvider, SocialUserInfo, ...}` 直接使用，
// 无需写完整路径 `bulwark::protocol::social::SocialLoginProvider`。
//
// - `SocialLoginProvider` / `SocialUserInfo` / `SocialProvider`：公共 trait/结构，无 feature 依赖
// - `WechatProvider`：需 `social-wechat` feature（微信扫码登录）
// - `AlipayProvider`：需 `social-alipay` feature（支付宝授权登录）
// - `SocialBindingService`：需 `db-sqlite` feature（依赖 DbPool 查 social_bindings 表）

/// 社交登录服务提供方 trait（get_authorization_url / exchange_token / get_user_info）。
#[cfg(any(feature = "social-wechat", feature = "social-alipay"))]
pub use protocol::social::SocialLoginProvider;

/// 社交用户信息（provider + provider_user_id + union_id + raw JSON）。
#[cfg(any(feature = "social-wechat", feature = "social-alipay"))]
pub use protocol::social::SocialUserInfo;

/// 社交登录平台标识（Wechat / Alipay / WechatMiniApp）。
#[cfg(any(feature = "social-wechat", feature = "social-alipay"))]
pub use protocol::social::SocialProvider;

/// 微信扫码登录 provider（需 `social-wechat` feature）。
#[cfg(feature = "social-wechat")]
pub use protocol::social::wechat::WechatProvider;

/// 微信小程序登录 provider（需 `social-wechat` feature，依据 design.md D11 D1）。
#[cfg(feature = "social-wechat")]
pub use protocol::social::wechat::WechatMiniAppProvider;

/// 支付宝授权登录 provider（需 `social-alipay` feature）。
#[cfg(feature = "social-alipay")]
pub use protocol::social::alipay::AlipayProvider;

/// 社交账号绑定服务（find_or_create，需 `db-sqlite` + `social-wechat`/`social-alipay` feature）。
#[cfg(all(
    feature = "db-sqlite",
    any(feature = "social-wechat", feature = "social-alipay")
))]
pub use protocol::social::SocialBindingService;

// ============================================================================
// Keycloak OIDC RP（v0.5.0 新增，依据 proposal K1 / spec keycloak-oidc-rp）
// ============================================================================
//
// 业务方可通过 `use bulwark::{KeycloakConfig, KeycloakProvider, ...}` 直接使用，
// 无需写完整路径 `bulwark::protocol::oauth2::keycloak::KeycloakConfig`。
//
// 全部类型需 `keycloak-oidc` feature（依赖 `protocol-oidc` → `protocol-jwt` + `protocol-oauth2`）。

/// Keycloak OIDC RP 配置（base_url / client_id / client_secret / redirect_uri）。
#[cfg(feature = "keycloak-oidc")]
pub use protocol::oauth2::keycloak::KeycloakConfig;

/// Keycloak OIDC 依赖方（discover / verify_id_token / exchange_code）。
#[cfg(feature = "keycloak-oidc")]
pub use protocol::oauth2::keycloak::KeycloakProvider;

/// Keycloak id_token 的 claims（sub / exp / realm_access / resource_access / tenant_id）。
#[cfg(feature = "keycloak-oidc")]
pub use protocol::oauth2::keycloak::KeycloakClaims;

/// Keycloak token endpoint 响应（access_token / refresh_token / id_token / expires_in）。
#[cfg(feature = "keycloak-oidc")]
pub use protocol::oauth2::keycloak::KeycloakTokenSet;

/// Keycloak realm 访问信息（roles 列表）。
#[cfg(feature = "keycloak-oidc")]
pub use protocol::oauth2::keycloak::RealmAccess;

// ============================================================================
// 安全防护套件（v0.5.0 新增，依据 proposal H5 / spec firewall）
// ============================================================================
//
// 业务方可通过 `use bulwark::{BulwarkFirewallStrategy, FirewallContext, ...}` 直接使用，
// 无需写完整路径 `bulwark::strategy::firewall::BulwarkFirewallStrategy`。
//
// - `firewall` feature：基础 trait + Context + StrategyRegistration（inventory 注册）
// - `firewall-bruteforce` / `firewall-ratelimit` / `firewall-anomalous` / `firewall-ddos` / `firewall-geoip`：
//   5 个独立 strategy 实现，各自 feature 门控
// - `GeoCoord` / `GeoLookup` / `CountryLookup`：共享地理查询抽象（anomalous / geoip 共用）

/// 防火墙策略 trait（IP 级安全检查契约）。
#[cfg(feature = "firewall")]
pub use strategy::firewall::BulwarkFirewallStrategy;

/// 防火墙上下文（IP / login_id / tenant_id）。
#[cfg(feature = "firewall")]
pub use strategy::firewall::FirewallContext;

/// 防火墙策略注册条目（inventory 收集，仅含 name）。
#[cfg(feature = "firewall")]
pub use strategy::firewall::StrategyRegistration;

/// 暴力破解防护策略 + 配置（依据 spec firewall R-firewall-001）。
#[cfg(feature = "firewall-bruteforce")]
pub use strategy::firewall::brute_force::{BruteForceConfig, BruteForceStrategy};

/// 速率限制策略 + 配置 + 作用域枚举（依据 spec firewall R-firewall-002）。
#[cfg(feature = "firewall-ratelimit")]
pub use strategy::firewall::rate_limit::{RateLimitConfig, RateLimitScope, RateLimitStrategy};

/// 异地登录检测策略 + 配置（依据 spec firewall R-firewall-003）。
#[cfg(feature = "firewall-anomalous")]
pub use strategy::firewall::anomalous::{AnomalousConfig, AnomalousLoginStrategy};

/// DDoS 防护策略 + 配置（依据 spec firewall R-firewall-004）。
#[cfg(feature = "firewall-ddos")]
pub use strategy::firewall::ddos::{DDoSConfig, DDoSStrategy};

/// GeoIP 地理位置拦截策略 + 配置（依据 spec firewall R-firewall-005）。
#[cfg(feature = "firewall-geoip")]
pub use strategy::firewall::geoip::{GeoIPConfig, GeoIPStrategy};

/// 地理坐标 + GeoLookup / CountryLookup trait（anomalous / geoip 共享）。
#[cfg(any(feature = "firewall-anomalous", feature = "firewall-geoip"))]
pub use strategy::firewall::geo::{CountryLookup, GeoCoord, GeoLookup};

// ============================================================================
// 过程宏注解（0.4.2 新增，依据 spec annotation-macros）
// ============================================================================

/// 过程宏注解模块（feature = "annotation-macros"）。
///
/// 启用 `annotation-macros` feature 时，re-export `bulwark-macros` crate 的 7 个
/// `#[proc_macro_attribute]`：
/// - `#[check_login]` / `#[check_permission]` / `#[check_role]`（0.4.2）
/// - `#[check_access_token]` / `#[check_client_token]` / `#[check_temp_token]`（0.5.0 P2）
/// - `#[check_api_key]`（0.6.1 新增，依据 spec annotation-check-api-key R-anno-003）
///
/// 宏将 async fn 包装为 wrapper，在 body 前插入 `BulwarkUtil::check_*()` 调用，
/// 失败时返回 `axum::response::Response`（401/403）。
///
/// # 示例
///
/// ```ignore
/// use bulwark::check_login;
/// use axum::response::IntoResponse;
///
/// #[check_login]
/// async fn handler() -> impl IntoResponse {
///     "hello"
/// }
/// ```
#[cfg(feature = "annotation-macros")]
pub use bulwark_macros::{
    check_access_token, check_api_key, check_client_token, check_login, check_permission,
    check_role, check_temp_token,
};
