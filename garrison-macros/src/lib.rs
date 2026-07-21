//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Garrison 过程宏 crate，提供鉴权注解属性宏。
//!
//! 依据 spec `annotation-macros`，提供 10 个 `#[proc_macro_attribute]`：
//!
//! - [`macro@check_login`]：登录校验，未登录返回 401
//! - [`macro@check_permission`]：权限校验（AND 语义），无权限返回 403
//! - [`macro@check_role`]：角色校验（AND 语义），无角色返回 403
//! - [`macro@check_access_token`] / [`macro@check_client_token`] / [`macro@check_temp_token`]：token 类型校验（0.5.0 P2）
//! - [`macro@check_api_key`]：API Key 校验（0.6.1 新增，依据 spec annotation-check-api-key R-anno-003）
//! - [`macro@check_mfa`]：MFA 二级认证校验（v0.7.x 新增，依据 spec annotation-macros R-anno-004）
//! - [`macro@check_abac`]：ABAC 策略校验（v0.7.x 新增，依据 spec annotation-macros R-anno-005）
//! - [`macro@check_disable`]：账号禁用状态校验（v0.7.3 新增，依据 spec annotation-macros R-anno-006）
//!
//! # 覆盖矩阵
//!
//! 10 个宏对 13 个特性域（见 `src/lib.rs` 特性域段落）的覆盖情况：
//!
//! | 特性域 | 已有宏 | 缺失宏 | 备注 |
//! |--------|--------|--------|------|
//! | 登录认证 | `#[check_login]` / `#[check_access_token]` / `#[check_client_token]` / `#[check_temp_token]` | — | check_login 校验登录状态；token 类型宏校验 token 类型粒度 |
//! | 权限认证 | `#[check_permission]` / `#[check_role]` | — | RBAC，AND 语义 |
//! | Session 会话 | — | `#[check_session]`? | 手动调用 GarrisonUtil 会话 API |
//! | OAuth2 | — | `#[check_oauth2]`? | 通过 OAuth2Client + `login_by_token` 建立 |
//! | 单点登录 (SSO) | — | `#[check_sso]`? | SsoClient ticket 协议层处理 |
//! | JWT | — | — | 协议层 JwtHandler sign/verify，非注解校验型 |
//! | 微服务网关鉴权 | — | `#[check_sign]`? | SignHandler HMAC-SHA256 签名校验 |
//! | API 接口鉴权 | `#[check_api_key]` | — | 支持 namespace 参数 |
//! | TOTP 动态验证码 | `#[check_mfa]` | — | v0.7.x 新增，封装 check_safe 二级认证校验 |
//! | ABAC 策略校验 | `#[check_abac]` | — | v0.7.x 新增，纯 ABAC 校验（无 RBAC 前置） |
//! | 账号禁用状态 | `#[check_disable]` | — | v0.7.3 新增，封装 check_disable 禁用账号校验 |
//! | Basic 认证 | — | — | 协议层 Extractor（secure::httpbasic） |
//! | Digest 认证 | — | — | 协议层 Extractor（secure::httpdigest） |
//! | 路由拦截鉴权 | — | — | Web 框架适配（GarrisonRouter + middleware），非校验型 |
//! | 插件化扩展 | — | — | 编译期插件注册（inventory），非校验型 |
//!
//! # 限制
//!
//! - 支持 `async fn` 和 `sync fn`（sync fn 调用 `check_*_sync()` 阻塞版本）
//! - 仅支持 axum handler（原返回类型需实现 `axum::response::IntoResponse`）
//! - 宏展开依赖 `GarrisonUtil` 全局单例（需先 `GarrisonManager::init`）
//! - sync fn wrapper 需在 tokio multi_thread runtime 上下文内调用（`block_in_place` 要求）
//!
//! # 展开结构
//!
//! 宏将原 fn（async 或 sync）重命名为内部函数 `__garrison_inner_<name>`，
//! 并生成同名的 wrapper 函数（返回 `axum::response::Response`），
//! 在 wrapper body 前插入 `GarrisonUtil::check_*()` 调用。
//! async fn 生成 async wrapper + `.await` 调用；sync fn 生成非 async wrapper + `_sync()` 调用：
//!
//! ```ignore
//! // 输入（async fn）
//! #[check_login]
//! async fn handler() -> &'static str { "ok" }
//!
//! // 展开（async）
//! async fn __garrison_inner_handler() -> &'static str { "ok" }
//!
//! async fn handler() -> axum::response::Response {
//!     // check_login().await ...
//!     ::axum::response::IntoResponse::into_response(
//!         __garrison_inner_handler().await
//!     )
//! }
//!
//! // 输入（sync fn）
//! #[check_login]
//! fn sync_handler() -> &'static str { "ok" }
//!
//! // 展开（sync）
//! fn __garrison_inner_sync_handler() -> &'static str { "ok" }
//!
//! fn sync_handler() -> axum::response::Response {
//!     // check_login_sync() ...
//!     ::axum::response::IntoResponse::into_response(
//!         __garrison_inner_sync_handler()
//!     )
//! }
//! ```

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    FnArg, Ident, ItemFn, LitStr, Token,
};

// ============================================================================
// 公开 proc_macro_attribute
// ============================================================================

/// 登录校验属性宏。
///
/// 标注在 async fn 或 sync fn 上，编译期生成 wrapper 在 fn body 前插入
/// `GarrisonUtil::check_login()`（async）或 `check_login_sync()`（sync）调用。未登录请求返回 401。
///
/// # 限制
///
/// - 支持 `async fn` 和 `sync fn`（sync fn 需在 tokio multi_thread runtime 内调用）
/// - 仅支持 axum handler（原返回类型需实现 `axum::response::IntoResponse`）
///
/// # 示例
///
/// ```ignore
/// use garrison::check_login;
/// use axum::response::IntoResponse;
///
/// #[check_login]
/// async fn handler() -> impl IntoResponse {
///     "hello"
/// }
///
/// #[check_login]
/// fn sync_handler() -> impl IntoResponse {
///     "hello"
/// }
/// ```
#[proc_macro_attribute]
pub fn check_login(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_login(item_fn)
}

/// 权限校验属性宏。
///
/// 标注在 async fn 或 sync fn 上，编译期生成 wrapper 在 fn body 前插入
/// `GarrisonUtil::check_permission("perm")`（async）或 `check_permission_sync("perm")`（sync）调用。无权限请求返回 403。
///
/// # 两种参数形式
///
/// ## 1. 位置参数（向后兼容，仅 RBAC）
///
/// 支持多个权限参数 `#[check_permission("a", "b")]`（AND 语义：必须持有全部权限）。
///
/// ## 2. 命名参数（v0.7.0 新增，RBAC + ABAC）
///
/// `#[check_permission(permission = "order:read", resource = "Resource::\"order\"", abac = "resource.user_id == principal.id")]`
///
/// - `permission`（必填）：单个权限标识
/// - `resource`（可选）：Cedar resource EntityUid 字符串（默认 `Resource::"default"`）
/// - `abac`（可选）：Cedar 条件表达式，RBAC 通过后自动调用 ABAC 求值
///
/// `abac` 参数存在时，RBAC 通过后调用 `garrison::abac::check_abac_with_policy(permission, resource, abac_expr)`。
/// resource 由 `resource` 属性注入（默认 `Resource::"default"`）。
/// ABAC 拒绝时返回 `GarrisonError::NotPermission`。`abac` feature 关闭时 ABAC 调用为 no-op。
///
/// # 限制
///
/// - 支持 `async fn` 和 `sync fn`（sync fn 需在 tokio multi_thread runtime 内调用）
/// - 位置参数形式：至少一个权限参数
/// - 命名参数形式：`permission` 必填，`resource` 和 `abac` 可选
/// - 两种形式不可混用
///
/// # 示例
///
/// ```ignore
/// use garrison::check_permission;
/// use axum::response::IntoResponse;
///
/// // 位置参数（仅 RBAC）
/// #[check_permission("user:read")]
/// async fn handler() -> impl IntoResponse { "ok" }
///
/// #[check_permission("user:read", "user:write")]
/// async fn admin_handler() -> impl IntoResponse { "admin" }
///
/// // 命名参数（RBAC + ABAC，显式 resource）
/// #[check_permission(permission = "order:read", resource = "Resource::\"order\"", abac = "resource.user_id == principal.id")]
/// async fn get_order() -> impl IntoResponse { "order" }
///
/// // 命名参数（RBAC + ABAC，默认 resource）
/// #[check_permission(permission = "order:read", abac = "resource.user_id == principal.id")]
/// async fn get_order_default() -> impl IntoResponse { "order" }
///
/// // 命名参数（仅 RBAC，等价于位置参数单权限形式）
/// #[check_permission(permission = "user:read")]
/// async fn named_handler() -> impl IntoResponse { "ok" }
///
/// #[check_permission("user:read")]
/// fn sync_handler() -> impl IntoResponse { "ok" }
/// ```
#[proc_macro_attribute]
pub fn check_permission(attr: TokenStream, item: TokenStream) -> TokenStream {
    // 优先尝试命名参数解析（permission = "...", resource = "...", abac = "..."）
    let attr2: proc_macro2::TokenStream = attr.clone().into();
    if let Ok(named) = syn::parse2::<CheckPermissionAttr>(attr2) {
        let item_fn = parse_macro_input!(item as ItemFn);
        // resource 未提供时使用默认值（向后兼容）
        let resource = named.resource.as_deref().unwrap_or(DEFAULT_RESOURCE);
        return expand_check_permission_named(
            &named.permission,
            resource,
            named.abac.as_deref(),
            item_fn,
        );
    }
    // 回退到位置参数解析（向后兼容："perm1", "perm2"）
    let args = parse_macro_input!(attr with Punctuated::<LitStr, Token![,]>::parse_terminated);
    let perms: Vec<String> = args.iter().map(|s| s.value()).collect();
    if perms.is_empty() {
        return syn::Error::new(
            Span::call_site(),
            "#[check_permission] 需要至少一个权限参数，例如 #[check_permission(\"user:read\")]",
        )
        .to_compile_error()
        .into();
    }
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_with_args("check_permission", &perms, item_fn)
}

/// 角色校验属性宏。
///
/// 标注在 async fn 或 sync fn 上，编译期生成 wrapper 在 fn body 前插入
/// `GarrisonUtil::check_role("role")`（async）或 `check_role_sync("role")`（sync）调用。无角色请求返回 403。
///
/// 支持多个角色参数（AND 语义：必须持有全部角色）。
///
/// # 限制
///
/// - 支持 `async fn` 和 `sync fn`（sync fn 需在 tokio multi_thread runtime 内调用）
/// - 至少一个角色参数
///
/// # 示例
///
/// ```ignore
/// use garrison::check_role;
/// use axum::response::IntoResponse;
///
/// #[check_role("admin")]
/// async fn handler() -> impl IntoResponse { "ok" }
///
/// #[check_role("admin")]
/// fn sync_handler() -> impl IntoResponse { "ok" }
/// ```
#[proc_macro_attribute]
pub fn check_role(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr with Punctuated::<LitStr, Token![,]>::parse_terminated);
    let roles: Vec<String> = args.iter().map(|s| s.value()).collect();
    if roles.is_empty() {
        return syn::Error::new(
            Span::call_site(),
            "#[check_role] 需要至少一个角色参数，例如 #[check_role(\"admin\")]",
        )
        .to_compile_error()
        .into();
    }
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_with_args("check_role", &roles, item_fn)
}

/// access_token 类型校验属性宏（0.5.0 新增，依据 spec annotation-macros P2）。
///
/// 标注在 async fn 或 sync fn 上，编译期生成 wrapper 在 fn body 前插入
/// `GarrisonUtil::check_access_token()`（async）或 `check_access_token_sync()`（sync）调用。未登录请求返回 401。
///
/// # 限制
///
/// - 支持 `async fn` 和 `sync fn`（sync fn 需在 tokio multi_thread runtime 内调用）
/// - 仅支持 axum handler
///
/// # 示例
///
/// ```ignore
/// use garrison::check_access_token;
/// use axum::response::IntoResponse;
///
/// #[check_access_token]
/// async fn handler() -> impl IntoResponse { "ok" }
/// ```
#[proc_macro_attribute]
pub fn check_access_token(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_no_args("check_access_token", item_fn)
}

/// client_token 类型校验属性宏（0.5.0 新增，依据 spec annotation-macros P2）。
///
/// 标注在 async fn 或 sync fn 上，编译期生成 wrapper 在 fn body 前插入
/// `GarrisonUtil::check_client_token()`（async）或 `check_client_token_sync()`（sync）调用。未登录请求返回 401。
#[proc_macro_attribute]
pub fn check_client_token(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_no_args("check_client_token", item_fn)
}

/// temp_token 类型校验属性宏（0.5.0 新增，依据 spec annotation-macros P2）。
///
/// 标注在 async fn 或 sync fn 上，编译期生成 wrapper 在 fn body 前插入
/// `GarrisonUtil::check_temp_token()`（async）或 `check_temp_token_sync()`（sync）调用。未登录请求返回 401。
#[proc_macro_attribute]
pub fn check_temp_token(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_no_args("check_temp_token", item_fn)
}

/// API Key 校验属性宏（0.6.1 新增，依据 spec annotation-check-api-key R-anno-003）。
///
/// 标注在 async fn 或 sync fn 上，编译期生成 wrapper 在 fn body 前插入
/// `GarrisonUtil::check_api_key(namespace)`（async）或 `check_api_key_sync(namespace)`（sync）调用。校验失败返回 401/403。
///
/// # 参数
///
/// - 无参数：`#[check_api_key]` → 使用默认命名空间 `"default"`
/// - `namespace = "xxx"`：`#[check_api_key(namespace = "ns1")]` → 使用指定命名空间
///
/// # 错误参数
///
/// - `#[check_api_key(foo = "bar")]`：编译时报错（仅支持 `namespace` 参数）
/// - `#[check_api_key("ns1")]`：编译时报错（必须使用 `namespace = "ns1"` 形式）
///
/// # 限制
///
/// - 支持 `async fn` 和 `sync fn`（sync fn 需在 tokio multi_thread runtime 内调用）
/// - 仅支持 axum handler
///
/// # 示例
///
/// ```ignore
/// use garrison::check_api_key;
/// use axum::response::IntoResponse;
///
/// #[check_api_key]
/// async fn handler() -> impl IntoResponse { "ok" }
///
/// #[check_api_key(namespace = "internal")]
/// async fn internal_handler() -> impl IntoResponse { "internal" }
/// ```
#[proc_macro_attribute]
pub fn check_api_key(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_parsed = parse_macro_input!(attr as CheckApiKeyAttr);
    let item_fn = parse_macro_input!(item as ItemFn);
    let ns = attr_parsed
        .namespace
        .unwrap_or_else(|| "default".to_string());
    expand_check_api_key(&ns, item_fn)
}

/// MFA 二级认证校验属性宏（v0.7.x 新增，依据 spec annotation-macros R-anno-004）。
///
/// 标注在 async fn 或 sync fn 上，编译期生成 wrapper 在 fn body 前插入
/// `GarrisonUtil::check_safe()`（async）或 `check_safe_sync()`（sync）调用。未通过二级认证返回 403。
///
/// # 限制
///
/// - 支持 `async fn` 和 `sync fn`（sync fn 需在 tokio multi_thread runtime 内调用）
/// - 仅支持 axum handler（原返回类型需实现 `axum::response::IntoResponse`）
/// - 无参数
///
/// # 示例
///
/// ```ignore
/// use garrison::check_mfa;
/// use axum::response::IntoResponse;
///
/// #[check_mfa]
/// async fn handler() -> impl IntoResponse { "mfa_ok" }
///
/// #[check_mfa]
/// fn sync_handler() -> impl IntoResponse { "mfa_ok" }
/// ```
#[proc_macro_attribute]
pub fn check_mfa(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_no_args("check_safe", item_fn)
}

/// 账号禁用状态校验属性宏（v0.7.3 新增，依据 spec annotation-macros R-anno-006）。
///
/// 标注在 async fn 或 sync fn 上，编译期生成 wrapper 在 fn body 前插入
/// `GarrisonUtil::check_disable()`（async）或 `check_disable_sync()`（sync）调用。
/// 账号已禁用时返回 `GarrisonError::DisableService`（对应 403）。
///
/// 典型场景：敏感操作前校验账号是否被管理员禁用（如违规账号限制关键接口访问）。
/// 与 `#[check_login]` 区别：后者校验登录状态，本宏校验账号是否被显式禁用。
///
/// # 限制
///
/// - 支持 `async fn` 和 `sync fn`（sync fn 需在 tokio multi_thread runtime 内调用）
/// - 仅支持 axum handler（原返回类型需实现 `axum::response::IntoResponse`）
/// - 无参数
///
/// # 示例
///
/// ```ignore
/// use garrison::check_disable;
/// use axum::response::IntoResponse;
///
/// #[check_disable]
/// async fn handler() -> impl IntoResponse { "ok" }
///
/// #[check_disable]
/// fn sync_handler() -> impl IntoResponse { "ok" }
/// ```
#[proc_macro_attribute]
pub fn check_disable(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_no_args("check_disable", item_fn)
}

/// ABAC 策略校验属性宏（v0.7.x 新增，依据 spec annotation-macros R-anno-005）。
///
/// 标注在 async fn 或 sync fn 上，编译期生成 wrapper 在 fn body 前插入
/// `garrison::abac::check_abac_with_policy(action, resource, abac_expr)` 调用。ABAC 策略拒绝返回 403。
///
/// 纯 ABAC 校验，不依赖 RBAC 权限表。与 `#[check_permission(permission=, resource=, abac=)]` 区别：
/// 后者先做 RBAC 校验，本宏直接做 ABAC 校验。
///
/// # 参数
///
/// - `action`（必填）：Cedar action 标识（权限名，如 "order:read"）
/// - `resource`（可选）：Cedar resource EntityUid 字符串（默认 `Resource::"default"`）
/// - `abac`（必填）：Cedar 条件表达式（如 "resource.user_id == principal.id"）
///
/// # Feature 依赖
///
/// - `abac` feature 开启：执行实际 Cedar 策略求值
/// - `abac` feature 关闭：`check_abac_with_policy` 为 no-op stub（返回 `Ok(())`）
///
/// # 限制
///
/// - 支持 `async fn` 和 `sync fn`（sync fn 需在 tokio multi_thread runtime 内调用）
/// - 仅支持 axum handler
/// - `action` 和 `abac` 均为必填，`resource` 可选
///
/// # 示例
///
/// ```ignore
/// use garrison::check_abac;
/// use axum::response::IntoResponse;
///
/// // 显式 resource
/// #[check_abac(action = "order:read", resource = "Resource::\"order\"", abac = "resource.user_id == principal.id")]
/// async fn handler() -> impl IntoResponse { "abac_ok" }
///
/// // 默认 resource（Resource::"default"）
/// #[check_abac(action = "order:read", abac = "resource.user_id == principal.id")]
/// async fn default_resource_handler() -> impl IntoResponse { "abac_ok" }
///
/// #[check_abac(action = "order:read", resource = "Resource::\"order\"", abac = "resource.user_id == principal.id")]
/// fn sync_handler() -> impl IntoResponse { "abac_ok" }
/// ```
#[proc_macro_attribute]
pub fn check_abac(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_parsed = parse_macro_input!(attr as CheckAbacAttr);
    let item_fn = parse_macro_input!(item as ItemFn);
    // resource 未提供时使用默认值（向后兼容）
    let resource = attr_parsed.resource.as_deref().unwrap_or(DEFAULT_RESOURCE);
    expand_check_abac(&attr_parsed.action, resource, &attr_parsed.abac, item_fn)
}

// ============================================================================
// 内部展开逻辑
// ============================================================================

/// 默认 Cedar resource EntityUid 字符串（向后兼容）。
///
/// 宏属性 `resource = "..."` 未提供时使用此默认值。
const DEFAULT_RESOURCE: &str = r#"Resource::"default""#;

/// 解析 `#[check_api_key]` 属性参数。
///
/// 支持两种形式：
/// - 空：`#[check_api_key]` → `namespace: None`（调用时使用 `"default"`）
/// - `namespace = "xxx"`：`#[check_api_key(namespace = "ns1")]` → `namespace: Some("ns1")`
///
/// 不支持其他形式（如 `#[check_api_key("ns1")]` 或 `#[check_api_key(foo = "bar")]`），
/// 解析时返回编译错误。
struct CheckApiKeyAttr {
    namespace: Option<String>,
}

impl Parse for CheckApiKeyAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(Self { namespace: None });
        }
        let ident: Ident = input.parse()?;
        if ident != "namespace" {
            return Err(syn::Error::new(
                ident.span(),
                "不支持的属性参数，仅支持 `namespace = \"xxx\"`",
            ));
        }
        let _: Token![=] = input.parse()?;
        let lit: LitStr = input.parse()?;
        Ok(Self {
            namespace: Some(lit.value()),
        })
    }
}

/// 解析 `#[check_permission]` 命名参数形式（v0.7.0 新增）。
///
/// 支持形式：`#[check_permission(permission = "x", resource = "r", abac = "expr")]`
///
/// - `permission`（必填）：权限标识
/// - `resource`（可选）：Cedar resource EntityUid 字符串（如 `Resource::"default"`）。
///   未提供时使用默认值 `Resource::"default"`（向后兼容）。
/// - `abac`（可选）：Cedar 条件表达式
///
/// 位置参数形式（`#[check_permission("x")]`）不走此解析器，
/// 在 `check_permission` 函数中先尝试命名参数解析，失败后回退到位置参数。
struct CheckPermissionAttr {
    permission: String,
    resource: Option<String>,
    abac: Option<String>,
}

impl Parse for CheckPermissionAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut permission = None;
        let mut resource = None;
        let mut abac = None;
        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            let _: Token![=] = input.parse()?;
            let lit: LitStr = input.parse()?;
            match ident.to_string().as_str() {
                "permission" => permission = Some(lit.value()),
                "resource" => resource = Some(lit.value()),
                "abac" => abac = Some(lit.value()),
                _ => {
                    return Err(syn::Error::new(
                        ident.span(),
                        "不支持的属性参数，仅支持 `permission`、`resource` 和 `abac`",
                    ))
                },
            }
            if !input.is_empty() {
                let _: Token![,] = input.parse()?;
            }
        }
        let permission = permission.ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "#[check_permission] 命名参数形式需要 `permission` 参数",
            )
        })?;
        Ok(Self {
            permission,
            resource,
            abac,
        })
    }
}

/// 解析 `#[check_abac]` 命名参数形式（v0.7.x 新增）。
///
/// 支持形式：`#[check_abac(action = "x", resource = "r", abac = "expr")]`
///
/// - `action`（必填）：Cedar action 标识
/// - `resource`（可选）：Cedar resource EntityUid 字符串（如 `Resource::"default"`）。
///   未提供时使用默认值 `Resource::"default"`（向后兼容）。
/// - `abac`（必填）：Cedar 条件表达式
///
/// `action` 和 `abac` 均为必填，缺失任一返回编译错误。
struct CheckAbacAttr {
    action: String,
    resource: Option<String>,
    abac: String,
}

impl Parse for CheckAbacAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut action = None;
        let mut resource = None;
        let mut abac = None;
        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            let _: Token![=] = input.parse()?;
            let lit: LitStr = input.parse()?;
            match ident.to_string().as_str() {
                "action" => action = Some(lit.value()),
                "resource" => resource = Some(lit.value()),
                "abac" => abac = Some(lit.value()),
                _ => {
                    return Err(syn::Error::new(
                        ident.span(),
                        "不支持的属性参数，仅支持 `action`、`resource` 和 `abac`",
                    ))
                },
            }
            if !input.is_empty() {
                let _: Token![,] = input.parse()?;
            }
        }
        let action = action.ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "#[check_abac] 需要 `action` 参数，例如 #[check_abac(action = \"order:read\", abac = \"...\")]",
            )
        })?;
        let abac = abac.ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "#[check_abac] 需要 `abac` 参数，例如 #[check_abac(action = \"...\", abac = \"resource.user_id == principal.id\")]",
            )
        })?;
        Ok(Self {
            action,
            resource,
            abac,
        })
    }
}

/// 展开 `#[check_api_key]`：在 fn body 前插入 `GarrisonUtil::check_api_key(namespace)` 调用。
///
/// `check_api_key(namespace)` 返回 `GarrisonResult<()>`：
/// - `Ok(())`：API Key 有效，继续执行 fn body
/// - `Err(e)`：校验失败（InvalidToken / ExpiredToken / NotLogin），返回错误对应的 Response
fn expand_check_api_key(namespace: &str, item_fn: ItemFn) -> TokenStream {
    let asyncness = detect_asyncness(&item_fn);
    let checks = match asyncness {
        Asyncness::Async => quote! {
            if let ::std::result::Result::Err(__garrison_err) = ::garrison::GarrisonUtil::check_api_key(#namespace).await {
                return ::axum::response::IntoResponse::into_response(__garrison_err);
            }
        },
        Asyncness::Sync => quote! {
            if let ::std::result::Result::Err(__garrison_err) = ::garrison::GarrisonUtil::check_api_key_sync(#namespace) {
                return ::axum::response::IntoResponse::into_response(__garrison_err);
            }
        },
    };
    expand_wrapper(&item_fn, checks, asyncness)
}

/// 检测 fn 是 async 还是 sync。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Asyncness {
    Async,
    Sync,
}

fn detect_asyncness(item_fn: &ItemFn) -> Asyncness {
    if item_fn.sig.asyncness.is_some() {
        Asyncness::Async
    } else {
        Asyncness::Sync
    }
}

/// 展开 `#[check_login]`：在 fn body 前插入 `GarrisonUtil::check_login()` 调用。
///
/// `check_login()` 返回 `GarrisonResult<bool>`：
/// - `Ok(true)`：已登录，继续执行 fn body
/// - `Ok(false)`：未登录（`throw_on_not_login=false`），返回 401
/// - `Err(e)`：错误（如 Manager 未初始化，或 `throw_on_not_login=true` 时未登录），
///   返回错误对应的 Response（NotLogin → 401，其他 → 500/etc.）
fn expand_check_login(item_fn: ItemFn) -> TokenStream {
    let asyncness = detect_asyncness(&item_fn);
    let checks = match asyncness {
        Asyncness::Async => quote! {
            match ::garrison::GarrisonUtil::check_login().await {
                ::std::result::Result::Ok(true) => {},
                ::std::result::Result::Ok(false) => {
                    return ::axum::response::IntoResponse::into_response(
                        ::garrison::GarrisonError::NotLogin("未登录（check_login 返回 false）".to_string())
                    );
                }
                ::std::result::Result::Err(__garrison_err) => {
                    return ::axum::response::IntoResponse::into_response(__garrison_err);
                }
            }
        },
        Asyncness::Sync => quote! {
            match ::garrison::GarrisonUtil::check_login_sync() {
                ::std::result::Result::Ok(true) => {},
                ::std::result::Result::Ok(false) => {
                    return ::axum::response::IntoResponse::into_response(
                        ::garrison::GarrisonError::NotLogin("未登录（check_login 返回 false）".to_string())
                    );
                }
                ::std::result::Result::Err(__garrison_err) => {
                    return ::axum::response::IntoResponse::into_response(__garrison_err);
                }
            }
        },
    };
    expand_wrapper(&item_fn, checks, asyncness)
}

/// 展开 `#[check_access_token]` / `#[check_client_token]` / `#[check_temp_token]`：
/// 在 fn body 前插入 `GarrisonUtil::<method>()` 调用（无参数，返回 `GarrisonResult<()>`）。
///
/// 与 `expand_check_login` 区别：后者返回 `GarrisonResult<bool>`，需要处理 `Ok(false)` 路径；
/// 本函数处理 `GarrisonResult<()>`，仅 `Err` 路径需转发。
fn expand_check_no_args(method: &str, item_fn: ItemFn) -> TokenStream {
    let asyncness = detect_asyncness(&item_fn);
    let method_ident = format_ident!("{}", method);
    let sync_method_ident = format_ident!("{}_sync", method);
    let checks = match asyncness {
        Asyncness::Async => quote! {
            if let ::std::result::Result::Err(__garrison_err) = ::garrison::GarrisonUtil::#method_ident().await {
                return ::axum::response::IntoResponse::into_response(__garrison_err);
            }
        },
        Asyncness::Sync => quote! {
            if let ::std::result::Result::Err(__garrison_err) = ::garrison::GarrisonUtil::#sync_method_ident() {
                return ::axum::response::IntoResponse::into_response(__garrison_err);
            }
        },
    };
    expand_wrapper(&item_fn, checks, asyncness)
}

/// 展开 `#[check_permission]` / `#[check_role]`：插入多次调用（AND 语义）。
fn expand_check_with_args(method: &str, args: &[String], item_fn: ItemFn) -> TokenStream {
    let asyncness = detect_asyncness(&item_fn);
    let method_ident = format_ident!("{}", method);
    let sync_method_ident = format_ident!("{}_sync", method);
    // 每个参数生成一次调用，AND 语义：任一失败立即 return
    let calls: Vec<proc_macro2::TokenStream> = args
        .iter()
        .map(|arg| match asyncness {
            Asyncness::Async => quote! {
                if let Err(__garrison_err) = ::garrison::GarrisonUtil::#method_ident(#arg).await {
                    return ::axum::response::IntoResponse::into_response(__garrison_err);
                }
            },
            Asyncness::Sync => quote! {
                if let Err(__garrison_err) = ::garrison::GarrisonUtil::#sync_method_ident(#arg) {
                    return ::axum::response::IntoResponse::into_response(__garrison_err);
                }
            },
        })
        .collect();
    let checks = quote! { #(#calls)* };
    expand_wrapper(&item_fn, checks, asyncness)
}

/// 展开 `#[check_permission]` 命名参数形式（RBAC + 可选 ABAC）。
///
/// 生成两段检查代码：
/// 1. RBAC 检查（始终）：`GarrisonUtil::check_permission(permission)` / `check_permission_sync(permission)`
/// 2. ABAC 检查（`abac` 参数存在时）：`garrison::abac::check_abac_with_policy(permission, resource, expr)`
///
/// ABAC 检查在 RBAC 通过后执行，AND 语义：任一失败立即 return 错误响应。
/// resource 参数由宏属性注入，避免硬编码。
///
/// sync fn 的 ABAC 检查通过 `block_in_place` + `block_on` 包装 async 调用，
/// 与 `GarrisonUtil::check_permission_sync` 的同步包装模式一致。
fn expand_check_permission_named(
    permission: &str,
    resource: &str,
    abac: Option<&str>,
    item_fn: ItemFn,
) -> TokenStream {
    let asyncness = detect_asyncness(&item_fn);

    // RBAC 检查（始终生成）
    let rbac_check = match asyncness {
        Asyncness::Async => quote! {
            if let ::std::result::Result::Err(__garrison_err) =
                ::garrison::GarrisonUtil::check_permission(#permission).await
            {
                return ::axum::response::IntoResponse::into_response(__garrison_err);
            }
        },
        Asyncness::Sync => quote! {
            if let ::std::result::Result::Err(__garrison_err) =
                ::garrison::GarrisonUtil::check_permission_sync(#permission)
            {
                return ::axum::response::IntoResponse::into_response(__garrison_err);
            }
        },
    };

    // ABAC 检查（仅 abac 参数存在时生成）
    // resource 参数显式注入，避免硬编码
    let abac_check = match abac {
        Some(expr) => match asyncness {
            Asyncness::Async => quote! {
                if let ::std::result::Result::Err(__garrison_err) =
                    ::garrison::abac::check_abac_with_policy(#permission, #resource, #expr).await
                {
                    return ::axum::response::IntoResponse::into_response(__garrison_err);
                }
            },
            Asyncness::Sync => quote! {
                {
                    let __garrison_perm = #permission.to_string();
                    let __garrison_resource = #resource.to_string();
                    let __garrison_abac = #expr.to_string();
                    if let ::std::result::Result::Err(__garrison_err) =
                        ::tokio::task::block_in_place(||
                            ::tokio::runtime::Handle::current().block_on(
                                ::garrison::abac::check_abac_with_policy(
                                    &__garrison_perm,
                                    &__garrison_resource,
                                    &__garrison_abac,
                                )
                            )
                        )
                    {
                        return ::axum::response::IntoResponse::into_response(__garrison_err);
                    }
                }
            },
        },
        None => quote! {},
    };

    let checks = quote! {
        #rbac_check
        #abac_check
    };
    expand_wrapper(&item_fn, checks, asyncness)
}

/// 展开 `#[check_abac]`：纯 ABAC 校验（无 RBAC 前置）。
///
/// 生成 wrapper 在 fn body 前插入 `::garrison::abac::check_abac_with_policy(action, resource, expr)` 调用。
/// async fn 直接 `.await`；sync fn 通过 `block_in_place` + `Handle::current().block_on()` 包装。
/// resource 参数由宏属性注入，避免硬编码。
///
/// 与 `expand_check_permission_named` 的 ABAC 部分类似，但不生成 RBAC 检查代码。
fn expand_check_abac(
    action: &str,
    resource: &str,
    abac_expr: &str,
    item_fn: ItemFn,
) -> TokenStream {
    let asyncness = detect_asyncness(&item_fn);

    let checks = match asyncness {
        Asyncness::Async => quote! {
            if let ::std::result::Result::Err(__garrison_err) =
                ::garrison::abac::check_abac_with_policy(#action, #resource, #abac_expr).await
            {
                return ::axum::response::IntoResponse::into_response(__garrison_err);
            }
        },
        Asyncness::Sync => quote! {
            {
                let __garrison_action = #action.to_string();
                let __garrison_resource = #resource.to_string();
                let __garrison_abac = #abac_expr.to_string();
                if let ::std::result::Result::Err(__garrison_err) =
                    ::tokio::task::block_in_place(||
                        ::tokio::runtime::Handle::current().block_on(
                            ::garrison::abac::check_abac_with_policy(
                                &__garrison_action,
                                &__garrison_resource,
                                &__garrison_abac,
                            )
                        )
                    )
                {
                    return ::axum::response::IntoResponse::into_response(__garrison_err);
                }
            }
        },
    };
    expand_wrapper(&item_fn, checks, asyncness)
}

/// 生成 wrapper 函数 + 重命名的 inner 函数。
///
/// - inner：原 sig（重命名 ident）+ 原 body
/// - wrapper：原 ident，返回 `axum::response::Response`，body 前插入 `checks`
///
/// 根据 `asyncness` 决定 wrapper 和 inner 是否为 `async fn`，以及 inner 调用是否 `.await`。
/// async fn：wrapper/inner 均为 async，inner 调用带 `.await`
/// sync fn：wrapper/inner 均非 async，inner 调用无 `.await`（checks 也由 expand_* 生成 sync 版本）
///
/// 参数转发使用 fresh idents（`__garrison_arg_N`），避免 pattern-vs-expression 问题。
fn expand_wrapper(
    item_fn: &ItemFn,
    checks: proc_macro2::TokenStream,
    asyncness: Asyncness,
) -> TokenStream {
    let vis = &item_fn.vis;
    let sig = &item_fn.sig;
    let original_name = &sig.ident;
    let inner_name = format_ident!("__garrison_inner_{}", original_name);
    let block = &item_fn.block;
    let attrs = &item_fn.attrs;

    // 为每个 Typed 参数生成 fresh ident；Receiver 直接用 self
    let wrapper_inputs: Punctuated<FnArg, Token![,]> = sig
        .inputs
        .iter()
        .enumerate()
        .map(|(i, arg)| match arg {
            FnArg::Typed(pat_type) => {
                let id = format_ident!("__garrison_arg_{}", i);
                let ty = &pat_type.ty;
                let arg_attrs = &pat_type.attrs;
                syn::parse_quote! { #(#arg_attrs)* #id: #ty }
            },
            FnArg::Receiver(_) => arg.clone(),
        })
        .collect();

    let forward_args: Vec<proc_macro2::TokenStream> = sig
        .inputs
        .iter()
        .enumerate()
        .map(|(i, arg)| match arg {
            FnArg::Typed(_) => {
                let id = format_ident!("__garrison_arg_{}", i);
                quote! { #id }
            },
            FnArg::Receiver(_) => quote! { self },
        })
        .collect();

    // inner sig：原 sig + ident 重命名
    let mut inner_sig = sig.clone();
    inner_sig.ident = inner_name.clone();

    // wrapper sig：原 sig + inputs 替换为 fresh idents + 返回类型改为 Response
    let mut wrapper_sig = sig.clone();
    wrapper_sig.inputs = wrapper_inputs;
    wrapper_sig.output = syn::parse_quote! { -> ::axum::response::Response };

    // sync fn 时 inner 调用无 .await（sig 已从原 fn 继承 asyncness，无需额外修改）
    let inner_call = match asyncness {
        Asyncness::Async => quote! { #inner_name(#(#forward_args),*).await },
        Asyncness::Sync => quote! { #inner_name(#(#forward_args),*) },
    };

    let expanded = quote! {
        // inner：保留原 sig（仅重命名）+ 原 body + 原 attrs（如 #[cfg]/#[doc]）
        #(#attrs)*
        #vis #inner_sig #block

        // wrapper：原名称 + Response 返回类型，body 前插入检查代码
        #vis #wrapper_sig {
            #checks
            ::axum::response::IntoResponse::into_response(#inner_call)
        }
    };
    expanded.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn detect_asyncness_returns_async_for_async_fn() {
        let item_fn: ItemFn = parse_quote! { async fn handler() {} };
        assert_eq!(detect_asyncness(&item_fn), Asyncness::Async);
    }

    #[test]
    fn detect_asyncness_returns_sync_for_sync_fn() {
        let item_fn: ItemFn = parse_quote! { fn handler() {} };
        assert_eq!(detect_asyncness(&item_fn), Asyncness::Sync);
    }
}
