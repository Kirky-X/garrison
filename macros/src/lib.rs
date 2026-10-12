// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Garrison 过程宏 crate：axum handler 鉴权注解属性宏。
//!
//! 提供 13 个 `#[proc_macro_attribute]`：登录/权限/角色/token 类型（access/client/temp）/API Key/MFA/ABAC/账号禁用校验共 10 个 axum wrapper 宏，加 3 个与 sdforge `#[forge]` 共存的 `*_forge` 变体（不生成 wrapper，直接改函数体，保留原返回类型）。均无 feature 门控，`annotation-macros` 一开即全可用。
//!
//! 宏覆盖登录/权限/角色/token/API Key/MFA/ABAC/禁用等特性域；Session/OAuth2/SSO/网关签名等特性域不提供注解，走协议层 API（JwtHandler、SsoClient、SignHandler）或手动调用。token 类型宏在默认装配下委托 `check_login`（不区分 token 类型），需要类型粒度校验须业务方覆写 `TokenLogic::check_*_token`（见 `src/stp/token.rs`）。
//!
//! 支持 `async fn` 和 `sync fn`（sync fn 调用 `check_*_sync()`，wrapper 需在 tokio multi_thread runtime 内调用）；仅支持 axum handler（原返回类型需实现 `axum::response::IntoResponse`）；宏展开依赖 `GarrisonUtil` 全局单例（需先 `GarrisonManager::builder().build().await`）。
//!
//! wrapper 宏将原 fn 重命名为 `__garrison_inner_<name>` 并生成同名 wrapper（返回 `axum::response::Response`），body 前插入 `GarrisonUtil::check_*()` 调用；async fn 生成 async wrapper + `.await`，sync fn 生成非 async wrapper + `_sync()` 调用。

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    FnArg, Ident, ItemFn, LitStr, Token,
};

// 公开 proc_macro_attribute

/// 登录校验属性宏：编译期生成 wrapper，在 fn body 前插入 `GarrisonUtil::check_login()`（async）或 `check_login_sync()`（sync）调用，未登录返回 401。支持 async/sync fn（sync 需 tokio multi_thread runtime），仅 axum handler，无参数。
#[proc_macro_attribute]
pub fn check_login(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_login(item_fn)
}

/// 权限校验属性宏：编译期生成 wrapper，在 fn body 前插入 `GarrisonUtil::check_permission("perm")`（async）或 `check_permission_sync("perm")`（sync）调用，无权限返回 403。多个权限参数 AND 语义（必须持有全部）。
///
/// 命名参数形式叠加 ABAC：`#[check_permission(permission = "order:read", resource = "Resource::\"order\"", abac = "resource.user_id == principal.id")]`。`permission` 必填，`resource`/`abac` 可选（`resource` 默认 `Resource::"default"`）；`abac` 存在且 RBAC 通过后调用 `garrison::abac::check_abac_with_policy`，ABAC 拒绝返回 `GarrisonError::NotPermission`，`abac` feature 关闭时 ABAC 调用为 no-op。位置参数与命名参数两种形式不可混用。
///
/// ```ignore
/// #[check_permission("user:read")]
/// async fn handler() -> impl IntoResponse { "ok" }
///
/// #[check_permission(permission = "order:read", abac = "resource.user_id == principal.id")]
/// async fn get_order() -> impl IntoResponse { "order" }
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
            "#[check_permission] requires at least one permission argument, e.g. #[check_permission(\"user:read\")]",
        )
        .to_compile_error()
        .into();
    }
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_with_args("check_permission", &perms, item_fn)
}

/// 角色校验属性宏：编译期生成 wrapper，在 fn body 前插入 `GarrisonUtil::check_role("role")`（async）或 `check_role_sync("role")`（sync）调用，无角色返回 403。多个角色参数 AND 语义，至少一个角色参数；支持 async/sync fn（sync 需 tokio multi_thread runtime）。
#[proc_macro_attribute]
pub fn check_role(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr with Punctuated::<LitStr, Token![,]>::parse_terminated);
    let roles: Vec<String> = args.iter().map(|s| s.value()).collect();
    if roles.is_empty() {
        return syn::Error::new(
            Span::call_site(),
            "#[check_role] requires at least one role argument, e.g. #[check_role(\"admin\")]",
        )
        .to_compile_error()
        .into();
    }
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_with_args("check_role", &roles, item_fn)
}

/// access_token 类型校验属性宏：在 fn body 前插入 `GarrisonUtil::check_access_token()`（async）或 `check_access_token_sync()`（sync）调用，未登录返回 401。仅 axum handler，无参数。
#[proc_macro_attribute]
pub fn check_access_token(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_no_args("check_access_token", item_fn)
}

/// client_token 类型校验属性宏：在 fn body 前插入 `GarrisonUtil::check_client_token()`（async）或 `check_client_token_sync()`（sync）调用，未登录返回 401。
#[proc_macro_attribute]
pub fn check_client_token(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_no_args("check_client_token", item_fn)
}

/// temp_token 类型校验属性宏：在 fn body 前插入 `GarrisonUtil::check_temp_token()`（async）或 `check_temp_token_sync()`（sync）调用，未登录返回 401。
#[proc_macro_attribute]
pub fn check_temp_token(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_no_args("check_temp_token", item_fn)
}

/// API Key 校验属性宏：在 fn body 前插入 `GarrisonUtil::check_api_key(namespace)`（async）或 `check_api_key_sync(namespace)`（sync）调用，校验失败返回 401/403。
///
/// 无参数用默认命名空间 `"default"`；`namespace = "xxx"` 用指定命名空间。其他形式（如 `#[check_api_key("ns1")]`、`#[check_api_key(foo = "bar")]`）编译报错。仅 axum handler。
#[proc_macro_attribute]
pub fn check_api_key(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_parsed = parse_macro_input!(attr as CheckApiKeyAttr);
    let item_fn = parse_macro_input!(item as ItemFn);
    let ns = attr_parsed
        .namespace
        .unwrap_or_else(|| "default".to_string());
    expand_check_api_key(&ns, item_fn)
}

/// MFA 二级认证校验属性宏：在 fn body 前插入 `GarrisonUtil::check_safe()`（async）或 `check_safe_sync()`（sync）调用，未通过二级认证返回 403。无参数，仅 axum handler。
#[proc_macro_attribute]
pub fn check_mfa(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_no_args("check_safe", item_fn)
}

/// 账号禁用状态校验属性宏：在 fn body 前插入 `GarrisonUtil::check_disable()`（async）或 `check_disable_sync()`（sync）调用，账号已禁用返回 `GarrisonError::DisableService`（403）。
///
/// 典型场景：敏感操作前校验账号是否被管理员禁用（如违规账号限制关键接口访问）。与 `#[check_login]` 区别：后者校验登录状态，本宏校验账号是否被显式禁用。无参数，仅 axum handler。
#[proc_macro_attribute]
pub fn check_disable(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_no_args("check_disable", item_fn)
}

/// ABAC 策略校验属性宏：在 fn body 前插入 `garrison::abac::check_abac_with_policy(action, resource, abac_expr)` 调用，ABAC 拒绝返回 403。
///
/// 纯 ABAC 校验，不依赖 RBAC 权限表；与 `#[check_permission(permission=, resource=, abac=)]` 区别：后者先做 RBAC 校验，本宏直接做 ABAC 校验。`action`/`abac` 必填，`resource` 可选（默认 `Resource::"default"`）。
///
/// `abac` feature 开启时执行实际 Cedar 策略求值；关闭时 `check_abac_with_policy` 降级为 fail-closed——声明了 `abac` 策略的端点默认拒绝（`Err(Config)`），仅未声明端点为 no-op 放行，可经 `garrison::abac::set_abac_missing_feature_policy(true)` 显式 opt-in 为 AllowWithWarn（放行 + warn）。详见 `src/abac/mod.rs`。
#[proc_macro_attribute]
pub fn check_abac(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_parsed = parse_macro_input!(attr as CheckAbacAttr);
    let item_fn = parse_macro_input!(item as ItemFn);
    // resource 未提供时使用默认值（向后兼容）
    let resource = attr_parsed.resource.as_deref().unwrap_or(DEFAULT_RESOURCE);
    expand_check_abac(&attr_parsed.action, resource, &attr_parsed.abac, item_fn)
}

// forge 兼容变体
//
// 与 sdforge `#[forge]` 宏共存的变体：不生成 wrapper 函数，直接在原函数体开头插入校验代码，保留原返回类型（`Result<T, E: From<GarrisonError>>`，校验失败返回 `Err(garrison_err.into())`）。
// `#[check_*_forge]` 必须置于 `#[forge]` 上方先展开（修改函数体），`#[forge]` 后展开时保留修改后的函数体并生成路由注册代码。

/// 登录校验属性宏（forge 兼容变体）：不生成 wrapper，直接在原函数体开头插入 `GarrisonUtil::check_login()`，校验失败返回 `Err(garrison_err.into())`（调用方错误类型须实现 `From<GarrisonError>`）。仅支持 async fn（`#[forge]` 宏要求 async handler）。
#[proc_macro_attribute]
pub fn check_login_forge(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_login_forge(item_fn).into()
}

/// 权限校验属性宏（forge 兼容变体）：不生成 wrapper，直接在原函数体开头插入 `GarrisonUtil::check_permission(arg)` 调用（AND 语义，至少一个权限参数），校验失败返回 `Err(garrison_err.into())`。仅支持 async fn，与 `#[forge]` 宏兼容。
#[proc_macro_attribute]
pub fn check_permission_forge(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr with Punctuated::<LitStr, Token![,]>::parse_terminated);
    let perms: Vec<String> = args.iter().map(|s| s.value()).collect();
    if perms.is_empty() {
        return syn::Error::new(
            Span::call_site(),
            "#[check_permission_forge] requires at least one permission argument, e.g. #[check_permission_forge(\"admin\")]",
        )
        .to_compile_error()
        .into();
    }
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_with_args_forge("check_permission", &perms, item_fn).into()
}

/// 角色校验属性宏（forge 兼容变体）：不生成 wrapper，直接在原函数体开头插入 `GarrisonUtil::check_role(arg)` 调用（AND 语义，至少一个角色参数），校验失败返回 `Err(garrison_err.into())`。仅支持 async fn，与 `#[forge]` 宏兼容。
#[proc_macro_attribute]
pub fn check_role_forge(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr with Punctuated::<LitStr, Token![,]>::parse_terminated);
    let roles: Vec<String> = args.iter().map(|s| s.value()).collect();
    if roles.is_empty() {
        return syn::Error::new(
            Span::call_site(),
            "#[check_role_forge] requires at least one role argument, e.g. #[check_role_forge(\"admin\")]",
        )
        .to_compile_error()
        .into();
    }
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_with_args_forge("check_role", &roles, item_fn).into()
}

// 内部展开逻辑

/// 默认 Cedar resource EntityUid 字符串（向后兼容）：宏属性 `resource = "..."` 未提供时使用。
const DEFAULT_RESOURCE: &str = r#"Resource::"default""#;

/// 解析 `#[check_api_key]` 属性参数：空使用默认命名空间（`namespace: None`），`namespace = "xxx"` 用指定命名空间；其他形式（如 `#[check_api_key("ns1")]`）解析时返回编译错误。
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
                "unsupported attribute argument; only `namespace = \"xxx\"` is supported",
            ));
        }
        let _: Token![=] = input.parse()?;
        let lit: LitStr = input.parse()?;
        Ok(Self {
            namespace: Some(lit.value()),
        })
    }
}

/// 解析 `#[check_permission]` 命名参数形式 `#[check_permission(permission = "x", resource = "r", abac = "expr")]`：`permission` 必填，`resource`/`abac` 可选（`resource` 默认 `Resource::"default"`，向后兼容）；位置参数形式不走此解析器，在 `check_permission` 中先试命名参数、失败后回退。
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
                        "unsupported attribute argument; only `permission`, `resource` and `abac` are supported",
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
                "#[check_permission] named-argument form requires the `permission` argument",
            )
        })?;
        Ok(Self {
            permission,
            resource,
            abac,
        })
    }
}

/// 解析 `#[check_abac]` 命名参数形式 `#[check_abac(action = "x", resource = "r", abac = "expr")]`：`action`/`abac` 必填，`resource` 可选（默认 `Resource::"default"`，向后兼容）；缺失必填项返回编译错误。
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
                        "unsupported attribute argument; only `action`, `resource` and `abac` are supported",
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
                "#[check_abac] requires the `action` argument, e.g. #[check_abac(action = \"order:read\", abac = \"...\")]",
            )
        })?;
        let abac = abac.ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "#[check_abac] requires the `abac` argument, e.g. #[check_abac(action = \"...\", abac = \"resource.user_id == principal.id\")]",
            )
        })?;
        Ok(Self {
            action,
            resource,
            abac,
        })
    }
}

/// 展开 `#[check_api_key]`：在 fn body 前插入 `GarrisonUtil::check_api_key(namespace)` 调用，`Err`（InvalidToken / ExpiredToken / NotLogin）返回错误对应的 Response。
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

/// 展开 `#[check_login]`：在 fn body 前插入 `GarrisonUtil::check_login()` 调用。返回 `GarrisonResult<bool>`：`Ok(true)` 继续执行；`Ok(false)`（`throw_on_not_login=false`）返回 401；`Err`（Manager 未初始化等）返回对应 Response。
fn expand_check_login(item_fn: ItemFn) -> TokenStream {
    let asyncness = detect_asyncness(&item_fn);
    let checks = match asyncness {
        Asyncness::Async => quote! {
            match ::garrison::GarrisonUtil::check_login().await {
                ::std::result::Result::Ok(true) => {},
                ::std::result::Result::Ok(false) => {
                    return ::axum::response::IntoResponse::into_response(
                        ::garrison::GarrisonError::NotLogin(::garrison::loc!(
                            "check-login-returned-false",
                            "Not logged in (check_login returned false)"
                        ))
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
                        ::garrison::GarrisonError::NotLogin(::garrison::loc!(
                            "check-login-returned-false",
                            "Not logged in (check_login returned false)"
                        ))
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

/// 展开 `#[check_access_token]` / `#[check_client_token]` / `#[check_temp_token]`：在 fn body 前插入无参 `GarrisonUtil::<method>()` 调用（返回 `GarrisonResult<()>`，仅 Err 路径需转发；与 `expand_check_login` 区别：后者返回 `bool` 需处理 `Ok(false)` 路径）。
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

/// 展开 `#[check_permission]` 命名参数形式（RBAC + 可选 ABAC）：始终生成 RBAC 检查；`abac` 参数存在时在 RBAC 通过后追加 ABAC 检查（AND 语义，任一失败立即 return）。resource 由宏属性注入；sync fn 的 ABAC 检查经 `block_in_place` + `block_on` 包装异步调用（与 `check_permission_sync` 的同步包装模式一致）。
fn expand_check_permission_named(
    permission: &str,
    resource: &str,
    abac: Option<&str>,
    item_fn: ItemFn,
) -> TokenStream {
    let asyncness = detect_asyncness(&item_fn);

    // RBAC 检查（始终生成）；ABAC 检查（仅 abac 参数存在时生成），resource 显式注入避免硬编码
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

    // ABAC 检查
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

/// 展开 `#[check_abac]`：纯 ABAC 校验（无 RBAC 前置），在 fn body 前插入 `check_abac_with_policy(action, resource, expr)` 调用；async fn 直接 `.await`，sync fn 经 `block_in_place` + `Handle::current().block_on()` 包装。与 `expand_check_permission_named` 的 ABAC 部分类似但不生成 RBAC 检查。
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

/// 生成 wrapper 函数 + 重命名的 inner 函数：inner 为原 sig（重命名 ident）+ 原 body；wrapper 用原 ident、返回 `axum::response::Response`、body 前插入 `checks`。`asyncness` 决定 wrapper/inner 是否 async 及 inner 调用是否 `.await`（checks 由 expand_* 生成对应 sync 版本）；参数转发用 fresh idents（`__garrison_arg_N`）避免 pattern-vs-expression 问题。
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

// forge 兼容变体展开逻辑

/// 展开 `#[check_login_forge]`：在原函数体开头插入 `GarrisonUtil::check_login()` 校验，失败返回 `Err(garrison_err.into())`（调用方错误类型须实现 `From<GarrisonError>`）。仅 async fn（sync fn 标注因 `.await` 非法产生编译错误，符合设计预期）。
fn expand_check_login_forge(item_fn: ItemFn) -> proc_macro2::TokenStream {
    let checks = quote! {
        match ::garrison::GarrisonUtil::check_login().await {
            ::std::result::Result::Ok(true) => {},
            ::std::result::Result::Ok(false) => {
                return ::std::result::Result::Err(::std::convert::Into::into(
                    ::garrison::GarrisonError::NotLogin(::garrison::loc!(
                        "check-login-returned-false",
                        "Not logged in (check_login returned false)"
                    ))
                ));
            }
            ::std::result::Result::Err(__garrison_err) => {
                return ::std::result::Result::Err(::std::convert::Into::into(__garrison_err));
            }
        }
    };
    expand_forge_inline(&item_fn, checks)
}

/// 展开 `#[check_permission_forge]` / `#[check_role_forge]`：在原函数体开头每参数插入一次调用（AND 语义，任一失败返回 `Err(garrison_err.into())`）。
fn expand_check_with_args_forge(
    method: &str,
    args: &[String],
    item_fn: ItemFn,
) -> proc_macro2::TokenStream {
    let method_ident = format_ident!("{}", method);
    // 每个参数生成一次调用，AND 语义：任一失败立即 return Err
    let calls: Vec<proc_macro2::TokenStream> = args
        .iter()
        .map(|arg| {
            quote! {
                if let ::std::result::Result::Err(__garrison_err) =
                    ::garrison::GarrisonUtil::#method_ident(#arg).await
                {
                    return ::std::result::Result::Err(::std::convert::Into::into(__garrison_err));
                }
            }
        })
        .collect();
    let checks = quote! { #(#calls)* };
    expand_forge_inline(&item_fn, checks)
}

/// forge 兼容变体展开核心：直接在原函数体开头插入校验代码，不生成 wrapper（与 [`expand_wrapper`] 区别：保留原返回类型 `Result<T, E: From<GarrisonError>>`，与 `#[forge]` 宏兼容）。原函数体作为内层块，其值作为函数体返回值，语义不变。
fn expand_forge_inline(
    item_fn: &ItemFn,
    checks: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let vis = &item_fn.vis;
    let sig = &item_fn.sig;
    let attrs = &item_fn.attrs;
    let block = &item_fn.block;

    let expanded = quote! {
        #(#attrs)*
        #vis #sig {
            #checks
            #block
        }
    };
    expanded
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

    // forge 兼容变体测试

    /// `expand_check_permission_forge` 展开后函数名不变（不生成 wrapper）
    #[test]
    fn check_permission_forge_preserves_function_name() {
        let item_fn: ItemFn =
            parse_quote! { async fn list_feedback() -> Result<i32, MyError> { Ok(42) } };
        let tokens =
            expand_check_with_args_forge("check_permission", &["admin".to_string()], item_fn);
        let ts: proc_macro2::TokenStream = tokens.into();
        let code = ts.to_string();
        assert!(
            !code.contains("__garrison_inner_"),
            "forge 变体不应生成 wrapper/inner 函数"
        );
        assert!(code.contains("list_feedback"));
    }

    /// `expand_check_permission_forge` 展开后函数体包含 check_permission 调用
    #[test]
    fn check_permission_forge_inserts_check_call() {
        let item_fn: ItemFn =
            parse_quote! { async fn handler() -> Result<i32, MyError> { Ok(42) } };
        let tokens =
            expand_check_with_args_forge("check_permission", &["admin".to_string()], item_fn);
        let ts: proc_macro2::TokenStream = tokens.into();
        let code = ts.to_string();
        assert!(
            code.contains("check_permission"),
            "应插入 check_permission 调用"
        );
        assert!(code.contains("admin"), "应包含权限参数");
        // 应包含 await（async handler）；proc_macro2 to_string 在 . 后插空格 → ". await"
        assert!(code.contains("await"), "应包含 await 调用");
    }

    /// `expand_check_permission_forge` 展开后保留原返回类型（不改为 Response）
    #[test]
    fn check_permission_forge_preserves_return_type() {
        let item_fn: ItemFn =
            parse_quote! { async fn handler() -> Result<i32, MyError> { Ok(42) } };
        let tokens =
            expand_check_with_args_forge("check_permission", &["admin".to_string()], item_fn);
        let ts: proc_macro2::TokenStream = tokens.into();
        let code = ts.to_string();
        assert!(code.contains("Result"), "应保留 Result 返回类型");
        assert!(
            !code.contains("-> :: axum :: response :: Response"),
            "不应将返回类型改为 axum::response::Response"
        );
    }

    /// `expand_check_login_forge` 展开后插入 check_login 三路 match
    #[test]
    fn check_login_forge_inserts_three_way_match() {
        let item_fn: ItemFn =
            parse_quote! { async fn handler() -> Result<i32, MyError> { Ok(42) } };
        let tokens = expand_check_login_forge(item_fn);
        let ts: proc_macro2::TokenStream = tokens.into();
        let code = ts.to_string();
        assert!(code.contains("check_login"), "应插入 check_login 调用");
        assert!(code.contains("Ok (true)"), "应处理 Ok(true) 分支");
        assert!(code.contains("Ok (false)"), "应处理 Ok(false) 分支");
    }

    /// `expand_check_role_forge` 支持多角色参数（AND 语义）
    #[test]
    fn check_role_forge_supports_multiple_roles() {
        let item_fn: ItemFn =
            parse_quote! { async fn handler() -> Result<i32, MyError> { Ok(42) } };
        let tokens = expand_check_with_args_forge(
            "check_role",
            &["admin".to_string(), "moderator".to_string()],
            item_fn,
        );
        let ts: proc_macro2::TokenStream = tokens.into();
        let code = ts.to_string();
        let count = code.matches("check_role").count();
        assert!(
            count >= 2,
            "应包含至少两次 check_role 调用（AND 语义），实际: {}",
            count
        );
        assert!(code.contains("admin"));
        assert!(code.contains("moderator"));
    }

    /// `expand_forge_inline` 保留原函数属性（如 #[cfg]）
    #[test]
    fn forge_inline_preserves_attributes() {
        let item_fn: ItemFn = parse_quote! {
            #[cfg(feature = "test")]
            async fn handler() -> Result<i32, MyError> { Ok(42) }
        };
        let checks = quote! { /* checks placeholder */ };
        let tokens = expand_forge_inline(&item_fn, checks);
        let ts: proc_macro2::TokenStream = tokens.into();
        let code = ts.to_string();
        assert!(code.contains("cfg"), "应保留 #[cfg] 属性");
    }
}
