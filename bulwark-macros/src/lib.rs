//! Bulwark 过程宏 crate，提供鉴权注解属性宏。
//!
//! 依据 spec `annotation-macros`，提供 3 个 `#[proc_macro_attribute]`：
//!
//! - [`macro@check_login`]：登录校验，未登录返回 401
//! - [`macro@check_permission`]：权限校验（AND 语义），无权限返回 403
//! - [`macro@check_role`]：角色校验（AND 语义），无角色返回 403
//!
//! # 限制
//!
//! - 仅支持 `async fn`（同步 fn 编译报错）
//! - 仅支持 axum handler（原返回类型需实现 `axum::response::IntoResponse`）
//! - 宏展开依赖 `BulwarkUtil` 全局单例（需先 `BulwarkManager::init`）
//!
//! # 展开结构
//!
//! 宏将原 async fn 重命名为内部函数 `__bulwark_inner_<name>`，
//! 并生成同名的 wrapper 函数（返回 `axum::response::Response`），
//! 在 wrapper body 前插入 `BulwarkUtil::check_*()` 调用：
//!
//! ```ignore
//! // 输入
//! #[check_login]
//! async fn handler() -> &'static str { "ok" }
//!
//! // 展开
//! async fn __bulwark_inner_handler() -> &'static str { "ok" }
//!
//! async fn handler() -> axum::response::Response {
//!     if let Err(e) = ::bulwark::BulwarkUtil::check_login().await {
//!         return ::axum::response::IntoResponse::into_response(e);
//!     }
//!     ::axum::response::IntoResponse::into_response(
//!         __bulwark_inner_handler().await
//!     )
//! }
//! ```

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{parse_macro_input, punctuated::Punctuated, FnArg, ItemFn, LitStr, Token};

// ============================================================================
// 公开 proc_macro_attribute
// ============================================================================

/// 登录校验属性宏。
///
/// 标注在 async fn 上，编译期生成 wrapper 在 fn body 前插入
/// `BulwarkUtil::check_login()` 调用。未登录请求返回 401。
///
/// # 限制
///
/// - 仅支持 `async fn`（同步 fn 编译报错）
/// - 仅支持 axum handler（原返回类型需实现 `axum::response::IntoResponse`）
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
#[proc_macro_attribute]
pub fn check_login(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);
    expand_check_login(item_fn)
}

/// 权限校验属性宏。
///
/// 标注在 async fn 上，编译期生成 wrapper 在 fn body 前插入
/// `BulwarkUtil::check_permission("perm")` 调用。无权限请求返回 403。
///
/// 支持多个权限参数 `#[check_permission("a", "b")]`（AND 语义：必须持有全部权限）。
///
/// # 限制
///
/// - 仅支持 `async fn`
/// - 至少一个权限参数
///
/// # 示例
///
/// ```ignore
/// use bulwark::check_permission;
/// use axum::response::IntoResponse;
///
/// #[check_permission("user:read")]
/// async fn handler() -> impl IntoResponse { "ok" }
///
/// #[check_permission("user:read", "user:write")]
/// async fn admin_handler() -> impl IntoResponse { "admin" }
/// ```
#[proc_macro_attribute]
pub fn check_permission(attr: TokenStream, item: TokenStream) -> TokenStream {
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
/// 标注在 async fn 上，编译期生成 wrapper 在 fn body 前插入
/// `BulwarkUtil::check_role("role")` 调用。无角色请求返回 403。
///
/// 支持多个角色参数（AND 语义：必须持有全部角色）。
///
/// # 限制
///
/// - 仅支持 `async fn`
/// - 至少一个角色参数
///
/// # 示例
///
/// ```ignore
/// use bulwark::check_role;
/// use axum::response::IntoResponse;
///
/// #[check_role("admin")]
/// async fn handler() -> impl IntoResponse { "ok" }
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

// ============================================================================
// 内部展开逻辑
// ============================================================================

/// 校验 `item_fn` 必须是 `async fn`，否则返回编译错误。
fn require_async(item_fn: &ItemFn) -> Result<(), proc_macro2::TokenStream> {
    if item_fn.sig.asyncness.is_none() {
        let err = syn::Error::new_spanned(
            item_fn.sig.fn_token,
            "#[check_login] / #[check_permission] / #[check_role] 仅支持 async fn \
             （同步 fn 支持计划 v0.5.0+）",
        );
        return Err(err.to_compile_error());
    }
    Ok(())
}

/// 展开 `#[check_login]`：在 fn body 前插入 `BulwarkUtil::check_login()` 调用。
///
/// `check_login()` 返回 `BulwarkResult<bool>`：
/// - `Ok(true)`：已登录，继续执行 fn body
/// - `Ok(false)`：未登录（`throw_on_not_login=false`），返回 401
/// - `Err(e)`：错误（如 Manager 未初始化，或 `throw_on_not_login=true` 时未登录），
///   返回错误对应的 Response（NotLogin → 401，其他 → 500/etc.）
fn expand_check_login(item_fn: ItemFn) -> TokenStream {
    if let Err(err) = require_async(&item_fn) {
        return err.into();
    }
    let checks = quote! {
        match ::bulwark::BulwarkUtil::check_login().await {
            ::std::result::Result::Ok(true) => {},
            ::std::result::Result::Ok(false) => {
                return ::axum::response::IntoResponse::into_response(
                    ::bulwark::BulwarkError::NotLogin("未登录（check_login 返回 false）".to_string())
                );
            }
            ::std::result::Result::Err(__bulwark_err) => {
                return ::axum::response::IntoResponse::into_response(__bulwark_err);
            }
        }
    };
    expand_wrapper(&item_fn, checks)
}

/// 展开 `#[check_permission]` / `#[check_role]`：插入多次调用（AND 语义）。
fn expand_check_with_args(method: &str, args: &[String], item_fn: ItemFn) -> TokenStream {
    if let Err(err) = require_async(&item_fn) {
        return err.into();
    }
    let method_ident = format_ident!("{}", method);
    // 每个参数生成一次调用，AND 语义：任一失败立即 return
    let calls: Vec<proc_macro2::TokenStream> = args
        .iter()
        .map(|arg| {
            quote! {
                if let Err(__bulwark_err) = ::bulwark::BulwarkUtil::#method_ident(#arg).await {
                    return ::axum::response::IntoResponse::into_response(__bulwark_err);
                }
            }
        })
        .collect();
    let checks = quote! { #(#calls)* };
    expand_wrapper(&item_fn, checks)
}

/// 生成 wrapper 函数 + 重命名的 inner 函数。
///
/// - inner：原 sig（重命名 ident）+ 原 body
/// - wrapper：原 ident，返回 `axum::response::Response`，body 前插入 `checks`
///
/// 参数转发使用 fresh idents（`__bulwark_arg_N`），避免 pattern-vs-expression 问题。
fn expand_wrapper(item_fn: &ItemFn, checks: proc_macro2::TokenStream) -> TokenStream {
    let vis = &item_fn.vis;
    let sig = &item_fn.sig;
    let original_name = &sig.ident;
    let inner_name = format_ident!("__bulwark_inner_{}", original_name);
    let block = &item_fn.block;
    let attrs = &item_fn.attrs;

    // 为每个 Typed 参数生成 fresh ident；Receiver 直接用 self
    let wrapper_inputs: Punctuated<FnArg, Token![,]> = sig
        .inputs
        .iter()
        .enumerate()
        .map(|(i, arg)| match arg {
            FnArg::Typed(pat_type) => {
                let id = format_ident!("__bulwark_arg_{}", i);
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
                let id = format_ident!("__bulwark_arg_{}", i);
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

    let expanded = quote! {
        // inner：保留原 sig（仅重命名）+ 原 body + 原 attrs（如 #[cfg]/#[doc]）
        #(#attrs)*
        #vis #inner_sig #block

        // wrapper：原名称 + Response 返回类型，body 前插入检查代码
        #vis #wrapper_sig {
            #checks
            ::axum::response::IntoResponse::into_response(
                #inner_name(#(#forward_args),*).await
            )
        }
    };
    expanded.into()
}
