//! 国际化模块，提供异常消息多语言切换（中英文）。
//!
//! 依据 spec exception-i18n 与 PRD 0.3.0 异常消息国际化改进。
//!
//! ## 设计
//!
//! - `BulwarkLocale`：支持的语言枚举（默认 `Zh`，向后兼容 0.2.x 硬编码中文行为）
//! - thread_local 栈式 scope：`set_locale()` 返回 RAII guard，drop 时自动 pop
//! - `OnceCell` 缓存 `FluentBundle`：首次访问时加载 .ftl 资源，后续零开销
//! - `translate_error(&BulwarkError) -> String`：依据当前 locale 查询 fluent bundle
//!
//! ## 使用示例
//!
//! ```ignore
//! use bulwark::i18n::{set_locale, BulwarkLocale};
//! use bulwark::error::BulwarkError;
//!
//! // 默认中文
//! let err = BulwarkError::NotLogin("请先登录".to_string());
//! assert_eq!(err.to_string(), "未登录: 请先登录");
//!
//! // 切换英文
//! let _guard = set_locale(BulwarkLocale::En);
//! assert_eq!(err.to_string(), "Not logged in: 请先登录");
//!
//! // guard drop 后自动恢复中文
//! ```

use crate::error::BulwarkError;
use fluent::concurrent::FluentBundle;
use fluent::{FluentArgs, FluentResource};
use once_cell::sync::OnceCell;
use std::cell::RefCell;
use unic_langid::LanguageIdentifier;

/// 支持的语言枚举。
///
/// 默认 `Zh`（中文），向后兼容 0.2.x 硬编码中文行为。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BulwarkLocale {
    /// 中文（默认语言）。
    #[default]
    Zh,
    /// 英文。
    En,
}

impl BulwarkLocale {
    /// 返回对应的 BCP-47 语言标签。
    fn as_lang_id(self) -> LanguageIdentifier {
        match self {
            BulwarkLocale::Zh => "zh".parse().expect("valid language identifier"),
            BulwarkLocale::En => "en".parse().expect("valid language identifier"),
        }
    }
}

// ============================================================================
// thread_local 栈式 scope（支持嵌套 set_locale 调用）
// ============================================================================

thread_local! {
    static CURRENT_LOCALE_STACK: RefCell<Vec<BulwarkLocale>> = const { RefCell::new(Vec::new()) };
}

/// 获取当前 locale（线程本地）。
///
/// 未调用 `set_locale()` 时返回默认 `BulwarkLocale::Zh`。
pub fn current_locale() -> BulwarkLocale {
    CURRENT_LOCALE_STACK.with(|stack| stack.borrow().last().copied().unwrap_or_default())
}

/// 设置当前线程的 locale，返回 RAII guard。
///
/// guard drop 时自动 pop，恢复上一个 locale。支持嵌套调用。
///
/// # 示例
///
/// ```ignore
/// let _guard = set_locale(BulwarkLocale::En);
/// // 此范围内 current_locale() == En
/// ```
pub fn set_locale(locale: BulwarkLocale) -> LocaleGuard {
    CURRENT_LOCALE_STACK.with(|stack| stack.borrow_mut().push(locale));
    LocaleGuard { _priv: () }
}

/// RAII guard，drop 时 pop locale 栈恢复上一个 locale。
///
/// 由 [`set_locale`] 返回，不应手动构造。
pub struct LocaleGuard {
    _priv: (),
}

impl Drop for LocaleGuard {
    fn drop(&mut self) {
        CURRENT_LOCALE_STACK.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}

// ============================================================================
// FluentBundle 单例缓存（OnceCell，首次访问加载 .ftl 资源）
// ============================================================================

static ZH_BUNDLE: OnceCell<FluentBundle<FluentResource>> = OnceCell::new();
static EN_BUNDLE: OnceCell<FluentBundle<FluentResource>> = OnceCell::new();

/// 获取指定 locale 的 FluentBundle（懒加载，首次访问时构造）。
fn get_bundle(locale: BulwarkLocale) -> &'static FluentBundle<FluentResource> {
    match locale {
        BulwarkLocale::Zh => ZH_BUNDLE.get_or_init(|| build_bundle(BulwarkLocale::Zh)),
        BulwarkLocale::En => EN_BUNDLE.get_or_init(|| build_bundle(BulwarkLocale::En)),
    }
}

/// 构造 FluentBundle（从 include_str! 加载 .ftl 资源）。
fn build_bundle(locale: BulwarkLocale) -> FluentBundle<FluentResource> {
    let ftl = match locale {
        BulwarkLocale::Zh => include_str!("../locales/zh.ftl"),
        BulwarkLocale::En => include_str!("../locales/en.ftl"),
    };
    let resource = FluentResource::try_new(ftl.to_string())
        .expect("Bulwark .ftl 资源解析失败（编译期已固化，不应失败）");
    let lang_id = locale.as_lang_id();
    let mut bundle = FluentBundle::new_concurrent(vec![lang_id]);
    // 关闭 FSI/PDI 隔离标记（U+2068/U+2069），保持错误消息纯净
    bundle.set_use_isolating(false);
    bundle
        .add_resource(resource)
        .expect("Bulwark .ftl 资源添加到 bundle 失败（资源键冲突不应发生）");
    bundle
}

// ============================================================================
// 错误翻译：依据当前 locale 查询 fluent bundle
// ============================================================================

/// 将 `BulwarkError` 翻译为当前 locale 的本地化字符串。
///
/// 依据 `current_locale()` 选取 bundle，查询错误对应的 message key 与 args。
/// 缺失 key 时回退到硬编码中文（与 0.2.x 行为一致）。
pub fn translate_error(err: &BulwarkError) -> String {
    let locale = current_locale();
    let bundle = get_bundle(locale);
    let (key, args) = error_to_key_args(err);
    match bundle.get_message(key) {
        Some(msg) => match msg.value() {
            Some(pattern) => {
                let mut fluent_args = FluentArgs::new();
                for (k, v) in args {
                    fluent_args.set(k, v);
                }
                let mut errors = vec![];
                let value = bundle.format_pattern(pattern, Some(&fluent_args), &mut errors);
                if errors.is_empty() {
                    value.into_owned()
                } else {
                    // 翻译失败回退到硬编码中文
                    fallback_display(err)
                }
            },
            None => fallback_display(err),
        },
        None => fallback_display(err),
    }
}

/// 按 key + args 翻译为当前 locale 的本地化字符串（0.6.0 新增，依据 T021）。
///
/// 与 [`translate_error`] 不同，本函数不依赖 `BulwarkError`，直接接收 message key 与
/// 参数列表，供 `loc!` 宏在社交登录 / Keycloak 等模块中按需翻译异常 detail。
///
/// # 参数
///
/// - `key`: FTL message key（如 `"wechat-token-request-failed"`）
/// - `args`: 参数列表（如 `[("detail", "connection reset")]`），可为空 slice
///
/// # 返回
///
/// - 找到 key 且格式化成功：返回格式化后的本地化字符串
/// - 未找到 key 或格式化出错：返回 `key` 本身（由调用方在 `loc!` 宏中提供 fallback）
pub fn translate_detail(key: &str, args: &[(&str, &str)]) -> String {
    let locale = current_locale();
    let bundle = get_bundle(locale);
    match bundle.get_message(key) {
        Some(msg) => match msg.value() {
            Some(pattern) => {
                let mut fluent_args = FluentArgs::new();
                for (k, v) in args {
                    fluent_args.set(*k, (*v).to_string());
                }
                let mut errors = vec![];
                let value = bundle.format_pattern(pattern, Some(&fluent_args), &mut errors);
                if errors.is_empty() {
                    value.into_owned()
                } else {
                    key.to_string()
                }
            },
            None => key.to_string(),
        },
        None => key.to_string(),
    }
}

/// 错误到 FTL message key + args 的映射。
fn error_to_key_args(err: &BulwarkError) -> (&'static str, Vec<(&'static str, String)>) {
    match err {
        BulwarkError::NotLogin(s) => ("not-login", vec![("detail", s.clone())]),
        BulwarkError::NotPermission(s) => ("not-permission", vec![("detail", s.clone())]),
        BulwarkError::NotRole(s) => ("not-role", vec![("detail", s.clone())]),
        BulwarkError::InvalidToken(s) => ("invalid-token", vec![("detail", s.clone())]),
        BulwarkError::ExpiredToken(s) => ("expired-token", vec![("detail", s.clone())]),
        BulwarkError::Dao(s) => ("dao", vec![("detail", s.clone())]),
        BulwarkError::Config(s) => ("config", vec![("detail", s.clone())]),
        BulwarkError::Internal(s) => ("internal", vec![("detail", s.clone())]),
        BulwarkError::Session(s) => ("session", vec![("detail", s.clone())]),
        BulwarkError::Annotation(s) => ("annotation", vec![("detail", s.clone())]),
        BulwarkError::Context(s) => ("context", vec![("detail", s.clone())]),
        BulwarkError::OAuth2(s) => ("oauth2", vec![("detail", s.clone())]),
        BulwarkError::Network(s) => ("network", vec![("detail", s.clone())]),
        BulwarkError::InvalidParam(s) => ("invalid-param", vec![("detail", s.clone())]),
        BulwarkError::NotImplemented(s) => ("not-implemented", vec![("detail", s.clone())]),
        BulwarkError::FirewallBlocked(s) => ("firewall-blocked", vec![("detail", s.clone())]),
        BulwarkError::DisableService { service, until } => (
            "disable-service",
            vec![
                ("service", service.clone()),
                ("until", format!("{:?}", until)),
            ],
        ),
        BulwarkError::NotSafe { reason } => ("not-safe", vec![("reason", reason.clone())]),
        BulwarkError::InvalidStateTransition { from, to } => (
            "invalid-state-transition",
            vec![("from", from.clone()), ("to", to.clone())],
        ),
        BulwarkError::Exception(ex) => (
            "exception",
            vec![
                ("code", ex.code.to_string()),
                ("detail", ex.message.clone()),
            ],
        ),
    }
}

/// 翻译失败时的硬编码中文回退（与 0.2.x Display 输出一致）。
fn fallback_display(err: &BulwarkError) -> String {
    match err {
        BulwarkError::NotLogin(s) => format!("未登录: {}", s),
        BulwarkError::NotPermission(s) => format!("无权限: {}", s),
        BulwarkError::NotRole(s) => format!("无角色: {}", s),
        BulwarkError::InvalidToken(s) => format!("Token 无效: {}", s),
        BulwarkError::ExpiredToken(s) => format!("Token 已过期: {}", s),
        BulwarkError::Dao(s) => format!("DAO 错误: {}", s),
        BulwarkError::Config(s) => format!("配置错误: {}", s),
        BulwarkError::Internal(s) => format!("内部错误: {}", s),
        BulwarkError::Session(s) => format!("会话错误: {}", s),
        BulwarkError::Annotation(s) => format!("注解错误: {}", s),
        BulwarkError::Context(s) => format!("上下文错误: {}", s),
        BulwarkError::OAuth2(s) => format!("OAuth2 错误: {}", s),
        BulwarkError::Network(s) => format!("网络错误: {}", s),
        BulwarkError::InvalidParam(s) => format!("参数无效: {}", s),
        BulwarkError::NotImplemented(s) => format!("未实现: {}", s),
        BulwarkError::FirewallBlocked(s) => format!("防火墙拦截: {}", s),
        BulwarkError::DisableService { service, until } => {
            format!("账号已被封禁：service={}, until={:?}", service, until)
        },
        BulwarkError::NotSafe { reason } => format!("未完成二次认证：{}", reason),
        BulwarkError::InvalidStateTransition { from, to } => {
            format!("非法状态转换：{} -> {}", from, to)
        },
        BulwarkError::Exception(ex) => format!("业务异常[{}]: {}", ex.code, ex.message),
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BulwarkError;
    use crate::exception::BulwarkException;

    // ========================================================================
    // BulwarkLocale 枚举测试
    // ========================================================================

    /// 默认 locale 应为中文。
    #[test]
    fn default_locale_is_zh() {
        let locale = BulwarkLocale::default();
        assert_eq!(locale, BulwarkLocale::Zh);
    }

    /// as_lang_id 返回正确的 LanguageIdentifier。
    #[test]
    fn as_lang_id_returns_correct_identifier() {
        assert_eq!(BulwarkLocale::Zh.as_lang_id().to_string(), "zh");
        assert_eq!(BulwarkLocale::En.as_lang_id().to_string(), "en");
    }

    // ========================================================================
    // current_locale / set_locale 测试
    // ========================================================================

    /// 未设置 locale 时返回默认值 Zh。
    #[test]
    fn current_locale_defaults_to_zh_when_not_set() {
        // 注意：此测试依赖 thread_local 状态，可能受其他测试影响
        // 但因为使用栈式 scope，无 set_locale 调用时栈为空
        let locale = current_locale();
        assert_eq!(locale, BulwarkLocale::Zh);
    }

    /// set_locale 后 current_locale 返回新值，drop 后恢复。
    #[test]
    fn set_locale_changes_current_and_restores_on_drop() {
        let original = current_locale();
        {
            let _guard = set_locale(BulwarkLocale::En);
            assert_eq!(current_locale(), BulwarkLocale::En);
        }
        assert_eq!(current_locale(), original);
    }

    /// set_locale 支持嵌套调用。
    #[test]
    fn set_locale_supports_nesting() {
        let original = current_locale();
        {
            let _g1 = set_locale(BulwarkLocale::En);
            assert_eq!(current_locale(), BulwarkLocale::En);
            {
                let _g2 = set_locale(BulwarkLocale::Zh);
                assert_eq!(current_locale(), BulwarkLocale::Zh);
            }
            assert_eq!(current_locale(), BulwarkLocale::En);
        }
        assert_eq!(current_locale(), original);
    }

    // ========================================================================
    // translate_error 测试
    // ========================================================================

    /// 默认中文：NotLogin 翻译为中文消息。
    #[test]
    fn translate_error_zh_returns_chinese_message() {
        let _guard = set_locale(BulwarkLocale::Zh);
        let err = BulwarkError::NotLogin("请先登录".to_string());
        let translated = translate_error(&err);
        assert_eq!(translated, "未登录: 请先登录");
    }

    /// 英文 locale：NotLogin 翻译为英文消息。
    #[test]
    fn translate_error_en_returns_english_message() {
        let _guard = set_locale(BulwarkLocale::En);
        let err = BulwarkError::NotLogin("please login first".to_string());
        let translated = translate_error(&err);
        assert_eq!(translated, "Not logged in: please login first");
    }

    /// 所有错误变体在中文 locale 下输出与硬编码一致。
    #[test]
    fn translate_error_zh_all_variants_match_hardcoded() {
        let _guard = set_locale(BulwarkLocale::Zh);
        let cases = vec![
            (BulwarkError::NotLogin("a".into()), "未登录: a"),
            (BulwarkError::NotPermission("a".into()), "无权限: a"),
            (BulwarkError::NotRole("a".into()), "无角色: a"),
            (BulwarkError::InvalidToken("a".into()), "Token 无效: a"),
            (BulwarkError::ExpiredToken("a".into()), "Token 已过期: a"),
            (BulwarkError::Dao("a".into()), "DAO 错误: a"),
            (BulwarkError::Config("a".into()), "配置错误: a"),
            (BulwarkError::Internal("a".into()), "内部错误: a"),
            (BulwarkError::Session("a".into()), "会话错误: a"),
            (BulwarkError::Annotation("a".into()), "注解错误: a"),
            (BulwarkError::Context("a".into()), "上下文错误: a"),
            (BulwarkError::OAuth2("a".into()), "OAuth2 错误: a"),
            (BulwarkError::Network("a".into()), "网络错误: a"),
            (BulwarkError::InvalidParam("a".into()), "参数无效: a"),
            (BulwarkError::NotImplemented("a".into()), "未实现: a"),
        ];
        for (err, expected) in cases {
            assert_eq!(translate_error(&err), expected, "mismatch for {:?}", err);
        }
    }

    /// 所有错误变体在英文 locale 下输出英文消息。
    #[test]
    fn translate_error_en_all_variants_english() {
        let _guard = set_locale(BulwarkLocale::En);
        let cases = vec![
            (BulwarkError::NotLogin("a".into()), "Not logged in: a"),
            (
                BulwarkError::NotPermission("a".into()),
                "Permission denied: a",
            ),
            (BulwarkError::NotRole("a".into()), "Role denied: a"),
            (BulwarkError::InvalidToken("a".into()), "Invalid token: a"),
            (BulwarkError::ExpiredToken("a".into()), "Token expired: a"),
            (BulwarkError::Dao("a".into()), "DAO error: a"),
            (BulwarkError::Config("a".into()), "Configuration error: a"),
            (BulwarkError::Internal("a".into()), "Internal error: a"),
            (BulwarkError::Session("a".into()), "Session error: a"),
            (BulwarkError::Annotation("a".into()), "Annotation error: a"),
            (BulwarkError::Context("a".into()), "Context error: a"),
            (BulwarkError::OAuth2("a".into()), "OAuth2 error: a"),
            (BulwarkError::Network("a".into()), "Network error: a"),
            (
                BulwarkError::InvalidParam("a".into()),
                "Invalid parameter: a",
            ),
            (
                BulwarkError::NotImplemented("a".into()),
                "Not implemented: a",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(translate_error(&err), expected, "mismatch for {:?}", err);
        }
    }

    /// Exception 变体在中文 locale 下输出"业务异常[code]: message"。
    #[test]
    fn translate_error_zh_exception_variant() {
        let _guard = set_locale(BulwarkLocale::Zh);
        let err = BulwarkError::Exception(BulwarkException::new(-1, "请先登录"));
        assert_eq!(translate_error(&err), "业务异常[-1]: 请先登录");
    }

    /// Exception 变体在英文 locale 下输出"Business exception[code]: message"。
    #[test]
    fn translate_error_en_exception_variant() {
        let _guard = set_locale(BulwarkLocale::En);
        let err = BulwarkError::Exception(BulwarkException::new(-1, "please login"));
        assert_eq!(
            translate_error(&err),
            "Business exception[-1]: please login"
        );
    }

    /// 运行时切换 locale 不影响其他范围。
    #[test]
    fn locale_switch_is_isolated_per_scope() {
        let original = current_locale();
        {
            let _g = set_locale(BulwarkLocale::En);
            let err = BulwarkError::Dao("err".to_string());
            assert_eq!(translate_error(&err), "DAO error: err");
        }
        // 范围外恢复原 locale
        let err = BulwarkError::Dao("err".to_string());
        if original == BulwarkLocale::En {
            assert_eq!(translate_error(&err), "DAO error: err");
        } else {
            assert_eq!(translate_error(&err), "DAO 错误: err");
        }
    }

    /// fallback_display 与硬编码 0.2.x 输出一致。
    #[test]
    fn fallback_display_matches_hardcoded_chinese() {
        let err = BulwarkError::NotLogin("测试".to_string());
        assert_eq!(fallback_display(&err), "未登录: 测试");
    }

    /// fallback_display 覆盖所有错误变体（确保每个 match arm 都有测试）。
    #[test]
    fn fallback_display_all_variants() {
        let cases: Vec<(BulwarkError, &str)> = vec![
            (BulwarkError::NotLogin("x".into()), "未登录: x"),
            (BulwarkError::NotPermission("x".into()), "无权限: x"),
            (BulwarkError::NotRole("x".into()), "无角色: x"),
            (BulwarkError::InvalidToken("x".into()), "Token 无效: x"),
            (BulwarkError::ExpiredToken("x".into()), "Token 已过期: x"),
            (BulwarkError::Dao("x".into()), "DAO 错误: x"),
            (BulwarkError::Config("x".into()), "配置错误: x"),
            (BulwarkError::Internal("x".into()), "内部错误: x"),
            (BulwarkError::Session("x".into()), "会话错误: x"),
            (BulwarkError::Annotation("x".into()), "注解错误: x"),
            (BulwarkError::Context("x".into()), "上下文错误: x"),
            (BulwarkError::OAuth2("x".into()), "OAuth2 错误: x"),
            (BulwarkError::Network("x".into()), "网络错误: x"),
            (BulwarkError::InvalidParam("x".into()), "参数无效: x"),
            (BulwarkError::NotImplemented("x".into()), "未实现: x"),
            (
                BulwarkError::Exception(BulwarkException::new(-1, "msg")),
                "业务异常[-1]: msg",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(fallback_display(&err), expected, "mismatch for {:?}", err);
        }
    }

    /// get_bundle 返回的 bundle 可重复获取（OnceCell 缓存）。
    #[test]
    fn get_bundle_returns_cached_instance() {
        let b1 = get_bundle(BulwarkLocale::Zh);
        let b2 = get_bundle(BulwarkLocale::Zh);
        // 指针相等表示同一实例
        assert!(std::ptr::eq(b1, b2));
    }
}
