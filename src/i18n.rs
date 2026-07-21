//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 国际化模块，提供异常消息多语言切换（中英文）。
//!
//! 异常消息国际化改进。
//!
//! ## 设计
//!
//! - `GarrisonLocale`：支持的语言枚举（默认 `Zh`，向后兼容 0.2.x 硬编码中文行为）
//! - thread_local 栈式 scope：`set_locale()` 返回 RAII guard，drop 时自动 pop
//! - `OnceCell` 缓存 `FluentBundle`：首次访问时加载 .ftl 资源，后续零开销
//! - `translate_error(&GarrisonError) -> String`：依据当前 locale 查询 fluent bundle
//!
//! ## 使用示例
//!
//! ```ignore
//! use garrison::i18n::{set_locale, GarrisonLocale};
//! use garrison::error::GarrisonError;
//!
//! // 默认中文
//! let err = GarrisonError::NotLogin("请先登录".to_string());
//! assert_eq!(err.to_string(), "未登录: 请先登录");
//!
//! // 切换英文
//! let _guard = set_locale(GarrisonLocale::En);
//! assert_eq!(err.to_string(), "Not logged in: 请先登录");
//!
//! // guard drop 后自动恢复中文
//! ```

use crate::error::GarrisonError;
use fluent::concurrent::FluentBundle;
use fluent::{FluentArgs, FluentResource};
use once_cell::sync::OnceCell;
use std::cell::RefCell;
use unic_langid::LanguageIdentifier;

/// 构造本地化错误文案：优先按 `key` 查 FTL 翻译，缺失时回退 `$fallback` 字符串。
///
/// i18n 基础层已无条件编译，本宏始终委托 [`translate_detail`]，无需 feature 门控。
///
/// # 示例
///
/// ```ignore
/// let err = GarrisonError::Network(loc!(
///     "wechat-response-missing-openid",
///     "wechat response missing openid field".to_string()
/// ));
/// ```
#[macro_export]
macro_rules! loc {
    ($key:expr, $fallback:expr $(, ($arg_k:expr, $arg_v:expr))*) => {{
        $crate::i18n::translate_detail($key, &[$(($arg_k, $arg_v)),*])
    }};
}

/// 支持的语言枚举。
///
/// 默认 `Zh`（中文），向后兼容 0.2.x 硬编码中文行为。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GarrisonLocale {
    /// 中文（默认语言）。
    #[default]
    Zh,
    /// 英文。
    En,
}

impl GarrisonLocale {
    /// 返回对应的 BCP-47 语言标签。
    fn as_lang_id(self) -> LanguageIdentifier {
        match self {
            GarrisonLocale::Zh => "zh".parse().expect("valid language identifier"),
            GarrisonLocale::En => "en".parse().expect("valid language identifier"),
        }
    }
}

// ============================================================================
// thread_local 栈式 scope（支持嵌套 set_locale 调用）
// ============================================================================

thread_local! {
    static CURRENT_LOCALE_STACK: RefCell<Vec<GarrisonLocale>> = const { RefCell::new(Vec::new()) };
}

/// 获取当前 locale（线程本地）。
///
/// 未调用 `set_locale()` 时返回默认 `GarrisonLocale::Zh`。
pub fn current_locale() -> GarrisonLocale {
    CURRENT_LOCALE_STACK.with(|stack| stack.borrow().last().copied().unwrap_or_default())
}

/// 设置当前线程的 locale，返回 RAII guard。
///
/// guard drop 时自动 pop，恢复上一个 locale。支持嵌套调用。
///
/// # 示例
///
/// ```ignore
/// let _guard = set_locale(GarrisonLocale::En);
/// // 此范围内 current_locale() == En
/// ```
pub fn set_locale(locale: GarrisonLocale) -> LocaleGuard {
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
fn get_bundle(locale: GarrisonLocale) -> &'static FluentBundle<FluentResource> {
    match locale {
        GarrisonLocale::Zh => ZH_BUNDLE.get_or_init(|| build_bundle(GarrisonLocale::Zh)),
        GarrisonLocale::En => EN_BUNDLE.get_or_init(|| build_bundle(GarrisonLocale::En)),
    }
}

/// 构造 FluentBundle（从 include_str! 加载 .ftl 资源）。
fn build_bundle(locale: GarrisonLocale) -> FluentBundle<FluentResource> {
    let ftl = match locale {
        GarrisonLocale::Zh => include_str!("../locales/zh.ftl"),
        GarrisonLocale::En => include_str!("../locales/en.ftl"),
    };
    let resource = FluentResource::try_new(ftl.to_string())
        .expect("Garrison .ftl 资源解析失败（编译期已固化，不应失败）");
    let lang_id = locale.as_lang_id();
    let mut bundle = FluentBundle::new_concurrent(vec![lang_id]);
    // 关闭 FSI/PDI 隔离标记（U+2068/U+2069），保持错误消息纯净
    bundle.set_use_isolating(false);
    bundle
        .add_resource(resource)
        .expect("Garrison .ftl 资源添加到 bundle 失败（资源键冲突不应发生）");
    bundle
}

// ============================================================================
// 错误翻译：依据当前 locale 查询 fluent bundle
// ============================================================================

/// 将 `GarrisonError` 翻译为当前 locale 的本地化字符串。
///
/// 依据 `current_locale()` 选取 bundle，查询错误对应的 message key 与 args。
/// 缺失 key 时回退到硬编码中文（与 0.2.x 行为一致）。
pub fn translate_error(err: &GarrisonError) -> String {
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

/// 按 key + args 翻译为当前 locale 的本地化字符串。
///
/// 与 [`translate_error`] 不同，本函数不依赖 `GarrisonError`，直接接收 message key 与
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
                let mut errors = vec![];
                // LOW-001：args 为空时短路，避免无意义的 FluentArgs 分配
                let value = if args.is_empty() {
                    bundle.format_pattern(pattern, None, &mut errors)
                } else {
                    let mut fluent_args = FluentArgs::new();
                    for (k, v) in args {
                        fluent_args.set(*k, (*v).to_string());
                    }
                    bundle.format_pattern(pattern, Some(&fluent_args), &mut errors)
                };
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

/// 解析结构化错误 detail：`key::arg0::arg1`。
///
/// 调用方在去语言化后，将 `GarrisonError` 的 `String` 字段写为
/// `format!("some-key::{}", arg0)` 或 `format!("some-key::{}::{}", arg0, arg1)`，
/// 本函数拆出 FTL message key 与位置化参数（键 `"arg0"`/`"arg1"` 对应 FTL 模板的 `{$arg0}`/`{$arg1}`，
/// 因 Fluent 变量标识符必须以字母开头，`0`/`1` 数字前缀非法，故统一加 `arg` 前缀）。
///
/// 非结构化（旧式中文或普通串）返回 `None`，交由调用方回退到 variant 默认 key。
fn parse_keyed_detail(s: &str) -> Option<(&'static str, Vec<(&'static str, String)>)> {
    // 仅当包含 `::` 分隔符才视为结构化 key，避免把普通中文/英文串误判为 key
    if !s.contains("::") {
        return None;
    }
    let mut parts = s.splitn(3, "::");
    let key = parts.next()?;
    // key 必须以字母开头且为合法 kebab-case（避免误命中文串）
    if key.is_empty() || !key.chars().next().unwrap().is_ascii_alphabetic() {
        return None;
    }
    if key.chars().any(|c| !c.is_ascii_lowercase() && c != '-') {
        return None;
    }
    let a0 = parts.next();
    let a1 = parts.next();
    match (a0, a1) {
        (None, None) | (None, Some(_)) => {
            Some((Box::leak(key.to_string().into_boxed_str()), vec![]))
        },
        (Some(x), None) => Some((
            Box::leak(key.to_string().into_boxed_str()),
            vec![("arg0", x.to_string())],
        )),
        (Some(x), Some(y)) => Some((
            Box::leak(key.to_string().into_boxed_str()),
            vec![("arg0", x.to_string()), ("arg1", y.to_string())],
        )),
    }
}

/// 将单个 `String` 错误字段映射为 (key, args)。
///
/// 优先尝试结构化 `key::arg` 形式；否则回退到 variant 默认 key + `detail` 参数
/// （兼容未迁移的硬编码中文串，保证向后可读）。
fn string_detail(
    variant_key: &'static str,
    s: &str,
) -> (&'static str, Vec<(&'static str, String)>) {
    match parse_keyed_detail(s) {
        Some((k, args)) => (k, args),
        None => (variant_key, vec![("detail", s.to_string())]),
    }
}

/// 错误到 FTL message key + args 的映射。
fn error_to_key_args(err: &GarrisonError) -> (&'static str, Vec<(&'static str, String)>) {
    match err {
        GarrisonError::NotLogin(s) => string_detail("not-login", s),
        GarrisonError::NotPermission(s) => string_detail("not-permission", s),
        GarrisonError::NotRole(s) => string_detail("not-role", s),
        GarrisonError::InvalidToken(s) => string_detail("invalid-token", s),
        GarrisonError::TokenRevoked(s) => string_detail("token-revoked", s),
        GarrisonError::ExpiredToken(s) => string_detail("expired-token", s),
        GarrisonError::Dao(s) => string_detail("dao", s),
        GarrisonError::Config(s) => string_detail("config", s),
        GarrisonError::Internal(s) => string_detail("internal", s),
        GarrisonError::Session(s) => string_detail("session", s),
        GarrisonError::Annotation(s) => string_detail("annotation", s),
        GarrisonError::Context(s) => string_detail("context", s),
        GarrisonError::OAuth2(s) => string_detail("oauth2", s),
        GarrisonError::Network(s) => string_detail("network", s),
        GarrisonError::InvalidParam(s) => string_detail("invalid-param", s),
        GarrisonError::NotImplemented(s) => string_detail("not-implemented", s),
        GarrisonError::FirewallBlocked(s) => string_detail("firewall-blocked", s),
        GarrisonError::DisableService { service, until } => (
            "disable-service",
            vec![
                ("service", service.clone()),
                ("until", format!("{:?}", until)),
            ],
        ),
        GarrisonError::NotSafe { reason } => ("not-safe", vec![("reason", reason.clone())]),
        GarrisonError::InvalidStateTransition { from, to } => (
            "invalid-state-transition",
            vec![("from", from.clone()), ("to", to.clone())],
        ),
        GarrisonError::SmsRateLimitExceeded { window } => {
            ("sms-rate-limit-exceeded", vec![("window", window.clone())])
        },
        GarrisonError::SmsVerifyMaxAttempts => ("sms-verify-max-attempts", vec![]),
        GarrisonError::SmsCodeNotFound => ("sms-code-not-found", vec![]),
        GarrisonError::SmsChannelRecycled => ("sms-channel-recycled", vec![]),
        GarrisonError::Exception(ex) => (
            "exception",
            vec![
                ("code", ex.code.to_string()),
                ("detail", ex.message.clone()),
            ],
        ),
    }
}

/// 翻译失败时的硬编码中文回退（与 0.2.x Display 输出一致）。
fn fallback_display(err: &GarrisonError) -> String {
    match err {
        GarrisonError::NotLogin(s) => format!("未登录: {}", s),
        GarrisonError::NotPermission(s) => format!("无权限: {}", s),
        GarrisonError::NotRole(s) => format!("无角色: {}", s),
        GarrisonError::InvalidToken(s) => format!("Token 无效: {}", s),
        GarrisonError::TokenRevoked(s) => format!("Token 已吊销: {}", s),
        GarrisonError::ExpiredToken(s) => format!("Token 已过期: {}", s),
        GarrisonError::Dao(s) => format!("DAO 错误: {}", s),
        GarrisonError::Config(s) => format!("配置错误: {}", s),
        GarrisonError::Internal(s) => format!("内部错误: {}", s),
        GarrisonError::Session(s) => format!("会话错误: {}", s),
        GarrisonError::Annotation(s) => format!("注解错误: {}", s),
        GarrisonError::Context(s) => format!("上下文错误: {}", s),
        GarrisonError::OAuth2(s) => format!("OAuth2 错误: {}", s),
        GarrisonError::Network(s) => format!("网络错误: {}", s),
        GarrisonError::InvalidParam(s) => format!("参数无效: {}", s),
        GarrisonError::NotImplemented(s) => format!("未实现: {}", s),
        GarrisonError::FirewallBlocked(s) => format!("防火墙拦截: {}", s),
        GarrisonError::DisableService { service, until } => {
            format!("账号已被封禁：service={}, until={:?}", service, until)
        },
        GarrisonError::NotSafe { reason } => format!("未完成二次认证：{}", reason),
        GarrisonError::InvalidStateTransition { from, to } => {
            format!("非法状态转换：{} -> {}", from, to)
        },
        GarrisonError::SmsRateLimitExceeded { window } => {
            format!("SMS 限速超出: {} 窗口", window)
        },
        GarrisonError::SmsVerifyMaxAttempts => "SMS 验证码尝试次数超限".to_string(),
        GarrisonError::SmsCodeNotFound => "SMS 验证码不存在".to_string(),
        GarrisonError::SmsChannelRecycled => "SMS 通道已回收".to_string(),
        GarrisonError::Exception(ex) => format!("业务异常[{}]: {}", ex.code, ex.message),
    }
}

// ============================================================================
// ICU4X 增强层（feature = "i18n-icu"）
// ============================================================================

/// ICU4X 增强模块，提供复数规则、日期/数字本地化。
///
/// 仅在 `i18n-icu` feature 启用时编译，不影响现有翻译逻辑。
#[cfg(feature = "i18n-icu")]
pub mod icu_enhanced {
    use crate::i18n::{current_locale, GarrisonLocale};
    use chrono::{Datelike, Timelike};
    use fixed_decimal::Decimal;
    use icu_datetime::fieldsets;
    use icu_datetime::DateTimeFormatter;
    use icu_decimal::DecimalFormatter;
    use icu_locale_core::{locale, Locale};
    use icu_plurals::{PluralCategory, PluralRules};

    /// 将 `GarrisonLocale` 转为 ICU `Locale`。
    fn to_icu_locale(l: GarrisonLocale) -> Locale {
        match l {
            GarrisonLocale::Zh => locale!("zh"),
            GarrisonLocale::En => locale!("en"),
        }
    }

    /// 返回当前 locale 下 `count` 的复数类别（Cardinal）。
    ///
    /// 用于选择正确的复数形式（如 "1 item" vs "2 items"）。
    pub fn plural_category(count: usize) -> PluralCategory {
        let rules =
            PluralRules::try_new(to_icu_locale(current_locale()).into(), Default::default())
                .expect("ICU PluralRules compiled_data 已编译，不应失败");
        rules.category_for(count)
    }

    /// 格式化 `chrono::DateTime` 为当前 locale 的本地化字符串。
    ///
    /// 替代 `format!("{:?}", dt)` 的 Debug 格式，输出如 "2026年1月1日" / "Jan 1, 2026"。
    pub fn format_datetime_locale(dt: &chrono::DateTime<chrono::Utc>) -> String {
        let icu_locale = to_icu_locale(current_locale());
        // YMDT fieldset：年月日+时间，medium 长度（如 "Jan 1, 2026, 12:00:00 AM"）
        let formatter = DateTimeFormatter::try_new(icu_locale.into(), fieldsets::YMDT::medium())
            .expect("ICU DateTimeFormatter compiled_data 已编译，不应失败");
        // 从 chrono 日期构造 ICU ISO Date
        let date = icu_calendar::Date::try_new_iso(dt.year(), dt.month() as u8, dt.day() as u8)
            .expect("chrono 日期转 ICU Date 不应失败");
        // 从 chrono 时间构造 ICU Time
        let time =
            icu_time::Time::try_new(dt.hour() as u8, dt.minute() as u8, dt.second() as u8, 0)
                .expect("chrono 时间转 ICU Time 不应失败");
        // DateTime 是 #[allow(clippy::exhaustive_structs)] 的公开结构体，可直接构造
        let datetime = icu_datetime::input::DateTime { date, time };
        formatter.format(&datetime).to_string()
    }

    /// 格式化整数为当前 locale 的本地化字符串（千分位/数字系统）。
    ///
    /// 如 en: "1,000,000" / zh: "1,000,000" / ar: "١٬٠٠٠٬٠٠٠"。
    pub fn format_number_locale(n: i64) -> String {
        let decimal = Decimal::from(n);
        let formatter =
            DecimalFormatter::try_new(to_icu_locale(current_locale()).into(), Default::default())
                .expect("ICU DecimalFormatter compiled_data 已编译，不应失败");
        formatter.format_to_string(&decimal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GarrisonError;
    use crate::exception::GarrisonException;

    // ========================================================================
    // GarrisonLocale 枚举测试
    // ========================================================================

    /// 默认 locale 应为中文。
    #[test]
    fn default_locale_is_zh() {
        let locale = GarrisonLocale::default();
        assert_eq!(locale, GarrisonLocale::Zh);
    }

    /// as_lang_id 返回正确的 LanguageIdentifier。
    #[test]
    fn as_lang_id_returns_correct_identifier() {
        assert_eq!(GarrisonLocale::Zh.as_lang_id().to_string(), "zh");
        assert_eq!(GarrisonLocale::En.as_lang_id().to_string(), "en");
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
        assert_eq!(locale, GarrisonLocale::Zh);
    }

    /// set_locale 后 current_locale 返回新值，drop 后恢复。
    #[test]
    fn set_locale_changes_current_and_restores_on_drop() {
        let original = current_locale();
        {
            let _guard = set_locale(GarrisonLocale::En);
            assert_eq!(current_locale(), GarrisonLocale::En);
        }
        assert_eq!(current_locale(), original);
    }

    /// set_locale 支持嵌套调用。
    #[test]
    fn set_locale_supports_nesting() {
        let original = current_locale();
        {
            let _g1 = set_locale(GarrisonLocale::En);
            assert_eq!(current_locale(), GarrisonLocale::En);
            {
                let _g2 = set_locale(GarrisonLocale::Zh);
                assert_eq!(current_locale(), GarrisonLocale::Zh);
            }
            assert_eq!(current_locale(), GarrisonLocale::En);
        }
        assert_eq!(current_locale(), original);
    }

    // ========================================================================
    // translate_error 测试
    // ========================================================================

    /// 默认中文：NotLogin 翻译为中文消息。
    #[test]
    fn translate_error_zh_returns_chinese_message() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::NotLogin("请先登录".to_string());
        let translated = translate_error(&err);
        assert_eq!(translated, "未登录: 请先登录");
    }

    /// 英文 locale：NotLogin 翻译为英文消息。
    #[test]
    fn translate_error_en_returns_english_message() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::NotLogin("please login first".to_string());
        let translated = translate_error(&err);
        assert_eq!(translated, "Not logged in: please login first");
    }

    /// 所有错误变体在中文 locale 下输出与硬编码一致。
    #[test]
    fn translate_error_zh_all_variants_match_hardcoded() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let cases = vec![
            (GarrisonError::NotLogin("a".into()), "未登录: a"),
            (GarrisonError::NotPermission("a".into()), "无权限: a"),
            (GarrisonError::NotRole("a".into()), "无角色: a"),
            (GarrisonError::InvalidToken("a".into()), "Token 无效: a"),
            (GarrisonError::ExpiredToken("a".into()), "Token 已过期: a"),
            (GarrisonError::Dao("a".into()), "DAO 错误: a"),
            (GarrisonError::Config("a".into()), "配置错误: a"),
            (GarrisonError::Internal("a".into()), "内部错误: a"),
            (GarrisonError::Session("a".into()), "会话错误: a"),
            (GarrisonError::Annotation("a".into()), "注解错误: a"),
            (GarrisonError::Context("a".into()), "上下文错误: a"),
            (GarrisonError::OAuth2("a".into()), "OAuth2 错误: a"),
            (GarrisonError::Network("a".into()), "网络错误: a"),
            (GarrisonError::InvalidParam("a".into()), "参数无效: a"),
            (GarrisonError::NotImplemented("a".into()), "未实现: a"),
        ];
        for (err, expected) in cases {
            assert_eq!(translate_error(&err), expected, "mismatch for {:?}", err);
        }
    }

    /// 所有错误变体在英文 locale 下输出英文消息。
    #[test]
    fn translate_error_en_all_variants_english() {
        let _guard = set_locale(GarrisonLocale::En);
        let cases = vec![
            (GarrisonError::NotLogin("a".into()), "Not logged in: a"),
            (
                GarrisonError::NotPermission("a".into()),
                "Permission denied: a",
            ),
            (GarrisonError::NotRole("a".into()), "Role denied: a"),
            (GarrisonError::InvalidToken("a".into()), "Invalid token: a"),
            (GarrisonError::ExpiredToken("a".into()), "Token expired: a"),
            (GarrisonError::Dao("a".into()), "DAO error: a"),
            (GarrisonError::Config("a".into()), "Configuration error: a"),
            (GarrisonError::Internal("a".into()), "Internal error: a"),
            (GarrisonError::Session("a".into()), "Session error: a"),
            (GarrisonError::Annotation("a".into()), "Annotation error: a"),
            (GarrisonError::Context("a".into()), "Context error: a"),
            (GarrisonError::OAuth2("a".into()), "OAuth2 error: a"),
            (GarrisonError::Network("a".into()), "Network error: a"),
            (
                GarrisonError::InvalidParam("a".into()),
                "Invalid parameter: a",
            ),
            (
                GarrisonError::NotImplemented("a".into()),
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
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::Exception(GarrisonException::new(-1, "请先登录"));
        assert_eq!(translate_error(&err), "业务异常[-1]: 请先登录");
    }

    /// Exception 变体在英文 locale 下输出"Business exception[code]: message"。
    #[test]
    fn translate_error_en_exception_variant() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::Exception(GarrisonException::new(-1, "please login"));
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
            let _g = set_locale(GarrisonLocale::En);
            let err = GarrisonError::Dao("err".to_string());
            assert_eq!(translate_error(&err), "DAO error: err");
        }
        // 范围外恢复原 locale
        let err = GarrisonError::Dao("err".to_string());
        if original == GarrisonLocale::En {
            assert_eq!(translate_error(&err), "DAO error: err");
        } else {
            assert_eq!(translate_error(&err), "DAO 错误: err");
        }
    }

    /// fallback_display 与硬编码 0.2.x 输出一致。
    #[test]
    fn fallback_display_matches_hardcoded_chinese() {
        let err = GarrisonError::NotLogin("测试".to_string());
        assert_eq!(fallback_display(&err), "未登录: 测试");
    }

    /// fallback_display 覆盖所有错误变体（确保每个 match arm 都有测试）。
    #[test]
    fn fallback_display_all_variants() {
        let cases: Vec<(GarrisonError, &str)> = vec![
            (GarrisonError::NotLogin("x".into()), "未登录: x"),
            (GarrisonError::NotPermission("x".into()), "无权限: x"),
            (GarrisonError::NotRole("x".into()), "无角色: x"),
            (GarrisonError::InvalidToken("x".into()), "Token 无效: x"),
            (GarrisonError::ExpiredToken("x".into()), "Token 已过期: x"),
            (GarrisonError::Dao("x".into()), "DAO 错误: x"),
            (GarrisonError::Config("x".into()), "配置错误: x"),
            (GarrisonError::Internal("x".into()), "内部错误: x"),
            (GarrisonError::Session("x".into()), "会话错误: x"),
            (GarrisonError::Annotation("x".into()), "注解错误: x"),
            (GarrisonError::Context("x".into()), "上下文错误: x"),
            (GarrisonError::OAuth2("x".into()), "OAuth2 错误: x"),
            (GarrisonError::Network("x".into()), "网络错误: x"),
            (GarrisonError::InvalidParam("x".into()), "参数无效: x"),
            (GarrisonError::NotImplemented("x".into()), "未实现: x"),
            (
                GarrisonError::Exception(GarrisonException::new(-1, "msg")),
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
        let b1 = get_bundle(GarrisonLocale::Zh);
        let b2 = get_bundle(GarrisonLocale::Zh);
        // 指针相等表示同一实例
        assert!(std::ptr::eq(b1, b2));
    }

    // ========================================================================
    // translate_detail 测试（loc! 宏底层调用）
    // ========================================================================

    /// translate_detail 找到 key 时返回中文翻译。
    #[test]
    fn translate_detail_zh_returns_translated_message() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = translate_detail("not-login", &[("detail", "请先登录")]);
        assert_eq!(msg, "未登录: 请先登录");
    }

    /// translate_detail 找到 key 时返回英文翻译。
    #[test]
    fn translate_detail_en_returns_translated_message() {
        let _guard = set_locale(GarrisonLocale::En);
        let msg = translate_detail("not-login", &[("detail", "please login")]);
        assert_eq!(msg, "Not logged in: please login");
    }

    /// translate_detail 未找到 key 时返回 key 本身。
    #[test]
    fn translate_detail_missing_key_returns_key() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = translate_detail("nonexistent-key-xyz", &[]);
        assert_eq!(msg, "nonexistent-key-xyz");
    }

    /// translate_detail 无参数时正常翻译。
    #[test]
    fn translate_detail_no_args_translates_successfully() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = translate_detail("sms-verify-max-attempts", &[]);
        assert_eq!(msg, "SMS 验证码尝试次数超限");
    }

    /// translate_detail 多参数翻译（disable-service 含 service + until）。
    #[test]
    fn translate_detail_multiple_args_zh() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = translate_detail(
            "disable-service",
            &[
                ("service", "default"),
                ("until", "Some(2026-01-01T00:00:00Z)"),
            ],
        );
        assert!(msg.contains("service=default"));
        assert!(msg.contains("账号已被封禁"));
    }

    /// translate_detail 多参数翻译（英文）。
    #[test]
    fn translate_detail_multiple_args_en() {
        let _guard = set_locale(GarrisonLocale::En);
        let msg = translate_detail(
            "invalid-state-transition",
            &[("from", "Active"), ("to", "Closed")],
        );
        assert_eq!(msg, "Invalid state transition: Active -> Closed");
    }

    // ========================================================================
    // 0.6.1 新增错误变体 translate_error 测试
    // ========================================================================

    /// TokenRevoked 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_token_revoked() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::TokenRevoked("reuse detected".to_string());
        let translated = translate_error(&err);
        // token-revoked key 不存在于 .ftl，走 fallback_display
        assert_eq!(translated, "Token 已吊销: reuse detected");
    }

    /// TokenRevoked 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_token_revoked() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::TokenRevoked("reuse detected".to_string());
        let translated = translate_error(&err);
        // token-revoked key 不存在于 .ftl，走 fallback_display（中文硬编码）
        assert_eq!(translated, "Token 已吊销: reuse detected");
    }

    /// FirewallBlocked 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_firewall_blocked() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::FirewallBlocked("black_path: /admin".to_string());
        let translated = translate_error(&err);
        // firewall-blocked key 不存在于 .ftl，走 fallback_display
        assert_eq!(translated, "防火墙拦截: black_path: /admin");
    }

    /// DisableService 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_disable_service() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let until = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let err = GarrisonError::DisableService {
            service: "default".to_string(),
            until: Some(until),
        };
        let translated = translate_error(&err);
        assert!(translated.contains("service=default"));
        assert!(translated.contains("账号已被封禁"));
    }

    /// DisableService 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_disable_service() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::DisableService {
            service: "oidc".to_string(),
            until: None,
        };
        let translated = translate_error(&err);
        assert!(translated.contains("service=oidc"));
        assert!(translated.contains("Account disabled"));
    }

    /// NotSafe 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_not_safe() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::NotSafe {
            reason: "MFA_TOTP_REQUIRED".to_string(),
        };
        assert_eq!(translate_error(&err), "未完成二次认证：MFA_TOTP_REQUIRED");
    }

    /// NotSafe 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_not_safe() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::NotSafe {
            reason: "WEBAUTHN_REQUIRED".to_string(),
        };
        assert_eq!(
            translate_error(&err),
            "Second factor authentication required: WEBAUTHN_REQUIRED"
        );
    }

    /// InvalidStateTransition 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_invalid_state_transition() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::InvalidStateTransition {
            from: "Active".to_string(),
            to: "Closed".to_string(),
        };
        assert_eq!(translate_error(&err), "非法状态转换：Active -> Closed");
    }

    /// InvalidStateTransition 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_invalid_state_transition() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::InvalidStateTransition {
            from: "Pending".to_string(),
            to: "Active".to_string(),
        };
        assert_eq!(
            translate_error(&err),
            "Invalid state transition: Pending -> Active"
        );
    }

    /// SmsRateLimitExceeded 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_sms_rate_limit_exceeded() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::SmsRateLimitExceeded {
            window: "hourly".to_string(),
        };
        assert_eq!(translate_error(&err), "SMS 限速超出: hourly 窗口");
    }

    /// SmsRateLimitExceeded 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_sms_rate_limit_exceeded() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::SmsRateLimitExceeded {
            window: "daily".to_string(),
        };
        assert_eq!(
            translate_error(&err),
            "SMS rate limit exceeded: daily window"
        );
    }

    /// SmsVerifyMaxAttempts 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_sms_verify_max_attempts() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::SmsVerifyMaxAttempts;
        assert_eq!(translate_error(&err), "SMS 验证码尝试次数超限");
    }

    /// SmsVerifyMaxAttempts 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_sms_verify_max_attempts() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::SmsVerifyMaxAttempts;
        assert_eq!(
            translate_error(&err),
            "SMS verification max attempts exceeded"
        );
    }

    /// SmsCodeNotFound 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_sms_code_not_found() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::SmsCodeNotFound;
        assert_eq!(translate_error(&err), "SMS 验证码不存在");
    }

    /// SmsCodeNotFound 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_sms_code_not_found() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::SmsCodeNotFound;
        assert_eq!(translate_error(&err), "SMS verification code not found");
    }

    /// SmsChannelRecycled 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_sms_channel_recycled() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::SmsChannelRecycled;
        assert_eq!(translate_error(&err), "SMS 通道已回收");
    }

    /// SmsChannelRecycled 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_sms_channel_recycled() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::SmsChannelRecycled;
        assert_eq!(translate_error(&err), "SMS channel recycled");
    }

    // ========================================================================
    // fallback_display 补充测试（0.6.1 新增变体）
    // ========================================================================

    /// fallback_display 覆盖 0.6.1 新增变体。
    #[test]
    fn fallback_display_new_variants() {
        let until = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let cases: Vec<(GarrisonError, String)> = vec![
            (
                GarrisonError::TokenRevoked("x".into()),
                "Token 已吊销: x".to_string(),
            ),
            (
                GarrisonError::FirewallBlocked("x".into()),
                "防火墙拦截: x".to_string(),
            ),
            (
                GarrisonError::DisableService {
                    service: "default".into(),
                    until: Some(until),
                },
                format!("账号已被封禁：service=default, until={:?}", Some(until)),
            ),
            (
                GarrisonError::DisableService {
                    service: "oidc".into(),
                    until: None,
                },
                "账号已被封禁：service=oidc, until=None".to_string(),
            ),
            (
                GarrisonError::NotSafe { reason: "r".into() },
                "未完成二次认证：r".to_string(),
            ),
            (
                GarrisonError::InvalidStateTransition {
                    from: "A".into(),
                    to: "B".into(),
                },
                "非法状态转换：A -> B".to_string(),
            ),
            (
                GarrisonError::SmsRateLimitExceeded { window: "w".into() },
                "SMS 限速超出: w 窗口".to_string(),
            ),
            (
                GarrisonError::SmsVerifyMaxAttempts,
                "SMS 验证码尝试次数超限".to_string(),
            ),
            (
                GarrisonError::SmsCodeNotFound,
                "SMS 验证码不存在".to_string(),
            ),
            (
                GarrisonError::SmsChannelRecycled,
                "SMS 通道已回收".to_string(),
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(fallback_display(&err), expected, "mismatch for {:?}", err);
        }
    }

    /// error_to_key_args 覆盖所有变体（确保每个 match arm 都被执行）。
    #[test]
    fn error_to_key_args_all_variants() {
        let until = chrono::Utc::now();
        let cases: Vec<GarrisonError> = vec![
            GarrisonError::NotLogin("a".into()),
            GarrisonError::NotPermission("a".into()),
            GarrisonError::NotRole("a".into()),
            GarrisonError::InvalidToken("a".into()),
            GarrisonError::TokenRevoked("a".into()),
            GarrisonError::ExpiredToken("a".into()),
            GarrisonError::Dao("a".into()),
            GarrisonError::Config("a".into()),
            GarrisonError::Internal("a".into()),
            GarrisonError::Session("a".into()),
            GarrisonError::Annotation("a".into()),
            GarrisonError::Context("a".into()),
            GarrisonError::OAuth2("a".into()),
            GarrisonError::Network("a".into()),
            GarrisonError::InvalidParam("a".into()),
            GarrisonError::NotImplemented("a".into()),
            GarrisonError::FirewallBlocked("a".into()),
            GarrisonError::DisableService {
                service: "s".into(),
                until: Some(until),
            },
            GarrisonError::NotSafe { reason: "r".into() },
            GarrisonError::InvalidStateTransition {
                from: "f".into(),
                to: "t".into(),
            },
            GarrisonError::SmsRateLimitExceeded { window: "w".into() },
            GarrisonError::SmsVerifyMaxAttempts,
            GarrisonError::SmsCodeNotFound,
            GarrisonError::SmsChannelRecycled,
            GarrisonError::Exception(GarrisonException::new(-1, "msg")),
        ];
        for err in cases {
            // 仅验证不 panic 且返回非空 key
            let (key, _args) = error_to_key_args(&err);
            assert!(!key.is_empty(), "key 不应为空: {:?}", err);
        }
    }

    /// get_bundle 对英文 locale 也返回缓存实例。
    #[test]
    fn get_bundle_en_returns_cached_instance() {
        let b1 = get_bundle(GarrisonLocale::En);
        let b2 = get_bundle(GarrisonLocale::En);
        assert!(std::ptr::eq(b1, b2), "英文 bundle 应为同一缓存实例");
    }

    // ========================================================================
    // translate_detail 测试
    // ========================================================================

    /// translate_detail 对已知 key 返回翻译后的字符串。
    #[test]
    fn translate_detail_known_key_returns_translation() {
        let _guard = set_locale(GarrisonLocale::En);
        let result = translate_detail("not-login", &[("detail", "test")]);
        assert!(result.contains("test"), "应包含参数值: {}", result);
    }

    /// translate_detail 对未知 key 返回 key 本身。
    #[test]
    fn translate_detail_unknown_key_returns_key() {
        let _guard = set_locale(GarrisonLocale::En);
        let result = translate_detail("nonexistent-key-xyz", &[]);
        assert_eq!(result, "nonexistent-key-xyz");
    }

    /// translate_detail 对已知 key 但无参数也能正常翻译。
    #[test]
    fn translate_detail_known_key_no_args() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let result = translate_detail("sms-verify-max-attempts", &[]);
        assert!(!result.is_empty());
        assert_ne!(result, "sms-verify-max-attempts", "应返回翻译而非 key 本身");
    }

    // ========================================================================
    // ICU4X 增强层测试（feature = "i18n-icu"）
    // ========================================================================

    #[cfg(feature = "i18n-icu")]
    #[test]
    fn icu_plural_category_en_one() {
        let _guard = set_locale(GarrisonLocale::En);
        let cat = icu_enhanced::plural_category(1);
        assert_eq!(cat, icu_plurals::PluralCategory::One);
    }

    #[cfg(feature = "i18n-icu")]
    #[test]
    fn icu_plural_category_en_other() {
        let _guard = set_locale(GarrisonLocale::En);
        let cat = icu_enhanced::plural_category(2);
        assert_eq!(cat, icu_plurals::PluralCategory::Other);
    }

    #[cfg(feature = "i18n-icu")]
    #[test]
    fn icu_format_number_en() {
        let _guard = set_locale(GarrisonLocale::En);
        let formatted = icu_enhanced::format_number_locale(1_000_000);
        assert!(formatted.contains("1"), "应包含数字 1: {}", formatted);
    }

    #[cfg(feature = "i18n-icu")]
    #[test]
    fn icu_format_datetime_en() {
        let _guard = set_locale(GarrisonLocale::En);
        let dt = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let formatted = icu_enhanced::format_datetime_locale(&dt);
        assert!(!formatted.is_empty(), "日期格式化不应为空");
        assert!(formatted.contains("2026"), "应包含年份: {}", formatted);
    }
}
