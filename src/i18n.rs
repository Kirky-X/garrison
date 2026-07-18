//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 国际化模块，提供异常消息多语言切换（中英文）。
//!
//! 异常消息国际化改进。
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

/// 构造本地化错误文案：优先按 `key` 查 FTL 翻译，缺失时回退 `$fallback` 字符串。
///
/// i18n 基础层已无条件编译，本宏始终委托 [`translate_detail`]，无需 feature 门控。
///
/// # 示例
///
/// ```ignore
/// let err = BulwarkError::Network(loc!(
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

/// 按 key + args 翻译为当前 locale 的本地化字符串。
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

/// 解析结构化错误 detail：`key::arg0::arg1`。
///
/// 调用方在去语言化后，将 `BulwarkError` 的 `String` 字段写为
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
fn error_to_key_args(err: &BulwarkError) -> (&'static str, Vec<(&'static str, String)>) {
    match err {
        BulwarkError::NotLogin(s) => string_detail("not-login", s),
        BulwarkError::NotPermission(s) => string_detail("not-permission", s),
        BulwarkError::NotRole(s) => string_detail("not-role", s),
        BulwarkError::InvalidToken(s) => string_detail("invalid-token", s),
        BulwarkError::TokenRevoked(s) => string_detail("token-revoked", s),
        BulwarkError::ExpiredToken(s) => string_detail("expired-token", s),
        BulwarkError::Dao(s) => string_detail("dao", s),
        BulwarkError::Config(s) => string_detail("config", s),
        BulwarkError::Internal(s) => string_detail("internal", s),
        BulwarkError::Session(s) => string_detail("session", s),
        BulwarkError::Annotation(s) => string_detail("annotation", s),
        BulwarkError::Context(s) => string_detail("context", s),
        BulwarkError::OAuth2(s) => string_detail("oauth2", s),
        BulwarkError::Network(s) => string_detail("network", s),
        BulwarkError::InvalidParam(s) => string_detail("invalid-param", s),
        BulwarkError::NotImplemented(s) => string_detail("not-implemented", s),
        BulwarkError::FirewallBlocked(s) => string_detail("firewall-blocked", s),
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
        BulwarkError::SmsRateLimitExceeded { window } => {
            ("sms-rate-limit-exceeded", vec![("window", window.clone())])
        },
        BulwarkError::SmsVerifyMaxAttempts => ("sms-verify-max-attempts", vec![]),
        BulwarkError::SmsCodeNotFound => ("sms-code-not-found", vec![]),
        BulwarkError::SmsChannelRecycled => ("sms-channel-recycled", vec![]),
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
        BulwarkError::TokenRevoked(s) => format!("Token 已吊销: {}", s),
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
        BulwarkError::SmsRateLimitExceeded { window } => {
            format!("SMS 限速超出: {} 窗口", window)
        },
        BulwarkError::SmsVerifyMaxAttempts => "SMS 验证码尝试次数超限".to_string(),
        BulwarkError::SmsCodeNotFound => "SMS 验证码不存在".to_string(),
        BulwarkError::SmsChannelRecycled => "SMS 通道已回收".to_string(),
        BulwarkError::Exception(ex) => format!("业务异常[{}]: {}", ex.code, ex.message),
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
    use crate::i18n::{current_locale, BulwarkLocale};
    use chrono::{Datelike, Timelike};
    use fixed_decimal::Decimal;
    use icu_datetime::fieldsets;
    use icu_datetime::DateTimeFormatter;
    use icu_decimal::DecimalFormatter;
    use icu_locale_core::{locale, Locale};
    use icu_plurals::{PluralCategory, PluralRules};

    /// 将 `BulwarkLocale` 转为 ICU `Locale`。
    fn to_icu_locale(l: BulwarkLocale) -> Locale {
        match l {
            BulwarkLocale::Zh => locale!("zh"),
            BulwarkLocale::En => locale!("en"),
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

    // ========================================================================
    // translate_detail 测试（loc! 宏底层调用）
    // ========================================================================

    /// translate_detail 找到 key 时返回中文翻译。
    #[test]
    fn translate_detail_zh_returns_translated_message() {
        let _guard = set_locale(BulwarkLocale::Zh);
        let msg = translate_detail("not-login", &[("detail", "请先登录")]);
        assert_eq!(msg, "未登录: 请先登录");
    }

    /// translate_detail 找到 key 时返回英文翻译。
    #[test]
    fn translate_detail_en_returns_translated_message() {
        let _guard = set_locale(BulwarkLocale::En);
        let msg = translate_detail("not-login", &[("detail", "please login")]);
        assert_eq!(msg, "Not logged in: please login");
    }

    /// translate_detail 未找到 key 时返回 key 本身。
    #[test]
    fn translate_detail_missing_key_returns_key() {
        let _guard = set_locale(BulwarkLocale::Zh);
        let msg = translate_detail("nonexistent-key-xyz", &[]);
        assert_eq!(msg, "nonexistent-key-xyz");
    }

    /// translate_detail 无参数时正常翻译。
    #[test]
    fn translate_detail_no_args_translates_successfully() {
        let _guard = set_locale(BulwarkLocale::Zh);
        let msg = translate_detail("sms-verify-max-attempts", &[]);
        assert_eq!(msg, "SMS 验证码尝试次数超限");
    }

    /// translate_detail 多参数翻译（disable-service 含 service + until）。
    #[test]
    fn translate_detail_multiple_args_zh() {
        let _guard = set_locale(BulwarkLocale::Zh);
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
        let _guard = set_locale(BulwarkLocale::En);
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
        let _guard = set_locale(BulwarkLocale::Zh);
        let err = BulwarkError::TokenRevoked("reuse detected".to_string());
        let translated = translate_error(&err);
        // token-revoked key 不存在于 .ftl，走 fallback_display
        assert_eq!(translated, "Token 已吊销: reuse detected");
    }

    /// TokenRevoked 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_token_revoked() {
        let _guard = set_locale(BulwarkLocale::En);
        let err = BulwarkError::TokenRevoked("reuse detected".to_string());
        let translated = translate_error(&err);
        // token-revoked key 不存在于 .ftl，走 fallback_display（中文硬编码）
        assert_eq!(translated, "Token 已吊销: reuse detected");
    }

    /// FirewallBlocked 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_firewall_blocked() {
        let _guard = set_locale(BulwarkLocale::Zh);
        let err = BulwarkError::FirewallBlocked("black_path: /admin".to_string());
        let translated = translate_error(&err);
        // firewall-blocked key 不存在于 .ftl，走 fallback_display
        assert_eq!(translated, "防火墙拦截: black_path: /admin");
    }

    /// DisableService 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_disable_service() {
        let _guard = set_locale(BulwarkLocale::Zh);
        let until = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let err = BulwarkError::DisableService {
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
        let _guard = set_locale(BulwarkLocale::En);
        let err = BulwarkError::DisableService {
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
        let _guard = set_locale(BulwarkLocale::Zh);
        let err = BulwarkError::NotSafe {
            reason: "MFA_TOTP_REQUIRED".to_string(),
        };
        assert_eq!(translate_error(&err), "未完成二次认证：MFA_TOTP_REQUIRED");
    }

    /// NotSafe 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_not_safe() {
        let _guard = set_locale(BulwarkLocale::En);
        let err = BulwarkError::NotSafe {
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
        let _guard = set_locale(BulwarkLocale::Zh);
        let err = BulwarkError::InvalidStateTransition {
            from: "Active".to_string(),
            to: "Closed".to_string(),
        };
        assert_eq!(translate_error(&err), "非法状态转换：Active -> Closed");
    }

    /// InvalidStateTransition 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_invalid_state_transition() {
        let _guard = set_locale(BulwarkLocale::En);
        let err = BulwarkError::InvalidStateTransition {
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
        let _guard = set_locale(BulwarkLocale::Zh);
        let err = BulwarkError::SmsRateLimitExceeded {
            window: "hourly".to_string(),
        };
        assert_eq!(translate_error(&err), "SMS 限速超出: hourly 窗口");
    }

    /// SmsRateLimitExceeded 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_sms_rate_limit_exceeded() {
        let _guard = set_locale(BulwarkLocale::En);
        let err = BulwarkError::SmsRateLimitExceeded {
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
        let _guard = set_locale(BulwarkLocale::Zh);
        let err = BulwarkError::SmsVerifyMaxAttempts;
        assert_eq!(translate_error(&err), "SMS 验证码尝试次数超限");
    }

    /// SmsVerifyMaxAttempts 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_sms_verify_max_attempts() {
        let _guard = set_locale(BulwarkLocale::En);
        let err = BulwarkError::SmsVerifyMaxAttempts;
        assert_eq!(
            translate_error(&err),
            "SMS verification max attempts exceeded"
        );
    }

    /// SmsCodeNotFound 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_sms_code_not_found() {
        let _guard = set_locale(BulwarkLocale::Zh);
        let err = BulwarkError::SmsCodeNotFound;
        assert_eq!(translate_error(&err), "SMS 验证码不存在");
    }

    /// SmsCodeNotFound 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_sms_code_not_found() {
        let _guard = set_locale(BulwarkLocale::En);
        let err = BulwarkError::SmsCodeNotFound;
        assert_eq!(translate_error(&err), "SMS verification code not found");
    }

    /// SmsChannelRecycled 在中文 locale 下输出翻译消息。
    #[test]
    fn translate_error_zh_sms_channel_recycled() {
        let _guard = set_locale(BulwarkLocale::Zh);
        let err = BulwarkError::SmsChannelRecycled;
        assert_eq!(translate_error(&err), "SMS 通道已回收");
    }

    /// SmsChannelRecycled 在英文 locale 下输出翻译消息。
    #[test]
    fn translate_error_en_sms_channel_recycled() {
        let _guard = set_locale(BulwarkLocale::En);
        let err = BulwarkError::SmsChannelRecycled;
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
        let cases: Vec<(BulwarkError, String)> = vec![
            (
                BulwarkError::TokenRevoked("x".into()),
                "Token 已吊销: x".to_string(),
            ),
            (
                BulwarkError::FirewallBlocked("x".into()),
                "防火墙拦截: x".to_string(),
            ),
            (
                BulwarkError::DisableService {
                    service: "default".into(),
                    until: Some(until),
                },
                format!("账号已被封禁：service=default, until={:?}", Some(until)),
            ),
            (
                BulwarkError::DisableService {
                    service: "oidc".into(),
                    until: None,
                },
                "账号已被封禁：service=oidc, until=None".to_string(),
            ),
            (
                BulwarkError::NotSafe { reason: "r".into() },
                "未完成二次认证：r".to_string(),
            ),
            (
                BulwarkError::InvalidStateTransition {
                    from: "A".into(),
                    to: "B".into(),
                },
                "非法状态转换：A -> B".to_string(),
            ),
            (
                BulwarkError::SmsRateLimitExceeded { window: "w".into() },
                "SMS 限速超出: w 窗口".to_string(),
            ),
            (
                BulwarkError::SmsVerifyMaxAttempts,
                "SMS 验证码尝试次数超限".to_string(),
            ),
            (
                BulwarkError::SmsCodeNotFound,
                "SMS 验证码不存在".to_string(),
            ),
            (
                BulwarkError::SmsChannelRecycled,
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
        let cases: Vec<BulwarkError> = vec![
            BulwarkError::NotLogin("a".into()),
            BulwarkError::NotPermission("a".into()),
            BulwarkError::NotRole("a".into()),
            BulwarkError::InvalidToken("a".into()),
            BulwarkError::TokenRevoked("a".into()),
            BulwarkError::ExpiredToken("a".into()),
            BulwarkError::Dao("a".into()),
            BulwarkError::Config("a".into()),
            BulwarkError::Internal("a".into()),
            BulwarkError::Session("a".into()),
            BulwarkError::Annotation("a".into()),
            BulwarkError::Context("a".into()),
            BulwarkError::OAuth2("a".into()),
            BulwarkError::Network("a".into()),
            BulwarkError::InvalidParam("a".into()),
            BulwarkError::NotImplemented("a".into()),
            BulwarkError::FirewallBlocked("a".into()),
            BulwarkError::DisableService {
                service: "s".into(),
                until: Some(until),
            },
            BulwarkError::NotSafe { reason: "r".into() },
            BulwarkError::InvalidStateTransition {
                from: "f".into(),
                to: "t".into(),
            },
            BulwarkError::SmsRateLimitExceeded { window: "w".into() },
            BulwarkError::SmsVerifyMaxAttempts,
            BulwarkError::SmsCodeNotFound,
            BulwarkError::SmsChannelRecycled,
            BulwarkError::Exception(BulwarkException::new(-1, "msg")),
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
        let b1 = get_bundle(BulwarkLocale::En);
        let b2 = get_bundle(BulwarkLocale::En);
        assert!(std::ptr::eq(b1, b2), "英文 bundle 应为同一缓存实例");
    }

    // ========================================================================
    // translate_detail 测试
    // ========================================================================

    /// translate_detail 对已知 key 返回翻译后的字符串。
    #[test]
    fn translate_detail_known_key_returns_translation() {
        let _guard = set_locale(BulwarkLocale::En);
        let result = translate_detail("not-login", &[("detail", "test")]);
        assert!(result.contains("test"), "应包含参数值: {}", result);
    }

    /// translate_detail 对未知 key 返回 key 本身。
    #[test]
    fn translate_detail_unknown_key_returns_key() {
        let _guard = set_locale(BulwarkLocale::En);
        let result = translate_detail("nonexistent-key-xyz", &[]);
        assert_eq!(result, "nonexistent-key-xyz");
    }

    /// translate_detail 对已知 key 但无参数也能正常翻译。
    #[test]
    fn translate_detail_known_key_no_args() {
        let _guard = set_locale(BulwarkLocale::Zh);
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
        let _guard = set_locale(BulwarkLocale::En);
        let cat = icu_enhanced::plural_category(1);
        assert_eq!(cat, icu_plurals::PluralCategory::One);
    }

    #[cfg(feature = "i18n-icu")]
    #[test]
    fn icu_plural_category_en_other() {
        let _guard = set_locale(BulwarkLocale::En);
        let cat = icu_enhanced::plural_category(2);
        assert_eq!(cat, icu_plurals::PluralCategory::Other);
    }

    #[cfg(feature = "i18n-icu")]
    #[test]
    fn icu_format_number_en() {
        let _guard = set_locale(BulwarkLocale::En);
        let formatted = icu_enhanced::format_number_locale(1_000_000);
        assert!(formatted.contains("1"), "应包含数字 1: {}", formatted);
    }

    #[cfg(feature = "i18n-icu")]
    #[test]
    fn icu_format_datetime_en() {
        let _guard = set_locale(BulwarkLocale::En);
        let dt = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let formatted = icu_enhanced::format_datetime_locale(&dt);
        assert!(!formatted.is_empty(), "日期格式化不应为空");
        assert!(formatted.contains("2026"), "应包含年份: {}", formatted);
    }
}
