// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 国际化模块，提供异常消息多语言切换（中英文）。
//!
//! - `GarrisonLocale`：支持的语言枚举（默认 `En`，英文）
//! - thread_local 栈式 scope：`set_locale()` 返回 RAII guard，drop 时自动 pop
//! - `OnceLock` 缓存 `FluentBundle`：首次访问时加载 .ftl 资源，后续零开销
//! - `translate_error(&GarrisonError) -> String`：依据当前 locale 查询 fluent bundle
//!
//! ## 使用示例
//!
//! ```ignore
//! use garrison::i18n::{set_locale, GarrisonLocale};
//! use garrison::error::GarrisonError;
//!
//! // 默认英文
//! let err = GarrisonError::NotLogin("请先登录".to_string());
//! assert_eq!(err.to_string(), "Not logged in: 请先登录");
//!
//! // 切换中文
//! let _guard = set_locale(GarrisonLocale::Zh);
//! assert_eq!(err.to_string(), "未登录: 请先登录");
//!
//! // guard drop 后自动恢复英文
//! ```
use crate::error::GarrisonError;
use fluent::concurrent::FluentBundle;
use fluent::{FluentArgs, FluentResource};
use std::cell::RefCell;
use std::sync::OnceLock;
use unic_langid::LanguageIdentifier;

/// 构造本地化错误文案：按 `key` 查 FTL 翻译，缺 key 或格式化失败回退 `$fallback`，`$fallback` 为空串时返回 `key` 本身（既有调用点传 `""` 时输出与旧行为一致）。
///
/// i18n 基础层无条件编译，本宏始终委托 [`translate_detail`]，无需 feature 门控。
///
/// # 示例
///
/// ```ignore
/// let err = GarrisonError::Network(loc!(
/// "wechat-response-missing-openid",
/// "wechat response missing openid field".to_string()
/// ));
/// ```
#[macro_export]
macro_rules! loc {
    ($key:expr, $fallback:expr $(, ($arg_k:expr, $arg_v:expr))*) => {{
        let translated = $crate::i18n::translate_detail($key, &[$(($arg_k, $arg_v)),*]);
        if translated == $key {
            // 缺 key：应用调用方 fallback；空串保持返回 key（视为未提供）
            let fallback = $fallback.to_string();
            if fallback.is_empty() {
                translated
            } else {
                fallback
            }
        } else {
            translated
        }
    }};
}

/// 支持的语言枚举（仅中文与英文）：`#[default] En` 为系统语言探测失败的回退值；未显式 [`set_locale`] 时 [`current_locale()`] 首次调用探测系统语言并缓存。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GarrisonLocale {
    /// 中文。
    Zh,
    /// 英文（默认语言，亦为探测失败回退）。
    #[default]
    En,
}

impl GarrisonLocale {
    /// 返回对应的 BCP-47 语言标签。
    fn as_lang_id(self) -> LanguageIdentifier {
        match self {
            GarrisonLocale::Zh => "zh"
                .parse()
                .expect("valid BCP-47 language identifier; 若失败请报告 bug"),
            GarrisonLocale::En => "en"
                .parse()
                .expect("valid BCP-47 language identifier; 若失败请报告 bug"),
        }
    }
}

// 系统语言自动检测（GARRISON_LANG → LC_ALL → LC_MESSAGES → LANG → sys-locale）

/// 系统语言检测结果缓存（进程级）：locale 栈为空时由 [`current_locale()`] 首次调用填充，所有线程"无显式 locale"状态共用；[`set_locale`] 覆盖栈内值，guard 全 pop 后回到该缓存值。
static DETECTED_LOCALE: OnceLock<GarrisonLocale> = OnceLock::new();

/// 探测系统语言（检测链命中即返回）：`GARRISON_LANG` → `LC_ALL`/`LC_MESSAGES`/`LANG`（显式读取保证 Windows/边缘环境确定性）→ `sys_locale::get_locale()` → 回退 [`GarrisonLocale::En`]。
///
/// 仅映射 `zh*`/`en*`；`C`/`POSIX` 与第三语言跳过并继续走链，链尾必为 `En`。
pub fn detect_locale() -> GarrisonLocale {
    detect_from(
        &|key| std::env::var(key).ok(),
        sys_locale::get_locale().as_deref(),
    )
}

/// 检测链纯函数：env 查找与系统 locale 均注入，不读进程环境，便于测试。
fn detect_from(getenv: &dyn Fn(&str) -> Option<String>, sys: Option<&str>) -> GarrisonLocale {
    detect_from_env(getenv)
        .or_else(|| sys.and_then(normalize_lang))
        .unwrap_or(GarrisonLocale::En)
}

/// 环境变量检测链：`GARRISON_LANG` → `LC_ALL` → `LC_MESSAGES` → `LANG`。
///
/// 全链未命中（无变量、空值、`C`/`POSIX`、不支持的第三语言）返回 `None`，
/// 交由 [`detect_from`] 继续走 sys-locale / `En` 回退。
fn detect_from_env(getenv: &dyn Fn(&str) -> Option<String>) -> Option<GarrisonLocale> {
    const CHAIN: [&str; 4] = ["GARRISON_LANG", "LC_ALL", "LC_MESSAGES", "LANG"];
    CHAIN.iter().find_map(|key| {
        getenv(key)
            .filter(|raw| !raw.trim().is_empty())
            .and_then(|raw| normalize_lang(&raw))
    })
}

/// 归一化语言标签：去 `@modifier`/`.codeset`（`zh_CN.UTF-8` → `zh-CN`），`zh*`/`en*` 映射两枚举；`C`/`POSIX` 与第三语言返回 `None`，交由检测链继续回退。
fn normalize_lang(raw: &str) -> Option<GarrisonLocale> {
    let tag = raw
        .split('@')
        .next()
        .unwrap_or_default()
        .split('.')
        .next()
        .unwrap_or_default()
        .replace('_', "-");
    if matches!(tag.as_str(), "C" | "POSIX") {
        return None;
    }
    let lang = tag
        .split('-')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match lang.as_str() {
        "zh" => Some(GarrisonLocale::Zh),
        "en" => Some(GarrisonLocale::En),
        _ => None,
    }
}

// thread_local 栈式 scope（支持嵌套 set_locale 调用）

thread_local! {
    static CURRENT_LOCALE_STACK: RefCell<Vec<GarrisonLocale>> = const { RefCell::new(Vec::new()) };
}

/// 获取当前 locale（线程本地）：[`set_locale`] scope 内返回栈顶显式值，否则返回缓存的系统检测值（首次经 [`detect_locale`] 探测，失败回退 `En`）。
pub fn current_locale() -> GarrisonLocale {
    CURRENT_LOCALE_STACK.with(|stack| match stack.borrow().last() {
        Some(locale) => *locale,
        None => *DETECTED_LOCALE.get_or_init(detect_locale),
    })
}

/// 设置当前线程 locale 并返回 RAII guard（drop 自动 pop，支持嵌套）；显式值优先于 [`detect_locale`] 检测值，栈 pop 回空后回到缓存的检测值。
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

/// RAII guard（由 [`set_locale`] 返回，不应手动构造）：drop 时 pop locale 栈恢复上一个 locale。
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

// FluentBundle 单例缓存（OnceLock，首次访问加载 .ftl 资源）

static ZH_BUNDLE: OnceLock<FluentBundle<FluentResource>> = OnceLock::new();
static EN_BUNDLE: OnceLock<FluentBundle<FluentResource>> = OnceLock::new();

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
        .expect("Garrison .ftl 资源解析失败（编译期已固化，不应失败；若触发请报告 bug）");
    let lang_id = locale.as_lang_id();
    let mut bundle = FluentBundle::new_concurrent(vec![lang_id]);
    // 关闭 FSI/PDI 隔离标记（U+2068/U+2069），保持错误消息纯净
    bundle.set_use_isolating(false);
    bundle
        .add_resource(resource)
        .expect("Garrison .ftl 资源添加到 bundle 失败（资源键冲突不应发生；若触发请报告 bug）");
    bundle
}

// 错误翻译：依据当前 locale 查询 fluent bundle

/// 将 `GarrisonError` 翻译为当前 locale 的本地化字符串：按 `current_locale()` 选 bundle 查 message key 与 args；缺失 key 时回退硬编码英文（与 `locales/en.ftl` 模板一致）。
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
                    // 翻译失败回退到硬编码英文
                    fallback_display(err)
                }
            },
            None => fallback_display(err),
        },
        None => fallback_display(err),
    }
}

/// 按 key + args 翻译为当前 locale 的本地化字符串；不依赖 `GarrisonError`，供 `loc!` 宏与社交登录 / Keycloak 等模块按需翻译异常 detail。
/// 未找到 key 或格式化出错返回 `key` 本身（[`loc!`] 在此基础上应用调用方 fallback，空时保持 key）。
pub fn translate_detail(key: &str, args: &[(&str, &str)]) -> String {
    let locale = current_locale();
    let bundle = get_bundle(locale);
    match bundle.get_message(key) {
        Some(msg) => match msg.value() {
            Some(pattern) => {
                let mut errors = vec![];
                // args 为空时短路，避免无意义的 FluentArgs 分配
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

/// 解析结构化错误 detail `key::arg0::arg1`：拆出 FTL message key 与位置参数（键 `arg0`/`arg1`，因 Fluent 变量标识符不能以数字开头）；非结构化串返回 `None`，交由调用方回退 variant 默认 key。
fn parse_keyed_detail(s: &str) -> Option<(&'static str, Vec<(&'static str, String)>)> {
    // 仅当包含 `::` 分隔符才视为结构化 key，避免把普通中文/英文串误判为 key
    if !s.contains("::") {
        return None;
    }
    let mut parts = s.splitn(3, "::");
    let key = parts.next()?;
    // key 必须以字母开头且为合法 kebab-case（允许数字段：argon2 / l1 / jwt-ec-sec1 等；
    // 中文串与含空格/大写的普通句子仍不满足形态，不会被误判为 key）
    if key.is_empty() || !key.chars().next().unwrap().is_ascii_alphabetic() {
        return None;
    }
    if key
        .chars()
        .any(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
    {
        return None;
    }
    let static_key = intern_string(key);
    let a0 = parts.next();
    let a1 = parts.next();
    match (a0, a1) {
        (None, None) | (None, Some(_)) => Some((static_key, vec![])),
        (Some(x), None) => Some((static_key, vec![("arg0", x.to_string())])),
        (Some(x), Some(y)) => Some((
            static_key,
            vec![("arg0", x.to_string()), ("arg1", y.to_string())],
        )),
    }
}

/// 全局字符串缓存：相同 key 只 `Box::leak` 一次，后续复用已缓存的 `&'static str`。
fn intern_string(s: &str) -> &'static str {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: Mutex<Option<HashMap<String, &'static str>>> = Mutex::new(None);
    let mut guard = CACHE.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    if let Some(&cached) = map.get(s) {
        return cached;
    }
    let leaked: &'static str = Box::leak(s.to_string().into_boxed_str());
    map.insert(s.to_string(), leaked);
    leaked
}

/// 单个 `String` 错误字段 → (key, args)：优先结构化 `key::arg`，否则 variant 默认 key + `detail` 参数（兼容未迁移的硬编码中文串）。
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
        GarrisonError::InvalidResponse(s) => string_detail("invalid-response", s),
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
        GarrisonError::RateLimited { .. } => ("rate-limited", vec![]),
        #[cfg(feature = "email-verification")]
        GarrisonError::EmailRateLimitExceeded { window } => (
            "email-rate-limit-exceeded",
            vec![("window", window.clone())],
        ),
        #[cfg(feature = "email-verification")]
        GarrisonError::EmailVerifyMaxAttempts => ("email-verify-max-attempts", vec![]),
        #[cfg(feature = "email-verification")]
        GarrisonError::EmailCodeNotFound => ("email-code-not-found", vec![]),
        #[cfg(feature = "email-verification")]
        GarrisonError::EmailChannelRecycled => ("email-channel-recycled", vec![]),
        #[cfg(feature = "credit-metering")]
        GarrisonError::CreditInsufficient {
            tenant_id,
            requested,
            remaining,
        } => (
            "credit-insufficient",
            vec![
                ("tenant_id", tenant_id.to_string()),
                ("requested", requested.to_string()),
                ("remaining", remaining.to_string()),
            ],
        ),
        GarrisonError::Exception(ex) => (
            "exception",
            vec![
                ("code", ex.code.to_string()),
                ("detail", ex.message.clone()),
            ],
        ),
    }
}

/// 翻译失败时的硬编码英文回退（文案与 `locales/en.ftl` 英文模板一致）。
fn fallback_display(err: &GarrisonError) -> String {
    match err {
        GarrisonError::NotLogin(s) => format!("Not logged in: {}", s),
        GarrisonError::NotPermission(s) => format!("Permission denied: {}", s),
        GarrisonError::NotRole(s) => format!("Role denied: {}", s),
        GarrisonError::InvalidToken(s) => format!("Invalid token: {}", s),
        GarrisonError::TokenRevoked(s) => format!("Token revoked: {}", s),
        GarrisonError::ExpiredToken(s) => format!("Token expired: {}", s),
        GarrisonError::Dao(s) => format!("DAO error: {}", s),
        GarrisonError::Config(s) => format!("Configuration error: {}", s),
        GarrisonError::Internal(s) => format!("Internal error: {}", s),
        GarrisonError::Session(s) => format!("Session error: {}", s),
        GarrisonError::Annotation(s) => format!("Annotation error: {}", s),
        GarrisonError::Context(s) => format!("Context error: {}", s),
        GarrisonError::OAuth2(s) => format!("OAuth2 error: {}", s),
        GarrisonError::Network(s) => format!("Network error: {}", s),
        GarrisonError::InvalidResponse(s) => format!("Invalid upstream response: {}", s),
        GarrisonError::InvalidParam(s) => format!("Invalid parameter: {}", s),
        GarrisonError::NotImplemented(s) => format!("Not implemented: {}", s),
        GarrisonError::FirewallBlocked(s) => format!("Firewall blocked: {}", s),
        GarrisonError::DisableService { service, until } => {
            format!("Account disabled: service={}, until={:?}", service, until)
        },
        GarrisonError::NotSafe { reason } => {
            format!("Second factor authentication required: {}", reason)
        },
        GarrisonError::InvalidStateTransition { from, to } => {
            format!("Invalid state transition: {} -> {}", from, to)
        },
        GarrisonError::SmsRateLimitExceeded { window } => {
            format!("SMS rate limit exceeded: {} window", window)
        },
        GarrisonError::SmsVerifyMaxAttempts => "SMS verification max attempts exceeded".to_string(),
        GarrisonError::SmsCodeNotFound => "SMS verification code not found".to_string(),
        GarrisonError::SmsChannelRecycled => "SMS channel recycled".to_string(),
        GarrisonError::RateLimited { .. } => "Rate limited".to_string(),
        #[cfg(feature = "email-verification")]
        GarrisonError::EmailRateLimitExceeded { window } => {
            format!("Email rate limit exceeded: {} window", window)
        },
        #[cfg(feature = "email-verification")]
        GarrisonError::EmailVerifyMaxAttempts => {
            "Email verification max attempts exceeded".to_string()
        },
        #[cfg(feature = "email-verification")]
        GarrisonError::EmailCodeNotFound => "Email verification code not found".to_string(),
        #[cfg(feature = "email-verification")]
        GarrisonError::EmailChannelRecycled => "Email channel recycled".to_string(),
        #[cfg(feature = "credit-metering")]
        GarrisonError::CreditInsufficient {
            tenant_id,
            requested,
            remaining,
        } => {
            format!(
                "Credit insufficient: tenant={}, requested={}, remaining={}",
                tenant_id, requested, remaining
            )
        },
        GarrisonError::Exception(ex) => format!("Business exception[{}]: {}", ex.code, ex.message),
    }
}

// ICU4X 增强层（feature = "i18n-icu"）

/// ICU4X 增强模块（仅 `i18n-icu` feature 编译）：复数规则、日期/数字本地化，不影响现有翻译逻辑。
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

    /// 当前 locale 下 `count` 的复数类别（Cardinal），用于选择正确复数形式。
    pub fn plural_category(count: usize) -> PluralCategory {
        let rules =
            PluralRules::try_new(to_icu_locale(current_locale()).into(), Default::default())
                .expect("ICU PluralRules compiled_data 已编译，不应失败");
        rules.category_for(count)
    }

    /// 格式化 `chrono::DateTime` 为当前 locale 的本地化字符串（替代 `{:?}` Debug 格式，如 "2026年1月1日" / "Jan 1, 2026"）。
    pub fn format_datetime_locale(dt: &chrono::DateTime<chrono::Utc>) -> String {
        let icu_locale = to_icu_locale(current_locale());
        // YMDT fieldset：年月日+时间，medium 长度（如 "Jan 1, 2026, 12:00:00 AM"）
        let formatter = DateTimeFormatter::try_new(icu_locale.into(), fieldsets::YMDT::medium())
            .expect("ICU DateTimeFormatter compiled_data 已编译，不应失败");
        let date = icu_calendar::Date::try_new_iso(dt.year(), dt.month() as u8, dt.day() as u8)
            .expect("chrono 日期转 ICU Date 不应失败");
        let time =
            icu_time::Time::try_new(dt.hour() as u8, dt.minute() as u8, dt.second() as u8, 0)
                .expect("chrono 时间转 ICU Time 不应失败");
        // DateTime 是 #[allow(clippy::exhaustive_structs)] 的公开结构体，可直接构造
        let datetime = icu_datetime::input::DateTime { date, time };
        formatter.format(&datetime).to_string()
    }

    /// 格式化整数为当前 locale 的本地化字符串（千分位/数字系统，如 en "1,000,000" / ar "١٬٠٠٠٬٠٠٠"）。
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

    // GarrisonLocale 枚举测试

    /// 枚举默认值应为英文；`En` 同时是系统语言探测失败的最终回退。
    #[test]
    fn default_locale_is_en() {
        let locale = GarrisonLocale::default();
        assert_eq!(locale, GarrisonLocale::En);
    }

    #[test]
    fn as_lang_id_returns_correct_identifier() {
        assert_eq!(GarrisonLocale::Zh.as_lang_id().to_string(), "zh");
        assert_eq!(GarrisonLocale::En.as_lang_id().to_string(), "en");
    }

    // current_locale / set_locale 测试

    /// 仅断言 current_locale() 与 detect_locale() 同源（进程 env 因机器而异，映射细节由纯函数测试覆盖）。
    #[test]
    fn current_locale_defaults_to_detected_locale_when_not_set() {
        assert_eq!(current_locale(), detect_locale());
    }

    #[test]
    fn set_locale_changes_current_and_restores_on_drop() {
        let original = current_locale();
        {
            let _guard = set_locale(GarrisonLocale::En);
            assert_eq!(current_locale(), GarrisonLocale::En);
        }
        assert_eq!(current_locale(), original);
    }

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

    #[test]
    fn set_locale_overrides_detection_and_pop_restores_detected() {
        let detected = current_locale(); // 首次调用触发探测并缓存
        {
            let _guard = set_locale(GarrisonLocale::En);
            assert_eq!(current_locale(), GarrisonLocale::En);
        }
        assert_eq!(current_locale(), detected);
        {
            let _guard = set_locale(GarrisonLocale::Zh);
            assert_eq!(current_locale(), GarrisonLocale::Zh);
        }
        assert_eq!(current_locale(), detected);
    }

    // 系统语言检测链测试（env 注入纯函数，不依赖进程环境）

    /// 构造注入式 env 查找闭包（按值持有，无生命周期绑定）。
    fn env_of<const N: usize>(
        vars: [(&'static str, &'static str); N],
    ) -> impl Fn(&str) -> Option<String> {
        move |key| {
            vars.iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn detect_chain_zh_cn_utf8_yields_zh() {
        let getenv = env_of([("LANG", "zh_CN.UTF-8")]);
        assert_eq!(detect_from(&getenv, None), GarrisonLocale::Zh);
    }

    #[test]
    fn detect_chain_fr_fr_falls_back_to_en() {
        let getenv = env_of([("LANG", "fr_FR.UTF-8")]);
        assert_eq!(detect_from(&getenv, None), GarrisonLocale::En);
    }

    #[test]
    fn detect_chain_c_and_posix_fall_back_to_en() {
        let c = env_of([("LANG", "C")]);
        assert_eq!(detect_from(&c, None), GarrisonLocale::En);
        let posix = env_of([("LC_ALL", "POSIX")]);
        assert_eq!(detect_from(&posix, None), GarrisonLocale::En);
        let c_utf8 = env_of([("LANG", "C.UTF-8")]);
        assert_eq!(detect_from(&c_utf8, None), GarrisonLocale::En);
    }

    #[test]
    fn detect_chain_garrison_lang_takes_precedence() {
        let en_overrides_zh = env_of([("GARRISON_LANG", "en_US"), ("LC_ALL", "zh_CN.UTF-8")]);
        assert_eq!(detect_from(&en_overrides_zh, None), GarrisonLocale::En);
        let zh_overrides_en = env_of([("GARRISON_LANG", "zh_CN"), ("LC_ALL", "en_US.UTF-8")]);
        assert_eq!(detect_from(&zh_overrides_en, None), GarrisonLocale::Zh);
    }

    #[test]
    fn detect_chain_lc_all_precedes_lang() {
        let getenv = env_of([("LC_ALL", "zh_CN.UTF-8"), ("LANG", "en_US.UTF-8")]);
        assert_eq!(detect_from(&getenv, None), GarrisonLocale::Zh);
    }

    #[test]
    fn detect_chain_empty_value_skipped() {
        let getenv = env_of([("GARRISON_LANG", "  "), ("LANG", "zh_CN")]);
        assert_eq!(detect_from(&getenv, None), GarrisonLocale::Zh);
    }

    #[test]
    fn detect_chain_empty_falls_back_to_en() {
        let none: fn(&str) -> Option<String> = |_key| None;
        assert_eq!(detect_from(&none, None), GarrisonLocale::En);
    }

    #[test]
    fn detect_chain_sys_locale_fallback() {
        let none: fn(&str) -> Option<String> = |_key| None;
        assert_eq!(detect_from(&none, Some("zh-Hans-CN")), GarrisonLocale::Zh);
        assert_eq!(detect_from(&none, Some("en-US")), GarrisonLocale::En);
        assert_eq!(detect_from(&none, Some("fr-FR")), GarrisonLocale::En);
        // env 链命中时 sys-locale 不参与
        let getenv = env_of([("LANG", "en_US.UTF-8")]);
        assert_eq!(detect_from(&getenv, Some("zh-CN")), GarrisonLocale::En);
    }

    #[test]
    fn detect_chain_normalizes_variants() {
        let none: fn(&str) -> Option<String> = |_key| None;
        for raw in ["zh", "zh_TW", "zh-Hant", "ZH-CN", "zh_SG@pinyin"] {
            assert_eq!(
                detect_from(&none, Some(raw)),
                GarrisonLocale::Zh,
                "raw={raw}"
            );
        }
        for raw in ["en", "en_GB.UTF-8", "EN-us"] {
            assert_eq!(
                detect_from(&none, Some(raw)),
                GarrisonLocale::En,
                "raw={raw}"
            );
        }
    }

    // translate_error 测试

    #[test]
    fn translate_error_zh_returns_chinese_message() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::NotLogin("请先登录".to_string());
        let translated = translate_error(&err);
        assert_eq!(translated, "未登录: 请先登录");
    }

    #[test]
    fn translate_error_en_returns_english_message() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::NotLogin("please login first".to_string());
        let translated = translate_error(&err);
        assert_eq!(translated, "Not logged in: please login first");
    }

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

    #[test]
    fn translate_error_zh_exception_variant() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::Exception(Box::new(GarrisonException::new(-1, "请先登录")));
        assert_eq!(translate_error(&err), "业务异常[-1]: 请先登录");
    }

    #[test]
    fn translate_error_en_exception_variant() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::Exception(Box::new(GarrisonException::new(-1, "please login")));
        assert_eq!(
            translate_error(&err),
            "Business exception[-1]: please login"
        );
    }

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

    #[test]
    fn fallback_display_matches_hardcoded_english() {
        let err = GarrisonError::NotLogin("test".to_string());
        assert_eq!(fallback_display(&err), "Not logged in: test");
    }

    #[test]
    fn fallback_display_all_variants() {
        let cases: Vec<(GarrisonError, &str)> = vec![
            (GarrisonError::NotLogin("x".into()), "Not logged in: x"),
            (
                GarrisonError::NotPermission("x".into()),
                "Permission denied: x",
            ),
            (GarrisonError::NotRole("x".into()), "Role denied: x"),
            (GarrisonError::InvalidToken("x".into()), "Invalid token: x"),
            (GarrisonError::ExpiredToken("x".into()), "Token expired: x"),
            (GarrisonError::Dao("x".into()), "DAO error: x"),
            (GarrisonError::Config("x".into()), "Configuration error: x"),
            (GarrisonError::Internal("x".into()), "Internal error: x"),
            (GarrisonError::Session("x".into()), "Session error: x"),
            (GarrisonError::Annotation("x".into()), "Annotation error: x"),
            (GarrisonError::Context("x".into()), "Context error: x"),
            (GarrisonError::OAuth2("x".into()), "OAuth2 error: x"),
            (GarrisonError::Network("x".into()), "Network error: x"),
            (
                GarrisonError::InvalidParam("x".into()),
                "Invalid parameter: x",
            ),
            (
                GarrisonError::NotImplemented("x".into()),
                "Not implemented: x",
            ),
            (
                GarrisonError::Exception(Box::new(GarrisonException::new(-1, "msg"))),
                "Business exception[-1]: msg",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(fallback_display(&err), expected, "mismatch for {:?}", err);
        }
    }

    #[test]
    fn get_bundle_returns_cached_instance() {
        let b1 = get_bundle(GarrisonLocale::Zh);
        let b2 = get_bundle(GarrisonLocale::Zh);
        // 指针相等表示同一实例
        assert!(std::ptr::eq(b1, b2));
    }

    // translate_detail 测试（loc! 宏底层调用）

    #[test]
    fn translate_detail_zh_returns_translated_message() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = translate_detail("not-login", &[("detail", "请先登录")]);
        assert_eq!(msg, "未登录: 请先登录");
    }

    #[test]
    fn translate_detail_en_returns_translated_message() {
        let _guard = set_locale(GarrisonLocale::En);
        let msg = translate_detail("not-login", &[("detail", "please login")]);
        assert_eq!(msg, "Not logged in: please login");
    }

    #[test]
    fn translate_detail_missing_key_returns_key() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = translate_detail("nonexistent-key-xyz", &[]);
        assert_eq!(msg, "nonexistent-key-xyz");
    }

    // loc! 宏 fallback 语义测试

    #[test]
    fn loc_macro_uses_fallback_when_key_missing() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = loc!("nonexistent-key-xyz", "human readable fallback");
        assert_eq!(msg, "human readable fallback");
    }

    #[test]
    fn loc_macro_uses_string_fallback_when_key_missing() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = loc!("nonexistent-key-xyz", "owned fallback".to_string());
        assert_eq!(msg, "owned fallback");
    }

    #[test]
    fn loc_macro_empty_fallback_keeps_key() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = loc!("nonexistent-key-xyz", "");
        assert_eq!(msg, "nonexistent-key-xyz");
    }

    #[test]
    fn loc_macro_translated_key_ignores_fallback() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = loc!("sms-verify-max-attempts", "unused fallback");
        assert_eq!(msg, "SMS 验证码尝试次数超限");
    }

    #[test]
    fn translate_detail_no_args_translates_successfully() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = translate_detail("sms-verify-max-attempts", &[]);
        assert_eq!(msg, "SMS 验证码尝试次数超限");
    }

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

    #[test]
    fn translate_detail_multiple_args_en() {
        let _guard = set_locale(GarrisonLocale::En);
        let msg = translate_detail(
            "invalid-state-transition",
            &[("from", "Active"), ("to", "Closed")],
        );
        assert_eq!(msg, "Invalid state transition: Active -> Closed");
    }

    // translate_error 测试

    #[test]
    fn translate_error_zh_token_revoked() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::TokenRevoked("reuse detected".to_string());
        let translated = translate_error(&err);
        assert_eq!(translated, "Token 已吊销: reuse detected");
    }

    #[test]
    fn translate_error_en_token_revoked() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::TokenRevoked("reuse detected".to_string());
        let translated = translate_error(&err);
        assert_eq!(translated, "Token revoked: reuse detected");
    }

    #[test]
    fn translate_error_zh_firewall_blocked() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::FirewallBlocked("black_path: /admin".to_string());
        let translated = translate_error(&err);
        assert_eq!(translated, "防火墙拦截: black_path: /admin");
    }

    #[test]
    fn translate_error_en_firewall_blocked() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::FirewallBlocked("black_path: /admin".to_string());
        let translated = translate_error(&err);
        assert_eq!(translated, "Firewall blocked: black_path: /admin");
    }

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

    #[test]
    fn translate_error_zh_not_safe() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::NotSafe {
            reason: "MFA_TOTP_REQUIRED".to_string(),
        };
        assert_eq!(translate_error(&err), "未完成二次认证：MFA_TOTP_REQUIRED");
    }

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

    #[test]
    fn translate_error_zh_invalid_state_transition() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::InvalidStateTransition {
            from: "Active".to_string(),
            to: "Closed".to_string(),
        };
        assert_eq!(translate_error(&err), "非法状态转换：Active -> Closed");
    }

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

    #[test]
    fn translate_error_zh_sms_rate_limit_exceeded() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::SmsRateLimitExceeded {
            window: "hourly".to_string(),
        };
        assert_eq!(translate_error(&err), "SMS 限速超出: hourly 窗口");
    }

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

    #[test]
    fn translate_error_zh_sms_verify_max_attempts() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::SmsVerifyMaxAttempts;
        assert_eq!(translate_error(&err), "SMS 验证码尝试次数超限");
    }

    #[test]
    fn translate_error_en_sms_verify_max_attempts() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::SmsVerifyMaxAttempts;
        assert_eq!(
            translate_error(&err),
            "SMS verification max attempts exceeded"
        );
    }

    #[test]
    fn translate_error_zh_sms_code_not_found() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::SmsCodeNotFound;
        assert_eq!(translate_error(&err), "SMS 验证码不存在");
    }

    #[test]
    fn translate_error_en_sms_code_not_found() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::SmsCodeNotFound;
        assert_eq!(translate_error(&err), "SMS verification code not found");
    }

    #[test]
    fn translate_error_zh_sms_channel_recycled() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::SmsChannelRecycled;
        assert_eq!(translate_error(&err), "SMS 通道已回收");
    }

    #[test]
    fn translate_error_en_sms_channel_recycled() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::SmsChannelRecycled;
        assert_eq!(translate_error(&err), "SMS channel recycled");
    }

    // fallback_display 补充测试

    #[test]
    fn fallback_display_new_variants() {
        let until = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let cases: Vec<(GarrisonError, String)> = vec![
            (
                GarrisonError::TokenRevoked("x".into()),
                "Token revoked: x".to_string(),
            ),
            (
                GarrisonError::FirewallBlocked("x".into()),
                "Firewall blocked: x".to_string(),
            ),
            (
                GarrisonError::DisableService {
                    service: "default".into(),
                    until: Some(until),
                },
                format!("Account disabled: service=default, until={:?}", Some(until)),
            ),
            (
                GarrisonError::DisableService {
                    service: "oidc".into(),
                    until: None,
                },
                "Account disabled: service=oidc, until=None".to_string(),
            ),
            (
                GarrisonError::NotSafe { reason: "r".into() },
                "Second factor authentication required: r".to_string(),
            ),
            (
                GarrisonError::InvalidStateTransition {
                    from: "A".into(),
                    to: "B".into(),
                },
                "Invalid state transition: A -> B".to_string(),
            ),
            (
                GarrisonError::SmsRateLimitExceeded { window: "w".into() },
                "SMS rate limit exceeded: w window".to_string(),
            ),
            (
                GarrisonError::SmsVerifyMaxAttempts,
                "SMS verification max attempts exceeded".to_string(),
            ),
            (
                GarrisonError::SmsCodeNotFound,
                "SMS verification code not found".to_string(),
            ),
            (
                GarrisonError::SmsChannelRecycled,
                "SMS channel recycled".to_string(),
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(fallback_display(&err), expected, "mismatch for {:?}", err);
        }
    }

    #[test]
    fn error_to_key_args_all_variants() {
        let until = chrono::Utc::now();
        #[cfg_attr(
            not(any(feature = "email-verification", feature = "credit-metering")),
            allow(unused_mut)
        )]
        let mut cases: Vec<GarrisonError> = vec![
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
            GarrisonError::InvalidResponse("a".into()),
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
            GarrisonError::RateLimited {
                retry_after_secs: 30,
            },
            GarrisonError::Exception(Box::new(GarrisonException::new(-1, "msg"))),
        ];
        #[cfg(feature = "email-verification")]
        cases.extend([
            GarrisonError::EmailRateLimitExceeded { window: "w".into() },
            GarrisonError::EmailVerifyMaxAttempts,
            GarrisonError::EmailCodeNotFound,
            GarrisonError::EmailChannelRecycled,
        ]);
        #[cfg(feature = "credit-metering")]
        cases.push(GarrisonError::CreditInsufficient {
            tenant_id: 1,
            requested: 2,
            remaining: 3,
        });

        for err in cases {
            // 仅验证不 panic 且返回非空 key
            let (key, _args) = error_to_key_args(&err);
            assert!(!key.is_empty(), "key 不应为空: {:?}", err);
        }
    }

    /// 限流 / 邮箱 / Credit 变体的 FTL 键命中且参数透传（key 未被误用为展示文案）。
    #[test]
    #[cfg_attr(
        not(any(feature = "email-verification", feature = "credit-metering")),
        allow(unused_mut)
    )]
    fn error_to_key_args_feature_variants_hit_ftl_keys() {
        let _guard = set_locale(GarrisonLocale::En);
        let mut cases: Vec<(GarrisonError, &str)> = vec![(
            GarrisonError::RateLimited {
                retry_after_secs: 30,
            },
            "rate-limited",
        )];
        #[cfg(feature = "email-verification")]
        cases.extend([
            (
                GarrisonError::EmailRateLimitExceeded {
                    window: "hourly".into(),
                },
                "email-rate-limit-exceeded",
            ),
            (
                GarrisonError::EmailVerifyMaxAttempts,
                "email-verify-max-attempts",
            ),
            (GarrisonError::EmailCodeNotFound, "email-code-not-found"),
            (
                GarrisonError::EmailChannelRecycled,
                "email-channel-recycled",
            ),
        ]);
        #[cfg(feature = "credit-metering")]
        cases.push((
            GarrisonError::CreditInsufficient {
                tenant_id: 1,
                requested: 2,
                remaining: 3,
            },
            "credit-insufficient",
        ));

        for (err, expected_key) in &cases {
            let (key, _args) = error_to_key_args(err);
            assert_eq!(key, *expected_key, "FTL 键失配: {err:?}");
            let translated = translate_error(err);
            assert_ne!(
                translated, *expected_key,
                "应命中 FTL 翻译而非回退 key 本身: {err:?}"
            );
            assert!(!translated.is_empty());
        }
    }

    /// 限流 / 邮箱 / Credit 变体的硬编码英文回退文案（bundle 缺失时的最后防线）。
    #[test]
    fn fallback_display_rate_limited_and_feature_variants() {
        assert_eq!(
            fallback_display(&GarrisonError::RateLimited {
                retry_after_secs: 30
            }),
            "Rate limited"
        );
        #[cfg(feature = "email-verification")]
        {
            assert_eq!(
                fallback_display(&GarrisonError::EmailRateLimitExceeded {
                    window: "hourly".into()
                }),
                "Email rate limit exceeded: hourly window"
            );
            assert_eq!(
                fallback_display(&GarrisonError::EmailVerifyMaxAttempts),
                "Email verification max attempts exceeded"
            );
            assert_eq!(
                fallback_display(&GarrisonError::EmailCodeNotFound),
                "Email verification code not found"
            );
            assert_eq!(
                fallback_display(&GarrisonError::EmailChannelRecycled),
                "Email channel recycled"
            );
        }
        #[cfg(feature = "credit-metering")]
        assert_eq!(
            fallback_display(&GarrisonError::CreditInsufficient {
                tenant_id: 1,
                requested: 2,
                remaining: 3
            }),
            "Credit insufficient: tenant=1, requested=2, remaining=3"
        );
    }

    // InvalidResponse 变体 i18n 测试（上游响应解析失败专用错误类型）

    #[test]
    fn translate_error_zh_invalid_response() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::InvalidResponse("JSON 解析失败".to_string());
        assert_eq!(translate_error(&err), "上游响应无效: JSON 解析失败");
    }

    #[test]
    fn translate_error_en_invalid_response() {
        let _guard = set_locale(GarrisonLocale::En);
        let err = GarrisonError::InvalidResponse("missing access_token field".to_string());
        assert_eq!(
            translate_error(&err),
            "Invalid upstream response: missing access_token field"
        );
    }

    #[test]
    fn fallback_display_invalid_response() {
        let err = GarrisonError::InvalidResponse("parse error".into());
        assert_eq!(
            fallback_display(&err),
            "Invalid upstream response: parse error"
        );
    }

    #[test]
    fn get_bundle_en_returns_cached_instance() {
        let b1 = get_bundle(GarrisonLocale::En);
        let b2 = get_bundle(GarrisonLocale::En);
        assert!(std::ptr::eq(b1, b2), "英文 bundle 应为同一缓存实例");
    }

    // translate_detail 测试

    #[test]
    fn translate_detail_known_key_returns_translation() {
        let _guard = set_locale(GarrisonLocale::En);
        let result = translate_detail("not-login", &[("detail", "test")]);
        assert!(result.contains("test"), "应包含参数值: {}", result);
    }

    #[test]
    fn translate_detail_unknown_key_returns_key() {
        let _guard = set_locale(GarrisonLocale::En);
        let result = translate_detail("nonexistent-key-xyz", &[]);
        assert_eq!(result, "nonexistent-key-xyz");
    }

    #[test]
    fn translate_detail_known_key_no_args() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let result = translate_detail("sms-verify-max-attempts", &[]);
        assert!(!result.is_empty());
        assert_ne!(result, "sms-verify-max-attempts", "应返回翻译而非 key 本身");
    }

    // ICU4X 增强层测试（feature = "i18n-icu"）

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
    /// 含数字的键（argon2 / l1 / jwt-ec-sec1 等）必须可解析：解析器若拒绝数字，
    /// FTL 词条永不生效、用户只能看到原始 key（回归锚定 22 个不可达键的修复）。
    #[test]
    fn parse_keyed_detail_accepts_digit_keys() {
        let (key, args) = parse_keyed_detail("config-password-hash-argon2-param-invalid::t_cost")
            .expect("含数字键应被解析");
        assert_eq!(key, "config-password-hash-argon2-param-invalid");
        assert_eq!(args, [("arg0", "t_cost".to_string())]);
        assert!(
            parse_keyed_detail("cache-l1-init::").is_some(),
            "纯数字段也应可解析"
        );
    }

    /// 守卫本意不变：中文串与含空格/大写的普通句子不得被误判为 key。
    #[test]
    fn parse_keyed_detail_still_rejects_prose() {
        assert!(parse_keyed_detail("这是一句中文::包含分隔符").is_none());
        assert!(parse_keyed_detail("not a key::with spaces").is_none());
        assert!(parse_keyed_detail("MixedCase::value").is_none());
    }

    /// 端到端：含数字键经 translate_detail 渲染 FTL 文案而非回退原始 key。
    #[test]
    fn translate_detail_renders_digit_key_from_catalog() {
        let rendered = translate_detail(
            "config-password-hash-argon2-param-invalid",
            &[("arg0", "t_cost")],
        );
        assert!(rendered.contains("t_cost"), "应渲染参数: {rendered}");
        assert!(
            !rendered.contains("config-password-hash"),
            "不得回退原始 key: {rendered}"
        );
    }
}
