// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Set-Cookie 单一构建点。
//!
//! garrison 全部 Set-Cookie 写路径（三框架适配器、axum 续签中间件、CSRF 中间件）
//! 统一经 [`build_set_cookie_value`] 构建，写点不再自行拼接属性串。
//! 设计吸收 Keycloak `DefaultCookieProvider.set(CookieType, …)` 的类型化 Cookie
//! 与 Pocket-ID 的 `__Host-` / `__Secure-` 前缀命名，按纯函数自由构建器重设计：
//! 无框架依赖，可脱离 HTTP 单测。
//!
//! ## 构建点不变式（调用方无法绕过）
//!
//! 1. **HttpOnly 恒定**：[`CookieScope`] 三个变体均输出 HttpOnly。
//! 2. **SameSite 白名单 fail-fast**：非 `["Lax", "Strict", "None"]`（复用
//!    `crate::config::COOKIE_SAME_SITE_VALUES`，与启动期配置校验同一份常量）
//!    返回错误，不产出 Set-Cookie。
//! 3. **None→Lax 降级**：`SameSite=None` 仅在 Secure 上下文（`cookie_secure=true`，
//!    作为「非 Secure 上下文」的确定性信号）合法；非 Secure 上下文自动降级为
//!    `Lax` 并输出一次 warn——浏览器对不带 Secure 的 `SameSite=None` 会整体拒收。
//! 4. **production 前缀强制**：`production` feature + Secure 上下文时，
//!    Path=/ 且无 Domain 的 cookie 强制 `__Host-` 前缀，其余（限定路径或跨子域
//!    共享）强制 `__Secure-` 前缀；非 Secure 上下文（http 调试）不加前缀。
//!    读侧必须用 [`token_cookie_name`] / [`CookieType::resolved_name`] 解析同名，
//!    保证写读一致。
//! 5. **注入防护**：name/value 复用 `validate_cookie_name_value` 校验，
//!    拒绝 `;`、控制字符等分隔符；path 拒 `;` 与控制字符，domain 仅允许
//!    主机名字符（字母数字连字符点），非法值不产出任何 Set-Cookie。

use std::sync::Once;

use crate::config::GarrisonConfig;
use crate::context::validate_cookie_name_value;
use crate::error::{GarrisonError, GarrisonResult};

/// SameSite=None 非 Secure 降级的警示（每进程一次，防每请求日志刷屏）。
static NONE_DOWNGRADE_WARN: Once = Once::new();

/// Cookie 作用域：定死 SameSite × HttpOnly 的合法组合。
///
/// 作用域是封闭枚举而非自由字符串，所有组合强制 HttpOnly，
/// 调用方无法构造「无 HttpOnly 的会话 cookie」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieScope {
    /// `SameSite=Lax`（默认：顶级导航 GET 携带，跨站 POST 不携带）。
    LaxHttpOnly,
    /// `SameSite=Strict`（最严格：跨站请求完全不携带）。
    StrictHttpOnly,
    /// `SameSite=None`（跨站携带；仅 Secure 上下文合法，非 Secure 上下文构建时降级为 Lax）。
    NoneHttpOnly,
}

impl CookieScope {
    /// 从配置字符串解析作用域（match 主判，未知值 fail-fast）。
    ///
    /// 合法值与启动期配置校验白名单 `crate::config::COOKIE_SAME_SITE_VALUES`
    /// 一一对应（由 `same_site_whitelist_matches_scope_variants` 跨引用测试锁定，
    /// 防白名单与 match 分支双源漂移）；非法值（含大小写不符、空白尾随）返回
    /// [`GarrisonError::Context`]。
    pub fn from_same_site(same_site: &str) -> GarrisonResult<Self> {
        match same_site {
            "Lax" => Ok(Self::LaxHttpOnly),
            "Strict" => Ok(Self::StrictHttpOnly),
            "None" => Ok(Self::NoneHttpOnly),
            other => Err(GarrisonError::Context(format!(
                "ctx-invalid-cookie-same-site::{other}"
            ))),
        }
    }

    /// 该作用域在给定 Secure 上下文下应输出的 `SameSite` 属性值。
    fn same_site_attr(&self, secure: bool) -> &'static str {
        match self {
            Self::LaxHttpOnly => "Lax",
            Self::StrictHttpOnly => "Strict",
            Self::NoneHttpOnly if secure => "None",
            Self::NoneHttpOnly => {
                NONE_DOWNGRADE_WARN.call_once(|| {
                    tracing::warn!(
                        "cookie SameSite=None requires a Secure context (cookie_secure=false); \
                         downgraded to SameSite=Lax"
                    );
                });
                "Lax"
            },
        }
    }
}

/// Cookie 路径作用域。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookiePath {
    /// `Path=/`（默认，全站可用）。
    Root,
    /// 限定路径作用域（预留）：为短时 token 将 cookie 携带范围收窄到
    /// 该路径及其子路径、缩小暴露面而设。当前无生产写点，供下游写点预留。
    Of(String),
}

impl CookiePath {
    /// 输出到 Set-Cookie 的 `Path` 属性值。
    pub fn as_str(&self) -> &str {
        match self {
            Self::Root => "/",
            Self::Of(p) => p,
        }
    }
}

/// Set-Cookie 构建参数（单一构建点的输入）。
///
/// garrison 的 cookie 名来自配置（`token_name` / CSRF `cookie_name`）而非硬编码
/// 枚举，故本类型为可构造 pub struct + 便捷构造器：`CookieType::token(config)`
/// 承接会话 token cookie，其余写点按字段直接构造。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieType {
    /// Cookie 基础名（不含 `__Host-` / `__Secure-` 前缀；前缀在构建时按 Secure
    /// 上下文解析，见 [`CookieType::resolved_name`]）。
    pub name: String,
    /// SameSite × HttpOnly 作用域。
    pub scope: CookieScope,
    /// 路径作用域。
    pub path: CookiePath,
    /// `Domain` 属性（`None` = 不设置，cookie 仅对当前 host 生效）。
    pub domain: Option<String>,
    /// `Max-Age` 秒数（`None` = 会话 cookie，不输出 Max-Age；负值构建点拒绝，
    /// `Some(0)` 合法 = 立即过期）。
    pub max_age: Option<i64>,
}

impl CookieType {
    /// 会话 token cookie：名称取 `config.token_name`，SameSite 取
    /// `config.cookie_same_site`（白名单 fail-fast），Path=/，无 Domain、无 Max-Age。
    pub fn token(config: &GarrisonConfig) -> GarrisonResult<Self> {
        Self::session(config.token_name.clone(), config)
    }

    /// 指定名称的会话 cookie：SameSite 取 `config.cookie_same_site`（白名单
    /// fail-fast），Path=/。供 cookie 名不取自 `token_name` 的写点复用。
    pub fn session(name: impl Into<String>, config: &GarrisonConfig) -> GarrisonResult<Self> {
        Ok(Self {
            name: name.into(),
            scope: CookieScope::from_same_site(&config.cookie_same_site)?,
            path: CookiePath::Root,
            domain: None,
            max_age: None,
        })
    }

    /// 解析后的 cookie 名（production + Secure 上下文含 `__Host-` / `__Secure-`
    /// 前缀）。读侧（Cookie 请求头查找）必须用本方法解析，保证写读同名。
    pub fn resolved_name(&self, secure: bool) -> String {
        resolve_cookie_name(&self.name, secure, &self.path, self.domain.as_deref())
    }
}

/// 解析带安全前缀的 cookie 名（吸收 Pocket-ID `__Host-` / `__Secure-` 前缀命名）。
///
/// - `production` feature + Secure 上下文：`Path=/` 且无 Domain → `__Host-<name>`
///   （host-locked，浏览器禁止其携带 Domain 与非 / Path，攻击面最小）；
///   其余 → `__Secure-<name>`。
/// - 非 Secure 上下文（http 降级）或非 production 构建：原样返回。
fn resolve_cookie_name(
    name: &str,
    secure: bool,
    path: &CookiePath,
    domain: Option<&str>,
) -> String {
    #[cfg(feature = "production")]
    {
        if secure {
            if matches!(path, CookiePath::Root) && domain.is_none() {
                return format!("__Host-{}", name);
            }
            return format!("__Secure-{}", name);
        }
    }
    #[cfg(not(feature = "production"))]
    {
        let _ = (secure, path, domain);
    }
    name.to_string()
}

/// 会话 token cookie 的解析名（读侧统一入口）。
///
/// 写侧（适配器 / 续签中间件）经构建点产出的名字与本函数一致——
/// production + Secure 上下文下两侧同为 `__Host-<token_name>`。
pub fn token_cookie_name(config: &GarrisonConfig) -> String {
    resolve_cookie_name(
        &config.token_name,
        config.cookie_secure,
        &CookiePath::Root,
        None,
    )
}

/// 校验 `Domain` 属性值：仅允许主机名字符（ASCII 字母数字、连字符、点），
/// 拒绝空格、`;`、控制字符与非 ASCII——含属性分隔符的值可注入 `SameSite` 等
/// 附加属性（如 `evil.com; SameSite=None`）。
fn validate_cookie_domain(domain: &str, cookie_name: &str) -> GarrisonResult<()> {
    let domain_ok = !domain.is_empty()
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    if !domain_ok {
        return Err(GarrisonError::Context(format!(
            "ctx-invalid-cookie-domain::{cookie_name}"
        )));
    }
    Ok(())
}

/// 校验 `Path` 属性值：拒绝 `;` 与控制字符——`;` 会截断 Path 并注入后续属性。
fn validate_cookie_path(path: &str, cookie_name: &str) -> GarrisonResult<()> {
    let path_ok = path.bytes().all(|b| b != b';' && (0x20..0x7f).contains(&b));
    if !path_ok {
        return Err(GarrisonError::Context(format!(
            "ctx-invalid-cookie-path::{cookie_name}"
        )));
    }
    Ok(())
}

/// 构建 Set-Cookie 值（单一构建点）。
///
/// 属性输出顺序统一：
/// `name=value; HttpOnly; [Secure; ]SameSite=<ss>; Path=<p>[; Domain=<d>][; Max-Age=<n>]`。
///
/// # 参数
///
/// - `cookie`: 构建参数（名称 / 作用域 / 路径 / Domain / Max-Age）。
/// - `value`: cookie 值（空串合法，用于清除 cookie）。
/// - `secure`: Secure 上下文标志（取 `config.cookie_secure`；同时决定
///   production 前缀与 SameSite=None→Lax 降级）。
///
/// # 错误
///
/// - name/value 含注入字符（复用 `validate_cookie_name_value`）；
/// - `CookiePath::Of` 为空串，或 path / domain 含注入字符
///   （path 拒 `;` 与控制字符，domain 仅允许主机名字符）；
/// - `max_age` 为负值——负 `Max-Age` 是浏览器「删除 cookie」语义，写点误用会
///   静默清 cookie（`Some(0)` 合法，立即过期）。
///
/// 错误时调用方不得产出任何 Set-Cookie 头（fail-fast）。
pub fn build_set_cookie_value(
    cookie: &CookieType,
    value: &str,
    secure: bool,
) -> GarrisonResult<String> {
    validate_cookie_name_value(&cookie.name, value)?;
    let path = cookie.path.as_str();
    if path.is_empty() {
        return Err(GarrisonError::Context(format!(
            "ctx-invalid-cookie-path::{}",
            cookie.name
        )));
    }
    validate_cookie_path(path, &cookie.name)?;
    let domain = cookie.domain.as_deref().filter(|d| !d.is_empty());
    if let Some(d) = domain {
        validate_cookie_domain(d, &cookie.name)?;
    }
    if cookie.max_age.is_some_and(|max_age| max_age < 0) {
        return Err(GarrisonError::Context(format!(
            "ctx-invalid-cookie-max-age::{}",
            cookie.name
        )));
    }
    let name = resolve_cookie_name(&cookie.name, secure, &cookie.path, domain);
    let mut out = format!("{}={}; HttpOnly", name, value);
    if secure {
        out.push_str("; Secure");
    }
    out.push_str("; SameSite=");
    out.push_str(cookie.scope.same_site_attr(secure));
    out.push_str("; Path=");
    out.push_str(path);
    if let Some(d) = domain {
        out.push_str("; Domain=");
        out.push_str(d);
    }
    if let Some(max_age) = cookie.max_age {
        out.push_str("; Max-Age=");
        out.push_str(&max_age.to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 按字段快速构造 CookieType 的测试辅助。
    fn cookie_type(scope: CookieScope) -> CookieType {
        CookieType {
            name: "garrison_token".to_string(),
            scope,
            path: CookiePath::Root,
            domain: None,
            max_age: None,
        }
    }

    // ========================================================================
    // CookieScope：None→Lax 降级不变式
    // ========================================================================

    /// NoneHttpOnly + 非 Secure 上下文：降级为 SameSite=Lax，不输出 SameSite=None
    /// 与 Secure（http 降级），且 HttpOnly 恒定。
    #[test]
    fn none_scope_insecure_downgrades_to_lax() {
        let value =
            build_set_cookie_value(&cookie_type(CookieScope::NoneHttpOnly), "tok", false).unwrap();
        assert!(
            value.contains("SameSite=Lax"),
            "应降级为 Lax，实际: {}",
            value
        );
        assert!(
            !value.contains("SameSite=None"),
            "非 Secure 上下文不得输出 SameSite=None，实际: {}",
            value
        );
        assert!(
            !value.contains("Secure"),
            "非 Secure 上下文不得输出 Secure，实际: {}",
            value
        );
        assert!(value.contains("HttpOnly"));
    }

    /// NoneHttpOnly + Secure 上下文：同时输出 SameSite=None 与 Secure。
    #[test]
    fn none_scope_secure_emits_none_with_secure() {
        let value =
            build_set_cookie_value(&cookie_type(CookieScope::NoneHttpOnly), "tok", true).unwrap();
        assert!(value.contains("SameSite=None"));
        assert!(value.contains("Secure"));
    }

    /// 三个作用域变体均输出 HttpOnly（HttpOnly 恒定不变式）。
    #[test]
    fn all_scopes_emit_httponly() {
        for scope in [
            CookieScope::LaxHttpOnly,
            CookieScope::StrictHttpOnly,
            CookieScope::NoneHttpOnly,
        ] {
            let value = build_set_cookie_value(&cookie_type(scope.clone()), "tok", true).unwrap();
            assert!(
                value.contains("HttpOnly"),
                "scope {:?} 应输出 HttpOnly，实际: {}",
                scope,
                value
            );
        }
    }

    // ========================================================================
    // production 前缀（cfg 拆分：production 门禁 / 非 production 回归锁）
    // ========================================================================

    #[cfg(feature = "production")]
    mod production_prefix {
        use super::*;

        /// Secure 上下文 + Path=/ + 无 Domain → `__Host-` 前缀。
        #[test]
        fn host_prefix_when_secure_root_no_domain() {
            let value = build_set_cookie_value(&cookie_type(CookieScope::LaxHttpOnly), "tok", true)
                .unwrap();
            assert!(
                value.starts_with("__Host-garrison_token="),
                "实际: {}",
                value
            );
        }

        /// Secure 上下文 + 限定路径 → `__Secure-` 前缀。
        #[test]
        fn secure_prefix_when_path_scoped() {
            let cookie = CookieType {
                path: CookiePath::Of("/api/device-login/exchange".to_string()),
                ..cookie_type(CookieScope::LaxHttpOnly)
            };
            let value = build_set_cookie_value(&cookie, "tok", true).unwrap();
            assert!(
                value.starts_with("__Secure-garrison_token="),
                "实际: {}",
                value
            );
        }

        /// Secure 上下文 + 有 Domain → `__Secure-` 前缀。
        #[test]
        fn secure_prefix_when_domain_present() {
            let cookie = CookieType {
                domain: Some("example.com".to_string()),
                ..cookie_type(CookieScope::LaxHttpOnly)
            };
            let value = build_set_cookie_value(&cookie, "tok", true).unwrap();
            assert!(
                value.starts_with("__Secure-garrison_token="),
                "实际: {}",
                value
            );
        }

        /// 非 Secure 上下文（http 降级）→ 无前缀。
        #[test]
        fn no_prefix_when_insecure() {
            for (path, domain) in [
                (CookiePath::Root, None),
                (
                    CookiePath::Of("/api/x".to_string()),
                    Some("example.com".to_string()),
                ),
            ] {
                let cookie = CookieType {
                    path,
                    domain,
                    ..cookie_type(CookieScope::LaxHttpOnly)
                };
                let value = build_set_cookie_value(&cookie, "tok", false).unwrap();
                assert!(
                    value.starts_with("garrison_token="),
                    "http 降级无前缀，实际: {}",
                    value
                );
            }
        }

        /// `__Host-` 不变式：输出含 `__Host-` 时必含 `Path=/` 与 `Secure`、必不含 `Domain=`。
        #[test]
        fn host_prefix_invariants() {
            for scope in [
                CookieScope::LaxHttpOnly,
                CookieScope::StrictHttpOnly,
                CookieScope::NoneHttpOnly,
            ] {
                let value = build_set_cookie_value(&cookie_type(scope), "tok", true).unwrap();
                assert!(
                    value.contains("__Host-"),
                    "Secure 上下文 + Root + 无 Domain 应带 __Host- 前缀，实际: {}",
                    value
                );
                assert!(value.contains("Path=/"), "实际: {}", value);
                assert!(value.contains("Secure"), "实际: {}", value);
                assert!(!value.contains("Domain="), "实际: {}", value);
            }
        }

        /// `token_cookie_name` 与构建点产出同名（写读 roundtrip）。
        #[test]
        fn token_cookie_name_matches_written_name() {
            let config = GarrisonConfig::default_config();
            let cookie = CookieType::token(&config).unwrap();
            let value = build_set_cookie_value(&cookie, "tok", config.cookie_secure).unwrap();
            assert!(
                value.starts_with(&format!("{}=", token_cookie_name(&config))),
                "写读名字应一致，实际: {}",
                value
            );
        }
    }

    #[cfg(not(feature = "production"))]
    mod non_production_regression {
        use super::*;

        /// 非 production 构建：任何组合均无前缀（字节级回归锁）。
        #[test]
        fn no_prefix_in_any_combination() {
            for (secure, path, domain) in [
                (true, CookiePath::Root, None),
                (true, CookiePath::Of("/api/x".to_string()), None),
                (true, CookiePath::Root, Some("example.com".to_string())),
                (false, CookiePath::Root, None),
            ] {
                let cookie = CookieType {
                    path,
                    domain,
                    ..cookie_type(CookieScope::LaxHttpOnly)
                };
                let value = build_set_cookie_value(&cookie, "tok", secure).unwrap();
                assert!(
                    value.starts_with("garrison_token="),
                    "非 production 构建不应有前缀，实际: {}",
                    value
                );
                assert!(!value.contains("__Host-"));
                assert!(!value.contains("__Secure-"));
            }
        }

        /// 非 production 构建：`token_cookie_name` 与构建点产出同名（写读 roundtrip）。
        #[test]
        fn token_cookie_name_matches_written_name() {
            let config = GarrisonConfig::default_config();
            let cookie = CookieType::token(&config).unwrap();
            let value = build_set_cookie_value(&cookie, "tok", config.cookie_secure).unwrap();
            assert!(
                value.starts_with(&format!("{}=", token_cookie_name(&config))),
                "写读名字应一致，实际: {}",
                value
            );
        }
    }

    // ========================================================================
    // SameSite 白名单 fail-fast
    // ========================================================================

    /// 非法 same_site（小写 / 空串 / 空白尾随）构造即报错，不产出 Set-Cookie。
    #[test]
    fn token_constructor_rejects_invalid_same_site() {
        for same_site in ["lax", "", "None ", "none", "LAX", "Strict;"] {
            let mut config = GarrisonConfig::default_config();
            config.cookie_same_site = same_site.to_string();
            let result =
                CookieType::token(&config).and_then(|c| build_set_cookie_value(&c, "tok", true));
            assert!(
                matches!(result, Err(GarrisonError::Context(_))),
                "same_site={:?} 应 fail-fast，实际: {:?}",
                same_site,
                result.map(|_| ())
            );
        }
    }

    /// 白名单跨引用：COOKIE_SAME_SITE_VALUES 每个合法值经 from_same_site 命中对应
    /// 变体，且作用域属性输出与输入一致（不落兜底）。机制性锁：若未来白名单加值
    /// 而 match 未加对应臂，未知值走 Err（match 主判）→ 本测试必红。
    #[test]
    fn same_site_whitelist_matches_scope_variants() {
        for value in crate::config::COOKIE_SAME_SITE_VALUES {
            let scope = CookieScope::from_same_site(value)
                .unwrap_or_else(|e| panic!("白名单值 {:?} 应被 from_same_site 接受: {}", value, e));
            assert_eq!(
                scope.same_site_attr(true),
                *value,
                "白名单值 {:?} 应与作用域属性输出一一对应（不得落兜底）",
                value
            );
        }
    }

    /// 合法 same_site 经映射产出对应属性（白名单复用 COOKIE_SAME_SITE_VALUES）。
    #[test]
    fn token_constructor_accepts_valid_same_site() {
        for (same_site, attr) in [
            ("Lax", "SameSite=Lax"),
            ("Strict", "SameSite=Strict"),
            ("None", "SameSite=None"),
        ] {
            let mut config = GarrisonConfig::default_config();
            config.cookie_same_site = same_site.to_string();
            let cookie = CookieType::token(&config).unwrap();
            let value = build_set_cookie_value(&cookie, "tok", true).unwrap();
            assert!(
                value.contains(attr),
                "same_site={} 应输出 {}，实际: {}",
                same_site,
                attr,
                value
            );
        }
    }

    // ========================================================================
    // 输入防护与属性段
    // ========================================================================

    /// value 含注入字符（`;` / 控制字符 / 空格 / 逗号）时报错，不产出 Set-Cookie。
    #[test]
    fn rejects_injected_value() {
        for bad in [
            "abc; Domain=evil.com",
            "bad\nvalue",
            "a b",
            "a,b",
            "a\\b",
            "a\"b",
        ] {
            let result = build_set_cookie_value(&cookie_type(CookieScope::LaxHttpOnly), bad, true);
            assert!(
                matches!(result, Err(GarrisonError::Context(_))),
                "value={:?} 应被拒绝，实际: {:?}",
                bad,
                result.map(|_| ())
            );
        }
    }

    /// domain 含注入字符（`;` / 空格 / 控制字符 / 非 ASCII）时拒绝，不产出 Set-Cookie。
    #[test]
    fn rejects_injected_domain() {
        for bad in [
            "evil.com; SameSite=None",
            "evil.com Domain=x",
            "bad\nexample.com",
            "evil\u{7f}.com",
            "例子.com",
        ] {
            let cookie = CookieType {
                domain: Some(bad.to_string()),
                ..cookie_type(CookieScope::LaxHttpOnly)
            };
            let result = build_set_cookie_value(&cookie, "tok", true);
            assert!(
                matches!(result, Err(GarrisonError::Context(_))),
                "domain={:?} 应被拒绝，实际: {:?}",
                bad,
                result.map(|_| ())
            );
        }
    }

    /// path 含 `;` / 控制字符时拒绝，不产出 Set-Cookie。
    #[test]
    fn rejects_injected_path() {
        for bad in ["/a;b", "/a\nb", "/api\u{7f}x"] {
            let cookie = CookieType {
                path: CookiePath::Of(bad.to_string()),
                ..cookie_type(CookieScope::LaxHttpOnly)
            };
            let result = build_set_cookie_value(&cookie, "tok", true);
            assert!(
                matches!(result, Err(GarrisonError::Context(_))),
                "path={:?} 应被拒绝，实际: {:?}",
                bad,
                result.map(|_| ())
            );
        }
    }

    /// 合法 domain（字母数字连字符点）放行并输出 Domain 属性。
    #[test]
    fn accepts_valid_domain() {
        for domain in ["example.com", "api.example.com", "sub-domain.example.com"] {
            let cookie = CookieType {
                domain: Some(domain.to_string()),
                ..cookie_type(CookieScope::LaxHttpOnly)
            };
            let value = build_set_cookie_value(&cookie, "tok", true).unwrap();
            assert!(
                value.contains(&format!("Domain={}", domain)),
                "domain={} 应放行，实际: {}",
                domain,
                value
            );
        }
    }

    /// max_age=Some(600) 输出 `Max-Age=600`；None 不输出 Max-Age。
    #[test]
    fn max_age_emitted_only_when_present() {
        let with = CookieType {
            max_age: Some(600),
            ..cookie_type(CookieScope::LaxHttpOnly)
        };
        let value = build_set_cookie_value(&with, "tok", true).unwrap();
        assert!(value.contains("Max-Age=600"), "实际: {}", value);

        let without = cookie_type(CookieScope::LaxHttpOnly);
        let value = build_set_cookie_value(&without, "tok", true).unwrap();
        assert!(!value.contains("Max-Age"), "实际: {}", value);
    }

    /// max_age 为负值时构建点拒绝（负 Max-Age 是浏览器「删除 cookie」语义，
    /// 写点误用会静默清 cookie），不产出 Set-Cookie；Some(0) 合法（立即过期），
    /// 放行并输出 Max-Age=0。
    #[test]
    fn rejects_negative_max_age_allows_zero() {
        let negative = CookieType {
            max_age: Some(-1),
            ..cookie_type(CookieScope::LaxHttpOnly)
        };
        let result = build_set_cookie_value(&negative, "tok", true);
        assert!(
            matches!(result, Err(GarrisonError::Context(_))),
            "max_age=-1 应被拒绝，实际: {:?}",
            result.map(|_| ())
        );

        let zero = CookieType {
            max_age: Some(0),
            ..cookie_type(CookieScope::LaxHttpOnly)
        };
        let value = build_set_cookie_value(&zero, "tok", true).unwrap();
        assert!(value.contains("Max-Age=0"), "实际: {}", value);
    }

    /// CookiePath::Of 输出指定 Path；Root 输出 Path=/；空路径报错。
    #[test]
    fn path_scope_emitted() {
        let scoped = CookieType {
            path: CookiePath::Of("/api/device-login/exchange".to_string()),
            ..cookie_type(CookieScope::LaxHttpOnly)
        };
        let value = build_set_cookie_value(&scoped, "tok", true).unwrap();
        assert!(
            value.contains("Path=/api/device-login/exchange"),
            "实际: {}",
            value
        );

        let root = cookie_type(CookieScope::LaxHttpOnly);
        let value = build_set_cookie_value(&root, "tok", true).unwrap();
        assert!(value.contains("Path=/"), "实际: {}", value);

        let empty = CookieType {
            path: CookiePath::Of(String::new()),
            ..cookie_type(CookieScope::LaxHttpOnly)
        };
        assert!(build_set_cookie_value(&empty, "tok", true).is_err());
    }

    /// domain=Some 输出 `Domain=`；空串 Domain 被忽略。
    #[test]
    fn domain_emitted_only_when_present() {
        let with = CookieType {
            domain: Some("example.com".to_string()),
            ..cookie_type(CookieScope::LaxHttpOnly)
        };
        let value = build_set_cookie_value(&with, "tok", true).unwrap();
        assert!(value.contains("Domain=example.com"), "实际: {}", value);

        let empty = CookieType {
            domain: Some(String::new()),
            ..cookie_type(CookieScope::LaxHttpOnly)
        };
        let value = build_set_cookie_value(&empty, "tok", true).unwrap();
        assert!(!value.contains("Domain="), "实际: {}", value);
    }
}
