//! 密码策略规则实现（v0.6.0 新增，依据 spec password-policy R-005/R-006）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 提供 12 条可插拔密码策略规则（v0.6.0 一次性交付）。
//! T008 实现 6 条核心规则（R-005），T009 实现 6 条扩展规则（R-006）。
//!
//! # 核心规则（R-005）
//!
//! | 规则 | `name()` | 说明 |
//! |:---|:---|:---|
//! | `LengthRule` | `"length"` | 长度规则（min/max，含边界） |
//! | `ComplexityRule` | `"complexity"` | 复杂度规则（大写/小写/数字/特殊字符各需 N 个） |
//! | `HistoryRule` | `"history"` | 密码历史规则（最近 N 条 hash 比对） |
//! | `BlacklistRule` | `"blacklist"` | 黑名单规则（精确匹配） |
//! | `NotUsernameRule` | `"not_username"` | 用户名相似规则（大小写不敏感子串） |
//! | `NotCommonPasswordRule` | `"not_common_password"` | 常见密码规则（精确匹配） |

use super::{PasswordPolicyRule, PolicyContext, PolicyError};
use crate::account::credential::password::PasswordVerifier;

// ============================================================================
// LengthRule（依据 spec R-005.1）
// ============================================================================

/// 长度规则（依据 spec password-policy R-005.1）。
///
/// 校验密码长度在 `[min, max]` 范围内（含边界）。
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::policy::rules::LengthRule;
/// use bulwark::account::policy::{PasswordPolicyRule, PolicyContext};
///
/// let rule = LengthRule::new(8, 128);
/// let ctx = PolicyContext { /* ... */ };
/// assert!(rule.validate(&ctx, "password").is_ok());  // 8 字符，边界通过
/// assert!(rule.validate(&ctx, "short").is_err());    // 5 字符，过短
/// ```
pub struct LengthRule {
    /// 最小长度（含）。
    min: u32,
    /// 最大长度（含）。
    max: u32,
}

impl LengthRule {
    /// 创建长度规则。
    ///
    /// # 参数
    /// - `min`: 最小长度（含）
    /// - `max`: 最大长度（含）
    pub fn new(min: u32, max: u32) -> Self {
        Self { min, max }
    }
}

impl PasswordPolicyRule for LengthRule {
    fn name(&self) -> &'static str {
        "length"
    }

    fn validate(&self, _ctx: &PolicyContext, password: &str) -> Result<(), PolicyError> {
        let len = password.len() as u32;
        if len < self.min {
            return Err(PolicyError::new(
                "length",
                format!("密码长度 {} 小于最小要求 {}", len, self.min),
            ));
        }
        if len > self.max {
            return Err(PolicyError::new(
                "length",
                format!("密码长度 {} 超过最大限制 {}", len, self.max),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// ComplexityRule（依据 spec R-005.2）
// ============================================================================

/// 复杂度规则（依据 spec password-policy R-005.2）。
///
/// 校验密码中大写字母、小写字母、数字、特殊字符各需至少 N 个。
///
/// # 特殊字符定义
///
/// 非 ASCII 字母数字字符（即 `char::is_alphanumeric()` 为 false 的字符，
/// 如 `!@#$%^&*` 等）。
pub struct ComplexityRule {
    /// 大写字母最少数量。
    upper: u32,
    /// 小写字母最少数量。
    lower: u32,
    /// 数字最少数量。
    digit: u32,
    /// 特殊字符最少数量。
    special: u32,
}

impl ComplexityRule {
    /// 创建复杂度规则。
    ///
    /// # 参数
    /// - `upper`: 大写字母最少数量
    /// - `lower`: 小写字母最少数量
    /// - `digit`: 数字最少数量
    /// - `special`: 特殊字符最少数量
    pub fn new(upper: u32, lower: u32, digit: u32, special: u32) -> Self {
        Self {
            upper,
            lower,
            digit,
            special,
        }
    }
}

impl PasswordPolicyRule for ComplexityRule {
    fn name(&self) -> &'static str {
        "complexity"
    }

    fn validate(&self, _ctx: &PolicyContext, password: &str) -> Result<(), PolicyError> {
        let mut upper_count = 0u32;
        let mut lower_count = 0u32;
        let mut digit_count = 0u32;
        let mut special_count = 0u32;

        for c in password.chars() {
            if c.is_uppercase() {
                upper_count += 1;
            } else if c.is_lowercase() {
                lower_count += 1;
            } else if c.is_ascii_digit() {
                digit_count += 1;
            } else {
                special_count += 1;
            }
        }

        if upper_count < self.upper {
            return Err(PolicyError::new(
                "complexity",
                format!("大写字母 {} 个，少于要求的 {} 个", upper_count, self.upper),
            ));
        }
        if lower_count < self.lower {
            return Err(PolicyError::new(
                "complexity",
                format!("小写字母 {} 个，少于要求的 {} 个", lower_count, self.lower),
            ));
        }
        if digit_count < self.digit {
            return Err(PolicyError::new(
                "complexity",
                format!("数字 {} 个，少于要求的 {} 个", digit_count, self.digit),
            ));
        }
        if special_count < self.special {
            return Err(PolicyError::new(
                "complexity",
                format!(
                    "特殊字符 {} 个，少于要求的 {} 个",
                    special_count, self.special
                ),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// HistoryRule（依据 spec R-005.3）
// ============================================================================

/// 密码历史规则（依据 spec password-policy R-005.3）。
///
/// 校验密码不允许与 `ctx.password_history` 最近 `count` 条 hash 相同。
/// 使用 `PasswordVerifier` 自动识别 hash 格式（Argon2/Bcrypt）进行校验。
///
/// # hash 比对
///
/// `password_history` 存储 hash（非明文），规则使用 `PasswordVerifier::verify`
/// 逐一校验明文密码与历史 hash 是否匹配。无效格式的 hash 会被跳过
/// （不阻塞密码修改，避免历史数据损坏影响正常使用）。
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::policy::rules::HistoryRule;
/// use bulwark::account::policy::{PasswordPolicyRule, PolicyContext};
///
/// let rule = HistoryRule::new(5);
/// let ctx = PolicyContext { password_history: vec!["$argon2id$...".into()], /* ... */ };
/// assert!(rule.validate(&ctx, "new-password").is_ok());
/// ```
pub struct HistoryRule {
    /// 比对的历史 hash 数量（从 `password_history` 末尾取最近 `count` 条）。
    count: u32,
}

impl HistoryRule {
    /// 创建密码历史规则。
    ///
    /// # 参数
    /// - `count`: 比对的历史 hash 数量（从 `password_history` 末尾取最近 `count` 条）
    pub fn new(count: u32) -> Self {
        Self { count }
    }
}

impl PasswordPolicyRule for HistoryRule {
    fn name(&self) -> &'static str {
        "history"
    }

    fn validate(&self, ctx: &PolicyContext, password: &str) -> Result<(), PolicyError> {
        if ctx.password_history.is_empty() || self.count == 0 {
            return Ok(());
        }
        // 取最近 count 条 hash（从末尾向前取）
        let start = ctx
            .password_history
            .len()
            .saturating_sub(self.count as usize);
        for hash in &ctx.password_history[start..] {
            // PasswordVerifier::verify 返回 BulwarkResult<bool>:
            // - Ok(true): 密码匹配历史 hash → 规则失败
            // - Ok(false): 不匹配 → 继续检查下一条
            // - Err(_): hash 格式无效 → 跳过（不阻塞密码修改）
            if let Ok(true) = PasswordVerifier::verify(password, hash) {
                return Err(PolicyError::new("history", "密码与历史密码重复"));
            }
        }
        Ok(())
    }
}

// ============================================================================
// BlacklistRule（依据 spec R-005.4）
// ============================================================================

/// 黑名单规则（依据 spec password-policy R-005.4）。
///
/// 校验密码不在黑名单列表中（精确匹配，非子串匹配）。
pub struct BlacklistRule {
    /// 黑名单密码列表。
    passwords: Vec<String>,
}

impl BlacklistRule {
    /// 创建黑名单规则。
    ///
    /// # 参数
    /// - `passwords`: 黑名单密码列表（精确匹配）
    pub fn new(passwords: Vec<String>) -> Self {
        Self { passwords }
    }
}

impl PasswordPolicyRule for BlacklistRule {
    fn name(&self) -> &'static str {
        "blacklist"
    }

    fn validate(&self, _ctx: &PolicyContext, password: &str) -> Result<(), PolicyError> {
        if self.passwords.iter().any(|p| p == password) {
            return Err(PolicyError::new("blacklist", "密码在黑名单中"));
        }
        Ok(())
    }
}

// ============================================================================
// NotUsernameRule（依据 spec R-005.5）
// ============================================================================

/// 用户名相似规则（依据 spec password-policy R-005.5）。
///
/// 校验密码不包含 `ctx.username`（大小写不敏感子串检测）。
/// `ctx.username` 为 `None` 或空字符串时规则通过。
pub struct NotUsernameRule;

impl NotUsernameRule {
    /// 创建用户名相似规则。
    pub fn new() -> Self {
        Self
    }
}

impl Default for NotUsernameRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordPolicyRule for NotUsernameRule {
    fn name(&self) -> &'static str {
        "not_username"
    }

    fn validate(&self, ctx: &PolicyContext, password: &str) -> Result<(), PolicyError> {
        let Some(username) = &ctx.username else {
            return Ok(());
        };
        if username.is_empty() {
            return Ok(());
        }
        // 大小写不敏感子串检测
        let password_lower = password.to_lowercase();
        let username_lower = username.to_lowercase();
        if password_lower.contains(&username_lower) {
            return Err(PolicyError::new("not_username", "密码包含用户名"));
        }
        Ok(())
    }
}

// ============================================================================
// NotCommonPasswordRule（依据 spec R-005.6）
// ============================================================================

/// 常见密码规则（依据 spec password-policy R-005.6）。
///
/// 校验密码不在常见密码列表中（精确匹配，非子串匹配）。
/// `common_list` 通常为 top 10000 常见密码列表。
pub struct NotCommonPasswordRule {
    /// 常见密码列表。
    common_list: Vec<String>,
}

impl NotCommonPasswordRule {
    /// 创建常见密码规则。
    ///
    /// # 参数
    /// - `common_list`: 常见密码列表（精确匹配）
    pub fn new(common_list: Vec<String>) -> Self {
        Self { common_list }
    }
}

impl PasswordPolicyRule for NotCommonPasswordRule {
    fn name(&self) -> &'static str {
        "not_common_password"
    }

    fn validate(&self, _ctx: &PolicyContext, password: &str) -> Result<(), PolicyError> {
        if self.common_list.iter().any(|p| p == password) {
            return Err(PolicyError::new("not_common_password", "密码为常见密码"));
        }
        Ok(())
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::credential::password::Argon2Hasher;
    use crate::account::credential::password::PasswordHasher;

    /// 辅助函数：构造测试用 PolicyContext。
    fn make_ctx(username: Option<&str>, history: Vec<&str>) -> PolicyContext {
        PolicyContext {
            user_id: "test-user".to_string(),
            tenant_id: None,
            username: username.map(|s| s.to_string()),
            email: None,
            password_history: history.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    // ========================================================================
    // LengthRule 测试
    // ========================================================================

    /// R-005.1: 长度在范围内 → 通过。
    #[test]
    fn length_rule_passes_within_range() {
        let rule = LengthRule::new(8, 128);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "password").is_ok());
    }

    /// R-005.1: 长度小于 min → 失败。
    #[test]
    fn length_rule_fails_too_short() {
        let rule = LengthRule::new(8, 128);
        let ctx = make_ctx(None, vec![]);
        let result = rule.validate(&ctx, "short");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.rule_name, "length");
    }

    /// R-005.1: 长度大于 max → 失败。
    #[test]
    fn length_rule_fails_too_long() {
        let rule = LengthRule::new(8, 10);
        let ctx = make_ctx(None, vec![]);
        let result = rule.validate(&ctx, "this_is_too_long");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().rule_name, "length");
    }

    /// R-005.1: 边界值 == min 和 == max → 通过。
    #[test]
    fn length_rule_boundary_min_and_max_pass() {
        let rule = LengthRule::new(4, 8);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "abcd").is_ok(), "== min 应通过");
        assert!(rule.validate(&ctx, "abcdefgh").is_ok(), "== max 应通过");
    }

    /// R-005.1: `name()` 返回 `"length"`。
    #[test]
    fn length_rule_name_returns_length() {
        let rule = LengthRule::new(8, 128);
        assert_eq!(rule.name(), "length");
    }

    // ========================================================================
    // ComplexityRule 测试
    // ========================================================================

    /// R-005.2: 4 类字符均满足 → 通过。
    #[test]
    fn complexity_rule_passes_all_met() {
        let rule = ComplexityRule::new(1, 1, 1, 1);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "Aa1!").is_ok());
    }

    /// R-005.2: 缺少大写字母 → 失败。
    #[test]
    fn complexity_rule_fails_missing_upper() {
        let rule = ComplexityRule::new(1, 1, 1, 1);
        let ctx = make_ctx(None, vec![]);
        let result = rule.validate(&ctx, "aa1!");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().rule_name, "complexity");
    }

    /// R-005.2: 缺少数字 → 失败。
    #[test]
    fn complexity_rule_fails_missing_digit() {
        let rule = ComplexityRule::new(1, 1, 1, 1);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "Aa!b").is_err());
    }

    /// R-005.2: 每类字符恰好达到要求 → 通过（边界）。
    #[test]
    fn complexity_rule_boundary_exact_counts() {
        let rule = ComplexityRule::new(2, 2, 2, 2);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "AAaa11!!").is_ok());
    }

    /// R-005.2: `name()` 返回 `"complexity"`。
    #[test]
    fn complexity_rule_name_returns_complexity() {
        let rule = ComplexityRule::new(1, 1, 1, 1);
        assert_eq!(rule.name(), "complexity");
    }

    // ========================================================================
    // HistoryRule 测试
    // ========================================================================

    /// R-005.3: 密码不匹配任何历史 hash → 通过。
    #[test]
    fn history_rule_passes_no_match() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("old-password").unwrap();
        let rule = HistoryRule::new(3);
        let ctx = make_ctx(None, vec![&hash]);
        assert!(rule.validate(&ctx, "new-password").is_ok());
    }

    /// R-005.3: 密码匹配最近的历史 hash → 失败。
    #[test]
    fn history_rule_fails_matches_recent() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("same-password").unwrap();
        let rule = HistoryRule::new(3);
        let ctx = make_ctx(None, vec![&hash]);
        let result = rule.validate(&ctx, "same-password");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().rule_name, "history");
    }

    /// R-005.3: 空历史 → 通过。
    #[test]
    fn history_rule_passes_empty_history() {
        let rule = HistoryRule::new(3);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "any").is_ok());
    }

    /// R-005.3: 历史条目少于 count → 检查全部历史。
    #[test]
    fn history_rule_passes_history_shorter_than_count() {
        let hasher = Argon2Hasher::default();
        let h1 = hasher.hash("pw1").unwrap();
        let rule = HistoryRule::new(5);
        let ctx = make_ctx(None, vec![&h1]);
        assert!(rule.validate(&ctx, "pw2").is_ok());
    }

    /// R-005.3: count=1 时仅检查最近 1 条 hash。
    #[test]
    fn history_rule_only_checks_recent_count() {
        let hasher = Argon2Hasher::default();
        let h1 = hasher.hash("very-old").unwrap();
        let h2 = hasher.hash("recent").unwrap();
        let rule = HistoryRule::new(1);
        let ctx = make_ctx(None, vec![&h1, &h2]);
        // count=1 → 仅检查 h2（最近一条）
        assert!(
            rule.validate(&ctx, "very-old").is_ok(),
            "very-old 不在最近 1 条中，应通过"
        );
        assert!(
            rule.validate(&ctx, "recent").is_err(),
            "recent 在最近 1 条中，应失败"
        );
    }

    /// R-005.3: count=0 → 永远通过。
    #[test]
    fn history_rule_count_zero_always_passes() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("same").unwrap();
        let rule = HistoryRule::new(0);
        let ctx = make_ctx(None, vec![&hash]);
        assert!(rule.validate(&ctx, "same").is_ok());
    }

    /// R-005.3: `name()` 返回 `"history"`。
    #[test]
    fn history_rule_name_returns_history() {
        let rule = HistoryRule::new(3);
        assert_eq!(rule.name(), "history");
    }

    // ========================================================================
    // BlacklistRule 测试
    // ========================================================================

    /// R-005.4: 密码不在黑名单 → 通过。
    #[test]
    fn blacklist_rule_passes_not_in_list() {
        let rule = BlacklistRule::new(vec!["password".into(), "123456".into()]);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "secure-pw").is_ok());
    }

    /// R-005.4: 密码在黑名单 → 失败。
    #[test]
    fn blacklist_rule_fails_in_list() {
        let rule = BlacklistRule::new(vec!["password".into(), "123456".into()]);
        let ctx = make_ctx(None, vec![]);
        let result = rule.validate(&ctx, "password");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().rule_name, "blacklist");
    }

    /// R-005.4: 空黑名单 → 永远通过。
    #[test]
    fn blacklist_rule_passes_empty_list() {
        let rule = BlacklistRule::new(vec![]);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "anything").is_ok());
    }

    /// R-005.4: 精确匹配（非子串匹配）。
    #[test]
    fn blacklist_rule_exact_match_not_substring() {
        let rule = BlacklistRule::new(vec!["pass".into()]);
        let ctx = make_ctx(None, vec![]);
        // "pass" 在黑名单中，但 "password" 含 "pass" 子串 → 精确匹配不命中，应通过
        assert!(rule.validate(&ctx, "password").is_ok());
    }

    /// R-005.4: `name()` 返回 `"blacklist"`。
    #[test]
    fn blacklist_rule_name_returns_blacklist() {
        let rule = BlacklistRule::new(vec![]);
        assert_eq!(rule.name(), "blacklist");
    }

    // ========================================================================
    // NotUsernameRule 测试
    // ========================================================================

    /// R-005.5: ctx.username 为 None → 通过。
    #[test]
    fn not_username_rule_passes_no_username() {
        let rule = NotUsernameRule::new();
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "anything").is_ok());
    }

    /// R-005.5: 密码不包含用户名 → 通过。
    #[test]
    fn not_username_rule_passes_does_not_contain() {
        let rule = NotUsernameRule::new();
        let ctx = make_ctx(Some("alice"), vec![]);
        assert!(rule.validate(&ctx, "secure-pw").is_ok());
    }

    /// R-005.5: 密码包含用户名 → 失败。
    #[test]
    fn not_username_rule_fails_contains_username() {
        let rule = NotUsernameRule::new();
        let ctx = make_ctx(Some("alice"), vec![]);
        let result = rule.validate(&ctx, "alice123");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().rule_name, "not_username");
    }

    /// R-005.5: 大小写不敏感检测。
    #[test]
    fn not_username_rule_case_insensitive() {
        let rule = NotUsernameRule::new();
        let ctx = make_ctx(Some("Alice"), vec![]);
        assert!(
            rule.validate(&ctx, "ALICE123").is_err(),
            "大写密码包含小写用户名应失败"
        );
        assert!(
            rule.validate(&ctx, "alice123").is_err(),
            "小写密码包含大写用户名应失败"
        );
    }

    /// R-005.5: `name()` 返回 `"not_username"`。
    #[test]
    fn not_username_rule_name_returns_not_username() {
        let rule = NotUsernameRule::new();
        assert_eq!(rule.name(), "not_username");
    }

    // ========================================================================
    // NotCommonPasswordRule 测试
    // ========================================================================

    /// R-005.6: 密码不在常见密码列表 → 通过。
    #[test]
    fn not_common_password_rule_passes_not_in_list() {
        let rule = NotCommonPasswordRule::new(vec!["123456".into(), "password".into()]);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "secure-pw").is_ok());
    }

    /// R-005.6: 密码在常见密码列表 → 失败。
    #[test]
    fn not_common_password_rule_fails_in_list() {
        let rule = NotCommonPasswordRule::new(vec!["123456".into(), "password".into()]);
        let ctx = make_ctx(None, vec![]);
        let result = rule.validate(&ctx, "123456");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().rule_name, "not_common_password");
    }

    /// R-005.6: 空常见密码列表 → 永远通过。
    #[test]
    fn not_common_password_rule_passes_empty_list() {
        let rule = NotCommonPasswordRule::new(vec![]);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "anything").is_ok());
    }

    /// R-005.6: 精确匹配（非子串匹配）。
    #[test]
    fn not_common_password_rule_exact_match_not_substring() {
        let rule = NotCommonPasswordRule::new(vec!["pass".into()]);
        let ctx = make_ctx(None, vec![]);
        // "pass" 在常见列表中，但 "password" 含 "pass" 子串 → 精确匹配不命中，应通过
        assert!(rule.validate(&ctx, "password").is_ok());
    }

    /// R-005.6: `name()` 返回 `"not_common_password"`。
    #[test]
    fn not_common_password_rule_name_returns_not_common_password() {
        let rule = NotCommonPasswordRule::new(vec![]);
        assert_eq!(rule.name(), "not_common_password");
    }

    // ========================================================================
    // 规则可作 Box<dyn PasswordPolicyRule> 使用（对象安全验证）
    // ========================================================================

    /// R-005: 6 个核心规则均可作 `Box<dyn PasswordPolicyRule>` 使用。
    #[test]
    fn all_rules_usable_as_dyn_trait_object() {
        let rules: Vec<Box<dyn PasswordPolicyRule>> = vec![
            Box::new(LengthRule::new(8, 128)),
            Box::new(ComplexityRule::new(1, 1, 1, 1)),
            Box::new(HistoryRule::new(3)),
            Box::new(BlacklistRule::new(vec![])),
            Box::new(NotUsernameRule::new()),
            Box::new(NotCommonPasswordRule::new(vec![])),
        ];
        assert_eq!(rules.len(), 6);
        assert_eq!(rules[0].name(), "length");
        assert_eq!(rules[1].name(), "complexity");
        assert_eq!(rules[2].name(), "history");
        assert_eq!(rules[3].name(), "blacklist");
        assert_eq!(rules[4].name(), "not_username");
        assert_eq!(rules[5].name(), "not_common_password");
    }
}
