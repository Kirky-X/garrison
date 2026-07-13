//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 密码策略规则实现。
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
//!
//! # 扩展规则（R-006）
//!
//! | 规则 | `name()` | 说明 |
//! |:---|:---|:---|
//! | `MaxAgeRule` | `"max_age"` | 密码过期规则（v0.6.0 stub，v0.6.5 启用） |
//! | `DictionaryRule` | `"dictionary"` | 字典规则（精确匹配） |
//! | `NotRepeatCharRule` | `"not_repeat_char"` | 重复字符规则（连续 N+1 个相同字符） |
//! | `NotSequenceRule` | `"not_sequence"` | 序列规则（正向/反向连续序列） |
//! | `NotEmailRule` | `"not_email"` | 邮箱规则（大小写不敏感子串检测邮箱前缀） |
//! | `RegexRule` | `"regex"` | 自定义正则规则（匹配即报错） |

use super::{PasswordPolicyRule, PolicyContext, PolicyError};
use crate::account::credential::PasswordVerifier;

// ============================================================================
// LengthRule
// ============================================================================

/// 长度规则。
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
// ComplexityRule
// ============================================================================

/// 复杂度规则。
///
/// 校验密码中大写字母、小写字母、数字、特殊字符各需至少 N 个。
///
/// # 特殊字符定义
///
/// 非 ASCII 字母数字字符（即 `char::is_alphanumeric()` 为 false 的字符，
/// 如 `!@#$%^&*` 等）。
///
/// # 已弃用
///
/// NIST SP 800-63B §5.1.1.2 不推荐强制复杂度规则（用户倾向使用可预测的
/// 替换模式如 `P@ssw0rd`）。请使用 [`NistComplianceRule`] 替代。
#[deprecated(note = "NIST SP 800-63B 不推荐强制复杂度，使用 NistComplianceRule")]
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

#[allow(deprecated)]
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

#[allow(deprecated)]
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
// HistoryRule
// ============================================================================

/// 密码历史规则。
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
// BlacklistRule
// ============================================================================

/// 黑名单规则。
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
// NotUsernameRule
// ============================================================================

/// 用户名相似规则。
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
// NotCommonPasswordRule
// ============================================================================

/// 常见密码规则。
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
// MaxAgeRule
// ============================================================================

/// 密码过期规则。
///
/// 校验密码是否超过 `days` 天未修改。
///
/// # v0.6.0 stub 实现
///
/// `PolicyContext` 当前不含密码创建时间字段（`password_created_at`），
/// 无法校验密码过期。v0.6.0 提供 **安全 no-op stub**（始终返回 `Ok(())`），
/// 不阻塞密码修改。v0.6.5 将扩展 `PolicyContext` 后实现完整逻辑。
///
/// # 安全性
///
/// stub 不触发 `todo!()`/`unimplemented!()` panic，可安全调用。
pub struct MaxAgeRule;

impl MaxAgeRule {
    /// 创建密码过期规则。
    ///
    /// # 参数
    /// - `days`: 密码最大有效天数（v0.6.5 启用校验，当前 stub 不存储）
    pub fn new(_days: u32) -> Self {
        Self
    }
}

impl PasswordPolicyRule for MaxAgeRule {
    fn name(&self) -> &'static str {
        "max_age"
    }

    fn validate(&self, _ctx: &PolicyContext, _password: &str) -> Result<(), PolicyError> {
        // v0.6.0 stub: PolicyContext 不含 password_created_at 字段，
        // 无法校验密码是否超过 self.days 天未修改。
        // v0.6.5 将扩展 PolicyContext 后实现完整逻辑。
        // 当前为安全 no-op（始终通过），不阻塞密码修改。
        Ok(())
    }
}

// ============================================================================
// DictionaryRule
// ============================================================================

/// 字典规则。
///
/// 校验密码不在字典单词列表中（精确匹配，非子串匹配）。
/// 与 `BlacklistRule` 语义不同：`DictionaryRule` 面向字典攻击防护
/// （加载系统词典/常见单词列表），`BlacklistRule` 面向已知泄露密码。
pub struct DictionaryRule {
    /// 字典单词列表。
    dictionary: Vec<String>,
}

impl DictionaryRule {
    /// 创建字典规则。
    ///
    /// # 参数
    /// - `dictionary`: 字典单词列表（精确匹配）
    pub fn new(dictionary: Vec<String>) -> Self {
        Self { dictionary }
    }
}

impl PasswordPolicyRule for DictionaryRule {
    fn name(&self) -> &'static str {
        "dictionary"
    }

    fn validate(&self, _ctx: &PolicyContext, password: &str) -> Result<(), PolicyError> {
        if self.dictionary.iter().any(|w| w == password) {
            return Err(PolicyError::new("dictionary", "密码为字典单词"));
        }
        Ok(())
    }
}

// ============================================================================
// NotRepeatCharRule
// ============================================================================

/// 重复字符规则。
///
/// 校验密码不含连续 `max_consecutive + 1` 个相同字符。
///
/// # 示例
///
/// - `max_consecutive = 2`：`"aa"` 通过（2 个，≤ 2），`"aaa"` 失败（3 = 2+1）
/// - `max_consecutive = 1`：`"a"` 通过，`"aa"` 失败（2 = 1+1）
///
/// # 已弃用
///
/// NIST SP 800-63B 不推荐此类字符模式校验规则。请使用 [`NistComplianceRule`] 替代。
#[deprecated(note = "NIST SP 800-63B 不推荐强制复杂度，使用 NistComplianceRule")]
pub struct NotRepeatCharRule {
    /// 允许的最大连续相同字符数（超过此数即触发错误）。
    max_consecutive: u32,
}

#[allow(deprecated)]
impl NotRepeatCharRule {
    /// 创建重复字符规则。
    ///
    /// # 参数
    /// - `max_consecutive`: 允许的最大连续相同字符数（`max_consecutive + 1` 个触发错误）
    pub fn new(max_consecutive: u32) -> Self {
        Self { max_consecutive }
    }
}

#[allow(deprecated)]
impl PasswordPolicyRule for NotRepeatCharRule {
    fn name(&self) -> &'static str {
        "not_repeat_char"
    }

    fn validate(&self, _ctx: &PolicyContext, password: &str) -> Result<(), PolicyError> {
        let chars: Vec<char> = password.chars().collect();
        if chars.len() <= 1 {
            return Ok(());
        }
        let max_allowed = self.max_consecutive as usize;
        let mut current_run = 1usize;
        for i in 1..chars.len() {
            if chars[i] == chars[i - 1] {
                current_run += 1;
                if current_run > max_allowed {
                    return Err(PolicyError::new(
                        "not_repeat_char",
                        format!(
                            "密码包含 {} 个连续相同字符 '{}'，超过最大允许 {}",
                            current_run, chars[i], max_allowed
                        ),
                    ));
                }
            } else {
                current_run = 1;
            }
        }
        Ok(())
    }
}

// ============================================================================
// NotSequenceRule
// ============================================================================

/// 序列规则。
///
/// 校验密码不含长度 `> max_sequence` 的连续序列（正向/反向）。
///
/// # 序列定义
///
/// 连续序列指 ASCII 码值依次 +1（正向，如 `abc`/`123`）或 -1（反向，
/// 如 `cba`/`321`/`zyx`）的字符序列。序列长度为字符数（非步数）。
///
/// # 示例
///
/// - `max_sequence = 3`：`"abc"` 通过（长度 3，不 > 3），`"abcd"` 失败（长度 4 > 3）
/// - `max_sequence = 2`：`"ab"` 通过，`"abc"` 失败，`"321"` 失败（反向长度 3 > 2）
///
/// # 已弃用
///
/// NIST SP 800-63B 不推荐此类字符模式校验规则。请使用 [`NistComplianceRule`] 替代。
#[deprecated(note = "NIST SP 800-63B 不推荐强制复杂度，使用 NistComplianceRule")]
pub struct NotSequenceRule {
    /// 允许的最大连续序列长度（超过此长度即触发错误）。
    max_sequence: u32,
}

#[allow(deprecated)]
impl NotSequenceRule {
    /// 创建序列规则。
    ///
    /// # 参数
    /// - `max_sequence`: 允许的最大连续序列长度（长度 `> max_sequence` 触发错误）
    pub fn new(max_sequence: u32) -> Self {
        Self { max_sequence }
    }
}

#[allow(deprecated)]
impl PasswordPolicyRule for NotSequenceRule {
    fn name(&self) -> &'static str {
        "not_sequence"
    }

    fn validate(&self, _ctx: &PolicyContext, password: &str) -> Result<(), PolicyError> {
        let chars: Vec<char> = password.chars().collect();
        if chars.len() <= 1 {
            return Ok(());
        }
        let max_seq = self.max_sequence as usize;
        let mut max_found = 1usize;
        let mut current_len = 1usize;
        // direction: 1 = 正向（+1），-1 = 反向（-1），0 = 无序列
        let mut direction = 0i32;

        for i in 1..chars.len() {
            let diff = chars[i] as i32 - chars[i - 1] as i32;
            let new_direction = if diff == 1 {
                1
            } else if diff == -1 {
                -1
            } else {
                0
            };

            if new_direction != 0 && new_direction == direction {
                // 继续当前序列
                current_len += 1;
            } else if new_direction != 0 {
                // 方向改变或新序列开始（含前一个字符作为序列起点）
                current_len = 2;
                direction = new_direction;
            } else {
                // 序列中断
                current_len = 1;
                direction = 0;
            }

            if current_len > max_found {
                max_found = current_len;
            }
        }

        if max_found > max_seq {
            return Err(PolicyError::new(
                "not_sequence",
                format!(
                    "密码包含长度 {} 的连续序列，超过最大允许 {}",
                    max_found, max_seq
                ),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// NotEmailRule
// ============================================================================

/// 邮箱规则。
///
/// 校验密码不包含 `ctx.email` 的 `@` 前部分（大小写不敏感子串检测）。
/// `ctx.email` 为 `None`、无 `@` 或 `@` 前部分为空时规则通过。
pub struct NotEmailRule;

impl NotEmailRule {
    /// 创建邮箱规则。
    pub fn new() -> Self {
        Self
    }
}

impl Default for NotEmailRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordPolicyRule for NotEmailRule {
    fn name(&self) -> &'static str {
        "not_email"
    }

    fn validate(&self, ctx: &PolicyContext, password: &str) -> Result<(), PolicyError> {
        let Some(email) = &ctx.email else {
            return Ok(());
        };
        // 提取 @ 前部分
        let local_part = match email.split_once('@') {
            Some((local, _)) => local,
            None => return Ok(()), // 无 @ → 无法提取，通过
        };
        if local_part.is_empty() {
            return Ok(());
        }
        // 大小写不敏感子串检测
        let password_lower = password.to_lowercase();
        let local_lower = local_part.to_lowercase();
        if password_lower.contains(&local_lower) {
            return Err(PolicyError::new("not_email", "密码包含邮箱前缀"));
        }
        Ok(())
    }
}

// ============================================================================
// RegexRule
// ============================================================================

/// 自定义正则规则。
///
/// 校验密码是否匹配 `pattern`（语义：`pattern.is_match(password)` 为 `true` 时报错，
/// 错误信息使用 `error_msg`）。
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::policy::rules::RegexRule;
/// use bulwark::account::policy::{PasswordPolicyRule, PolicyContext};
///
/// // 禁止包含空格的密码
/// let rule = RegexRule::new(regex::Regex::new(r"\s").unwrap(), "密码不能包含空格".into());
/// let ctx = PolicyContext { /* ... */ };
/// assert!(rule.validate(&ctx, "no spaces").is_err());
/// assert!(rule.validate(&ctx, "no_spaces").is_ok());
/// ```
pub struct RegexRule {
    /// 正则表达式（匹配即报错）。
    pattern: regex::Regex,
    /// 错误信息（匹配时返回）。
    error_msg: String,
}

impl RegexRule {
    /// 创建自定义正则规则。
    ///
    /// # 参数
    /// - `pattern`: 正则表达式（`is_match` 为 `true` 时报错）
    /// - `error_msg`: 匹配时返回的错误信息
    pub fn new(pattern: regex::Regex, error_msg: String) -> Self {
        Self { pattern, error_msg }
    }
}

impl PasswordPolicyRule for RegexRule {
    fn name(&self) -> &'static str {
        "regex"
    }

    fn validate(&self, _ctx: &PolicyContext, password: &str) -> Result<(), PolicyError> {
        if self.pattern.is_match(password) {
            return Err(PolicyError::new("regex", self.error_msg.clone()));
        }
        Ok(())
    }
}

// ============================================================================
// NistComplianceRule（T013 — NIST SP 800-63B 密码策略合规）
// ============================================================================

/// NIST SP 800-63B 密码策略合规规则。
///
/// 基于 NIST SP 800-63B §5.1.1.2 推荐实践：
/// - **仅校验最小长度**（默认 ≥ 8 字符），不强制复杂度
/// - **不强制大写/小写/数字/特殊字符混合**（NIST 不推荐此类规则）
/// - **HIBP（Have I Been Pwned）检查为 stub**，始终返回 `Ok(())`，推迟到 v0.9.0
///
/// # 设计
///
/// NIST SP 800-63B 明确指出强制复杂度规则（混合大小写、数字、特殊字符）反而
/// 降低密码安全性（用户倾向使用可预测的替换模式如 `P@ssw0rd`）。推荐做法是：
/// 1. 仅校验最小长度（8 字符以上，鼓励长密码）
/// 2. 检查密码是否在已知泄露密码库中（HIBP）
/// 3. 不强制复杂度规则
///
/// # HIBP stub
///
/// `check_hibp` 方法为 v0.7.0 stub，始终返回 `Ok(())`。
/// v0.9.0 将实现真实 HIBP API 调用（通过 range search k-anonymity 协议）。
///
/// # 替代关系
///
/// `NistComplianceRule` 替代 [`ComplexityRule`]（已 `#[deprecated]`）。
/// 不需要替代 [`LengthRule`]（NIST 规则内部就是长度校验）。
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::policy::rules::NistComplianceRule;
/// use bulwark::account::policy::{PasswordPolicyRule, PolicyContext};
///
/// let rule = NistComplianceRule::new(8);  // NIST 推荐最小长度
/// let ctx = PolicyContext { /* ... */ };
/// assert!(rule.validate(&ctx, "password").is_ok());     // 8 字符通过
/// assert!(rule.validate(&ctx, "short").is_err());       // 5 字符拒绝
/// assert!(rule.validate(&ctx, "Password123!").is_ok()); // 不强制复杂度
/// ```
pub struct NistComplianceRule {
    /// 最小密码长度（含）。NIST SP 800-63B 推荐 ≥ 8。
    min_length: u32,
}

impl NistComplianceRule {
    /// 创建 NIST 合规规则。
    ///
    /// # 参数
    /// - `min_length`: 最小密码长度（含）。NIST SP 800-63B §5.1.1.2 推荐 ≥ 8。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use bulwark::account::policy::rules::NistComplianceRule;
    ///
    /// let rule = NistComplianceRule::new(8);  // NIST 推荐
    /// let rule = NistComplianceRule::new(12); // 更严格策略
    /// ```
    pub fn new(min_length: u32) -> Self {
        Self { min_length }
    }

    /// HIBP（Have I Been Pwned）泄露密码检查。
    ///
    /// # v0.7.0 stub
    ///
    /// 当前为 stub，始终返回 `Ok(())`。v0.9.0 将实现真实 HIBP API 调用：
    /// - 使用 SHA-1 哈希密码
    /// - 通过 k-anonymity range search 查询 HIBP API（仅发送哈希前缀）
    /// - 匹配到的泄露次数 > 0 时返回 `Err(PolicyError)`
    ///
    /// # 参数
    /// - `password`: 待检查的明文密码
    ///
    /// # 返回
    /// - `Ok(())`: 密码未泄露（stub 阶段始终返回 Ok）
    /// - `Err(PolicyError)`: 密码已泄露（v0.9.0 实现）
    pub fn check_hibp(&self, _password: &str) -> Result<(), PolicyError> {
        // v0.7.0 stub: 始终返回 Ok，推迟到 v0.9.0 实现真实 HIBP API 调用。
        // v0.9.0 实现时需注意：
        // - 使用 reqwest 异步 HTTP client（需将本方法改为 async）
        // - k-anonymity 协议：仅发送 SHA-1 前 5 字符
        // - 不阻塞密码修改（HIBP API 不可达时返回 Ok，记日志）
        Ok(())
    }
}

impl PasswordPolicyRule for NistComplianceRule {
    fn name(&self) -> &'static str {
        "nist_compliance"
    }

    fn validate(&self, _ctx: &PolicyContext, password: &str) -> Result<(), PolicyError> {
        let len = password.len() as u32;
        if len < self.min_length {
            return Err(PolicyError::new(
                "nist_compliance",
                format!(
                    "密码长度 {} 小于 NIST SP 800-63B 最小要求 {}",
                    len, self.min_length
                ),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::account::credential::Argon2Hasher;
    use crate::account::credential::PasswordHasher;

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
    // MaxAgeRule 测试（R-006.7 stub）
    // ========================================================================

    /// R-006.7: stub 实现 — 任意密码 → 通过（不 panic）。
    #[test]
    fn max_age_rule_stub_always_passes() {
        let rule = MaxAgeRule::new(90);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "any-password").is_ok());
    }

    /// R-006.7: stub 实现 — 空密码也通过。
    #[test]
    fn max_age_rule_stub_passes_empty_password() {
        let rule = MaxAgeRule::new(30);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "").is_ok());
    }

    /// R-006.7: `name()` 返回 `"max_age"`。
    #[test]
    fn max_age_rule_name_returns_max_age() {
        let rule = MaxAgeRule::new(90);
        assert_eq!(rule.name(), "max_age");
    }

    // ========================================================================
    // DictionaryRule 测试
    // ========================================================================

    /// R-006.8: 密码不在字典 → 通过。
    #[test]
    fn dictionary_rule_passes_not_in_dictionary() {
        let rule = DictionaryRule::new(vec!["hello".into(), "world".into()]);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "secure-pw").is_ok());
    }

    /// R-006.8: 密码在字典 → 失败。
    #[test]
    fn dictionary_rule_fails_in_dictionary() {
        let rule = DictionaryRule::new(vec!["hello".into(), "world".into()]);
        let ctx = make_ctx(None, vec![]);
        let result = rule.validate(&ctx, "hello");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().rule_name, "dictionary");
    }

    /// R-006.8: 空字典 → 永远通过。
    #[test]
    fn dictionary_rule_passes_empty_dictionary() {
        let rule = DictionaryRule::new(vec![]);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "anything").is_ok());
    }

    /// R-006.8: 精确匹配（非子串匹配）。
    #[test]
    fn dictionary_rule_exact_match_not_substring() {
        let rule = DictionaryRule::new(vec!["hello".into()]);
        let ctx = make_ctx(None, vec![]);
        // "hello" 在字典中，但 "helloworld" 含 "hello" 子串 → 精确匹配不命中，应通过
        assert!(rule.validate(&ctx, "helloworld").is_ok());
    }

    /// R-006.8: `name()` 返回 `"dictionary"`。
    #[test]
    fn dictionary_rule_name_returns_dictionary() {
        let rule = DictionaryRule::new(vec![]);
        assert_eq!(rule.name(), "dictionary");
    }

    // ========================================================================
    // NotRepeatCharRule 测试
    // ========================================================================

    /// R-006.9: 无连续重复字符 → 通过。
    #[test]
    fn not_repeat_char_rule_passes_no_repeats() {
        let rule = NotRepeatCharRule::new(2);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "abac").is_ok());
    }

    /// R-006.9: 连续重复超过限制 → 失败。
    #[test]
    fn not_repeat_char_rule_fails_consecutive_repeats() {
        let rule = NotRepeatCharRule::new(2);
        let ctx = make_ctx(None, vec![]);
        let result = rule.validate(&ctx, "aaa");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().rule_name, "not_repeat_char");
    }

    /// R-006.9: 边界 — 恰好 max_consecutive 个连续 → 通过。
    #[test]
    fn not_repeat_char_rule_boundary_exact_max() {
        let rule = NotRepeatCharRule::new(2);
        let ctx = make_ctx(None, vec![]);
        assert!(
            rule.validate(&ctx, "aa").is_ok(),
            "2 个连续（== max）应通过"
        );
    }

    /// R-006.9: max_consecutive=1 时 "aa" 失败。
    #[test]
    fn not_repeat_char_rule_max_one_fails_pair() {
        let rule = NotRepeatCharRule::new(1);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "aa").is_err());
        assert!(rule.validate(&ctx, "ab").is_ok());
    }

    /// R-006.9: `name()` 返回 `"not_repeat_char"`。
    #[test]
    fn not_repeat_char_rule_name_returns_not_repeat_char() {
        let rule = NotRepeatCharRule::new(2);
        assert_eq!(rule.name(), "not_repeat_char");
    }

    // ========================================================================
    // NotSequenceRule 测试
    // ========================================================================

    /// R-006.10: 无序列 → 通过。
    #[test]
    fn not_sequence_rule_passes_no_sequence() {
        let rule = NotSequenceRule::new(3);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "a1b2").is_ok());
    }

    /// R-006.10: 正向序列超长 → 失败。
    #[test]
    fn not_sequence_rule_fails_forward_sequence() {
        let rule = NotSequenceRule::new(3);
        let ctx = make_ctx(None, vec![]);
        let result = rule.validate(&ctx, "abcd");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().rule_name, "not_sequence");
    }

    /// R-006.10: 反向序列超长 → 失败。
    #[test]
    fn not_sequence_rule_fails_reverse_sequence() {
        let rule = NotSequenceRule::new(2);
        let ctx = make_ctx(None, vec![]);
        // 321 → 反向序列长度 3 > 2
        assert!(rule.validate(&ctx, "321").is_err());
    }

    /// R-006.10: 边界 — 序列长度恰好 == max_sequence → 通过。
    #[test]
    fn not_sequence_rule_boundary_exact_max() {
        let rule = NotSequenceRule::new(3);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "abc").is_ok(), "长度 3 == max，应通过");
    }

    /// R-006.10: 字母反向序列 zyx → 失败。
    #[test]
    fn not_sequence_rule_fails_alpha_reverse() {
        let rule = NotSequenceRule::new(2);
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "zyx").is_err());
    }

    /// R-006.10: `name()` 返回 `"not_sequence"`。
    #[test]
    fn not_sequence_rule_name_returns_not_sequence() {
        let rule = NotSequenceRule::new(3);
        assert_eq!(rule.name(), "not_sequence");
    }

    // ========================================================================
    // NotEmailRule 测试
    // ========================================================================

    /// R-006.11: ctx.email 为 None → 通过。
    #[test]
    fn not_email_rule_passes_no_email() {
        let rule = NotEmailRule::new();
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "anything").is_ok());
    }

    /// R-006.11: 密码不包含邮箱前缀 → 通过。
    #[test]
    fn not_email_rule_passes_does_not_contain() {
        let rule = NotEmailRule::new();
        let ctx = PolicyContext {
            user_id: "test-user".to_string(),
            tenant_id: None,
            username: None,
            email: Some("alice@example.com".to_string()),
            password_history: vec![],
        };
        assert!(rule.validate(&ctx, "secure-pw").is_ok());
    }

    /// R-006.11: 密码包含邮箱前缀 → 失败。
    #[test]
    fn not_email_rule_fails_contains_email_prefix() {
        let rule = NotEmailRule::new();
        let ctx = PolicyContext {
            user_id: "test-user".to_string(),
            tenant_id: None,
            username: None,
            email: Some("alice@example.com".to_string()),
            password_history: vec![],
        };
        let result = rule.validate(&ctx, "alice123");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().rule_name, "not_email");
    }

    /// R-006.11: 大小写不敏感检测。
    #[test]
    fn not_email_rule_case_insensitive() {
        let rule = NotEmailRule::new();
        let ctx = PolicyContext {
            user_id: "test-user".to_string(),
            tenant_id: None,
            username: None,
            email: Some("Alice@example.com".to_string()),
            password_history: vec![],
        };
        assert!(
            rule.validate(&ctx, "ALICE123").is_err(),
            "大写密码包含小写邮箱前缀应失败"
        );
    }

    /// R-006.11: 无 @ 的 email → 通过。
    #[test]
    fn not_email_rule_no_at_sign_passes() {
        let rule = NotEmailRule::new();
        let ctx = PolicyContext {
            user_id: "test-user".to_string(),
            tenant_id: None,
            username: None,
            email: Some("alice".to_string()),
            password_history: vec![],
        };
        assert!(rule.validate(&ctx, "alice123").is_ok());
    }

    /// R-006.11: `name()` 返回 `"not_email"`。
    #[test]
    fn not_email_rule_name_returns_not_email() {
        let rule = NotEmailRule::new();
        assert_eq!(rule.name(), "not_email");
    }

    // ========================================================================
    // RegexRule 测试
    // ========================================================================

    /// R-006.12: 正则不匹配 → 通过。
    #[test]
    fn regex_rule_passes_no_match() {
        let rule = RegexRule::new(
            regex::Regex::new(r"\s").unwrap(),
            "密码不能包含空格".to_string(),
        );
        let ctx = make_ctx(None, vec![]);
        assert!(rule.validate(&ctx, "no_spaces").is_ok());
    }

    /// R-006.12: 正则匹配 → 失败。
    #[test]
    fn regex_rule_fails_match() {
        let rule = RegexRule::new(
            regex::Regex::new(r"\s").unwrap(),
            "密码不能包含空格".to_string(),
        );
        let ctx = make_ctx(None, vec![]);
        let result = rule.validate(&ctx, "has space");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().rule_name, "regex");
    }

    /// R-006.12: 错误信息使用构造器传入的 error_msg。
    #[test]
    fn regex_rule_error_msg_in_error() {
        let rule = RegexRule::new(
            regex::Regex::new(r"[0-9]").unwrap(),
            "密码不能包含数字".to_string(),
        );
        let ctx = make_ctx(None, vec![]);
        let err = rule.validate(&ctx, "abc1").unwrap_err();
        assert_eq!(err.message, "密码不能包含数字");
    }

    /// R-006.12: `name()` 返回 `"regex"`。
    #[test]
    fn regex_rule_name_returns_regex() {
        let rule = RegexRule::new(regex::Regex::new(r".").unwrap(), "test".to_string());
        assert_eq!(rule.name(), "regex");
    }

    // ========================================================================
    // 全部 12 个规则可作 Box<dyn PasswordPolicyRule> 使用（对象安全验证）
    // ========================================================================

    /// R-005/R-006: 12 个规则均可作 `Box<dyn PasswordPolicyRule>` 使用。
    #[test]
    fn all_rules_usable_as_dyn_trait_object() {
        let rules: Vec<Box<dyn PasswordPolicyRule>> = vec![
            Box::new(LengthRule::new(8, 128)),
            Box::new(ComplexityRule::new(1, 1, 1, 1)),
            Box::new(HistoryRule::new(3)),
            Box::new(BlacklistRule::new(vec![])),
            Box::new(NotUsernameRule::new()),
            Box::new(NotCommonPasswordRule::new(vec![])),
            Box::new(MaxAgeRule::new(90)),
            Box::new(DictionaryRule::new(vec![])),
            Box::new(NotRepeatCharRule::new(2)),
            Box::new(NotSequenceRule::new(3)),
            Box::new(NotEmailRule::new()),
            Box::new(RegexRule::new(
                regex::Regex::new(r".").unwrap(),
                "test".to_string(),
            )),
        ];
        assert_eq!(rules.len(), 12);
        assert_eq!(rules[0].name(), "length");
        assert_eq!(rules[1].name(), "complexity");
        assert_eq!(rules[2].name(), "history");
        assert_eq!(rules[3].name(), "blacklist");
        assert_eq!(rules[4].name(), "not_username");
        assert_eq!(rules[5].name(), "not_common_password");
        assert_eq!(rules[6].name(), "max_age");
        assert_eq!(rules[7].name(), "dictionary");
        assert_eq!(rules[8].name(), "not_repeat_char");
        assert_eq!(rules[9].name(), "not_sequence");
        assert_eq!(rules[10].name(), "not_email");
        assert_eq!(rules[11].name(), "regex");
    }
}
