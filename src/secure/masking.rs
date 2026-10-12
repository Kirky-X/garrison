// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 敏感数据脱敏子模块。
//!
//! `MaskType` 定义脱敏类型，`SensitiveDataMasker` 持 `(MaskType, field_name)` 规则列表；
//! `mask_value` 按类型脱敏单值，`mask_json` 递归遍历 JSON Object 匹配字段名脱敏
//! （`Custom` 变体用 `regex::Regex` 将全部匹配替换为 `***`）。

use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// 正则编译缓存上限（防止动态 pattern 无界增长）；pattern 来自配置/代码，超限后新 pattern 仍即时编译，只是不入缓存。
const REGEX_CACHE_CAP: usize = 256;

/// 进程级正则编译缓存：`Custom` 复用编译结果（`Regex` 内部为 Arc，clone 廉价），消除 `mask_value`/`mask_json` 热路径上的重复 `Regex::new`。
fn regex_cache() -> &'static Mutex<HashMap<String, regex::Regex>> {
    static CACHE: OnceLock<Mutex<HashMap<String, regex::Regex>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 脱敏类型。`Custom` 存正则模式，编译失败时记录 `tracing::error!` 并返回 `"***"`（fail-closed，避免泄露原值）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskType {
    /// 手机号（11 位）：保留前 3 后 4，中间 `*` 填充，如 `138****1234`。
    Phone,
    /// 身份证号（18 位）：保留前 3 后 4，中间 `*` 填充，如 `110***********1234`。
    IdCard,
    /// 邮箱：保留首字符 + `***` + `@` + 域名，如 `a***@example.com`。
    Email,
    /// 银行卡号：保留前 6 后 4（PCI-DSS 3.4），中间 `*` 填充，如 `622588******7890`。
    BankCard,
    /// 自定义正则模式：所有匹配项替换为 `***`（正则无效时返回 `"***"` + error 日志）。
    Custom(String),
}

/// 敏感数据脱敏器：按 `(MaskType, field_name)` 规则列表对 JSON Object 递归脱敏。
///
/// # 示例
///
/// ```ignore
/// use garrison::secure::masking::{MaskType, SensitiveDataMasker};
/// use serde_json::json;
///
/// let masker = SensitiveDataMasker::new()
/// .with_rule(MaskType::Phone, "phone");
/// let input = json!({"phone": "13812341234"});
/// let masked = masker.mask_json(&input);
/// assert_eq!(masked, json!({"phone": "138****1234"}));
/// ```
#[derive(Debug, Clone, Default)]
pub struct SensitiveDataMasker {
    /// 字段名 → 首个匹配规则（`with_rule` 构建，O(1) 查找）；同一字段名多次添加规则时以最先添加者为准。
    index: HashMap<&'static str, MaskType>,
}

impl SensitiveDataMasker {
    /// 创建空的脱敏器（无规则）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 添加脱敏规则（builder 模式）；同一字段名重复添加时保留首个规则。
    pub fn with_rule(mut self, mask_type: MaskType, field_name: &'static str) -> Self {
        self.index.entry(field_name).or_insert(mask_type);
        self
    }

    /// 按类型脱敏单个字符串。`Custom` 正则编译失败返回 `"***"` 并记 `tracing::error!`（安全 fallback）；其他类型不满足最小长度时返回原值。
    pub fn mask_value(&self, value: &str, mask_type: &MaskType) -> String {
        match mask_type {
            MaskType::Phone => mask_phone(value),
            MaskType::IdCard => mask_id_card(value),
            MaskType::Email => mask_email(value),
            MaskType::BankCard => mask_bank_card(value),
            MaskType::Custom(regex_str) => mask_custom(value, regex_str),
        }
    }

    /// 按字段名匹配规则脱敏；无匹配规则返回原值，`Custom` 正则无效返回 `"***"`。
    ///
    /// 始终返回 `String`（fail-closed 设计，不向调用方报错），保持外部调用方（如 `src/listener/audit.rs`）签名不变。
    pub fn mask_field(&self, field: &str, value: &str) -> String {
        match self.index.get(field) {
            Some(mask_type) => self.mask_value(value, mask_type),
            None => value.to_string(),
        }
    }

    /// 递归脱敏 JSON Value：Object 字段按规则脱敏，嵌套 Object 与数组内 Object 递归，非 Object 返回原值（深拷贝）。
    pub fn mask_json(&self, value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (key, val) in map {
                    let recursed = self.mask_json(val);
                    let final_val = if let Some(mask_type) = self.index.get(key.as_str()) {
                        match &recursed {
                            Value::String(s) => Value::String(self.mask_value(s, mask_type)),
                            _ => recursed,
                        }
                    } else {
                        recursed
                    };
                    new_map.insert(key.clone(), final_val);
                }
                Value::Object(new_map)
            },
            Value::Array(arr) => Value::Array(arr.iter().map(|v| self.mask_json(v)).collect()),
            _ => value.clone(),
        }
    }
}

/// 手机号：保留前 3 后 4，中间 `*` 填充，少于 7 位返回原值；按 `chars()` 切分避免非 ASCII 字符（中文、emoji）被切开 panic。
fn mask_phone(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 7 {
        return value.to_string();
    }
    let prefix: String = chars[..3].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    let stars = "*".repeat(chars.len() - 7);
    format!("{prefix}{stars}{suffix}")
}

/// 身份证号：保留前 3 后 4，中间 `*` 填充，少于 7 位返回原值。
fn mask_id_card(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 7 {
        return value.to_string();
    }
    let prefix: String = chars[..3].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    let stars = "*".repeat(chars.len() - 7);
    format!("{prefix}{stars}{suffix}")
}

/// 邮箱脱敏：保留首字符 + `***` + `@` + 域名。无 `@` 返回原值。
fn mask_email(value: &str) -> String {
    match value.find('@') {
        Some(at_pos) if at_pos > 0 => {
            let first = value
                .chars()
                .next()
                .expect("at_pos > 0 guarantees non-empty local part");
            let domain = &value[at_pos..];
            format!("{first}***{domain}")
        },
        _ => value.to_string(),
    }
}

/// 银行卡（PCI-DSS 3.4）：保留前 6 后 4，中间 `*` 填充；少于 10 位无法安全拆分时全 `*` 屏蔽（长度与输入一致，避免长度泄漏）。
fn mask_bank_card(value: &str) -> String {
    const BANK_CARD_PREFIX_LEN: usize = 6;
    const BANK_CARD_SUFFIX_LEN: usize = 4;
    const BANK_CARD_MIN_LEN: usize = BANK_CARD_PREFIX_LEN + BANK_CARD_SUFFIX_LEN;
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < BANK_CARD_MIN_LEN {
        return "*".repeat(chars.len());
    }
    let prefix: String = chars[..BANK_CARD_PREFIX_LEN].iter().collect();
    let suffix: String = chars[chars.len() - BANK_CARD_SUFFIX_LEN..].iter().collect();
    let stars = "*".repeat(chars.len() - BANK_CARD_MIN_LEN);
    format!("{prefix}{stars}{suffix}")
}

/// 自定义正则脱敏：所有匹配 `regex_str` 的子串替换为 `"***"`，编译结果经 [`regex_cache`] 按 pattern 复用。
///
/// # 安全语义
///
/// 编译成功有匹配 → 真实脱敏；成功但无匹配 → 返回原值（正则正确性由用户负责）；
/// 编译失败 → 返回 `"***"` 并记 error（无法解析用户意图时保守屏蔽全部，而非返回可能含敏感数据的原值；
/// 失败结果不入缓存，保留每次失败告警）。
///
/// # 示例
///
/// ```ignore
/// use garrison::secure::masking::MaskType;
/// let masker = garrison::secure::masking::SensitiveDataMasker::new();
/// // SSN 脱敏：123-45-6789 → ***-***-***（每个数字组替换为 ***，不论原长度）
/// let result = masker.mask_value("123-45-6789", &MaskType::Custom(r"\d+".to_string()));
/// assert_eq!(result, "***-***-***");
/// ```
fn mask_custom(value: &str, regex_str: &str) -> String {
    let compiled: Option<regex::Regex> = {
        let mut cache = match regex_cache().lock() {
            Ok(guard) => guard,
            // 缓存锁中毒（持锁线程 panic）时降级为继续使用，不影响脱敏正确性
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(re) = cache.get(regex_str) {
            Some(re.clone())
        } else {
            match regex::Regex::new(regex_str) {
                Ok(re) => {
                    // 达到缓存上限后不再入缓存（新 pattern 仍即时编译，正确性不变）
                    if cache.len() < REGEX_CACHE_CAP {
                        cache.insert(regex_str.to_string(), re.clone());
                    }
                    Some(re)
                },
                // 编译失败不入缓存：保持原有的每次失败告警语义
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        pattern = regex_str,
                        "Custom mask regex compilation failed; returning '***' as safe fallback"
                    );
                    None
                },
            }
        }
    };
    match compiled {
        Some(re) => re.replace_all(value, "***").to_string(),
        None => "***".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // mask_value 测试

    /// 手机号 "13812341234" → "138****1234"。
    #[test]
    fn mask_phone_returns_138_1234() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("13812341234", &MaskType::Phone);
        assert_eq!(result, "138****1234");
    }

    /// 身份证 "110101199001011234" → "110***********1234"。
    #[test]
    fn mask_id_card_returns_masked() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("110101199001011234", &MaskType::IdCard);
        assert_eq!(result, "110***********1234");
    }

    /// 邮箱 "alice@example.com" → "a***@example.com"。
    #[test]
    fn mask_email_returns_masked() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("alice@example.com", &MaskType::Email);
        assert_eq!(result, "a***@example.com");
    }

    /// 银行卡 "6222021234567890" → "622202******7890"（PCI-DSS first 6 + last 4）。
    #[test]
    fn mask_bank_card_returns_masked() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("6222021234567890", &MaskType::BankCard);
        assert_eq!(result, "622202******7890");
    }

    /// Custom 正则 `\d+` 匹配所有数字组：SSN `123-45-6789` → `***-***-***`。
    #[test]
    fn mask_custom_redacts_matching_digits() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("123-45-6789", &MaskType::Custom(r"\d+".to_string()));
        assert_eq!(result, "***-***-***");
    }

    /// Custom 类型正则无匹配时返回原值（用户负责正则正确性）。
    #[test]
    fn mask_custom_no_match_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("no-digits-here", &MaskType::Custom(r"\d+".to_string()));
        assert_eq!(result, "no-digits-here");
    }

    /// Custom 正则 `[` 编译失败返回 `"***"`（fail-closed，避免泄露原值）+ error 日志。
    #[test]
    fn mask_custom_invalid_regex_returns_safe_fallback() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("sensitive-secret", &MaskType::Custom(r"[".to_string()));
        assert_eq!(result, "***");
    }

    /// Custom 复杂正则（多 `\d+\.` 组合）匹配 IP 地址并替换为 `***`。
    #[test]
    fn mask_custom_redacts_ip_pattern() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value(
            "client_ip=192.168.1.1;",
            &MaskType::Custom(r"\d+\.\d+\.\d+\.\d+".to_string()),
        );
        assert_eq!(result, "client_ip=***;");
    }

    /// 手机号少于 7 位返回原值。
    #[test]
    fn mask_phone_short_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("123456", &MaskType::Phone);
        assert_eq!(result, "123456");
    }

    /// 身份证少于 7 位返回原值。
    #[test]
    fn mask_id_card_short_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("123456", &MaskType::IdCard);
        assert_eq!(result, "123456");
    }

    /// 邮箱无 `@` 返回原值。
    #[test]
    fn mask_email_no_at_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("noemail", &MaskType::Email);
        assert_eq!(result, "noemail");
    }

    /// 邮箱 `@` 在首位（无本地部分）返回原值。
    #[test]
    fn mask_email_at_start_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("@example.com", &MaskType::Email);
        assert_eq!(result, "@example.com");
    }

    /// 银行卡少于 10 位返回全 `*`（PCI-DSS 3.4：不足 first 6 + last 4 时全屏蔽）。
    #[test]
    fn mask_bank_card_short_returns_all_stars() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("1234567", &MaskType::BankCard);
        assert_eq!(result, "*******");
    }

    /// PCI-DSS 3.4：16 位卡号 "6225881234567890" → "622588******7890"（前 6 + 中 6 星 + 后 4）。
    #[test]
    fn mask_bank_card_pci_dss_first6_last4() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("6225881234567890", &MaskType::BankCard);
        assert_eq!(result, "622588******7890");
    }

    /// PCI-DSS 边界 — 恰好 10 位时 first 6 + last 4 中间 0 星。
    #[test]
    fn mask_bank_card_pci_dss_boundary_10_chars() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("6225887890", &MaskType::BankCard);
        assert_eq!(result, "6225887890");
    }

    /// PCI-DSS 边界 — 9 位（< 10）返回全 `*`，长度与输入一致。
    #[test]
    fn mask_bank_card_pci_dss_short_9_chars_all_stars() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("622588789", &MaskType::BankCard);
        assert_eq!(result, "*********");
    }

    /// PCI-DSS 边界 — 空字符串返回空（长度 0 < 10，全 `*` 即空串）。
    #[test]
    fn mask_bank_card_pci_dss_empty_string() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("", &MaskType::BankCard);
        assert_eq!(result, "");
    }

    /// 手机号含多字节字符（"中" 占 3 字节）不 panic。
    #[test]
    fn mask_phone_handles_multibyte_input() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("ab中cdefg", &MaskType::Phone);
        assert!(!result.is_empty(), "多字节输入不应 panic 且应返回非空结果");
    }

    /// 身份证含多字节字符不应 panic。
    #[test]
    fn mask_id_card_handles_multibyte_input() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("ab中cdefg", &MaskType::IdCard);
        assert!(!result.is_empty(), "多字节输入不应 panic 且应返回非空结果");
    }

    /// 银行卡含多字节字符不 panic。
    #[test]
    fn mask_bank_card_handles_multibyte_input() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("ab中cdefg", &MaskType::BankCard);
        assert!(!result.is_empty(), "多字节输入不应 panic 且应返回非空结果");
    }

    // mask_field 测试

    /// mask_field 匹配 Phone 规则脱敏。
    #[test]
    fn mask_field_matches_phone_rule() {
        let masker = SensitiveDataMasker::new().with_rule(MaskType::Phone, "phone");
        let result = masker.mask_field("phone", "13812341234");
        assert_eq!(result, "138****1234");
    }

    /// mask_field 无匹配规则返回原值。
    #[test]
    fn mask_field_no_match_returns_original() {
        let masker = SensitiveDataMasker::new().with_rule(MaskType::Phone, "phone");
        let result = masker.mask_field("email", "alice@example.com");
        assert_eq!(result, "alice@example.com");
    }

    /// mask_field 多规则匹配第一个。
    #[test]
    fn mask_field_matches_first_rule() {
        let masker = SensitiveDataMasker::new()
            .with_rule(MaskType::Phone, "contact")
            .with_rule(MaskType::Email, "contact");
        let result = masker.mask_field("contact", "13812341234");
        assert_eq!(result, "138****1234");
    }

    /// mask_field 空规则返回原值。
    #[test]
    fn mask_field_empty_rules_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_field("phone", "13812341234");
        assert_eq!(result, "13812341234");
    }

    // mask_json 测试

    /// `{"phone":"13812341234"}` → `{"phone":"1381234"}`。
    #[test]
    fn mask_json_masks_phone_field() {
        let masker = SensitiveDataMasker::new().with_rule(MaskType::Phone, "phone");
        let input = json!({"phone": "13812341234"});
        let masked = masker.mask_json(&input);
        assert_eq!(masked, json!({"phone": "138****1234"}));
    }

    /// 嵌套 Object 递归脱敏。
    #[test]
    fn mask_json_masks_nested_object() {
        let masker = SensitiveDataMasker::new().with_rule(MaskType::Phone, "phone");
        let input = json!({"user": {"phone": "13812341234"}});
        let masked = masker.mask_json(&input);
        assert_eq!(masked, json!({"user": {"phone": "138****1234"}}));
    }

    /// 数组中的 Object 递归脱敏。
    #[test]
    fn mask_json_masks_array_of_objects() {
        let masker = SensitiveDataMasker::new().with_rule(MaskType::Phone, "phone");
        let input = json!([{"phone": "13812341234"}, {"phone": "13912341234"}]);
        let masked = masker.mask_json(&input);
        assert_eq!(
            masked,
            json!([{"phone": "138****1234"}, {"phone": "139****1234"}])
        );
    }

    /// 非 Object 类型返回原值。
    #[test]
    fn mask_json_non_object_returns_original() {
        let masker = SensitiveDataMasker::new();
        let input = json!("just a string");
        let masked = masker.mask_json(&input);
        assert_eq!(masked, input);
    }

    /// 无匹配字段返回原值。
    #[test]
    fn mask_json_no_matching_field_returns_original() {
        let masker = SensitiveDataMasker::new().with_rule(MaskType::Phone, "phone");
        let input = json!({"name": "Alice"});
        let masked = masker.mask_json(&input);
        assert_eq!(masked, json!({"name": "Alice"}));
    }

    /// 多字段混合脱敏（phone + email + 非敏感字段）。
    #[test]
    fn mask_json_masks_multiple_fields() {
        let masker = SensitiveDataMasker::new()
            .with_rule(MaskType::Phone, "phone")
            .with_rule(MaskType::Email, "email");
        let input = json!({
            "name": "Alice",
            "phone": "13812341234",
            "email": "alice@example.com"
        });
        let masked = masker.mask_json(&input);
        assert_eq!(
            masked,
            json!({
                "name": "Alice",
                "phone": "138****1234",
                "email": "a***@example.com"
            })
        );
    }

    // Custom 正则脱敏测试（regex feature）

    /// Custom 每个数字替换为 `***`："123-45-6789" → "*********-******-************"。
    #[test]
    fn mask_custom_regex_replaces_digits_with_star() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("123-45-6789", &MaskType::Custom(r"\d".to_string()));
        assert_eq!(result, "*********-******-************");
    }

    /// Custom 替换 email 本地部分：`^[^@]+` 匹配 "alice" → "***"。
    #[test]
    fn mask_custom_regex_replaces_email_local_part() {
        let masker = SensitiveDataMasker::new();
        // 替换 @ 之前的所有字符为 `***`（整个匹配替换为 `***`）
        let result = masker.mask_value(
            "alice@example.com",
            &MaskType::Custom(r"^[^@]+".to_string()),
        );
        assert_eq!(result, "***@example.com");
    }

    /// Custom regex 不匹配时返回原值。
    #[test]
    fn mask_custom_regex_no_match_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("no-digits-here", &MaskType::Custom(r"\d".to_string()));
        assert_eq!(result, "no-digits-here");
    }

    /// Custom regex 空输入返回空字符串。
    #[test]
    fn mask_custom_regex_empty_input_returns_empty() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("", &MaskType::Custom(r"\d".to_string()));
        assert_eq!(result, "");
    }

    /// 空 pattern 匹配每个字符间位置并逐个替换："anything" 8 字符 → 9 个空位置。
    #[test]
    fn mask_custom_regex_empty_pattern_returns_original() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("anything", &MaskType::Custom("".to_string()));
        assert_eq!(result, "***a***n***y***t***h***i***n***g***");
    }

    /// Custom regex 无效 pattern `[` 返回 `"***"`（fail-closed）+ error 日志。
    #[test]
    fn mask_custom_regex_invalid_pattern_returns_safe_fallback() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("test", &MaskType::Custom(r"[".to_string()));
        assert_eq!(result, "***");
    }

    /// 多处匹配全部替换："a1b2c3d4" → "a***b***c***d***"。
    #[test]
    fn mask_custom_regex_replaces_all_matches() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("a1b2c3d4", &MaskType::Custom(r"\d".to_string()));
        assert_eq!(result, "a***b***c***d***");
    }

    /// 银行卡 16 位数字逐个替换为 `***` → 48 个 `*`。
    #[test]
    fn mask_custom_regex_bank_card_partial_mask() {
        let masker = SensitiveDataMasker::new();
        let result = masker.mask_value("6222021234567890", &MaskType::Custom(r"\d".to_string()));
        assert_eq!(result, "*".repeat(48));
    }

    /// mask_field 遇无效 regex 返回 `"***"`（fail-closed，不泄露原值）。
    #[test]
    fn mask_field_custom_regex_error_returns_safe_fallback() {
        let masker = SensitiveDataMasker::new().with_rule(MaskType::Custom("[".to_string()), "ssn");
        // 无效 regex pattern，mask_field 应返回 "***"（fail-closed，不泄露原值）
        let result = masker.mask_field("ssn", "123-45-6789");
        assert_eq!(result, "***");
    }

    /// mask_field 在 regex 有效时经 `mask_value` 正确脱敏。
    #[test]
    fn mask_field_custom_regex_valid_masks_correctly() {
        let masker =
            SensitiveDataMasker::new().with_rule(MaskType::Custom(r"\d".to_string()), "ssn");
        let result = masker.mask_field("ssn", "123-45-6789");
        assert_eq!(result, "*********-******-************");
    }
}
